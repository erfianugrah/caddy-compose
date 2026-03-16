package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ─── Team Cymru DNS Lookup ──────────────────────────────────────────────────
// Queries: <reversed-ip>.origin.asn.cymru.com TXT
// Response: "AS_NUM | PREFIX | CC | RIR | ALLOC_DATE"
// Then:     AS<num>.asn.cymru.com TXT
// Response: "AS_NUM | CC | RIR | ALLOC_DATE | AS_NAME"

func (s *IPIntelStore) lookupRouting(ip string) *RoutingInfo {
	info := &RoutingInfo{}

	// Step 1: Reverse IP and query origin TXT record.
	reversed := reverseIP(ip)
	if reversed == "" {
		return info
	}

	originHost := reversed + ".origin.asn.cymru.com"
	txts, err := net.LookupTXT(originHost)
	if err != nil || len(txts) == 0 {
		return info
	}

	// Parse: "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"
	origin := parseCymruOrigin(txts[0])
	if origin.asNumber == "" {
		return info
	}

	info.IsAnnounced = true
	info.ASNumber = origin.asNumber
	info.Route = origin.route
	info.RIR = origin.rir
	info.AllocDate = origin.allocDate

	// Step 2: Query AS name.
	asHost := "AS" + origin.asNumber + ".asn.cymru.com"
	asTxts, err := net.LookupTXT(asHost)
	if err == nil && len(asTxts) > 0 {
		info.ASName = parseCymruASName(asTxts[0])
	}

	// Step 3: RPKI/ROA validation via RIPE.
	if info.ASNumber != "" && info.Route != "" {
		roa := s.lookupRPKI(info.ASNumber, info.Route)
		info.ROAValidity = roa.validity
		info.ROACount = roa.count
	}

	return info
}

type cymruOrigin struct {
	asNumber  string
	route     string
	cc        string
	rir       string
	allocDate string
}

// parseCymruOrigin parses a Team Cymru origin TXT response.
// Format: "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"
func parseCymruOrigin(txt string) cymruOrigin {
	parts := strings.Split(txt, "|")
	if len(parts) < 3 {
		return cymruOrigin{}
	}
	o := cymruOrigin{
		asNumber: strings.TrimSpace(parts[0]),
	}
	// Take first AS if multiple (some prefixes have multiple origins).
	if idx := strings.Index(o.asNumber, " "); idx > 0 {
		o.asNumber = o.asNumber[:idx]
	}
	if len(parts) > 1 {
		o.route = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		o.cc = strings.TrimSpace(parts[2])
	}
	if len(parts) > 3 {
		o.rir = strings.TrimSpace(parts[3])
	}
	if len(parts) > 4 {
		o.allocDate = strings.TrimSpace(parts[4])
	}
	return o
}

// parseCymruASName parses a Team Cymru AS TXT response.
// Format: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"
func parseCymruASName(txt string) string {
	parts := strings.Split(txt, "|")
	if len(parts) < 5 {
		return ""
	}
	return strings.TrimSpace(parts[4])
}

// reverseIP reverses an IPv4 address for DNS lookup (1.2.3.4 → 4.3.2.1).
// Returns "" for IPv6 or invalid IPs (Team Cymru DNS works best with IPv4).
func reverseIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	// Only support IPv4 for Team Cymru origin lookups.
	ip4 := parsed.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
}

// ─── RIPE RPKI Validation ───────────────────────────────────────────────────
// Queries: https://stat.ripe.net/data/rpki-validation/data.json?resource=AS<num>&prefix=<route>
// Response: { data: { status: "valid"|"invalid"|"unknown", validating_roas: [...] } }

type rpkiResult struct {
	validity string
	count    int
}

func (s *IPIntelStore) lookupRPKI(asNumber, route string) rpkiResult {
	url := fmt.Sprintf("https://stat.ripe.net/data/rpki-validation/data.json?resource=AS%s&prefix=%s&sourceapp=wafctl",
		asNumber, route)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return rpkiResult{validity: "unknown"}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("ipintel: RPKI lookup failed: %v", err)
		return rpkiResult{validity: "unknown"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return rpkiResult{validity: "unknown"}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if err != nil {
		return rpkiResult{validity: "unknown"}
	}

	var result struct {
		Data struct {
			Status         string `json:"status"`
			ValidatingROAs []struct {
				Origin    string `json:"origin"`
				Prefix    string `json:"prefix"`
				MaxLength int    `json:"max_length"`
				Validity  string `json:"validity"`
			} `json:"validating_roas"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return rpkiResult{validity: "unknown"}
	}

	validity := strings.ToLower(result.Data.Status)
	if validity == "" {
		validity = "not_found"
	}
	return rpkiResult{
		validity: validity,
		count:    len(result.Data.ValidatingROAs),
	}
}

// ─── Reputation Lookups ─────────────────────────────────────────────────────

func (s *IPIntelStore) lookupReputation(ip string) *ReputationInfo {
	info := &ReputationInfo{
		Status: "clean",
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var entries []ReputationEntry

	wg.Add(2)

	// GreyNoise Community API (free, no key).
	go func() {
		defer wg.Done()
		if entry := s.lookupGreyNoise(ip); entry != nil {
			mu.Lock()
			entries = append(entries, *entry)
			mu.Unlock()
		}
	}()

	// StopForumSpam API (free, no key).
	go func() {
		defer wg.Done()
		if entry := s.lookupStopForumSpam(ip); entry != nil {
			mu.Lock()
			entries = append(entries, *entry)
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Check IPsum blocklist (local, instant).
	if s.blocklist != nil {
		check := s.blocklist.Check(ip)
		if check.Blocked {
			info.IpsumListed = true
		}
	}

	info.Sources = entries

	// Derive overall status from individual sources.
	info.Status = deriveReputationStatus(entries, info.IpsumListed)

	return info
}

// lookupGreyNoise queries the GreyNoise Community API.
// Response: { ip, noise, riot, classification, name, last_seen, message }
func (s *IPIntelStore) lookupGreyNoise(ip string) *ReputationEntry {
	reqURL := "https://api.greynoise.io/v3/community/" + url.PathEscape(ip)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// GreyNoise returns 404 for unknown IPs — that's fine, means clean.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var result struct {
		IP             string `json:"ip"`
		Noise          bool   `json:"noise"`
		Riot           bool   `json:"riot"`
		Classification string `json:"classification"`
		Name           string `json:"name"`
		LastSeen       string `json:"last_seen"`
		Message        string `json:"message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	entry := &ReputationEntry{
		Source:   "greynoise",
		LastSeen: result.LastSeen,
	}

	if result.Name != "" && result.Name != "unknown" {
		entry.Name = result.Name
	}

	switch {
	case result.Riot || result.Classification == "benign":
		entry.Status = "benign"
		entry.Classification = "benign"
	case result.Classification == "malicious":
		entry.Status = "malicious"
		entry.Classification = "malicious"
	case result.Noise:
		entry.Status = "noisy"
		entry.Classification = "unknown"
	default:
		entry.Status = "clean"
		entry.Classification = "unknown"
	}

	return entry
}

// lookupStopForumSpam queries the StopForumSpam API.
// Response: { success, ip: { value, frequency, appears, asn, country } }
func (s *IPIntelStore) lookupStopForumSpam(ip string) *ReputationEntry {
	reqURL := "https://api.stopforumspam.org/api?json&ip=" + url.QueryEscape(ip)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var result struct {
		Success int `json:"success"`
		IP      struct {
			Appears   int    `json:"appears"`
			Frequency int    `json:"frequency"`
			Country   string `json:"country"`
		} `json:"ip"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	entry := &ReputationEntry{
		Source: "stopforumspam",
	}

	if result.IP.Appears == 1 {
		entry.Status = "malicious"
	} else {
		entry.Status = "clean"
	}

	return entry
}

// ─── Shodan InternetDB ──────────────────────────────────────────────────────
// Free API, no key needed. Returns open ports, hostnames, tags, CPEs, CVEs.
// Response: { ip, ports, hostnames, cpes, tags, vulns }

func (s *IPIntelStore) lookupShodan(ip string) *ShodanInfo {
	reqURL := "https://internetdb.shodan.io/" + url.PathEscape(ip)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Shodan returns 404 for IPs with no data.
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if err != nil {
		return nil
	}

	var result struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		Tags      []string `json:"tags"`
		CPEs      []string `json:"cpes"`
		Vulns     []string `json:"vulns"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	// Only return if there's actually some data.
	if len(result.Ports) == 0 && len(result.Hostnames) == 0 && len(result.Vulns) == 0 {
		return nil
	}

	return &ShodanInfo{
		Ports:     result.Ports,
		Hostnames: result.Hostnames,
		Tags:      result.Tags,
		CPEs:      result.CPEs,
		Vulns:     result.Vulns,
	}
}
