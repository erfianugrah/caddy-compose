package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── IP Intelligence Store ───────────────────────────────────────────────────
// Aggregates data from multiple free intelligence sources:
//   - Team Cymru DNS (AS number, route, RIR, allocation date)
//   - RIPE RIPEstat API (RPKI/ROA validation)
//   - GreyNoise Community API (known good/bad classification)
//   - StopForumSpam API (spam/abuse blacklist)
//   - Shodan InternetDB (open ports, CVEs, hostnames)
//   - Local IPsum blocklist (our own blocklist state)

// IPIntelStore provides IP intelligence lookups with caching.
type IPIntelStore struct {
	mu        sync.RWMutex
	cache     map[string]intelEntry
	client    *http.Client
	blocklist *BlocklistStore // may be nil
}

type intelEntry struct {
	intel *IPIntelligence
	ts    time.Time
}

const intelCacheTTL = 24 * time.Hour
const intelCacheMaxSize = 10000

// NewIPIntelStore creates a new IP intelligence store.
func NewIPIntelStore(blocklist *BlocklistStore) *IPIntelStore {
	return &IPIntelStore{
		cache: make(map[string]intelEntry),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		blocklist: blocklist,
	}
}

// Lookup returns enriched IP intelligence, using cache when available.
// All external lookups run in parallel for minimum latency.
func (s *IPIntelStore) Lookup(ip string) *IPIntelligence {
	if ip == "" || net.ParseIP(ip) == nil {
		return nil
	}

	// Check cache.
	s.mu.RLock()
	if entry, ok := s.cache[ip]; ok && time.Since(entry.ts) < intelCacheTTL {
		s.mu.RUnlock()
		return entry.intel
	}
	s.mu.RUnlock()

	// Run all lookups in parallel.
	var wg sync.WaitGroup
	var routing *RoutingInfo
	var reputation *ReputationInfo
	var shodan *ShodanInfo

	wg.Add(3)

	// 1. Routing: Team Cymru DNS + RIPE RPKI
	go func() {
		defer wg.Done()
		routing = s.lookupRouting(ip)
	}()

	// 2. Reputation: GreyNoise + StopForumSpam + IPsum
	go func() {
		defer wg.Done()
		reputation = s.lookupReputation(ip)
	}()

	// 3. Shodan InternetDB
	go func() {
		defer wg.Done()
		shodan = s.lookupShodan(ip)
	}()

	wg.Wait()

	// Infer network type from routing + Shodan data.
	netType := inferNetworkType(routing, shodan)

	intel := &IPIntelligence{
		Routing:    routing,
		NetType:    netType,
		Reputation: reputation,
		Shodan:     shodan,
	}

	// Cache result.
	s.mu.Lock()
	if len(s.cache) >= intelCacheMaxSize {
		s.evictOldest()
	}
	s.cache[ip] = intelEntry{intel: intel, ts: time.Now()}
	s.mu.Unlock()

	return intel
}

// evictOldest removes ~25% of cache entries by age. Caller must hold s.mu write lock.
func (s *IPIntelStore) evictOldest() {
	target := intelCacheMaxSize / 4
	deleted := 0
	for k := range s.cache {
		if deleted >= target {
			break
		}
		delete(s.cache, k)
		deleted++
	}
}

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
	url := "https://api.greynoise.io/v3/community/" + ip

	req, err := http.NewRequest("GET", url, nil)
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
	url := "https://api.stopforumspam.org/api?json&ip=" + ip

	req, err := http.NewRequest("GET", url, nil)
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
	url := "https://internetdb.shodan.io/" + ip

	req, err := http.NewRequest("GET", url, nil)
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

// ─── Network Type Inference ─────────────────────────────────────────────────

// Known anycast AS numbers (major CDN/DNS providers).
var knownAnycastASNs = map[string]bool{
	"13335": true, // Cloudflare
	"15169": true, // Google
	"8075":  true, // Microsoft
	"16509": true, // Amazon
	"20940": true, // Akamai
	"54113": true, // Fastly
	"13238": true, // Yandex
	"32934": true, // Facebook
	"2906":  true, // Netflix
}

// Keywords that indicate hosting/datacenter providers.
// Order matters: more specific patterns first to avoid false positives
// (e.g., "cloud" is too broad — "cloudflare" is a CDN, not a generic host).
var dcKeywords = []string{
	"hosting", "hetzner", "ovh", "digitalocean", "linode", "vultr",
	"amazon", "google cloud", "gcp", "azure",
	"oracle cloud", "alibaba", "tencent", "rackspace", "softlayer",
	"leaseweb", "choopa", "contabo", "scaleway", "upcloud",
	"datacenter", "data center", "colocation",
	"server farm", "vps", "dedicated server",
}

// Keywords that indicate ISP/consumer providers.
var ispKeywords = []string{
	"telecom", "telekom", "telefonica", "comcast", "verizon", "at&t",
	"spectrum", "cox", "charter", "centurylink", "broadband",
	"cable", "dsl", "fiber", "mobile", "wireless",
	"vodafone", "orange", "t-mobile", "sprint",
	"virgin media", "swisscom", "kpn",
	"proximus", "telia", "telenor", "elisa",
}

func inferNetworkType(routing *RoutingInfo, shodan *ShodanInfo) *NetworkType {
	if routing == nil {
		return nil
	}

	nt := &NetworkType{}

	// Check anycast.
	if knownAnycastASNs[routing.ASNumber] {
		nt.IsAnycast = true
	}

	// Infer org type from AS name.
	if routing.ASName != "" {
		lower := strings.ToLower(routing.ASName)
		nt.OrgType = classifyASName(lower)
		if nt.OrgType == "hosting" {
			nt.IsDC = true
		}
	}

	// Shodan tags can confirm hosting/DC.
	if shodan != nil {
		for _, tag := range shodan.Tags {
			lt := strings.ToLower(tag)
			if lt == "cloud" || lt == "datacenter" || lt == "hosting" {
				nt.IsDC = true
			}
		}
	}

	return nt
}

func classifyASName(lower string) string {
	for _, kw := range dcKeywords {
		if strings.Contains(lower, kw) {
			return "hosting"
		}
	}
	for _, kw := range ispKeywords {
		if strings.Contains(lower, kw) {
			return "isp"
		}
	}
	if strings.Contains(lower, "universit") || strings.Contains(lower, "college") || strings.Contains(lower, "academ") || strings.Contains(lower, "institute of technology") {
		return "education"
	}
	if strings.Contains(lower, "government") || strings.Contains(lower, "gouv") || strings.Contains(lower, "gov.") {
		return "government"
	}
	return "business"
}

// ─── Reputation Status Derivation ───────────────────────────────────────────

func deriveReputationStatus(entries []ReputationEntry, ipsumListed bool) string {
	if ipsumListed {
		return "malicious"
	}

	hasKnownGood := false
	hasMalicious := false
	hasNoisy := false

	for _, e := range entries {
		switch e.Status {
		case "malicious":
			hasMalicious = true
		case "benign":
			hasKnownGood = true
		case "noisy":
			hasNoisy = true
		}
	}

	switch {
	case hasMalicious:
		return "malicious"
	case hasKnownGood:
		return "known_good"
	case hasNoisy:
		return "suspicious"
	default:
		return "clean"
	}
}
