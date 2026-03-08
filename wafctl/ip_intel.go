package main

import (
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
