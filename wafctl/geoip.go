package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── GeoIP Store ─────────────────────────────────────────────────────────────
// Thread-safe country lookup with three-tier resolution:
//   Priority 1: Cf-Ipcountry header (free, zero latency, present when behind CF)
//   Priority 2: Local MMDB database lookup (sub-microsecond, offline)
//   Priority 3: Online API fallback (for deployments without CF or MMDB)

// GeoIPAPIConfig holds configuration for the online GeoIP API fallback.
type GeoIPAPIConfig struct {
	URL     string        // API URL template with %s for IP (e.g., "https://ipinfo.io/%s/json")
	Key     string        // API key (sent as Bearer token, empty = no auth)
	Timeout time.Duration // HTTP request timeout (default 2s)
}

// GeoIPStore provides IP-to-country resolution with caching.
type GeoIPStore struct {
	mu     sync.RWMutex
	db     *geoIPDB // nil if no MMDB loaded
	cache  map[string]geoEntry
	api    *GeoIPAPIConfig // nil if no online API configured
	client *http.Client    // shared HTTP client for API calls
}

type geoEntry struct {
	country string
	ts      time.Time
}

const geoCacheTTL = 24 * time.Hour
const geoCacheMaxSize = 100000

// NewGeoIPStore creates a new GeoIP store. If dbPath is non-empty and the file
// exists, it loads the MMDB database. If apiCfg is provided with a non-empty URL,
// the store will fall back to online API lookups when both CF header and MMDB
// are unavailable. Otherwise the store works in header-only mode (Cf-Ipcountry).
func NewGeoIPStore(dbPath string, apiCfg *GeoIPAPIConfig) *GeoIPStore {
	s := &GeoIPStore{
		cache: make(map[string]geoEntry),
	}
	if dbPath != "" {
		if _, err := os.Stat(dbPath); err == nil {
			db, err := newGeoIPDB(dbPath)
			if err != nil {
				log.Printf("geoip: failed to load MMDB %s: %v", dbPath, err)
			} else {
				s.db = db
				log.Printf("geoip: loaded MMDB %s (ipVersion=%d, nodeCount=%d, recordSize=%d)",
					dbPath, db.ipVersion, db.nodeCount, db.recordSize)
			}
		} else {
			log.Printf("geoip: MMDB file not found at %s, running in header-only mode", dbPath)
		}
	}

	// Configure online API fallback.
	if apiCfg != nil && apiCfg.URL != "" {
		timeout := apiCfg.Timeout
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		s.api = apiCfg
		s.client = &http.Client{Timeout: timeout}
		log.Printf("geoip: online API fallback enabled (url=%s, timeout=%s)", apiCfg.URL, timeout)
	}

	return s
}

// HasDB returns true if an MMDB database is loaded.
func (s *GeoIPStore) HasDB() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db != nil
}

// LookupIP resolves an IP address to a country code using the MMDB database.
// Returns "" if no database is loaded or the IP is not found.
// Results are cached for geoCacheTTL.
func (s *GeoIPStore) LookupIP(ip string) string {
	if ip == "" {
		return ""
	}

	// Check cache first
	s.mu.RLock()
	if entry, ok := s.cache[ip]; ok && time.Since(entry.ts) < geoCacheTTL {
		s.mu.RUnlock()
		return entry.country
	}
	db := s.db
	s.mu.RUnlock()

	if db == nil {
		return ""
	}

	country := db.lookupCountry(ip)

	// Store in cache
	s.mu.Lock()
	// Evict if cache too large
	if len(s.cache) >= geoCacheMaxSize {
		s.evictRandom()
	}
	s.cache[ip] = geoEntry{country: country, ts: time.Now()}
	s.mu.Unlock()

	return country
}

// Resolve returns the country for an IP, using the CF header first, then MMDB,
// then online API. cfCountry is the value of the Cf-Ipcountry header (empty if
// not present).
func (s *GeoIPStore) Resolve(ip, cfCountry string) string {
	// Priority 1: Cloudflare header
	if cfCountry != "" && cfCountry != "XX" && cfCountry != "T1" {
		return strings.ToUpper(cfCountry)
	}
	// Priority 2: MMDB lookup
	if country := s.LookupIP(ip); country != "" {
		return country
	}
	// Priority 3: Online API fallback
	if s.api != nil {
		return s.lookupOnline(ip)
	}
	return ""
}

// HasAPI returns true if an online GeoIP API fallback is configured.
func (s *GeoIPStore) HasAPI() bool {
	return s.api != nil
}

// LookupFull returns enriched GeoIP information for an IP address.
// Uses all available sources: CF header (country only), MMDB (country only),
// and online API (full enrichment: ASN, org, city, region, timezone, network).
func (s *GeoIPStore) LookupFull(ip, cfCountry string) *GeoIPInfo {
	if ip == "" {
		return nil
	}
	info := &GeoIPInfo{}

	// Priority 1: Cloudflare header (country only).
	if cfCountry != "" && cfCountry != "XX" && cfCountry != "T1" {
		info.Country = strings.ToUpper(cfCountry)
		info.Source = "cf_header"
	}

	// Priority 2: MMDB lookup (country only).
	if info.Country == "" {
		if country := s.LookupIP(ip); country != "" {
			info.Country = country
			info.Source = "mmdb"
		}
	}

	// Priority 3: Online API (full enrichment).
	if s.api != nil {
		full := s.lookupOnlineFull(ip)
		if full != nil {
			// If we didn't have country yet, use API country.
			if info.Country == "" && full.Country != "" {
				info.Country = full.Country
				info.Source = "api"
			}
			// Always overlay enrichment fields from API.
			info.City = full.City
			info.Region = full.Region
			info.Timezone = full.Timezone
			info.ASN = full.ASN
			info.Org = full.Org
			info.Network = full.Network
			if info.Source != "cf_header" && info.Source != "mmdb" {
				info.Source = "api"
			}
		}
	}

	// If we have no data at all, return nil.
	if info.Country == "" && info.ASN == "" {
		return nil
	}
	return info
}

// lookupOnline queries the configured online GeoIP API for a country code.
// Results are cached in the shared cache. Returns "" on error.
func (s *GeoIPStore) lookupOnline(ip string) string {
	if ip == "" || net.ParseIP(ip) == nil {
		return ""
	}

	// Check cache first (may have been populated by a previous online lookup).
	s.mu.RLock()
	if entry, ok := s.cache[ip]; ok && time.Since(entry.ts) < geoCacheTTL {
		s.mu.RUnlock()
		return entry.country
	}
	s.mu.RUnlock()

	// Build URL — support %s placeholder for IP, or append as path segment.
	url := s.api.URL
	if strings.Contains(url, "%s") {
		url = fmt.Sprintf(url, ip)
	} else {
		url = strings.TrimRight(url, "/") + "/" + ip
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("geoip: online API request error: %v", err)
		return ""
	}
	if s.api.Key != "" {
		req.Header.Set("Authorization", "Bearer "+s.api.Key)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("geoip: online API request failed for %s: %v", ip, err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("geoip: online API returned status %d for %s", resp.StatusCode, ip)
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		log.Printf("geoip: online API read error for %s: %v", ip, err)
		return ""
	}

	// Parse JSON — supports common API response formats:
	// IPinfo.io: {"country": "US", ...}
	// ip-api.com: {"countryCode": "US", ...}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("geoip: online API JSON parse error for %s: %v", ip, err)
		return ""
	}

	// Try common field names for country code.
	country := ""
	for _, field := range []string{"country", "countryCode", "country_code"} {
		if val, ok := result[field]; ok {
			if s, ok := val.(string); ok && len(s) == 2 {
				country = strings.ToUpper(s)
				break
			}
		}
	}

	// Cache the result (even empty results to avoid repeated failed lookups).
	s.mu.Lock()
	if len(s.cache) >= geoCacheMaxSize {
		s.evictRandom()
	}
	s.cache[ip] = geoEntry{country: country, ts: time.Now()}
	s.mu.Unlock()

	return country
}

// lookupOnlineFull queries the configured online GeoIP API and returns enriched
// info (ASN, org, city, region, timezone, network) in addition to country.
// Returns nil on error. Results are NOT cached in the country cache since this
// returns richer data that we don't persist.
func (s *GeoIPStore) lookupOnlineFull(ip string) *GeoIPInfo {
	if ip == "" || net.ParseIP(ip) == nil {
		return nil
	}

	// Build URL — support %s placeholder for IP, or append as path segment.
	url := s.api.URL
	if strings.Contains(url, "%s") {
		url = fmt.Sprintf(url, ip)
	} else {
		url = strings.TrimRight(url, "/") + "/" + ip
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	if s.api.Key != "" {
		req.Header.Set("Authorization", "Bearer "+s.api.Key)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("geoip: online full lookup failed for %s: %v", ip, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	info := &GeoIPInfo{Source: "api"}

	// Country — common field names across providers.
	for _, f := range []string{"country", "countryCode", "country_code"} {
		if v, ok := raw[f]; ok {
			if s, ok := v.(string); ok && len(s) == 2 {
				info.Country = strings.ToUpper(s)
				break
			}
		}
	}

	// City
	for _, f := range []string{"city"} {
		if v, ok := raw[f]; ok {
			if s, ok := v.(string); ok && s != "" {
				info.City = s
				break
			}
		}
	}

	// Region — IPinfo uses "region", ip-api uses "regionName"
	for _, f := range []string{"region", "regionName", "region_name"} {
		if v, ok := raw[f]; ok {
			if s, ok := v.(string); ok && s != "" {
				info.Region = s
				break
			}
		}
	}

	// Timezone
	for _, f := range []string{"timezone"} {
		if v, ok := raw[f]; ok {
			if s, ok := v.(string); ok && s != "" {
				info.Timezone = s
				break
			}
		}
	}

	// ASN — try dedicated fields first, then composite "org" field.
	// IPinfo Lite: "asn": "AS15169"
	// ip-api: "as": "AS15169 Google LLC"
	// IPinfo standard: "org": "AS13335 Cloudflare, Inc."
	for _, f := range []string{"asn", "as"} {
		if v, ok := raw[f]; ok {
			if s, ok := v.(string); ok && s != "" {
				if strings.HasPrefix(s, "AS") {
					// May contain org name after space (ip-api format)
					parts := strings.SplitN(s, " ", 2)
					info.ASN = parts[0]
					if len(parts) > 1 && info.Org == "" {
						info.Org = parts[1]
					}
				} else {
					info.ASN = s
				}
				break
			}
		}
	}
	// IPinfo standard format: "org": "AS13335 Cloudflare, Inc."
	if info.ASN == "" {
		if v, ok := raw["org"]; ok {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "AS") {
				parts := strings.SplitN(s, " ", 2)
				info.ASN = parts[0]
				if len(parts) > 1 {
					info.Org = parts[1]
				}
			}
		}
	}

	// Organization — try provider-specific fields.
	// IPinfo Lite: "as_name": "Google LLC"
	// ip-api: "isp" or "org"
	// ip-api: "asname"
	if info.Org == "" {
		for _, f := range []string{"as_name", "org", "isp", "organization", "asname"} {
			if v, ok := raw[f]; ok {
				if s, ok := v.(string); ok && s != "" && !strings.HasPrefix(s, "AS") {
					info.Org = s
					break
				}
			}
		}
	}

	// Network — ip-api uses no network field, but we can try common ones
	for _, f := range []string{"network", "net"} {
		if v, ok := raw[f]; ok {
			if s, ok := v.(string); ok && s != "" {
				info.Network = s
				break
			}
		}
	}

	// AS domain — IPinfo Lite provides this.
	if v, ok := raw["as_domain"]; ok {
		if s, ok := v.(string); ok && s != "" {
			info.ASDomain = s
		}
	}

	// Continent — IPinfo Lite provides this.
	if v, ok := raw["continent"]; ok {
		if s, ok := v.(string); ok && s != "" {
			info.Continent = s
		}
	}

	return info
}

// evictRandom removes ~25% of cache entries. Map iteration order is random in Go,
// so this is effectively random eviction — acceptable for a country-code cache
// where re-derivation is cheap. Caller must hold s.mu write lock.
func (s *GeoIPStore) evictRandom() {
	target := geoCacheMaxSize / 4
	// Map iteration order is random in Go, so deleting the first N entries
	// we encounter is effectively random eviction.
	deleted := 0
	for k := range s.cache {
		if deleted >= target {
			break
		}
		delete(s.cache, k)
		deleted++
	}
}

// TopCountries returns the top N countries by request count from the given events.
func TopCountries(events []Event, n int) []CountryCount {
	counts := make(map[string]*CountryCount)
	for i := range events {
		cc := events[i].Country
		if cc == "" {
			cc = "XX" // unknown
		}
		entry, ok := counts[cc]
		if !ok {
			entry = &CountryCount{Country: cc}
			counts[cc] = entry
		}
		entry.Count++
		if events[i].IsBlocked {
			entry.TotalBlocked++
		}
	}

	result := make([]CountryCount, 0, len(counts))
	for _, v := range counts {
		result = append(result, *v)
	}

	// Sort by count descending.
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	if n > 0 && len(result) > n {
		result = result[:n]
	}
	return result
}
