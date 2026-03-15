package main

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// --- Handlers: Analytics ---

func handleTopBlockedIPs(store *Store, als *AccessLogStore) http.HandlerFunc {
	cache := newResponseCache(20)
	return func(w http.ResponseWriter, r *http.Request) {
		gen := combinedGeneration(&store.generation, &als.generation)
		cacheKey := normalizeCacheKey(r.URL.RawQuery)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
		tr := parseTimeRange(r)
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		// Use WAF events (snapshot) + raw ALS events (no enrichment needed —
		// topBlockedIPs only reads ClientIP, IsBlocked, Country, Timestamp).
		wafEvents := getWAFEvents(store, tr, hours)
		rlRaw := getRawRLSnapshot(als, tr, hours)
		result := topBlockedIPsMixed(wafEvents, rlRaw, limit)
		cache.set(cacheKey, result, gen, 10*time.Second)
		writeJSON(w, http.StatusOK, result)
	}
}

func handleTopTargetedURIs(store *Store, als *AccessLogStore) http.HandlerFunc {
	cache := newResponseCache(20)
	return func(w http.ResponseWriter, r *http.Request) {
		gen := combinedGeneration(&store.generation, &als.generation)
		cacheKey := normalizeCacheKey(r.URL.RawQuery)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
		tr := parseTimeRange(r)
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		// Use WAF events (snapshot) + raw ALS events (no enrichment needed —
		// topTargetedURIs only reads URI, IsBlocked, Service).
		wafEvents := getWAFEvents(store, tr, hours)
		rlRaw := getRawRLSnapshot(als, tr, hours)
		result := topTargetedURIsMixed(wafEvents, rlRaw, limit)
		cache.set(cacheKey, result, gen, 10*time.Second)
		writeJSON(w, http.StatusOK, result)
	}
}

func handleTopCountries(store *Store, als *AccessLogStore) http.HandlerFunc {
	cache := newResponseCache(20)
	return func(w http.ResponseWriter, r *http.Request) {
		gen := combinedGeneration(&store.generation, &als.generation)
		cacheKey := normalizeCacheKey(r.URL.RawQuery)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
		tr := parseTimeRange(r)
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}

		// Fast path: use incremental counters when no absolute time range.
		// TopCountries is already computed by FastSummary — O(buckets) vs O(events).
		if !tr.Valid {
			wafSummary := store.FastSummary(hours)
			alsSummary := als.FastSummary(hours)
			merged := mergeSummaryResponses(wafSummary, alsSummary)
			result := merged.TopCountries
			if len(result) > limit {
				result = result[:limit]
			}
			cache.set(cacheKey, result, gen, 10*time.Second)
			writeJSON(w, http.StatusOK, result)
			return
		}

		// Fallback: absolute time range — use raw ALS events (no enrichment).
		wafEvents := getWAFEvents(store, tr, hours)
		rlRaw := getRawRLSnapshot(als, tr, hours)
		result := topCountriesMixed(wafEvents, rlRaw, limit)
		cache.set(cacheKey, result, gen, 10*time.Second)
		writeJSON(w, http.StatusOK, result)
	}
}

// --- Handler: IP Lookup ---

func handleIPLookup(store *Store, als *AccessLogStore, geo *GeoIPStore, intel *IPIntelStore) http.HandlerFunc {
	cache := newResponseCache(50)
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.PathValue("ip")
		if ip == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "IP address is required"})
			return
		}
		// Basic IP validation.
		if net.ParseIP(ip) == nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid IP address"})
			return
		}

		gen := combinedGeneration(&store.generation, &als.generation)
		cacheKey := ip + ":" + normalizeCacheKey(r.URL.RawQuery)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		q := r.URL.Query()
		tr := parseTimeRange(r)
		hours := parseHours(r)
		limit := queryInt(q.Get("limit"), 50)
		if limit <= 0 || limit > 1000 {
			limit = 50
		}
		offset := queryInt(q.Get("offset"), 0)
		if offset < 0 {
			offset = 0
		}

		// Merge WAF events + access log events (rate_limited, ipsum_blocked).
		rlEvents := getRLEvents(als, tr, hours, nil)
		result := store.IPLookupRange(ip, tr, hours, limit, offset, rlEvents)

		// Skip expensive intelligence lookups when paginating (offset > 0).
		// The frontend already has GeoIP/intel from the first page.
		skipIntel := q.Get("skip_intel") == "true" || offset > 0
		if !skipIntel {
			// Enrich with GeoIP information.
			if geo != nil {
				result.GeoIP = geo.LookupFull(ip, "")
			}
			// Enrich with IP intelligence (routing, reputation, Shodan).
			if intel != nil {
				result.Intelligence = intel.Lookup(ip)
			}
		}

		cache.set(cacheKey, result, gen, 10*time.Second)
		writeJSON(w, http.StatusOK, result)
	}
}

// --- Policy rule name helpers ---

// matchesPolicyRuleName checks whether an event was triggered by a policy
// exclusion with the given name.  It scans the matched_rules for a msg
// containing "Policy Allow/Skip/Block: <name>".
func matchesPolicyRuleName(ev *Event, name string) bool {
	if name == "" {
		return false
	}
	for _, mr := range ev.MatchedRules {
		if extractPolicyName(mr.Msg) == name {
			return true
		}
	}
	return false
}

// matchesPolicyRuleNameFilter checks whether an event's policy rule name
// matches the given fieldFilter (supporting eq, neq, contains, regex, in).
func matchesPolicyRuleNameFilter(ev *Event, f *fieldFilter) bool {
	for _, mr := range ev.MatchedRules {
		name := extractPolicyName(mr.Msg)
		if name != "" && f.matchField(name) {
			return true
		}
	}
	return false
}

// policyPrefixes are the known prefixes for policy rule msg strings.
// Declared at package level to avoid per-call allocation.
var policyPrefixes = []string{"Policy Allow: ", "Policy Skip: ", "Policy Block: "}

// extractPolicyName extracts the exclusion name from a policy rule msg string.
// Expected formats: "Policy Allow: <name>", "Policy Skip: <name>", "Policy Block: <name>"
func extractPolicyName(msg string) string {
	for _, p := range policyPrefixes {
		if strings.HasPrefix(msg, p) {
			return msg[len(p):]
		}
	}
	return ""
}
