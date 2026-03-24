package main

import (
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ─── Endpoint Discovery ─────────────────────────────────────────────
//
// Aggregates traffic by (service, method, path) to show operators their
// API surface, which paths are covered by challenge/rate-limit rules,
// and which paths have suspicious non-browser traffic.

// DiscoveredEndpoint represents a unique endpoint observed in traffic.
type DiscoveredEndpoint struct {
	Service       string      `json:"service"`
	Method        string      `json:"method"`
	Path          string      `json:"path"`
	Requests      int         `json:"requests"`
	UniqueIPs     int         `json:"unique_ips"`
	UniqueJA4s    int         `json:"unique_ja4s"`
	UniqueUAs     int         `json:"unique_uas"`
	NonBrowserPct float64     `json:"non_browser_pct"`
	HasChallenge  bool        `json:"has_challenge"`
	HasRateLimit  bool        `json:"has_rate_limit"`
	TopJA4        string      `json:"top_ja4,omitempty"`
	StatusCodes   map[int]int `json:"status_codes,omitempty"`
}

// EndpointDiscoveryResponse is the response for GET /api/discovery/endpoints.
type EndpointDiscoveryResponse struct {
	Endpoints     []DiscoveredEndpoint `json:"endpoints"`
	TotalRequests int                  `json:"total_requests"`
	TotalPaths    int                  `json:"total_paths"`
	UncoveredPct  float64              `json:"uncovered_pct"`
}

// ─── Path normalization ─────────────────────────────────────────────

// pathIDRegex matches path segments that look like IDs:
// UUIDs, numeric IDs, hex strings >= 8 chars.
var pathIDRegex = regexp.MustCompile(
	`(?i)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` + // UUID
		`|/\d+` + // numeric ID
		`|/[0-9a-f]{8,}`, // hex string >= 8 chars
)

// normalizePath collapses dynamic segments into {id} and strips query strings.
func normalizePath(raw string) string {
	// Strip query string.
	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		raw = raw[:idx]
	}
	// Strip fragment.
	if idx := strings.IndexByte(raw, '#'); idx >= 0 {
		raw = raw[:idx]
	}
	// Collapse IDs.
	normalized := pathIDRegex.ReplaceAllStringFunc(raw, func(match string) string {
		// Preserve the leading slash.
		return "/{id}"
	})
	// Collapse repeated {id} segments.
	for strings.Contains(normalized, "/{id}/{id}") {
		normalized = strings.ReplaceAll(normalized, "/{id}/{id}", "/{id}")
	}
	if normalized == "" {
		normalized = "/"
	}
	return normalized
}

// ─── Non-browser detection ──────────────────────────────────────────

// isNonBrowserJA4 checks the JA4 ALPN field. Real browsers negotiate
// h2 or h3. JA4 format: "t13d1516h2_..." — chars at position 8:10 are ALPN.
// "00" = no ALPN, "h1" = HTTP/1.1 only → likely non-browser.
func isNonBrowserJA4(ja4 string) bool {
	if ja4 == "" {
		return false // no JA4 = can't tell, assume browser
	}
	parts := strings.SplitN(ja4, "_", 2)
	if len(parts) == 0 || len(parts[0]) < 10 {
		return false
	}
	alpn := parts[0][8:10]
	return alpn == "00" || alpn == "h1"
}

// ─── Rule coverage check ────────────────────────────────────────────

type ruleCoverage struct {
	challengePaths map[string]bool // normalized paths covered by challenge rules
	rateLimitPaths map[string]bool // normalized paths covered by rate limit rules
	challengeAll   bool            // a catch-all challenge rule exists (e.g., path begins_with /)
	rateLimitAll   bool
}

func buildRuleCoverage(rules []RuleExclusion) ruleCoverage {
	rc := ruleCoverage{
		challengePaths: make(map[string]bool),
		rateLimitPaths: make(map[string]bool),
	}

	for _, r := range rules {
		if !r.Enabled {
			continue
		}

		isChallenge := r.Type == "challenge"
		isRateLimit := r.Type == "rate_limit"
		if !isChallenge && !isRateLimit {
			continue
		}

		for _, c := range r.Conditions {
			if c.Field != "path" {
				continue
			}
			path := normalizePath(c.Value)
			switch c.Operator {
			case "begins_with":
				if c.Value == "/" || c.Value == "" {
					// Covers everything.
					if isChallenge {
						rc.challengeAll = true
					}
					if isRateLimit {
						rc.rateLimitAll = true
					}
				}
				// For begins_with, we mark the prefix and check with HasPrefix later.
				if isChallenge {
					rc.challengePaths[path] = true
				}
				if isRateLimit {
					rc.rateLimitPaths[path] = true
				}
			case "eq", "contains":
				if isChallenge {
					rc.challengePaths[path] = true
				}
				if isRateLimit {
					rc.rateLimitPaths[path] = true
				}
			}
		}
	}

	return rc
}

func (rc *ruleCoverage) isChallenged(path string) bool {
	if rc.challengeAll {
		return true
	}
	if rc.challengePaths[path] {
		return true
	}
	// Check begins_with prefixes.
	for prefix := range rc.challengePaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (rc *ruleCoverage) isRateLimited(path string) bool {
	if rc.rateLimitAll {
		return true
	}
	if rc.rateLimitPaths[path] {
		return true
	}
	for prefix := range rc.rateLimitPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// ─── Discovery aggregation ──────────────────────────────────────────

func (s *AccessLogStore) DiscoverEndpoints(hours int, filterService string, rules []RuleExclusion) EndpointDiscoveryResponse {
	events := s.snapshotSince(hours)
	rc := buildRuleCoverage(rules)

	type endpointKey struct {
		service, method, path string
	}
	type endpointAgg struct {
		requests    int
		ips         map[string]struct{}
		ja4s        map[string]struct{}
		uas         map[string]struct{}
		nonBrowser  int
		statusCodes map[int]int
		ja4Counts   map[string]int // for top JA4
	}

	endpoints := make(map[endpointKey]*endpointAgg)
	totalRequests := 0

	for _, e := range events {
		if filterService != "" && e.Service != filterService {
			continue
		}

		path := normalizePath(e.URI)
		key := endpointKey{service: e.Service, method: e.Method, path: path}

		agg, ok := endpoints[key]
		if !ok {
			agg = &endpointAgg{
				ips:         make(map[string]struct{}),
				ja4s:        make(map[string]struct{}),
				uas:         make(map[string]struct{}),
				statusCodes: make(map[int]int),
				ja4Counts:   make(map[string]int),
			}
			endpoints[key] = agg
		}

		agg.requests++
		totalRequests++
		agg.ips[e.ClientIP] = struct{}{}
		if e.JA4 != "" {
			agg.ja4s[e.JA4] = struct{}{}
			agg.ja4Counts[e.JA4]++
		}
		if e.UserAgent != "" {
			agg.uas[e.UserAgent] = struct{}{}
		}
		if isNonBrowserJA4(e.JA4) {
			agg.nonBrowser++
		}
		if e.Status > 0 {
			agg.statusCodes[e.Status]++
		}
	}

	// Build response.
	result := make([]DiscoveredEndpoint, 0, len(endpoints))
	uncoveredRequests := 0

	for key, agg := range endpoints {
		// Find top JA4.
		var topJA4 string
		topJA4Count := 0
		for ja4, count := range agg.ja4Counts {
			if count > topJA4Count {
				topJA4 = ja4
				topJA4Count = count
			}
		}

		nonBrowserPct := 0.0
		if agg.requests > 0 {
			nonBrowserPct = float64(agg.nonBrowser) / float64(agg.requests)
		}

		hasCh := rc.isChallenged(key.path)
		hasRL := rc.isRateLimited(key.path)

		if !hasCh {
			uncoveredRequests += agg.requests
		}

		ep := DiscoveredEndpoint{
			Service:       key.service,
			Method:        key.method,
			Path:          key.path,
			Requests:      agg.requests,
			UniqueIPs:     len(agg.ips),
			UniqueJA4s:    len(agg.ja4s),
			UniqueUAs:     len(agg.uas),
			NonBrowserPct: nonBrowserPct,
			HasChallenge:  hasCh,
			HasRateLimit:  hasRL,
			TopJA4:        topJA4,
		}
		// Only include status codes if there's interesting diversity.
		if len(agg.statusCodes) > 1 {
			ep.StatusCodes = agg.statusCodes
		}

		result = append(result, ep)
	}

	// Sort by request count descending.
	sort.Slice(result, func(i, j int) bool {
		return result[i].Requests > result[j].Requests
	})

	// Limit to top 100.
	if len(result) > 100 {
		result = result[:100]
	}

	uncoveredPct := 0.0
	if totalRequests > 0 {
		uncoveredPct = float64(uncoveredRequests) / float64(totalRequests)
	}

	return EndpointDiscoveryResponse{
		Endpoints:     result,
		TotalRequests: totalRequests,
		TotalPaths:    len(endpoints),
		UncoveredPct:  uncoveredPct,
	}
}

// handleEndpointDiscovery serves GET /api/discovery/endpoints?hours=24&service=x.
func handleEndpointDiscovery(als *AccessLogStore, excStore *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if v, err := strconv.Atoi(h); err == nil && v > 0 {
				hours = v
			}
		}
		service := r.URL.Query().Get("service")
		rules := excStore.List()
		resp := als.DiscoverEndpoints(hours, service, rules)
		writeJSON(w, http.StatusOK, resp)
	}
}
