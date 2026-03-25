package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
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
// UUIDs, numeric IDs, hex strings >= 8 chars, base64 tokens >= 16 chars,
// date segments (YYYY-MM-DD), and file hashes in filenames.
var pathIDRegex = regexp.MustCompile(
	`(?i)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` + // UUID
		`|/\d{4}-\d{2}-\d{2}` + // date YYYY-MM-DD
		`|/\d+` + // numeric ID
		`|/[0-9a-f]{8,}` + // hex string >= 8 chars
		`|/[A-Za-z0-9_-]{16,}(?:\.[a-z]{2,5})?`, // base64/token >= 16 chars (with optional ext)
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

// ─── OpenAPI Schema Support ─────────────────────────────────────────
//
// When an OpenAPI spec is loaded, paths are matched against the schema's
// route templates instead of using heuristic normalization. This provides
// accurate endpoint grouping for APIs with documented routes.

// openAPISchema holds a parsed OpenAPI spec (v2/v3 — only paths are used).
type openAPISchema struct {
	// templates are compiled route patterns from the spec, e.g. "/api/v3/command".
	// Each entry has a regex compiled from the OpenAPI path template and the
	// original template string for display.
	templates []openAPIRoute
}

type openAPIRoute struct {
	method   string         // uppercase HTTP method, "" = any method
	template string         // original template e.g. "/api/v3/episode/{id}"
	regex    *regexp.Regexp // compiled from template with {param} → [^/]+
}

// openAPISchemaStore holds loaded schemas keyed by service name.
type openAPISchemaStore struct {
	mu      sync.RWMutex
	schemas map[string]*openAPISchema // service name → schema
}

var globalOpenAPIStore = &openAPISchemaStore{
	schemas: make(map[string]*openAPISchema),
}

// parseOpenAPISpec extracts route templates from an OpenAPI v2 or v3 spec.
// It reads only the paths object — no validation, no dereferencing.
func parseOpenAPISpec(data []byte) (*openAPISchema, error) {
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, err
	}

	schema := &openAPISchema{}
	paramRe := regexp.MustCompile(`\{[^}]+\}`)

	for pathTemplate, methods := range spec.Paths {
		// Convert OpenAPI path template to regex: /api/{id}/items → /api/[^/]+/items
		pattern := "^" + paramRe.ReplaceAllString(regexp.QuoteMeta(pathTemplate), `[^/]+`) + "$"
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue // skip malformed patterns
		}

		for method := range methods {
			method = strings.ToUpper(method)
			// Skip non-HTTP keys like "parameters", "summary", etc.
			switch method {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
				schema.templates = append(schema.templates, openAPIRoute{
					method:   method,
					template: pathTemplate,
					regex:    re,
				})
			}
		}
	}

	// Sort longest templates first so more specific routes match before general ones.
	sort.Slice(schema.templates, func(i, j int) bool {
		return len(schema.templates[i].template) > len(schema.templates[j].template)
	})

	return schema, nil
}

// matchPath tries to match a raw path against OpenAPI route templates.
// Returns the template string if matched, or empty string if no match.
func (s *openAPISchema) matchPath(method, path string) string {
	if s == nil {
		return ""
	}
	for _, route := range s.templates {
		if route.method != "" && route.method != method {
			continue
		}
		if route.regex.MatchString(path) {
			return route.template
		}
	}
	return ""
}

// LoadOpenAPISchema loads an OpenAPI spec from a file for a given service.
func (store *openAPISchemaStore) LoadFromFile(service, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	schema, err := parseOpenAPISpec(data)
	if err != nil {
		return err
	}
	store.mu.Lock()
	store.schemas[service] = schema
	store.mu.Unlock()
	return nil
}

// Get returns the schema for a service, or nil.
func (store *openAPISchemaStore) Get(service string) *openAPISchema {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.schemas[service]
}

// ListServices returns all services with loaded schemas.
func (store *openAPISchemaStore) ListServices() []string {
	store.mu.RLock()
	defer store.mu.RUnlock()
	services := make([]string, 0, len(store.schemas))
	for s := range store.schemas {
		services = append(services, s)
	}
	sort.Strings(services)
	return services
}

// Delete removes a loaded schema for a service.
func (store *openAPISchemaStore) Delete(service string) {
	store.mu.Lock()
	delete(store.schemas, service)
	store.mu.Unlock()
}

// normalizePathWithSchema attempts schema-based normalization first, then
// falls back to the heuristic regex normalization.
func normalizePathWithSchema(method, rawPath, service string) string {
	// Strip query/fragment first.
	path := rawPath
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if idx := strings.IndexByte(path, '#'); idx >= 0 {
		path = path[:idx]
	}

	// Try OpenAPI schema match.
	if schema := globalOpenAPIStore.Get(service); schema != nil {
		if template := schema.matchPath(method, path); template != "" {
			return template
		}
	}

	// Fallback to heuristic normalization.
	return normalizePath(rawPath)
}

// ─── Non-browser detection ──────────────────────────────────────────

// isNonBrowserJA4 checks the JA4 ALPN field. Real browsers negotiate
// h2 or h3. JA4 format: "t13d1516h2_..." — chars at position 8:10 are ALPN.
// "00" = no ALPN, "h1" = HTTP/1.1 only → likely non-browser.
func isNonBrowserJA4(ja4 string) bool {
	if ja4 == "" {
		return false // no JA4 = can't tell
	}
	parts := strings.SplitN(ja4, "_", 2)
	if len(parts) == 0 || len(parts[0]) < 10 {
		return false
	}
	alpn := parts[0][8:10]
	return alpn == "00" || alpn == "h1"
}

// nonBrowserUAPatterns are User-Agent substrings that indicate non-browser clients.
var nonBrowserUAPatterns = []string{
	"curl/", "wget/", "python-requests/", "python-urllib/", "httpie/",
	"go-http-client/", "java/", "apache-httpclient/", "okhttp/",
	"node-fetch/", "axios/", "undici/", "got/",
	"libwww-perl/", "ruby/", "php/", "guzzlehttp/",
	"postman", "insomnia/", "httpx/",
	"bot", "spider", "crawler", "scraper",
	"prometheus/", "grafana/", "telegraf/", "datadog",
	"health", "monitor", "check", "uptime",
}

// isNonBrowserUA checks if a User-Agent string looks like a non-browser client.
func isNonBrowserUA(ua string) bool {
	if ua == "" {
		return true // empty UA = almost certainly non-browser
	}
	lower := strings.ToLower(ua)
	for _, pattern := range nonBrowserUAPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// isNonBrowser checks JA4 ALPN first, then falls back to User-Agent heuristics.
func isNonBrowser(ja4, ua string) bool {
	if ja4 != "" {
		return isNonBrowserJA4(ja4)
	}
	return isNonBrowserUA(ua)
}

// apiPathPrefixes are URL path prefixes that strongly indicate API endpoints.
var apiPathPrefixes = []string{
	"/api/", "/graphql", "/v1/", "/v2/", "/v3/", "/v4/",
	"/.well-known/", "/oauth/", "/auth/", "/token",
	"/webhook", "/rpc/", "/jsonrpc",
}

// apiPathSuffixes are URL suffixes that indicate non-browser resources.
var apiPathSuffixes = []string{
	".json", ".xml", ".yaml", ".yml", ".csv", ".rss", ".atom",
}

// isAPIPath checks if a normalized path looks like an API endpoint.
func isAPIPath(path string) bool {
	lower := strings.ToLower(path)
	for _, prefix := range apiPathPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, suffix := range apiPathSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// classifyEndpointNonBrowser computes a non-browser score for an endpoint
// using multiple signals. Returns a value in [0.0, 1.0].
//
// Signals:
//   - Per-request JA4/UA classification (existing isNonBrowser)
//   - Path heuristics (paths that look like API endpoints)
//   - Behavioral: low UA diversity relative to request count indicates automation
//   - Method: DELETE/PUT/PATCH are almost never browser-initiated
func classifyEndpointNonBrowser(path, method string, requests, nonBrowserCount, uniqueUAs int) float64 {
	if requests == 0 {
		return 0
	}

	// Start with the per-request classification ratio.
	perRequestPct := float64(nonBrowserCount) / float64(requests)

	// Path heuristic: API-looking paths get a boost.
	pathBoost := 0.0
	if isAPIPath(path) {
		pathBoost = 0.6
	}

	// Method heuristic: non-GET/HEAD/OPTIONS methods from browsers are rare.
	methodBoost := 0.0
	switch method {
	case "DELETE", "PUT", "PATCH":
		methodBoost = 0.7
	case "POST":
		// POST is ambiguous — browsers do POST for forms.
		// Only boost if path also looks like API.
		if isAPIPath(path) {
			methodBoost = 0.4
		}
	}

	// Behavioral: low UA diversity relative to request count.
	// Browsers hitting an endpoint 30+ times would show varied UAs (updates, different sessions).
	// A single UA making 30 requests is clearly a bot/API client.
	behaviorBoost := 0.0
	if requests >= 10 && uniqueUAs <= 1 {
		behaviorBoost = 0.5
	} else if requests >= 20 && uniqueUAs <= 2 {
		behaviorBoost = 0.3
	}

	// Combine signals — take the maximum of (per-request, heuristic composite).
	heuristicScore := pathBoost
	if methodBoost > heuristicScore {
		heuristicScore = methodBoost
	}
	// Behavioral evidence strengthens the heuristic but doesn't override clean per-request data.
	heuristicScore = heuristicScore + behaviorBoost*0.5
	if heuristicScore > 1.0 {
		heuristicScore = 1.0
	}

	// Use the higher of per-request classification and heuristic score.
	if perRequestPct > heuristicScore {
		return perRequestPct
	}
	return heuristicScore
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

func (s *GeneralLogStore) DiscoverEndpoints(hours int, filterService string, rules []RuleExclusion) EndpointDiscoveryResponse {
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

		path := normalizePathWithSchema(e.Method, e.URI, e.Service)
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
		if isNonBrowser(e.JA4, e.UserAgent) {
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

		nonBrowserPct := classifyEndpointNonBrowser(
			key.path, key.method,
			agg.requests, agg.nonBrowser, len(agg.uas),
		)

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
// Uses GeneralLogStore (all traffic) instead of AccessLogStore (security events only)
// to get accurate request counts and non-browser % for all endpoints.
func handleEndpointDiscovery(gls *GeneralLogStore, excStore *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if v, err := strconv.Atoi(h); err == nil && v > 0 {
				hours = v
			}
		}
		service := r.URL.Query().Get("service")
		rules := excStore.List()
		resp := gls.DiscoverEndpoints(hours, service, rules)
		writeJSON(w, http.StatusOK, resp)
	}
}

// ─── OpenAPI Schema Management Handlers ─────────────────────────────

// handleOpenAPISchemas serves GET /api/discovery/schemas — list loaded schemas.
func handleListOpenAPISchemas() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		services := globalOpenAPIStore.ListServices()
		schemas := make([]map[string]interface{}, 0, len(services))
		for _, svc := range services {
			schema := globalOpenAPIStore.Get(svc)
			schemas = append(schemas, map[string]interface{}{
				"service": svc,
				"routes":  len(schema.templates),
			})
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"schemas": schemas,
		})
	}
}

// handleUploadOpenAPISchema serves PUT /api/discovery/schemas/{service}.
// Accepts a JSON or YAML OpenAPI spec body. Only JSON is currently supported.
func handleUploadOpenAPISchema() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		service := r.PathValue("service")
		if service == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "service name required"})
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 5*1024*1024)) // 5 MB limit
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "failed to read body", Details: err.Error()})
			return
		}

		schema, err := parseOpenAPISpec(body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "failed to parse OpenAPI spec", Details: err.Error()})
			return
		}

		if len(schema.templates) == 0 {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "no valid paths found in spec"})
			return
		}

		globalOpenAPIStore.mu.Lock()
		globalOpenAPIStore.schemas[service] = schema
		globalOpenAPIStore.mu.Unlock()

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"service": service,
			"routes":  len(schema.templates),
			"message": "schema loaded successfully",
		})
	}
}

// handleDeleteOpenAPISchema serves DELETE /api/discovery/schemas/{service}.
func handleDeleteOpenAPISchema() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		service := r.PathValue("service")
		if service == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "service name required"})
			return
		}

		globalOpenAPIStore.Delete(service)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message": "schema removed",
		})
	}
}
