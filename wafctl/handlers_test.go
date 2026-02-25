package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthEndpoint(t *testing.T) {
	handler := testHealthHandler(t)
	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp HealthResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != "ok" {
		t.Errorf("status: want ok, got %s", resp.Status)
	}
	if resp.Version != version {
		t.Errorf("version: want %s, got %s", version, resp.Version)
	}
	if resp.Uptime == "" {
		t.Error("uptime should not be empty")
	}
	if resp.Stores == nil {
		t.Fatal("stores should not be nil")
	}
	// Verify subsystem keys exist.
	for _, key := range []string{"waf_events", "access_events", "geoip", "exclusions", "blocklist"} {
		if _, ok := resp.Stores[key]; !ok {
			t.Errorf("stores missing key %q", key)
		}
	}
}

// emptyAccessLogStore returns an AccessLogStore with no events for tests that
// don't care about 429 merging.

func TestSummaryEndpoint(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()
	als := emptyAccessLogStore(t)

	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()
	handleSummary(store, als)(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: want application/json, got %s", ct)
	}

	var resp SummaryResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.TotalEvents != 3 {
		t.Errorf("total: want 3, got %d", resp.TotalEvents)
	}
	if resp.RateLimited != 0 {
		t.Errorf("rate_limited: want 0 (no 429s), got %d", resp.RateLimited)
	}
}

func TestEventsEndpointWithFilters(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()
	als := emptyAccessLogStore(t)

	req := httptest.NewRequest("GET", "/api/events?service=radarr.erfi.io&blocked=true&limit=10", nil)
	w := httptest.NewRecorder()
	handleEvents(store, als)(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp EventsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 1 {
		t.Errorf("want 1 blocked event for radarr, got %d", resp.Total)
	}
}

func TestCORSHeadersWildcard(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", testHealthHandler(t))
	handler := newCORSMiddleware([]string{"*"})(mux)

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Errorf("CORS origin: want *, got %s", origin)
	}

	methods := w.Header().Get("Access-Control-Allow-Methods")
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		if !strings.Contains(methods, m) {
			t.Errorf("CORS methods missing %s, got %s", m, methods)
		}
	}
}

func TestCORSHeadersAllowedOrigin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", testHealthHandler(t))
	handler := newCORSMiddleware([]string{"https://waf.erfi.io", "https://dash.erfi.io"})(mux)

	// Allowed origin.
	req := httptest.NewRequest("GET", "/api/health", nil)
	req.Header.Set("Origin", "https://waf.erfi.io")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "https://waf.erfi.io" {
		t.Errorf("CORS allowed origin: want https://waf.erfi.io, got %s", origin)
	}
	if vary := w.Header().Get("Vary"); vary != "Origin" {
		t.Errorf("Vary header: want Origin, got %s", vary)
	}

	// Disallowed origin — no CORS header set.
	req = httptest.NewRequest("GET", "/api/health", nil)
	req.Header.Set("Origin", "https://evil.com")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "" {
		t.Errorf("CORS disallowed origin: want empty, got %s", origin)
	}
}

func TestCORSPreflightAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", testHealthHandler(t))
	handler := newCORSMiddleware([]string{"https://waf.erfi.io"})(mux)

	req := httptest.NewRequest("OPTIONS", "/api/health", nil)
	req.Header.Set("Origin", "https://waf.erfi.io")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("preflight allowed: want 204, got %d", w.Code)
	}
}

func TestCORSPreflightRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", testHealthHandler(t))
	handler := newCORSMiddleware([]string{"https://waf.erfi.io"})(mux)

	req := httptest.NewRequest("OPTIONS", "/api/health", nil)
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("preflight rejected: want 403, got %d", w.Code)
	}
}

func TestCORSPreflightWildcard(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", testHealthHandler(t))
	handler := newCORSMiddleware([]string{"*"})(mux)

	req := httptest.NewRequest("OPTIONS", "/api/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("preflight wildcard: want 204, got %d", w.Code)
	}
}

func TestMissingLogFile(t *testing.T) {
	store := NewStore("/nonexistent/path/audit.log")
	store.Load() // should not panic
	if got := store.EventCount(); got != 0 {
		t.Errorf("want 0 events for missing file, got %d", got)
	}
}

// --- IP Lookup tests ---

// --- IP Lookup tests ---

func TestIPLookup(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	result := store.IPLookup("10.0.0.1", 0)
	if result.Total != 2 {
		t.Errorf("want 2 events for 10.0.0.1, got %d", result.Total)
	}
	if result.Blocked != 1 {
		t.Errorf("want 1 blocked for 10.0.0.1, got %d", result.Blocked)
	}
	if result.FirstSeen == nil || result.LastSeen == nil {
		t.Fatal("first_seen/last_seen should not be nil")
	}
	if len(result.Services) != 1 {
		t.Errorf("want 1 service for 10.0.0.1, got %d", len(result.Services))
	}
}

func TestIPLookupEndpoint(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/lookup/{ip}", handleIPLookup(store))

	req := httptest.NewRequest("GET", "/api/lookup/10.0.0.1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp IPLookupResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 2 {
		t.Errorf("want 2 events, got %d", resp.Total)
	}
}

func TestIPLookupEndpointInvalidIP(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/lookup/{ip}", handleIPLookup(store))

	req := httptest.NewRequest("GET", "/api/lookup/not-an-ip", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("want 400 for invalid IP, got %d", w.Code)
	}
}

func TestIPLookupNoResults(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	result := store.IPLookup("192.168.1.1", 0)
	if result.Total != 0 {
		t.Errorf("want 0 events for unknown IP, got %d", result.Total)
	}
	if result.FirstSeen != nil || result.LastSeen != nil {
		t.Error("first_seen/last_seen should be nil for unknown IP")
	}
}

// --- Hours filter tests ---

// --- Hours filter tests ---

func TestParseHours(t *testing.T) {
	tests := []struct {
		query string
		want  int
	}{
		{"", 0},
		{"hours=24", 24},
		{"hours=1", 1},
		{"hours=6", 6},
		{"hours=72", 72},
		{"hours=168", 168},
		{"hours=12", 0},  // invalid value
		{"hours=abc", 0}, // not a number
		{"hours=-1", 0},  // negative
	}

	for _, tt := range tests {
		url := "/api/test"
		if tt.query != "" {
			url += "?" + tt.query
		}
		req := httptest.NewRequest("GET", url, nil)
		got := parseHours(req)
		if got != tt.want {
			t.Errorf("parseHours(%q): want %d, got %d", tt.query, tt.want, got)
		}
	}
}

func TestSummaryEndpointWithHours(t *testing.T) {
	// Create events with timestamps that are definitely old (>168h ago).
	oldLines := []string{
		`{"transaction":{"timestamp":"2020/01/01 00:00:00","unix_timestamp":1577836800000000000,"id":"OLD1","client_ip":"1.1.1.1","client_port":0,"host_ip":"","host_port":0,"server_id":"test.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/old","http_version":"","headers":{"User-Agent":["old-agent"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":200,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":[]},"highest_severity":"","is_interrupted":false}}`,
	}
	path := writeTempLog(t, oldLines)
	store := NewStore(path)
	store.Load()
	als := emptyAccessLogStore(t)

	// hours=1 should filter out old events.
	req := httptest.NewRequest("GET", "/api/summary?hours=1", nil)
	w := httptest.NewRecorder()
	handleSummary(store, als)(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp SummaryResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.TotalEvents != 0 {
		t.Errorf("want 0 events with hours=1 for old data, got %d", resp.TotalEvents)
	}

	// Without hours filter, should get all events.
	req = httptest.NewRequest("GET", "/api/summary", nil)
	w = httptest.NewRecorder()
	handleSummary(store, als)(w, req)

	json.NewDecoder(w.Body).Decode(&resp)
	if resp.TotalEvents != 1 {
		t.Errorf("want 1 event without filter, got %d", resp.TotalEvents)
	}
}

// --- Exclusion Store tests ---

// --- Analytics endpoint tests ---

func TestTopBlockedIPs(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	result := store.TopBlockedIPs(0, 10)

	// sampleLines: AAA111 (195.240.81.42) blocked, BBB222 (10.0.0.1) blocked, CCC333 (10.0.0.1) not blocked
	// So 10.0.0.1 has 1 blocked out of 2 total, 195.240.81.42 has 1 blocked out of 1 total
	if len(result) != 2 {
		t.Fatalf("expected 2 IPs with blocks, got %d", len(result))
	}

	// Both have 1 block, but sort is by blocked count then it's stable-ish
	found42 := false
	found001 := false
	for _, ip := range result {
		switch ip.ClientIP {
		case "195.240.81.42":
			found42 = true
			if ip.Total != 1 || ip.Blocked != 1 {
				t.Errorf("195.240.81.42: expected total=1 blocked=1, got total=%d blocked=%d", ip.Total, ip.Blocked)
			}
			if ip.BlockRate != 100 {
				t.Errorf("195.240.81.42: expected block_rate=100, got %f", ip.BlockRate)
			}
		case "10.0.0.1":
			found001 = true
			if ip.Total != 2 || ip.Blocked != 1 {
				t.Errorf("10.0.0.1: expected total=2 blocked=1, got total=%d blocked=%d", ip.Total, ip.Blocked)
			}
			if ip.BlockRate != 50 {
				t.Errorf("10.0.0.1: expected block_rate=50, got %f", ip.BlockRate)
			}
		}
	}
	if !found42 || !found001 {
		t.Error("missing expected IPs in results")
	}
}

func TestTopBlockedIPsLimit(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	result := store.TopBlockedIPs(0, 1)
	if len(result) != 1 {
		t.Fatalf("expected 1 IP (limit=1), got %d", len(result))
	}
}

func TestTopTargetedURIs(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	result := store.TopTargetedURIs(0, 10)

	// URIs: /socket.io/?EIO=4, /.env, /api/v3/queue — each with 1 event
	if len(result) != 3 {
		t.Fatalf("expected 3 URIs, got %d", len(result))
	}

	uriMap := make(map[string]TopTargetedURI)
	for _, u := range result {
		uriMap[u.URI] = u
	}

	env, ok := uriMap["/.env"]
	if !ok {
		t.Fatal("missing /.env in results")
	}
	if env.Total != 1 || env.Blocked != 1 {
		t.Errorf("/.env: expected total=1 blocked=1, got total=%d blocked=%d", env.Total, env.Blocked)
	}
	if len(env.Services) != 1 || env.Services[0] != "radarr.erfi.io" {
		t.Errorf("/.env: expected services=[radarr.erfi.io], got %v", env.Services)
	}

	queue, ok := uriMap["/api/v3/queue"]
	if !ok {
		t.Fatal("missing /api/v3/queue in results")
	}
	if queue.Total != 1 || queue.Blocked != 0 {
		t.Errorf("/api/v3/queue: expected total=1 blocked=0, got total=%d blocked=%d", queue.Total, queue.Blocked)
	}
}

func TestTopTargetedURIsLimit(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	result := store.TopTargetedURIs(0, 1)
	if len(result) != 1 {
		t.Fatalf("expected 1 URI (limit=1), got %d", len(result))
	}
}

func TestAnalyticsEndpoints(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/analytics/top-ips", handleTopBlockedIPs(store))
	mux.HandleFunc("GET /api/analytics/top-uris", handleTopTargetedURIs(store))

	// Test top-ips endpoint
	req := httptest.NewRequest("GET", "/api/analytics/top-ips", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("top-ips: expected 200, got %d", rec.Code)
	}

	var ips []TopBlockedIP
	if err := json.NewDecoder(rec.Body).Decode(&ips); err != nil {
		t.Fatalf("top-ips: failed to decode response: %v", err)
	}
	if len(ips) != 2 {
		t.Errorf("top-ips: expected 2 results, got %d", len(ips))
	}

	// Test top-uris endpoint
	req = httptest.NewRequest("GET", "/api/analytics/top-uris?hours=24", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("top-uris: expected 200, got %d", rec.Code)
	}

	var uris []TopTargetedURI
	if err := json.NewDecoder(rec.Body).Decode(&uris); err != nil {
		t.Fatalf("top-uris: failed to decode response: %v", err)
	}

	// Test with limit parameter
	req = httptest.NewRequest("GET", "/api/analytics/top-ips?limit=1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("top-ips with limit: expected 200, got %d", rec.Code)
	}

	var limitedIPs []TopBlockedIP
	if err := json.NewDecoder(rec.Body).Decode(&limitedIPs); err != nil {
		t.Fatalf("top-ips with limit: failed to decode response: %v", err)
	}
	if len(limitedIPs) != 1 {
		t.Errorf("top-ips with limit=1: expected 1 result, got %d", len(limitedIPs))
	}
}

// --- CRS Catalog endpoint tests ---

// ─── Tests for audit fix changes ──────────────────────────────────

func TestDecodeJSON_ValidBody(t *testing.T) {
	mux, _ := setupExclusionMux(t)
	body := `{"name":"Test","type":"remove_by_id","rule_id":"920420","enabled":true}`
	req := httptest.NewRequest("POST", "/api/exclusions", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDecodeJSON_InvalidJSON(t *testing.T) {
	mux, _ := setupExclusionMux(t)
	req := httptest.NewRequest("POST", "/api/exclusions", strings.NewReader(`{invalid`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("want 400 for invalid JSON, got %d", w.Code)
	}
	var resp ErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != "invalid JSON body" {
		t.Errorf("want 'invalid JSON body', got %q", resp.Error)
	}
}

func TestDecodeJSON_BodyTooLarge(t *testing.T) {
	mux, _ := setupExclusionMux(t)
	// maxJSONBody is 5 << 20 = 5MB. Build valid JSON that exceeds the limit.
	// {"name":"AAAA..."} — the padding makes the total body > 5MB.
	padding := strings.Repeat("A", 6*1024*1024)
	bigBody := `{"name":"` + padding + `"}`
	req := httptest.NewRequest("POST", "/api/exclusions", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("want 400 for oversized body, got %d", w.Code)
	}
	var resp ErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp.Error, "too large") {
		t.Errorf("want 'too large' in error, got %q", resp.Error)
	}
}

// --- rule_name filter on handleEvents ---

func TestHandleEventsRuleNameFilter(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{
			ID: "ev1", Timestamp: now.Add(-1 * time.Hour), EventType: "policy_skip",
			Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", URI: "/api/test",
			MatchedRules: []MatchedRule{{ID: 9500001, Msg: "Policy Skip: Allow uploads"}},
		},
		{
			ID: "ev2", Timestamp: now.Add(-2 * time.Hour), EventType: "policy_skip",
			Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", URI: "/api/other",
			MatchedRules: []MatchedRule{{ID: 9500002, Msg: "Policy Skip: Block bots"}},
		},
		{
			ID: "ev3", Timestamp: now.Add(-30 * time.Minute), EventType: "blocked",
			Service: "cdn.erfi.io", ClientIP: "5.6.7.8", Method: "POST", URI: "/login",
			RuleID: 942100,
		},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleEvents(store, als)

	// Without rule_name: should return all 3 events
	req := httptest.NewRequest("GET", "/api/events?hours=24", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var resp struct {
		Total  int     `json:"total"`
		Events []Event `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Total != 3 {
		t.Errorf("without filter: total = %d, want 3", resp.Total)
	}

	// With rule_name=Allow uploads: should return only ev1
	req2 := httptest.NewRequest("GET", "/api/events?hours=24&rule_name=Allow+uploads", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	var resp2 struct {
		Total  int     `json:"total"`
		Events []Event `json:"events"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp2.Total != 1 {
		t.Errorf("with rule_name=Allow uploads: total = %d, want 1", resp2.Total)
	}
	if len(resp2.Events) > 0 && resp2.Events[0].ID != "ev1" {
		t.Errorf("expected event ev1, got %s", resp2.Events[0].ID)
	}

	// With non-matching rule_name: should return 0 events
	req3 := httptest.NewRequest("GET", "/api/events?hours=24&rule_name=Nonexistent+rule", nil)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	var resp3 struct {
		Total  int     `json:"total"`
		Events []Event `json:"events"`
	}
	if err := json.Unmarshal(rec3.Body.Bytes(), &resp3); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp3.Total != 0 {
		t.Errorf("with non-matching rule_name: total = %d, want 0", resp3.Total)
	}
}

func TestHandleEventsRuleNameFilterOperators(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{
			ID: "ev1", Timestamp: now.Add(-1 * time.Hour), EventType: "policy_skip",
			Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET",
			MatchedRules: []MatchedRule{{ID: 9500001, Msg: "Policy Skip: Allow uploads"}},
		},
		{
			ID: "ev2", Timestamp: now.Add(-2 * time.Hour), EventType: "policy_skip",
			Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET",
			MatchedRules: []MatchedRule{{ID: 9500002, Msg: "Policy Block: Block bots"}},
		},
		{
			ID: "ev3", Timestamp: now.Add(-30 * time.Minute), EventType: "blocked",
			Service: "cdn.erfi.io", ClientIP: "5.6.7.8", Method: "POST",
			RuleID: 942100,
		},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleEvents(store, als)

	tests := []struct {
		name      string
		query     string
		wantTotal int
		wantIDs   []string
	}{
		{"contains uploads", "rule_name=uploads&rule_name_op=contains", 1, []string{"ev1"}},
		{"contains Block", "rule_name=Block&rule_name_op=contains", 1, []string{"ev2"}},
		{"neq Allow uploads", "rule_name=Allow+uploads&rule_name_op=neq", 1, []string{"ev2"}},
		{"in two rules", "rule_name=Allow+uploads,Block+bots&rule_name_op=in", 2, []string{"ev1", "ev2"}},
		{"regex ^Allow", "rule_name=^Allow.*&rule_name_op=regex", 1, []string{"ev1"}},
		{"regex none", "rule_name=^Nonexistent.*&rule_name_op=regex", 0, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/events?hours=24&"+tt.query, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			var resp struct {
				Total  int     `json:"total"`
				Events []Event `json:"events"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if resp.Total != tt.wantTotal {
				t.Errorf("total = %d, want %d", resp.Total, tt.wantTotal)
			}
			if tt.wantIDs != nil {
				gotIDs := make(map[string]bool)
				for _, e := range resp.Events {
					gotIDs[e.ID] = true
				}
				for _, id := range tt.wantIDs {
					if !gotIDs[id] {
						t.Errorf("expected event %s in results", id)
					}
				}
			}
		})
	}
}

func TestHandleSummaryRuleNameFilterOperators(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{
			ID: "ev1", Timestamp: now.Add(-1 * time.Hour), EventType: "policy_skip",
			Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET",
			MatchedRules: []MatchedRule{{ID: 9500001, Msg: "Policy Skip: Allow uploads"}},
		},
		{
			ID: "ev2", Timestamp: now.Add(-2 * time.Hour), EventType: "policy_skip",
			Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET",
			MatchedRules: []MatchedRule{{ID: 9500002, Msg: "Policy Block: Block bots"}},
		},
		{
			ID: "ev3", Timestamp: now.Add(-30 * time.Minute), EventType: "blocked",
			Service: "cdn.erfi.io", ClientIP: "5.6.7.8", Method: "POST",
			RuleID: 942100,
		},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	tests := []struct {
		name      string
		query     string
		wantTotal int
	}{
		{"contains uploads", "rule_name=uploads&rule_name_op=contains", 1},
		{"in two rules", "rule_name=Allow+uploads,Block+bots&rule_name_op=in", 2},
		{"regex ^Block", "rule_name=^Block.*&rule_name_op=regex", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/summary?hours=24&"+tt.query, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != 200 {
				t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
			}

			var resp SummaryResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if resp.TotalEvents != tt.wantTotal {
				t.Errorf("total_events = %d, want %d", resp.TotalEvents, tt.wantTotal)
			}
		})
	}
}

// --- rule_name filter on handleSummary ---

func TestHandleSummaryRuleNameFilter(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{
			ID: "ev1", Timestamp: now.Add(-1 * time.Hour), EventType: "policy_skip",
			Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET",
			MatchedRules: []MatchedRule{{ID: 9500001, Msg: "Policy Skip: My rule"}},
		},
		{
			ID: "ev2", Timestamp: now.Add(-2 * time.Hour), EventType: "policy_skip",
			Service: "app.erfi.io", ClientIP: "5.6.7.8", Method: "POST",
			MatchedRules: []MatchedRule{{ID: 9500001, Msg: "Policy Skip: My rule"}},
		},
		{
			ID: "ev3", Timestamp: now.Add(-30 * time.Minute), EventType: "blocked",
			Service: "cdn.erfi.io", ClientIP: "9.0.1.2", Method: "GET",
			RuleID: 942100,
		},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	// With rule_name filter: should only see the 2 policy events
	req := httptest.NewRequest("GET", "/api/summary?hours=24&rule_name=My+rule", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if resp.TotalEvents != 2 {
		t.Errorf("rule_name filtered summary: total_events = %d, want 2", resp.TotalEvents)
	}
	if resp.UniqueClients != 2 {
		t.Errorf("rule_name filtered summary: unique_clients = %d, want 2", resp.UniqueClients)
	}
	if resp.UniqueServices != 2 {
		t.Errorf("rule_name filtered summary: unique_services = %d, want 2", resp.UniqueServices)
	}
	// Blocked count should be 0 (these are policy_skip, not blocked)
	if resp.BlockedEvents != 0 {
		t.Errorf("rule_name filtered summary: blocked = %d, want 0", resp.BlockedEvents)
	}

	// Without rule_name filter: should see all 3 events
	req2 := httptest.NewRequest("GET", "/api/summary?hours=24", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	var resp2 SummaryResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp2.TotalEvents != 3 {
		t.Errorf("unfiltered summary: total_events = %d, want 3", resp2.TotalEvents)
	}
}

// --- Generalized filter params on handleSummary ---

// --- Generalized filter params on handleSummary ---

func TestHandleSummaryServiceFilter(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "cdn.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "logged"},
		{ID: "e3", Timestamp: now.Add(-3 * time.Hour), Service: "app.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	// Filter by service=cdn.erfi.io — should return 2 events
	req := httptest.NewRequest("GET", "/api/summary?hours=24&service=cdn.erfi.io", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalEvents != 2 {
		t.Errorf("service filter: total_events = %d, want 2", resp.TotalEvents)
	}
	if resp.BlockedEvents != 1 {
		t.Errorf("service filter: blocked = %d, want 1", resp.BlockedEvents)
	}
	if resp.UniqueClients != 2 {
		t.Errorf("service filter: unique_clients = %d, want 2", resp.UniqueClients)
	}
	if resp.UniqueServices != 1 {
		t.Errorf("service filter: unique_services = %d, want 1", resp.UniqueServices)
	}
}

func TestHandleSummaryClientFilter(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "cdn.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "logged"},
		{ID: "e3", Timestamp: now.Add(-3 * time.Hour), Service: "app.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "logged"},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	// Filter by client=1.2.3.4 — should return 2 events
	req := httptest.NewRequest("GET", "/api/summary?hours=24&client=1.2.3.4", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalEvents != 2 {
		t.Errorf("client filter: total_events = %d, want 2", resp.TotalEvents)
	}
	if resp.UniqueClients != 1 {
		t.Errorf("client filter: unique_clients = %d, want 1", resp.UniqueClients)
	}
	if resp.UniqueServices != 2 {
		t.Errorf("client filter: unique_services = %d, want 2", resp.UniqueServices)
	}
}

func TestHandleSummaryMethodFilter(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "logged"},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "cdn.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "logged"},
		{ID: "e3", Timestamp: now.Add(-3 * time.Hour), Service: "app.erfi.io", ClientIP: "9.0.1.2", Method: "GET", EventType: "blocked", IsBlocked: true},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	// Filter by method=GET — should return 2 events
	req := httptest.NewRequest("GET", "/api/summary?hours=24&method=GET", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalEvents != 2 {
		t.Errorf("method filter: total_events = %d, want 2", resp.TotalEvents)
	}
}

func TestHandleSummaryEventTypeFilter(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "cdn.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "logged"},
		{ID: "e3", Timestamp: now.Add(-3 * time.Hour), Service: "app.erfi.io", ClientIP: "9.0.1.2", Method: "GET", EventType: "blocked", IsBlocked: true},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	// Filter by event_type=blocked — should return 2 events
	req := httptest.NewRequest("GET", "/api/summary?hours=24&event_type=blocked", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalEvents != 2 {
		t.Errorf("event_type filter: total_events = %d, want 2", resp.TotalEvents)
	}
	if resp.BlockedEvents != 2 {
		t.Errorf("event_type filter: blocked = %d, want 2", resp.BlockedEvents)
	}
}

func TestHandleSummaryMultipleFilters(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "cdn.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "blocked", IsBlocked: true},
		{ID: "e3", Timestamp: now.Add(-3 * time.Hour), Service: "app.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e4", Timestamp: now.Add(-4 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "logged"},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	// service=cdn.erfi.io + event_type=blocked + method=GET — should match only e1
	req := httptest.NewRequest("GET", "/api/summary?hours=24&service=cdn.erfi.io&event_type=blocked&method=GET", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalEvents != 1 {
		t.Errorf("multiple filters: total_events = %d, want 1", resp.TotalEvents)
	}
	if resp.UniqueClients != 1 {
		t.Errorf("multiple filters: unique_clients = %d, want 1", resp.UniqueClients)
	}
	if resp.UniqueServices != 1 {
		t.Errorf("multiple filters: unique_services = %d, want 1", resp.UniqueServices)
	}
}

func TestHandleSummaryEventTypeFilterWithRL(t *testing.T) {
	// Test that event_type=rate_limited correctly fetches RL events
	// and filters out WAF events.
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "w1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	als.mu.Lock()
	als.events = []RateLimitEvent{
		{Timestamp: now.Add(-30 * time.Minute), Service: "api.erfi.io", ClientIP: "10.0.0.1", Method: "GET"},
		{Timestamp: now.Add(-45 * time.Minute), Service: "api.erfi.io", ClientIP: "10.0.0.2", Method: "POST", Source: "ipsum"},
	}
	als.mu.Unlock()

	handler := handleSummary(store, als)

	// event_type=rate_limited — should only see the RL event, not WAF or ipsum
	req := httptest.NewRequest("GET", "/api/summary?hours=24&event_type=rate_limited", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalEvents != 1 {
		t.Errorf("event_type=rate_limited filter: total_events = %d, want 1", resp.TotalEvents)
	}
	if resp.RateLimited != 1 {
		t.Errorf("event_type=rate_limited filter: rate_limited = %d, want 1", resp.RateLimited)
	}
}

func TestHandleSummaryNoFilterFallsThrough(t *testing.T) {
	// When no filters are set, the summary should go through the optimized
	// pre-aggregated path (not the filtered path). We verify by checking
	// that total_events includes both WAF and RL events.
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "w1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	als.mu.Lock()
	als.events = []RateLimitEvent{
		{Timestamp: now.Add(-30 * time.Minute), Service: "api.erfi.io", ClientIP: "10.0.0.1", Method: "GET"},
	}
	als.mu.Unlock()

	handler := handleSummary(store, als)

	req := httptest.NewRequest("GET", "/api/summary?hours=24", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	// 1 WAF + 1 RL = 2 total
	if resp.TotalEvents != 2 {
		t.Errorf("no-filter summary: total_events = %d, want 2", resp.TotalEvents)
	}
}

// --- fieldFilter / matchField unit tests ---

// --- fieldFilter / matchField unit tests ---

func TestParseFieldFilter(t *testing.T) {
	t.Run("nil when empty value", func(t *testing.T) {
		f := parseFieldFilter("", "eq")
		if f != nil {
			t.Errorf("expected nil, got %+v", f)
		}
	})
	t.Run("defaults to eq for unknown op", func(t *testing.T) {
		f := parseFieldFilter("test", "bogus")
		if f.op != "eq" {
			t.Errorf("expected eq, got %s", f.op)
		}
	})
	t.Run("defaults to eq for empty op", func(t *testing.T) {
		f := parseFieldFilter("test", "")
		if f.op != "eq" {
			t.Errorf("expected eq, got %s", f.op)
		}
	})
	t.Run("in splits values", func(t *testing.T) {
		f := parseFieldFilter("a,b,c", "in")
		if len(f.ins) != 3 {
			t.Errorf("expected 3 in-values, got %d", len(f.ins))
		}
	})
	t.Run("in trims whitespace", func(t *testing.T) {
		f := parseFieldFilter(" a , b , ", "in")
		if len(f.ins) != 2 {
			t.Errorf("expected 2 in-values, got %d: %v", len(f.ins), f.ins)
		}
	})
	t.Run("regex compiles valid pattern", func(t *testing.T) {
		f := parseFieldFilter("^cdn\\.", "regex")
		if f.re == nil {
			t.Error("expected compiled regexp")
		}
	})
	t.Run("regex falls back to contains on bad pattern", func(t *testing.T) {
		f := parseFieldFilter("[invalid", "regex")
		if f.op != "contains" {
			t.Errorf("expected contains fallback, got %s", f.op)
		}
	})
}

func TestMatchField(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		op     string
		target string
		want   bool
	}{
		{"nil filter matches all", "", "", "anything", true},
		{"eq match", "cdn.erfi.io", "eq", "CDN.ERFI.IO", true},
		{"eq no match", "cdn.erfi.io", "eq", "app.erfi.io", false},
		{"neq match", "cdn.erfi.io", "neq", "app.erfi.io", true},
		{"neq no match", "cdn.erfi.io", "neq", "cdn.erfi.io", false},
		{"contains match", "erfi", "contains", "cdn.erfi.io", true},
		{"contains case insensitive", "ERFI", "contains", "cdn.erfi.io", true},
		{"contains no match", "xyz", "contains", "cdn.erfi.io", false},
		{"in match first", "cdn.erfi.io,app.erfi.io", "in", "cdn.erfi.io", true},
		{"in match second", "cdn.erfi.io,app.erfi.io", "in", "APP.ERFI.IO", true},
		{"in no match", "cdn.erfi.io,app.erfi.io", "in", "other.io", false},
		{"regex match", "^cdn\\.", "regex", "cdn.erfi.io", true},
		{"regex no match", "^cdn\\.", "regex", "app.erfi.io", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f *fieldFilter
			if tt.value != "" {
				f = parseFieldFilter(tt.value, tt.op)
			}
			got := f.matchField(tt.target)
			if got != tt.want {
				t.Errorf("matchField(%q) = %v, want %v (op=%s, value=%s)", tt.target, got, tt.want, tt.op, tt.value)
			}
		})
	}
}

// --- Operator-aware handler tests ---

// --- Operator-aware handler tests ---

func TestHandleSummaryContainsOperator(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "app.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "logged"},
		{ID: "e3", Timestamp: now.Add(-3 * time.Hour), Service: "other.com", ClientIP: "9.0.0.1", Method: "GET", EventType: "blocked", IsBlocked: true},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	// service contains "erfi" should match 2 events
	req := httptest.NewRequest("GET", "/api/summary?hours=24&service=erfi&service_op=contains", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalEvents != 2 {
		t.Errorf("contains filter: total_events = %d, want 2", resp.TotalEvents)
	}
}

func TestHandleSummaryInOperator(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "app.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "logged"},
		{ID: "e3", Timestamp: now.Add(-3 * time.Hour), Service: "other.com", ClientIP: "9.0.0.1", Method: "DELETE", EventType: "blocked", IsBlocked: true},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	// method in GET,POST should match 2 events
	req := httptest.NewRequest("GET", "/api/summary?hours=24&method=GET,POST&method_op=in", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalEvents != 2 {
		t.Errorf("in filter: total_events = %d, want 2", resp.TotalEvents)
	}
}

func TestHandleSummaryNeqOperator(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "cdn.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "logged"},
		{ID: "e3", Timestamp: now.Add(-3 * time.Hour), Service: "app.erfi.io", ClientIP: "9.0.0.1", Method: "GET", EventType: "blocked", IsBlocked: true},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	// service neq cdn.erfi.io should match 1 event (app.erfi.io)
	req := httptest.NewRequest("GET", "/api/summary?hours=24&service=cdn.erfi.io&service_op=neq", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalEvents != 1 {
		t.Errorf("neq filter: total_events = %d, want 1", resp.TotalEvents)
	}
}

func TestHandleSummaryRegexOperator(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "app.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "logged"},
		{ID: "e3", Timestamp: now.Add(-3 * time.Hour), Service: "other.com", ClientIP: "9.0.0.1", Method: "GET", EventType: "blocked", IsBlocked: true},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleSummary(store, als)

	// service regex ^cdn\. should match 1 event
	req := httptest.NewRequest("GET", `/api/summary?hours=24&service=^cdn\.&service_op=regex`, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp SummaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalEvents != 1 {
		t.Errorf("regex filter: total_events = %d, want 1", resp.TotalEvents)
	}
}

func TestHandleEventsInOperator(t *testing.T) {
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "app.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "logged"},
		{ID: "e3", Timestamp: now.Add(-3 * time.Hour), Service: "other.com", ClientIP: "9.0.0.1", Method: "DELETE", EventType: "blocked", IsBlocked: true},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleEvents(store, als)

	req := httptest.NewRequest("GET", "/api/events?hours=24&event_type=blocked,logged&event_type_op=in", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Total  int     `json:"total"`
		Events []Event `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Total != 3 {
		t.Errorf("events in filter: total = %d, want 3", resp.Total)
	}
}

func TestHandleEventsNoOpDefaultsToEq(t *testing.T) {
	// Without _op param, should behave exactly as before (eq).
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{ID: "e1", Timestamp: now.Add(-1 * time.Hour), Service: "cdn.erfi.io", ClientIP: "1.2.3.4", Method: "GET", EventType: "blocked", IsBlocked: true},
		{ID: "e2", Timestamp: now.Add(-2 * time.Hour), Service: "app.erfi.io", ClientIP: "5.6.7.8", Method: "POST", EventType: "logged"},
	}
	store.mu.Unlock()

	als := NewAccessLogStore("")
	handler := handleEvents(store, als)

	req := httptest.NewRequest("GET", "/api/events?hours=24&service=cdn.erfi.io", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Total  int     `json:"total"`
		Events []Event `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("events default eq filter: total = %d, want 1", resp.Total)
	}
}
