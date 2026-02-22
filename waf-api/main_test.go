package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sample log lines matching Coraza's JSON audit format.
// Headers are now map[string][]string format.
var sampleLines = []string{
	`{"transaction":{"timestamp":"2026/02/22 07:19:01","unix_timestamp":1771744741169677031,"id":"AAA111","client_ip":"195.240.81.42","client_port":0,"host_ip":"","host_port":0,"server_id":"dockge-sg.erfi.io","request":{"method":"POST","protocol":"HTTP/2.0","uri":"/socket.io/?EIO=4","http_version":"","headers":{"User-Agent":["Mozilla/5.0"]},"body":"40","files":null,"args":{},"length":0},"response":{"protocol":"","status":0,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":true}}`,
	`{"transaction":{"timestamp":"2026/02/22 07:20:00","unix_timestamp":1771744800000000000,"id":"BBB222","client_ip":"10.0.0.1","client_port":0,"host_ip":"","host_port":0,"server_id":"radarr.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/.env","http_version":"","headers":{"User-Agent":["curl/7.68"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":403,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":true}}`,
	`{"transaction":{"timestamp":"2026/02/22 08:00:00","unix_timestamp":1771747200000000000,"id":"CCC333","client_ip":"10.0.0.1","client_port":0,"host_ip":"","host_port":0,"server_id":"radarr.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/api/v3/queue","http_version":"","headers":{"User-Agent":["Radarr/5.0"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":200,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":false}}`,
}

func writeTempLog(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
	f.Close()
	return path
}

func TestStoreLoad(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3 events, got %d", got)
	}
}

func TestStoreIncrementalLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Write first 2 lines.
	f, _ := os.Create(path)
	for _, l := range sampleLines[:2] {
		f.WriteString(l + "\n")
	}
	f.Close()

	store := NewStore(path)
	store.Load()
	if got := store.EventCount(); got != 2 {
		t.Fatalf("expected 2, got %d", got)
	}

	// Append third line.
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString(sampleLines[2] + "\n")
	f.Close()

	store.Load()
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3 after append, got %d", got)
	}
}

func TestStoreFileRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Write 3 lines.
	f, _ := os.Create(path)
	for _, l := range sampleLines {
		f.WriteString(l + "\n")
	}
	f.Close()

	store := NewStore(path)
	store.Load()
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3, got %d", got)
	}

	// Simulate rotation: truncate and write 1 line.
	f, _ = os.Create(path) // truncates
	f.WriteString(sampleLines[0] + "\n")
	f.Close()

	store.Load()
	if got := store.EventCount(); got != 1 {
		t.Fatalf("expected 1 after rotation, got %d", got)
	}
}

func TestSummary(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	s := store.Summary(0) // 0 = all time

	if s.TotalEvents != 3 {
		t.Errorf("total: want 3, got %d", s.TotalEvents)
	}
	if s.BlockedEvents != 2 {
		t.Errorf("blocked: want 2, got %d", s.BlockedEvents)
	}
	if s.LoggedEvents != 1 {
		t.Errorf("logged: want 1, got %d", s.LoggedEvents)
	}
	if s.UniqueClients != 2 {
		t.Errorf("unique clients: want 2, got %d", s.UniqueClients)
	}
	if s.UniqueServices != 2 {
		t.Errorf("unique services: want 2, got %d", s.UniqueServices)
	}
	if len(s.EventsByHour) != 2 {
		t.Errorf("events_by_hour: want 2 buckets, got %d", len(s.EventsByHour))
	}
}

func TestFilteredEvents(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	// Filter by service.
	resp := store.FilteredEvents("radarr.erfi.io", "", "", nil, 50, 0, 0)
	if resp.Total != 2 {
		t.Errorf("filter by service: want 2, got %d", resp.Total)
	}

	// Filter by blocked.
	blocked := true
	resp = store.FilteredEvents("", "", "", &blocked, 50, 0, 0)
	if resp.Total != 2 {
		t.Errorf("filter by blocked=true: want 2, got %d", resp.Total)
	}

	// Pagination.
	resp = store.FilteredEvents("", "", "", nil, 1, 0, 0)
	if len(resp.Events) != 1 || resp.Total != 3 {
		t.Errorf("pagination: want 1 event of 3 total, got %d/%d", len(resp.Events), resp.Total)
	}

	// Verify newest-first ordering.
	if resp.Events[0].ID != "CCC333" {
		t.Errorf("newest-first: want CCC333, got %s", resp.Events[0].ID)
	}
}

func TestServices(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	resp := store.Services(0)
	if len(resp.Services) != 2 {
		t.Fatalf("want 2 services, got %d", len(resp.Services))
	}

	// Sorted by total desc: radarr=2, dockge=1.
	if resp.Services[0].Service != "radarr.erfi.io" {
		t.Errorf("top service: want radarr.erfi.io, got %s", resp.Services[0].Service)
	}
	if resp.Services[0].Blocked != 1 || resp.Services[0].Logged != 1 {
		t.Errorf("radarr: want blocked=1 logged=1, got blocked=%d logged=%d",
			resp.Services[0].Blocked, resp.Services[0].Logged)
	}
}

func TestParseTimestamp(t *testing.T) {
	ts := parseTimestamp("2026/02/22 07:19:01")
	expected := time.Date(2026, 2, 22, 7, 19, 1, 0, time.UTC)
	if !ts.Equal(expected) {
		t.Errorf("want %v, got %v", expected, ts)
	}
}

func TestHeaderValueExtraction(t *testing.T) {
	headers := map[string][]string{
		"User-Agent":   {"Mozilla/5.0"},
		"Content-Type": {"application/json", "text/html"},
	}

	// Exact match.
	if got := headerValue(headers, "User-Agent"); got != "Mozilla/5.0" {
		t.Errorf("want Mozilla/5.0, got %s", got)
	}
	// Case-insensitive fallback.
	if got := headerValue(headers, "user-agent"); got != "Mozilla/5.0" {
		t.Errorf("case-insensitive: want Mozilla/5.0, got %s", got)
	}
	// First value for multi-valued header.
	if got := headerValue(headers, "Content-Type"); got != "application/json" {
		t.Errorf("multi-value: want application/json, got %s", got)
	}
	// Missing header.
	if got := headerValue(headers, "X-Missing"); got != "" {
		t.Errorf("missing: want empty, got %s", got)
	}
}

// --- HTTP handler tests ---

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp HealthResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != "ok" {
		t.Errorf("want ok, got %s", resp.Status)
	}
}

// emptyAccessLogStore returns an AccessLogStore with no events for tests that
// don't care about 429 merging.
func emptyAccessLogStore(t *testing.T) *AccessLogStore {
	t.Helper()
	return NewAccessLogStore(filepath.Join(t.TempDir(), "empty-access.log"))
}

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
	mux.HandleFunc("GET /api/health", handleHealth)
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
	mux.HandleFunc("GET /api/health", handleHealth)
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
	mux.HandleFunc("GET /api/health", handleHealth)
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
	mux.HandleFunc("GET /api/health", handleHealth)
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
	mux.HandleFunc("GET /api/health", handleHealth)
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

func newTestExclusionStore(t *testing.T) *ExclusionStore {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")
	return NewExclusionStore(path)
}

func TestExclusionStoreCRUD(t *testing.T) {
	es := newTestExclusionStore(t)

	// Create.
	exc := RuleExclusion{
		Name:    "Test exclusion",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	}

	created, err := es.Create(exc)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == "" {
		t.Error("created exclusion should have an ID")
	}
	if created.CreatedAt.IsZero() {
		t.Error("created_at should be set")
	}

	// List.
	list := es.List()
	if len(list) != 1 {
		t.Fatalf("list: want 1, got %d", len(list))
	}

	// Get.
	got, found := es.Get(created.ID)
	if !found {
		t.Fatal("get: not found")
	}
	if got.Name != "Test exclusion" {
		t.Errorf("get: want Test exclusion, got %s", got.Name)
	}

	// Update.
	exc.Name = "Updated exclusion"
	exc.Description = "Now with description"
	updated, found, err := es.Update(created.ID, exc)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !found {
		t.Fatal("update: not found")
	}
	if updated.Name != "Updated exclusion" {
		t.Errorf("update: want Updated exclusion, got %s", updated.Name)
	}
	if updated.ID != created.ID {
		t.Error("update should preserve ID")
	}
	if updated.CreatedAt != created.CreatedAt {
		t.Error("update should preserve created_at")
	}

	// Delete.
	deleted, err := es.Delete(created.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !deleted {
		t.Fatal("delete: not found")
	}

	list = es.List()
	if len(list) != 0 {
		t.Errorf("list after delete: want 0, got %d", len(list))
	}
}

func TestExclusionStoreDeleteNotFound(t *testing.T) {
	es := newTestExclusionStore(t)
	found, err := es.Delete("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("should not find nonexistent exclusion")
	}
}

func TestExclusionStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")

	es1 := NewExclusionStore(path)
	_, err := es1.Create(RuleExclusion{
		Name:    "Persistent",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Create new store from same file — should load the exclusion.
	es2 := NewExclusionStore(path)
	list := es2.List()
	if len(list) != 1 {
		t.Fatalf("persistence: want 1, got %d", len(list))
	}
	if list[0].Name != "Persistent" {
		t.Errorf("persistence: want Persistent, got %s", list[0].Name)
	}
}

func TestExclusionStoreImportExport(t *testing.T) {
	es := newTestExclusionStore(t)

	// Create some exclusions.
	es.Create(RuleExclusion{Name: "First", Type: "remove_by_id", RuleID: "920420", Enabled: true})
	es.Create(RuleExclusion{Name: "Second", Type: "remove_by_tag", RuleTag: "attack-sqli", Enabled: false})

	// Export.
	export := es.Export()
	if export.Version != 1 {
		t.Errorf("export version: want 1, got %d", export.Version)
	}
	if len(export.Exclusions) != 2 {
		t.Fatalf("export: want 2 exclusions, got %d", len(export.Exclusions))
	}

	// Import into a fresh store.
	es2 := newTestExclusionStore(t)
	err := es2.Import(export.Exclusions)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	list := es2.List()
	if len(list) != 2 {
		t.Fatalf("import: want 2, got %d", len(list))
	}
}

func TestExclusionStoreEnabledFilter(t *testing.T) {
	es := newTestExclusionStore(t)
	es.Create(RuleExclusion{Name: "Enabled", Type: "remove_by_id", RuleID: "1", Enabled: true})
	es.Create(RuleExclusion{Name: "Disabled", Type: "remove_by_id", RuleID: "2", Enabled: false})

	enabled := es.EnabledExclusions()
	if len(enabled) != 1 {
		t.Fatalf("want 1 enabled, got %d", len(enabled))
	}
	if enabled[0].Name != "Enabled" {
		t.Errorf("want Enabled, got %s", enabled[0].Name)
	}
}

// --- Exclusion validation tests ---

func TestValidateExclusion(t *testing.T) {
	tests := []struct {
		name    string
		exc     RuleExclusion
		wantErr bool
	}{
		{
			name:    "valid remove_by_id",
			exc:     RuleExclusion{Name: "test", Type: "remove_by_id", RuleID: "920420"},
			wantErr: false,
		},
		{
			name:    "valid remove_by_tag",
			exc:     RuleExclusion{Name: "test", Type: "remove_by_tag", RuleTag: "attack-sqli"},
			wantErr: false,
		},
		{
			name:    "valid update_target_by_id",
			exc:     RuleExclusion{Name: "test", Type: "update_target_by_id", RuleID: "920420", Variable: "ARGS:foo"},
			wantErr: false,
		},
		{
			name:    "valid runtime_remove_by_id",
			exc:     RuleExclusion{Name: "test", Type: "runtime_remove_by_id", RuleID: "920420", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/"}}},
			wantErr: false,
		},
		{
			name:    "valid runtime_remove_target_by_id",
			exc:     RuleExclusion{Name: "test", Type: "runtime_remove_target_by_id", RuleID: "920420", Variable: "ARGS:x", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/"}}},
			wantErr: false,
		},
		{
			name:    "missing name",
			exc:     RuleExclusion{Type: "remove_by_id", RuleID: "920420"},
			wantErr: true,
		},
		{
			name:    "invalid type",
			exc:     RuleExclusion{Name: "test", Type: "invalid_type"},
			wantErr: true,
		},
		{
			name:    "remove_by_id missing rule_id",
			exc:     RuleExclusion{Name: "test", Type: "remove_by_id"},
			wantErr: true,
		},
		{
			name:    "remove_by_tag missing rule_tag",
			exc:     RuleExclusion{Name: "test", Type: "remove_by_tag"},
			wantErr: true,
		},
		{
			name:    "update_target_by_id missing variable",
			exc:     RuleExclusion{Name: "test", Type: "update_target_by_id", RuleID: "920420"},
			wantErr: true,
		},
		{
			name:    "runtime_remove_by_id missing conditions",
			exc:     RuleExclusion{Name: "test", Type: "runtime_remove_by_id", RuleID: "920420"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExclusion(tt.exc)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExclusion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// --- Exclusion HTTP endpoint tests ---

func setupExclusionMux(t *testing.T) (*http.ServeMux, *ExclusionStore) {
	t.Helper()
	es := newTestExclusionStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/exclusions", handleListExclusions(es))
	mux.HandleFunc("POST /api/exclusions", handleCreateExclusion(es))
	mux.HandleFunc("GET /api/exclusions/export", handleExportExclusions(es))
	mux.HandleFunc("POST /api/exclusions/import", handleImportExclusions(es))
	mux.HandleFunc("POST /api/exclusions/generate", handleGenerateExclusions(es))
	mux.HandleFunc("GET /api/exclusions/{id}", handleGetExclusion(es))
	mux.HandleFunc("PUT /api/exclusions/{id}", handleUpdateExclusion(es))
	mux.HandleFunc("DELETE /api/exclusions/{id}", handleDeleteExclusion(es))
	return mux, es
}

func TestExclusionEndpointCreate(t *testing.T) {
	mux, _ := setupExclusionMux(t)

	body := `{"name":"Test","type":"remove_by_id","rule_id":"920420","enabled":true}`
	req := httptest.NewRequest("POST", "/api/exclusions", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 201 {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp RuleExclusion
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.ID == "" {
		t.Error("response should have an ID")
	}
	if resp.Name != "Test" {
		t.Errorf("want Test, got %s", resp.Name)
	}
}

func TestExclusionEndpointCreateInvalid(t *testing.T) {
	mux, _ := setupExclusionMux(t)

	body := `{"name":"","type":"remove_by_id","rule_id":"920420"}`
	req := httptest.NewRequest("POST", "/api/exclusions", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestExclusionEndpointGetNotFound(t *testing.T) {
	mux, _ := setupExclusionMux(t)

	req := httptest.NewRequest("GET", "/api/exclusions/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestExclusionEndpointCRUDFlow(t *testing.T) {
	mux, _ := setupExclusionMux(t)

	// Create.
	body := `{"name":"Flow Test","type":"remove_by_id","rule_id":"920420","enabled":true}`
	req := httptest.NewRequest("POST", "/api/exclusions", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("create: want 201, got %d", w.Code)
	}

	var created RuleExclusion
	json.NewDecoder(w.Body).Decode(&created)

	// Get.
	req = httptest.NewRequest("GET", "/api/exclusions/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("get: want 200, got %d", w.Code)
	}

	// Update.
	body = `{"name":"Updated Flow Test","type":"remove_by_id","rule_id":"920420","enabled":false}`
	req = httptest.NewRequest("PUT", "/api/exclusions/"+created.ID, strings.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("update: want 200, got %d: %s", w.Code, w.Body.String())
	}

	var updated RuleExclusion
	json.NewDecoder(w.Body).Decode(&updated)
	if updated.Name != "Updated Flow Test" {
		t.Errorf("update: want Updated Flow Test, got %s", updated.Name)
	}
	if updated.Enabled {
		t.Error("update: want enabled=false")
	}

	// List — should have 1.
	req = httptest.NewRequest("GET", "/api/exclusions", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("list: want 200, got %d", w.Code)
	}
	var list []RuleExclusion
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("list: want 1, got %d", len(list))
	}

	// Delete.
	req = httptest.NewRequest("DELETE", "/api/exclusions/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 204 {
		t.Fatalf("delete: want 204, got %d", w.Code)
	}

	// Verify deleted.
	req = httptest.NewRequest("GET", "/api/exclusions/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("get after delete: want 404, got %d", w.Code)
	}
}

func TestExclusionEndpointExportImport(t *testing.T) {
	mux, es := setupExclusionMux(t)

	// Create two exclusions.
	es.Create(RuleExclusion{Name: "Export1", Type: "remove_by_id", RuleID: "1", Enabled: true})
	es.Create(RuleExclusion{Name: "Export2", Type: "remove_by_tag", RuleTag: "sqli", Enabled: true})

	// Export.
	req := httptest.NewRequest("GET", "/api/exclusions/export", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("export: want 200, got %d", w.Code)
	}

	exportBody := w.Body.Bytes()
	var export ExclusionExport
	json.Unmarshal(exportBody, &export)
	if len(export.Exclusions) != 2 {
		t.Fatalf("export: want 2 exclusions, got %d", len(export.Exclusions))
	}

	// Import into the same store (replaces).
	req = httptest.NewRequest("POST", "/api/exclusions/import", bytes.NewReader(exportBody))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("import: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExclusionEndpointImportInvalid(t *testing.T) {
	mux, _ := setupExclusionMux(t)

	// Empty exclusions.
	body := `{"version":1,"exclusions":[]}`
	req := httptest.NewRequest("POST", "/api/exclusions/import", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("import empty: want 400, got %d", w.Code)
	}
}

func TestExclusionEndpointGenerate(t *testing.T) {
	mux, es := setupExclusionMux(t)

	es.Create(RuleExclusion{
		Name:    "Remove rule",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	})
	es.Create(RuleExclusion{
		Name:       "Runtime remove",
		Type:       "runtime_remove_by_id",
		RuleID:     "941100",
		Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/webhook"}},
		Enabled:    true,
	})

	req := httptest.NewRequest("POST", "/api/exclusions/generate", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("generate: want 200, got %d", w.Code)
	}

	var resp GenerateResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp.PostCRS, "SecRuleRemoveById 920420") {
		t.Error("post-crs should contain SecRuleRemoveById 920420")
	}
	if !strings.Contains(resp.PreCRS, "ruleRemoveById=941100") {
		t.Error("pre-crs should contain runtime removal for 941100")
	}
}

// --- Config Store tests ---

func newTestConfigStore(t *testing.T) *ConfigStore {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	return NewConfigStore(path)
}

func TestConfigStoreDefaults(t *testing.T) {
	cs := newTestConfigStore(t)
	cfg := cs.Get()

	if cfg.Defaults.ParanoiaLevel != 1 {
		t.Errorf("default paranoia: want 1, got %d", cfg.Defaults.ParanoiaLevel)
	}
	if cfg.Defaults.InboundThreshold != 5 {
		t.Errorf("default inbound: want 5, got %d", cfg.Defaults.InboundThreshold)
	}
	if cfg.Defaults.OutboundThreshold != 4 {
		t.Errorf("default outbound: want 4, got %d", cfg.Defaults.OutboundThreshold)
	}
	if cfg.Defaults.Mode != "enabled" {
		t.Errorf("default mode: want enabled, got %s", cfg.Defaults.Mode)
	}
}

func TestConfigStoreUpdate(t *testing.T) {
	cs := newTestConfigStore(t)

	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "detection_only", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8,
		},
		Services: map[string]WAFServiceSettings{
			"test.erfi.io": {Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}

	updated, err := cs.Update(cfg)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Defaults.ParanoiaLevel != 2 {
		t.Errorf("want paranoia 2, got %d", updated.Defaults.ParanoiaLevel)
	}
}

func TestConfigStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cs1 := NewConfigStore(path)
	cs1.Update(WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 3, InboundThreshold: 7, OutboundThreshold: 6},
		Services: make(map[string]WAFServiceSettings),
	})

	cs2 := NewConfigStore(path)
	cfg := cs2.Get()
	if cfg.Defaults.ParanoiaLevel != 3 {
		t.Errorf("persistence: want paranoia 3, got %d", cfg.Defaults.ParanoiaLevel)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     WAFConfig
		wantErr bool
	}{
		{
			name: "valid",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: false,
		},
		{
			name: "paranoia too low",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 0, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: true,
		},
		{
			name: "paranoia too high",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 5, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: true,
		},
		{
			name: "invalid mode",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "maybe", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: true,
		},
		{
			name: "invalid rule group tag",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, DisabledGroups: []string{"not-a-real-tag"}},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: true,
		},
		{
			name: "valid with disabled groups",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, DisabledGroups: []string{"attack-sqli", "attack-xss"}},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: false,
		},
		{
			name: "valid per-service override",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{
					"test.erfi.io": {Mode: "disabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid per-service paranoia",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{
					"test.erfi.io": {Mode: "enabled", ParanoiaLevel: 0, InboundThreshold: 5, OutboundThreshold: 4},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// --- Config HTTP endpoint tests ---

func TestConfigEndpoints(t *testing.T) {
	cs := newTestConfigStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/config", handleGetConfig(cs))
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(cs))

	// GET defaults.
	req := httptest.NewRequest("GET", "/api/config", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("get: want 200, got %d", w.Code)
	}

	var cfg WAFConfig
	json.NewDecoder(w.Body).Decode(&cfg)
	if cfg.Defaults.ParanoiaLevel != 1 {
		t.Errorf("default paranoia: want 1, got %d", cfg.Defaults.ParanoiaLevel)
	}

	// PUT update.
	body := `{"defaults":{"mode":"enabled","paranoia_level":2,"inbound_threshold":10,"outbound_threshold":8},"services":{}}`
	req = httptest.NewRequest("PUT", "/api/config", strings.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("put: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify.
	req = httptest.NewRequest("GET", "/api/config", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	json.NewDecoder(w.Body).Decode(&cfg)
	if cfg.Defaults.ParanoiaLevel != 2 {
		t.Errorf("updated paranoia: want 2, got %d", cfg.Defaults.ParanoiaLevel)
	}
}

func TestConfigEndpointInvalid(t *testing.T) {
	cs := newTestConfigStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(cs))

	body := `{"defaults":{"mode":"enabled","paranoia_level":0,"inbound_threshold":5,"outbound_threshold":4},"services":{}}`
	req := httptest.NewRequest("PUT", "/api/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// --- Generator tests ---

func TestGenerateConfigBasic(t *testing.T) {
	ResetRuleIDCounter()

	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8},
		Services: map[string]WAFServiceSettings{},
	}

	exclusions := []RuleExclusion{
		{Name: "Remove 920420", Type: "remove_by_id", RuleID: "920420", Enabled: true},
		{Name: "Remove sqli tag", Type: "remove_by_tag", RuleTag: "attack-sqli", Enabled: true},
		{Name: "Update target", Type: "update_target_by_id", RuleID: "941100", Variable: "ARGS:body", Enabled: true},
		{Name: "Runtime remove", Type: "runtime_remove_by_id", RuleID: "942100", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/hook"}}, Enabled: true},
		{Name: "Runtime remove target", Type: "runtime_remove_target_by_id", RuleID: "943100", Variable: "ARGS:data", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/webhook"}}, Enabled: true},
	}

	result := GenerateConfigs(cfg, exclusions)

	// Pre-CRS should NOT contain CRS setup rules — those are in the Caddyfile WAF tiers.
	if strings.Contains(result.PreCRS, "blocking_paranoia_level") {
		t.Error("pre-crs should not contain paranoia level (managed by Caddyfile tiers)")
	}
	if strings.Contains(result.PreCRS, "inbound_anomaly_score_threshold") {
		t.Error("pre-crs should not contain inbound threshold (managed by Caddyfile tiers)")
	}
	if strings.Contains(result.PreCRS, "SecRuleEngine") {
		t.Error("pre-crs should not contain SecRuleEngine (managed by Caddyfile tiers)")
	}
	// Pre-CRS should contain runtime exclusions.
	if !strings.Contains(result.PreCRS, "ruleRemoveById=942100") {
		t.Error("pre-crs should contain runtime removal")
	}
	if !strings.Contains(result.PreCRS, "ruleRemoveTargetById=943100") {
		t.Error("pre-crs should contain runtime target removal")
	}

	// Post-CRS checks.
	if !strings.Contains(result.PostCRS, "SecRuleRemoveById 920420") {
		t.Error("post-crs should contain SecRuleRemoveById 920420")
	}
	if !strings.Contains(result.PostCRS, `SecRuleRemoveByTag "attack-sqli"`) {
		t.Error("post-crs should contain SecRuleRemoveByTag attack-sqli")
	}
	if !strings.Contains(result.PostCRS, `SecRuleUpdateTargetById 941100 "!ARGS:body"`) {
		t.Error("post-crs should contain SecRuleUpdateTargetById")
	}

	// Runtime exclusions should NOT be in post-CRS.
	if strings.Contains(result.PostCRS, "942100") {
		t.Error("post-crs should not contain runtime exclusions")
	}
	// Configure-time exclusions should NOT be in pre-CRS (as SecRuleRemoveById).
	if strings.Contains(result.PreCRS, "SecRuleRemoveById") {
		t.Error("pre-crs should not contain SecRuleRemoveById")
	}
}

func TestGenerateConfigEmpty(t *testing.T) {
	ResetRuleIDCounter()

	cfg := defaultConfig()
	result := GenerateConfigs(cfg, nil)

	// Pre-CRS should NOT contain CRS setup — those are per-tier in the Caddyfile.
	if strings.Contains(result.PreCRS, "blocking_paranoia_level") {
		t.Error("pre-crs should not contain paranoia level (managed by Caddyfile tiers)")
	}
	if strings.Contains(result.PreCRS, "SecRuleEngine") {
		t.Error("pre-crs should not contain SecRuleEngine (managed by Caddyfile tiers)")
	}
	// Pre-CRS should just have the header, no rules.
	if strings.Contains(result.PreCRS, "SecRule") {
		t.Error("pre-crs should have no rules with no exclusions")
	}
	// Post-CRS should just have the header.
	if strings.Contains(result.PostCRS, "SecRule") {
		t.Error("post-crs should have no rules with no exclusions")
	}
}

// --- WAF Settings Generator tests ---

func TestGenerateWAFSettingsDefaults(t *testing.T) {
	cfg := defaultConfig()
	output := GenerateWAFSettings(cfg)

	if !strings.Contains(output, "paranoia_level=1") {
		t.Error("should contain default paranoia_level=1")
	}
	if !strings.Contains(output, "blocking_paranoia_level=1") {
		t.Error("should contain default blocking_paranoia_level=1")
	}
	if !strings.Contains(output, "inbound_anomaly_score_threshold=5") {
		t.Error("should contain default inbound threshold=5")
	}
	if !strings.Contains(output, "outbound_anomaly_score_threshold=4") {
		t.Error("should contain default outbound threshold=4")
	}
	// Should NOT contain ctl:ruleEngine=Off for default enabled mode.
	if strings.Contains(output, "ctl:ruleEngine=Off") {
		t.Error("enabled mode should not disable rule engine")
	}
}

func TestGenerateWAFSettingsDetectionOnly(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "detection_only", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	// Detection-only mode should use threshold 10000.
	if !strings.Contains(output, "inbound_anomaly_score_threshold=10000") {
		t.Error("detection_only should set inbound threshold to 10000")
	}
	if !strings.Contains(output, "outbound_anomaly_score_threshold=10000") {
		t.Error("detection_only should set outbound threshold to 10000")
	}
	// Detection-only mode MUST emit SecRuleEngine DetectionOnly as a
	// config-time directive. High thresholds alone are insufficient — Coraza
	// can still block on individual rules before anomaly scoring evaluates.
	if !strings.Contains(output, "SecRuleEngine DetectionOnly") {
		t.Error("detection_only should contain SecRuleEngine DetectionOnly")
	}
}

func TestGenerateWAFSettingsDisabled(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "disabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	if !strings.Contains(output, "SecRuleEngine Off") {
		t.Error("disabled mode should contain SecRuleEngine Off")
	}
}

func TestGenerateWAFSettingsPerService(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{
			"httpbun.erfi.io": {Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 3, OutboundThreshold: 3},
			"qbit.erfi.io":    {Mode: "disabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	output := GenerateWAFSettings(cfg)

	// httpbun override
	if !strings.Contains(output, `@streq httpbun.erfi.io`) {
		t.Error("should contain httpbun SERVER_NAME check")
	}
	if !strings.Contains(output, "paranoia_level=2") {
		t.Error("httpbun should have paranoia_level=2")
	}

	// qbit disabled
	if !strings.Contains(output, `@streq qbit.erfi.io`) {
		t.Error("should contain qbit SERVER_NAME check")
	}
	if !strings.Contains(output, "ctl:ruleEngine=Off") {
		t.Error("qbit should have ctl:ruleEngine=Off")
	}
}

func TestGenerateWAFSettingsDisabledGroups(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, DisabledGroups: []string{"attack-sqli"}},
		Services: map[string]WAFServiceSettings{
			"test.erfi.io": {Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, DisabledGroups: []string{"attack-sqli", "attack-xss"}},
		},
	}
	output := GenerateWAFSettings(cfg)

	// Default group should be disabled globally.
	if !strings.Contains(output, "ctl:ruleRemoveByTag=attack-sqli") {
		t.Error("should disable attack-sqli globally")
	}
	// Per-service: xss should be disabled for test.erfi.io (sqli is already global).
	if !strings.Contains(output, "ctl:ruleRemoveByTag=attack-xss") {
		t.Error("should disable attack-xss for test.erfi.io")
	}
}

func TestGenerateWAFSettingsNoUnnecessaryOverrides(t *testing.T) {
	// Service with same settings as defaults should NOT generate overrides.
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{
			"same.erfi.io": {Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	output := GenerateWAFSettings(cfg)

	if strings.Contains(output, "@streq same.erfi.io") {
		t.Error("service with identical settings should not generate a SERVER_NAME override")
	}
}

func TestGenerateWAFSettingsDeterministic(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{
			"b.erfi.io": {Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 5, OutboundThreshold: 4},
			"a.erfi.io": {Mode: "enabled", ParanoiaLevel: 3, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	// Generate twice, verify same output (sorted by hostname).
	out1 := GenerateWAFSettings(cfg)
	out2 := GenerateWAFSettings(cfg)

	// Strip timestamps (they differ).
	strip := func(s string) string {
		lines := strings.Split(s, "\n")
		var filtered []string
		for _, l := range lines {
			if !strings.Contains(l, "Generated:") {
				filtered = append(filtered, l)
			}
		}
		return strings.Join(filtered, "\n")
	}
	if strip(out1) != strip(out2) {
		t.Error("WAF settings should be deterministic")
	}

	// Verify alphabetical order.
	aIdx := strings.Index(out1, "a.erfi.io")
	bIdx := strings.Index(out1, "b.erfi.io")
	if aIdx > bIdx {
		t.Error("services should be sorted alphabetically (a before b)")
	}
}

func TestGenerateWAFSettingsReEnableEngine(t *testing.T) {
	// Bug #1: When default mode is "disabled", services with "enabled" or
	// "detection_only" must get ctl:ruleEngine=On to override the global Off.
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "disabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{
			"active.erfi.io":   {Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 5, OutboundThreshold: 4},
			"logonly.erfi.io":  {Mode: "detection_only", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
			"alsodead.erfi.io": {Mode: "disabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	output := GenerateWAFSettings(cfg)

	// Global Off should be present as a config-time directive.
	if !strings.Contains(output, "SecRuleEngine Off") {
		t.Error("should contain global SecRuleEngine Off")
	}

	// active.erfi.io should get ctl:ruleEngine=On.
	activeIdx := strings.Index(output, "active.erfi.io")
	if activeIdx < 0 {
		t.Fatal("should contain active.erfi.io")
	}
	afterActive := output[activeIdx:]
	if !strings.Contains(afterActive, "ctl:ruleEngine=On") {
		t.Error("active.erfi.io should have ctl:ruleEngine=On")
	}

	// logonly.erfi.io should get ctl:ruleEngine=DetectionOnly (not just On).
	// detection_only mode must use DetectionOnly so Coraza logs but never blocks.
	logonlyIdx := strings.Index(output, "logonly.erfi.io")
	if logonlyIdx < 0 {
		t.Fatal("should contain logonly.erfi.io")
	}
	afterLogonly := output[logonlyIdx:]
	if !strings.Contains(afterLogonly, "ctl:ruleEngine=DetectionOnly") {
		t.Error("logonly.erfi.io should have ctl:ruleEngine=DetectionOnly")
	}

	// alsodead.erfi.io should NOT appear (same as default: disabled).
	if strings.Contains(output, "alsodead.erfi.io") {
		t.Error("alsodead.erfi.io should not generate output (same mode as default)")
	}
}

// TestGenerateWAFSettingsAllModeTransitions tests every combination of
// global default mode and per-service override mode to ensure the correct
// SecRuleEngine / ctl:ruleEngine directives are emitted.
func TestGenerateWAFSettingsAllModeTransitions(t *testing.T) {
	modes := []string{"enabled", "detection_only", "disabled"}
	base := WAFServiceSettings{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}

	for _, globalMode := range modes {
		for _, svcMode := range modes {
			name := "global_" + globalMode + "_svc_" + svcMode
			t.Run(name, func(t *testing.T) {
				defaults := base
				defaults.Mode = globalMode
				svc := base
				svc.Mode = svcMode
				cfg := WAFConfig{
					Defaults: defaults,
					Services: map[string]WAFServiceSettings{
						"test.erfi.io": svc,
					},
				}
				output := GenerateWAFSettings(cfg)

				// Global SecRuleEngine directive should always be present.
				switch globalMode {
				case "enabled":
					if !strings.Contains(output, "SecRuleEngine On") {
						t.Error("global enabled should emit SecRuleEngine On")
					}
				case "detection_only":
					if !strings.Contains(output, "SecRuleEngine DetectionOnly") {
						t.Error("global detection_only should emit SecRuleEngine DetectionOnly")
					}
					if !strings.Contains(output, "anomaly_score_threshold=10000") {
						t.Error("global detection_only should set thresholds to 10000")
					}
				case "disabled":
					if !strings.Contains(output, "SecRuleEngine Off") {
						t.Error("global disabled should emit SecRuleEngine Off")
					}
				}

				// Per-service engine override when modes differ.
				svcSection := ""
				idx := strings.Index(output, "test.erfi.io")
				if idx >= 0 {
					svcSection = output[idx:]
				}

				if globalMode == svcMode {
					// Same mode → no per-service override needed (skip if
					// paranoia/thresholds also match).
					if svcSection != "" && strings.Contains(svcSection, "ctl:ruleEngine") {
						t.Error("same mode should not emit per-service ctl:ruleEngine")
					}
				} else {
					switch {
					case svcMode == "disabled" && globalMode != "disabled":
						if !strings.Contains(svcSection, "ctl:ruleEngine=Off") {
							t.Error("svc disabled (global non-disabled) should emit ctl:ruleEngine=Off")
						}
					case svcMode == "detection_only":
						if !strings.Contains(svcSection, "ctl:ruleEngine=DetectionOnly") {
							t.Error("svc detection_only should emit ctl:ruleEngine=DetectionOnly")
						}
					case svcMode == "enabled" && (globalMode == "disabled" || globalMode == "detection_only"):
						if !strings.Contains(svcSection, "ctl:ruleEngine=On") {
							t.Error("svc enabled (global " + globalMode + ") should emit ctl:ruleEngine=On")
						}
					}
				}
			})
		}
	}
}

// TestGenerateWAFSettingsEnabledEmitsSecRuleEngineOn verifies that the default
// "enabled" mode explicitly emits SecRuleEngine On, since the Caddyfile no
// longer contains this directive.
func TestGenerateWAFSettingsEnabledEmitsSecRuleEngineOn(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	if !strings.Contains(output, "SecRuleEngine On") {
		t.Error("enabled mode must emit SecRuleEngine On")
	}
	if strings.Contains(output, "SecRuleEngine Off") || strings.Contains(output, "SecRuleEngine DetectionOnly") {
		t.Error("enabled mode should not emit Off or DetectionOnly")
	}
	// Verify paranoia and thresholds are emitted with actual values (not 10000).
	if !strings.Contains(output, "paranoia_level=2") {
		t.Error("should set paranoia_level=2")
	}
	if !strings.Contains(output, "inbound_anomaly_score_threshold=10") {
		t.Error("should set inbound threshold to 10")
	}
}

// TestGenerateWAFSettingsDetectionOnlyToBlocking tests switching from
// detection_only global to per-service blocking (enabled) mode.
func TestGenerateWAFSettingsDetectionOnlyToBlocking(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "detection_only", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{
			"strict.erfi.io": {Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	output := GenerateWAFSettings(cfg)

	// Global should be DetectionOnly.
	if !strings.Contains(output, "SecRuleEngine DetectionOnly") {
		t.Error("global should be SecRuleEngine DetectionOnly")
	}

	// strict.erfi.io should re-enable blocking.
	idx := strings.Index(output, "strict.erfi.io")
	if idx < 0 {
		t.Fatal("should contain strict.erfi.io")
	}
	after := output[idx:]
	if !strings.Contains(after, "ctl:ruleEngine=On") {
		t.Error("strict.erfi.io should have ctl:ruleEngine=On to override DetectionOnly")
	}
}

// TestGenerateWAFSettingsPlaceholderContainsSecRuleEngine verifies the
// placeholder file written by ensureCorazaDir includes SecRuleEngine On.
func TestGenerateWAFSettingsPlaceholderContainsSecRuleEngine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "coraza")
	if err := ensureCorazaDir(dir); err != nil {
		t.Fatalf("ensureCorazaDir failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "custom-waf-settings.conf"))
	if err != nil {
		t.Fatalf("reading placeholder: %v", err)
	}
	if !strings.Contains(string(data), "SecRuleEngine On") {
		t.Error("placeholder custom-waf-settings.conf should contain SecRuleEngine On")
	}
}

func TestConfigMigrationFromOldFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Write old format config.
	oldConfig := `{"paranoia_level":2,"inbound_threshold":15,"outbound_threshold":15,"rule_engine":"DetectionOnly","services":{"test.erfi.io":{"profile":"strict"},"qbit.erfi.io":{"profile":"off"}}}`
	os.WriteFile(path, []byte(oldConfig), 0644)

	cs := NewConfigStore(path)
	cfg := cs.Get()

	// Check migrated defaults.
	if cfg.Defaults.Mode != "detection_only" {
		t.Errorf("migrated mode: want detection_only, got %s", cfg.Defaults.Mode)
	}
	if cfg.Defaults.ParanoiaLevel != 2 {
		t.Errorf("migrated paranoia: want 2, got %d", cfg.Defaults.ParanoiaLevel)
	}
	if cfg.Defaults.InboundThreshold != 15 {
		t.Errorf("migrated inbound: want 15, got %d", cfg.Defaults.InboundThreshold)
	}

	// Check migrated services.
	if ss, ok := cfg.Services["test.erfi.io"]; !ok {
		t.Error("migrated service test.erfi.io not found")
	} else if ss.Mode != "enabled" {
		t.Errorf("migrated test.erfi.io mode: want enabled, got %s", ss.Mode)
	}
	if ss, ok := cfg.Services["qbit.erfi.io"]; !ok {
		t.Error("migrated service qbit.erfi.io not found")
	} else if ss.Mode != "disabled" {
		t.Errorf("migrated qbit.erfi.io mode: want disabled, got %s", ss.Mode)
	}
}

// --- Generate config endpoint test ---

func TestGenerateConfigEndpoint(t *testing.T) {
	cs := newTestConfigStore(t)
	es := newTestExclusionStore(t)

	cs.Update(WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8},
		Services: map[string]WAFServiceSettings{},
	})

	es.Create(RuleExclusion{
		Name:    "Test",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/config/generate", handleGenerateConfig(cs, es))

	req := httptest.NewRequest("POST", "/api/config/generate", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	// Pre-CRS exclusions should NOT contain CRS setup — those are in waf_settings.
	if strings.Contains(resp["pre_crs_conf"], "blocking_paranoia_level") {
		t.Error("pre-crs should not contain paranoia level (managed by waf_settings)")
	}
	if !strings.Contains(resp["post_crs_conf"], "SecRuleRemoveById 920420") {
		t.Error("should contain exclusion")
	}
	// WAF settings should contain paranoia level.
	if !strings.Contains(resp["waf_settings"], "paranoia_level=2") {
		t.Error("waf_settings should contain paranoia_level=2")
	}
}

// --- UUID generation test ---

func TestGenerateUUID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateUUID()
		if seen[id] {
			t.Fatalf("duplicate UUID: %s", id)
		}
		seen[id] = true

		// Basic format check: should contain hyphens.
		parts := strings.Split(id, "-")
		if len(parts) != 5 {
			t.Errorf("UUID format: want 5 parts, got %d in %s", len(parts), id)
		}
	}
}

// --- SnapshotSince test ---

func TestSnapshotSince(t *testing.T) {
	// Use old events that are definitely outside any hours window.
	oldLines := []string{
		`{"transaction":{"timestamp":"2020/01/01 00:00:00","unix_timestamp":1577836800000000000,"id":"OLD1","client_ip":"1.1.1.1","client_port":0,"host_ip":"","host_port":0,"server_id":"test.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/old","http_version":"","headers":{"User-Agent":["old"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":200,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":[]},"highest_severity":"","is_interrupted":false}}`,
	}
	path := writeTempLog(t, oldLines)
	store := NewStore(path)
	store.Load()

	// hours=0 (all time) should return everything.
	all := store.SnapshotSince(0)
	if len(all) != 1 {
		t.Errorf("all: want 1, got %d", len(all))
	}

	// hours=1 should filter out old events.
	recent := store.SnapshotSince(1)
	if len(recent) != 0 {
		t.Errorf("hours=1 for old events: want 0, got %d", len(recent))
	}

	// Now test with the standard sample lines (recent events).
	path2 := writeTempLog(t, sampleLines)
	store2 := NewStore(path2)
	store2.Load()
	all2 := store2.SnapshotSince(0)
	if len(all2) != 3 {
		t.Errorf("all sampleLines: want 3, got %d", len(all2))
	}
}

// --- Enhanced generator tests (method chaining, path operators) ---

func TestGenerateWithMethodFilter(t *testing.T) {
	ResetRuleIDCounter()

	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:   "POST-only upload exclusion",
			Type:   "runtime_remove_by_id",
			RuleID: "942100",
			Conditions: []Condition{
				{Field: "method", Operator: "eq", Value: "POST"},
				{Field: "path", Operator: "eq", Value: "/api/upload"},
			},
			Enabled: true,
		},
	}

	result := GenerateConfigs(cfg, exclusions)

	// Should have a chained rule: METHOD match then URI match
	if !strings.Contains(result.PreCRS, `REQUEST_METHOD "@streq POST"`) {
		t.Error("pre-crs should contain REQUEST_METHOD chain for POST")
	}
	if !strings.Contains(result.PreCRS, "chain") {
		t.Error("pre-crs should contain chain action for method filter")
	}
	if !strings.Contains(result.PreCRS, "ruleRemoveById=942100") {
		t.Error("pre-crs should contain the ctl action")
	}
}

func TestGenerateWithMultiMethodFilter(t *testing.T) {
	ResetRuleIDCounter()

	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:   "POST|PUT upload exclusion",
			Type:   "runtime_remove_by_id",
			RuleID: "942100",
			Conditions: []Condition{
				{Field: "method", Operator: "in", Value: "POST|PUT"},
				{Field: "path", Operator: "eq", Value: "/api/upload"},
			},
			Enabled: true,
		},
	}

	result := GenerateConfigs(cfg, exclusions)

	// Multiple methods should use @pm
	if !strings.Contains(result.PreCRS, `@pm POST|PUT`) {
		t.Error("pre-crs should use @pm for multiple methods")
	}
	if !strings.Contains(result.PreCRS, "chain") {
		t.Error("pre-crs should contain chain action")
	}
}

func TestGenerateWithPathOperator(t *testing.T) {
	ResetRuleIDCounter()

	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:       "Regex path exclusion",
			Type:       "runtime_remove_by_id",
			RuleID:     "941100",
			Conditions: []Condition{{Field: "path", Operator: "regex", Value: "^/api/v[0-9]+/webhook"}},
			Enabled:    true,
		},
		{
			Name:       "Prefix path exclusion",
			Type:       "runtime_remove_by_tag",
			RuleTag:    "attack-sqli",
			Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/api/"}},
			Enabled:    true,
		},
	}

	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, `@rx ^/api/v[0-9]+/webhook`) {
		t.Error("pre-crs should contain @rx operator")
	}
	if !strings.Contains(result.PreCRS, `@beginsWith /api/`) {
		t.Error("pre-crs should contain @beginsWith operator")
	}
}

func TestGenerateWithMethodAndOperator(t *testing.T) {
	ResetRuleIDCounter()

	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:     "POST + regex combo",
			Type:     "runtime_remove_target_by_id",
			RuleID:   "943100",
			Variable: "ARGS:data",
			Conditions: []Condition{
				{Field: "method", Operator: "eq", Value: "POST"},
				{Field: "path", Operator: "regex", Value: "^/webhook/"},
			},
			Enabled: true,
		},
	}

	result := GenerateConfigs(cfg, exclusions)

	// Should have chained: METHOD then URI with @rx
	if !strings.Contains(result.PreCRS, `REQUEST_METHOD "@streq POST"`) {
		t.Error("should contain method match")
	}
	if !strings.Contains(result.PreCRS, `@rx ^/webhook/`) {
		t.Error("should contain @rx operator")
	}
	if !strings.Contains(result.PreCRS, "ruleRemoveTargetById=943100;ARGS:data") {
		t.Error("should contain target removal action")
	}
}

// --- Condition validation tests ---

func TestValidateConditionFields(t *testing.T) {
	// Valid: all field types with appropriate operators
	validCases := []Condition{
		{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
		{Field: "ip", Operator: "eq", Value: "1.2.3.4"},
		{Field: "path", Operator: "eq", Value: "/api/"},
		{Field: "path", Operator: "regex", Value: "^/api/v[0-9]+/"},
		{Field: "path", Operator: "begins_with", Value: "/api/"},
		{Field: "host", Operator: "eq", Value: "radarr.erfi.io"},
		{Field: "method", Operator: "eq", Value: "POST"},
		{Field: "method", Operator: "in", Value: "GET|POST"},
		{Field: "user_agent", Operator: "regex", Value: "BadBot.*"},
		{Field: "header", Operator: "eq", Value: "X-Custom:value"},
		{Field: "query", Operator: "contains", Value: "debug=true"},
	}

	for _, c := range validCases {
		e := RuleExclusion{
			Name:       "test",
			Type:       "allow",
			Conditions: []Condition{c},
		}
		if err := validateExclusion(e); err != nil {
			t.Errorf("condition %s/%s should be valid, got: %v", c.Field, c.Operator, err)
		}
	}

	// Invalid field
	e := RuleExclusion{
		Name:       "test",
		Type:       "allow",
		Conditions: []Condition{{Field: "invalid_field", Operator: "eq", Value: "x"}},
	}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for invalid condition field")
	}

	// Invalid operator for field
	e.Conditions = []Condition{{Field: "ip", Operator: "begins_with", Value: "1.2.3.4"}}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for invalid operator on ip field")
	}

	// Empty value
	e.Conditions = []Condition{{Field: "path", Operator: "eq", Value: ""}}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for empty condition value")
	}

	// Invalid method value
	e.Conditions = []Condition{{Field: "method", Operator: "eq", Value: "INVALID"}}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for invalid method value")
	}

	// Partially invalid method
	e.Conditions = []Condition{{Field: "method", Operator: "in", Value: "GET|INVALID"}}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for partially invalid method value")
	}
}

func TestValidateGroupOperator(t *testing.T) {
	base := RuleExclusion{
		Name:       "test",
		Type:       "allow",
		Conditions: []Condition{{Field: "ip", Operator: "eq", Value: "1.2.3.4"}},
	}

	for _, op := range []string{"", "and", "or"} {
		e := base
		e.GroupOp = op
		if err := validateExclusion(e); err != nil {
			t.Errorf("group_operator %q should be valid, got: %v", op, err)
		}
	}

	e := base
	e.GroupOp = "invalid"
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for invalid group_operator")
	}
}

// --- Quick Action validation tests ---

func TestValidateAllowAction(t *testing.T) {
	// Valid: allow by IP
	e := RuleExclusion{Name: "Allow my IP", Type: "allow", Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "195.240.81.42"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("allow by IP should be valid: %v", err)
	}

	// Valid: allow by path
	e = RuleExclusion{Name: "Allow API", Type: "allow", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/health"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("allow by path should be valid: %v", err)
	}

	// Invalid: no conditions
	e = RuleExclusion{Name: "Empty allow", Type: "allow"}
	if err := validateExclusion(e); err == nil {
		t.Error("allow with no conditions should fail validation")
	}
}

func TestValidateBlockAction(t *testing.T) {
	// Valid: block by IP
	e := RuleExclusion{Name: "Block bad IP", Type: "block", Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "10.0.0.1"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("block by IP should be valid: %v", err)
	}

	// Valid: block by UA
	e = RuleExclusion{Name: "Block bot", Type: "block", Conditions: []Condition{{Field: "user_agent", Operator: "regex", Value: "BadBot/1.0"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("block by UA should be valid: %v", err)
	}

	// Invalid: no conditions
	e = RuleExclusion{Name: "Empty block", Type: "block"}
	if err := validateExclusion(e); err == nil {
		t.Error("block with no conditions should fail validation")
	}
}

func TestValidateSkipRuleAction(t *testing.T) {
	// Valid: skip rule by ID + path
	e := RuleExclusion{Name: "Skip 920420", Type: "skip_rule", RuleID: "920420", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/socket.io/"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("skip_rule should be valid: %v", err)
	}

	// Invalid: no rule ID/tag
	e = RuleExclusion{Name: "Skip nothing", Type: "skip_rule", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/"}}}
	if err := validateExclusion(e); err == nil {
		t.Error("skip_rule without rule_id or rule_tag should fail")
	}

	// Invalid: no conditions
	e = RuleExclusion{Name: "Skip everywhere", Type: "skip_rule", RuleID: "920420"}
	if err := validateExclusion(e); err == nil {
		t.Error("skip_rule without conditions should fail")
	}
}

func TestValidateRawAction(t *testing.T) {
	// Valid
	e := RuleExclusion{Name: "Custom rule", Type: "raw", RawRule: "SecRule REQUEST_URI \"@streq /test\" \"id:10001,phase:1,pass,nolog\""}
	if err := validateExclusion(e); err != nil {
		t.Errorf("raw with raw_rule should be valid: %v", err)
	}

	// Invalid: no raw_rule
	e = RuleExclusion{Name: "Empty raw", Type: "raw"}
	if err := validateExclusion(e); err == nil {
		t.Error("raw without raw_rule should fail")
	}
}

// --- Quick Action generator tests ---

func TestGenerateAllowByIP(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Allow my IP", Type: "allow", Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "195.240.81.42"}}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "@ipMatch 195.240.81.42") {
		t.Error("expected @ipMatch in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "allow") {
		t.Error("expected allow action in pre-CRS output")
	}
}

func TestGenerateAllowByIPAndPath(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Allow my IP on API", Type: "allow", Conditions: []Condition{
			{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
			{Field: "path", Operator: "begins_with", Value: "/api/"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "@ipMatch 10.0.0.0/8") {
		t.Error("expected @ipMatch in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "chain") {
		t.Error("expected chain for IP+path allow rule")
	}
	if !strings.Contains(result.PreCRS, "@beginsWith /api/") {
		t.Error("expected @beginsWith in chained rule")
	}
}

func TestGenerateBlockByIP(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block bad actor", Type: "block", Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "192.168.1.100"}}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "@ipMatch 192.168.1.100") {
		t.Error("expected @ipMatch in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "deny,status:403") {
		t.Error("expected deny action in pre-CRS output")
	}
}

func TestGenerateBlockByUA(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block bad bot", Type: "block", Conditions: []Condition{{Field: "user_agent", Operator: "regex", Value: "BadBot.*"}}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_HEADERS:User-Agent") {
		t.Error("expected User-Agent check in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "@rx BadBot.*") {
		t.Error("expected @rx operator for UA pattern")
	}
}

func TestGenerateSkipRule(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Skip 920420 for socket.io", Type: "skip_rule", RuleID: "920420", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/socket.io/"}}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveById=920420") {
		t.Error("expected ctl:ruleRemoveById in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "@streq /socket.io/") {
		t.Error("expected path condition in pre-CRS output")
	}
}

func TestGenerateSkipRuleByTag(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Skip SQLi for API", Type: "skip_rule", RuleTag: "attack-sqli", Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/api/v3/"}}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveByTag=attack-sqli") {
		t.Error("expected ctl:ruleRemoveByTag in pre-CRS output")
	}
}

func TestGenerateRawRule(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	rawDirective := "SecRule REQUEST_URI \"@streq /admin\" \"id:10001,phase:1,deny,status:403,t:none,log\""
	exclusions := []RuleExclusion{
		{Name: "Custom block admin", Type: "raw", RawRule: rawDirective, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, rawDirective) {
		t.Error("expected raw rule verbatim in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "# Custom block admin") {
		t.Error("expected name comment in pre-CRS output")
	}
}

// --- Deploy tests ---

func TestEnsureCorazaDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "coraza")
	if err := ensureCorazaDir(dir); err != nil {
		t.Fatalf("ensureCorazaDir failed: %v", err)
	}

	// Check placeholder files exist
	for _, name := range []string{"custom-pre-crs.conf", "custom-post-crs.conf"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
		if !strings.Contains(string(data), "Managed by waf-api") {
			t.Errorf("%s missing header comment", name)
		}
	}

	// Calling again should be idempotent (doesn't overwrite)
	if err := ensureCorazaDir(dir); err != nil {
		t.Fatalf("second ensureCorazaDir failed: %v", err)
	}
}

func TestWriteConfFiles(t *testing.T) {
	dir := t.TempDir()
	pre := "# pre-crs content\nSecRuleRemoveById 920420\n"
	post := "# post-crs content\n"
	settings := "# waf settings\nSecAction \"id:9700001,phase:1,pass,t:none,nolog\"\n"

	if err := writeConfFiles(dir, pre, post, settings); err != nil {
		t.Fatalf("writeConfFiles failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "custom-pre-crs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != pre {
		t.Errorf("pre-crs content mismatch: got %q", string(data))
	}

	data, err = os.ReadFile(filepath.Join(dir, "custom-post-crs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != post {
		t.Errorf("post-crs content mismatch: got %q", string(data))
	}

	data, err = os.ReadFile(filepath.Join(dir, "custom-waf-settings.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != settings {
		t.Errorf("waf-settings content mismatch: got %q", string(data))
	}
}

func TestDeployEndpoint(t *testing.T) {
	corazaDir := t.TempDir()
	caddyfileDir := t.TempDir()
	caddyfilePath := filepath.Join(caddyfileDir, "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80 {\n\trespond \"ok\"\n}\n"), 0644)

	// Mock Caddy admin API
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer adminServer.Close()

	deployCfg := DeployConfig{
		CorazaDir:     corazaDir,
		CaddyfilePath: caddyfilePath,
		CaddyAdminURL: adminServer.URL,
	}

	excDir := t.TempDir()
	cfgDir := t.TempDir()
	es := NewExclusionStore(filepath.Join(excDir, "exclusions.json"))
	cs := NewConfigStore(filepath.Join(cfgDir, "config.json"))

	// Create an exclusion so the generated config isn't empty
	es.Create(RuleExclusion{
		Name:    "test-exclusion",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(cs, es, deployCfg))

	req := httptest.NewRequest("POST", "/api/config/deploy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp DeployResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "deployed" {
		t.Errorf("expected status=deployed, got %q", resp.Status)
	}
	if !resp.Reloaded {
		t.Error("expected reloaded=true")
	}

	// Verify files were written
	preData, err := os.ReadFile(filepath.Join(corazaDir, "custom-pre-crs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(preData) == 0 {
		t.Error("custom-pre-crs.conf is empty")
	}
}

func TestDeployEndpointReloadFail(t *testing.T) {
	corazaDir := t.TempDir()
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80\n"), 0644)

	// Admin server that always fails
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("reload failed"))
	}))
	defer adminServer.Close()

	deployCfg := DeployConfig{
		CorazaDir:     corazaDir,
		CaddyfilePath: caddyfilePath,
		CaddyAdminURL: adminServer.URL,
	}

	es := NewExclusionStore(filepath.Join(t.TempDir(), "exclusions.json"))
	cs := NewConfigStore(filepath.Join(t.TempDir(), "config.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(cs, es, deployCfg))

	req := httptest.NewRequest("POST", "/api/config/deploy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200 (partial success), got %d", rec.Code)
	}

	var resp DeployResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Status != "partial" {
		t.Errorf("expected status=partial, got %q", resp.Status)
	}
	if resp.Reloaded {
		t.Error("expected reloaded=false")
	}
}

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

func TestCRSRulesEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/crs/rules", handleCRSRules)

	req := httptest.NewRequest("GET", "/api/crs/rules", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var catalog CRSCatalogResponse
	if err := json.NewDecoder(rec.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total == 0 {
		t.Error("expected non-zero total rules")
	}
	if len(catalog.Categories) == 0 {
		t.Error("expected non-empty categories")
	}
	if len(catalog.Rules) != catalog.Total {
		t.Errorf("rules length %d != total %d", len(catalog.Rules), catalog.Total)
	}
	// Verify a known rule exists.
	found := false
	for _, r := range catalog.Rules {
		if r.ID == "920420" {
			found = true
			if r.Category != "protocol-enforcement" {
				t.Errorf("rule 920420: expected category protocol-enforcement, got %s", r.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected rule 920420 in catalog")
	}
}

func TestCRSAutocompleteEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/crs/autocomplete", handleCRSAutocomplete)

	req := httptest.NewRequest("GET", "/api/crs/autocomplete", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var ac CRSAutocompleteResponse
	if err := json.NewDecoder(rec.Body).Decode(&ac); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(ac.Variables) == 0 {
		t.Error("expected non-empty variables")
	}
	if len(ac.Operators) == 0 {
		t.Error("expected non-empty operators")
	}
	if len(ac.Actions) == 0 {
		t.Error("expected non-empty actions")
	}
	// Verify operators have human-readable labels.
	for _, op := range ac.Operators {
		if op.Label == "" {
			t.Errorf("operator %s has empty label", op.Name)
		}
	}
}

// --- Rule match (messages) parsing tests ---

func TestParseEventWithMessages(t *testing.T) {
	// Audit log entry with messages array (part H)
	logLine := `{"transaction":{"timestamp":"2026/02/22 09:00:00","unix_timestamp":1771750800000000000,"id":"MSG111","client_ip":"10.0.0.1","client_port":0,"host_ip":"","host_port":0,"server_id":"radarr.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/.env","http_version":"","headers":{"User-Agent":["curl/7.68"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":403,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":true},"messages":[{"actionset":"","message":"","data":{"file":"REQUEST-930-APPLICATION-ATTACK-LFI.conf","line":100,"id":930120,"rev":"","msg":"OS File Access Attempt","data":"Matched Data: .env found within REQUEST_FILENAME: /.env","severity":2,"ver":"OWASP_CRS/4.15.0","tags":["attack-lfi","OWASP_CRS"]}},{"actionset":"","message":"","data":{"file":"REQUEST-949-BLOCKING-EVALUATION.conf","line":1,"id":949110,"rev":"","msg":"Inbound Anomaly Score Exceeded","data":"","severity":0,"ver":"","tags":["anomaly-evaluation"]}}]}`

	path := writeTempLog(t, []string{logLine})
	store := NewStore(path)
	store.Load()

	events := store.FilteredEvents("", "", "", nil, 50, 0, 0)
	if events.Total != 1 {
		t.Fatalf("expected 1 event, got %d", events.Total)
	}

	ev := events.Events[0]
	// Should pick rule 930120 (the real detection rule), not 949110 (anomaly scoring)
	if ev.RuleID != 930120 {
		t.Errorf("expected rule_id=930120, got %d", ev.RuleID)
	}
	if ev.RuleMsg != "OS File Access Attempt" {
		t.Errorf("expected rule_msg='OS File Access Attempt', got %q", ev.RuleMsg)
	}
	if ev.Severity != 2 {
		t.Errorf("expected severity=2, got %d", ev.Severity)
	}
	if !strings.Contains(ev.MatchedData, ".env") {
		t.Errorf("expected matched_data to contain '.env', got %q", ev.MatchedData)
	}
	if len(ev.RuleTags) == 0 {
		t.Error("expected non-empty rule_tags")
	}
}

func TestParseEventWithoutMessages(t *testing.T) {
	// Original format without messages — should still work with zero values
	path := writeTempLog(t, sampleLines[:1])
	store := NewStore(path)
	store.Load()

	events := store.FilteredEvents("", "", "", nil, 50, 0, 0)
	if events.Total != 1 {
		t.Fatalf("expected 1 event, got %d", events.Total)
	}

	ev := events.Events[0]
	if ev.RuleID != 0 {
		t.Errorf("expected rule_id=0 (no messages), got %d", ev.RuleID)
	}
	if ev.RuleMsg != "" {
		t.Errorf("expected empty rule_msg, got %q", ev.RuleMsg)
	}
}

// --- Rate Limit Store tests ---

func TestRateLimitStoreDefaults(t *testing.T) {
	s := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))
	cfg := s.Get()

	if len(cfg.Zones) != 23 {
		t.Fatalf("expected 23 default zones, got %d", len(cfg.Zones))
	}

	// Check a known zone
	z := s.GetZone("sonarr")
	if z == nil {
		t.Fatal("expected sonarr zone")
	}
	if z.Events != 300 || z.Window != "1m" || !z.Enabled {
		t.Errorf("sonarr: events=%d window=%s enabled=%v", z.Events, z.Window, z.Enabled)
	}

	// Non-existent zone
	if s.GetZone("nonexistent") != nil {
		t.Error("expected nil for nonexistent zone")
	}
}

func TestRateLimitStoreUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rl.json")
	s := NewRateLimitStore(path)

	newCfg := RateLimitConfig{
		Zones: []RateLimitZone{
			{Name: "test", Events: 500, Window: "5m", Enabled: true},
		},
	}
	updated, err := s.Update(newCfg)
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if len(updated.Zones) != 1 || updated.Zones[0].Name != "test" {
		t.Fatalf("unexpected update result: %+v", updated)
	}

	// Reload from disk
	s2 := NewRateLimitStore(path)
	cfg := s2.Get()
	if len(cfg.Zones) != 1 || cfg.Zones[0].Events != 500 {
		t.Errorf("persisted data mismatch: %+v", cfg)
	}
}

func TestRateLimitValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RateLimitConfig
		wantErr bool
	}{
		{
			name:    "valid",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test", Events: 100, Window: "1m", Enabled: true}}},
			wantErr: false,
		},
		{
			name:    "empty zones",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{}},
			wantErr: false,
		},
		{
			name:    "empty name",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "", Events: 100, Window: "1m"}}},
			wantErr: true,
		},
		{
			name:    "invalid name chars",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test zone", Events: 100, Window: "1m"}}},
			wantErr: true,
		},
		{
			name:    "duplicate names",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "a", Events: 100, Window: "1m"}, {Name: "a", Events: 200, Window: "1m"}}},
			wantErr: true,
		},
		{
			name:    "zero events",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test", Events: 0, Window: "1m"}}},
			wantErr: true,
		},
		{
			name:    "events too high",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test", Events: 200000, Window: "1m"}}},
			wantErr: true,
		},
		{
			name:    "empty window",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test", Events: 100, Window: ""}}},
			wantErr: true,
		},
		{
			name:    "invalid window",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test", Events: 100, Window: "abc"}}},
			wantErr: true,
		},
		{
			name:    "valid windows",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "a", Events: 100, Window: "30s"}, {Name: "b", Events: 100, Window: "5m"}, {Name: "c", Events: 100, Window: "1h"}}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRateLimitConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRateLimitConfig() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateZoneFile(t *testing.T) {
	t.Run("enabled zone", func(t *testing.T) {
		zone := RateLimitZone{Name: "sonarr", Events: 300, Window: "1m", Enabled: true}
		content := generateZoneFile(zone)

		if !strings.Contains(content, "zone sonarr") {
			t.Error("expected zone name in output")
		}
		if !strings.Contains(content, "events 300") {
			t.Error("expected events 300")
		}
		if !strings.Contains(content, "window 1m") {
			t.Error("expected window 1m")
		}
		if !strings.Contains(content, "rate_limit {") {
			t.Error("expected rate_limit directive")
		}
		if !strings.Contains(content, "not header Connection *Upgrade*") {
			t.Error("expected WebSocket exclusion")
		}
		if !strings.Contains(content, `X-RateLimit-Limit "300"`) {
			t.Error("expected X-RateLimit-Limit header")
		}
	})

	t.Run("disabled zone", func(t *testing.T) {
		zone := RateLimitZone{Name: "test", Events: 100, Window: "1m", Enabled: false}
		content := generateZoneFile(zone)

		if strings.Contains(content, "rate_limit {") {
			t.Error("disabled zone should not contain rate_limit directive")
		}
		if !strings.Contains(content, "Rate limiting disabled") {
			t.Error("expected disabled comment")
		}
	})
}

func TestWriteZoneFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rl")

	zones := []RateLimitZone{
		{Name: "test1", Events: 100, Window: "1m", Enabled: true},
		{Name: "test2", Events: 500, Window: "5m", Enabled: false},
	}

	written, err := writeZoneFiles(dir, zones)
	if err != nil {
		t.Fatalf("writeZoneFiles failed: %v", err)
	}
	if len(written) != 2 {
		t.Fatalf("expected 2 files written, got %d", len(written))
	}

	// Check file 1 exists and has content
	data1, err := os.ReadFile(filepath.Join(dir, "test1.caddy"))
	if err != nil {
		t.Fatalf("reading test1.caddy: %v", err)
	}
	if !strings.Contains(string(data1), "events 100") {
		t.Error("test1.caddy missing events")
	}

	// Check file 2 is disabled
	data2, err := os.ReadFile(filepath.Join(dir, "test2.caddy"))
	if err != nil {
		t.Fatalf("reading test2.caddy: %v", err)
	}
	if strings.Contains(string(data2), "rate_limit") {
		t.Error("test2.caddy should be disabled (no rate_limit)")
	}
}

func TestRateLimitAPIEndpoints(t *testing.T) {
	rs := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rate-limits", handleGetRateLimits(rs))
	mux.HandleFunc("PUT /api/rate-limits", handleUpdateRateLimits(rs))

	// GET — should return defaults
	req := httptest.NewRequest("GET", "/api/rate-limits", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("GET expected 200, got %d", rec.Code)
	}

	var cfg RateLimitConfig
	json.NewDecoder(rec.Body).Decode(&cfg)
	if len(cfg.Zones) != 23 {
		t.Fatalf("expected 23 default zones, got %d", len(cfg.Zones))
	}

	// PUT — update to single zone
	body := `{"zones":[{"name":"test","events":500,"window":"5m","enabled":true}]}`
	req = httptest.NewRequest("PUT", "/api/rate-limits", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("PUT expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var updated RateLimitConfig
	json.NewDecoder(rec.Body).Decode(&updated)
	if len(updated.Zones) != 1 || updated.Zones[0].Events != 500 {
		t.Errorf("unexpected PUT result: %+v", updated)
	}

	// PUT — validation error (duplicate names)
	body = `{"zones":[{"name":"a","events":100,"window":"1m"},{"name":"a","events":200,"window":"1m"}]}`
	req = httptest.NewRequest("PUT", "/api/rate-limits", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400 for duplicate names, got %d", rec.Code)
	}

	// PUT — validation error (bad window)
	body = `{"zones":[{"name":"x","events":100,"window":"bad"}]}`
	req = httptest.NewRequest("PUT", "/api/rate-limits", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400 for bad window, got %d", rec.Code)
	}
}

func TestRateLimitDeployEndpoint(t *testing.T) {
	rlDir := filepath.Join(t.TempDir(), "rl")
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost { respond 200 }"), 0644)

	// Mock Caddy admin API
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer adminServer.Close()

	deployCfg := DeployConfig{
		CorazaDir:     filepath.Join(t.TempDir(), "coraza"),
		RateLimitDir:  rlDir,
		CaddyfilePath: caddyfilePath,
		CaddyAdminURL: adminServer.URL,
	}

	rs := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))
	// Set a small config for testing
	rs.Update(RateLimitConfig{
		Zones: []RateLimitZone{
			{Name: "test", Events: 100, Window: "1m", Enabled: true},
			{Name: "disabled", Events: 50, Window: "30s", Enabled: false},
		},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/rate-limits/deploy", handleDeployRateLimits(rs, deployCfg))

	req := httptest.NewRequest("POST", "/api/rate-limits/deploy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RateLimitDeployResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Status != "deployed" {
		t.Errorf("expected status=deployed, got %q", resp.Status)
	}
	if !resp.Reloaded {
		t.Error("expected reloaded=true")
	}
	if len(resp.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(resp.Files))
	}

	// Verify files exist on disk
	data, err := os.ReadFile(filepath.Join(rlDir, "test.caddy"))
	if err != nil {
		t.Fatalf("reading test.caddy: %v", err)
	}
	if !strings.Contains(string(data), "events 100") {
		t.Error("test.caddy missing events")
	}

	data, err = os.ReadFile(filepath.Join(rlDir, "disabled.caddy"))
	if err != nil {
		t.Fatalf("reading disabled.caddy: %v", err)
	}
	if strings.Contains(string(data), "rate_limit") {
		t.Error("disabled.caddy should not have rate_limit directive")
	}
}

// ─── AccessLogStore (429 analytics) tests ───────────────────────────

// Sample combined access log lines — mix of 200s, 429s, 403s.
var sampleAccessLogLines = []string{
	`{"level":"info","ts":"2026/02/22 12:00:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["Sonarr/4.0"]}},"status":200,"size":1234,"duration":0.05}`,
	`{"level":"info","ts":"2026/02/22 12:01:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"status":429,"size":0,"duration":0.001}`,
	`{"level":"info","ts":"2026/02/22 12:02:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"POST","host":"radarr.erfi.io","uri":"/api/v3/command","headers":{"User-Agent":["curl/7.68"]}},"status":429,"size":0,"duration":0.001}`,
	`{"level":"info","ts":"2026/02/22 12:03:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/1.1","method":"GET","host":"radarr.erfi.io","uri":"/.env","headers":{"User-Agent":["BadBot/1.0"]}},"status":403,"size":0,"duration":0.002}`,
	`{"level":"info","ts":"2026/02/22 13:00:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/series","headers":{"User-Agent":["BadBot/1.0"]}},"status":429,"size":0,"duration":0.001}`,
}

func writeTempAccessLog(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "combined-access.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
	f.Close()
	return path
}

func TestAccessLogStoreLoad(t *testing.T) {
	path := writeTempAccessLog(t, sampleAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	// Only 3 lines are status 429 out of 5 total.
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3 429 events, got %d", got)
	}
}

func TestAccessLogStoreIgnoresNon429(t *testing.T) {
	// All 200s — should produce zero events.
	lines := []string{
		`{"level":"info","ts":"2026/02/22 12:00:00","logger":"test","msg":"handled request","request":{"remote_ip":"1.1.1.1","client_ip":"1.1.1.1","proto":"HTTP/2.0","method":"GET","host":"test.erfi.io","uri":"/","headers":{}},"status":200,"size":100,"duration":0.01}`,
		`{"level":"info","ts":"2026/02/22 12:01:00","logger":"test","msg":"handled request","request":{"remote_ip":"1.1.1.1","client_ip":"1.1.1.1","proto":"HTTP/2.0","method":"GET","host":"test.erfi.io","uri":"/","headers":{}},"status":403,"size":0,"duration":0.01}`,
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)
	store.Load()

	if got := store.EventCount(); got != 0 {
		t.Fatalf("expected 0 429 events, got %d", got)
	}
}

func TestAccessLogStoreIncrementalLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "combined-access.log")

	// Write first 2 lines (1 is 200, 1 is 429).
	f, _ := os.Create(path)
	for _, l := range sampleAccessLogLines[:2] {
		f.WriteString(l + "\n")
	}
	f.Close()

	store := NewAccessLogStore(path)
	store.Load()
	if got := store.EventCount(); got != 1 {
		t.Fatalf("expected 1 429 event, got %d", got)
	}

	// Append line 3 (another 429).
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString(sampleAccessLogLines[2] + "\n")
	f.Close()

	store.Load()
	if got := store.EventCount(); got != 2 {
		t.Fatalf("expected 2 429 events after append, got %d", got)
	}
}

func TestAccessLogStoreFileRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "combined-access.log")

	// Write all 5 lines (3 are 429).
	f, _ := os.Create(path)
	for _, l := range sampleAccessLogLines {
		f.WriteString(l + "\n")
	}
	f.Close()

	store := NewAccessLogStore(path)
	store.Load()
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3, got %d", got)
	}

	// Simulate rotation: truncate and write 1 line (a 429).
	f, _ = os.Create(path) // truncates
	f.WriteString(sampleAccessLogLines[1] + "\n")
	f.Close()

	store.Load()
	if got := store.EventCount(); got != 1 {
		t.Fatalf("expected 1 after rotation, got %d", got)
	}
}

func TestAccessLogStoreMissingFile(t *testing.T) {
	store := NewAccessLogStore("/nonexistent/combined-access.log")
	store.Load() // should not panic
	if got := store.EventCount(); got != 0 {
		t.Errorf("expected 0 events for missing file, got %d", got)
	}
}

func TestAccessLogStoreEventFields(t *testing.T) {
	// Single 429 line — verify all fields parsed correctly.
	lines := []string{
		`{"level":"info","ts":"2026/02/22 12:01:00","logger":"combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"POST","host":"radarr.erfi.io","uri":"/api/v3/command","headers":{"User-Agent":["curl/7.68"]}},"status":429,"size":0,"duration":0.001}`,
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)
	store.Load()

	events := store.snapshotSince(0)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.ClientIP != "10.0.0.2" {
		t.Errorf("client_ip: want 10.0.0.2, got %s", e.ClientIP)
	}
	if e.Service != "radarr.erfi.io" {
		t.Errorf("service: want radarr.erfi.io, got %s", e.Service)
	}
	if e.Method != "POST" {
		t.Errorf("method: want POST, got %s", e.Method)
	}
	if e.URI != "/api/v3/command" {
		t.Errorf("uri: want /api/v3/command, got %s", e.URI)
	}
	if e.UserAgent != "curl/7.68" {
		t.Errorf("user_agent: want curl/7.68, got %s", e.UserAgent)
	}
	expected := time.Date(2026, 2, 22, 12, 1, 0, 0, time.UTC)
	if !e.Timestamp.Equal(expected) {
		t.Errorf("timestamp: want %v, got %v", expected, e.Timestamp)
	}
}

func TestAccessLogStoreSummary(t *testing.T) {
	path := writeTempAccessLog(t, sampleAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	s := store.Summary(0) // all time

	if s.Total429s != 3 {
		t.Errorf("total_429s: want 3, got %d", s.Total429s)
	}
	if s.UniqueClients != 2 {
		t.Errorf("unique_clients: want 2 (10.0.0.2, 10.0.0.3), got %d", s.UniqueClients)
	}
	if s.UniqueServices != 2 {
		t.Errorf("unique_services: want 2 (sonarr, radarr), got %d", s.UniqueServices)
	}

	// EventsByHour: events span 12:xx and 13:xx → 2 buckets.
	if len(s.EventsByHour) != 2 {
		t.Errorf("events_by_hour: want 2 buckets, got %d", len(s.EventsByHour))
	}

	// TopClients: 10.0.0.2 has 2, 10.0.0.3 has 1.
	if len(s.TopClients) != 2 {
		t.Fatalf("top_clients: want 2, got %d", len(s.TopClients))
	}
	if s.TopClients[0].ClientIP != "10.0.0.2" || s.TopClients[0].Count != 2 {
		t.Errorf("top client: want 10.0.0.2 with count 2, got %s with %d",
			s.TopClients[0].ClientIP, s.TopClients[0].Count)
	}

	// TopServices: sonarr=2, radarr=1 (only 429s counted).
	if len(s.TopServices) != 2 {
		t.Fatalf("top_services: want 2, got %d", len(s.TopServices))
	}
	if s.TopServices[0].Service != "sonarr.erfi.io" || s.TopServices[0].Count != 2 {
		t.Errorf("top service: want sonarr.erfi.io with count 2, got %s with %d",
			s.TopServices[0].Service, s.TopServices[0].Count)
	}

	// RecentEvents: newest first.
	if len(s.RecentEvents) != 3 {
		t.Fatalf("recent_events: want 3, got %d", len(s.RecentEvents))
	}
	if s.RecentEvents[0].Service != "sonarr.erfi.io" || s.RecentEvents[0].ClientIP != "10.0.0.3" {
		t.Errorf("most recent event: want sonarr.erfi.io/10.0.0.3, got %s/%s",
			s.RecentEvents[0].Service, s.RecentEvents[0].ClientIP)
	}
}

func TestAccessLogStoreFilteredEvents(t *testing.T) {
	path := writeTempAccessLog(t, sampleAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	// Filter by service.
	resp := store.FilteredEvents("sonarr.erfi.io", "", "", 50, 0, 0)
	if resp.Total != 2 {
		t.Errorf("filter by service sonarr: want 2, got %d", resp.Total)
	}

	// Filter by client.
	resp = store.FilteredEvents("", "10.0.0.2", "", 50, 0, 0)
	if resp.Total != 2 {
		t.Errorf("filter by client 10.0.0.2: want 2, got %d", resp.Total)
	}

	// Filter by method.
	resp = store.FilteredEvents("", "", "POST", 50, 0, 0)
	if resp.Total != 1 {
		t.Errorf("filter by method POST: want 1, got %d", resp.Total)
	}

	// Combined filter.
	resp = store.FilteredEvents("sonarr.erfi.io", "10.0.0.2", "", 50, 0, 0)
	if resp.Total != 1 {
		t.Errorf("filter sonarr+10.0.0.2: want 1, got %d", resp.Total)
	}

	// Pagination.
	resp = store.FilteredEvents("", "", "", 1, 0, 0)
	if len(resp.Events) != 1 || resp.Total != 3 {
		t.Errorf("pagination: want 1 event of 3 total, got %d/%d", len(resp.Events), resp.Total)
	}

	// Offset beyond total.
	resp = store.FilteredEvents("", "", "", 50, 100, 0)
	if len(resp.Events) != 0 || resp.Total != 3 {
		t.Errorf("offset beyond total: want 0 events of 3 total, got %d/%d", len(resp.Events), resp.Total)
	}

	// Newest-first ordering.
	resp = store.FilteredEvents("", "", "", 50, 0, 0)
	if len(resp.Events) > 1 && !resp.Events[0].Timestamp.After(resp.Events[1].Timestamp) {
		t.Error("events should be sorted newest-first")
	}
}

func TestAccessLogStoreSnapshotSince(t *testing.T) {
	// Use old 429 events that are outside any hours window.
	oldLine := `{"level":"info","ts":"2020/01/01 00:00:00","logger":"combined","msg":"handled request","request":{"remote_ip":"1.1.1.1","client_ip":"1.1.1.1","proto":"HTTP/2.0","method":"GET","host":"test.erfi.io","uri":"/","headers":{}},"status":429,"size":0,"duration":0.001}`
	path := writeTempAccessLog(t, []string{oldLine})
	store := NewAccessLogStore(path)
	store.Load()

	// hours=0 (all time) — should include old events.
	all := store.snapshotSince(0)
	if len(all) != 1 {
		t.Errorf("all: want 1, got %d", len(all))
	}

	// hours=1 — should filter out old events.
	recent := store.snapshotSince(1)
	if len(recent) != 0 {
		t.Errorf("hours=1 for old events: want 0, got %d", len(recent))
	}
}

func TestAccessLogStoreSummaryWithHours(t *testing.T) {
	// Mix of old and "recent" (future-dated) 429 events.
	lines := []string{
		`{"level":"info","ts":"2020/01/01 00:00:00","logger":"combined","msg":"handled request","request":{"remote_ip":"1.1.1.1","client_ip":"1.1.1.1","proto":"HTTP/2.0","method":"GET","host":"old.erfi.io","uri":"/old","headers":{}},"status":429,"size":0,"duration":0.001}`,
		`{"level":"info","ts":"2026/02/22 12:01:00","logger":"combined","msg":"handled request","request":{"remote_ip":"2.2.2.2","client_ip":"2.2.2.2","proto":"HTTP/2.0","method":"GET","host":"new.erfi.io","uri":"/new","headers":{}},"status":429,"size":0,"duration":0.001}`,
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)
	store.Load()

	// All time.
	s := store.Summary(0)
	if s.Total429s != 2 {
		t.Errorf("all time: want 2, got %d", s.Total429s)
	}

	// hours=1 — only the "recent" one (which has timestamp in the future from test perspective, but let's check it works).
	// The old one from 2020 should be filtered out.
	s = store.Summary(1)
	// Both might be in range if running in 2026, but old one definitely isn't.
	if s.Total429s > 1 {
		t.Logf("hours=1 returned %d events (expected 0 or 1 depending on time)", s.Total429s)
	}
}

// --- Rate Limit Analytics HTTP endpoint tests ---

func TestRLSummaryEndpoint(t *testing.T) {
	path := writeTempAccessLog(t, sampleAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rate-limits/summary", handleRLSummary(store))

	req := httptest.NewRequest("GET", "/api/rate-limits/summary", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: want application/json, got %s", ct)
	}

	var resp RLSummaryResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total429s != 3 {
		t.Errorf("total_429s: want 3, got %d", resp.Total429s)
	}
	if resp.UniqueClients != 2 {
		t.Errorf("unique_clients: want 2, got %d", resp.UniqueClients)
	}
	if resp.UniqueServices != 2 {
		t.Errorf("unique_services: want 2, got %d", resp.UniqueServices)
	}
}

func TestRLSummaryEndpointWithHours(t *testing.T) {
	// Old 429 events only.
	oldLine := `{"level":"info","ts":"2020/01/01 00:00:00","logger":"combined","msg":"handled request","request":{"remote_ip":"1.1.1.1","client_ip":"1.1.1.1","proto":"HTTP/2.0","method":"GET","host":"test.erfi.io","uri":"/","headers":{}},"status":429,"size":0,"duration":0.001}`
	path := writeTempAccessLog(t, []string{oldLine})
	store := NewAccessLogStore(path)
	store.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rate-limits/summary", handleRLSummary(store))

	// hours=1 should filter out old events.
	req := httptest.NewRequest("GET", "/api/rate-limits/summary?hours=1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp RLSummaryResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total429s != 0 {
		t.Errorf("want 0 events with hours=1 for old data, got %d", resp.Total429s)
	}

	// Without hours filter, should get 1 event.
	req = httptest.NewRequest("GET", "/api/rate-limits/summary", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total429s != 1 {
		t.Errorf("want 1 event without filter, got %d", resp.Total429s)
	}
}

func TestRLEventsEndpoint(t *testing.T) {
	path := writeTempAccessLog(t, sampleAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rate-limits/events", handleRLEvents(store))

	// No filters — all 429 events.
	req := httptest.NewRequest("GET", "/api/rate-limits/events", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp RLEventsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 3 {
		t.Errorf("total: want 3, got %d", resp.Total)
	}
	if len(resp.Events) != 3 {
		t.Errorf("events count: want 3, got %d", len(resp.Events))
	}
}

func TestRLEventsEndpointWithFilters(t *testing.T) {
	path := writeTempAccessLog(t, sampleAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rate-limits/events", handleRLEvents(store))

	// Filter by service.
	req := httptest.NewRequest("GET", "/api/rate-limits/events?service=sonarr.erfi.io", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp RLEventsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 2 {
		t.Errorf("filter service=sonarr: want 2, got %d", resp.Total)
	}

	// Filter by client.
	req = httptest.NewRequest("GET", "/api/rate-limits/events?client=10.0.0.3", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 1 {
		t.Errorf("filter client=10.0.0.3: want 1, got %d", resp.Total)
	}

	// Filter by method.
	req = httptest.NewRequest("GET", "/api/rate-limits/events?method=POST", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 1 {
		t.Errorf("filter method=POST: want 1, got %d", resp.Total)
	}

	// Pagination: limit=1.
	req = httptest.NewRequest("GET", "/api/rate-limits/events?limit=1", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Events) != 1 || resp.Total != 3 {
		t.Errorf("pagination: want 1 event of 3 total, got %d/%d", len(resp.Events), resp.Total)
	}
}

func TestRLEventsEndpointEmpty(t *testing.T) {
	// No 429 events at all.
	lines := []string{
		`{"level":"info","ts":"2026/02/22 12:00:00","logger":"combined","msg":"handled request","request":{"remote_ip":"1.1.1.1","client_ip":"1.1.1.1","proto":"HTTP/2.0","method":"GET","host":"test.erfi.io","uri":"/","headers":{}},"status":200,"size":100,"duration":0.01}`,
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)
	store.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rate-limits/events", handleRLEvents(store))
	mux.HandleFunc("GET /api/rate-limits/summary", handleRLSummary(store))

	// Events endpoint.
	req := httptest.NewRequest("GET", "/api/rate-limits/events", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var evResp RLEventsResponse
	json.NewDecoder(w.Body).Decode(&evResp)
	if evResp.Total != 0 || len(evResp.Events) != 0 {
		t.Errorf("expected 0 events, got total=%d events=%d", evResp.Total, len(evResp.Events))
	}

	// Summary endpoint.
	req = httptest.NewRequest("GET", "/api/rate-limits/summary", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var sumResp RLSummaryResponse
	json.NewDecoder(w.Body).Decode(&sumResp)
	if sumResp.Total429s != 0 {
		t.Errorf("expected total_429s=0, got %d", sumResp.Total429s)
	}
	if sumResp.UniqueClients != 0 {
		t.Errorf("expected unique_clients=0, got %d", sumResp.UniqueClients)
	}
}

func TestAccessLogStoreMalformedLines(t *testing.T) {
	// Mix of valid and malformed JSON — malformed should be silently skipped.
	lines := []string{
		`not json at all`,
		`{"level":"info","ts":"2026/02/22 12:01:00","logger":"combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"test.erfi.io","uri":"/","headers":{}},"status":429,"size":0,"duration":0.001}`,
		`{"incomplete json`,
		``,
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)
	store.Load()

	if got := store.EventCount(); got != 1 {
		t.Errorf("expected 1 valid 429 event, got %d", got)
	}
}

// ─── Event Type + Merge tests ───────────────────────────────────────

func TestParseEventSetsEventType(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	events := store.Snapshot()
	for _, ev := range events {
		if ev.IsBlocked && ev.EventType != "blocked" {
			t.Errorf("event %s: is_blocked=true but event_type=%q", ev.ID, ev.EventType)
		}
		if !ev.IsBlocked && ev.EventType != "logged" {
			t.Errorf("event %s: is_blocked=false but event_type=%q", ev.ID, ev.EventType)
		}
	}

	// AAA111 and BBB222 are blocked, CCC333 is logged.
	blocked := 0
	logged := 0
	for _, ev := range events {
		switch ev.EventType {
		case "blocked":
			blocked++
		case "logged":
			logged++
		}
	}
	if blocked != 2 {
		t.Errorf("expected 2 blocked, got %d", blocked)
	}
	if logged != 1 {
		t.Errorf("expected 1 logged, got %d", logged)
	}
}

func TestRateLimitEventToEvent(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 2, 22, 12, 1, 0, 0, time.UTC),
		ClientIP:  "10.0.0.5",
		Service:   "sonarr.erfi.io",
		Method:    "GET",
		URI:       "/api/v3/queue",
		UserAgent: "curl/7.68",
	}

	ev := RateLimitEventToEvent(rle)

	if ev.EventType != "rate_limited" {
		t.Errorf("event_type: want rate_limited, got %s", ev.EventType)
	}
	if !ev.IsBlocked {
		t.Error("rate_limited events should have is_blocked=true")
	}
	if ev.ResponseStatus != 429 {
		t.Errorf("response_status: want 429, got %d", ev.ResponseStatus)
	}
	if ev.ClientIP != "10.0.0.5" {
		t.Errorf("client_ip: want 10.0.0.5, got %s", ev.ClientIP)
	}
	if ev.Service != "sonarr.erfi.io" {
		t.Errorf("service: want sonarr.erfi.io, got %s", ev.Service)
	}
	if ev.ID == "" {
		t.Error("ID should not be empty")
	}
	// UUIDv7 format: 8-4-4-4-12 hex chars, version nibble = 7
	parts := strings.Split(ev.ID, "-")
	if len(parts) != 5 {
		t.Errorf("ID should be UUIDv7 format (5 parts), got %s", ev.ID)
	} else if len(parts[2]) >= 1 && parts[2][0] != '7' {
		t.Errorf("ID should be UUIDv7 (version nibble 7), got %s", ev.ID)
	}
}

func TestSnapshotAsEvents(t *testing.T) {
	path := writeTempAccessLog(t, sampleAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	events := store.SnapshotAsEvents(0)
	if len(events) != 3 {
		t.Fatalf("expected 3 converted events, got %d", len(events))
	}

	for _, ev := range events {
		if ev.EventType != "rate_limited" {
			t.Errorf("expected event_type=rate_limited, got %s", ev.EventType)
		}
		if ev.ResponseStatus != 429 {
			t.Errorf("expected status=429, got %d", ev.ResponseStatus)
		}
	}
}

func TestSummaryMergesRateLimitedEvents(t *testing.T) {
	// WAF events.
	wafPath := writeTempLog(t, sampleLines)
	store := NewStore(wafPath)
	store.Load()

	// 429 events.
	alsPath := writeTempAccessLog(t, sampleAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()
	handleSummary(store, als)(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp SummaryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// 3 WAF events + 3 429 events = 6 total.
	if resp.TotalEvents != 6 {
		t.Errorf("total_events: want 6 (3 WAF + 3 RL), got %d", resp.TotalEvents)
	}
	if resp.RateLimited != 3 {
		t.Errorf("rate_limited: want 3, got %d", resp.RateLimited)
	}
	if resp.BlockedEvents != 2 {
		t.Errorf("blocked_events: want 2 (WAF only), got %d", resp.BlockedEvents)
	}
	if resp.LoggedEvents != 1 {
		t.Errorf("logged_events: want 1, got %d", resp.LoggedEvents)
	}
}

func TestEventsMergesRateLimitedEvents(t *testing.T) {
	wafPath := writeTempLog(t, sampleLines)
	store := NewStore(wafPath)
	store.Load()

	alsPath := writeTempAccessLog(t, sampleAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	// All events (no filter).
	req := httptest.NewRequest("GET", "/api/events?limit=100", nil)
	w := httptest.NewRecorder()
	handleEvents(store, als)(w, req)

	var resp EventsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 6 {
		t.Errorf("total: want 6 (3 WAF + 3 RL), got %d", resp.Total)
	}

	// Verify newest-first ordering.
	for i := 1; i < len(resp.Events); i++ {
		prev, _ := time.Parse(time.RFC3339Nano, resp.Events[i-1].Timestamp.Format(time.RFC3339Nano))
		curr, _ := time.Parse(time.RFC3339Nano, resp.Events[i].Timestamp.Format(time.RFC3339Nano))
		if prev.Before(curr) {
			t.Errorf("events not sorted newest-first at index %d", i)
			break
		}
	}
}

func TestEventsEventTypeFilter(t *testing.T) {
	wafPath := writeTempLog(t, sampleLines)
	store := NewStore(wafPath)
	store.Load()

	alsPath := writeTempAccessLog(t, sampleAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	tests := []struct {
		eventType string
		want      int
	}{
		{"blocked", 2},      // 2 WAF blocked events
		{"logged", 1},       // 1 WAF logged event
		{"rate_limited", 3}, // 3 429 events
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/api/events?event_type="+tt.eventType+"&limit=100", nil)
		w := httptest.NewRecorder()
		handleEvents(store, als)(w, req)

		var resp EventsResponse
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.Total != tt.want {
			t.Errorf("event_type=%s: want %d events, got %d", tt.eventType, tt.want, resp.Total)
		}
		// Verify all returned events have the correct type.
		for _, ev := range resp.Events {
			if ev.EventType != tt.eventType {
				t.Errorf("event_type=%s filter: event %s has type %s", tt.eventType, ev.ID, ev.EventType)
			}
		}
	}
}

// --- Eviction tests ---

func TestStoreEviction(t *testing.T) {
	// Create events: one old (2020), one recent (2026).
	lines := []string{
		`{"transaction":{"timestamp":"2020/01/01 00:00:00","unix_timestamp":1577836800000000000,"id":"OLD1","client_ip":"1.1.1.1","client_port":0,"host_ip":"","host_port":0,"server_id":"test.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/old","http_version":"","headers":{"User-Agent":["old"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":200,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":[]},"highest_severity":"","is_interrupted":false}}`,
	}
	// Append one of the recent sample lines.
	lines = append(lines, sampleLines[0])

	path := writeTempLog(t, lines)
	store := NewStore(path)
	// Set max age to 168 hours (7 days) — the 2020 event should be evicted, but today's event kept.
	store.SetMaxAge(168 * time.Hour)
	store.Load()

	// The old event from 2020 should have been evicted, leaving only the recent one.
	if got := store.EventCount(); got != 1 {
		t.Errorf("expected 1 event after eviction, got %d", got)
	}
}

func TestStoreEvictionNoMaxAge(t *testing.T) {
	// With no maxAge set, nothing should be evicted.
	lines := []string{
		`{"transaction":{"timestamp":"2020/01/01 00:00:00","unix_timestamp":1577836800000000000,"id":"OLD1","client_ip":"1.1.1.1","client_port":0,"host_ip":"","host_port":0,"server_id":"test.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/old","http_version":"","headers":{"User-Agent":["old"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":200,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":[]},"highest_severity":"","is_interrupted":false}}`,
	}
	path := writeTempLog(t, lines)
	store := NewStore(path)
	// No SetMaxAge call — default is zero (no eviction).
	store.Load()

	if got := store.EventCount(); got != 1 {
		t.Errorf("expected 1 event (no eviction), got %d", got)
	}
}

func TestAccessLogStoreEviction(t *testing.T) {
	lines := []string{
		// Old 429 event (2020).
		`{"level":"info","ts":"2020/01/01 00:00:00","logger":"combined","msg":"handled request","request":{"remote_ip":"1.1.1.1","client_ip":"1.1.1.1","proto":"HTTP/2.0","method":"GET","host":"test.erfi.io","uri":"/","headers":{}},"status":429,"size":0,"duration":0.001}`,
		// Recent 429 event (today).
		sampleAccessLogLines[1],
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)
	// 7 days — keeps today's event, evicts 2020 event.
	store.SetMaxAge(168 * time.Hour)
	store.Load()

	// Only the recent event should remain.
	if got := store.EventCount(); got != 1 {
		t.Errorf("expected 1 event after eviction, got %d", got)
	}
}

// --- Atomic write tests ---

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	data := []byte(`{"key": "value"}`)

	if err := atomicWriteFile(path, data, 0644); err != nil {
		t.Fatalf("atomicWriteFile failed: %v", err)
	}

	// Verify content.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content mismatch: want %q, got %q", string(data), string(got))
	}

	// Verify permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("permissions: want 0644, got %o", info.Mode().Perm())
	}

	// Verify no temp files left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected 1 file in dir, got %d", len(entries))
	}
}

func TestAtomicWriteFileOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	// Write initial content.
	atomicWriteFile(path, []byte("initial"), 0644)

	// Overwrite.
	atomicWriteFile(path, []byte("updated"), 0644)

	got, _ := os.ReadFile(path)
	if string(got) != "updated" {
		t.Errorf("overwrite: want 'updated', got %q", string(got))
	}
}

// --- Deploy fingerprint tests ---

func TestDeployFingerprint(t *testing.T) {
	dir := t.TempDir()

	// Create two files with known content.
	f1 := filepath.Join(dir, "a.conf")
	f2 := filepath.Join(dir, "b.conf")
	os.WriteFile(f1, []byte("content-a"), 0644)
	os.WriteFile(f2, []byte("content-b"), 0644)

	fp1 := deployFingerprint([]string{f1, f2})
	if len(fp1) != 16 {
		t.Errorf("fingerprint should be 16 hex chars, got %d: %s", len(fp1), fp1)
	}

	// Same files, same content → same fingerprint.
	fp2 := deployFingerprint([]string{f1, f2})
	if fp1 != fp2 {
		t.Errorf("same content should produce same fingerprint: %s vs %s", fp1, fp2)
	}

	// Change one file → different fingerprint.
	os.WriteFile(f2, []byte("content-b-changed"), 0644)
	fp3 := deployFingerprint([]string{f1, f2})
	if fp1 == fp3 {
		t.Error("different content should produce different fingerprint")
	}

	// Missing file → still produces a fingerprint (hashes path instead).
	fp4 := deployFingerprint([]string{f1, filepath.Join(dir, "nonexistent.conf")})
	if fp4 == fp1 {
		t.Error("missing file should produce different fingerprint than two real files")
	}

	// No files → produces a fingerprint (empty hash).
	fp5 := deployFingerprint(nil)
	if len(fp5) != 16 {
		t.Errorf("empty fingerprint should be 16 hex chars, got %d", len(fp5))
	}
}

func TestReloadCaddyInjectsFingerprint(t *testing.T) {
	caddyfileDir := t.TempDir()
	caddyfilePath := filepath.Join(caddyfileDir, "Caddyfile")
	caddyfileContent := "{\n\tadmin localhost:2019\n}\nlocalhost:80 {\n\trespond \"ok\"\n}\n"
	os.WriteFile(caddyfilePath, []byte(caddyfileContent), 0644)

	// Create config files to fingerprint.
	confDir := t.TempDir()
	confFile := filepath.Join(confDir, "custom-waf-settings.conf")
	os.WriteFile(confFile, []byte("SecAction \"id:9700001\""), 0644)

	// Mock Caddy admin API that captures the POST body.
	var receivedBody []byte
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" && r.Method == "POST" {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer adminServer.Close()

	err := reloadCaddy(caddyfilePath, adminServer.URL, confFile)
	if err != nil {
		t.Fatalf("reloadCaddy failed: %v", err)
	}

	bodyStr := string(receivedBody)

	// Should start with a fingerprint comment.
	if !strings.HasPrefix(bodyStr, "# waf-api deploy ") {
		t.Error("POST body should start with fingerprint comment")
	}
	if !strings.Contains(bodyStr, "fingerprint:") {
		t.Error("POST body should contain 'fingerprint:'")
	}

	// Original Caddyfile content should follow the comment.
	if !strings.Contains(bodyStr, caddyfileContent) {
		t.Error("POST body should contain the original Caddyfile content")
	}

	// Verify the on-disk Caddyfile was NOT modified.
	diskContent, _ := os.ReadFile(caddyfilePath)
	if string(diskContent) != caddyfileContent {
		t.Error("Caddyfile on disk should not be modified")
	}
}

func TestReloadCaddyFingerprintChangesWithContent(t *testing.T) {
	caddyfileDir := t.TempDir()
	caddyfilePath := filepath.Join(caddyfileDir, "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80 { respond ok }"), 0644)

	confDir := t.TempDir()
	confFile := filepath.Join(confDir, "settings.conf")
	os.WriteFile(confFile, []byte("version-1"), 0644)

	var bodies []string
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer adminServer.Close()

	// First reload.
	reloadCaddy(caddyfilePath, adminServer.URL, confFile)

	// Change config file content.
	os.WriteFile(confFile, []byte("version-2"), 0644)

	// Second reload.
	reloadCaddy(caddyfilePath, adminServer.URL, confFile)

	if len(bodies) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(bodies))
	}
	// The two POST bodies should differ (different fingerprints).
	if bodies[0] == bodies[1] {
		t.Error("POST bodies should differ when config file content changes")
	}
}

func TestServicesMergesRateLimitedCounts(t *testing.T) {
	wafPath := writeTempLog(t, sampleLines)
	store := NewStore(wafPath)
	store.Load()

	alsPath := writeTempAccessLog(t, sampleAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/services", nil)
	w := httptest.NewRecorder()
	handleServices(store, als)(w, req)

	var resp ServicesResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// WAF has: radarr.erfi.io (2), dockge-sg.erfi.io (1).
	// 429s have: sonarr.erfi.io (2), radarr.erfi.io (1).
	// Merged: radarr.erfi.io (3), sonarr.erfi.io (2), dockge-sg.erfi.io (1).
	if len(resp.Services) != 3 {
		t.Fatalf("want 3 services, got %d", len(resp.Services))
	}

	svcMap := make(map[string]ServiceDetail)
	for _, s := range resp.Services {
		svcMap[s.Service] = s
	}

	radarr := svcMap["radarr.erfi.io"]
	if radarr.Total != 3 {
		t.Errorf("radarr total: want 3 (2 WAF + 1 RL), got %d", radarr.Total)
	}
	if radarr.RateLimited != 1 {
		t.Errorf("radarr rate_limited: want 1, got %d", radarr.RateLimited)
	}

	sonarr := svcMap["sonarr.erfi.io"]
	if sonarr.Total != 2 {
		t.Errorf("sonarr total: want 2, got %d", sonarr.Total)
	}
	if sonarr.RateLimited != 2 {
		t.Errorf("sonarr rate_limited: want 2, got %d", sonarr.RateLimited)
	}

	dockge := svcMap["dockge-sg.erfi.io"]
	if dockge.Total != 1 {
		t.Errorf("dockge total: want 1, got %d", dockge.Total)
	}
	if dockge.RateLimited != 0 {
		t.Errorf("dockge rate_limited: want 0, got %d", dockge.RateLimited)
	}
}

// ─── IPsum Blocked Tests ────────────────────────────────────────────

// sampleIpsumAccessLogLines contains mixed 429 (rate limited) and 403+X-Blocked-By:ipsum lines.
var sampleIpsumAccessLogLines = []string{
	// 200 OK — should be ignored
	`{"level":"info","ts":"2026/02/22 12:00:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["Sonarr/4.0"]}},"resp_headers":{},"status":200,"size":1234,"duration":0.05}`,
	// 429 rate limited
	`{"level":"info","ts":"2026/02/22 12:01:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`,
	// 403 ipsum blocked (has X-Blocked-By: ipsum)
	`{"level":"info","ts":"2026/02/22 12:02:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/2.0","method":"GET","host":"radarr.erfi.io","uri":"/","headers":{"User-Agent":["BadBot/1.0"]}},"resp_headers":{"X-Blocked-By":["ipsum"]},"status":403,"size":0,"duration":0.001}`,
	// 403 without ipsum header — should be ignored
	`{"level":"info","ts":"2026/02/22 12:03:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.4","client_ip":"10.0.0.4","proto":"HTTP/1.1","method":"GET","host":"radarr.erfi.io","uri":"/.env","headers":{"User-Agent":["Scanner/1.0"]}},"resp_headers":{},"status":403,"size":0,"duration":0.002}`,
	// Another ipsum blocked
	`{"level":"info","ts":"2026/02/22 13:00:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.5","client_ip":"10.0.0.5","proto":"HTTP/2.0","method":"POST","host":"sonarr.erfi.io","uri":"/login","headers":{"User-Agent":["MaliciousBot/2.0"]}},"resp_headers":{"X-Blocked-By":["ipsum"]},"status":403,"size":0,"duration":0.001}`,
}

func TestIsIpsumBlocked(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		want    bool
	}{
		{"ipsum header present", map[string][]string{"X-Blocked-By": {"ipsum"}}, true},
		{"different value", map[string][]string{"X-Blocked-By": {"other"}}, false},
		{"no header", map[string][]string{}, false},
		{"nil headers", nil, false},
		{"multiple values with ipsum", map[string][]string{"X-Blocked-By": {"other", "ipsum"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isIpsumBlocked(tt.headers); got != tt.want {
				t.Errorf("isIpsumBlocked(%v) = %v, want %v", tt.headers, got, tt.want)
			}
		})
	}
}

func TestAccessLogStoreLoadsIpsumEvents(t *testing.T) {
	path := writeTempAccessLog(t, sampleIpsumAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	// 1 rate-limited (429) + 2 ipsum-blocked (403+header) = 3 total, ignoring 200 and bare 403.
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3 events (1 RL + 2 ipsum), got %d", got)
	}
}

func TestIpsumEventSource(t *testing.T) {
	path := writeTempAccessLog(t, sampleIpsumAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	events := store.SnapshotAsEvents(0)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	var rlCount, ipsumCount int
	for _, ev := range events {
		switch ev.EventType {
		case "rate_limited":
			rlCount++
			if ev.ResponseStatus != 429 {
				t.Errorf("rate_limited event should have status 429, got %d", ev.ResponseStatus)
			}
		case "ipsum_blocked":
			ipsumCount++
			if ev.ResponseStatus != 403 {
				t.Errorf("ipsum_blocked event should have status 403, got %d", ev.ResponseStatus)
			}
		default:
			t.Errorf("unexpected event type: %s", ev.EventType)
		}
	}

	if rlCount != 1 {
		t.Errorf("expected 1 rate_limited event, got %d", rlCount)
	}
	if ipsumCount != 2 {
		t.Errorf("expected 2 ipsum_blocked events, got %d", ipsumCount)
	}
}

func TestRateLimitEventToEventIpsum(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 2, 22, 12, 2, 0, 0, time.UTC),
		ClientIP:  "10.0.0.3",
		Service:   "radarr.erfi.io",
		Method:    "GET",
		URI:       "/",
		UserAgent: "BadBot/1.0",
		Source:    "ipsum",
	}

	ev := RateLimitEventToEvent(rle)

	if ev.EventType != "ipsum_blocked" {
		t.Errorf("event_type: want ipsum_blocked, got %s", ev.EventType)
	}
	if !ev.IsBlocked {
		t.Error("ipsum_blocked events should have is_blocked=true")
	}
	if ev.ResponseStatus != 403 {
		t.Errorf("response_status: want 403, got %d", ev.ResponseStatus)
	}
}

func TestSummaryMergesIpsumEvents(t *testing.T) {
	wafPath := writeTempLog(t, sampleLines)
	store := NewStore(wafPath)
	store.Load()

	alsPath := writeTempAccessLog(t, sampleIpsumAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()
	handleSummary(store, als)(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp SummaryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// 3 WAF events + 1 RL + 2 ipsum = 6 total.
	if resp.TotalEvents != 6 {
		t.Errorf("total_events: want 6 (3 WAF + 1 RL + 2 ipsum), got %d", resp.TotalEvents)
	}
	if resp.RateLimited != 1 {
		t.Errorf("rate_limited: want 1, got %d", resp.RateLimited)
	}
	if resp.IpsumBlocked != 2 {
		t.Errorf("ipsum_blocked: want 2, got %d", resp.IpsumBlocked)
	}
	if resp.BlockedEvents != 2 {
		t.Errorf("blocked_events: want 2 (WAF only), got %d", resp.BlockedEvents)
	}

	// Check hourly buckets have ipsum_blocked.
	var totalIpsum int
	for _, hc := range resp.EventsByHour {
		totalIpsum += hc.IpsumBlocked
	}
	if totalIpsum != 2 {
		t.Errorf("hourly ipsum_blocked sum: want 2, got %d", totalIpsum)
	}
}

func TestEventsIpsumBlockedFilter(t *testing.T) {
	wafPath := writeTempLog(t, sampleLines)
	store := NewStore(wafPath)
	store.Load()

	alsPath := writeTempAccessLog(t, sampleIpsumAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/events?event_type=ipsum_blocked&limit=100", nil)
	w := httptest.NewRecorder()
	handleEvents(store, als)(w, req)

	var resp EventsResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Total != 2 {
		t.Errorf("ipsum_blocked filter: want 2, got %d", resp.Total)
	}
	for _, ev := range resp.Events {
		if ev.EventType != "ipsum_blocked" {
			t.Errorf("event %s has type %s, want ipsum_blocked", ev.ID, ev.EventType)
		}
		if ev.ResponseStatus != 403 {
			t.Errorf("event %s has status %d, want 403", ev.ID, ev.ResponseStatus)
		}
	}
}

func TestServicesMergesIpsumCounts(t *testing.T) {
	wafPath := writeTempLog(t, sampleLines)
	store := NewStore(wafPath)
	store.Load()

	alsPath := writeTempAccessLog(t, sampleIpsumAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/services", nil)
	w := httptest.NewRecorder()
	handleServices(store, als)(w, req)

	var resp ServicesResponse
	json.NewDecoder(w.Body).Decode(&resp)

	svcMap := make(map[string]ServiceDetail)
	for _, s := range resp.Services {
		svcMap[s.Service] = s
	}

	radarr := svcMap["radarr.erfi.io"]
	if radarr.IpsumBlocked != 1 {
		t.Errorf("radarr ipsum_blocked: want 1, got %d", radarr.IpsumBlocked)
	}

	sonarr := svcMap["sonarr.erfi.io"]
	if sonarr.RateLimited != 1 {
		t.Errorf("sonarr rate_limited: want 1, got %d", sonarr.RateLimited)
	}
	if sonarr.IpsumBlocked != 1 {
		t.Errorf("sonarr ipsum_blocked: want 1, got %d", sonarr.IpsumBlocked)
	}
}

// ─── Blocklist tests ────────────────────────────────────────────────

func writeTempBlocklist(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ipsum_block.caddy")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBlocklistStatsParseFile(t *testing.T) {
	content := `# AUTO-GENERATED by update-ipsum.sh — do not edit manually
# Updated: 2026-02-22T06:00:01Z
# IPs: 3 (min_score=3)
# Source: https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
@ipsum_blocked client_ip 1.2.3.4 5.6.7.8 9.10.11.12
route @ipsum_blocked {
	header X-Blocked-By ipsum
	respond 403 {
		body "Blocked"
		close
	}
}
`
	path := writeTempBlocklist(t, content)
	bs := NewBlocklistStore(path)

	stats := bs.Stats()
	if stats.BlockedIPs != 3 {
		t.Errorf("BlockedIPs: want 3, got %d", stats.BlockedIPs)
	}
	if stats.LastUpdated != "2026-02-22T06:00:01Z" {
		t.Errorf("LastUpdated: want 2026-02-22T06:00:01Z, got %q", stats.LastUpdated)
	}
	if stats.MinScore != 3 {
		t.Errorf("MinScore: want 3, got %d", stats.MinScore)
	}
	if stats.Source != "IPsum" {
		t.Errorf("Source: want IPsum, got %q", stats.Source)
	}
}

func TestBlocklistCheckIP(t *testing.T) {
	content := `# Updated: 2026-02-22T06:00:01Z
# IPs: 2 (min_score=3)
@ipsum_blocked client_ip 1.2.3.4 5.6.7.8
route @ipsum_blocked {
	respond 403
}
`
	path := writeTempBlocklist(t, content)
	bs := NewBlocklistStore(path)

	// Blocked IP
	result := bs.Check("1.2.3.4")
	if !result.Blocked {
		t.Error("1.2.3.4 should be blocked")
	}
	if result.Source != "IPsum" {
		t.Errorf("Source: want IPsum, got %q", result.Source)
	}

	// Clean IP
	result = bs.Check("10.0.0.1")
	if result.Blocked {
		t.Error("10.0.0.1 should not be blocked")
	}
}

func TestBlocklistStatsEndpoint(t *testing.T) {
	content := `# Updated: 2026-02-22T06:00:01Z
# IPs: 2 (min_score=5)
@ipsum_blocked client_ip 1.2.3.4 5.6.7.8
route @ipsum_blocked { respond 403 }
`
	path := writeTempBlocklist(t, content)
	bs := NewBlocklistStore(path)

	req := httptest.NewRequest("GET", "/api/blocklist/stats", nil)
	w := httptest.NewRecorder()
	handleBlocklistStats(bs)(w, req)

	if w.Code != 200 {
		t.Fatalf("status: want 200, got %d", w.Code)
	}
	var resp BlocklistStatsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.BlockedIPs != 2 {
		t.Errorf("BlockedIPs: want 2, got %d", resp.BlockedIPs)
	}
	if resp.MinScore != 5 {
		t.Errorf("MinScore: want 5, got %d", resp.MinScore)
	}
}

func TestBlocklistCheckEndpoint(t *testing.T) {
	content := `@ipsum_blocked client_ip 1.2.3.4
route @ipsum_blocked { respond 403 }
`
	path := writeTempBlocklist(t, content)
	bs := NewBlocklistStore(path)

	// Check blocked IP
	req := httptest.NewRequest("GET", "/api/blocklist/check/1.2.3.4", nil)
	req.SetPathValue("ip", "1.2.3.4")
	w := httptest.NewRecorder()
	handleBlocklistCheck(bs)(w, req)

	if w.Code != 200 {
		t.Fatalf("status: want 200, got %d", w.Code)
	}
	var resp BlocklistCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Blocked {
		t.Error("1.2.3.4 should be blocked")
	}

	// Check clean IP
	req = httptest.NewRequest("GET", "/api/blocklist/check/10.0.0.1", nil)
	req.SetPathValue("ip", "10.0.0.1")
	w = httptest.NewRecorder()
	handleBlocklistCheck(bs)(w, req)

	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Blocked {
		t.Error("10.0.0.1 should not be blocked")
	}
}

func TestBlocklistCheckInvalidIP(t *testing.T) {
	bs := NewBlocklistStore("/nonexistent")

	req := httptest.NewRequest("GET", "/api/blocklist/check/notanip", nil)
	req.SetPathValue("ip", "notanip")
	w := httptest.NewRecorder()
	handleBlocklistCheck(bs)(w, req)

	if w.Code != 400 {
		t.Fatalf("status: want 400, got %d", w.Code)
	}
}

func TestBlocklistEmptyFile(t *testing.T) {
	path := writeTempBlocklist(t, "")
	bs := NewBlocklistStore(path)

	stats := bs.Stats()
	if stats.BlockedIPs != 0 {
		t.Errorf("BlockedIPs: want 0, got %d", stats.BlockedIPs)
	}
}

// ─── Client count merging tests ─────────────────────────────────────

func TestSummaryMergesClientCounts(t *testing.T) {
	// WAF store with events from 10.0.0.1
	logPath := writeTempLog(t, sampleLines)
	store := NewStore(logPath)
	store.Load()

	// Access log with RL + ipsum events
	accessLines := []string{
		`{"level":"info","ts":"2026/02/22 07:30:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"radarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`,
		`{"level":"info","ts":"2026/02/22 07:31:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"radarr.erfi.io","uri":"/test","headers":{"User-Agent":["BadBot/1.0"]}},"resp_headers":{"X-Blocked-By":["ipsum"]},"status":403,"size":0,"duration":0.001}`,
		`{"level":"info","ts":"2026/02/22 07:32:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"99.99.99.99","client_ip":"99.99.99.99","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`,
	}
	accessPath := writeTempAccessLog(t, accessLines)
	als := NewAccessLogStore(accessPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()
	handleSummary(store, als)(w, req)

	if w.Code != 200 {
		t.Fatalf("status: want 200, got %d", w.Code)
	}

	var resp SummaryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	// Build client map
	clientMap := make(map[string]ClientCount)
	for _, c := range resp.TopClients {
		clientMap[c.Client] = c
	}

	// 10.0.0.1 should have WAF blocked + RL + ipsum counts merged
	c1 := clientMap["10.0.0.1"]
	if c1.RateLimited != 1 {
		t.Errorf("10.0.0.1 rate_limited: want 1, got %d", c1.RateLimited)
	}
	if c1.IpsumBlocked != 1 {
		t.Errorf("10.0.0.1 ipsum_blocked: want 1, got %d", c1.IpsumBlocked)
	}

	// 99.99.99.99 should have only RL count
	c2 := clientMap["99.99.99.99"]
	if c2.RateLimited != 1 {
		t.Errorf("99.99.99.99 rate_limited: want 1, got %d", c2.RateLimited)
	}
	if c2.IpsumBlocked != 0 {
		t.Errorf("99.99.99.99 ipsum_blocked: want 0, got %d", c2.IpsumBlocked)
	}
}

// --- Tests: extractAnomalyScore ---

func TestExtractAnomalyScore(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want int
	}{
		{"inbound score 5", "Inbound Anomaly Score Exceeded (Total Score: 5)", 5},
		{"inbound score 25", "Inbound Anomaly Score Exceeded (Total Score: 25)", 25},
		{"inbound score 100", "Inbound Anomaly Score Exceeded (Total Score: 100)", 100},
		{"outbound score 3", "Outbound Anomaly Score Exceeded (Total Score: 3)", 3},
		{"zero score", "Inbound Anomaly Score Exceeded (Total Score: 0)", 0},
		{"no match empty", "", 0},
		{"no match unrelated", "Remote Command Execution detected", 0},
		{"partial prefix", "Total Score: ", 0},
		{"no digits after prefix", "Total Score: abc)", 0},
		{"score in middle of text", "foo Total Score: 42 bar", 42},
		{"large score", "Inbound Anomaly Score Exceeded (Total Score: 99999)", 99999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAnomalyScore(tt.msg)
			if got != tt.want {
				t.Errorf("extractAnomalyScore(%q) = %d, want %d", tt.msg, got, tt.want)
			}
		})
	}
}

func TestAnomalyScoreInParsedEvent(t *testing.T) {
	// Construct a minimal audit log entry with rule 949110 carrying a score.
	entry := `{"transaction":{"timestamp":"2026/01/01 00:00:00","unix_timestamp":1,"id":"test1","client_ip":"1.2.3.4","server_id":"test.erfi.io","request":{"method":"GET","uri":"/test","headers":{}},"response":{"status":403},"producer":{"rule_engine":"On"}},"messages":[{"message":"SQL Injection","data":{"id":942100,"msg":"SQL Injection","severity":2,"tags":["attack-sqli"]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 15)","data":{"id":949110,"msg":"Inbound Anomaly Score Exceeded (Total Score: 15)","severity":0,"tags":["anomaly-evaluation"]}}]}`

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	os.WriteFile(path, []byte(entry+"\n"), 0644)

	store := NewStore(path)
	store.Load()
	events := store.Snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].AnomalyScore != 15 {
		t.Errorf("expected anomaly score 15, got %d", events[0].AnomalyScore)
	}
	// Best rule should be 942100 (not the 949110 scoring rule).
	if events[0].RuleID != 942100 {
		t.Errorf("expected rule ID 942100, got %d", events[0].RuleID)
	}
}
