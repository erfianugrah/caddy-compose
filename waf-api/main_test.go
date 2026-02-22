package main

import (
	"bytes"
	"encoding/json"
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

func TestSummaryEndpoint(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()
	handleSummary(store)(w, req)

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
}

func TestEventsEndpointWithFilters(t *testing.T) {
	path := writeTempLog(t, sampleLines)
	store := NewStore(path)
	store.Load()

	req := httptest.NewRequest("GET", "/api/events?service=radarr.erfi.io&blocked=true&limit=10", nil)
	w := httptest.NewRecorder()
	handleEvents(store)(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp EventsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 1 {
		t.Errorf("want 1 blocked event for radarr, got %d", resp.Total)
	}
}

func TestCORSHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", handleHealth)
	handler := corsMiddleware(mux)

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

func TestCORSPreflight(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", handleHealth)
	handler := corsMiddleware(mux)

	req := httptest.NewRequest("OPTIONS", "/api/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("preflight: want 204, got %d", w.Code)
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

	// hours=1 should filter out old events.
	req := httptest.NewRequest("GET", "/api/summary?hours=1", nil)
	w := httptest.NewRecorder()
	handleSummary(store)(w, req)

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
	handleSummary(store)(w, req)

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

	if cfg.ParanoiaLevel != 1 {
		t.Errorf("default paranoia: want 1, got %d", cfg.ParanoiaLevel)
	}
	if cfg.InboundThreshold != 5 {
		t.Errorf("default inbound: want 5, got %d", cfg.InboundThreshold)
	}
	if cfg.OutboundThreshold != 4 {
		t.Errorf("default outbound: want 4, got %d", cfg.OutboundThreshold)
	}
	if cfg.RuleEngine != "On" {
		t.Errorf("default engine: want On, got %s", cfg.RuleEngine)
	}
}

func TestConfigStoreUpdate(t *testing.T) {
	cs := newTestConfigStore(t)

	cfg := WAFConfig{
		ParanoiaLevel:     2,
		InboundThreshold:  10,
		OutboundThreshold: 8,
		RuleEngine:        "DetectionOnly",
		Services: map[string]ServiceConfig{
			"test.erfi.io": {Profile: "strict"},
		},
	}

	updated, err := cs.Update(cfg)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.ParanoiaLevel != 2 {
		t.Errorf("want paranoia 2, got %d", updated.ParanoiaLevel)
	}
}

func TestConfigStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cs1 := NewConfigStore(path)
	cs1.Update(WAFConfig{
		ParanoiaLevel:     3,
		InboundThreshold:  7,
		OutboundThreshold: 6,
		RuleEngine:        "On",
		Services:          map[string]ServiceConfig{},
	})

	cs2 := NewConfigStore(path)
	cfg := cs2.Get()
	if cfg.ParanoiaLevel != 3 {
		t.Errorf("persistence: want paranoia 3, got %d", cfg.ParanoiaLevel)
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
				ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, RuleEngine: "On",
				Services: map[string]ServiceConfig{},
			},
			wantErr: false,
		},
		{
			name: "paranoia too low",
			cfg: WAFConfig{
				ParanoiaLevel: 0, InboundThreshold: 5, OutboundThreshold: 4, RuleEngine: "On",
				Services: map[string]ServiceConfig{},
			},
			wantErr: true,
		},
		{
			name: "paranoia too high",
			cfg: WAFConfig{
				ParanoiaLevel: 5, InboundThreshold: 5, OutboundThreshold: 4, RuleEngine: "On",
				Services: map[string]ServiceConfig{},
			},
			wantErr: true,
		},
		{
			name: "invalid engine",
			cfg: WAFConfig{
				ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, RuleEngine: "Maybe",
				Services: map[string]ServiceConfig{},
			},
			wantErr: true,
		},
		{
			name: "invalid profile",
			cfg: WAFConfig{
				ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, RuleEngine: "On",
				Services: map[string]ServiceConfig{"test": {Profile: "unknown"}},
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
	if cfg.ParanoiaLevel != 1 {
		t.Errorf("default paranoia: want 1, got %d", cfg.ParanoiaLevel)
	}

	// PUT update.
	body := `{"paranoia_level":2,"inbound_threshold":10,"outbound_threshold":8,"rule_engine":"On","services":{}}`
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
	if cfg.ParanoiaLevel != 2 {
		t.Errorf("updated paranoia: want 2, got %d", cfg.ParanoiaLevel)
	}
}

func TestConfigEndpointInvalid(t *testing.T) {
	cs := newTestConfigStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(cs))

	body := `{"paranoia_level":0,"inbound_threshold":5,"outbound_threshold":4,"rule_engine":"On","services":{}}`
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
		ParanoiaLevel:     2,
		InboundThreshold:  10,
		OutboundThreshold: 8,
		RuleEngine:        "On",
		Services:          map[string]ServiceConfig{},
	}

	exclusions := []RuleExclusion{
		{Name: "Remove 920420", Type: "remove_by_id", RuleID: "920420", Enabled: true},
		{Name: "Remove sqli tag", Type: "remove_by_tag", RuleTag: "attack-sqli", Enabled: true},
		{Name: "Update target", Type: "update_target_by_id", RuleID: "941100", Variable: "ARGS:body", Enabled: true},
		{Name: "Runtime remove", Type: "runtime_remove_by_id", RuleID: "942100", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/hook"}}, Enabled: true},
		{Name: "Runtime remove target", Type: "runtime_remove_target_by_id", RuleID: "943100", Variable: "ARGS:data", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/webhook"}}, Enabled: true},
	}

	result := GenerateConfigs(cfg, exclusions)

	// Pre-CRS checks.
	if !strings.Contains(result.PreCRS, "blocking_paranoia_level=2") {
		t.Error("pre-crs should contain paranoia level 2")
	}
	if !strings.Contains(result.PreCRS, "inbound_anomaly_score_threshold=10") {
		t.Error("pre-crs should contain inbound threshold 10")
	}
	if !strings.Contains(result.PreCRS, "outbound_anomaly_score_threshold=8") {
		t.Error("pre-crs should contain outbound threshold 8")
	}
	if !strings.Contains(result.PreCRS, "SecRuleEngine On") {
		t.Error("pre-crs should contain SecRuleEngine On")
	}
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

	if !strings.Contains(result.PreCRS, "blocking_paranoia_level=1") {
		t.Error("pre-crs should contain default paranoia level")
	}
	// Post-CRS should just have the header.
	if strings.Contains(result.PostCRS, "SecRule") {
		t.Error("post-crs should have no rules with no exclusions")
	}
}

// --- Generate config endpoint test ---

func TestGenerateConfigEndpoint(t *testing.T) {
	cs := newTestConfigStore(t)
	es := newTestExclusionStore(t)

	cs.Update(WAFConfig{
		ParanoiaLevel:     2,
		InboundThreshold:  10,
		OutboundThreshold: 8,
		RuleEngine:        "On",
		Services:          map[string]ServiceConfig{},
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

	var resp GenerateResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp.PreCRS, "blocking_paranoia_level=2") {
		t.Error("should use config paranoia level")
	}
	if !strings.Contains(resp.PostCRS, "SecRuleRemoveById 920420") {
		t.Error("should contain exclusion")
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

	if err := writeConfFiles(dir, pre, post); err != nil {
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
