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
			exc:     RuleExclusion{Name: "test", Type: "runtime_remove_by_id", RuleID: "920420", Condition: "/api/"},
			wantErr: false,
		},
		{
			name:    "valid runtime_remove_target_by_id",
			exc:     RuleExclusion{Name: "test", Type: "runtime_remove_target_by_id", RuleID: "920420", Variable: "ARGS:x", Condition: "/api/"},
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
			name:    "runtime_remove_by_id missing condition",
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
		Name:      "Runtime remove",
		Type:      "runtime_remove_by_id",
		RuleID:    "941100",
		Condition: "/api/webhook",
		Enabled:   true,
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
		{Name: "Runtime remove", Type: "runtime_remove_by_id", RuleID: "942100", Condition: "/api/hook", Enabled: true},
		{Name: "Runtime remove target", Type: "runtime_remove_target_by_id", RuleID: "943100", Variable: "ARGS:data", Condition: "/webhook", Enabled: true},
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
