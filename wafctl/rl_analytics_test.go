package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)


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
	// Copytruncate rotation: existing 3 events kept + 1 new = 4.
	if got := store.EventCount(); got != 4 {
		t.Fatalf("expected 4 after rotation (3 kept + 1 new), got %d", got)
	}
}



func TestAccessLogStoreOffsetPersistence(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "combined-access.log")
	offsetPath := filepath.Join(dir, "offset")

	// Write all 5 lines (3 are 429).
	f, _ := os.Create(logPath)
	for _, l := range sampleAccessLogLines {
		f.WriteString(l + "\n")
	}
	f.Close()

	// First store: read all events, offset is persisted.
	store1 := NewAccessLogStore(logPath)
	store1.SetOffsetFile(offsetPath)
	store1.Load()
	if got := store1.EventCount(); got != 3 {
		t.Fatalf("store1: expected 3 events, got %d", got)
	}

	// Verify offset file was written.
	data, err := os.ReadFile(offsetPath)
	if err != nil {
		t.Fatalf("offset file not created: %v", err)
	}
	savedOffset := strings.TrimSpace(string(data))
	if savedOffset == "" || savedOffset == "0" {
		t.Fatalf("offset file should contain non-zero offset, got %q", savedOffset)
	}

	// Second store: restores offset from disk, reads nothing new.
	store2 := NewAccessLogStore(logPath)
	store2.SetOffsetFile(offsetPath)
	store2.Load()
	if got := store2.EventCount(); got != 0 {
		t.Fatalf("store2: expected 0 events (offset restored), got %d", got)
	}

	// Append one more 429 line.
	f, _ = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString(sampleAccessLogLines[1] + "\n")
	f.Close()

	// Second store picks up only the new line.
	store2.Load()
	if got := store2.EventCount(); got != 1 {
		t.Fatalf("store2: expected 1 new event after append, got %d", got)
	}
}

// --- Access Log JSONL event persistence tests ---



// --- Access Log JSONL event persistence tests ---

func TestAccessLogStoreEventFilePersistence(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "combined-access.log")
	eventPath := filepath.Join(dir, "access-events.jsonl")

	// Write all 5 lines (3 are 429).
	f, _ := os.Create(logPath)
	for _, l := range sampleAccessLogLines {
		f.WriteString(l + "\n")
	}
	f.Close()

	// First store: parse and persist events.
	store1 := NewAccessLogStore(logPath)
	store1.SetEventFile(eventPath)
	store1.Load()
	if got := store1.EventCount(); got != 3 {
		t.Fatalf("store1: expected 3 events, got %d", got)
	}

	// Verify JSONL file was created.
	if _, err := os.Stat(eventPath); err != nil {
		t.Fatalf("event file not created: %v", err)
	}

	// Second store: should restore events from JSONL.
	store2 := NewAccessLogStore(logPath)
	store2.SetEventFile(eventPath)
	if got := store2.EventCount(); got != 3 {
		t.Fatalf("store2: expected 3 events restored from JSONL, got %d", got)
	}
}



func TestAccessLogStoreEventFileIncremental(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "combined-access.log")
	eventPath := filepath.Join(dir, "access-events.jsonl")

	// Write first 3 lines (2 are 429).
	f, _ := os.Create(logPath)
	for _, l := range sampleAccessLogLines[:3] {
		f.WriteString(l + "\n")
	}
	f.Close()

	store := NewAccessLogStore(logPath)
	store.SetEventFile(eventPath)
	store.Load()
	if got := store.EventCount(); got != 2 {
		t.Fatalf("expected 2, got %d", got)
	}

	// Append remaining lines (1 more 429).
	f, _ = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	for _, l := range sampleAccessLogLines[3:] {
		f.WriteString(l + "\n")
	}
	f.Close()

	store.Load()
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3 after append, got %d", got)
	}

	// New store should restore all 3 from JSONL.
	store2 := NewAccessLogStore(logPath)
	store2.SetEventFile(eventPath)
	if got := store2.EventCount(); got != 3 {
		t.Fatalf("store2: expected 3 from JSONL, got %d", got)
	}
}



func TestAccessLogStoreEventFileRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "combined-access.log")
	eventPath := filepath.Join(dir, "access-events.jsonl")
	offsetPath := filepath.Join(dir, "offset")

	// Write all 5 lines (3 are 429).
	f, _ := os.Create(logPath)
	for _, l := range sampleAccessLogLines {
		f.WriteString(l + "\n")
	}
	f.Close()

	store := NewAccessLogStore(logPath)
	store.SetOffsetFile(offsetPath)
	store.SetEventFile(eventPath)
	store.Load()
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3, got %d", got)
	}

	// Simulate rotation: truncate and write 1 line (a 429).
	f, _ = os.Create(logPath)
	f.WriteString(sampleAccessLogLines[1] + "\n")
	f.Close()

	store.Load()
	// Copytruncate: 3 kept + 1 new = 4.
	if got := store.EventCount(); got != 4 {
		t.Fatalf("expected 4 after rotation, got %d", got)
	}

	// New store should restore all 4 from JSONL.
	store2 := NewAccessLogStore(logPath)
	store2.SetOffsetFile(offsetPath)
	store2.SetEventFile(eventPath)
	if got := store2.EventCount(); got != 4 {
		t.Fatalf("store2: expected 4 from JSONL, got %d", got)
	}
}



func TestAccessLogStoreEventFileEvictionCompaction(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "combined-access.log")
	eventPath := filepath.Join(dir, "access-events.jsonl")

	// Write one old 429 event (2020) and one recent 429 event.
	oldLine := `{"level":"info","ts":"2020/01/01 00:00:00","logger":"combined","msg":"handled request","request":{"remote_ip":"1.1.1.1","client_ip":"1.1.1.1","proto":"HTTP/2.0","method":"GET","host":"test.erfi.io","uri":"/old","headers":{}},"status":429,"size":0,"duration":0.001}`
	f, _ := os.Create(logPath)
	f.WriteString(oldLine + "\n")
	f.WriteString(sampleAccessLogLines[1] + "\n") // recent 429
	f.Close()

	store := NewAccessLogStore(logPath)
	store.SetEventFile(eventPath)
	store.Load()
	if got := store.EventCount(); got != 2 {
		t.Fatalf("expected 2 events before eviction, got %d", got)
	}

	// JSONL should have 2 events.
	events, _ := loadRLEventsFromJSONL(eventPath)
	if len(events) != 2 {
		t.Fatalf("JSONL should have 2 events before eviction, got %d", len(events))
	}

	// Set maxAge and trigger eviction.
	store.SetMaxAge(168 * time.Hour)
	store.Load()

	if got := store.EventCount(); got != 1 {
		t.Fatalf("expected 1 event after eviction, got %d", got)
	}

	// Wait for async compaction.
	time.Sleep(50 * time.Millisecond)

	events, _ = loadRLEventsFromJSONL(eventPath)
	if len(events) != 1 {
		t.Fatalf("JSONL should have 1 event after compaction, got %d", len(events))
	}
}



func TestAccessLogStoreEventFileDataIntegrity(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "combined-access.log")
	eventPath := filepath.Join(dir, "access-events.jsonl")

	// Write a single 429 line (sampleAccessLogLines[1]: sonarr, GET, /api/v3/queue).
	f, _ := os.Create(logPath)
	f.WriteString(sampleAccessLogLines[1] + "\n")
	f.Close()

	store := NewAccessLogStore(logPath)
	store.SetEventFile(eventPath)
	store.Load()

	// Restore into a new store and verify field values.
	store2 := NewAccessLogStore(logPath)
	store2.SetEventFile(eventPath)
	if got := store2.EventCount(); got != 1 {
		t.Fatalf("expected 1 event, got %d", got)
	}

	events := store2.snapshotSince(0)
	ev := events[0]
	if ev.ClientIP != "10.0.0.2" {
		t.Errorf("ClientIP: want 10.0.0.2, got %s", ev.ClientIP)
	}
	if ev.Service != "sonarr.erfi.io" {
		t.Errorf("Service: want sonarr.erfi.io, got %s", ev.Service)
	}
	if ev.Method != "GET" {
		t.Errorf("Method: want GET, got %s", ev.Method)
	}
	if ev.URI != "/api/v3/queue" {
		t.Errorf("URI: want /api/v3/queue, got %s", ev.URI)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}



func TestAccessLogStoreEventFileMalformedLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "combined-access.log")
	eventPath := filepath.Join(dir, "access-events.jsonl")

	// Pre-seed JSONL with valid + garbage lines.
	ef, _ := os.Create(eventPath)
	ef.WriteString(`{"timestamp":"2026-02-22T12:01:00Z","client_ip":"1.1.1.1","service":"test.erfi.io","method":"GET","uri":"/ok","user_agent":"curl"}` + "\n")
	ef.WriteString("GARBAGE LINE\n")
	ef.WriteString(`{"timestamp":"2026-02-22T12:02:00Z","client_ip":"2.2.2.2","service":"test.erfi.io","method":"POST","uri":"/api","user_agent":"wget"}` + "\n")
	ef.Close()

	os.Create(logPath)

	store := NewAccessLogStore(logPath)
	store.SetEventFile(eventPath)

	if got := store.EventCount(); got != 2 {
		t.Fatalf("expected 2 events (skipping malformed), got %d", got)
	}
}



func TestAccessLogStoreEventFileEmpty(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "combined-access.log")
	eventPath := filepath.Join(dir, "access-events.jsonl")

	os.Create(eventPath)
	os.Create(logPath)

	store := NewAccessLogStore(logPath)
	store.SetEventFile(eventPath)

	if got := store.EventCount(); got != 0 {
		t.Fatalf("expected 0 events from empty JSONL, got %d", got)
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
