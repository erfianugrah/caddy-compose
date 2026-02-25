package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	// Copytruncate rotation: existing 3 events kept + 1 new = 4.
	if got := store.EventCount(); got != 4 {
		t.Fatalf("expected 4 after rotation (3 kept + 1 new), got %d", got)
	}
}

func TestStoreOffsetPersistence(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "offset")

	// Write 3 lines.
	f, _ := os.Create(logPath)
	for _, l := range sampleLines {
		f.WriteString(l + "\n")
	}
	f.Close()

	// First store: read all events, offset is persisted.
	store1 := NewStore(logPath)
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
	store2 := NewStore(logPath)
	store2.SetOffsetFile(offsetPath)
	store2.Load()
	if got := store2.EventCount(); got != 0 {
		t.Fatalf("store2: expected 0 events (offset restored), got %d", got)
	}

	// Append one more line.
	f, _ = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString(sampleLines[0] + "\n")
	f.Close()

	// Second store picks up only the new line.
	store2.Load()
	if got := store2.EventCount(); got != 1 {
		t.Fatalf("store2: expected 1 new event after append, got %d", got)
	}
}

func TestStoreOffsetPersistenceRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "offset")

	// Write 3 lines.
	f, _ := os.Create(logPath)
	for _, l := range sampleLines {
		f.WriteString(l + "\n")
	}
	f.Close()

	store := NewStore(logPath)
	store.SetOffsetFile(offsetPath)
	store.Load()
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3, got %d", got)
	}

	// Simulate rotation: truncate and write 1 line.
	f, _ = os.Create(logPath)
	f.WriteString(sampleLines[0] + "\n")
	f.Close()

	store.Load()
	// Copytruncate rotation: existing 3 events kept + 1 new = 4.
	if got := store.EventCount(); got != 4 {
		t.Fatalf("expected 4 after rotation (3 kept + 1 new), got %d", got)
	}

	// Offset file should be updated (non-zero, but smaller than before).
	data, err := os.ReadFile(offsetPath)
	if err != nil {
		t.Fatalf("offset file missing after rotation: %v", err)
	}
	savedOffset := strings.TrimSpace(string(data))
	if savedOffset == "" {
		t.Fatalf("offset file should not be empty after rotation")
	}
}

// --- JSONL event persistence tests ---

// --- JSONL event persistence tests ---

func TestStoreEventFilePersistence(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	eventPath := filepath.Join(dir, "events.jsonl")

	// Write 3 lines.
	f, _ := os.Create(logPath)
	for _, l := range sampleLines {
		f.WriteString(l + "\n")
	}
	f.Close()

	// First store: parse and persist events.
	store1 := NewStore(logPath)
	store1.SetEventFile(eventPath)
	store1.Load()
	if got := store1.EventCount(); got != 3 {
		t.Fatalf("store1: expected 3 events, got %d", got)
	}

	// Verify JSONL file was created.
	if _, err := os.Stat(eventPath); err != nil {
		t.Fatalf("event file not created: %v", err)
	}

	// Second store: should restore events from JSONL (not from audit log).
	store2 := NewStore(logPath)
	store2.SetEventFile(eventPath)
	// Before Load(), events should already be restored from JSONL.
	if got := store2.EventCount(); got != 3 {
		t.Fatalf("store2: expected 3 events restored from JSONL, got %d", got)
	}
}

func TestStoreEventFileStripsLargeFields(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	eventPath := filepath.Join(dir, "events.jsonl")

	// Write a log line that would produce an event with request headers.
	f, _ := os.Create(logPath)
	f.WriteString(sampleLines[0] + "\n")
	f.Close()

	store := NewStore(logPath)
	store.SetEventFile(eventPath)
	store.Load()

	// Read the JSONL file and verify large fields are stripped.
	data, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatalf("read event file: %v", err)
	}

	// The JSONL should NOT contain request_headers (they're stripped).
	if strings.Contains(string(data), "request_headers") {
		t.Error("JSONL should not contain request_headers (stripped)")
	}
	if strings.Contains(string(data), "request_body") {
		t.Error("JSONL should not contain request_body (stripped)")
	}
	if strings.Contains(string(data), "request_args") {
		t.Error("JSONL should not contain request_args (stripped)")
	}
}

func TestStoreEventFileIncremental(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	eventPath := filepath.Join(dir, "events.jsonl")

	// Write first 2 lines.
	f, _ := os.Create(logPath)
	for _, l := range sampleLines[:2] {
		f.WriteString(l + "\n")
	}
	f.Close()

	store := NewStore(logPath)
	store.SetEventFile(eventPath)
	store.Load()
	if got := store.EventCount(); got != 2 {
		t.Fatalf("expected 2, got %d", got)
	}

	// Append third line.
	f, _ = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString(sampleLines[2] + "\n")
	f.Close()

	store.Load()
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3 after append, got %d", got)
	}

	// New store should restore all 3 from JSONL.
	store2 := NewStore(logPath)
	store2.SetEventFile(eventPath)
	if got := store2.EventCount(); got != 3 {
		t.Fatalf("store2: expected 3 from JSONL, got %d", got)
	}
}

func TestStoreEventFileRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	eventPath := filepath.Join(dir, "events.jsonl")
	offsetPath := filepath.Join(dir, "offset")

	// Write 3 lines.
	f, _ := os.Create(logPath)
	for _, l := range sampleLines {
		f.WriteString(l + "\n")
	}
	f.Close()

	store := NewStore(logPath)
	store.SetOffsetFile(offsetPath)
	store.SetEventFile(eventPath)
	store.Load()
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3, got %d", got)
	}

	// Simulate rotation: truncate and write 1 line.
	f, _ = os.Create(logPath)
	f.WriteString(sampleLines[0] + "\n")
	f.Close()

	store.Load()
	// Copytruncate: 3 kept + 1 new = 4.
	if got := store.EventCount(); got != 4 {
		t.Fatalf("expected 4 after rotation, got %d", got)
	}

	// New store should restore all 4 from JSONL.
	store2 := NewStore(logPath)
	store2.SetOffsetFile(offsetPath)
	store2.SetEventFile(eventPath)
	if got := store2.EventCount(); got != 4 {
		t.Fatalf("store2: expected 4 from JSONL, got %d", got)
	}
}

func TestStoreEventFileEvictionCompaction(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	eventPath := filepath.Join(dir, "events.jsonl")

	// Write one old event (2020) and one recent event.
	oldLine := `{"transaction":{"timestamp":"2020/01/01 00:00:00","unix_timestamp":1577836800000000000,"id":"OLD1","client_ip":"1.1.1.1","client_port":0,"host_ip":"","host_port":0,"server_id":"test.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/old","http_version":"","headers":{"User-Agent":["old"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":200,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":[]},"highest_severity":"","is_interrupted":false}}`
	f, _ := os.Create(logPath)
	f.WriteString(oldLine + "\n")
	f.WriteString(sampleLines[0] + "\n")
	f.Close()

	store := NewStore(logPath)
	store.SetEventFile(eventPath)
	store.Load()
	if got := store.EventCount(); got != 2 {
		t.Fatalf("expected 2 events before eviction, got %d", got)
	}

	// JSONL should have 2 events.
	events, _ := loadEventsFromJSONL(eventPath)
	if len(events) != 2 {
		t.Fatalf("JSONL should have 2 events before eviction, got %d", len(events))
	}

	// Now set maxAge to 168h and trigger eviction via a second Load.
	store.SetMaxAge(168 * time.Hour)
	store.Load() // triggers evict() which compacts

	// In-memory: old event evicted, only recent remains.
	if got := store.EventCount(); got != 1 {
		t.Fatalf("expected 1 event after eviction, got %d", got)
	}

	// Wait briefly for async compaction goroutine.
	time.Sleep(50 * time.Millisecond)

	// JSONL should also be compacted to 1 event.
	events, _ = loadEventsFromJSONL(eventPath)
	if len(events) != 1 {
		t.Fatalf("JSONL should have 1 event after compaction, got %d", len(events))
	}
	if events[0].ID != "AAA111" {
		t.Errorf("expected recent event AAA111 to survive, got %s", events[0].ID)
	}
}

func TestStoreEventFileDataIntegrity(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	eventPath := filepath.Join(dir, "events.jsonl")

	f, _ := os.Create(logPath)
	f.WriteString(sampleLines[1] + "\n") // BBB222: 10.0.0.1, radarr, /.env, blocked
	f.Close()

	store := NewStore(logPath)
	store.SetEventFile(eventPath)
	store.Load()

	// Restore into a new store and verify field values, not just count.
	store2 := NewStore(logPath)
	store2.SetEventFile(eventPath)
	if got := store2.EventCount(); got != 1 {
		t.Fatalf("expected 1 event, got %d", got)
	}

	events := store2.Snapshot()
	ev := events[0]
	if ev.ID != "BBB222" {
		t.Errorf("ID: want BBB222, got %s", ev.ID)
	}
	if ev.ClientIP != "10.0.0.1" {
		t.Errorf("ClientIP: want 10.0.0.1, got %s", ev.ClientIP)
	}
	if ev.Service != "radarr.erfi.io" {
		t.Errorf("Service: want radarr.erfi.io, got %s", ev.Service)
	}
	if ev.URI != "/.env" {
		t.Errorf("URI: want /.env, got %s", ev.URI)
	}
	if !ev.IsBlocked {
		t.Error("expected IsBlocked=true")
	}
	if ev.Method != "GET" {
		t.Errorf("Method: want GET, got %s", ev.Method)
	}
	if ev.UserAgent != "curl/7.68" {
		t.Errorf("UserAgent: want curl/7.68, got %s", ev.UserAgent)
	}
	if ev.ResponseStatus != 403 {
		t.Errorf("ResponseStatus: want 403, got %d", ev.ResponseStatus)
	}
	// Large fields should be nil/empty after restore from JSONL.
	if ev.RequestHeaders != nil {
		t.Error("RequestHeaders should be nil after JSONL restore")
	}
	if ev.RequestBody != "" {
		t.Error("RequestBody should be empty after JSONL restore")
	}
	if ev.RequestArgs != nil {
		t.Error("RequestArgs should be nil after JSONL restore")
	}
}

func TestStoreEventFileMalformedLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	eventPath := filepath.Join(dir, "events.jsonl")

	// Pre-seed a JSONL file with some valid events and some garbage.
	ef, _ := os.Create(eventPath)
	// Valid event line (manually construct minimal JSON).
	ef.WriteString(`{"id":"GOOD1","timestamp":"2026-02-22T07:19:01Z","client_ip":"1.1.1.1","service":"test.erfi.io","method":"GET","uri":"/ok","is_blocked":false,"response_status":200,"event_type":"logged"}` + "\n")
	ef.WriteString("THIS IS NOT JSON\n")
	ef.WriteString("{broken json\n")
	ef.WriteString(`{"id":"GOOD2","timestamp":"2026-02-22T07:20:00Z","client_ip":"2.2.2.2","service":"test.erfi.io","method":"POST","uri":"/api","is_blocked":true,"response_status":403,"event_type":"blocked"}` + "\n")
	ef.Close()

	// Create empty audit log so Load() has nothing to add.
	os.Create(logPath)

	store := NewStore(logPath)
	store.SetEventFile(eventPath)

	// Should gracefully skip malformed lines and load 2 valid events.
	if got := store.EventCount(); got != 2 {
		t.Fatalf("expected 2 events (skipping malformed), got %d", got)
	}

	events := store.Snapshot()
	if events[0].ID != "GOOD1" {
		t.Errorf("first event: want GOOD1, got %s", events[0].ID)
	}
	if events[1].ID != "GOOD2" {
		t.Errorf("second event: want GOOD2, got %s", events[1].ID)
	}
}

func TestStoreEventFileEmpty(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	eventPath := filepath.Join(dir, "events.jsonl")

	// Create an empty JSONL file.
	os.Create(eventPath)
	os.Create(logPath)

	store := NewStore(logPath)
	store.SetEventFile(eventPath)

	if got := store.EventCount(); got != 0 {
		t.Fatalf("expected 0 events from empty JSONL, got %d", got)
	}
}

func TestStoreEventFileMigratesMisclassifiedPolicySkip(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	eventPath := filepath.Join(dir, "events.jsonl")
	os.Create(logPath)

	// Write JSONL with a misclassified event: policy_skip but is_blocked=true.
	ef, _ := os.Create(eventPath)
	ef.WriteString(`{"id":"MIS1","timestamp":"2026-02-22T10:00:00Z","client_ip":"1.1.1.1","service":"test.erfi.io","method":"POST","uri":"/upload","is_blocked":true,"response_status":403,"event_type":"policy_skip"}` + "\n")
	// Correctly classified: policy_skip and NOT blocked.
	ef.WriteString(`{"id":"OK1","timestamp":"2026-02-22T10:01:00Z","client_ip":"2.2.2.2","service":"test.erfi.io","method":"GET","uri":"/page","is_blocked":false,"response_status":200,"event_type":"policy_skip"}` + "\n")
	// Normal blocked event — should not be touched.
	ef.WriteString(`{"id":"OK2","timestamp":"2026-02-22T10:02:00Z","client_ip":"3.3.3.3","service":"test.erfi.io","method":"GET","uri":"/.env","is_blocked":true,"response_status":403,"event_type":"blocked"}` + "\n")
	ef.Close()

	store := NewStore(logPath)
	store.SetEventFile(eventPath)

	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3 events, got %d", got)
	}

	events := store.Snapshot()
	for _, ev := range events {
		switch ev.ID {
		case "MIS1":
			if ev.EventType != "blocked" {
				t.Errorf("MIS1: want event_type=blocked after migration, got %s", ev.EventType)
			}
		case "OK1":
			if ev.EventType != "policy_skip" {
				t.Errorf("OK1: should remain policy_skip, got %s", ev.EventType)
			}
		case "OK2":
			if ev.EventType != "blocked" {
				t.Errorf("OK2: should remain blocked, got %s", ev.EventType)
			}
		}
	}

	// Verify the compacted JSONL file also has the fix.
	// Give the goroutine a moment to compact.
	time.Sleep(100 * time.Millisecond)
	restored, err := loadEventsFromJSONL(eventPath)
	if err != nil {
		t.Fatalf("error reading compacted JSONL: %v", err)
	}
	for _, ev := range restored {
		if ev.ID == "MIS1" && ev.EventType != "blocked" {
			t.Errorf("MIS1 in compacted JSONL: want blocked, got %s", ev.EventType)
		}
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

// testHealthHandler returns a handleHealth closure with minimal test stores.

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

func TestComputeAnomalyScoreByPhase(t *testing.T) {
	tests := []struct {
		name     string
		messages []AuditMessage
		outbound bool
		want     int
	}{
		{"empty inbound", nil, false, 0},
		{"empty outbound", nil, true, 0},
		{"single inbound critical", []AuditMessage{{Data: AuditMessageData{ID: 942100, Severity: 2}}}, false, 5},
		{"single inbound notice", []AuditMessage{{Data: AuditMessageData{ID: 920330, Severity: 5}}}, false, 2},
		{"inbound critical + notice", []AuditMessage{
			{Data: AuditMessageData{ID: 942100, Severity: 2}},
			{Data: AuditMessageData{ID: 920330, Severity: 5}},
		}, false, 7},
		{"dedup chain rules", []AuditMessage{
			{Data: AuditMessageData{ID: 932240, Severity: 2}},
			{Data: AuditMessageData{ID: 932240, Severity: 2}}, // chain duplicate
		}, false, 5},
		{"skip scoring rules", []AuditMessage{
			{Data: AuditMessageData{ID: 942100, Severity: 2}},
			{Data: AuditMessageData{ID: 949110, Severity: 0}},
			{Data: AuditMessageData{ID: 959100, Severity: 0}},
			{Data: AuditMessageData{ID: 980170, Severity: 0}},
		}, false, 5},
		{"skip id 0", []AuditMessage{
			{Data: AuditMessageData{ID: 0, Severity: 2}},
			{Data: AuditMessageData{ID: 920330, Severity: 5}},
		}, false, 2},
		{"all inbound severities", []AuditMessage{
			{Data: AuditMessageData{ID: 910100, Severity: 2}}, // CRITICAL = 5
			{Data: AuditMessageData{ID: 920100, Severity: 3}}, // ERROR = 4
			{Data: AuditMessageData{ID: 930100, Severity: 4}}, // WARNING = 3
			{Data: AuditMessageData{ID: 941100, Severity: 5}}, // NOTICE = 2
		}, false, 14},
		// Outbound tests
		{"single outbound critical", []AuditMessage{{Data: AuditMessageData{ID: 950100, Severity: 2}}}, true, 5},
		{"outbound SQL leak", []AuditMessage{{Data: AuditMessageData{ID: 951100, Severity: 2}}}, true, 5},
		{"outbound multiple", []AuditMessage{
			{Data: AuditMessageData{ID: 950100, Severity: 4}}, // WARNING = 3
			{Data: AuditMessageData{ID: 951100, Severity: 2}}, // CRITICAL = 5
		}, true, 8},
		// Phase separation
		{"inbound ignores outbound rules", []AuditMessage{
			{Data: AuditMessageData{ID: 942100, Severity: 2}}, // inbound
			{Data: AuditMessageData{ID: 950100, Severity: 2}}, // outbound - should be ignored
		}, false, 5},
		{"outbound ignores inbound rules", []AuditMessage{
			{Data: AuditMessageData{ID: 942100, Severity: 2}}, // inbound - should be ignored
			{Data: AuditMessageData{ID: 950100, Severity: 2}}, // outbound
		}, true, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeAnomalyScoreByPhase(tt.messages, tt.outbound)
			if got != tt.want {
				t.Errorf("computeAnomalyScoreByPhase(outbound=%v) = %d, want %d", tt.outbound, got, tt.want)
			}
		})
	}
}

func TestIsScoringRule(t *testing.T) {
	// These should all be treated as scoring/evaluation rules.
	scoringIDs := []int{0, 949110, 959100, 980170}
	for _, id := range scoringIDs {
		if !isScoringRule(id) {
			t.Errorf("isScoringRule(%d) = false, want true", id)
		}
	}

	// These should NOT be scoring rules.
	normalIDs := []int{942100, 930120, 920420, 950100, 9500001, 9100021}
	for _, id := range normalIDs {
		if isScoringRule(id) {
			t.Errorf("isScoringRule(%d) = true, want false", id)
		}
	}
}

func TestComputeAnomalyScoreCombined(t *testing.T) {
	// computeAnomalyScore should sum both inbound and outbound.
	messages := []AuditMessage{
		{Data: AuditMessageData{ID: 942100, Severity: 2}}, // inbound CRITICAL = 5
		{Data: AuditMessageData{ID: 950100, Severity: 4}}, // outbound WARNING = 3
	}
	got := computeAnomalyScore(messages)
	if got != 8 {
		t.Errorf("computeAnomalyScore() = %d, want 8", got)
	}
}

func TestExtractScoresFrom980170(t *testing.T) {
	tests := []struct {
		name         string
		msg          string
		wantInbound  int
		wantOutbound int
	}{
		{
			"full CRS 4.x message",
			"Anomaly Scores: (Inbound Scores: blocking=15, detection=15, per_pl=15-0-0-0, threshold=5) - (Outbound Scores: blocking=3, detection=3, per_pl=3-0-0-0, threshold=4)",
			15, 3,
		},
		{
			"zero outbound",
			"Anomaly Scores: (Inbound Scores: blocking=5, detection=5, per_pl=5-0-0-0, threshold=5) - (Outbound Scores: blocking=0, detection=0, per_pl=0-0-0-0, threshold=4)",
			5, 0,
		},
		{
			"zero inbound",
			"Anomaly Scores: (Inbound Scores: blocking=0, detection=0, per_pl=0-0-0-0, threshold=5) - (Outbound Scores: blocking=8, detection=8, per_pl=8-0-0-0, threshold=4)",
			0, 8,
		},
		{"empty", "", 0, 0},
		{"unrelated", "Remote Command Execution detected", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIn, gotOut := extractScoresFrom980170(tt.msg)
			if gotIn != tt.wantInbound {
				t.Errorf("inbound = %d, want %d", gotIn, tt.wantInbound)
			}
			if gotOut != tt.wantOutbound {
				t.Errorf("outbound = %d, want %d", gotOut, tt.wantOutbound)
			}
		})
	}
}

func TestOutboundAnomalyScoreInParsedEvent(t *testing.T) {
	// Audit log with both inbound (949110) and outbound (959100) scoring rules.
	entry := `{"transaction":{"timestamp":"2026/01/01 00:00:00","unix_timestamp":1,"id":"test-outbound","client_ip":"1.2.3.4","server_id":"test.erfi.io","request":{"method":"GET","uri":"/test","headers":{}},"response":{"status":403},"producer":{"rule_engine":"On"}},"messages":[{"message":"SQL Injection","data":{"id":942100,"msg":"SQL Injection","severity":2,"tags":["attack-sqli"]}},{"message":"SQL Information Leakage","data":{"id":951100,"msg":"SQL Information Leakage","severity":2,"tags":["leakage-sql"]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","data":{"id":949110,"msg":"Inbound Anomaly Score Exceeded (Total Score: 5)","severity":0,"tags":["anomaly-evaluation"]}},{"message":"Outbound Anomaly Score Exceeded (Total Score: 5)","data":{"id":959100,"msg":"Outbound Anomaly Score Exceeded (Total Score: 5)","severity":0,"tags":["anomaly-evaluation"]}}]}`

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	os.WriteFile(path, []byte(entry+"\n"), 0644)

	store := NewStore(path)
	store.Load()
	events := store.Snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].AnomalyScore != 5 {
		t.Errorf("expected inbound anomaly score 5, got %d", events[0].AnomalyScore)
	}
	if events[0].OutboundAnomalyScore != 5 {
		t.Errorf("expected outbound anomaly score 5, got %d", events[0].OutboundAnomalyScore)
	}
}

func TestOutboundScoreFrom980170Fallback(t *testing.T) {
	// When 949110/959100 don't fire but 980170 provides the full breakdown.
	entry := `{"transaction":{"timestamp":"2026/01/01 00:00:00","unix_timestamp":1,"id":"test-980170","client_ip":"1.2.3.4","server_id":"test.erfi.io","request":{"method":"GET","uri":"/test","headers":{}},"response":{"status":200},"producer":{"rule_engine":"DetectionOnly"}},"messages":[{"message":"SQL Injection","data":{"id":942100,"msg":"SQL Injection","severity":2,"tags":["attack-sqli"]}},{"message":"SQL Information Leakage","data":{"id":951100,"msg":"SQL Information Leakage","severity":2,"tags":["leakage-sql"]}},{"message":"Anomaly Scores: (Inbound Scores: blocking=5, detection=5, per_pl=5-0-0-0, threshold=10000) - (Outbound Scores: blocking=5, detection=5, per_pl=5-0-0-0, threshold=10000)","data":{"id":980170,"msg":"Anomaly Scores: (Inbound Scores: blocking=5, detection=5, per_pl=5-0-0-0, threshold=10000) - (Outbound Scores: blocking=5, detection=5, per_pl=5-0-0-0, threshold=10000)","severity":0,"tags":["reporting"]}}]}`

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	os.WriteFile(path, []byte(entry+"\n"), 0644)

	store := NewStore(path)
	store.Load()
	events := store.Snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].AnomalyScore != 5 {
		t.Errorf("expected inbound anomaly score 5, got %d", events[0].AnomalyScore)
	}
	if events[0].OutboundAnomalyScore != 5 {
		t.Errorf("expected outbound anomaly score 5, got %d", events[0].OutboundAnomalyScore)
	}
}

func TestAnomalyScoreFallbackComputed(t *testing.T) {
	// DetectionOnly mode: rule 949110 doesn't fire (score below threshold).
	// Score should be computed from individual rule severities.
	entry := `{"transaction":{"timestamp":"2026/01/01 00:00:00","unix_timestamp":1,"id":"test2","client_ip":"1.2.3.4","server_id":"test.erfi.io","request":{"method":"GET","uri":"/test","headers":{}},"response":{"status":200},"producer":{"rule_engine":"DetectionOnly"}},"messages":[{"message":"Empty User Agent Header","data":{"id":920330,"msg":"Empty User Agent Header","severity":5,"tags":["attack-protocol"]}}]}`

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	os.WriteFile(path, []byte(entry+"\n"), 0644)

	store := NewStore(path)
	store.Load()
	events := store.Snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	// NOTICE severity = 2 points.
	if events[0].AnomalyScore != 2 {
		t.Errorf("expected computed anomaly score 2, got %d", events[0].AnomalyScore)
	}
}

// ─── End-to-End Deploy Pipeline Tests ───────────────────────────────

// TestDeployEndToEnd_ExclusionAndSettings simulates the full user flow:
// 1. Create an exclusion via POST /api/exclusions
// 2. Update WAF settings via PUT /api/config
// 3. Deploy via POST /api/config/deploy
// 4. Verify all three generated files contain correct content
// 5. Verify exclusions are NOT lost when settings deploy, and vice versa

func TestParseEvent_PolicyEventType(t *testing.T) {
	// When the audit log contains a rule in the 9500000-9599999 range
	// with a "Policy ..." msg, parseEvent should set the correct event_type.

	tests := []struct {
		name          string
		ruleID        int
		msg           string
		isInterrupted bool
		wantType      string
	}{
		{"policy skip", 9500001, "Policy Skip: Skip 920420", false, "policy_skip"},
		{"policy allow", 9500002, "Policy Allow: Allow my IP", false, "policy_allow"},
		{"policy block", 9500003, "Policy Block: Block bad actor", true, "policy_block"},
		{"normal CRS rule", 932235, "Remote Command Execution", false, "logged"},
		{"blocked CRS rule (needs IsInterrupted)", 932235, "Remote Command Execution", false, "logged"},
		// Skip rule fired but request was still blocked by other CRS rules.
		// Should classify as "blocked", not "policy_skip".
		{"policy skip still blocked", 9500001, "Policy Skip: Skip 920420", true, "blocked"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := AuditLogEntry{
				Transaction: Transaction{
					Timestamp:     "2026-01-01T00:00:00Z",
					ID:            "test-" + tt.name,
					IsInterrupted: tt.isInterrupted,
				},
				Messages: []AuditMessage{
					{Data: AuditMessageData{ID: tt.ruleID, Msg: tt.msg}},
				},
			}
			ev := parseEvent(entry)
			if ev.EventType != tt.wantType {
				t.Errorf("parseEvent() event_type = %q, want %q", ev.EventType, tt.wantType)
			}
		})
	}
}

func TestParseEvent_HoneypotEventType(t *testing.T) {
	// Honeypot rule IDs are 9100020–9100029. When the audit log contains
	// a match from this range, parseEvent should classify it as "honeypot".
	tests := []struct {
		name          string
		ruleID        int
		msg           string
		isInterrupted bool
		wantType      string
	}{
		{"honeypot path probe", 9100020, "Honeypot: known-bad path probe", true, "honeypot"},
		{"honeypot high ID", 9100029, "Honeypot: some other path", true, "honeypot"},
		{"not honeypot - below range", 9100019, "Post-CRS rule", true, "blocked"},
		{"not honeypot - above range", 9100030, "Heuristic: missing Accept header", false, "logged"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := AuditLogEntry{
				Transaction: Transaction{
					Timestamp:     "2026-01-15T12:00:00Z",
					ID:            "honeypot-" + tt.name,
					IsInterrupted: tt.isInterrupted,
				},
				Messages: []AuditMessage{
					{Data: AuditMessageData{ID: tt.ruleID, Msg: tt.msg}},
				},
			}
			ev := parseEvent(entry)
			if ev.EventType != tt.wantType {
				t.Errorf("parseEvent() event_type = %q, want %q", ev.EventType, tt.wantType)
			}
		})
	}
}

func TestParseEvent_ScannerEventType(t *testing.T) {
	// Scanner UA rule ID is 9100032. When the audit log contains a match
	// from this specific rule, parseEvent should classify it as "scanner".
	tests := []struct {
		name          string
		ruleID        int
		msg           string
		isInterrupted bool
		wantType      string
	}{
		{"scanner UA drop", 9100032, "Heuristic: known scanner User-Agent", true, "scanner"},
		{"heuristic missing Accept (not scanner)", 9100030, "Heuristic: missing Accept header", false, "logged"},
		{"heuristic HTTP/1.0 (not scanner)", 9100031, "Heuristic: HTTP/1.0 protocol", false, "logged"},
		{"heuristic empty UA (not scanner)", 9100033, "Heuristic: empty or missing User-Agent", false, "logged"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := AuditLogEntry{
				Transaction: Transaction{
					Timestamp:     "2026-01-15T12:00:00Z",
					ID:            "scanner-" + tt.name,
					IsInterrupted: tt.isInterrupted,
				},
				Messages: []AuditMessage{
					{Data: AuditMessageData{ID: tt.ruleID, Msg: tt.msg}},
				},
			}
			ev := parseEvent(entry)
			if ev.EventType != tt.wantType {
				t.Errorf("parseEvent() event_type = %q, want %q", ev.EventType, tt.wantType)
			}
		})
	}
}

func TestParseEvent_PolicyTakesPriorityOverHoneypot(t *testing.T) {
	// If both a policy rule and a honeypot rule match (unlikely but possible
	// in a chained scenario), policy classification should win.
	entry := AuditLogEntry{
		Transaction: Transaction{
			Timestamp:     "2026-01-15T12:00:00Z",
			ID:            "priority-test",
			IsInterrupted: true,
		},
		Messages: []AuditMessage{
			{Data: AuditMessageData{ID: 9100020, Msg: "Honeypot: known-bad path probe"}},
			{Data: AuditMessageData{ID: 9500001, Msg: "Policy Block: Block bad paths"}},
		},
	}
	ev := parseEvent(entry)
	if ev.EventType != "policy_block" {
		t.Errorf("parseEvent() event_type = %q, want %q (policy should take priority)", ev.EventType, "policy_block")
	}
}

func TestSummarizeEvents_HoneypotAndScannerCounts(t *testing.T) {
	events := []Event{
		{ID: "1", EventType: "blocked", IsBlocked: true},
		{ID: "2", EventType: "honeypot", IsBlocked: true},
		{ID: "3", EventType: "honeypot", IsBlocked: true},
		{ID: "4", EventType: "scanner", IsBlocked: true},
		{ID: "5", EventType: "logged", IsBlocked: false},
		{ID: "6", EventType: "policy_skip", IsBlocked: false},
	}
	summary := summarizeEvents(events)

	if summary.HoneypotEvents != 2 {
		t.Errorf("HoneypotEvents = %d, want 2", summary.HoneypotEvents)
	}
	if summary.ScannerEvents != 1 {
		t.Errorf("ScannerEvents = %d, want 1", summary.ScannerEvents)
	}
	// Honeypot (2) + scanner (1) + regular blocked (1) = 4 total blocked
	if summary.BlockedEvents != 4 {
		t.Errorf("BlockedEvents = %d, want 4", summary.BlockedEvents)
	}
	if summary.LoggedEvents != 1 {
		t.Errorf("LoggedEvents = %d, want 1", summary.LoggedEvents)
	}
	if summary.PolicyEvents != 1 {
		t.Errorf("PolicyEvents = %d, want 1", summary.PolicyEvents)
	}
}

// ─── GeoIP Tests ─────────────────────────────────────────────────────────────

// ─── Per-Hour/Service/Client Breakdown Tests ─────────────────────────────────

func TestSummarizeEvents_PerHourBreakdown(t *testing.T) {
	ts := time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{ID: "1", Timestamp: ts, Service: "a.io", ClientIP: "1.1.1.1", EventType: "blocked", IsBlocked: true},
		{ID: "2", Timestamp: ts, Service: "a.io", ClientIP: "1.1.1.1", EventType: "honeypot", IsBlocked: true},
		{ID: "3", Timestamp: ts, Service: "a.io", ClientIP: "2.2.2.2", EventType: "scanner", IsBlocked: true},
		{ID: "4", Timestamp: ts, Service: "a.io", ClientIP: "2.2.2.2", EventType: "policy_skip", IsBlocked: false},
		{ID: "5", Timestamp: ts, Service: "a.io", ClientIP: "3.3.3.3", EventType: "policy_block", IsBlocked: true},
		{ID: "6", Timestamp: ts, Service: "a.io", ClientIP: "3.3.3.3", EventType: "logged", IsBlocked: false},
	}
	summary := summarizeEvents(events)

	if len(summary.EventsByHour) != 1 {
		t.Fatalf("EventsByHour length = %d, want 1", len(summary.EventsByHour))
	}
	h := summary.EventsByHour[0]
	if h.Count != 6 {
		t.Errorf("hour.Count = %d, want 6", h.Count)
	}
	if h.Blocked != 1 { // only plain "blocked" type (not honeypot/scanner/policy)
		t.Errorf("hour.Blocked = %d, want 1", h.Blocked)
	}
	if h.Logged != 1 { // total - blocked - honeypot - scanner - policy
		t.Errorf("hour.Logged = %d, want 1", h.Logged)
	}
	if h.Honeypot != 1 {
		t.Errorf("hour.Honeypot = %d, want 1", h.Honeypot)
	}
	if h.Scanner != 1 {
		t.Errorf("hour.Scanner = %d, want 1", h.Scanner)
	}
	if h.Policy != 2 { // policy_skip + policy_block
		t.Errorf("hour.Policy = %d, want 2", h.Policy)
	}
}

func TestSummarizeEvents_PerServiceBreakdown(t *testing.T) {
	ts := time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{ID: "1", Timestamp: ts, Service: "svc1.io", ClientIP: "1.1.1.1", EventType: "honeypot", IsBlocked: true},
		{ID: "2", Timestamp: ts, Service: "svc1.io", ClientIP: "1.1.1.1", EventType: "scanner", IsBlocked: true},
		{ID: "3", Timestamp: ts, Service: "svc1.io", ClientIP: "1.1.1.1", EventType: "policy_allow", IsBlocked: false},
		{ID: "4", Timestamp: ts, Service: "svc2.io", ClientIP: "2.2.2.2", EventType: "policy_block", IsBlocked: true},
		{ID: "5", Timestamp: ts, Service: "svc2.io", ClientIP: "2.2.2.2", EventType: "logged", IsBlocked: false},
	}
	summary := summarizeEvents(events)

	// Find svc1 in ServiceBreakdown
	var svc1, svc2 *ServiceDetail
	for i := range summary.ServiceBreakdown {
		switch summary.ServiceBreakdown[i].Service {
		case "svc1.io":
			svc1 = &summary.ServiceBreakdown[i]
		case "svc2.io":
			svc2 = &summary.ServiceBreakdown[i]
		}
	}
	if svc1 == nil || svc2 == nil {
		t.Fatalf("missing services in breakdown: svc1=%v svc2=%v", svc1, svc2)
	}
	if svc1.Honeypot != 1 {
		t.Errorf("svc1.Honeypot = %d, want 1", svc1.Honeypot)
	}
	if svc1.Scanner != 1 {
		t.Errorf("svc1.Scanner = %d, want 1", svc1.Scanner)
	}
	if svc1.Policy != 1 { // policy_allow
		t.Errorf("svc1.Policy = %d, want 1", svc1.Policy)
	}
	if svc2.Policy != 1 { // policy_block
		t.Errorf("svc2.Policy = %d, want 1", svc2.Policy)
	}
	if svc2.Honeypot != 0 {
		t.Errorf("svc2.Honeypot = %d, want 0", svc2.Honeypot)
	}
}

func TestSummarizeEvents_PerClientBreakdown(t *testing.T) {
	ts := time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{ID: "1", Timestamp: ts, Service: "a.io", ClientIP: "10.0.0.1", EventType: "honeypot", IsBlocked: true},
		{ID: "2", Timestamp: ts, Service: "a.io", ClientIP: "10.0.0.1", EventType: "scanner", IsBlocked: true},
		{ID: "3", Timestamp: ts, Service: "a.io", ClientIP: "10.0.0.1", EventType: "policy_skip", IsBlocked: false},
		{ID: "4", Timestamp: ts, Service: "a.io", ClientIP: "10.0.0.2", EventType: "blocked", IsBlocked: true},
	}
	summary := summarizeEvents(events)

	// Find client 10.0.0.1
	var c1 *ClientCount
	for i := range summary.TopClients {
		if summary.TopClients[i].Client == "10.0.0.1" {
			c1 = &summary.TopClients[i]
		}
	}
	if c1 == nil {
		t.Fatal("client 10.0.0.1 not found in TopClients")
	}
	if c1.Honeypot != 1 {
		t.Errorf("client.Honeypot = %d, want 1", c1.Honeypot)
	}
	if c1.Scanner != 1 {
		t.Errorf("client.Scanner = %d, want 1", c1.Scanner)
	}
	if c1.Policy != 1 {
		t.Errorf("client.Policy = %d, want 1", c1.Policy)
	}
	if c1.Count != 3 {
		t.Errorf("client.Count = %d, want 3", c1.Count)
	}
	if c1.Blocked != 0 { // Blocked only counts plain "blocked" type, not honeypot/scanner
		t.Errorf("client.Blocked = %d, want 0", c1.Blocked)
	}
}

func TestComputeServices_TracksAllEventTypes(t *testing.T) {
	events := []Event{
		{Service: "web.io", EventType: "blocked", IsBlocked: true},
		{Service: "web.io", EventType: "honeypot", IsBlocked: true},
		{Service: "web.io", EventType: "scanner", IsBlocked: true},
		{Service: "web.io", EventType: "policy_skip", IsBlocked: false},
		{Service: "web.io", EventType: "policy_block", IsBlocked: true},
		{Service: "web.io", EventType: "logged", IsBlocked: false},
		{Service: "api.io", EventType: "honeypot", IsBlocked: true},
	}
	resp := computeServices(events)

	var web, api *ServiceDetail
	for i := range resp.Services {
		switch resp.Services[i].Service {
		case "web.io":
			web = &resp.Services[i]
		case "api.io":
			api = &resp.Services[i]
		}
	}
	if web == nil || api == nil {
		t.Fatalf("missing service: web=%v api=%v", web, api)
	}

	if web.Total != 6 {
		t.Errorf("web.Total = %d, want 6", web.Total)
	}
	if web.Blocked != 4 { // blocked + honeypot + scanner + policy_block
		t.Errorf("web.Blocked = %d, want 4", web.Blocked)
	}
	if web.Logged != 2 {
		t.Errorf("web.Logged = %d, want 2", web.Logged)
	}
	if web.Honeypot != 1 {
		t.Errorf("web.Honeypot = %d, want 1", web.Honeypot)
	}
	if web.Scanner != 1 {
		t.Errorf("web.Scanner = %d, want 1", web.Scanner)
	}
	if web.Policy != 2 { // policy_skip + policy_block
		t.Errorf("web.Policy = %d, want 2", web.Policy)
	}
	if api.Honeypot != 1 {
		t.Errorf("api.Honeypot = %d, want 1", api.Honeypot)
	}
	if api.Scanner != 0 {
		t.Errorf("api.Scanner = %d, want 0", api.Scanner)
	}
}

func TestIPLookup_TracksAllEventTypes(t *testing.T) {
	s := NewStore("")
	s.mu.Lock()
	s.events = []Event{
		{ID: "1", Timestamp: time.Now(), Service: "web.io", ClientIP: "10.0.0.1", EventType: "honeypot", IsBlocked: true},
		{ID: "2", Timestamp: time.Now(), Service: "web.io", ClientIP: "10.0.0.1", EventType: "scanner", IsBlocked: true},
		{ID: "3", Timestamp: time.Now(), Service: "web.io", ClientIP: "10.0.0.1", EventType: "policy_allow", IsBlocked: false},
		{ID: "4", Timestamp: time.Now(), Service: "api.io", ClientIP: "10.0.0.1", EventType: "policy_block", IsBlocked: true},
		{ID: "5", Timestamp: time.Now(), Service: "web.io", ClientIP: "99.99.99.99", EventType: "blocked", IsBlocked: true},
	}
	s.mu.Unlock()

	resp := s.IPLookup("10.0.0.1", 168, 50, 0)

	if resp.Total != 4 {
		t.Errorf("Total = %d, want 4", resp.Total)
	}
	if resp.Blocked != 3 { // honeypot + scanner + policy_block
		t.Errorf("Blocked = %d, want 3", resp.Blocked)
	}

	var web, api *ServiceDetail
	for i := range resp.Services {
		switch resp.Services[i].Service {
		case "web.io":
			web = &resp.Services[i]
		case "api.io":
			api = &resp.Services[i]
		}
	}
	if web == nil || api == nil {
		t.Fatalf("missing service: web=%v api=%v", web, api)
	}
	if web.Honeypot != 1 {
		t.Errorf("web.Honeypot = %d, want 1", web.Honeypot)
	}
	if web.Scanner != 1 {
		t.Errorf("web.Scanner = %d, want 1", web.Scanner)
	}
	if web.Policy != 1 { // policy_allow
		t.Errorf("web.Policy = %d, want 1", web.Policy)
	}
	if api.Policy != 1 { // policy_block
		t.Errorf("api.Policy = %d, want 1", api.Policy)
	}
}

// --- GeoIP Online API Fallback Tests ---
