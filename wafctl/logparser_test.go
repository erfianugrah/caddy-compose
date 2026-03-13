package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStoreEviction verifies that events older than maxAge are removed.
func TestStoreEviction(t *testing.T) {
	store := storeWithEvents(t, []Event{
		{ID: "old", Timestamp: time.Now().UTC().Add(-200 * time.Hour), EventType: "detect_block"},
		{ID: "new", Timestamp: time.Now().UTC().Add(-1 * time.Hour), EventType: "detect_block"},
	})
	store.SetMaxAge(168 * time.Hour) // 7 days
	store.evictOld()                 // triggers eviction
	if got := store.EventCount(); got != 1 {
		t.Fatalf("expected 1 event after eviction, got %d", got)
	}
	snap := store.Snapshot()
	if snap[0].ID != "new" {
		t.Errorf("expected 'new' event to survive, got %q", snap[0].ID)
	}
}

func TestStoreEventFileMalformedLines(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")

	// Pre-seed a JSONL file with some valid events and some garbage.
	ef, _ := os.Create(eventPath)
	// Valid event line (manually construct minimal JSON).
	ef.WriteString(`{"id":"GOOD1","timestamp":"2026-02-22T07:19:01Z","client_ip":"1.1.1.1","service":"test.erfi.io","method":"GET","uri":"/ok","is_blocked":false,"response_status":200,"event_type":"logged"}` + "\n")
	ef.WriteString("THIS IS NOT JSON\n")
	ef.WriteString("{broken json\n")
	ef.WriteString(`{"id":"GOOD2","timestamp":"2026-02-22T07:20:00Z","client_ip":"2.2.2.2","service":"test.erfi.io","method":"POST","uri":"/api","is_blocked":true,"response_status":403,"event_type":"blocked"}` + "\n")
	ef.Close()

	store := NewStore()
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
	eventPath := filepath.Join(dir, "events.jsonl")

	// Create an empty JSONL file.
	os.Create(eventPath)

	store := NewStore()
	store.SetEventFile(eventPath)

	if got := store.EventCount(); got != 0 {
		t.Fatalf("expected 0 events from empty JSONL, got %d", got)
	}
}

func TestStoreEventFileLoadsEvents(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")

	ef, _ := os.Create(eventPath)
	ef.WriteString(`{"id":"E1","timestamp":"2026-02-22T10:00:00Z","client_ip":"1.1.1.1","service":"test.erfi.io","method":"POST","uri":"/upload","is_blocked":true,"response_status":403,"event_type":"blocked"}` + "\n")
	ef.WriteString(`{"id":"E2","timestamp":"2026-02-22T10:01:00Z","client_ip":"2.2.2.2","service":"test.erfi.io","method":"GET","uri":"/page","is_blocked":false,"response_status":200,"event_type":"policy_skip"}` + "\n")
	ef.WriteString(`{"id":"E3","timestamp":"2026-02-22T10:02:00Z","client_ip":"3.3.3.3","service":"test.erfi.io","method":"GET","uri":"/.env","is_blocked":true,"response_status":403,"event_type":"policy_block"}` + "\n")
	ef.Close()

	store := NewStore()
	store.SetEventFile(eventPath)

	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3 events, got %d", got)
	}

	events := store.Snapshot()
	if events[0].ID != "E1" || events[0].EventType != "detect_block" {
		t.Errorf("event 0: want E1/detect_block, got %s/%s", events[0].ID, events[0].EventType)
	}
	if events[1].ID != "E2" || events[1].EventType != "policy_skip" {
		t.Errorf("event 1: want E2/policy_skip, got %s/%s", events[1].ID, events[1].EventType)
	}
	if events[2].ID != "E3" || events[2].EventType != "policy_block" {
		t.Errorf("event 2: want E3/policy_block, got %s/%s", events[2].ID, events[2].EventType)
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

func TestRateLimitEventToEvent(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 2, 22, 12, 1, 0, 0, time.UTC),
		ClientIP:  "10.0.0.5",
		Service:   "sonarr.erfi.io",
		Method:    "GET",
		URI:       "/api/v3/queue",
		UserAgent: "curl/7.68",
	}

	ev := RateLimitEventToEvent(rle, nil)

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
	// Events without a Caddy request UUID have an empty ID (legacy entries age out).
	if ev.ID != "" {
		t.Errorf("ID should be empty for events without RequestID, got %s", ev.ID)
	}
}

func TestSnapshotAsEvents(t *testing.T) {
	path := writeTempAccessLog(t, sampleAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	events := store.SnapshotAsEvents(0, nil)
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
	store := emptyWAFStore(t)

	// 429 events.
	alsPath := writeTempAccessLog(t, sampleAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()
	handleSummary(store, als, emptyRLRuleStore(t))(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp SummaryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// 0 WAF events + 3 429 events = 3 total.
	if resp.TotalEvents != 3 {
		t.Errorf("total_events: want 3 (0 WAF + 3 RL), got %d", resp.TotalEvents)
	}
	if resp.RateLimited != 3 {
		t.Errorf("rate_limited: want 3, got %d", resp.RateLimited)
	}
	if resp.TotalBlocked != 0 {
		t.Errorf("total_blocked: want 0, got %d", resp.TotalBlocked)
	}
	if resp.LoggedEvents != 0 {
		t.Errorf("logged_events: want 0, got %d", resp.LoggedEvents)
	}
}

func TestEventsMergesRateLimitedEvents(t *testing.T) {
	store := emptyWAFStore(t)

	alsPath := writeTempAccessLog(t, sampleAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	// All events (no filter).
	req := httptest.NewRequest("GET", "/api/events?limit=100", nil)
	w := httptest.NewRecorder()
	handleEvents(store, als, emptyRLRuleStore(t))(w, req)

	var resp EventsResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 3 {
		t.Errorf("total: want 3 (0 WAF + 3 RL), got %d", resp.Total)
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
	store := emptyWAFStore(t)

	alsPath := writeTempAccessLog(t, sampleAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	tests := []struct {
		eventType string
		want      int
	}{
		{"detect_block", 0}, // 0 WAF detect_block events (empty WAF store)
		{"logged", 0},       // 0 WAF logged events
		{"rate_limited", 3}, // 3 429 events
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/api/events?event_type="+tt.eventType+"&limit=100", nil)
		w := httptest.NewRecorder()
		handleEvents(store, als, emptyRLRuleStore(t))(w, req)

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

func TestServicesMergesRateLimitedCounts(t *testing.T) {
	store := emptyWAFStore(t)

	alsPath := writeTempAccessLog(t, sampleAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/services", nil)
	w := httptest.NewRecorder()
	handleServices(store, als, emptyRLRuleStore(t))(w, req)

	var resp ServicesResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Empty WAF store + 429s: sonarr.erfi.io (2), radarr.erfi.io (1).
	if len(resp.Services) != 2 {
		t.Fatalf("want 2 services, got %d", len(resp.Services))
	}

	svcMap := make(map[string]ServiceDetail)
	for _, s := range resp.Services {
		svcMap[s.Service] = s
	}

	radarr := svcMap["radarr.erfi.io"]
	if radarr.Total != 1 {
		t.Errorf("radarr total: want 1 (1 RL), got %d", radarr.Total)
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
}

func TestHeaderValuesCI(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		key     string
		want    string
	}{
		{"title-case key", map[string][]string{"X-Blocked-By": {"policy-engine"}}, "X-Blocked-By", "policy-engine"},
		{"lowercase key (HTTP/2)", map[string][]string{"x-blocked-by": {"policy-engine"}}, "X-Blocked-By", "policy-engine"},
		{"uppercase key", map[string][]string{"X-BLOCKED-BY": {"policy-engine"}}, "X-Blocked-By", "policy-engine"},
		{"no header", map[string][]string{}, "X-Blocked-By", ""},
		{"nil headers", nil, "X-Blocked-By", ""},
		{"empty value", map[string][]string{"x-blocked-by": {""}}, "X-Blocked-By", ""},
		{"lowercase X-Blocked-Rule", map[string][]string{"x-blocked-rule": {"Honeypot Paths"}}, "X-Blocked-Rule", "Honeypot Paths"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := headerValueCI(tt.headers, tt.key); got != tt.want {
				t.Errorf("headerValueCI(%v, %q) = %q, want %q", tt.headers, tt.key, got, tt.want)
			}
		})
	}
}

func TestAccessLogStoreLoadsPolicyBlocksFromIpsumFixture(t *testing.T) {
	// Uses the ipsum fixture which now has policy engine blocks.
	path := writeTempAccessLog(t, sampleIpsumAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	// 1 rate-limited (429) + 2 policy blocks (403+policy_action or lowercase header) = 3 total.
	if got := store.EventCount(); got != 3 {
		t.Fatalf("expected 3 events (1 RL + 2 policy), got %d", got)
	}
}

func TestPolicyBlockEventSource(t *testing.T) {
	path := writeTempAccessLog(t, sampleIpsumAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	events := store.SnapshotAsEvents(0, nil)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	var rl429Count, policyBlockCount int
	for _, ev := range events {
		switch ev.EventType {
		case "rate_limited":
			if ev.ResponseStatus != 429 {
				t.Errorf("rate_limited event should have status 429, got %d", ev.ResponseStatus)
			}
			rl429Count++
		case "policy_block":
			if ev.ResponseStatus != 403 {
				t.Errorf("policy_block event should have status 403, got %d", ev.ResponseStatus)
			}
			policyBlockCount++
		default:
			t.Errorf("unexpected event type: %s", ev.EventType)
		}
	}

	if rl429Count != 1 {
		t.Errorf("expected 1 rate_limited event, got %d", rl429Count)
	}
	if policyBlockCount != 2 {
		t.Errorf("expected 2 policy_block events, got %d", policyBlockCount)
	}
}

func TestRateLimitEventToEventIpsum(t *testing.T) {
	// Legacy Source="ipsum" is treated as policy_block (migrated to policy engine).
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 2, 22, 12, 2, 0, 0, time.UTC),
		ClientIP:  "10.0.0.3",
		Service:   "radarr.erfi.io",
		Method:    "GET",
		URI:       "/",
		UserAgent: "BadBot/1.0",
		Source:    "ipsum",
	}

	ev := RateLimitEventToEvent(rle, nil)

	if ev.EventType != "policy_block" {
		t.Errorf("event_type: want policy_block, got %s", ev.EventType)
	}
	if !ev.IsBlocked {
		t.Error("ipsum events should have is_blocked=true")
	}
	if ev.ResponseStatus != 403 {
		t.Errorf("response_status: want 403, got %d", ev.ResponseStatus)
	}
	// No hardcoded tags — tags come from exclusion store enrichment.
	if len(ev.Tags) != 0 {
		t.Errorf("tags: want empty (no extraTags), got %v", ev.Tags)
	}
}

func TestRateLimitEventToEvent_RequestID(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 2, 22, 12, 1, 0, 0, time.UTC),
		ClientIP:  "10.0.0.5",
		Service:   "sonarr.erfi.io",
		Method:    "GET",
		URI:       "/api/v3/queue",
		UserAgent: "curl/7.68",
		RequestID: "caddy-uuid-test-123",
	}

	ev := RateLimitEventToEvent(rle, nil)

	if ev.RequestID != "caddy-uuid-test-123" {
		t.Errorf("request_id: want caddy-uuid-test-123, got %q", ev.RequestID)
	}
	// Unified request ID: Event.ID should be the Caddy request UUID.
	if ev.ID != "caddy-uuid-test-123" {
		t.Errorf("ID (unified request ID): want caddy-uuid-test-123, got %q", ev.ID)
	}
}

func TestRateLimitEventToEvent_RequestID_Empty(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 2, 22, 12, 1, 0, 0, time.UTC),
		ClientIP:  "10.0.0.5",
		Service:   "sonarr.erfi.io",
		Method:    "GET",
		URI:       "/api/v3/queue",
	}

	ev := RateLimitEventToEvent(rle, nil)

	if ev.RequestID != "" {
		t.Errorf("request_id should be empty for events without it, got %q", ev.RequestID)
	}
	// Without a Caddy request UUID, ID is empty (legacy entries age out).
	if ev.ID != "" {
		t.Errorf("ID without RequestID should be empty, got %q", ev.ID)
	}
}

// --- Policy Engine Event Detection Tests ---

func TestIsPolicyBlocked(t *testing.T) {
	tests := []struct {
		name  string
		entry AccessLogEntry
		want  bool
	}{
		{"policy_action=block", AccessLogEntry{PolicyAction: "block"}, true},
		{"policy_action=honeypot", AccessLogEntry{PolicyAction: "honeypot"}, true},
		{"policy_action=allow", AccessLogEntry{PolicyAction: "allow"}, false},
		{"policy_action empty, header title-case", AccessLogEntry{RespHeaders: map[string][]string{"X-Blocked-By": {"policy-engine"}}}, true},
		{"policy_action empty, header lowercase (HTTP/2)", AccessLogEntry{RespHeaders: map[string][]string{"x-blocked-by": {"policy-engine"}}}, true},
		{"neither", AccessLogEntry{RespHeaders: map[string][]string{}}, false},
		{"nil headers", AccessLogEntry{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPolicyBlocked(tt.entry); got != tt.want {
				t.Errorf("isPolicyBlocked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyBlockedRuleName(t *testing.T) {
	tests := []struct {
		name  string
		entry AccessLogEntry
		want  string
	}{
		{"policy_rule field", AccessLogEntry{PolicyRule: "Honeypot Paths"}, "Honeypot Paths"},
		{"header title-case", AccessLogEntry{RespHeaders: map[string][]string{"X-Blocked-Rule": {"Honeypot Paths"}}}, "Honeypot Paths"},
		{"header lowercase (HTTP/2)", AccessLogEntry{RespHeaders: map[string][]string{"x-blocked-rule": {"Block Admin"}}}, "Block Admin"},
		{"policy_rule takes precedence over header", AccessLogEntry{PolicyRule: "From Var", RespHeaders: map[string][]string{"X-Blocked-Rule": {"From Header"}}}, "From Var"},
		{"no field no header", AccessLogEntry{}, ""},
		{"empty header", AccessLogEntry{RespHeaders: map[string][]string{"X-Blocked-Rule": {""}}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policyBlockedRuleName(tt.entry); got != tt.want {
				t.Errorf("policyBlockedRuleName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimitEventToEvent_PolicyBlock(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 2, 22, 12, 3, 0, 0, time.UTC),
		ClientIP:  "10.0.0.99",
		Service:   "sonarr.erfi.io",
		Method:    "GET",
		URI:       "/.env",
		UserAgent: "Scanner/1.0",
		Source:    "policy",
		RuleName:  "Honeypot Paths",
	}

	ev := RateLimitEventToEvent(rle, nil)

	if ev.EventType != "policy_block" {
		t.Errorf("event_type: want policy_block, got %s", ev.EventType)
	}
	if !ev.IsBlocked {
		t.Error("policy_block events should have is_blocked=true")
	}
	if ev.ResponseStatus != 403 {
		t.Errorf("response_status: want 403, got %d", ev.ResponseStatus)
	}
	if ev.RuleMsg != "Policy Block: Honeypot Paths" {
		t.Errorf("rule_msg: want 'Policy Block: Honeypot Paths', got %q", ev.RuleMsg)
	}
	// No default tags for policy events (tags come from exclusion store enrichment).
	if len(ev.Tags) != 0 {
		t.Errorf("tags: want empty (no extraTags), got %v", ev.Tags)
	}
}

func TestRateLimitEventToEvent_PolicyBlockWithTags(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 2, 22, 12, 3, 0, 0, time.UTC),
		ClientIP:  "10.0.0.99",
		Service:   "sonarr.erfi.io",
		Method:    "GET",
		URI:       "/.env",
		Source:    "policy",
		RuleName:  "Honeypot Paths",
	}

	ev := RateLimitEventToEvent(rle, []string{"honeypot", "scanner"})

	if ev.EventType != "policy_block" {
		t.Errorf("event_type: want policy_block, got %s", ev.EventType)
	}
	if len(ev.Tags) != 2 || ev.Tags[0] != "honeypot" || ev.Tags[1] != "scanner" {
		t.Errorf("tags: want [honeypot scanner], got %v", ev.Tags)
	}
}

func TestRateLimitEventToEvent_PolicyBlockNoRuleName(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 2, 22, 12, 3, 0, 0, time.UTC),
		ClientIP:  "10.0.0.99",
		Service:   "sonarr.erfi.io",
		Method:    "GET",
		URI:       "/admin",
		Source:    "policy",
	}

	ev := RateLimitEventToEvent(rle, nil)

	if ev.EventType != "policy_block" {
		t.Errorf("event_type: want policy_block, got %s", ev.EventType)
	}
	if ev.RuleMsg != "" {
		t.Errorf("rule_msg: want empty when no rule name, got %q", ev.RuleMsg)
	}
}

// samplePolicyAccessLogLines contains policy engine block events in access log format.
// Tests both detection paths: policy_action log_append field (primary) and
// X-Blocked-By response header (fallback, both title-case and lowercase).
var samplePolicyAccessLogLines = func() []string {
	nowHour := time.Now().Truncate(time.Hour)
	ts := func(t time.Time) string { return t.UTC().Format("2006/01/02 15:04:05") }
	return []string{
		// 200 OK — should be ignored
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["Sonarr/4.0"]}},"resp_headers":{},"status":200,"size":1234,"duration":0.05}`, ts(nowHour.Add(-50*time.Minute))),
		// 403 policy engine block — detected via policy_action field + title-case header
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.10","client_ip":"10.0.0.10","proto":"HTTP/1.1","method":"GET","host":"sonarr.erfi.io","uri":"/.env","headers":{"User-Agent":["Scanner/1.0"]}},"resp_headers":{"X-Blocked-By":["policy-engine"],"X-Blocked-Rule":["Honeypot Paths"]},"policy_action":"block","policy_rule":"Honeypot Paths","status":403,"size":0,"duration":0.001}`, ts(nowHour.Add(-49*time.Minute))),
		// 403 policy engine block — lowercase headers only (HTTP/2), no policy_action field
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.11","client_ip":"10.0.0.11","proto":"HTTP/1.1","method":"GET","host":"radarr.erfi.io","uri":"/","headers":{"User-Agent":["Nmap/7.0"]}},"resp_headers":{"x-blocked-by":["policy-engine"]},"status":403,"size":0,"duration":0.001}`, ts(nowHour.Add(-48*time.Minute))),
		// 429 rate limited — should still be collected as normal
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`, ts(nowHour.Add(-47*time.Minute))),
		// 403 policy engine block — via policy_action=honeypot, lowercase headers
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/2.0","method":"GET","host":"radarr.erfi.io","uri":"/wp-admin","headers":{"User-Agent":["BadBot/1.0"]}},"resp_headers":{"x-blocked-by":["policy-engine"],"x-blocked-rule":["Honeypot WP"]},"policy_action":"honeypot","policy_rule":"Honeypot WP","status":403,"size":0,"duration":0.001}`, ts(nowHour.Add(-46*time.Minute))),
		// 403 without X-Blocked-By — should be ignored
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.4","client_ip":"10.0.0.4","proto":"HTTP/1.1","method":"GET","host":"radarr.erfi.io","uri":"/.env","headers":{"User-Agent":["Scanner/2.0"]}},"resp_headers":{},"status":403,"size":0,"duration":0.002}`, ts(nowHour.Add(-45*time.Minute))),
	}
}()

func TestAccessLogStoreLoadsPolicyEvents(t *testing.T) {
	path := writeTempAccessLog(t, samplePolicyAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	// 3 policy blocks + 1 rate-limited (429) = 4 total.
	// The 200 OK and bare 403 are ignored.
	if got := store.EventCount(); got != 4 {
		t.Fatalf("expected 4 events (3 policy + 1 RL), got %d", got)
	}
}

func TestPolicyEventSource(t *testing.T) {
	path := writeTempAccessLog(t, samplePolicyAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	events := store.SnapshotAsEvents(0, nil)
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	var policyCount, rlCount int
	for _, ev := range events {
		switch ev.EventType {
		case "policy_block":
			policyCount++
		case "rate_limited":
			rlCount++
		}
	}
	if policyCount != 3 {
		t.Errorf("expected 3 policy_block events, got %d", policyCount)
	}
	if rlCount != 1 {
		t.Errorf("expected 1 rate_limited event, got %d", rlCount)
	}
}

func TestPolicyEventRuleMsg(t *testing.T) {
	path := writeTempAccessLog(t, samplePolicyAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	events := store.SnapshotAsEvents(0, nil)
	var withRuleMsg, withoutRuleMsg int
	for _, ev := range events {
		if ev.EventType == "policy_block" {
			if strings.HasPrefix(ev.RuleMsg, "Policy Block: ") {
				withRuleMsg++
			} else if ev.RuleMsg == "" {
				withoutRuleMsg++
			}
		}
	}
	// 2 events have policy_rule field (Honeypot Paths, Honeypot WP), 1 has only header (no rule name)
	if withRuleMsg != 2 {
		t.Errorf("expected 2 policy events with rule msg, got %d", withRuleMsg)
	}
	if withoutRuleMsg != 1 {
		t.Errorf("expected 1 policy event without rule msg, got %d", withoutRuleMsg)
	}
}

func TestPolicyEventsWithExclusionTagEnrichment(t *testing.T) {
	// Create an exclusion store with a rule that matches the policy event name.
	es := newTestExclusionStore(t)
	exc := RuleExclusion{
		Name:    "Honeypot Paths",
		Type:    "block",
		Enabled: true,
		Tags:    []string{"honeypot"},
		Conditions: []Condition{
			{Field: "path", Operator: "in", Value: "/.env|/.git"},
		},
	}
	es.Create(exc)

	path := writeTempAccessLog(t, samplePolicyAccessLogLines)
	store := NewAccessLogStore(path)
	store.SetExclusionStore(es)
	store.Load()

	events := store.SnapshotAsEvents(0, nil)
	var enrichedCount int
	for _, ev := range events {
		if ev.EventType == "policy_block" && ev.RuleMsg == "Policy Block: Honeypot Paths" {
			// Should have been enriched with "honeypot" tag from exclusion store.
			for _, tag := range ev.Tags {
				if tag == "honeypot" {
					enrichedCount++
				}
			}
		}
	}
	if enrichedCount != 1 {
		t.Errorf("expected 1 policy event enriched with honeypot tag, got %d", enrichedCount)
	}
}

func TestEnrichAccessEvents_PolicyTagLookup(t *testing.T) {
	now := time.Now().UTC()
	rlEvents := []RateLimitEvent{
		{Timestamp: now, ClientIP: "1.2.3.4", Source: "policy", RuleName: "Scanner UA Block"},
		{Timestamp: now, ClientIP: "5.6.7.8", Source: "policy", RuleName: "Unknown Rule"},
		{Timestamp: now, ClientIP: "9.0.1.2", Source: ""},
	}
	exclusions := []RuleExclusion{
		{Name: "Scanner UA Block", Tags: []string{"scanner", "bot-detection"}},
		{Name: "Other Rule", Tags: []string{"other"}},
	}

	events := enrichAccessEvents(rlEvents, nil, exclusions)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// First event: matches "Scanner UA Block" exclusion, should get scanner + bot-detection tags.
	if events[0].EventType != "policy_block" {
		t.Errorf("events[0] type: want policy_block, got %s", events[0].EventType)
	}
	if len(events[0].Tags) != 2 || events[0].Tags[0] != "scanner" || events[0].Tags[1] != "bot-detection" {
		t.Errorf("events[0] tags: want [scanner bot-detection], got %v", events[0].Tags)
	}

	// Second event: no matching exclusion, should have no tags.
	if events[1].EventType != "policy_block" {
		t.Errorf("events[1] type: want policy_block, got %s", events[1].EventType)
	}
	if len(events[1].Tags) != 0 {
		t.Errorf("events[1] tags: want empty (no matching exclusion), got %v", events[1].Tags)
	}

	// Third event: rate limited (no source), should be rate_limited.
	if events[2].EventType != "rate_limited" {
		t.Errorf("events[2] type: want rate_limited, got %s", events[2].EventType)
	}
}

// ─── Policy Engine Rate Limit Detection Tests ───────────────────────

func TestIsPolicyRateLimit(t *testing.T) {
	tests := []struct {
		name  string
		entry AccessLogEntry
		want  bool
	}{
		{"policy_action=rate_limit", AccessLogEntry{PolicyAction: "rate_limit"}, true},
		{"policy_action=block (not RL)", AccessLogEntry{PolicyAction: "block"}, false},
		{"policy_action=allow (not RL)", AccessLogEntry{PolicyAction: "allow"}, false},
		{"policy_action empty, X-RateLimit-Policy header", AccessLogEntry{RespHeaders: map[string][]string{"X-RateLimit-Policy": {`10;w=1m;name="api-rl"`}}}, true},
		{"policy_action empty, lowercase header (HTTP/2)", AccessLogEntry{RespHeaders: map[string][]string{"x-ratelimit-policy": {`10;w=1m;name="api-rl"`}}}, true},
		{"neither", AccessLogEntry{RespHeaders: map[string][]string{}}, false},
		{"nil headers", AccessLogEntry{}, false},
		{"policy_action=rate_limit_monitor (not blocked)", AccessLogEntry{PolicyAction: "rate_limit_monitor"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPolicyRateLimit(tt.entry); got != tt.want {
				t.Errorf("isPolicyRateLimit() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyRateLimitRuleName(t *testing.T) {
	tests := []struct {
		name  string
		entry AccessLogEntry
		want  string
	}{
		{"policy_rule field", AccessLogEntry{PolicyRule: "api-rate-limit"}, "api-rate-limit"},
		{"header with name", AccessLogEntry{RespHeaders: map[string][]string{"X-RateLimit-Policy": {`10;w=1m;name="api-rate-limit"`}}}, "api-rate-limit"},
		{"header lowercase (HTTP/2)", AccessLogEntry{RespHeaders: map[string][]string{"x-ratelimit-policy": {`50;w=5m;name="brute-force"`}}}, "brute-force"},
		{"policy_rule takes precedence over header", AccessLogEntry{PolicyRule: "from-var", RespHeaders: map[string][]string{"X-RateLimit-Policy": {`10;w=1m;name="from-header"`}}}, "from-var"},
		{"no field no header", AccessLogEntry{}, ""},
		{"header without name field", AccessLogEntry{RespHeaders: map[string][]string{"X-RateLimit-Policy": {"10"}}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policyRateLimitRuleName(tt.entry); got != tt.want {
				t.Errorf("policyRateLimitRuleName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimitEventToEvent_PolicyRL(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC),
		ClientIP:  "10.0.0.50",
		Service:   "api.erfi.io",
		Method:    "POST",
		URI:       "/api/v1/login",
		UserAgent: "curl/8.0",
		Source:    "policy_rl",
		RuleName:  "login-rate-limit",
	}

	ev := RateLimitEventToEvent(rle, []string{"auth", "brute-force"})

	if ev.EventType != "rate_limited" {
		t.Errorf("event_type: want rate_limited, got %s", ev.EventType)
	}
	if ev.ResponseStatus != 429 {
		t.Errorf("response_status: want 429, got %d", ev.ResponseStatus)
	}
	if !ev.IsBlocked {
		t.Error("policy_rl events should have is_blocked=true")
	}
	if ev.RuleMsg != "Rate Limited: login-rate-limit" {
		t.Errorf("rule_msg: want 'Rate Limited: login-rate-limit', got %q", ev.RuleMsg)
	}
	if len(ev.Tags) != 2 || ev.Tags[0] != "auth" || ev.Tags[1] != "brute-force" {
		t.Errorf("tags: want [auth brute-force], got %v", ev.Tags)
	}
}

func TestRateLimitEventToEvent_PolicyRLNoRuleName(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC),
		ClientIP:  "10.0.0.50",
		Service:   "api.erfi.io",
		Method:    "GET",
		URI:       "/",
		Source:    "policy_rl",
	}

	ev := RateLimitEventToEvent(rle, nil)

	if ev.EventType != "rate_limited" {
		t.Errorf("event_type: want rate_limited, got %s", ev.EventType)
	}
	if ev.ResponseStatus != 429 {
		t.Errorf("response_status: want 429, got %d", ev.ResponseStatus)
	}
	if ev.RuleMsg != "" {
		t.Errorf("rule_msg: want empty when no rule name, got %q", ev.RuleMsg)
	}
}

func TestEnrichAccessEvents_PolicyRLTagLookup(t *testing.T) {
	now := time.Now().UTC()
	rlEvents := []RateLimitEvent{
		{Timestamp: now, ClientIP: "1.2.3.4", Source: "policy_rl", RuleName: "api-rate-limit"},
		{Timestamp: now, ClientIP: "5.6.7.8", Source: "policy_rl", RuleName: "unknown-rule"},
		{Timestamp: now, ClientIP: "9.0.1.2", Source: "policy", RuleName: "Honeypot Paths"},
		{Timestamp: now, ClientIP: "3.4.5.6", Source: ""},
	}
	rules := []RateLimitRule{
		{Name: "api-rate-limit", Tags: []string{"api", "throttle"}, Enabled: true, Service: "*"},
	}
	exclusions := []RuleExclusion{
		{Name: "Honeypot Paths", Tags: []string{"honeypot"}},
	}

	events := enrichAccessEvents(rlEvents, rules, exclusions)
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	// First: policy_rl with matching rule → gets RL rule tags.
	if events[0].EventType != "rate_limited" {
		t.Errorf("events[0] type: want rate_limited, got %s", events[0].EventType)
	}
	if len(events[0].Tags) != 2 || events[0].Tags[0] != "api" || events[0].Tags[1] != "throttle" {
		t.Errorf("events[0] tags: want [api throttle], got %v", events[0].Tags)
	}
	if events[0].RuleMsg != "Rate Limited: api-rate-limit" {
		t.Errorf("events[0] rule_msg: want 'Rate Limited: api-rate-limit', got %q", events[0].RuleMsg)
	}

	// Second: policy_rl with unknown rule name → no tags.
	if events[1].EventType != "rate_limited" {
		t.Errorf("events[1] type: want rate_limited, got %s", events[1].EventType)
	}
	if len(events[1].Tags) != 0 {
		t.Errorf("events[1] tags: want empty, got %v", events[1].Tags)
	}

	// Third: policy block → uses exclusion tag lookup.
	if events[2].EventType != "policy_block" {
		t.Errorf("events[2] type: want policy_block, got %s", events[2].EventType)
	}
	if len(events[2].Tags) != 1 || events[2].Tags[0] != "honeypot" {
		t.Errorf("events[2] tags: want [honeypot], got %v", events[2].Tags)
	}

	// Fourth: legacy RL (no source) → heuristic matching (no rules match here).
	if events[3].EventType != "rate_limited" {
		t.Errorf("events[3] type: want rate_limited, got %s", events[3].EventType)
	}
}

// samplePolicyRLAccessLogLines contains policy engine rate limit events in access log format.
var samplePolicyRLAccessLogLines = func() []string {
	nowHour := time.Now().Truncate(time.Hour)
	ts := func(t time.Time) string { return t.UTC().Format("2006/01/02 15:04:05") }
	return []string{
		// 429 from policy engine — detected via policy_action field
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.50","client_ip":"10.0.0.50","proto":"HTTP/2.0","method":"POST","host":"api.erfi.io","uri":"/api/v1/login","headers":{"User-Agent":["curl/8.0"]}},"resp_headers":{"X-RateLimit-Limit":["10"],"X-RateLimit-Remaining":["0"],"X-RateLimit-Policy":["10;w=1m;name=\"login-rl\""]},"policy_action":"rate_limit","policy_rule":"login-rl","status":429,"size":0,"duration":0.001}`, ts(nowHour.Add(-50*time.Minute))),
		// 429 from policy engine — detected via X-RateLimit-Policy header only (no log_append fields)
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.51","client_ip":"10.0.0.51","proto":"HTTP/1.1","method":"GET","host":"api.erfi.io","uri":"/api/v1/search","headers":{"User-Agent":["Bot/1.0"]}},"resp_headers":{"x-ratelimit-policy":["50;w=5m;name=\"search-rl\""]},"status":429,"size":0,"duration":0.001}`, ts(nowHour.Add(-49*time.Minute))),
		// 429 from legacy caddy-ratelimit (no policy_action, no X-RateLimit-Policy)
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.52","client_ip":"10.0.0.52","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["Sonarr/4.0"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`, ts(nowHour.Add(-48*time.Minute))),
		// 403 policy engine block — should be classified as policy block, not RL
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.53","client_ip":"10.0.0.53","proto":"HTTP/1.1","method":"GET","host":"sonarr.erfi.io","uri":"/.env","headers":{"User-Agent":["Scanner/1.0"]}},"resp_headers":{},"policy_action":"block","policy_rule":"Honeypot Paths","status":403,"size":0,"duration":0.001}`, ts(nowHour.Add(-47*time.Minute))),
		// 200 OK — should be ignored
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/","headers":{"User-Agent":["Chrome/120"]}},"resp_headers":{},"status":200,"size":5000,"duration":0.05}`, ts(nowHour.Add(-46*time.Minute))),
	}
}()

func TestAccessLogStoreLoadsPolicyRLEvents(t *testing.T) {
	path := writeTempAccessLog(t, samplePolicyRLAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	// 2 policy RL (429) + 1 legacy RL (429) + 1 policy block (403) = 4 events.
	if got := store.EventCount(); got != 4 {
		t.Fatalf("expected 4 events, got %d", got)
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	// Verify classification of each event.
	var policyRL, legacyRL, policyBlock int
	for _, ev := range store.events {
		switch ev.Source {
		case "policy_rl":
			policyRL++
		case "policy":
			policyBlock++
		case "":
			legacyRL++
		}
	}
	if policyRL != 2 {
		t.Errorf("expected 2 policy_rl events, got %d", policyRL)
	}
	if legacyRL != 1 {
		t.Errorf("expected 1 legacy RL event, got %d", legacyRL)
	}
	if policyBlock != 1 {
		t.Errorf("expected 1 policy block event, got %d", policyBlock)
	}
}

func TestPolicyRLEventRuleName(t *testing.T) {
	path := writeTempAccessLog(t, samplePolicyRLAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	store.mu.RLock()
	defer store.mu.RUnlock()

	// Collect policy_rl events and verify rule names.
	var ruleNames []string
	for _, ev := range store.events {
		if ev.Source == "policy_rl" {
			ruleNames = append(ruleNames, ev.RuleName)
		}
	}
	if len(ruleNames) != 2 {
		t.Fatalf("expected 2 policy_rl events, got %d", len(ruleNames))
	}
	// First: detected via policy_rule log_append field.
	if ruleNames[0] != "login-rl" {
		t.Errorf("ruleNames[0]: want 'login-rl', got %q", ruleNames[0])
	}
	// Second: detected via X-RateLimit-Policy header name extraction.
	if ruleNames[1] != "search-rl" {
		t.Errorf("ruleNames[1]: want 'search-rl', got %q", ruleNames[1])
	}
}

func TestPolicyRLEventsAsUnifiedEvents(t *testing.T) {
	path := writeTempAccessLog(t, samplePolicyRLAccessLogLines)
	store := NewAccessLogStore(path)
	store.Load()

	rules := []RateLimitRule{
		{Name: "login-rl", Tags: []string{"auth", "brute-force"}, Enabled: true, Service: "*"},
	}
	events := store.SnapshotAsEvents(0, rules)

	// 4 total events (2 policy_rl + 1 legacy RL + 1 policy block).
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	var rateLimited, policyBlock int
	var loginRLEvent *Event
	for i, ev := range events {
		switch ev.EventType {
		case "rate_limited":
			rateLimited++
			if ev.RuleMsg == "Rate Limited: login-rl" {
				loginRLEvent = &events[i]
			}
		case "policy_block":
			policyBlock++
		}
	}
	if rateLimited != 3 {
		t.Errorf("expected 3 rate_limited events (2 policy_rl + 1 legacy), got %d", rateLimited)
	}
	if policyBlock != 1 {
		t.Errorf("expected 1 policy_block event, got %d", policyBlock)
	}
	// login-rl event should have been enriched with tags from the rule.
	if loginRLEvent == nil {
		t.Fatal("expected a login-rl rate_limited event with RuleMsg")
	}
	if len(loginRLEvent.Tags) != 2 || loginRLEvent.Tags[0] != "auth" || loginRLEvent.Tags[1] != "brute-force" {
		t.Errorf("login-rl tags: want [auth brute-force], got %v", loginRLEvent.Tags)
	}
}

func TestSummaryMergesPolicyEvents(t *testing.T) {
	wafStore := emptyWAFStore(t)

	alsPath := writeTempAccessLog(t, samplePolicyAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()
	handleSummary(wafStore, als, emptyRLRuleStore(t))(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp SummaryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// 0 WAF events + 3 policy_block + 1 RL(429) = 4 total.
	if resp.TotalEvents != 4 {
		t.Errorf("total_events: want 4 (0 WAF + 3 policy + 1 RL), got %d", resp.TotalEvents)
	}
	// rate_limited = 1 RL only (ipsum blocks are now policy_block).
	if resp.RateLimited != 1 {
		t.Errorf("rate_limited: want 1, got %d", resp.RateLimited)
	}
}

func TestEventsPolicyBlockFilter(t *testing.T) {
	wafStore := emptyWAFStore(t)

	alsPath := writeTempAccessLog(t, samplePolicyAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/events?event_type=policy_block&limit=100", nil)
	w := httptest.NewRecorder()
	handleEvents(wafStore, als, emptyRLRuleStore(t))(w, req)

	var resp EventsResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Total != 3 {
		t.Errorf("policy_block filter: want 3, got %d", resp.Total)
	}
	for _, ev := range resp.Events {
		if ev.EventType != "policy_block" {
			t.Errorf("event %s has type %s, want policy_block", ev.ID, ev.EventType)
		}
	}
}

func TestSummaryMergesPolicyBlockEvents(t *testing.T) {
	store := emptyWAFStore(t)

	alsPath := writeTempAccessLog(t, sampleIpsumAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()
	handleSummary(store, als, emptyRLRuleStore(t))(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp SummaryResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// 0 WAF events + 1 RL(429) + 2 policy_block = 3 total.
	if resp.TotalEvents != 3 {
		t.Errorf("total_events: want 3 (0 WAF + 1 RL + 2 policy_block), got %d", resp.TotalEvents)
	}
	// Only 1 rate_limited (the actual 429).
	if resp.RateLimited != 1 {
		t.Errorf("rate_limited: want 1, got %d", resp.RateLimited)
	}
	if resp.TotalBlocked != 0 {
		t.Errorf("total_blocked: want 0 (empty WAF store), got %d", resp.TotalBlocked)
	}
}

func TestEventsRateLimitedFilterExcludesPolicyBlocks(t *testing.T) {
	store := emptyWAFStore(t)

	alsPath := writeTempAccessLog(t, sampleIpsumAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	// Filtering by rate_limited should only get the actual 429 event,
	// not the policy_block events (which are now separate).
	req := httptest.NewRequest("GET", "/api/events?event_type=rate_limited&limit=100", nil)
	w := httptest.NewRecorder()
	handleEvents(store, als, emptyRLRuleStore(t))(w, req)

	var resp EventsResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Total != 1 {
		t.Errorf("rate_limited filter: want 1 (only 429), got %d", resp.Total)
	}
	for _, ev := range resp.Events {
		if ev.EventType != "rate_limited" {
			t.Errorf("event %s has type %s, want rate_limited", ev.ID, ev.EventType)
		}
	}
}

func TestServicesMergesPolicyBlockCounts(t *testing.T) {
	store := emptyWAFStore(t)

	alsPath := writeTempAccessLog(t, sampleIpsumAccessLogLines)
	als := NewAccessLogStore(alsPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/services", nil)
	w := httptest.NewRecorder()
	handleServices(store, als, emptyRLRuleStore(t))(w, req)

	var resp ServicesResponse
	json.NewDecoder(w.Body).Decode(&resp)

	svcMap := make(map[string]ServiceDetail)
	for _, s := range resp.Services {
		svcMap[s.Service] = s
	}

	// Policy blocks are now separate from rate_limited.
	// radarr: 2 WAF + 1 policy_block = 3 total, 0 RateLimited
	radarr := svcMap["radarr.erfi.io"]
	if radarr.RateLimited != 0 {
		t.Errorf("radarr rate_limited: want 0, got %d", radarr.RateLimited)
	}

	// sonarr: 1 RL(429) + 1 policy_block = 2 access events, 1 RateLimited
	sonarr := svcMap["sonarr.erfi.io"]
	if sonarr.RateLimited != 1 {
		t.Errorf("sonarr rate_limited: want 1, got %d", sonarr.RateLimited)
	}
}

// ─── Blocklist tests ────────────────────────────────────────────────

// ─── Client count merging tests ─────────────────────────────────────

func TestSummaryMergesClientCounts(t *testing.T) {
	// WAF store with events from 10.0.0.1
	store := emptyWAFStore(t)

	// Access log with RL + policy engine block events
	accessLines := []string{
		`{"level":"info","ts":"2026/02/22 07:30:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"radarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`,
		`{"level":"info","ts":"2026/02/22 07:31:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"radarr.erfi.io","uri":"/test","headers":{"User-Agent":["BadBot/1.0"]}},"resp_headers":{"x-blocked-by":["policy-engine"]},"policy_action":"block","status":403,"size":0,"duration":0.001}`,
		`{"level":"info","ts":"2026/02/22 07:32:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"99.99.99.99","client_ip":"99.99.99.99","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`,
	}
	accessPath := writeTempAccessLog(t, accessLines)
	als := NewAccessLogStore(accessPath)
	als.Load()

	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()
	handleSummary(store, als, emptyRLRuleStore(t))(w, req)

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

	// 10.0.0.1 should have WAF blocked + RL + policy_block counts merged.
	// The policy engine block is separate from rate_limited.
	c1 := clientMap["10.0.0.1"]
	if c1.RateLimited != 1 {
		t.Errorf("10.0.0.1 rate_limited: want 1 (only the 429), got %d", c1.RateLimited)
	}

	// 99.99.99.99 should have only RL count
	c2 := clientMap["99.99.99.99"]
	if c2.RateLimited != 1 {
		t.Errorf("99.99.99.99 rate_limited: want 1, got %d", c2.RateLimited)
	}
}

func TestSummarizeEvents_PolicyBlockAndRateLimitedCounts(t *testing.T) {
	// Old honeypot/scanner events are now policy_block; ipsum is rate_limited.
	events := []Event{
		{ID: "1", EventType: "detect_block", IsBlocked: true},
		{ID: "2", EventType: "policy_block", IsBlocked: true, Tags: []string{"honeypot"}},
		{ID: "3", EventType: "policy_block", IsBlocked: true, Tags: []string{"honeypot"}},
		{ID: "4", EventType: "policy_block", IsBlocked: true, Tags: []string{"scanner", "bot-detection"}},
		{ID: "5", EventType: "logged", IsBlocked: false},
		{ID: "6", EventType: "policy_skip", IsBlocked: false},
	}
	summary := summarizeEvents(events)

	// policy_block events count toward both PolicyEvents and TotalBlocked.
	// TotalBlocked: detect_block(1, IsBlocked) + policy_block(3, IsBlocked) = 4
	if summary.TotalBlocked != 4 {
		t.Errorf("TotalBlocked = %d, want 4", summary.TotalBlocked)
	}
	if summary.LoggedEvents != 1 {
		t.Errorf("LoggedEvents = %d, want 1", summary.LoggedEvents)
	}
}

// ─── GeoIP Tests ─────────────────────────────────────────────────────────────

// ─── Per-Hour/Service/Client Breakdown Tests ─────────────────────────────────

func TestSummarizeEvents_PerHourBreakdown(t *testing.T) {
	ts := time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{ID: "1", Timestamp: ts, Service: "a.io", ClientIP: "1.1.1.1", EventType: "detect_block", IsBlocked: true},
		{ID: "2", Timestamp: ts, Service: "a.io", ClientIP: "1.1.1.1", EventType: "policy_block", IsBlocked: true, Tags: []string{"honeypot"}},
		{ID: "3", Timestamp: ts, Service: "a.io", ClientIP: "2.2.2.2", EventType: "policy_block", IsBlocked: true, Tags: []string{"scanner", "bot-detection"}},
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
	// TotalBlocked = ALL events with IsBlocked=true: detect_block(1) + policy_block(3) = 4.
	if h.TotalBlocked != 4 {
		t.Errorf("hour.TotalBlocked = %d, want 4", h.TotalBlocked)
	}
	if h.DetectBlock != 1 {
		t.Errorf("hour.DetectBlock = %d, want 1", h.DetectBlock)
	}
	// Logged = total - totalBlocked - rateLimited - policyAllow - policySkip = 6 - 4 - 0 - 0 - 1 = 1
	if h.Logged != 1 {
		t.Errorf("hour.Logged = %d, want 1", h.Logged)
	}
	// PolicyBlock = policy_block(3)
	if h.PolicyBlock != 3 {
		t.Errorf("hour.PolicyBlock = %d, want 3", h.PolicyBlock)
	}
	// PolicySkip = policy_skip(1)
	if h.PolicySkip != 1 {
		t.Errorf("hour.PolicySkip = %d, want 1", h.PolicySkip)
	}
	// PolicyAllow = 0
	if h.PolicyAllow != 0 {
		t.Errorf("hour.PolicyAllow = %d, want 0", h.PolicyAllow)
	}
}

func TestSummarizeEvents_PerServiceBreakdown(t *testing.T) {
	ts := time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{ID: "1", Timestamp: ts, Service: "svc1.io", ClientIP: "1.1.1.1", EventType: "policy_block", IsBlocked: true, Tags: []string{"honeypot"}},
		{ID: "2", Timestamp: ts, Service: "svc1.io", ClientIP: "1.1.1.1", EventType: "policy_block", IsBlocked: true, Tags: []string{"scanner", "bot-detection"}},
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
	// svc1: policy_block(2)
	if svc1.PolicyBlock != 2 {
		t.Errorf("svc1.PolicyBlock = %d, want 2", svc1.PolicyBlock)
	}
	// svc1: policy_allow(1)
	if svc1.PolicyAllow != 1 {
		t.Errorf("svc1.PolicyAllow = %d, want 1", svc1.PolicyAllow)
	}
	// svc1: policy_skip(0)
	if svc1.PolicySkip != 0 {
		t.Errorf("svc1.PolicySkip = %d, want 0", svc1.PolicySkip)
	}
	// svc1: TotalBlocked = ALL IsBlocked events: policy_block(2) = 2
	if svc1.TotalBlocked != 2 {
		t.Errorf("svc1.TotalBlocked = %d, want 2", svc1.TotalBlocked)
	}
	// svc2: policy_block(1)
	if svc2.PolicyBlock != 1 {
		t.Errorf("svc2.PolicyBlock = %d, want 1", svc2.PolicyBlock)
	}
}

func TestSummarizeEvents_PerClientBreakdown(t *testing.T) {
	ts := time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{ID: "1", Timestamp: ts, Service: "a.io", ClientIP: "10.0.0.1", EventType: "policy_block", IsBlocked: true, Tags: []string{"honeypot"}},
		{ID: "2", Timestamp: ts, Service: "a.io", ClientIP: "10.0.0.1", EventType: "policy_block", IsBlocked: true, Tags: []string{"scanner", "bot-detection"}},
		{ID: "3", Timestamp: ts, Service: "a.io", ClientIP: "10.0.0.1", EventType: "policy_skip", IsBlocked: false},
		{ID: "4", Timestamp: ts, Service: "a.io", ClientIP: "10.0.0.2", EventType: "detect_block", IsBlocked: true},
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
	// policy_block(2)
	if c1.PolicyBlock != 2 {
		t.Errorf("client.PolicyBlock = %d, want 2", c1.PolicyBlock)
	}
	// policy_skip(1)
	if c1.PolicySkip != 1 {
		t.Errorf("client.PolicySkip = %d, want 1", c1.PolicySkip)
	}
	// policy_allow(0)
	if c1.PolicyAllow != 0 {
		t.Errorf("client.PolicyAllow = %d, want 0", c1.PolicyAllow)
	}
	if c1.Count != 3 {
		t.Errorf("client.Count = %d, want 3", c1.Count)
	}
	// TotalBlocked = ALL IsBlocked events: policy_block(2) = 2
	if c1.TotalBlocked != 2 {
		t.Errorf("client.TotalBlocked = %d, want 2", c1.TotalBlocked)
	}
}

func TestComputeServices_TracksAllEventTypes(t *testing.T) {
	events := []Event{
		{Service: "web.io", EventType: "detect_block", IsBlocked: true},
		{Service: "web.io", EventType: "policy_block", IsBlocked: true, Tags: []string{"honeypot"}},
		{Service: "web.io", EventType: "policy_block", IsBlocked: true, Tags: []string{"scanner", "bot-detection"}},
		{Service: "web.io", EventType: "policy_skip", IsBlocked: false},
		{Service: "web.io", EventType: "policy_block", IsBlocked: true},
		{Service: "web.io", EventType: "logged", IsBlocked: false},
		{Service: "api.io", EventType: "policy_block", IsBlocked: true, Tags: []string{"honeypot"}},
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
	// Blocked = all IsBlocked=true events: blocked(1) + policy_block(3) = 4
	if web.TotalBlocked != 4 {
		t.Errorf("web.TotalBlocked = %d, want 4", web.TotalBlocked)
	}
	// Logged = Total - Blocked = 6 - 4 = 2
	if web.Logged != 2 {
		t.Errorf("web.Logged = %d, want 2", web.Logged)
	}
	// PolicyBlock = policy_block(3)
	if web.PolicyBlock != 3 {
		t.Errorf("web.PolicyBlock = %d, want 3", web.PolicyBlock)
	}
	// PolicySkip = policy_skip(1)
	if web.PolicySkip != 1 {
		t.Errorf("web.PolicySkip = %d, want 1", web.PolicySkip)
	}
	// PolicyAllow = 0
	if web.PolicyAllow != 0 {
		t.Errorf("web.PolicyAllow = %d, want 0", web.PolicyAllow)
	}
	// api.io: 1 policy_block
	if api.PolicyBlock != 1 {
		t.Errorf("api.PolicyBlock = %d, want 1", api.PolicyBlock)
	}
	if api.TotalBlocked != 1 {
		t.Errorf("api.TotalBlocked = %d, want 1", api.TotalBlocked)
	}
}

func TestIPLookup_TracksAllEventTypes(t *testing.T) {
	s := NewStore()
	s.mu.Lock()
	s.events = []Event{
		{ID: "1", Timestamp: time.Now(), Service: "web.io", ClientIP: "10.0.0.1", EventType: "policy_block", IsBlocked: true, Tags: []string{"honeypot"}},
		{ID: "2", Timestamp: time.Now(), Service: "web.io", ClientIP: "10.0.0.1", EventType: "policy_block", IsBlocked: true, Tags: []string{"scanner", "bot-detection"}},
		{ID: "3", Timestamp: time.Now(), Service: "web.io", ClientIP: "10.0.0.1", EventType: "policy_allow", IsBlocked: false},
		{ID: "4", Timestamp: time.Now(), Service: "api.io", ClientIP: "10.0.0.1", EventType: "policy_block", IsBlocked: true},
		{ID: "5", Timestamp: time.Now(), Service: "web.io", ClientIP: "99.99.99.99", EventType: "detect_block", IsBlocked: true},
	}
	s.mu.Unlock()

	resp := s.IPLookup("10.0.0.1", 168, 50, 0, nil)

	if resp.Total != 4 {
		t.Errorf("Total = %d, want 4", resp.Total)
	}
	// Blocked = all IsBlocked=true: policy_block(3) = 3
	if resp.TotalBlocked != 3 {
		t.Errorf("Blocked = %d, want 3", resp.TotalBlocked)
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
	// web: policy_block(2)
	if web.PolicyBlock != 2 {
		t.Errorf("web.PolicyBlock = %d, want 2", web.PolicyBlock)
	}
	// web: policy_allow(1)
	if web.PolicyAllow != 1 {
		t.Errorf("web.PolicyAllow = %d, want 1", web.PolicyAllow)
	}
	// web: policy_skip(0)
	if web.PolicySkip != 0 {
		t.Errorf("web.PolicySkip = %d, want 0", web.PolicySkip)
	}
	if api.PolicyBlock != 1 { // policy_block
		t.Errorf("api.PolicyBlock = %d, want 1", api.PolicyBlock)
	}
}

// --- RequestID Extraction Tests ---

func TestSetEventFile_PreservesTagsAndTypes(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")

	events := []Event{
		{ID: "1", EventType: "policy_block", IsBlocked: true, Tags: []string{"honeypot"}, Timestamp: time.Now()},
		{ID: "2", EventType: "detect_block", IsBlocked: true, Timestamp: time.Now()},
		{ID: "3", EventType: "rate_limited", IsBlocked: true, Tags: []string{"blocklist", "ipsum"}, Timestamp: time.Now()},
	}
	f, _ := os.Create(eventPath)
	for _, ev := range events {
		data, _ := json.Marshal(ev)
		f.Write(data)
		f.Write([]byte{'\n'})
	}
	f.Close()

	store := &Store{events: nil, maxAge: 24 * time.Hour}
	store.SetEventFile(eventPath)

	restored := store.SnapshotSince(24)
	if len(restored) != 3 {
		t.Fatalf("expected 3 events, got %d", len(restored))
	}
	if restored[0].EventType != "policy_block" || len(restored[0].Tags) != 1 || restored[0].Tags[0] != "honeypot" {
		t.Errorf("event 1: got type=%q tags=%v", restored[0].EventType, restored[0].Tags)
	}
	if restored[1].EventType != "detect_block" || len(restored[1].Tags) != 0 {
		t.Errorf("event 2: got type=%q tags=%v", restored[1].EventType, restored[1].Tags)
	}
	if restored[2].EventType != "rate_limited" || len(restored[2].Tags) != 2 {
		t.Errorf("event 3: got type=%q tags=%v", restored[2].EventType, restored[2].Tags)
	}
}

func TestSummarizeEvents_TagCounts(t *testing.T) {
	ts := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{ID: "1", Timestamp: ts, Service: "a.io", EventType: "policy_block", IsBlocked: true, Tags: []string{"scanner", "bot-detection"}},
		{ID: "2", Timestamp: ts, Service: "a.io", EventType: "policy_block", IsBlocked: true, Tags: []string{"scanner"}},
		{ID: "3", Timestamp: ts, Service: "a.io", EventType: "detect_block", IsBlocked: true, Tags: []string{"honeypot"}},
		{ID: "4", Timestamp: ts, Service: "a.io", EventType: "logged"},
	}
	summary := summarizeEvents(events)

	if len(summary.TagCounts) != 3 {
		t.Fatalf("TagCounts length = %d, want 3, got %v", len(summary.TagCounts), summary.TagCounts)
	}
	// scanner=2, bot-detection=1, honeypot=1 — sorted count desc then alpha
	if summary.TagCounts[0].Tag != "scanner" || summary.TagCounts[0].Count != 2 {
		t.Errorf("TagCounts[0] = %+v, want {scanner 2}", summary.TagCounts[0])
	}
	if summary.TagCounts[1].Tag != "bot-detection" || summary.TagCounts[1].Count != 1 {
		t.Errorf("TagCounts[1] = %+v, want {bot-detection 1}", summary.TagCounts[1])
	}
	if summary.TagCounts[2].Tag != "honeypot" || summary.TagCounts[2].Count != 1 {
		t.Errorf("TagCounts[2] = %+v, want {honeypot 1}", summary.TagCounts[2])
	}
}

func TestSummarizeEvents_TagCountsEmpty(t *testing.T) {
	events := []Event{
		{ID: "1", EventType: "detect_block", IsBlocked: true},
		{ID: "2", EventType: "logged"},
	}
	summary := summarizeEvents(events)
	if len(summary.TagCounts) != 0 {
		t.Errorf("TagCounts should be empty for events without tags, got %v", summary.TagCounts)
	}
}

// --- Detect Block Match Details Tests ---

func TestParseDetectRulesDetail(t *testing.T) {
	// New format: rule IDs without PE- prefix.
	rules := parseDetectRulesDetail("920350:WARNING:3,941100:CRITICAL:5")
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Name != "920350" {
		t.Errorf("expected Name '920350', got %q", rules[0].Name)
	}
	if rules[0].ID != 920350 {
		t.Errorf("expected numeric ID 920350, got %d", rules[0].ID)
	}
	if rules[0].Msg != "920350 (WARNING, score 3)" {
		t.Errorf("expected msg '920350 (WARNING, score 3)', got %q", rules[0].Msg)
	}
	if rules[0].Severity != 4 { // WARNING = 4
		t.Errorf("expected severity 4 (WARNING), got %d", rules[0].Severity)
	}
	if rules[1].Name != "941100" {
		t.Errorf("expected Name '941100', got %q", rules[1].Name)
	}
	if rules[1].Msg != "941100 (CRITICAL, score 5)" {
		t.Errorf("expected msg '941100 (CRITICAL, score 5)', got %q", rules[1].Msg)
	}
	if rules[1].Severity != 2 { // CRITICAL = 2
		t.Errorf("expected severity 2 (CRITICAL), got %d", rules[1].Severity)
	}
}

func TestParseDetectRulesDetail_BackwardCompat(t *testing.T) {
	// Old format: PE- prefixed IDs should be stripped.
	rules := parseDetectRulesDetail("PE-920350:WARNING:3")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "920350" {
		t.Errorf("expected Name '920350' (PE- stripped), got %q", rules[0].Name)
	}
	if rules[0].ID != 920350 {
		t.Errorf("expected numeric ID 920350, got %d", rules[0].ID)
	}
}

func TestParseDetectRulesDetail_Empty(t *testing.T) {
	rules := parseDetectRulesDetail("")
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for empty string, got %d", len(rules))
	}
}

func TestEnrichMatchedRulesWithDetails(t *testing.T) {
	rules := []MatchedRule{
		{Name: "920350", Msg: "920350 (WARNING, score 3)", Severity: 4},
		{Name: "941100", Msg: "941100 (CRITICAL, score 5)", Severity: 2},
	}
	matchesJSON := `[
		{
			"rule_id": "920350",
			"rule_name": "Missing Host header",
			"severity": "WARNING",
			"score": 3,
			"matches": [
				{
					"field": "header",
					"var_name": "REQUEST_HEADERS:Host",
					"value": "",
					"operator": "eq"
				}
			]
		},
		{
			"rule_id": "941100",
			"rule_name": "XSS via User-Agent",
			"severity": "CRITICAL",
			"score": 5,
			"matches": [
				{
					"field": "user_agent",
					"var_name": "REQUEST_HEADERS:User-Agent",
					"value": "<script>alert(1)</script>",
					"matched_data": "<script>",
					"operator": "regex"
				}
			]
		}
	]`

	enrichMatchedRulesWithDetails(rules, matchesJSON)

	// First rule should have match details.
	if len(rules[0].Matches) != 1 {
		t.Fatalf("expected 1 match for rule 0, got %d", len(rules[0].Matches))
	}
	if rules[0].Matches[0].VarName != "REQUEST_HEADERS:Host" {
		t.Errorf("expected VarName 'REQUEST_HEADERS:Host', got %q", rules[0].Matches[0].VarName)
	}
	// First rule has empty value (missing Host header), so MatchedData stays empty.
	if rules[0].MatchedData != "" {
		t.Errorf("expected empty MatchedData for empty value match, got %q", rules[0].MatchedData)
	}

	// Second rule should have match details with matched_data.
	if len(rules[1].Matches) != 1 {
		t.Fatalf("expected 1 match for rule 1, got %d", len(rules[1].Matches))
	}
	if rules[1].Matches[0].MatchedData != "<script>" {
		t.Errorf("expected MatchedData '<script>', got %q", rules[1].Matches[0].MatchedData)
	}
	if rules[1].MatchedData != "REQUEST_HEADERS:User-Agent: <script>" {
		t.Errorf("expected enriched MatchedData, got %q", rules[1].MatchedData)
	}
}

func TestEnrichMatchedRulesWithDetails_BackwardCompat(t *testing.T) {
	// Old PE- prefixed rules should still match against PE- prefixed JSON entries.
	rules := []MatchedRule{
		{Name: "920350", Msg: "920350 (WARNING, score 3)", Severity: 4},
	}
	matchesJSON := `[{"rule_id": "PE-920350", "severity": "WARNING", "score": 3, "matches": [{"field": "header", "var_name": "REQUEST_HEADERS:Host", "operator": "eq"}]}]`
	enrichMatchedRulesWithDetails(rules, matchesJSON)
	if len(rules[0].Matches) != 1 {
		t.Fatalf("expected 1 match (backward compat PE- prefix), got %d", len(rules[0].Matches))
	}
}

func TestEnrichMatchedRulesWithDetails_InvalidJSON(t *testing.T) {
	rules := []MatchedRule{{Name: "920350", Msg: "920350 (WARNING, score 3)"}}
	// Should not panic, just log a warning.
	enrichMatchedRulesWithDetails(rules, "invalid json{{{")
	if len(rules[0].Matches) != 0 {
		t.Error("expected no matches after invalid JSON")
	}
}

func TestEnrichMatchedRulesWithDetails_Empty(t *testing.T) {
	rules := []MatchedRule{{Name: "920350", Msg: "920350 (WARNING, score 3)"}}
	enrichMatchedRulesWithDetails(rules, "")
	if len(rules[0].Matches) != 0 {
		t.Error("expected no matches for empty string")
	}
}

func TestRateLimitEventToEvent_DetectBlock(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp:     time.Now(),
		ClientIP:      "1.2.3.4",
		Service:       "test",
		Method:        "GET",
		URI:           "/admin",
		UserAgent:     "curl/7.88",
		Source:        "detect_block",
		RuleName:      "Detect Block (score 8/5, 2 rules)",
		AnomalyScore:  8,
		DetectRules:   "d1:CRITICAL:5,d2:WARNING:3",
		DetectMatches: `[{"rule_id":"d1","severity":"CRITICAL","score":5,"matches":[{"field":"user_agent","var_name":"REQUEST_HEADERS:User-Agent","value":"curl/7.88","matched_data":"curl","operator":"contains"}]},{"rule_id":"d2","severity":"WARNING","score":3,"matches":[{"field":"path","var_name":"REQUEST_URI","value":"/admin","matched_data":"/admin","operator":"contains"}]}]`,
	}

	evt := RateLimitEventToEvent(rle, nil)
	if evt.EventType != "detect_block" {
		t.Errorf("expected event_type 'detect_block', got %q", evt.EventType)
	}
	if evt.AnomalyScore != 8 {
		t.Errorf("expected anomaly_score 8, got %d", evt.AnomalyScore)
	}
	if len(evt.MatchedRules) != 2 {
		t.Fatalf("expected 2 matched rules, got %d", len(evt.MatchedRules))
	}

	// First rule should have enriched match details.
	r1 := evt.MatchedRules[0]
	if len(r1.Matches) != 1 {
		t.Fatalf("expected 1 match detail for rule 0, got %d", len(r1.Matches))
	}
	if r1.Matches[0].VarName != "REQUEST_HEADERS:User-Agent" {
		t.Errorf("expected VarName 'REQUEST_HEADERS:User-Agent', got %q", r1.Matches[0].VarName)
	}
	if r1.Matches[0].MatchedData != "curl" {
		t.Errorf("expected MatchedData 'curl', got %q", r1.Matches[0].MatchedData)
	}
	// MatchedData now uses CRS-compatible format for frontend parseMatchedData().
	wantMD := "Matched Data: curl found within REQUEST_HEADERS:User-Agent: curl/7.88"
	if r1.MatchedData != wantMD {
		t.Errorf("expected CRS-format MatchedData on rule, got %q", r1.MatchedData)
	}

	// Second rule.
	r2 := evt.MatchedRules[1]
	if len(r2.Matches) != 1 {
		t.Fatalf("expected 1 match detail for rule 1, got %d", len(r2.Matches))
	}
	if r2.Matches[0].VarName != "REQUEST_URI" {
		t.Errorf("expected VarName 'REQUEST_URI', got %q", r2.Matches[0].VarName)
	}

	// Top-level fields should be populated from the highest severity rule.
	if evt.BlockedBy != "anomaly_inbound" {
		t.Errorf("expected BlockedBy 'anomaly_inbound', got %q", evt.BlockedBy)
	}
	// Highest severity is CRITICAL (severity=2) — d1 rule.
	if evt.Severity != 2 {
		t.Errorf("expected top-level Severity 2 (CRITICAL), got %d", evt.Severity)
	}
	if evt.RuleMsg == "" {
		t.Error("expected top-level RuleMsg to be set")
	}
	if evt.MatchedData == "" {
		t.Error("expected top-level MatchedData to be set")
	}
}

func TestRateLimitEventToEvent_DetectBlock_NoMatches(t *testing.T) {
	// Older plugin versions don't emit detect_matches — should still work.
	rle := RateLimitEvent{
		Timestamp:    time.Now(),
		ClientIP:     "1.2.3.4",
		Service:      "test",
		Method:       "GET",
		URI:          "/admin",
		Source:       "detect_block",
		RuleName:     "Detect Block (score 5/3, 1 rules)",
		AnomalyScore: 5,
		DetectRules:  "d1:CRITICAL:5",
	}

	evt := RateLimitEventToEvent(rle, nil)
	if len(evt.MatchedRules) != 1 {
		t.Fatalf("expected 1 matched rule, got %d", len(evt.MatchedRules))
	}
	// No matches enrichment — Matches should be nil.
	if len(evt.MatchedRules[0].Matches) != 0 {
		t.Error("expected no matches without detect_matches JSON")
	}
}

// --- Request Context Propagation Tests ---

func TestRateLimitEventToEvent_RequestContext(t *testing.T) {
	hdrs := map[string][]string{
		"User-Agent":    {"Mozilla/5.0"},
		"Accept":        {"text/html"},
		"Authorization": {"Bearer secret"},
	}
	rle := RateLimitEvent{
		Timestamp:      time.Now(),
		ClientIP:       "10.0.0.1",
		Service:        "test.erfi.io",
		Method:         "POST",
		URI:            "/api/data",
		UserAgent:      "Mozilla/5.0",
		Source:         "policy",
		RuleName:       "Block Scanner",
		RequestID:      "caddy-uuid-reqctx",
		RequestHeaders: hdrs,
		RequestBody:    `{"action":"test"}`,
	}

	evt := RateLimitEventToEvent(rle, nil)

	// Headers should be propagated.
	if len(evt.RequestHeaders) != 3 {
		t.Errorf("expected 3 request headers, got %d", len(evt.RequestHeaders))
	}
	if evt.RequestHeaders["User-Agent"][0] != "Mozilla/5.0" {
		t.Errorf("User-Agent not propagated: %v", evt.RequestHeaders["User-Agent"])
	}
	// Body should be propagated.
	if evt.RequestBody != `{"action":"test"}` {
		t.Errorf("request_body not propagated: %q", evt.RequestBody)
	}
	// Unified request ID should match the Caddy UUID.
	if evt.ID != "caddy-uuid-reqctx" {
		t.Errorf("ID (unified request ID): want caddy-uuid-reqctx, got %q", evt.ID)
	}
}

func TestRateLimitEventToEvent_NoRequestContext(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Now(),
		ClientIP:  "10.0.0.1",
		Service:   "test.erfi.io",
		Method:    "GET",
		URI:       "/",
		UserAgent: "curl/7.68",
	}

	evt := RateLimitEventToEvent(rle, nil)

	if evt.RequestHeaders != nil {
		t.Errorf("expected nil request headers for events without context, got %v", evt.RequestHeaders)
	}
	if evt.RequestBody != "" {
		t.Errorf("expected empty request body, got %q", evt.RequestBody)
	}
}

func TestParsePolicyRequestHeaders(t *testing.T) {
	raw := `{"User-Agent":["Mozilla/5.0"],"Accept":["text/html"]}`
	hdrs := parsePolicyRequestHeaders(raw)
	if hdrs == nil {
		t.Fatal("expected non-nil headers")
	}
	if hdrs["User-Agent"][0] != "Mozilla/5.0" {
		t.Errorf("User-Agent: got %v", hdrs["User-Agent"])
	}
}

func TestParsePolicyRequestHeaders_Empty(t *testing.T) {
	if hdrs := parsePolicyRequestHeaders(""); hdrs != nil {
		t.Errorf("expected nil for empty input, got %v", hdrs)
	}
}

func TestParsePolicyRequestHeaders_InvalidJSON(t *testing.T) {
	if hdrs := parsePolicyRequestHeaders("{invalid"); hdrs != nil {
		t.Errorf("expected nil for invalid JSON, got %v", hdrs)
	}
}

// --- GeoIP Online API Fallback Tests ---
