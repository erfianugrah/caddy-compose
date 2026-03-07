package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── Test Data ──────────────────────────────────────────────────────

// sampleGeneralAccessLogLines generates realistic Caddy access log entries
// with various status codes, services, and security headers.
var sampleGeneralAccessLogLines = func() []string {
	now := time.Now()
	ts := func(offset time.Duration) string { return now.Add(offset).UTC().Format("2006/01/02 15:04:05") }
	return []string{
		// 200 OK with full security headers
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.svc1","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"app.example.com","uri":"/","headers":{"User-Agent":["Mozilla/5.0"],"Cf-Ipcountry":["US"]}},"resp_headers":{"Content-Security-Policy":["default-src 'self'"],"Strict-Transport-Security":["max-age=31536000"],"X-Content-Type-Options":["nosniff"],"X-Frame-Options":["DENY"],"Referrer-Policy":["strict-origin"]},"status":200,"size":5000,"duration":0.050}`, ts(-2*time.Hour)),
		// 200 OK missing CSP and HSTS
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.svc2","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"api.example.com","uri":"/v1/users","headers":{"User-Agent":["curl/8.0"],"Cf-Ipcountry":["DE"]}},"resp_headers":{"X-Content-Type-Options":["nosniff"],"Access-Control-Allow-Origin":["*"]},"status":200,"size":2000,"duration":0.020}`, ts(-90*time.Minute)),
		// 404 Not Found
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.svc1","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/1.1","method":"GET","host":"app.example.com","uri":"/nonexistent","headers":{"User-Agent":["Googlebot/2.1"],"Cf-Ipcountry":["US"]}},"resp_headers":{},"status":404,"size":100,"duration":0.005}`, ts(-60*time.Minute)),
		// 500 Internal Server Error
		fmt.Sprintf(`{"level":"error","ts":"%s","logger":"http.log.access.svc2","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"POST","host":"api.example.com","uri":"/v1/webhook","headers":{"User-Agent":["Mozilla/5.0"],"Cf-Ipcountry":["US"]}},"resp_headers":{},"status":500,"size":50,"duration":1.200}`, ts(-45*time.Minute)),
		// 502 Bad Gateway
		fmt.Sprintf(`{"level":"error","ts":"%s","logger":"http.log.access.svc1","msg":"handled request","request":{"remote_ip":"10.0.0.4","client_ip":"10.0.0.4","proto":"HTTP/2.0","method":"GET","host":"app.example.com","uri":"/api/data","headers":{"User-Agent":["Mozilla/5.0"],"Cf-Ipcountry":["JP"]}},"resp_headers":{},"status":502,"size":0,"duration":30.000}`, ts(-30*time.Minute)),
		// 301 Redirect
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.svc1","msg":"handled request","request":{"remote_ip":"10.0.0.5","client_ip":"10.0.0.5","proto":"HTTP/2.0","method":"GET","host":"app.example.com","uri":"/old-page","headers":{"User-Agent":["Mozilla/5.0"],"Cf-Ipcountry":["GB"]}},"resp_headers":{"Strict-Transport-Security":["max-age=31536000"]},"status":301,"size":0,"duration":0.001}`, ts(-15*time.Minute)),
		// 429 Rate Limited (also captured by general log store)
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.svc2","msg":"handled request","request":{"remote_ip":"10.0.0.6","client_ip":"10.0.0.6","proto":"HTTP/2.0","method":"GET","host":"api.example.com","uri":"/v1/search","headers":{"User-Agent":["BadBot/1.0"],"Cf-Ipcountry":["CN"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`, ts(-5*time.Minute)),
		// 200 with CORS and Permissions-Policy
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.svc2","msg":"handled request","request":{"remote_ip":"10.0.0.7","client_ip":"10.0.0.7","proto":"HTTP/2.0","method":"OPTIONS","host":"api.example.com","uri":"/v1/data","headers":{"User-Agent":["Mozilla/5.0"],"Cf-Ipcountry":["FR"]}},"resp_headers":{"Access-Control-Allow-Origin":["https://app.example.com"],"Permissions-Policy":["camera=(), microphone=()"]},"status":200,"size":0,"duration":0.001}`, ts(-2*time.Minute)),
	}
}()

func writeGeneralAccessLog(t *testing.T, lines []string) string {
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

// ─── Store Tests ────────────────────────────────────────────────────

func TestGeneralLogStore_Load(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	count := store.EventCount()
	if count != 8 {
		t.Errorf("expected 8 events, got %d", count)
	}
}

func TestGeneralLogStore_LoadAllStatusCodes(t *testing.T) {
	// Unlike AccessLogStore which only captures 429/ipsum, GeneralLogStore captures ALL
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	events := store.snapshotSince(0)
	statusCodes := make(map[int]int)
	for _, e := range events {
		statusCodes[e.Status]++
	}

	// Verify we captured all status codes, not just 429/403
	expected := map[int]int{200: 3, 301: 1, 404: 1, 429: 1, 500: 1, 502: 1}
	for code, wantCount := range expected {
		if got := statusCodes[code]; got != wantCount {
			t.Errorf("status %d: want %d, got %d", code, wantCount, got)
		}
	}
}

func TestGeneralLogStore_SecurityHeaders(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	events := store.snapshotSince(0)

	// First event should have full security headers
	first := events[0]
	if !first.SecurityHeaders.HasCSP {
		t.Error("first event should have CSP")
	}
	if first.SecurityHeaders.CSP != "default-src 'self'" {
		t.Errorf("CSP value wrong: got %q", first.SecurityHeaders.CSP)
	}
	if !first.SecurityHeaders.HasHSTS {
		t.Error("first event should have HSTS")
	}
	if !first.SecurityHeaders.HasXContentTypeOptions {
		t.Error("first event should have X-Content-Type-Options")
	}
	if !first.SecurityHeaders.HasXFrameOptions {
		t.Error("first event should have X-Frame-Options")
	}
	if !first.SecurityHeaders.HasReferrerPolicy {
		t.Error("first event should have Referrer-Policy")
	}
	if first.SecurityHeaders.HasCORSOrigin {
		t.Error("first event should NOT have CORS header")
	}

	// Second event: missing CSP, HSTS but has CORS
	second := events[1]
	if second.SecurityHeaders.HasCSP {
		t.Error("second event should NOT have CSP")
	}
	if second.SecurityHeaders.HasHSTS {
		t.Error("second event should NOT have HSTS")
	}
	if !second.SecurityHeaders.HasCORSOrigin {
		t.Error("second event should have CORS header")
	}
	if second.SecurityHeaders.CORSOrigin != "*" {
		t.Errorf("CORS value wrong: got %q", second.SecurityHeaders.CORSOrigin)
	}
}

func TestGeneralLogStore_FieldsParsed(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	events := store.snapshotSince(0)
	first := events[0]

	if first.ClientIP != "10.0.0.1" {
		t.Errorf("client_ip: got %q", first.ClientIP)
	}
	if first.Service != "app.example.com" {
		t.Errorf("service: got %q", first.Service)
	}
	if first.Method != "GET" {
		t.Errorf("method: got %q", first.Method)
	}
	if first.URI != "/" {
		t.Errorf("uri: got %q", first.URI)
	}
	if first.Protocol != "HTTP/2.0" {
		t.Errorf("protocol: got %q", first.Protocol)
	}
	if first.Status != 200 {
		t.Errorf("status: got %d", first.Status)
	}
	if first.Size != 5000 {
		t.Errorf("size: got %d", first.Size)
	}
	if first.Duration != 0.050 {
		t.Errorf("duration: got %f", first.Duration)
	}
	if first.UserAgent != "Mozilla/5.0" {
		t.Errorf("user_agent: got %q", first.UserAgent)
	}
	if first.Level != "info" {
		t.Errorf("level: got %q", first.Level)
	}
	if first.Logger != "http.log.access.svc1" {
		t.Errorf("logger: got %q", first.Logger)
	}
}

func TestGeneralLogStore_IncrementalLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")

	// Write first batch
	f, _ := os.Create(path)
	f.WriteString(sampleGeneralAccessLogLines[0] + "\n")
	f.WriteString(sampleGeneralAccessLogLines[1] + "\n")
	f.Close()

	store := NewGeneralLogStore(path)
	store.Load()
	if store.EventCount() != 2 {
		t.Fatalf("first load: expected 2, got %d", store.EventCount())
	}

	// Append more lines
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString(sampleGeneralAccessLogLines[2] + "\n")
	f.Close()

	store.Load()
	if store.EventCount() != 3 {
		t.Fatalf("second load: expected 3, got %d", store.EventCount())
	}
}

func TestGeneralLogStore_Eviction(t *testing.T) {
	now := time.Now()
	ts := func(offset time.Duration) string { return now.Add(offset).UTC().Format("2006/01/02 15:04:05") }

	lines := []string{
		// Old event — should be evicted with 1h max age
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"test","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"old.example.com","uri":"/","headers":{}},"resp_headers":{},"status":200,"size":100,"duration":0.01}`, ts(-3*time.Hour)),
		// Recent event — should survive
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"test","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"new.example.com","uri":"/","headers":{}},"resp_headers":{},"status":200,"size":100,"duration":0.01}`, ts(-10*time.Minute)),
	}

	path := writeGeneralAccessLog(t, lines)
	store := NewGeneralLogStore(path)
	store.SetMaxAge(1 * time.Hour)
	store.Load()

	if store.EventCount() != 1 {
		t.Errorf("expected 1 event after eviction, got %d", store.EventCount())
	}

	events := store.snapshotSince(0)
	if len(events) > 0 && events[0].Service != "new.example.com" {
		t.Errorf("wrong event survived: got service %q", events[0].Service)
	}
}

func TestGeneralLogStore_JSONLPersistence(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines[:3])
	dir := t.TempDir()
	eventFile := filepath.Join(dir, "general-events.jsonl")

	// Load and persist
	store := NewGeneralLogStore(path)
	store.SetEventFile(eventFile)
	store.Load()
	if store.EventCount() != 3 {
		t.Fatalf("expected 3 events, got %d", store.EventCount())
	}

	// Create new store, restore from JSONL
	store2 := NewGeneralLogStore(filepath.Join(dir, "nonexistent.log"))
	store2.SetEventFile(eventFile)
	if store2.EventCount() != 3 {
		t.Errorf("expected 3 restored events, got %d", store2.EventCount())
	}
}

func TestGeneralLogStore_OffsetPersistence(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines[:2])
	dir := t.TempDir()
	offsetFile := filepath.Join(dir, "offset")

	store := NewGeneralLogStore(path)
	store.SetOffsetFile(offsetFile)
	store.Load()
	if store.EventCount() != 2 {
		t.Fatalf("expected 2 events, got %d", store.EventCount())
	}

	// Verify offset file was written
	data, err := os.ReadFile(offsetFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("offset file should not be empty")
	}
}

func TestGeneralLogStore_RotationDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")

	// Write initial data
	f, _ := os.Create(path)
	f.WriteString(sampleGeneralAccessLogLines[0] + "\n")
	f.WriteString(sampleGeneralAccessLogLines[1] + "\n")
	f.Close()

	store := NewGeneralLogStore(path)
	store.Load()
	if store.EventCount() != 2 {
		t.Fatalf("expected 2 events, got %d", store.EventCount())
	}

	// Simulate rotation — truncate and write smaller data
	f, _ = os.Create(path)
	f.WriteString(sampleGeneralAccessLogLines[2] + "\n")
	f.Close()

	store.Load()
	// Should detect rotation and re-read from start, adding the new event
	if store.EventCount() != 3 {
		t.Errorf("expected 3 events after rotation, got %d", store.EventCount())
	}
}

func TestGeneralLogStore_Stats(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines[:2])
	store := NewGeneralLogStore(path)
	store.SetMaxAge(168 * time.Hour)
	store.Load()

	stats := store.Stats()
	if stats["events"] != 2 {
		t.Errorf("stats events: got %v", stats["events"])
	}
	if stats["log_file"] != path {
		t.Errorf("stats log_file: got %v", stats["log_file"])
	}
	if stats["max_age"] != "168h0m0s" {
		t.Errorf("stats max_age: got %v", stats["max_age"])
	}
}

func TestGeneralLogStore_SnapshotRange(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	now := time.Now().UTC()
	// Only get events from last 20 minutes
	start := now.Add(-20 * time.Minute)
	end := now

	events := store.snapshotRange(start, end)
	// Should only include events from -15m, -5m, -2m
	if len(events) != 3 {
		t.Errorf("expected 3 events in range, got %d", len(events))
	}
}

// ─── Security Header Extraction Tests ───────────────────────────────

func TestExtractSecurityHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		check   func(t *testing.T, info SecurityHeaderInfo)
	}{
		{
			name:    "empty headers",
			headers: map[string][]string{},
			check: func(t *testing.T, info SecurityHeaderInfo) {
				if info.HasCSP || info.HasHSTS || info.HasXContentTypeOptions {
					t.Error("all should be false for empty headers")
				}
			},
		},
		{
			name: "full security headers",
			headers: map[string][]string{
				"Content-Security-Policy":     {"default-src 'self'"},
				"Strict-Transport-Security":   {"max-age=31536000; includeSubDomains"},
				"X-Content-Type-Options":      {"nosniff"},
				"X-Frame-Options":             {"SAMEORIGIN"},
				"Referrer-Policy":             {"strict-origin-when-cross-origin"},
				"Access-Control-Allow-Origin": {"https://example.com"},
				"Permissions-Policy":          {"camera=()"},
			},
			check: func(t *testing.T, info SecurityHeaderInfo) {
				if !info.HasCSP || info.CSP != "default-src 'self'" {
					t.Errorf("CSP: has=%v val=%q", info.HasCSP, info.CSP)
				}
				if !info.HasHSTS || info.HSTS != "max-age=31536000; includeSubDomains" {
					t.Errorf("HSTS: has=%v val=%q", info.HasHSTS, info.HSTS)
				}
				if !info.HasXContentTypeOptions || info.XContentTypeOptions != "nosniff" {
					t.Errorf("XCTO: has=%v val=%q", info.HasXContentTypeOptions, info.XContentTypeOptions)
				}
				if !info.HasXFrameOptions || info.XFrameOptions != "SAMEORIGIN" {
					t.Errorf("XFO: has=%v val=%q", info.HasXFrameOptions, info.XFrameOptions)
				}
				if !info.HasReferrerPolicy {
					t.Error("Referrer-Policy should be present")
				}
				if !info.HasCORSOrigin || info.CORSOrigin != "https://example.com" {
					t.Errorf("CORS: has=%v val=%q", info.HasCORSOrigin, info.CORSOrigin)
				}
				if !info.HasPermissionsPolicy || info.PermissionsPolicy != "camera=()" {
					t.Errorf("PP: has=%v val=%q", info.HasPermissionsPolicy, info.PermissionsPolicy)
				}
			},
		},
		{
			name: "CSP report-only",
			headers: map[string][]string{
				"Content-Security-Policy-Report-Only": {"default-src 'none'"},
			},
			check: func(t *testing.T, info SecurityHeaderInfo) {
				if !info.HasCSP {
					t.Error("CSP-Report-Only should count as HasCSP")
				}
				if info.CSP != "default-src 'none'" {
					t.Errorf("CSP value: got %q", info.CSP)
				}
			},
		},
		{
			name: "CSP overrides CSP-Report-Only",
			headers: map[string][]string{
				"Content-Security-Policy":             {"default-src 'self'"},
				"Content-Security-Policy-Report-Only": {"default-src 'none'"},
			},
			check: func(t *testing.T, info SecurityHeaderInfo) {
				// CSP should take priority since it's processed first
				if info.CSP != "default-src 'self'" {
					t.Errorf("CSP should prefer enforce over report-only: got %q", info.CSP)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := extractSecurityHeaders(tt.headers)
			tt.check(t, info)
		})
	}
}

// ─── Aggregation Tests ──────────────────────────────────────────────

func TestSummarizeGeneralLogs(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	events := store.snapshotSince(0)
	summary := summarizeGeneralLogs(events)

	if summary.TotalRequests != 8 {
		t.Errorf("TotalRequests: got %d", summary.TotalRequests)
	}

	// 5xx errors: 500, 502
	if summary.ErrorCount != 2 {
		t.Errorf("ErrorCount: want 2, got %d", summary.ErrorCount)
	}

	// 4xx errors: 404, 429
	if summary.ClientErrorCount != 2 {
		t.Errorf("ClientErrorCount: want 2, got %d", summary.ClientErrorCount)
	}

	// Status distribution
	if summary.StatusDistribution["2xx"] != 3 {
		t.Errorf("2xx: want 3, got %d", summary.StatusDistribution["2xx"])
	}
	if summary.StatusDistribution["3xx"] != 1 {
		t.Errorf("3xx: want 1, got %d", summary.StatusDistribution["3xx"])
	}
	if summary.StatusDistribution["4xx"] != 2 {
		t.Errorf("4xx: want 2, got %d", summary.StatusDistribution["4xx"])
	}
	if summary.StatusDistribution["5xx"] != 2 {
		t.Errorf("5xx: want 2, got %d", summary.StatusDistribution["5xx"])
	}

	// Latency: avg should be > 0
	if summary.AvgDuration <= 0 {
		t.Error("AvgDuration should be > 0")
	}
	if summary.P50Duration <= 0 {
		t.Error("P50Duration should be > 0")
	}
	if summary.P99Duration < summary.P50Duration {
		t.Error("P99 should be >= P50")
	}

	// Top services should exist
	if len(summary.TopServices) == 0 {
		t.Error("TopServices should not be empty")
	}

	// Header compliance should exist
	if len(summary.HeaderCompliance) == 0 {
		t.Error("HeaderCompliance should not be empty")
	}

	// Recent errors should include 4xx and 5xx
	if len(summary.RecentErrors) == 0 {
		t.Error("RecentErrors should not be empty")
	}
}

func TestSummarizeGeneralLogs_Empty(t *testing.T) {
	summary := summarizeGeneralLogs(nil)
	if summary.TotalRequests != 0 {
		t.Errorf("empty should have 0 total, got %d", summary.TotalRequests)
	}
	if summary.StatusDistribution == nil {
		t.Error("StatusDistribution should be initialized even when empty")
	}
}

func TestSummarizeGeneralLogs_HeaderCompliance(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	events := store.snapshotSince(0)
	summary := summarizeGeneralLogs(events)

	// Find app.example.com compliance
	var appCompliance *HeaderCompliance
	for i := range summary.HeaderCompliance {
		if summary.HeaderCompliance[i].Service == "app.example.com" {
			appCompliance = &summary.HeaderCompliance[i]
			break
		}
	}
	if appCompliance == nil {
		t.Fatal("app.example.com not found in header compliance")
	}

	// app.example.com: 4 events total (200, 404, 502, 301)
	// CSP present in 1/4 events (first 200)
	if appCompliance.CSPRate < 0.20 || appCompliance.CSPRate > 0.30 {
		t.Errorf("app.example.com CSP rate: expected ~0.25, got %f", appCompliance.CSPRate)
	}
}

func TestPercentile(t *testing.T) {
	tests := []struct {
		name   string
		values []float64
		p      float64
		want   float64
	}{
		{"empty", nil, 0.50, 0},
		{"single", []float64{5.0}, 0.50, 5.0},
		{"median_odd", []float64{1, 2, 3, 4, 5}, 0.50, 3.0},
		{"p95", []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.95, 9.55},
		{"p99_small", []float64{1, 2, 3}, 0.99, 2.98},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := percentile(tt.values, tt.p)
			if diff := got - tt.want; diff < -0.01 || diff > 0.01 {
				t.Errorf("percentile(%v, %f) = %f, want %f", tt.values, tt.p, got, tt.want)
			}
		})
	}
}

func TestStatusBucket(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{200, "2xx"},
		{204, "2xx"},
		{301, "3xx"},
		{404, "4xx"},
		{429, "4xx"},
		{500, "5xx"},
		{502, "5xx"},
		{100, "other"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.status), func(t *testing.T) {
			if got := statusBucket(tt.status); got != tt.want {
				t.Errorf("statusBucket(%d) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestIsMissingHeader(t *testing.T) {
	evt := GeneralLogEvent{
		SecurityHeaders: SecurityHeaderInfo{
			HasCSP:  true,
			HasHSTS: false,
		},
	}

	if isMissingHeader(&evt, "csp") {
		t.Error("CSP is present, should not be missing")
	}
	if !isMissingHeader(&evt, "hsts") {
		t.Error("HSTS is absent, should be missing")
	}
	if !isMissingHeader(&evt, "xfo") {
		t.Error("XFO is absent, should be missing")
	}
}

// ─── Handler Tests ──────────────────────────────────────────────────

func newTestGeneralLogStore(t *testing.T) *GeneralLogStore {
	t.Helper()
	path := writeGeneralAccessLog(t, sampleGeneralAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()
	return store
}

func TestHandleGeneralLogs_Basic(t *testing.T) {
	store := newTestGeneralLogStore(t)
	handler := handleGeneralLogs(store)

	req := httptest.NewRequest("GET", "/api/logs", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}

	var resp GeneralLogsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.Total != 8 {
		t.Errorf("total: want 8, got %d", resp.Total)
	}
	// Default limit is 50, should return all 8
	if len(resp.Events) != 8 {
		t.Errorf("events: want 8, got %d", len(resp.Events))
	}
	// Should be newest first
	if len(resp.Events) >= 2 && resp.Events[0].Timestamp.Before(resp.Events[1].Timestamp) {
		t.Error("events should be newest-first")
	}
}

func TestHandleGeneralLogs_ServiceFilter(t *testing.T) {
	store := newTestGeneralLogStore(t)
	handler := handleGeneralLogs(store)

	req := httptest.NewRequest("GET", "/api/logs?service=api.example.com", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var resp GeneralLogsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	// api.example.com has 4 events
	if resp.Total != 4 {
		t.Errorf("filtered total: want 4, got %d", resp.Total)
	}
	for _, e := range resp.Events {
		if e.Service != "api.example.com" {
			t.Errorf("leaked service: %s", e.Service)
		}
	}
}

func TestHandleGeneralLogs_StatusBucketFilter(t *testing.T) {
	store := newTestGeneralLogStore(t)
	handler := handleGeneralLogs(store)

	req := httptest.NewRequest("GET", "/api/logs?status=5xx", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var resp GeneralLogsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	// 5xx events: 500, 502
	if resp.Total != 2 {
		t.Errorf("5xx total: want 2, got %d", resp.Total)
	}
	for _, e := range resp.Events {
		if e.Status < 500 || e.Status >= 600 {
			t.Errorf("leaked non-5xx status: %d", e.Status)
		}
	}
}

func TestHandleGeneralLogs_ExactStatusFilter(t *testing.T) {
	store := newTestGeneralLogStore(t)
	handler := handleGeneralLogs(store)

	req := httptest.NewRequest("GET", "/api/logs?status=404", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var resp GeneralLogsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Total != 1 {
		t.Errorf("404 total: want 1, got %d", resp.Total)
	}
}

func TestHandleGeneralLogs_MissingHeaderFilter(t *testing.T) {
	store := newTestGeneralLogStore(t)
	handler := handleGeneralLogs(store)

	req := httptest.NewRequest("GET", "/api/logs?missing_header=csp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var resp GeneralLogsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	// Most events lack CSP — only the first event has it
	if resp.Total != 7 {
		t.Errorf("missing CSP total: want 7, got %d", resp.Total)
	}
	for _, e := range resp.Events {
		if e.SecurityHeaders.HasCSP {
			t.Error("should not return events WITH CSP")
		}
	}
}

func TestHandleGeneralLogs_Pagination(t *testing.T) {
	store := newTestGeneralLogStore(t)
	handler := handleGeneralLogs(store)

	req := httptest.NewRequest("GET", "/api/logs?limit=3&offset=0", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var resp GeneralLogsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Total != 8 {
		t.Errorf("total should be 8 (all matching), got %d", resp.Total)
	}
	if len(resp.Events) != 3 {
		t.Errorf("events: want 3, got %d", len(resp.Events))
	}

	// Page 2
	req2 := httptest.NewRequest("GET", "/api/logs?limit=3&offset=3", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	var resp2 GeneralLogsResponse
	json.NewDecoder(rec2.Body).Decode(&resp2)

	if len(resp2.Events) != 3 {
		t.Errorf("page 2 events: want 3, got %d", len(resp2.Events))
	}
}

func TestHandleGeneralLogs_MethodFilter(t *testing.T) {
	store := newTestGeneralLogStore(t)
	handler := handleGeneralLogs(store)

	req := httptest.NewRequest("GET", "/api/logs?method=POST", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var resp GeneralLogsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	// POST events: the webhook 500
	if resp.Total != 1 {
		t.Errorf("POST total: want 1, got %d", resp.Total)
	}
}

func TestHandleGeneralLogs_LevelFilter(t *testing.T) {
	store := newTestGeneralLogStore(t)
	handler := handleGeneralLogs(store)

	req := httptest.NewRequest("GET", "/api/logs?level=error", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var resp GeneralLogsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	// Error level events: 500, 502
	if resp.Total != 2 {
		t.Errorf("error level total: want 2, got %d", resp.Total)
	}
}

func TestHandleGeneralLogsSummary(t *testing.T) {
	store := newTestGeneralLogStore(t)
	handler := handleGeneralLogsSummary(store)

	req := httptest.NewRequest("GET", "/api/logs/summary", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}

	var summary GeneralLogsSummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}

	if summary.TotalRequests != 8 {
		t.Errorf("TotalRequests: want 8, got %d", summary.TotalRequests)
	}
	if summary.ErrorCount != 2 {
		t.Errorf("ErrorCount: want 2, got %d", summary.ErrorCount)
	}
	if len(summary.TopServices) == 0 {
		t.Error("TopServices should not be empty")
	}
	if len(summary.HeaderCompliance) == 0 {
		t.Error("HeaderCompliance should not be empty")
	}
}

func TestHandleGeneralLogsSummary_ServiceFilter(t *testing.T) {
	store := newTestGeneralLogStore(t)
	handler := handleGeneralLogsSummary(store)

	req := httptest.NewRequest("GET", "/api/logs/summary?service=api.example.com", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var summary GeneralLogsSummary
	json.NewDecoder(rec.Body).Decode(&summary)

	if summary.TotalRequests != 4 {
		t.Errorf("filtered total: want 4, got %d", summary.TotalRequests)
	}
}

// ─── TLS, BytesRead, RequestID Parsing ──────────────────────────────

// sampleTLSAccessLogLines generates access log entries with TLS metadata,
// bytes_read, and X-Request-Id header for enrichment tests.
var sampleTLSAccessLogLines = func() []string {
	now := time.Now()
	ts := func(offset time.Duration) string { return now.Add(offset).UTC().Format("2006/01/02 15:04:05") }
	return []string{
		// TLS 1.3 with ECH, h2, bytes_read, X-Request-Id
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.svc1","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"POST","host":"app.example.com","uri":"/api/upload","headers":{"User-Agent":["Mozilla/5.0"],"X-Request-Id":["abc-123-def"]},"tls":{"version":772,"cipher_suite":4865,"proto":"h2","ech":true,"resumed":false,"server_name":"app.example.com"}},"resp_headers":{},"status":200,"size":500,"duration":0.100,"bytes_read":4096}`, ts(-10*time.Minute)),
		// TLS 1.2, no ECH, resumed session, HTTP/1.1
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.svc2","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/1.1","method":"GET","host":"api.example.com","uri":"/health","headers":{"User-Agent":["curl/8.0"]},"tls":{"version":771,"cipher_suite":49199,"proto":"http/1.1","ech":false,"resumed":true,"server_name":"api.example.com"}},"resp_headers":{},"status":200,"size":50,"duration":0.005,"bytes_read":0}`, ts(-5*time.Minute)),
		// No TLS (plain HTTP — edge case for testing)
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.svc1","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/1.1","method":"GET","host":"app.example.com","uri":"/","headers":{}},"resp_headers":{},"status":200,"size":100,"duration":0.001,"bytes_read":0}`, ts(-2*time.Minute)),
	}
}()

func TestGeneralLogStore_TLSFields(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleTLSAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	events := store.snapshotSince(0)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// First event: TLS 1.3 + ECH + h2
	first := events[0]
	if first.TLS == nil {
		t.Fatal("first event TLS should not be nil")
	}
	if first.TLS.Version != "TLS 1.3" {
		t.Errorf("TLS version: got %q, want %q", first.TLS.Version, "TLS 1.3")
	}
	if first.TLS.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("cipher suite: got %q, want %q", first.TLS.CipherSuite, "TLS_AES_128_GCM_SHA256")
	}
	if first.TLS.Proto != "h2" {
		t.Errorf("ALPN proto: got %q, want %q", first.TLS.Proto, "h2")
	}
	if !first.TLS.ECH {
		t.Error("ECH should be true")
	}
	if first.TLS.Resumed {
		t.Error("Resumed should be false")
	}
	if first.TLS.ServerName != "app.example.com" {
		t.Errorf("server_name: got %q", first.TLS.ServerName)
	}

	// Second event: TLS 1.2 + resumed
	second := events[1]
	if second.TLS == nil {
		t.Fatal("second event TLS should not be nil")
	}
	if second.TLS.Version != "TLS 1.2" {
		t.Errorf("TLS version: got %q, want %q", second.TLS.Version, "TLS 1.2")
	}
	if second.TLS.CipherSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("cipher suite: got %q, want %q", second.TLS.CipherSuite, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	}
	if second.TLS.Proto != "http/1.1" {
		t.Errorf("ALPN proto: got %q", second.TLS.Proto)
	}
	if second.TLS.ECH {
		t.Error("ECH should be false")
	}
	if !second.TLS.Resumed {
		t.Error("Resumed should be true")
	}

	// Third event: no TLS (plain HTTP)
	third := events[2]
	if third.TLS != nil {
		t.Error("third event (plain HTTP) should have nil TLS")
	}
}

func TestGeneralLogStore_BytesRead(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleTLSAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	events := store.snapshotSince(0)

	// First event: POST with 4096 bytes_read
	if events[0].BytesRead != 4096 {
		t.Errorf("bytes_read: got %d, want 4096", events[0].BytesRead)
	}
	// Second event: GET with 0 bytes_read
	if events[1].BytesRead != 0 {
		t.Errorf("bytes_read: got %d, want 0", events[1].BytesRead)
	}
}

func TestGeneralLogStore_RequestID(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleTLSAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	events := store.snapshotSince(0)

	// First event has X-Request-Id header
	if events[0].RequestID != "abc-123-def" {
		t.Errorf("request_id: got %q, want %q", events[0].RequestID, "abc-123-def")
	}
	// Second event has no X-Request-Id
	if events[1].RequestID != "" {
		t.Errorf("request_id should be empty, got %q", events[1].RequestID)
	}
	// Third event has no X-Request-Id
	if events[2].RequestID != "" {
		t.Errorf("request_id should be empty, got %q", events[2].RequestID)
	}
}

func TestAccessLogRequestID_TopLevelPreference(t *testing.T) {
	// Top-level request_id (from log_append) takes priority over header
	now := time.Now()
	ts := now.Add(-1 * time.Minute).UTC().Format("2006/01/02 15:04:05")

	// Entry with BOTH top-level request_id AND X-Request-Id header
	line := fmt.Sprintf(`{"level":"info","ts":"%s","logger":"test","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"app.example.com","uri":"/","headers":{"X-Request-Id":["header-id-old"]}},"resp_headers":{},"status":200,"size":100,"duration":0.01,"request_id":"log-append-id-new"}`, ts)

	path := writeGeneralAccessLog(t, []string{line})
	store := NewGeneralLogStore(path)
	store.Load()

	events := store.snapshotSince(0)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// Should prefer top-level request_id over header
	if events[0].RequestID != "log-append-id-new" {
		t.Errorf("request_id: got %q, want %q (should prefer top-level over header)", events[0].RequestID, "log-append-id-new")
	}
}

func TestAccessLogRequestID_HeaderFallback(t *testing.T) {
	// When no top-level request_id, falls back to X-Request-Id header
	now := time.Now()
	ts := now.Add(-1 * time.Minute).UTC().Format("2006/01/02 15:04:05")

	// Entry with only X-Request-Id header (no top-level field — older logs)
	line := fmt.Sprintf(`{"level":"info","ts":"%s","logger":"test","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"app.example.com","uri":"/","headers":{"X-Request-Id":["header-fallback-id"]}},"resp_headers":{},"status":200,"size":100,"duration":0.01}`, ts)

	path := writeGeneralAccessLog(t, []string{line})
	store := NewGeneralLogStore(path)
	store.Load()

	events := store.snapshotSince(0)
	if events[0].RequestID != "header-fallback-id" {
		t.Errorf("request_id: got %q, want %q (should fall back to header)", events[0].RequestID, "header-fallback-id")
	}
}

func TestGeneralLogStore_TLSFieldsInJSONResponse(t *testing.T) {
	path := writeGeneralAccessLog(t, sampleTLSAccessLogLines)
	store := NewGeneralLogStore(path)
	store.Load()

	handler := handleGeneralLogs(store)
	req := httptest.NewRequest("GET", "/api/logs?limit=10", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}

	var resp GeneralLogsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Total != 3 {
		t.Fatalf("total: got %d, want 3", resp.Total)
	}

	// API returns newest first — first in response is the no-TLS event
	// (most recent), last is the TLS 1.3 event (oldest of the 3).
	tlsEvent := resp.Events[len(resp.Events)-1]
	if tlsEvent.TLS == nil {
		t.Fatal("TLS 1.3 event should have TLS info in JSON response")
	}
	if tlsEvent.TLS.Version != "TLS 1.3" {
		t.Errorf("JSON TLS version: got %q", tlsEvent.TLS.Version)
	}
	if tlsEvent.BytesRead != 4096 {
		t.Errorf("JSON bytes_read: got %d", tlsEvent.BytesRead)
	}
	if tlsEvent.RequestID != "abc-123-def" {
		t.Errorf("JSON request_id: got %q", tlsEvent.RequestID)
	}

	// No-TLS event should have nil TLS
	noTLSEvent := resp.Events[0]
	if noTLSEvent.TLS != nil {
		t.Error("plain HTTP event should have null TLS in JSON response")
	}
}
