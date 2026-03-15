package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── Benchmark Helpers ─────────────────────────────────────────────

func benchAccessLogStore(b *testing.B) *AccessLogStore {
	b.Helper()
	return NewAccessLogStore(filepath.Join(b.TempDir(), "empty-access.log"))
}

// generateEvents creates n synthetic events spread across the last `hours` hours.
func generateEvents(n, hours int) []Event {
	now := time.Now()
	services := []string{"sonarr.erfi.io", "radarr.erfi.io", "httpbun.erfi.io", "jellyfin.erfi.io", "dockge.erfi.io"}
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	types := []string{"detect_block", "logged", "policy_block", "policy_allow", "policy_skip"}
	uris := []string{"/api/v3/queue", "/.env", "/login", "/api/health", "/wp-admin", "/socket.io/"}
	countries := []string{"US", "DE", "CN", "RU", "GB", "FR", "JP"}

	events := make([]Event, n)
	for i := 0; i < n; i++ {
		ts := now.Add(-time.Duration(rand.Intn(hours*60)) * time.Minute)
		events[i] = Event{
			ID:             fmt.Sprintf("evt-%d", i),
			Timestamp:      ts,
			ClientIP:       fmt.Sprintf("10.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256)),
			Service:        services[rand.Intn(len(services))],
			Method:         methods[rand.Intn(len(methods))],
			URI:            uris[rand.Intn(len(uris))],
			Protocol:       "HTTP/2.0",
			UserAgent:      "Mozilla/5.0 (bench)",
			ResponseStatus: []int{200, 403, 429, 500}[rand.Intn(4)],
			IsBlocked:      rand.Intn(2) == 0,
			EventType:      types[rand.Intn(len(types))],
			Country:        countries[rand.Intn(len(countries))],
		}
	}
	return events
}

// ─── BenchmarkSummarizeEvents ──────────────────────────────────────

func BenchmarkSummarizeEvents_1K(b *testing.B) {
	events := generateEvents(1_000, 24)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		summarizeEvents(events)
	}
}

func BenchmarkSummarizeEvents_10K(b *testing.B) {
	events := generateEvents(10_000, 24)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		summarizeEvents(events)
	}
}

func BenchmarkSummarizeEvents_50K(b *testing.B) {
	events := generateEvents(50_000, 24)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		summarizeEvents(events)
	}
}

func BenchmarkSummarizeEventsWithSets_10K(b *testing.B) {
	events := generateEvents(10_000, 24)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		summarizeEventsWithSets(events)
	}
}

// ─── BenchmarkFieldFilter ──────────────────────────────────────────

func BenchmarkFieldFilter_Eq(b *testing.B) {
	f := parseFieldFilter("sonarr.erfi.io", "eq")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.matchField("radarr.erfi.io")
	}
}

func BenchmarkFieldFilter_Contains(b *testing.B) {
	f := parseFieldFilter("erfi", "contains")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.matchField("sonarr.erfi.io")
	}
}

func BenchmarkFieldFilter_In(b *testing.B) {
	f := parseFieldFilter("sonarr.erfi.io,radarr.erfi.io,httpbun.erfi.io", "in")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.matchField("httpbun.erfi.io")
	}
}

func BenchmarkFieldFilter_Regex(b *testing.B) {
	f := parseFieldFilter("^sonarr\\..*\\.io$", "regex")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.matchField("sonarr.erfi.io")
	}
}

func BenchmarkMatchIntField_Eq(b *testing.B) {
	f := parseFieldFilter("403", "eq")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.matchIntField(403)
	}
}

func BenchmarkMatchIntField_In(b *testing.B) {
	f := parseFieldFilter("200,403,429,500", "in")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.matchIntField(429)
	}
}

// ─── BenchmarkBuildServiceFQDNMap ──────────────────────────────────

func BenchmarkBuildServiceFQDNMap(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	var content string
	for i := 0; i < 30; i++ {
		content += fmt.Sprintf("service%d.erfi.io {\n\timport waf\n\treverse_proxy service%d:8080\n}\n", i, i)
	}
	os.WriteFile(path, []byte(content), 0644)

	// Clear the cache to benchmark cold path.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Invalidate cache by changing path each iteration.
		fqdnCache.mu.Lock()
		fqdnCache.data = nil
		fqdnCache.mu.Unlock()
		BuildServiceFQDNMap(path)
	}
}

func BenchmarkBuildServiceFQDNMap_Cached(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	var content string
	for i := 0; i < 30; i++ {
		content += fmt.Sprintf("service%d.erfi.io {\n\timport waf\n\treverse_proxy service%d:8080\n}\n", i, i)
	}
	os.WriteFile(path, []byte(content), 0644)

	// Warm cache.
	BuildServiceFQDNMap(path)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildServiceFQDNMap(path)
	}
}

// ─── BenchmarkHandleSummary ────────────────────────────────────────

func BenchmarkHandleSummary_1K(b *testing.B) {
	benchmarkHandleSummary(b, 1_000)
}

func BenchmarkHandleSummary_10K(b *testing.B) {
	benchmarkHandleSummary(b, 10_000)
}

func benchmarkHandleSummary(b *testing.B, n int) {
	store := NewStore()
	events := generateEvents(n, 24)
	store.mu.Lock()
	store.events = events
	store.mu.Unlock()

	als := benchAccessLogStore(b)

	handler := handleSummary(store, als)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/summary?hours=24", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d", rec.Code)
		}
	}
}

// ─── BenchmarkHandleEvents ─────────────────────────────────────────

func BenchmarkHandleEvents_Page1_1K(b *testing.B) {
	benchmarkHandleEvents(b, 1_000)
}

func BenchmarkHandleEvents_Page1_10K(b *testing.B) {
	benchmarkHandleEvents(b, 10_000)
}

func benchmarkHandleEvents(b *testing.B, n int) {
	store := NewStore()
	events := generateEvents(n, 24)
	store.mu.Lock()
	store.events = events
	store.mu.Unlock()

	als := benchAccessLogStore(b)

	handler := handleEvents(store, als)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/events?hours=24&limit=50", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d", rec.Code)
		}
	}
}

// ─── BenchmarkUIFileServer ─────────────────────────────────────────

func BenchmarkUIFileServer_HashedAsset(b *testing.B) {
	dir := b.TempDir()
	astroDir := filepath.Join(dir, "_astro")
	os.MkdirAll(astroDir, 0755)
	os.WriteFile(filepath.Join(astroDir, "main.AbCd1234.js"), []byte("console.log('bench')"), 0644)

	handler := uiFileServer(dir)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/_astro/main.AbCd1234.js", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d", rec.Code)
		}
	}
}
