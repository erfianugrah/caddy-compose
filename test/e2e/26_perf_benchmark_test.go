package e2e_test

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// 26. Performance Benchmarks — Seed Events + Measure Endpoint Latency
// ════════════════════════════════════════════════════════════════════

// TestPerfSeedAndMeasure generates realistic WAF events by sending attack
// payloads through the proxy, waits for the event pipeline to process them,
// then measures API endpoint response times under load.
func TestPerfSeedAndMeasure(t *testing.T) {
	// ── Phase 1: Seed events ─────────────────────────────────────────
	// Send a burst of requests through the WAF to generate events in both
	// the WAF store (CRS detections) and the access log store (policy blocks,
	// rate limits, logged events).

	const seedCount = 200 // requests to generate
	const concurrency = 10

	// Ensure WAF is at default config (PL2, threshold 15).
	ensureDefaultConfig(t)
	deployWAF(t)
	time.Sleep(2 * time.Second)

	// Attack payloads that trigger CRS rules at different severity levels.
	payloads := []struct {
		path string
		ua   string
		desc string
	}{
		{"/get?id=1+OR+1=1--", "PerfBot/1.0", "SQLi"},
		{"/get?q=<script>alert(1)</script>", "PerfBot/1.0", "XSS"},
		{"/get?file=../../../../etc/passwd", "PerfBot/1.0", "LFI"},
		{"/get?cmd=;cat+/etc/shadow", "PerfBot/1.0", "RCE"},
		{"/get?page=1", "PerfBot/1.0", "clean"},
		{"/get", "PerfBot/1.0", "clean-no-params"},
		{"/post", "PerfBot/1.0", "clean-post-path"},
		{"/get?search=hello+world", "PerfBot/1.0", "clean-search"},
	}

	t.Logf("Seeding %d events (%d concurrent)...", seedCount, concurrency)
	start := time.Now()

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for i := 0; i < seedCount; i++ {
		wg.Add(1)
		p := payloads[i%len(payloads)]
		go func(path, ua string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, _ := http.NewRequest("GET", caddyURL+path, nil)
			setBrowserHeaders(req)
			req.Header.Set("User-Agent", ua)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}(p.path, p.ua)
	}
	wg.Wait()
	seedDuration := time.Since(start)
	t.Logf("Seeded %d requests in %v (%.0f req/s)", seedCount, seedDuration, float64(seedCount)/seedDuration.Seconds())

	// Wait for the event pipeline to process (tail interval + processing).
	t.Log("Waiting for event pipeline to process...")
	time.Sleep(8 * time.Second)

	// ── Phase 2: Measure endpoint latencies ──────────────────────────

	endpoints := []struct {
		name  string
		url   string
		maxMS int64 // maximum acceptable latency in milliseconds
	}{
		{"health", wafctlURL + "/api/health", 100},
		{"summary", wafctlURL + "/api/summary?hours=24", 500},
		{"services", wafctlURL + "/api/services", 500},
		{"events", wafctlURL + "/api/events?hours=24&limit=25", 500},
		{"rules", wafctlURL + "/api/rules", 100},
		{"config", wafctlURL + "/api/config", 100},
		{"default-rules", wafctlURL + "/api/default-rules", 200},
		{"exclusions-hits", wafctlURL + "/api/exclusions/hits?hours=24", 500},
	}

	// Warm up caches with one request each.
	for _, ep := range endpoints {
		resp, err := client.Do(mustNewRequest(t, "GET", ep.url))
		if err == nil {
			resp.Body.Close()
		}
	}
	time.Sleep(500 * time.Millisecond)

	// Measure cold latency (after cache expiry).
	t.Log("Measuring endpoint latencies...")
	var failures []string
	for _, ep := range endpoints {
		start := time.Now()
		resp, err := client.Do(mustNewRequest(t, "GET", ep.url))
		elapsed := time.Since(start)
		if err != nil {
			t.Errorf("%s: request failed: %v", ep.name, err)
			continue
		}
		resp.Body.Close()

		ms := elapsed.Milliseconds()
		status := "PASS"
		if ms > ep.maxMS {
			status = "SLOW"
			failures = append(failures, fmt.Sprintf("%s: %dms (max %dms)", ep.name, ms, ep.maxMS))
		}
		t.Logf("  %-20s %4dms (max %dms) [%s] HTTP %d", ep.name, ms, ep.maxMS, status, resp.StatusCode)
	}

	if len(failures) > 0 {
		t.Errorf("Slow endpoints: %s", strings.Join(failures, ", "))
	}

	// ── Phase 3: Concurrent load test ────────────────────────────────
	// Hit summary + services + events concurrently (simulates dashboard load).

	t.Log("Concurrent dashboard load test (3 endpoints × 5 iterations)...")
	concEndpoints := []string{
		wafctlURL + "/api/summary?hours=24",
		wafctlURL + "/api/services",
		wafctlURL + "/api/events?hours=24&limit=25",
	}

	start = time.Now()
	var concWg sync.WaitGroup
	const loadIterations = 5
	for iter := 0; iter < loadIterations; iter++ {
		for _, url := range concEndpoints {
			concWg.Add(1)
			go func(u string) {
				defer concWg.Done()
				req, _ := http.NewRequest("GET", u, nil)
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}(url)
		}
	}
	concWg.Wait()
	concDuration := time.Since(start)
	totalReqs := loadIterations * len(concEndpoints)
	t.Logf("Concurrent load: %d requests in %v (%.0f req/s)", totalReqs, concDuration, float64(totalReqs)/concDuration.Seconds())

	if concDuration > 5*time.Second {
		t.Errorf("Concurrent dashboard load too slow: %v (max 5s for %d requests)", concDuration, totalReqs)
	}
}
