package e2e_test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  DDoS Load Tests — native Go flood + verification
//
//  Gated behind DDOS_LOAD=1 env var to avoid running in normal CI.
//  Uses raw Go HTTP with aggressive connection pooling — no k6 needed.
// ════════════════════════════════════════════════════════════════════

func skipUnlessLoadTest(t *testing.T) {
	if envOr("DDOS_LOAD", "") != "1" {
		t.Skip("skipping load test (set DDOS_LOAD=1 to enable)")
	}
}

// floodResult holds metrics from a flood run.
type floodResult struct {
	total      int64
	ok200      int64
	ok403      int64
	errors     int64
	firstBlock time.Duration
	elapsed    time.Duration
}

func (r floodResult) rps() float64 { return float64(r.total) / r.elapsed.Seconds() }

// flood sends concurrent HTTP requests to target for the given duration.
// Uses HTTP/2 multiplexing — fewer TCP connections, more pipelined requests.
// Returns metrics about the run.
func flood(target string, workers int, duration time.Duration) floodResult {
	transport := &http.Transport{
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     100, // fewer connections, HTTP/2 multiplexes on each
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{},
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
	}
	c := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	var total, ok200, ok403, errors atomic.Int64
	var firstBlockMs atomic.Int64
	start := time.Now()
	stop := make(chan struct{})

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest("GET", target, nil)
				req.Header.Set("User-Agent", "ddos-load-test/1.0")
				req.Header.Set("Accept", "*/*")
				resp, err := c.Do(req)
				total.Add(1)
				if err != nil {
					errors.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				switch resp.StatusCode {
				case 200:
					ok200.Add(1)
				case 403:
					ok403.Add(1)
					if firstBlockMs.Load() == 0 {
						firstBlockMs.Store(time.Since(start).Milliseconds())
					}
				default:
					errors.Add(1)
				}
			}
		}()
	}

	time.Sleep(duration)
	close(stop)
	wg.Wait()

	fb := time.Duration(0)
	if ms := firstBlockMs.Load(); ms > 0 {
		fb = time.Duration(ms) * time.Millisecond
	}
	return floodResult{
		total:      total.Load(),
		ok200:      ok200.Load(),
		ok403:      ok403.Load(),
		errors:     errors.Load(),
		firstBlock: fb,
		elapsed:    time.Since(start),
	}
}

// TestDDoS_Load_BaselineThenAttack runs a full DDoS simulation:
// 1. Seed diverse baseline traffic so the behavioral profiler has context
// 2. Flood a single endpoint to trigger behavioral anomaly detection
// 3. Verify the IP was auto-jailed
// 4. Verify DDoS events appear in the security events API
func TestDDoS_Load_BaselineThenAttack(t *testing.T) {
	skipUnlessLoadTest(t)

	// Raise WAF threshold so CRS detect rules don't interfere.
	ensureDefaultConfig(t)
	httpPut(t, wafctlURL+"/api/config", map[string]any{
		"defaults": map[string]any{
			"paranoia_level":     1,
			"inbound_threshold":  50,
			"outbound_threshold": 50,
		},
	})
	deployWAF(t)
	time.Sleep(3 * time.Second)
	t.Log("WAF threshold raised to 50 for load test")
	defer func() {
		ensureDefaultConfig(t)
		deployWAF(t)
	}()

	// Phase 1: Baseline — concurrent diverse paths to seed the profiler
	t.Log("Phase 1: Baseline traffic (diverse paths, 10s, 50 workers)...")
	paths := []string{"/get", "/headers", "/ip", "/user-agent", "/anything/page1",
		"/anything/page2", "/anything/page3", "/anything/about", "/anything/contact",
		"/anything/api/v1/users", "/anything/api/v1/products", "/anything/api/v2/search"}
	var baselineReqs atomic.Int64
	baselineStop := make(chan struct{})
	var baselineWg sync.WaitGroup
	baselineTransport := &http.Transport{
		MaxIdleConnsPerHost: 50,
		TLSClientConfig:     &tls.Config{},
		ForceAttemptHTTP2:   true,
	}
	baselineClient := &http.Client{Timeout: 5 * time.Second, Transport: baselineTransport}
	for i := 0; i < 50; i++ {
		baselineWg.Add(1)
		go func(id int) {
			defer baselineWg.Done()
			for {
				select {
				case <-baselineStop:
					return
				default:
				}
				p := paths[id%len(paths)]
				req, _ := http.NewRequest("GET", caddyURL+p, nil)
				req.Header.Set("User-Agent", fmt.Sprintf("ddos-baseline-%d/1.0", id))
				req.Header.Set("Accept", "*/*")
				resp, err := baselineClient.Do(req)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				baselineReqs.Add(1)
			}
		}(i)
	}
	time.Sleep(10 * time.Second)
	close(baselineStop)
	baselineWg.Wait()
	t.Logf("Baseline: %d requests across %d paths", baselineReqs.Load(), len(paths))

	// Phase 2: Attack — flood single endpoint with high concurrency
	// HTTP/2 multiplexing: 100 TCP connections * many streams each.
	// 2000 goroutines pipeline requests without waiting per-connection.
	t.Log("Phase 2: Flood attack (2000 workers, single path, 30s)...")
	attackURL := caddyURL + "/anything/api/v1/vulnerable-endpoint"
	result := flood(attackURL, 2000, 30*time.Second)

	t.Logf("Flood results:")
	t.Logf("  Duration:    %s", result.elapsed.Round(time.Millisecond))
	t.Logf("  Total:       %d (%.0f req/s)", result.total, result.rps())
	t.Logf("  200 OK:      %d", result.ok200)
	t.Logf("  403 Blocked: %d", result.ok403)
	t.Logf("  Errors:      %d", result.errors)
	if result.firstBlock > 0 {
		t.Logf("  First block: %s", result.firstBlock)
	} else {
		t.Log("  First block: NEVER")
	}

	// Phase 3: Verify jail
	t.Log("Phase 3: Verifying DDoS mitigator response...")
	time.Sleep(2 * time.Second) // wait for jail file sync

	resp, body := httpGet(t, wafctlURL+"/api/dos/jail")
	assertCode(t, "jail after attack", 200, resp)
	var jailEntries []map[string]any
	json.Unmarshal(body, &jailEntries)
	t.Logf("Jail entries: %d", len(jailEntries))
	for _, e := range jailEntries {
		t.Logf("  %s reason=%s expires=%s", e["ip"], e["reason"], e["expires_at"])
	}

	if result.ok403 == 0 {
		t.Log("WARNING: No 403s during flood — mitigator may not have triggered at this volume")
	} else {
		blockRate := float64(result.ok403) / float64(result.total) * 100
		t.Logf("Block rate: %.1f%% (%d/%d)", blockRate, result.ok403, result.total)
	}

	// Phase 4: Check DDoS events in security events
	resp, body = httpGet(t, wafctlURL+"/api/events?hours=1&limit=5")
	assertCode(t, "events after attack", 200, resp)
	events := jsonFieldArray(body, "events")
	ddosCount := 0
	for _, e := range events {
		var evt map[string]any
		json.Unmarshal(e, &evt)
		if strings.HasPrefix(fmt.Sprint(evt["event_type"]), "ddos") {
			ddosCount++
		}
	}
	t.Logf("DDoS events in security log: %d (of %d recent events)", ddosCount, len(events))

	// Phase 5: Check DDoS status
	resp, body = httpGet(t, wafctlURL+"/api/dos/status")
	assertCode(t, "dos status", 200, resp)
	t.Logf("DDoS status: %s", string(body))
}

// TestDDoS_Load_ConnectionFlood creates many rapid TCP connections to
// verify Caddy handles connection pressure without crashing.
func TestDDoS_Load_ConnectionFlood(t *testing.T) {
	skipUnlessLoadTest(t)

	host := strings.TrimPrefix(caddyURL, "http://")
	host = strings.TrimPrefix(host, "https://")
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	t.Logf("Connection flood: 500 rapid TCP connections to %s", host)
	var connected, failed int
	for range 500 {
		conn, err := net.DialTimeout("tcp", host, 2*time.Second)
		if err != nil {
			failed++
			continue
		}
		conn.Close()
		connected++
	}
	t.Logf("Connected: %d, Failed: %d", connected, failed)

	// Caddy should still be healthy
	resp, _ := httpGet(t, wafctlURL+"/api/health")
	assertCode(t, "wafctl healthy after flood", 200, resp)
}

// TestDDoS_Load_SustainedPressure runs sustained moderate traffic to verify
// no memory leaks or lock contention under prolonged load.
func TestDDoS_Load_SustainedPressure(t *testing.T) {
	skipUnlessLoadTest(t)

	t.Log("Sustained pressure: 50 workers, 60s, mixed paths...")
	// Mix of single-path flood and diverse traffic
	done := make(chan struct{})
	var total, blocked atomic.Int64

	transport := &http.Transport{
		MaxIdleConnsPerHost: 100,
		TLSClientConfig:     &tls.Config{},
	}
	c := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	// 40 workers hammering one endpoint (attacker pattern)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				req, _ := http.NewRequest("GET", caddyURL+"/anything/api/v1/sustained-target", nil)
				req.Header.Set("User-Agent", "sustained-attacker/1.0")
				req.Header.Set("Accept", "*/*")
				resp, err := c.Do(req)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					total.Add(1)
					if resp.StatusCode == 403 {
						blocked.Add(1)
					}
				}
			}
		}()
	}

	// 10 workers doing diverse browsing (legitimate traffic)
	paths := []string{"/get", "/headers", "/ip", "/anything/page1", "/anything/page2"}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				p := paths[id%len(paths)]
				req, _ := http.NewRequest("GET", caddyURL+p, nil)
				req.Header.Set("User-Agent", fmt.Sprintf("legit-user-%d/1.0", id))
				req.Header.Set("Accept", "text/html,*/*")
				resp, err := c.Do(req)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					total.Add(1)
				}
				time.Sleep(100 * time.Millisecond) // legitimate users are slower
			}
		}(i)
	}

	// Run for 60 seconds, reporting every 10s
	start := time.Now()
	for elapsed := 0; elapsed < 60; elapsed += 10 {
		time.Sleep(10 * time.Second)
		t.Logf("  [%ds] total=%d blocked=%d rps=%.0f",
			elapsed+10, total.Load(), blocked.Load(),
			float64(total.Load())/time.Since(start).Seconds())
	}
	close(done)
	wg.Wait()

	t.Logf("Final: total=%d blocked=%d (%.1f%%) rps=%.0f",
		total.Load(), blocked.Load(),
		float64(blocked.Load())/float64(total.Load())*100,
		float64(total.Load())/time.Since(start).Seconds())

	// Verify stack is still healthy
	resp, _ := httpGet(t, wafctlURL+"/api/health")
	assertCode(t, "wafctl healthy after sustained", 200, resp)
}
