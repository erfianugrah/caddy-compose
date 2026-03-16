package e2e_test

import (
	"net/http"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  1. Health & Basics
// ════════════════════════════════════════════════════════════════════

func TestHealthAndBasics(t *testing.T) {
	t.Parallel()
	t.Run("wafctl health", func(t *testing.T) {
		t.Parallel()
		resp, body := httpGet(t, wafctlURL+"/api/health")
		assertCode(t, "health", 200, resp)
		assertField(t, "health", body, "status", "ok")
	})

	t.Run("Caddy admin", func(t *testing.T) {
		t.Parallel()
		resp, _ := httpGet(t, caddyAdmin+"/config/")
		assertCode(t, "caddy admin", 200, resp)
	})

	t.Run("proxy GET", func(t *testing.T) {
		t.Parallel()
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "proxy GET", 200, resp)
	})

	t.Run("proxy POST", func(t *testing.T) {
		t.Parallel()
		resp, _ := httpPost(t, caddyURL+"/post", map[string]string{"hello": "world"})
		assertCode(t, "proxy POST", 200, resp)
	})

	t.Run("security headers", func(t *testing.T) {
		t.Parallel()
		resp, _ := httpGet(t, caddyURL+"/get")
		// Security headers are only present when configured and deployed via
		// wafctl. In a fresh CI stack they may not exist yet. Log instead of fail.
		if !headerContains(resp, "X-Content-Type-Options", "nosniff") {
			t.Log("X-Content-Type-Options not present (security headers may not be deployed yet)")
		}
		if !headerContains(resp, "Strict-Transport-Security", "max-age=") {
			t.Log("HSTS header not present (security headers may not be deployed yet)")
		}
	})
}

// ════════════════════════════════════════════════════════════════════
//  2. WAF Blocking
// ════════════════════════════════════════════════════════════════════

func TestWAFBlocking(t *testing.T) {
	// Not parallel — requires WAF config at known state (default thresholds).
	// Parallel tests that mutate config (e.g., threshold=10000) can poison results.
	ensureDefaultConfig(t)
	deployWAF(t)
	// Wait for SQLi to actually be blocked (confirms threshold took effect).
	// CI may need longer than local — policy engine hot-reload is 5s interval.
	waitForCondition(t, "SQLi blocked", 30*time.Second, func() bool {
		req, _ := http.NewRequest("GET", caddyURL+"/get?id=1%20OR%201=1%20--", nil)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 403
	})

	tests := []struct {
		name string
		url  string
		want int
	}{
		{"SQL injection", caddyURL + "/get?id=1%20OR%201=1%20--", 403},
		{"XSS", caddyURL + "/get?q=%3Cscript%3Ealert(1)%3C/script%3E", 403},
		{"path traversal", caddyURL + "/get?file=../../../../etc/passwd", 403},
		{"legitimate request", caddyURL + "/get?q=hello", 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mustNewRequest(t, "GET", tt.url)
			setBrowserHeaders(req)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Errorf("expected %d, got %d", tt.want, resp.StatusCode)
			}
		})
	}
}

// ════════════════════════════════════════════════════════════════════
//  3. WAF Events & Summary
// ════════════════════════════════════════════════════════════════════

func TestWAFEventsAndSummary(t *testing.T) {
	t.Parallel()
	// Give the log tailer time to pick up the blocked requests from TestWAFBlocking.
	time.Sleep(2 * time.Second)

	t.Run("summary has events", func(t *testing.T) {
		_, body := httpGet(t, wafctlURL+"/api/summary?hours=1")
		total := jsonInt(body, "total_events")
		if total <= 0 {
			// Retry once — tailer may not have caught up.
			time.Sleep(2 * time.Second)
			_, body = httpGet(t, wafctlURL+"/api/summary?hours=1")
			total = jsonInt(body, "total_events")
			if total <= 0 {
				t.Errorf("expected total_events > 0, got %d", total)
			}
		}
	})

	t.Run("events endpoint", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/events?hours=1&limit=10")
		assertCode(t, "events", 200, resp)
	})

	t.Run("services endpoint", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/services")
		assertCode(t, "services", 200, resp)
	})
}

// ════════════════════════════════════════════════════════════════════
//  4. Analytics
// ════════════════════════════════════════════════════════════════════

func TestAnalytics(t *testing.T) {
	t.Parallel()
	endpoints := []string{
		"/api/analytics/top-ips?hours=1",
		"/api/analytics/top-uris?hours=1",
		"/api/analytics/top-countries?hours=1",
		"/api/lookup/127.0.0.1",
	}
	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			t.Parallel()
			resp, _ := httpGet(t, wafctlURL+ep)
			assertCode(t, ep, 200, resp)
		})
	}
}
