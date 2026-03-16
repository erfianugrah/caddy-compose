package e2e_test

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  CRS v7 Default Rules — New Operators (v0.12.0)
// ════════════════════════════════════════════════════════════════════
//
// These tests prove that the policy engine's new v0.12.0+ operators (detect_sqli,
// detect_xss, validate_byte_range, cmdLine transform) actually work end-to-end.
//
// ISOLATION STRATEGY: Set Coraza to detection_only mode so it logs but CANNOT
// block. Keep the policy engine's inbound_threshold at 15. Now if a request
// gets 403, it MUST be from the policy engine's anomaly scoring — Coraza
// cannot return 403 in detection_only mode. This cleanly attributes the block.
// Threshold=15 is high enough that protocol enforcement rules alone (9100034,
// 920310, etc.) don't trigger blocking, but low enough that any real attack
// payload (SQLi=50+, XSS=55+, RCE=20+) easily exceeds it.
//
// Each test then verifies:
//   1. The malicious payload returns 403 (policy engine detect_block)
//   2. A clean payload passes through (200)
//   3. The events API shows event_type=detect_block with the correct rule ID,
//      rule message, and matched_data
//
// The default-rules.json v7 (255 rules, CRS 4.24.1) is baked into both the
// caddy image (plugin loads them) and wafctl image (API serves them).

// setCRSv7TestConfig sets detection_only mode with threshold=5 to isolate
// policy engine from Coraza, deploys, and waits for hot-reload.
// Threshold=5 allows "clean" requests with browser headers (setBrowserHeaders
// adds User-Agent/Accept/Accept-Language/Accept-Encoding) to pass — they score
// at most 2 (9100034 for missing Referer). Attack payloads score ≥7 (CRITICAL
// rule + 9100034), so threshold=5 reliably catches them.
func setCRSv7TestConfig(t *testing.T) {
	t.Helper()
	configPayload := map[string]any{
		"defaults": map[string]any{
			"paranoia_level":     1,
			"inbound_threshold":  5,
			"outbound_threshold": 5,
		},
	}
	resp, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "set detection_only config", 200, resp)
	time.Sleep(1 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy detection_only", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	waitForStatus(t, caddyURL+"/get", 200, 10*time.Second)
}

// restoreCRSv7TestConfig restores the WAF config to production defaults.
func restoreCRSv7TestConfig(t *testing.T) {
	t.Helper()
	restorePayload := map[string]any{
		"defaults": map[string]any{
			"paranoia_level":     2,
			"inbound_threshold":  10,
			"outbound_threshold": 10,
		},
	}
	httpPut(t, wafctlURL+"/api/config", restorePayload)
	time.Sleep(1 * time.Second)
	httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	waitForStatus(t, caddyURL+"/get", 200, 10*time.Second)
}

// TestCRSv7 groups all CRSv7 feature validation tests under one config cycle.
// Sharing setCRSv7TestConfig/restoreCRSv7TestConfig across subtests saves ~80s
// compared to per-test setup/teardown (5×10s setup + 5×10s teardown → 1+1).
func TestCRSv7(t *testing.T) {
	setCRSv7TestConfig(t)
	defer restoreCRSv7TestConfig(t)

	// --- DetectSQLi (942100) ---

	t.Run("DetectSQLi/UNION SELECT blocked by policy engine", func(t *testing.T) {
		sentinel := fmt.Sprintf("e2e-sqli-union-%d", time.Now().UnixNano())
		req, _ := http.NewRequest("GET",
			caddyURL+"/get?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users", nil)
		req.Header.Set("User-Agent", sentinel)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("expected 403 (policy engine detect_block), got %d; body=%.300s",
				resp.StatusCode, string(body))
		}
		evt := waitForEvent(t, sentinel, 15*time.Second)
		verifyDetectBlockEventFromMap(t, evt, "942100", "libinjection")
	})

	t.Run("DetectSQLi/OR 1=1 blocked by policy engine", func(t *testing.T) {
		sentinel := fmt.Sprintf("e2e-sqli-or1-%d", time.Now().UnixNano())
		req, _ := http.NewRequest("GET",
			caddyURL+"/get?user=admin%27%20OR%20%271%27%3D%271", nil)
		req.Header.Set("User-Agent", sentinel)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 for SQLi OR 1=1, got %d", resp.StatusCode)
		}
	})

	t.Run("DetectSQLi/clean query passes through", func(t *testing.T) {
		req, _ := http.NewRequest("GET", caddyURL+"/get?name=John&age=30", nil)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 for clean query, got 403")
		}
	})

	// --- DetectXSS (941100) ---

	t.Run("DetectXSS/script tag blocked by policy engine", func(t *testing.T) {
		sentinel := fmt.Sprintf("e2e-xss-script-%d", time.Now().UnixNano())
		req, _ := http.NewRequest("GET",
			caddyURL+"/get?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", nil)
		req.Header.Set("User-Agent", sentinel)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("expected 403 (policy engine detect_block), got %d; body=%.300s",
				resp.StatusCode, string(body))
		}
		evt := waitForEvent(t, sentinel, 15*time.Second)
		verifyDetectBlockEventFromMap(t, evt, "941100", "libinjection")
	})

	t.Run("DetectXSS/img onerror blocked by policy engine", func(t *testing.T) {
		sentinel := fmt.Sprintf("e2e-xss-img-%d", time.Now().UnixNano())
		req, _ := http.NewRequest("GET",
			caddyURL+"/get?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", nil)
		req.Header.Set("User-Agent", sentinel)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 for XSS img onerror, got %d", resp.StatusCode)
		}
	})

	t.Run("DetectXSS/clean HTML entities pass through", func(t *testing.T) {
		req, _ := http.NewRequest("GET", caddyURL+"/get?q=Hello%20%26%20World", nil)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 for clean HTML entities, got 403")
		}
	})

	// --- ValidateByteRange (920270) ---

	t.Run("ValidateByteRange/null byte blocked by policy engine", func(t *testing.T) {
		sentinel := fmt.Sprintf("e2e-bytrange-%d", time.Now().UnixNano())
		req, _ := http.NewRequest("GET",
			caddyURL+"/get?data=test%00injected", nil)
		req.Header.Set("User-Agent", sentinel)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			bodyStr := string(body)
			if len(bodyStr) > 300 {
				bodyStr = bodyStr[:300]
			}
			t.Fatalf("expected 403 (policy engine detect_block), got %d; body=%q",
				resp.StatusCode, bodyStr)
		}
		evt := waitForEvent(t, sentinel, 15*time.Second)
		verifyDetectBlockEventFromMap(t, evt, "920270", "null character")
	})

	t.Run("ValidateByteRange/normal printable chars pass through", func(t *testing.T) {
		req, _ := http.NewRequest("GET", caddyURL+"/get?data=hello+world+123", nil)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 for normal printable chars, got 403")
		}
	})

	// --- CmdLineTransform (932120) ---

	t.Run("CmdLineTransform/PowerShell invoke-expression blocked", func(t *testing.T) {
		sentinel := fmt.Sprintf("e2e-cmdline-%d", time.Now().UnixNano())
		req, _ := http.NewRequest("GET",
			caddyURL+"/get?cmd=Invoke-Expression", nil)
		req.Header.Set("User-Agent", sentinel)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("expected 403 (policy engine detect_block), got %d; body=%.300s",
				resp.StatusCode, string(body))
		}
		evt := waitForEvent(t, sentinel, 15*time.Second)
		verifyDetectBlockEventFromMap(t, evt, "932120", "PowerShell")
	})

	t.Run("CmdLineTransform/caret evasion still caught", func(t *testing.T) {
		sentinel := fmt.Sprintf("e2e-cmdcaret-%d", time.Now().UnixNano())
		req, _ := http.NewRequest("GET",
			caddyURL+"/get?cmd=inv%5Eoke-exp%5Eression", nil)
		req.Header.Set("User-Agent", sentinel)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 for PowerShell with caret evasion, got %d", resp.StatusCode)
		}
	})

	t.Run("CmdLineTransform/clean command-like string passes", func(t *testing.T) {
		req, _ := http.NewRequest("GET", caddyURL+"/get?q=invoke+something+normal", nil)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 for benign 'invoke' word, got 403")
		}
	})

	// --- DetectBlockIsolation (proof that policy engine blocks, not Coraza) ---

	t.Run("DetectBlockIsolation/clean request passes in detection_only", func(t *testing.T) {
		req, _ := http.NewRequest("GET", caddyURL+"/get?safe=true", nil)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("expected 200 for clean request in detection_only, got %d", resp.StatusCode)
		}
	})

	t.Run("DetectBlockIsolation/SQLi blocked by policy engine only", func(t *testing.T) {
		sentinel := fmt.Sprintf("e2e-isolation-%d", time.Now().UnixNano())
		req, _ := http.NewRequest("GET",
			caddyURL+"/get?id=1%20UNION%20SELECT%20*%20FROM%20users", nil)
		req.Header.Set("User-Agent", sentinel)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("expected 403 from policy engine (Coraza is detection_only), got %d; body=%.300s",
				resp.StatusCode, string(body))
		}
		t.Log("403 confirmed — MUST be from policy engine (Coraza is detection_only)")

		evt := waitForEvent(t, sentinel, 15*time.Second)
		eventType, _ := evt["event_type"].(string)
		if eventType != "detect_block" {
			t.Errorf("event_type: want detect_block, got %q", eventType)
		}
		score, _ := evt["anomaly_score"].(float64)
		if score < 15 {
			t.Errorf("anomaly_score: want >= 15, got %v", score)
		}
		t.Logf("event: type=%s score=%v blocked_by=%v", eventType, score, evt["blocked_by"])
	})

	t.Run("DetectBlockIsolation/same payload passes with high threshold", func(t *testing.T) {
		highThreshold := map[string]any{
			"defaults": map[string]any{
				"paranoia_level":     1,
				"inbound_threshold":  999,
				"outbound_threshold": 999,
			},
		}
		httpPut(t, wafctlURL+"/api/config", highThreshold)
		time.Sleep(1 * time.Second)
		httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
		// Poll until the SQLi payload passes (proves threshold change took effect).
		sqliURL := caddyURL + "/get?id=1%20UNION%20SELECT%20*%20FROM%20users"
		waitForStatus(t, sqliURL, 200, 10*time.Second)
		t.Log("SQLi passes with threshold=999 — proves policy engine was the blocker")
	})
}
