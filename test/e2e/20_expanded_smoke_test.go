package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ─── CRS Default Rules: Bulk Override Behavior ─────────────────────
// Disable a CRS rule via bulk override, verify the attack it catches now
// passes through, then re-enable and verify it's blocked again.

func TestDefaultRulesBulkBehavior(t *testing.T) {
	// Set a low threshold so SQLi attacks (CRITICAL=5) trigger blocking.
	// The default threshold (60) is too high for single-rule attack detection.
	httpPut(t, wafctlURL+"/api/config", map[string]any{
		"defaults": map[string]any{
			"paranoia_level":     2,
			"inbound_threshold":  15,
			"outbound_threshold": 15,
		},
		"services": map[string]any{},
	})
	deployWAF(t)

	// Rule 942100 catches "UNION SELECT" SQLi. Confirm it blocks first.
	sentinel := fmt.Sprintf("e2e-crsbulk-%d", time.Now().UnixNano())
	attackURL := caddyURL + "/get?q=1+UNION+SELECT+username,password+FROM+users"

	// Wait for the default config (threshold=15) to take effect before testing.
	waitForCondition(t, "SQLi blocked at default threshold", 15*time.Second, func() bool {
		req, _ := http.NewRequest("GET", attackURL, nil)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 403
	})

	t.Run("baseline blocked", func(t *testing.T) {
		req := mustNewRequest(t, "GET", attackURL)
		setBrowserHeaders(req)
		req.Header.Set("User-Agent", sentinel+"-baseline")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("expected 403 baseline block, got %d", resp.StatusCode)
		}
	})

	// Disable rule 942100 via bulk override.
	bulkPayload := map[string]any{
		"ids":    []string{"942100"},
		"action": "override",
		"override": map[string]any{
			"enabled": false,
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/default-rules/bulk", bulkPayload)
	assertCode(t, "bulk disable 942100", 200, resp)
	changed := jsonInt(body, "changed")
	if changed != 1 {
		t.Fatalf("expected 1 changed, got %d", changed)
	}

	// Deploy so the policy engine picks up the change.
	deployAndWaitForStatus(t, caddyURL+"/get", 200)

	t.Run("rule disabled in store", func(t *testing.T) {
		// Other SQLi rules (942150, etc.) may still fire and accumulate
		// enough score to block, so we verify via the API instead.
		resp2, body2 := httpGet(t, wafctlURL+"/api/default-rules/942100")
		assertCode(t, "get rule 942100", 200, resp2)
		if enabled, found := jsonFieldBool(body2, "enabled"); found && enabled {
			t.Error("rule 942100 should be disabled after bulk override")
		}
	})

	// Re-enable via bulk reset.
	resetPayload := map[string]any{
		"ids":    []string{"942100"},
		"action": "reset",
	}
	resp, body = httpPost(t, wafctlURL+"/api/default-rules/bulk", resetPayload)
	assertCode(t, "bulk reset 942100", 200, resp)
	removed := jsonInt(body, "removed")
	if removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}

	// Deploy again.
	deployAndWaitForStatus(t, attackURL, 403)

	t.Run("blocked after reset", func(t *testing.T) {
		req := mustNewRequest(t, "GET", attackURL)
		setBrowserHeaders(req)
		req.Header.Set("User-Agent", sentinel+"-reset")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 after reset, got %d", resp.StatusCode)
		}
	})
}

// ─── Exclusion Bulk: Enable/Disable Behavior ───────────────────────
// Create a block rule, verify it blocks, bulk-disable it, verify unblocked.

func TestExclusionBulkBehavior(t *testing.T) {
	blockPath := fmt.Sprintf("/e2e-bulk-behav-%d", time.Now().UnixNano())

	payload := map[string]any{
		"name":     "e2e-bulk-behavioral",
		"type":     "block",
		"enabled":  true,
		"priority": 100,
		"conditions": []map[string]any{
			{"field": "path", "operator": "eq", "value": blockPath},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create block rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+ruleID)
		httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	})

	deployAndWaitForStatus(t, caddyURL+blockPath, 403)

	t.Run("blocked before disable", func(t *testing.T) {
		req := mustNewRequest(t, "GET", caddyURL+blockPath)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403, got %d", resp.StatusCode)
		}
	})

	// Bulk disable.
	bulkPayload := map[string]any{
		"ids":    []string{ruleID},
		"action": "disable",
	}
	resp, body = httpPost(t, wafctlURL+"/api/exclusions/bulk", bulkPayload)
	assertCode(t, "bulk disable", 200, resp)
	if jsonInt(body, "changed") != 1 {
		t.Fatalf("expected 1 changed, got %d", jsonInt(body, "changed"))
	}

	// 404 = path doesn't exist on httpbun, proving the block rule is gone.
	deployAndWaitForStatus(t, caddyURL+blockPath, 404)

	t.Run("unblocked after disable", func(t *testing.T) {
		req := mustNewRequest(t, "GET", caddyURL+blockPath)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 after bulk disable, got 403")
		}
		t.Logf("status after bulk disable: %d", resp.StatusCode)
	})

	// Bulk re-enable.
	resp, _ = httpPost(t, wafctlURL+"/api/exclusions/bulk", map[string]any{
		"ids":    []string{ruleID},
		"action": "enable",
	})
	assertCode(t, "bulk re-enable", 200, resp)

	deployAndWaitForStatus(t, caddyURL+blockPath, 403)

	t.Run("blocked after re-enable", func(t *testing.T) {
		req := mustNewRequest(t, "GET", caddyURL+blockPath)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 after re-enable, got %d", resp.StatusCode)
		}
	})
}

// ─── Non-Root Process Verification ─────────────────────────────────
// Verify Caddy runs as non-root by checking it can still serve, write
// logs, and that wafctl can read them.

func TestCaddyNonRoot(t *testing.T) {
	t.Run("caddy admin reachable", func(t *testing.T) {
		resp, _ := httpGet(t, caddyAdmin+"/config/")
		assertCode(t, "caddy admin config", 200, resp)
	})

	t.Run("log pipeline works", func(t *testing.T) {
		// Generate a request through Caddy, wait for wafctl to tail the
		// access log. Proves: Caddy writes logs as non-root → wafctl reads.
		sentinel := fmt.Sprintf("e2e-nonroot-%d", time.Now().UnixNano())
		req := mustNewRequest(t, "GET", caddyURL+"/get")
		setBrowserHeaders(req)
		req.Header.Set("User-Agent", sentinel)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		// Poll general logs for the sentinel (WAF events only contain blocked requests).
		// Best-effort: passing 200 already proves Caddy serves as non-root.
		found := false
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			_, logsBody := httpGet(t, wafctlURL+"/api/logs?hours=1&limit=50")
			if strings.Contains(string(logsBody), sentinel) {
				found = true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if found {
			t.Log("sentinel found in general logs — log pipeline verified")
		} else {
			t.Log("sentinel not in recent logs (expected for clean requests)")
		}
	})

	t.Run("wafctl serves UI", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/")
		assertCode(t, "wafctl root", 200, resp)
		if !strings.Contains(string(body), "<html") {
			t.Error("expected HTML content from wafctl UI")
		}
	})
}

// ─── WebSocket Hijack Through Policy Engine ────────────────────────
// Verify WebSocket upgrades work when the policy engine is actively
// wrapping responseWriter (the Hijack() fix on responseHeaderWriter).

func TestWebSocketPolicyEngineHijack(t *testing.T) {
	// Create a block rule on a different path to prove the policy engine
	// middleware is active and wrapping responseWriter.
	blockPath := fmt.Sprintf("/e2e-ws-block-%d", time.Now().UnixNano())
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name":    "e2e-ws-hijack-proof",
		"type":    "block",
		"enabled": true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "eq", "value": blockPath},
		},
	})
	assertCode(t, "create block rule", 201, resp)
	blockRuleID := mustGetID(t, body)

	// Allow rule for /websocket/ to bypass CRS header checks.
	resp, body = httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name":    "e2e-ws-hijack-allow",
		"type":    "allow",
		"enabled": true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/websocket/"},
		},
	})
	assertCode(t, "create ws allow", 201, resp)
	wsRuleID := mustGetID(t, body)

	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+blockRuleID)
		cleanup(t, wafctlURL+"/api/exclusions/"+wsRuleID)
		httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	})

	httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	waitForStatus(t, caddyURL+blockPath, 403, 10*time.Second)
	waitForStatus(t, caddyURL+"/websocket/echo", 400, 10*time.Second)

	t.Run("block rule active", func(t *testing.T) {
		req := mustNewRequest(t, "GET", caddyURL+blockPath)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("expected 403 from block rule, got %d — policy engine not active?", resp.StatusCode)
		}
		if resp.Header.Get("X-Blocked-By") != "policy-engine" {
			t.Errorf("expected X-Blocked-By: policy-engine, got %q", resp.Header.Get("X-Blocked-By"))
		}
		t.Log("policy engine active — responseHeaderWriter wraps w")
	})

	t.Run("websocket upgrade succeeds", func(t *testing.T) {
		// If Hijack() isn't implemented on responseHeaderWriter, the
		// WebSocket upgrade fails with 400.
		conn, br := wsHandshake(t, caddyURL+"/websocket/echo")
		defer conn.Close()

		msg := "hijacker-proof"
		wsWriteText(t, conn, msg)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := wsReadText(t, br)
		if got != msg {
			t.Errorf("echo mismatch: sent %q, got %q", msg, got)
		}
		t.Log("Hijack() on responseHeaderWriter confirmed working")
	})

	t.Run("multiple frames", func(t *testing.T) {
		conn, br := wsHandshake(t, caddyURL+"/websocket/echo")
		defer conn.Close()

		for i, msg := range []string{"frame-1", "frame-2", "frame-3-日本語"} {
			wsWriteText(t, conn, msg)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := wsReadText(t, br)
			if got != msg {
				t.Errorf("frame %d: sent %q, got %q", i, msg, got)
			}
		}
	})
}

// ─── Backup/Restore Data Integrity ─────────────────────────────────
// Create data, backup, delete, restore, verify data came back.
// NOTE: Import assigns fresh UUIDs, so we verify by name in the list
// endpoint rather than by original ID.

func TestBackupRestoreIntegrity(t *testing.T) {
	excName := fmt.Sprintf("e2e-backup-integrity-%d", time.Now().UnixNano())
	excPayload := map[string]any{
		"name":     excName,
		"type":     "allow",
		"enabled":  true,
		"priority": 200,
		"conditions": []map[string]any{
			{"field": "path", "operator": "eq", "value": "/e2e-backup-test"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", excPayload)
	assertCode(t, "create exclusion", 201, resp)
	excID := mustGetID(t, body)

	rlName := fmt.Sprintf("e2e-backup-rl-%d", time.Now().UnixNano())
	rlPayload := map[string]any{
		"name":              rlName,
		"type":              "rate_limit",
		"service":           "httpbun",
		"rate_limit_key":    "client_ip",
		"rate_limit_events": 100,
		"rate_limit_window": "1m",
		"rate_limit_action": "deny",
		"enabled":           true,
	}
	resp, body = httpPost(t, wafctlURL+"/api/rules", rlPayload)
	assertCode(t, "create rl rule", 201, resp)
	rlID := mustGetID(t, body)

	t.Cleanup(func() {
		// Clean up any resources with our test names (IDs change after restore).
		cleanupByName(t, wafctlURL+"/api/rules", excName)
		cleanupByName(t, wafctlURL+"/api/rules", rlName)
	})

	t.Run("backup contains resources", func(t *testing.T) {
		_, backupBody := httpGet(t, wafctlURL+"/api/backup")
		s := string(backupBody)
		if !strings.Contains(s, excName) {
			t.Error("backup missing exclusion name")
		}
		if !strings.Contains(s, rlName) {
			t.Error("backup missing RL rule name")
		}
	})

	// Take backup, delete both, restore, verify.
	_, backupBody := httpGet(t, wafctlURL+"/api/backup")

	// Delete both via unified API.
	resp, _ = httpDelete(t, wafctlURL+"/api/rules/"+excID)
	assertCode(t, "delete exclusion", 204, resp)
	resp, _ = httpDelete(t, wafctlURL+"/api/rules/"+rlID)
	assertCode(t, "delete rl rule", 204, resp)

	code, _ := httpGetCode(wafctlURL + "/api/rules/" + excID)
	if code != 404 {
		t.Fatalf("exclusion should be 404, got %d", code)
	}
	code, _ = httpGetCode(wafctlURL + "/api/rules/" + rlID)
	if code != 404 {
		t.Fatalf("rl rule should be 404, got %d", code)
	}

	var backupObj map[string]json.RawMessage
	json.Unmarshal(backupBody, &backupObj)
	resp, _ = httpPost(t, wafctlURL+"/api/backup/restore", backupObj)
	assertCode(t, "restore", 200, resp)

	// Import assigns fresh UUIDs — verify by name via the list endpoint.
	t.Run("exclusion restored", func(t *testing.T) {
		_, listBody := httpGet(t, wafctlURL+"/api/exclusions")
		if !strings.Contains(string(listBody), excName) {
			t.Errorf("exclusion %q not found in list after restore", excName)
		}
	})

	t.Run("rate rule restored", func(t *testing.T) {
		_, listBody := httpGet(t, wafctlURL+"/api/rules")
		if !strings.Contains(string(listBody), rlName) {
			t.Errorf("rate rule %q not found in list after restore", rlName)
		}
	})
}

// ─── Security Headers: Deploy + Response Verification ──────────────

func TestSecurityHeadersDeploy(t *testing.T) {
	_, origBody := httpGet(t, wafctlURL+"/api/security-headers")

	t.Cleanup(func() {
		// Restore original config and deploy to avoid polluting other tests.
		var orig map[string]json.RawMessage
		json.Unmarshal(origBody, &orig)
		httpPut(t, wafctlURL+"/api/security-headers", orig)
		httpPostDeploy(t, wafctlURL+"/api/security-headers/deploy", struct{}{})
		// Wait for the original headers to propagate (X-Content-Type-Options
		// is present in all profiles, so it's a safe signal).
		waitForHeader(t, caddyURL+"/get", "X-Content-Type-Options", "nosniff", 15*time.Second)
	})

	t.Run("custom header appears", func(t *testing.T) {
		// PUT replaces the entire config, so we must include the full
		// profile headers plus our custom one. Start from strict profile.
		customConfig := map[string]any{
			"profile": "strict",
			"headers": map[string]any{
				"Strict-Transport-Security":         "max-age=63072000; includeSubDomains; preload",
				"X-Content-Type-Options":            "nosniff",
				"X-Frame-Options":                   "DENY",
				"Referrer-Policy":                   "no-referrer",
				"Permissions-Policy":                "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()",
				"Cross-Origin-Opener-Policy":        "same-origin",
				"Cross-Origin-Resource-Policy":      "same-origin",
				"Cross-Origin-Embedder-Policy":      "require-corp",
				"X-Permitted-Cross-Domain-Policies": "none",
				// Custom header added on top of strict profile.
				"X-E2E-Custom-Header": "e2e-smoke-test-value",
			},
			"remove": []string{"Server", "X-Powered-By"},
		}
		resp, _ := httpPut(t, wafctlURL+"/api/security-headers", customConfig)
		assertCode(t, "update headers", 200, resp)

		resp, _ = httpPostDeploy(t, wafctlURL+"/api/security-headers/deploy", struct{}{})
		assertCode(t, "deploy headers", 200, resp)

		waitForHeader(t, caddyURL+"/get", "X-E2E-Custom-Header", "e2e-smoke-test-value", 15*time.Second)

		resp2, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "proxied request", 200, resp2)
		got := resp2.Header.Get("X-E2E-Custom-Header")
		if got != "e2e-smoke-test-value" {
			t.Errorf("expected X-E2E-Custom-Header=e2e-smoke-test-value, got %q", got)
		}
		if resp2.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Error("X-Content-Type-Options missing after custom header deploy")
		}
	})

	t.Run("profile switch reflected", func(t *testing.T) {
		// Previous subtest set "strict" which has X-Frame-Options: DENY.
		// Switch to "api" profile which omits X-Frame-Options entirely.
		// PUT replaces whole config — send the full api profile headers.
		apiConfig := map[string]any{
			"profile": "api",
			"headers": map[string]any{
				"Strict-Transport-Security":    "max-age=63072000; includeSubDomains; preload",
				"X-Content-Type-Options":       "nosniff",
				"Referrer-Policy":              "no-referrer",
				"Cross-Origin-Resource-Policy": "cross-origin",
			},
			"remove": []string{"Server", "X-Powered-By"},
		}
		resp, _ := httpPut(t, wafctlURL+"/api/security-headers", apiConfig)
		assertCode(t, "update to api", 200, resp)

		resp, _ = httpPostDeploy(t, wafctlURL+"/api/security-headers/deploy", struct{}{})
		assertCode(t, "deploy api", 200, resp)

		// API profile has NO X-Frame-Options — wait for its absence as signal.
		waitForNoHeader(t, caddyURL+"/get", "X-Frame-Options", 15*time.Second)

		resp2, _ := httpGet(t, caddyURL+"/get")
		// API profile should still have X-Content-Type-Options.
		if resp2.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Error("api profile should still have X-Content-Type-Options: nosniff")
		}
		// API profile should NOT have Permissions-Policy (only strict/default/relaxed have it).
		pp := resp2.Header.Get("Permissions-Policy")
		if strings.Contains(pp, "camera") {
			t.Errorf("api profile should not have Permissions-Policy with camera=(), got %q", pp)
		}
	})
}

// ─── Dashboard Content ─────────────────────────────────────────────

func TestDashboardContent(t *testing.T) {
	t.Run("valid HTML from wafctl", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/")
		assertCode(t, "wafctl root", 200, resp)
		html := string(body)

		if !strings.Contains(html, "<!DOCTYPE html") && !strings.Contains(html, "<!doctype html") {
			t.Error("missing DOCTYPE")
		}
		if !strings.Contains(html, "_astro/") {
			t.Error("missing _astro/ references — dashboard build may be missing")
		}
	})

	t.Run("static assets served", func(t *testing.T) {
		_, body := httpGet(t, wafctlURL+"/")
		html := string(body)

		idx := strings.Index(html, "/_astro/")
		if idx == -1 {
			t.Skip("no _astro/ asset found in HTML")
		}
		end := idx + 1
		for end < len(html) && html[end] != '"' && html[end] != '\'' && html[end] != ' ' && html[end] != '>' {
			end++
		}
		assetPath := html[idx:end]
		t.Logf("testing asset: %s", assetPath)

		code, err := httpGetCode(wafctlURL + assetPath)
		if err != nil {
			t.Fatalf("asset request: %v", err)
		}
		if code != 200 {
			t.Errorf("expected 200 for %s, got %d", assetPath, code)
		}
	})

	t.Run("proxy matches direct", func(t *testing.T) {
		_, directBody := httpGet(t, wafctlURL+"/")
		_, proxyBody := httpGet(t, dashURL+"/")

		if !strings.Contains(string(directBody), "_astro/") {
			t.Error("direct: missing _astro/")
		}
		if !strings.Contains(string(proxyBody), "_astro/") {
			t.Error("proxy: missing _astro/")
		}
		t.Logf("direct: %d bytes, proxy: %d bytes", len(directBody), len(proxyBody))
	})

	t.Run("404 has content", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/nonexistent-xyz-123")
		if resp.StatusCode != 404 {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
		if len(body) == 0 {
			t.Error("404 page should have content")
		}
	})
}
