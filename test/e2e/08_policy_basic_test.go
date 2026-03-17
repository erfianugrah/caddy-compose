package e2e_test

import (
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// 16. Policy Engine — Block/Honeypot/Allow via Caddy Plugin
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineBlock(t *testing.T) {
	ensureDefaultConfig(t)
	deployWAF(t)
	// Create a block rule for a specific path.
	payload := map[string]any{
		"name":        "e2e-policy-block",
		"type":        "block",
		"description": "Block /e2e-blocked path",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "path", "operator": "begins_with", "value": "/e2e-blocked"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create block rule", 201, resp)
	blockID := mustGetID(t, body)
	// Don't deploy in cleanup — avoids mtime race with next test's deploy.
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+blockID) })

	// Deploy — triggers policy-rules.json generation + Caddy reload.
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")

	// Wait for plugin hot reload.
	waitForStatus(t, caddyURL+"/e2e-blocked", 403, 10*time.Second)

	t.Run("blocked path returns 403 with policy-engine header", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-blocked")
		assertCode(t, "block", 403, resp)
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("unblocked path still works", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "unblocked", 200, resp)
	})
}

func TestPolicyEngineHoneypot(t *testing.T) {
	ensureDefaultConfig(t)
	deployWAF(t)
	// Create a block rule with honeypot tag and in operator — tests exact matching.
	payload := map[string]any{
		"name":        "e2e-honeypot",
		"type":        "block",
		"description": "Honeypot paths",
		"tags":        []string{"honeypot"},
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "path", "operator": "in", "value": "/e2e-trap|/e2e-honeypot"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create honeypot block rule", 201, resp)
	hpID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+hpID) })

	// Deploy and wait for honeypot rule to take effect.
	deployAndWaitForStatus(t, caddyURL+"/e2e-trap", 403)

	t.Run("honeypot path blocked", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-trap")
		assertCode(t, "honeypot", 403, resp)
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("in operator exact match — /e2e-trap-extended NOT blocked", func(t *testing.T) {
		// This is the core security fix: @pm /e2e-trap would match /e2e-trap-extended,
		// but the plugin's hash set does NOT. httpbun returns 404 for unknown paths,
		// which proves the request passed through without being blocked.
		code, err := httpGetCode(caddyURL + "/e2e-trap-extended")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 (not blocked), got 403 — in operator has substring match bug")
		}
	})

	t.Run("second honeypot path also blocked", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-honeypot")
		assertCode(t, "honeypot2", 403, resp)
	})
}

func TestPolicyEngineAllow(t *testing.T) {
	// Low threshold so a single CRS CRITICAL rule (score 5) triggers blocking.
	httpPut(t, wafctlURL+"/api/config", map[string]any{
		"defaults": map[string]any{"paranoia_level": 4, "inbound_threshold": 3, "outbound_threshold": 15},
		"services": map[string]any{},
	})
	deployWAF(t)
	// Use /get with UNION SELECT — triggers CRS 942100 (detectSQLi) at CRITICAL severity.
	sqliURL := caddyURL + "/get?q=1+UNION+SELECT+username,password+FROM+users"

	// Wait for the low threshold config to take effect.
	waitForStatus(t, sqliURL, 403, 15*time.Second)

	t.Run("pre-allow blocked", func(t *testing.T) {
		code, err := httpGetCode(sqliURL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 403 {
			t.Fatalf("expected 403 (WAF block), got %d — WAF not working", code)
		}
	})

	// Create an allow rule that bypasses WAF for /get path.
	payload := map[string]any{
		"name":        "e2e-policy-allow",
		"type":        "allow",
		"description": "Allow /get path via policy engine",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "uri_path", "operator": "eq", "value": "/get"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create allow rule", 201, resp)
	allowID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+allowID)
		// Redeploy to remove the allow rule from policy-rules.json,
		// otherwise subsequent tests see a stale WAF bypass.
		deployAndWaitForStatus(t, sqliURL, 403)
	})

	// Deploy and wait for allow rule to take effect.
	deployAndWaitForStatus(t, sqliURL, 200)

	t.Run("post-allow SQLi passes through", func(t *testing.T) {
		code, err := httpGetCode(sqliURL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 200 {
			t.Errorf("expected 200 (WAF bypass via policy engine allow), got %d", code)
		}
	})
}

func TestPolicyEngineBodyJSON(t *testing.T) {
	ensureDefaultConfig(t)
	deployWAF(t)
	// Create a block rule that matches a JSON body field: .action == "delete_all".
	payload := map[string]any{
		"name":        "e2e-body-json-block",
		"type":        "block",
		"description": "Block requests with dangerous action in JSON body",
		"enabled":     true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "begins_with", "value": "/post"},
			{"field": "body_json", "operator": "eq", "value": ".action:delete_all"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create body_json block rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	// Deploy and wait for body_json block rule to take effect.
	time.Sleep(1 * time.Second) // mtime boundary
	deployWAF(t)
	waitForCondition(t, "body_json block active", 10*time.Second, func() bool {
		code, err := httpPostRaw(caddyURL+"/post", []byte(`{"action":"delete_all"}`))
		return err == nil && code == 403
	})

	t.Run("matching JSON body blocked", func(t *testing.T) {
		dangerousBody := []byte(`{"action":"delete_all","target":"users"}`)
		code, err := httpPostRaw(caddyURL+"/post", dangerousBody)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 403 {
			t.Errorf("expected 403 (body_json block), got %d", code)
		}
	})

	t.Run("non-matching JSON body passes", func(t *testing.T) {
		// Use a minimal JSON body that won't trigger CRS SQL/XSS heuristics.
		safeBody := []byte(`{"ok":true}`)
		code, err := httpPostRaw(caddyURL+"/post", safeBody)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 (safe body should pass), got 403")
		}
	})

	t.Run("non-JSON body passes", func(t *testing.T) {
		plainBody := []byte(`just some plain text`)
		code, err := httpPostRaw(caddyURL+"/post", plainBody)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 (non-JSON body should pass), got 403")
		}
	})
}
