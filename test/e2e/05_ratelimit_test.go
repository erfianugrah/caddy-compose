package e2e_test

import "testing"

// ════════════════════════════════════════════════════════════════════
//  9. Rate Limit Rules (unified /api/rules endpoint)
// ════════════════════════════════════════════════════════════════════

func TestRateLimitRules(t *testing.T) {
	// List — response is a bare JSON array []Rule
	t.Run("list", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rules")
		assertCode(t, "list", 200, resp)
		n := jsonArrayLen(body)
		if n < 0 {
			t.Errorf("expected JSON array, got: %.200s", string(body))
		}
	})

	// Create — must return 201 Created
	var rlID string
	t.Run("create", func(t *testing.T) {
		payload := map[string]any{
			"name":              "e2e-rl-test",
			"type":              "rate_limit",
			"service":           "httpbun",
			"rate_limit_key":    "client_ip",
			"rate_limit_events": 100,
			"rate_limit_window": "1m",
			"rate_limit_action": "deny",
			"enabled":           true,
		}
		resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "create RL rule", 201, resp)
		rlID = mustGetID(t, body)
		assertField(t, "create", body, "name", "e2e-rl-test")
		assertField(t, "create", body, "rate_limit_action", "deny")
	})

	if rlID == "" {
		t.Fatal("no RL rule id, cannot continue")
	}
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+rlID) })

	// Get
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rules/"+rlID)
		assertCode(t, "get", 200, resp)
		assertField(t, "get", body, "name", "e2e-rl-test")
		assertField(t, "get", body, "id", rlID)
	})

	// Update — PUT requires full object
	t.Run("update", func(t *testing.T) {
		payload := map[string]any{
			"name":              "e2e-rl-test",
			"type":              "rate_limit",
			"service":           "httpbun",
			"rate_limit_key":    "client_ip",
			"rate_limit_events": 200,
			"rate_limit_window": "1m",
			"rate_limit_action": "deny",
			"enabled":           true,
		}
		resp, body := httpPut(t, wafctlURL+"/api/rules/"+rlID, payload)
		assertCode(t, "update", 200, resp)
		events := jsonInt(body, "rate_limit_events")
		if events != 200 {
			t.Errorf("expected rate_limit_events=200, got %d", events)
		}
		assertField(t, "update", body, "name", "e2e-rl-test")
	})

	// Deploy — must return status "deployed". Rate limit rules are deployed via
	// policy-rules.json hot-reload so Caddy itself is not restarted (reloaded=false).
	t.Run("deploy", func(t *testing.T) {
		resp, body := httpPostDeploy(t, wafctlURL+"/api/deploy", struct{}{})
		assertCode(t, "deploy", 200, resp)
		assertField(t, "deploy status", body, "status", "deployed")
		assertField(t, "deploy reloaded", body, "reloaded", "false")
	})

	// Read-only endpoints — use httpGetRetry because these run immediately after
	// deploy which may briefly cause EOF/connection-reset as Caddy reloads.
	readOnly := []string{
		"/api/rate-limits/summary?hours=1",
		"/api/rate-limits/events?hours=1",
		"/api/rate-rules/hits",
		"/api/rate-rules/advisor?window=1m",
	}
	for _, ep := range readOnly {
		t.Run("GET "+ep, func(t *testing.T) {
			resp, _ := httpGetRetry(t, wafctlURL+ep, 3)
			assertCode(t, ep, 200, resp)
		})
	}

	// Export — response is RuleExport: {version, exported_at, rules: [...]}
	t.Run("export", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rules/export")
		assertCode(t, "export", 200, resp)
		version := jsonInt(body, "version")
		if version != 1 {
			t.Errorf("expected export version=1, got %d", version)
		}
		// exclusions array should exist inside the export object (unified format)
		exclusionsRaw := jsonFieldArray(body, "exclusions")
		if exclusionsRaw == nil {
			t.Errorf("expected exclusions array in export, got: %.200s", string(body))
		}
	})

	// Delete — unified API returns 204 No Content
	t.Run("delete", func(t *testing.T) {
		resp, _ := httpDelete(t, wafctlURL+"/api/rules/"+rlID)
		assertCode(t, "delete RL rule", 204, resp)
		rlID = "" // prevent cleanup double-delete
	})
}

// ════════════════════════════════════════════════════════════════════
// 10. CSP Management
// ════════════════════════════════════════════════════════════════════
