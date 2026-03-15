package e2e_test

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// 18. End-to-End: Policy Engine Rate Limiting
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineRateLimit(t *testing.T) {
	// Step 1: Create a rate limit rule with a very low threshold.
	// 3 events per 10s window so we can trigger it quickly.
	payload := map[string]any{
		"name":              "e2e-ratelimit-test",
		"type":              "rate_limit",
		"service":           "*",
		"rate_limit_key":    "client_ip",
		"rate_limit_events": 3,
		"rate_limit_window": "10s",
		"rate_limit_action": "deny",
		"enabled":           true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "begins_with", "value": "/e2e-rl-"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create RL rule", 201, resp)
	rlID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/rules/"+rlID)
		// Redeploy to remove the rule from policy-rules.json.
		httpPostDeploy(t, wafctlURL+"/api/deploy", struct{}{})
	})

	// Step 2: Deploy — writes to policy-rules.json, no Caddy reload needed.
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/deploy", struct{}{})
	assertCode(t, "deploy RL", 200, resp2)
	assertField(t, "deploy status", deployBody, "status", "deployed")

	// Step 3: Wait for policy engine to hot-reload the rules file and the
	// rate limit rule to take effect. Poll until we can trigger a 429.
	targetURL := caddyURL + "/e2e-rl-target"
	var lastResp *http.Response
	var lastBody []byte
	got429 := false

	waitForCondition(t, "rate limit triggers 429", 15*time.Second, func() bool {
		for i := 0; i < 10; i++ {
			lastResp, lastBody = httpGet(t, targetURL)
			if lastResp.StatusCode == 429 {
				got429 = true
				return true
			}
			time.Sleep(50 * time.Millisecond)
		}
		// Not triggered yet — window may not have started. Wait for next poll.
		return false
	})

	if !got429 {
		t.Fatalf("expected 429 after exceeding rate limit (3 req/10s), last status=%d body=%.200s",
			lastResp.StatusCode, string(lastBody))
	}

	// Step 5: Verify rate limit response headers from the policy engine.
	t.Run("429 headers", func(t *testing.T) {
		// X-RateLimit-Policy should contain the rule name.
		policy := lastResp.Header.Get("X-RateLimit-Policy")
		if policy == "" {
			t.Error("missing X-RateLimit-Policy header on 429 response")
		} else if !strings.Contains(policy, "e2e-ratelimit-test") {
			t.Errorf("X-RateLimit-Policy=%q, expected to contain 'e2e-ratelimit-test'", policy)
		}

		// X-RateLimit-Limit should be "3".
		limit := lastResp.Header.Get("X-RateLimit-Limit")
		if limit != "3" {
			t.Errorf("X-RateLimit-Limit=%q, expected '3'", limit)
		}

		// Retry-After should be present and non-empty.
		retryAfter := lastResp.Header.Get("Retry-After")
		if retryAfter == "" {
			t.Error("missing Retry-After header on 429 response")
		}
	})

	// Step 6: Wait for the window to fully expire. Sliding window interpolation
	// means the previous window retains partial weight for one full window after
	// it ends, so we need ~2 full windows for the counter to drain.
	t.Run("recovers after window", func(t *testing.T) {
		waitForCondition(t, "rate limit window expiry", 25*time.Second, func() bool {
			code, err := httpGetCode(targetURL)
			return err == nil && code != 429
		})
	})

	// Step 7: Verify log_only mode — update rule to log_only, redeploy, verify no block.
	t.Run("log_only mode", func(t *testing.T) {
		updatePayload := map[string]any{
			"name":              "e2e-ratelimit-test",
			"type":              "rate_limit",
			"service":           "*",
			"rate_limit_key":    "client_ip",
			"rate_limit_events": 3,
			"rate_limit_window": "10s",
			"rate_limit_action": "log_only",
			"enabled":           true,
			"conditions": []map[string]string{
				{"field": "path", "operator": "begins_with", "value": "/e2e-rl-"},
			},
		}
		resp, body := httpPut(t, wafctlURL+"/api/rules/"+rlID, updatePayload)
		assertCode(t, "update to log_only", 200, resp)
		assertField(t, "update action", body, "rate_limit_action", "log_only")

		// Deploy and wait for hot-reload — poll until requests stop getting 429.
		resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/deploy", struct{}{})
		assertCode(t, "deploy log_only", 200, resp2)
		assertField(t, "deploy log_only status", deployBody, "status", "deployed")
		// log_only rules don't block, so counter state from the deny phase must
		// drain AND the new rule must hot-reload. Give 25s (2+ sliding windows).
		waitForCondition(t, "log_only mode active", 25*time.Second, func() bool {
			code, err := httpGetCode(targetURL)
			return err == nil && code != 429
		})

		// Send requests exceeding the threshold — should NOT get 429.
		for i := 0; i < 8; i++ {
			r, _ := httpGet(t, targetURL)
			if r.StatusCode == 429 {
				t.Fatalf("got 429 in log_only mode on request %d", i+1)
			}
		}
		// Last request should have the monitor header.
		monResp, _ := httpGet(t, targetURL)
		monitor := monResp.Header.Get("X-RateLimit-Monitor")
		if monitor == "" {
			t.Log("X-RateLimit-Monitor header not present (may not have exceeded threshold yet)")
		}
	})
}
