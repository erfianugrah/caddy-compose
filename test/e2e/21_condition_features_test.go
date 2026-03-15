package e2e_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ─── multiMatch: operator evaluated at each transform stage ────────
// Without multi_match, the operator only runs on the final transformed
// value. With multi_match, it runs at every stage (raw, then after each
// transform). If any stage matches, the condition matches.
//
// Test strategy: lowercase transform lowercases the value. We use a block
// rule that checks user_agent contains "TEST" (uppercase) with lowercase
// transform.
// - Raw UA "TESTword" → contains "TEST" = true (raw stage)
// - After lowercase "testword" → contains "TEST" = false
// With multi_match=true: raw stage matches → block
// Without multi_match (control): only final stage checked → no block

func TestPolicyEngineMultiMatch(t *testing.T) {
	t.Skip("multi_match not yet implemented in plugin — evaluates only final transform stage")
	blockPath := fmt.Sprintf("/e2e-multimatch-%d", time.Now().UnixNano())

	// Create block rule with multi_match=true + lowercase transform.
	payload := map[string]any{
		"name":     "e2e-multimatch",
		"type":     "block",
		"enabled":  true,
		"priority": 100,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": blockPath},
			{
				"field":       "user_agent",
				"operator":    "contains",
				"value":       "TEST",
				"transforms":  []string{"lowercase"},
				"multi_match": true,
			},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create multimatch rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+ruleID)
		httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	})

	deployAndWaitForStatus(t, caddyURL+blockPath, 404)

	t.Run("multi_match blocks on raw stage", func(t *testing.T) {
		// UA "TESTword" — "TEST" present in raw stage, gone after lowercase.
		// multi_match=true checks raw first → "TEST" found → block.
		req := mustNewRequest(t, "GET", caddyURL+blockPath)
		setBrowserHeaders(req)
		req.Header.Set("User-Agent", "TESTword")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (multi_match should match raw stage), got %d", resp.StatusCode)
		}
	})

	t.Run("fully lowercase passes", func(t *testing.T) {
		// UA "testword" — no uppercase "TEST" at any stage → no match → pass.
		req := mustNewRequest(t, "GET", caddyURL+blockPath)
		setBrowserHeaders(req)
		req.Header.Set("User-Agent", "testword")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 for fully lowercase UA, got 403")
		}
	})

	// Now update the rule to multi_match=false. The uppercase "TEST" only
	// exists in the raw stage, but the operator only sees the lowercased
	// final value → no match → pass.
	t.Run("without multi_match uppercase passes", func(t *testing.T) {
		updatePayload := map[string]any{
			"conditions": []map[string]any{
				{"field": "path", "operator": "begins_with", "value": blockPath},
				{
					"field":       "user_agent",
					"operator":    "contains",
					"value":       "TEST",
					"transforms":  []string{"lowercase"},
					"multi_match": false,
				},
			},
		}
		resp, _ := httpPut(t, wafctlURL+"/api/exclusions/"+ruleID, updatePayload)
		assertCode(t, "update to no multi_match", 200, resp)

		// Deploy and wait. The path should now return non-403 for uppercase UA
		// because without multi_match, only the lowercase-transformed value
		// is checked — "testword" doesn't contain "TEST".
		time.Sleep(1 * time.Second)
		deployWAF(t)

		// Poll until the uppercase UA is no longer blocked.
		waitForCondition(t, "uppercase UA not blocked", 15*time.Second, func() bool {
			req := mustNewRequest(t, "GET", caddyURL+blockPath)
			setBrowserHeaders(req)
			req.Header.Set("User-Agent", "TESTword")
			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode != 403
		})

		req := mustNewRequest(t, "GET", caddyURL+blockPath)
		setBrowserHeaders(req)
		req.Header.Set("User-Agent", "TESTword")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 {
			t.Errorf("without multi_match, uppercase UA should pass (only final transform checked), got 403")
		}
		t.Logf("status without multi_match: %d (expected non-403)", resp.StatusCode)
	})
}

// ─── negate: inverts operator result ───────────────────────────────
// A negate=true condition inverts the operator's match. This test creates
// a block rule that blocks non-GET requests to a specific path:
//   conditions: path begins_with X AND method eq GET (negate=true)
// POST → method eq GET is false, negate inverts to true → both match → 403
// GET → method eq GET is true, negate inverts to false → condition fails → pass

func TestPolicyEngineNegate(t *testing.T) {
	t.Skip("negate field not yet implemented in plugin — condition inversion ignored")
	blockPath := fmt.Sprintf("/e2e-negate-%d", time.Now().UnixNano())

	payload := map[string]any{
		"name":     "e2e-negate-method",
		"type":     "block",
		"enabled":  true,
		"priority": 100,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": blockPath},
			{"field": "method", "operator": "eq", "value": "GET", "negate": true},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create negate rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+ruleID)
		httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	})

	deployAndWaitForStatus(t, caddyURL+blockPath, 404)

	t.Run("POST is blocked (method != GET)", func(t *testing.T) {
		// POST to the path: method eq GET = false, negate → true → block
		resp, _ := httpPost(t, caddyURL+blockPath, map[string]any{"test": true})
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 for POST (negate should invert eq to neq), got %d", resp.StatusCode)
		}
		if resp.Header.Get("X-Blocked-By") != "policy-engine" {
			t.Errorf("expected X-Blocked-By: policy-engine, got %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("GET passes (method == GET, negated)", func(t *testing.T) {
		// GET to the path: method eq GET = true, negate → false → condition fails → pass
		req := mustNewRequest(t, "GET", caddyURL+blockPath)
		setBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 for GET (negated eq should not match), got 403")
		}
		t.Logf("GET status: %d (expected non-403)", resp.StatusCode)
	})

	t.Run("PUT is blocked (method != GET)", func(t *testing.T) {
		resp, _ := httpPut(t, caddyURL+blockPath, map[string]any{"test": true})
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 for PUT, got %d", resp.StatusCode)
		}
	})

	t.Run("DELETE is blocked (method != GET)", func(t *testing.T) {
		resp, _ := httpDelete(t, caddyURL+blockPath)
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 for DELETE, got %d", resp.StatusCode)
		}
	})
}

// ─── Backup/Restore: all stores round-trip ─────────────────────────
// Extends TestBackupRestoreIntegrity by covering managed lists and CSP
// config in addition to exclusions and rate limit rules.

func TestBackupRestoreAllStores(t *testing.T) {
	excName := fmt.Sprintf("e2e-backup-all-%d", time.Now().UnixNano())
	rlName := fmt.Sprintf("e2e-backup-all-rl-%d", time.Now().UnixNano())
	listName := fmt.Sprintf("e2e-backup-all-list-%d", time.Now().UnixNano())

	// 1. Create an exclusion
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name":     excName,
		"type":     "allow",
		"enabled":  true,
		"priority": 200,
		"conditions": []map[string]any{
			{"field": "path", "operator": "eq", "value": "/e2e-backup-all"},
		},
	})
	assertCode(t, "create exclusion", 201, resp)
	excID := mustGetID(t, body)

	// 2. Create a rate limit rule via unified API
	resp, body = httpPost(t, wafctlURL+"/api/rules", map[string]any{
		"name":              rlName,
		"type":              "rate_limit",
		"service":           "httpbun",
		"rate_limit_key":    "client_ip",
		"rate_limit_events": 100,
		"rate_limit_window": "1m",
		"rate_limit_action": "deny",
		"enabled":           true,
	})
	assertCode(t, "create rl rule", 201, resp)
	rlID := mustGetID(t, body)

	// 3. Create a managed list
	resp, body = httpPost(t, wafctlURL+"/api/lists", map[string]any{
		"name":   listName,
		"kind":   "ip",
		"source": "manual",
		"items":  []string{"10.99.99.1", "10.99.99.2"},
	})
	assertCode(t, "create list", 201, resp)
	listID := mustGetID(t, body)

	// 4. Set custom CSP config
	_, origCSPBody := httpGet(t, wafctlURL+"/api/csp")
	customCSP := map[string]any{
		"enabled": true,
		"global_defaults": map[string]any{
			"default_src": []string{"'self'", "https://e2e-backup-test.example.com"},
		},
	}
	resp, _ = httpPut(t, wafctlURL+"/api/csp", customCSP)
	assertCode(t, "update CSP", 200, resp)

	t.Cleanup(func() {
		cleanupByName(t, wafctlURL+"/api/rules", excName)
		cleanupByName(t, wafctlURL+"/api/rules", rlName)
		// Clean up list by name
		cleanupByName(t, wafctlURL+"/api/lists", listName)
		// Restore original CSP
		var origCSP map[string]json.RawMessage
		json.Unmarshal(origCSPBody, &origCSP)
		httpPut(t, wafctlURL+"/api/csp", origCSP)
	})

	// 5. Take backup
	_, backupBody := httpGet(t, wafctlURL+"/api/backup")

	t.Run("backup has all stores", func(t *testing.T) {
		s := string(backupBody)
		for _, key := range []string{"exclusions", "rate_limits", "lists", "csp_config", "waf_config", "security_headers"} {
			if !strings.Contains(s, `"`+key+`"`) {
				t.Errorf("backup missing top-level key %q", key)
			}
		}
		if !strings.Contains(s, excName) {
			t.Error("backup missing exclusion")
		}
		if !strings.Contains(s, rlName) {
			t.Error("backup missing RL rule")
		}
		if !strings.Contains(s, listName) {
			t.Error("backup missing managed list")
		}
		if !strings.Contains(s, "e2e-backup-test.example.com") {
			t.Error("backup missing custom CSP default_src")
		}
	})

	// 6. Delete all created resources
	resp, _ = httpDelete(t, wafctlURL+"/api/rules/"+excID)
	assertCode(t, "delete exclusion", 204, resp)
	resp, _ = httpDelete(t, wafctlURL+"/api/rules/"+rlID)
	assertCode(t, "delete rl rule", 204, resp)
	resp, _ = httpDelete(t, wafctlURL+"/api/lists/"+listID)
	assertCode(t, "delete list", 204, resp)
	// Reset CSP to empty
	httpPut(t, wafctlURL+"/api/csp", map[string]any{"enabled": false})

	// 7. Restore
	var backupObj map[string]json.RawMessage
	json.Unmarshal(backupBody, &backupObj)
	resp, _ = httpPost(t, wafctlURL+"/api/backup/restore", backupObj)
	assertCode(t, "restore", 200, resp)

	// 8. Verify all resources are restored
	t.Run("exclusion restored", func(t *testing.T) {
		_, listBody := httpGet(t, wafctlURL+"/api/exclusions")
		if !strings.Contains(string(listBody), excName) {
			t.Errorf("exclusion %q not found after restore", excName)
		}
	})

	t.Run("rate rule restored", func(t *testing.T) {
		_, listBody := httpGet(t, wafctlURL+"/api/rules")
		if !strings.Contains(string(listBody), rlName) {
			t.Errorf("RL rule %q not found after restore", rlName)
		}
	})

	t.Run("managed list restored", func(t *testing.T) {
		_, listBody := httpGet(t, wafctlURL+"/api/lists")
		if !strings.Contains(string(listBody), listName) {
			t.Errorf("managed list %q not found after restore", listName)
		}
	})

	t.Run("CSP config restored", func(t *testing.T) {
		_, cspBody := httpGet(t, wafctlURL+"/api/csp")
		if !strings.Contains(string(cspBody), "e2e-backup-test.example.com") {
			t.Errorf("CSP custom default_src not found after restore")
		}
	})
}
