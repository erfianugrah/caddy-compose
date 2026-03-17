package e2e_test

import (
	"net/http"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  Transform Functions (v0.8.1)
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineTransforms(t *testing.T) {
	ensureDefaultConfig(t)
	deployWAF(t)
	// Test transform functions end-to-end:
	// 1. Create a block rule with transforms: ["urlDecode", "lowercase"]
	//    that blocks requests containing "/admin" in the path after decoding.
	// 2. Deploy to policy engine.
	// 3. Send a URL-encoded path like /%41dmin — after urlDecode+lowercase it
	//    becomes "/admin" and should be blocked.
	// 4. Verify the block triggers.
	// 5. Send a normal request to verify pass-through.

	// Step 1: Create block rule with transforms.
	blockPayload := map[string]any{
		"name":        "e2e-transform-block-admin",
		"type":        "block",
		"description": "Block /admin after URL decode + lowercase",
		"enabled":     true,
		"conditions": []map[string]any{
			{
				"field":      "path",
				"operator":   "contains",
				"value":      "/admin",
				"transforms": []string{"urlDecode", "lowercase"},
			},
		},
		"tags": []string{"e2e-transforms"},
	}
	resp1, body1 := httpPost(t, wafctlURL+"/api/exclusions", blockPayload)
	assertCode(t, "create block rule with transforms", 201, resp1)
	ruleID := mustGetID(t, body1)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	// Step 2: Deploy.
	time.Sleep(1 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")

	// Wait for plugin hot-reload.
	waitForStatus(t, caddyURL+"/%41dmin", 403, 10*time.Second)

	// Step 3: Send URL-encoded path — %41 = 'A', so /%41dmin → /Admin → /admin
	t.Run("url-encoded path blocked after transform", func(t *testing.T) {
		resp, body := httpGet(t, caddyURL+"/%41dmin")
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 for /%s, got %d; body=%.200s",
				"%41dmin", resp.StatusCode, string(body))
		}
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Error("expected X-Blocked-By: policy-engine header")
		}
		t.Logf("URL-encoded path correctly blocked: %d", resp.StatusCode)
	})

	// Step 4: Mixed case — /ADMIN should also match after lowercase transform.
	t.Run("mixed-case path blocked after lowercase", func(t *testing.T) {
		resp, body := httpGet(t, caddyURL+"/ADMIN")
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 for /ADMIN, got %d; body=%.200s",
				resp.StatusCode, string(body))
		}
		t.Logf("Mixed-case path correctly blocked: %d", resp.StatusCode)
	})

	// Step 5: Double-encoded — %2541dmin → after urlDecode → %41dmin → contains
	// "/admin"? No — urlDecode is applied once, so %25 → '%', result is "%41dmin".
	// This should NOT match "/admin" — tests that transforms don't over-decode.
	t.Run("double-encoded path passes — no recursive decode", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/%2541dmin")
		if resp.StatusCode == 403 {
			t.Error("double-encoded path should NOT be blocked (single urlDecode)")
		}
		t.Logf("Double-encoded path correctly passed: %d", resp.StatusCode)
	})

	// Step 6: Normal path should pass through.
	t.Run("normal request passes", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		if resp.StatusCode != 200 {
			t.Errorf("expected 200 for /get, got %d", resp.StatusCode)
		}
	})
}

// ════════════════════════════════════════════════════════════════════
//  v0.9.0: Aggregate Fields, Phrase Match, Numeric Operators, Count
// ════════════════════════════════════════════════════════════════════

func TestPolicyEnginePhraseMatch(t *testing.T) {
	ensureDefaultConfig(t)
	deployWAF(t)
	// Test phrase_match operator with Aho-Corasick multi-pattern matching.
	// Use user_agent field with custom bot-name patterns to avoid CRS interference
	// (CRS inspects query strings for SQLi but doesn't block arbitrary UA strings).

	// Step 1: Create block rule with phrase_match on user_agent.
	payload := map[string]any{
		"name":        "e2e-phrase-match",
		"type":        "block",
		"description": "Block specific bot UA phrases",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-pm-"},
			{
				"field":      "user_agent",
				"operator":   "phrase_match",
				"list_items": []string{"dangerous-bot", "evil-scanner", "attack-crawler"},
			},
		},
		"tags": []string{"e2e-phrase-match"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create phrase_match rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	// Step 2: Deploy and wait for plugin hot-reload.
	time.Sleep(1 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	waitForCondition(t, "phrase_match rule active", 10*time.Second, func() bool {
		req, _ := http.NewRequest("GET", caddyURL+"/e2e-pm-test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (dangerous-bot/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 403
	})

	// Step 3: Verify phrase_match matching via User-Agent.
	t.Run("UA with 'dangerous-bot' blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pm-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (dangerous-bot/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (phrase_match), got %d", resp.StatusCode)
		}
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("UA with 'evil-scanner' blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pm-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "evil-scanner v2.0")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (phrase_match), got %d", resp.StatusCode)
		}
	})

	t.Run("safe UA passes", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pm-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64)")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 && headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected non-403 for safe UA, got 403 from policy engine")
		}
	})

	t.Run("partial keyword does NOT match", func(t *testing.T) {
		// "dangerous" alone should not match "dangerous-bot" — AC is substring
		// match of patterns in the input. "dangerous" does NOT contain "dangerous-bot".
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pm-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "dangerous thing but not the full phrase")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 && headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected non-403 for partial keyword, got 403 from policy engine")
		}
	})

	t.Run("other paths unaffected", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "dangerous-bot/1.0")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		// /get doesn't match /e2e-pm- prefix
		if resp.StatusCode == 403 && headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("policy engine blocked /get — path condition should have prevented this")
		}
	})
}

func TestPolicyEngineAggregateFields(t *testing.T) {
	ensureDefaultConfig(t)
	deployWAF(t)
	// Test aggregate field matching. Create a block rule that matches
	// any header value containing a specific pattern.

	payload := map[string]any{
		"name":        "e2e-all-headers-block",
		"type":        "block",
		"description": "Block requests with 'E2E-Evil' in any header value",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-agg-"},
			{"field": "all_headers", "operator": "contains", "value": "E2E-Evil"},
		},
		"tags": []string{"e2e-aggregate"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create aggregate field rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	time.Sleep(1 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	waitForCondition(t, "aggregate field rule active", 10*time.Second, func() bool {
		req, _ := http.NewRequest("GET", caddyURL+"/e2e-agg-test", nil)
		req.Header.Set("X-Custom", "contains E2E-Evil marker")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 403
	})

	t.Run("header containing E2E-Evil blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-agg-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("X-Custom", "contains E2E-Evil marker")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (all_headers contains E2E-Evil), got %d", resp.StatusCode)
		}
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("different header name also matches", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-agg-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("X-Another-Header", "E2E-Evil-payload")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (all_headers matches any header), got %d", resp.StatusCode)
		}
	})

	t.Run("clean headers pass", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-agg-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("X-Custom", "totally-safe-value")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 && headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected non-403 (no E2E-Evil in headers), got 403 from policy engine")
		}
	})
}

func TestPolicyEnginePhraseMatchAggregateField(t *testing.T) {
	ensureDefaultConfig(t)
	deployWAF(t)
	// Test phrase_match on an aggregate field: scan ALL header values for
	// SQL injection patterns using Aho-Corasick. This is the core CRS-like
	// use case — multi-pattern scanning across all request variables.

	payload := map[string]any{
		"name":        "e2e-pm-all-headers",
		"type":        "block",
		"description": "Phrase match SQL keywords in all headers",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-pmh-"},
			{
				"field":      "all_headers",
				"operator":   "phrase_match",
				"list_items": []string{"union select", "script>alert", "../../etc/passwd"},
			},
		},
		"tags": []string{"e2e-pm-aggregate"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create phrase_match aggregate rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	time.Sleep(1 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	waitForCondition(t, "phrase_match aggregate rule active", 10*time.Second, func() bool {
		req, _ := http.NewRequest("GET", caddyURL+"/e2e-pmh-test", nil)
		req.Header.Set("X-Search", "1 union select * from users")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 403
	})

	t.Run("SQLi in custom header blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pmh-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("X-Search", "1 union select * from users")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (phrase_match all_headers), got %d", resp.StatusCode)
		}
	})

	t.Run("path traversal in Referer header blocked", func(t *testing.T) {
		// Retry briefly — the all_headers phrase_match may need an extra
		// policy engine reload cycle to evaluate Referer consistently.
		waitForCondition(t, "Referer path traversal blocked", 10*time.Second, func() bool {
			req, err := http.NewRequest("GET", caddyURL+"/e2e-pmh-test", nil)
			if err != nil {
				return false
			}
			req.Header.Set("Referer", "https://example.com/../../etc/passwd")
			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == 403
		})
	})

	t.Run("clean headers pass", func(t *testing.T) {
		code, err := httpGetCode(caddyURL + "/e2e-pmh-test")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 for clean request, got 403")
		}
	})
}

func TestPolicyEngineCountField(t *testing.T) {
	ensureDefaultConfig(t)
	deployWAF(t)
	// Test count: pseudo-field with numeric operators.
	// count:all_args_names counts just the query param names (not values).
	// Block requests to /e2e-count-test that have more than 3 query param names.

	payload := map[string]any{
		"name":        "e2e-count-args",
		"type":        "block",
		"description": "Block requests with >3 query arg names",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-count-"},
			{"field": "count:all_args_names", "operator": "gt", "value": "3"},
		},
		"tags": []string{"e2e-count"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create count rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	time.Sleep(1 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	waitForStatus(t, caddyURL+"/e2e-count-test?a=1&b=2&c=3&d=4", 403, 10*time.Second)

	t.Run("4 args blocked (count > 3)", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-count-test?a=1&b=2&c=3&d=4")
		assertCode(t, "4 args", 403, resp)
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("3 args pass (count = 3, not > 3)", func(t *testing.T) {
		code, err := httpGetCode(caddyURL + "/e2e-count-test?a=1&b=2&c=3")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 for 3 args (not > 3), got 403")
		}
	})

	t.Run("0 args pass", func(t *testing.T) {
		code, err := httpGetCode(caddyURL + "/e2e-count-test")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 for 0 args, got 403")
		}
	})

	t.Run("many args blocked", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-count-test?a=1&b=2&c=3&d=4&e=5&f=6")
		assertCode(t, "6 args", 403, resp)
	})

	t.Run("other paths unaffected", func(t *testing.T) {
		code, err := httpGetCode(caddyURL + "/get?a=1&b=2&c=3&d=4&e=5")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		// /get doesn't match /e2e-count- prefix
		if code == 403 {
			// Could be CRS blocking, check header
			resp, _ := httpGet(t, caddyURL+"/get?a=1&b=2&c=3&d=4&e=5")
			if headerContains(resp, "X-Blocked-By", "policy-engine") {
				t.Errorf("policy engine blocked /get — path condition should have prevented this")
			}
		}
	})
}

func TestV090ValidationEndpoints(t *testing.T) {
	t.Parallel()
	// Test that wafctl validation correctly accepts and rejects v0.9.0 features.

	t.Run("aggregate field accepted for policy engine type", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":    "e2e-val-aggregate",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "all_cookies", "operator": "contains", "value": "evil"},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "aggregate accepted", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/exclusions/"+id)
	})

	t.Run("phrase_match without list_items rejected", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":    "e2e-val-pm-no-items",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "query", "operator": "phrase_match"},
			},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "phrase_match without list_items", 400, resp)
	})

	t.Run("count: with non-aggregate field rejected", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":    "e2e-val-count-bad",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "count:path", "operator": "gt", "value": "10"},
			},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "count: non-aggregate rejected", 400, resp)
	})

	t.Run("count: with non-numeric operator rejected", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":    "e2e-val-count-op",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "count:all_args", "operator": "contains", "value": "10"},
			},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "count: non-numeric op rejected", 400, resp)
	})

	t.Run("numeric operator with non-numeric value rejected", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":    "e2e-val-numeric-bad",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "count:all_args", "operator": "gt", "value": "abc"},
			},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "numeric with non-numeric value", 400, resp)
	})

	t.Run("numeric operator on named field accepted", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":    "e2e-val-numeric-named",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "path", "operator": "begins_with", "value": "/test"},
				{"field": "header", "operator": "gt", "value": "Content-Length:1000"},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "numeric on named field", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/exclusions/"+id)
	})
}

func TestPolicyEngineTransformValidation(t *testing.T) {
	t.Parallel()
	// Test that wafctl rejects unknown transform names via the API.

	t.Run("invalid transform name rejected", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":    "e2e-bad-transform",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{
					"field":      "path",
					"operator":   "eq",
					"value":      "/test",
					"transforms": []string{"noSuchTransform"},
				},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		if resp.StatusCode != 400 {
			t.Errorf("expected 400 for invalid transform, got %d; body=%s",
				resp.StatusCode, string(body))
		}
		t.Logf("Invalid transform correctly rejected: %d", resp.StatusCode)
	})

	t.Run("valid transforms accepted", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":    "e2e-valid-transforms",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{
					"field":      "path",
					"operator":   "contains",
					"value":      "/test",
					"transforms": []string{"lowercase", "urlDecode", "normalizePath"},
				},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "create with valid transforms", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/exclusions/"+id)
		t.Log("Valid transforms accepted")
	})
}
