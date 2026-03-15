package e2e_test

import (
	"net/http"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// 19. Policy Engine — in_list / not_in_list via Managed Lists
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineInList(t *testing.T) {
	// Test the full pipeline: managed list → exclusion with in_list → deploy →
	// plugin hot reload → request matching. This validates the core security fix:
	// exact path matching via hash set instead of @pm substring matching.

	// Step 1: Create a string list with specific paths.
	listPayload := map[string]any{
		"name":   "e2e-blocked-paths",
		"kind":   "string",
		"source": "manual",
		"items":  []string{"/e2e-list-trap", "/e2e-list-blocked"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/lists", listPayload)
	assertCode(t, "create list", 201, resp)
	listID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+listID) })

	// Step 2: Create a block exclusion referencing the list.
	exclPayload := map[string]any{
		"name":        "e2e-in-list-block",
		"type":        "block",
		"description": "Block paths from managed list",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "path", "operator": "in_list", "value": "e2e-blocked-paths"}},
	}
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions", exclPayload)
	assertCode(t, "create in_list exclusion", 201, resp2)
	exclID := mustGetID(t, body2)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Step 3: Deploy and wait for plugin hot reload.
	time.Sleep(1 * time.Second)
	resp3, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp3)
	assertField(t, "deploy", deployBody, "status", "deployed")
	waitForStatus(t, caddyURL+"/e2e-list-trap", 403, 10*time.Second)

	// Step 4: Verify exact path matching.
	t.Run("listed path /e2e-list-trap blocked", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-list-trap")
		assertCode(t, "blocked", 403, resp)
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("listed path /e2e-list-blocked blocked", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-list-blocked")
		assertCode(t, "blocked", 403, resp)
	})

	t.Run("exact match — /e2e-list-trap-extended NOT blocked", func(t *testing.T) {
		// Core security fix: @pm would substring-match this, hash set does not.
		code, err := httpGetCode(caddyURL + "/e2e-list-trap-extended")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 (not in list), got 403 — in_list has substring match bug")
		}
	})

	t.Run("unrelated path still works", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "unblocked", 200, resp)
	})
}

func TestPolicyEngineNotInList(t *testing.T) {
	// Test not_in_list: block all paths NOT in the safe list.
	// This uses method field to avoid interfering with other tests.

	// Step 1: Create a string list of "safe" user agents.
	listPayload := map[string]any{
		"name":   "e2e-safe-agents",
		"kind":   "string",
		"source": "manual",
		"items":  []string{"Go-http-client/1.1", "Mozilla/5.0 (compatible; e2e-test/1.0)"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/lists", listPayload)
	assertCode(t, "create safe list", 201, resp)
	listID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+listID) })

	// Step 2: Create a block rule: block requests to /e2e-notinlist-test
	// whose user_agent is NOT in the safe list. Combined with a path condition
	// to avoid blocking all traffic.
	exclPayload := map[string]any{
		"name":        "e2e-not-in-list-block",
		"type":        "block",
		"description": "Block unknown UAs on specific path",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-notinlist-test"},
			{"field": "user_agent", "operator": "not_in_list", "value": "e2e-safe-agents"},
		},
	}
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions", exclPayload)
	assertCode(t, "create not_in_list exclusion", 201, resp2)
	exclID := mustGetID(t, body2)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Step 3: Deploy and wait for plugin hot reload.
	time.Sleep(1 * time.Second)
	resp3, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp3)
	assertField(t, "deploy", deployBody, "status", "deployed")
	// Wait for the rule to take effect by polling the evil UA (should get 403).
	waitForCondition(t, "not_in_list blocks unknown UA", 15*time.Second, func() bool {
		req, _ := http.NewRequest("GET", caddyURL+"/e2e-notinlist-test", nil)
		req.Header.Set("User-Agent", "EvilBot/1.0")
		req.Header.Set("Accept", "*/*")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 403
	})

	// Step 4: Verify not_in_list matching.
	t.Run("safe UA passes through", func(t *testing.T) {
		// The e2e browserTransport sends "Mozilla/5.0 (compatible; e2e-test/1.0)" which is in the safe list.
		code, err := httpGetCode(caddyURL + "/e2e-notinlist-test")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		// Should NOT be blocked since Go's UA is in the safe list.
		if code == 403 {
			t.Errorf("expected non-403 (UA in safe list), got 403")
		}
	})

	t.Run("unknown UA blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-notinlist-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "EvilBot/1.0")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (UA not in safe list), got %d", resp.StatusCode)
		}
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("other paths unaffected", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "EvilBot/1.0")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		// /get should not be affected by the rule (path condition limits scope).
		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 (different path), got 403")
		}
	})
}

func TestPolicyEngineInListIP(t *testing.T) {
	// Test in_list with IP kind list. Uses a CIDR that covers Docker bridge
	// networks (172.16.0.0/12) to match the E2E test client's IP.

	// Step 1: Create IP list with Docker bridge CIDR.
	listPayload := map[string]any{
		"name":   "e2e-blocked-ips",
		"kind":   "ip",
		"source": "manual",
		"items":  []string{"172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/lists", listPayload)
	assertCode(t, "create IP list", 201, resp)
	listID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+listID) })

	// Step 2: Create block rule for specific path + IP in_list.
	exclPayload := map[string]any{
		"name":        "e2e-ip-in-list-block",
		"type":        "block",
		"description": "Block private IPs on specific path",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-ip-list-test"},
			{"field": "ip", "operator": "in_list", "value": "e2e-blocked-ips"},
		},
	}
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions", exclPayload)
	assertCode(t, "create IP in_list exclusion", 201, resp2)
	exclID := mustGetID(t, body2)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Step 3: Deploy and wait for plugin hot reload.
	time.Sleep(1 * time.Second)
	resp3, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp3)
	assertField(t, "deploy", deployBody, "status", "deployed")
	waitForStatus(t, caddyURL+"/e2e-ip-list-test", 403, 10*time.Second)

	// Step 4: Our E2E client IP is a Docker private IP — should be blocked.
	t.Run("private IP blocked on target path", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-ip-list-test")
		assertCode(t, "blocked", 403, resp)
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("other paths unaffected", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "unblocked", 200, resp)
	})
}

func TestPolicyEngineInListLarge(t *testing.T) {
	// Stress test: create a large IP list (10K entries), reference it in a
	// block rule, deploy, and verify the plugin handles it without timeout.

	const n = 10_000
	ips := generateIPs(n)

	// Step 1: Create large IP list.
	listPayload := map[string]any{
		"name":   "e2e-large-ip-list",
		"kind":   "ip",
		"source": "manual",
		"items":  ips,
	}
	resp, body := httpPost(t, wafctlURL+"/api/lists", listPayload)
	assertCode(t, "create large list", 201, resp)
	listID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+listID) })

	count := jsonInt(body, "item_count")
	if count != n {
		t.Errorf("expected item_count=%d, got %d", n, count)
	}

	// Step 2: Create block rule referencing it.
	exclPayload := map[string]any{
		"name":        "e2e-large-list-block",
		"type":        "block",
		"description": "Block IPs from large list",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-large-list-test"},
			{"field": "ip", "operator": "in_list", "value": "e2e-large-ip-list"},
		},
	}
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions", exclPayload)
	assertCode(t, "create large list exclusion", 201, resp2)
	exclID := mustGetID(t, body2)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Step 3: Deploy — must succeed (not partial/timeout).
	time.Sleep(1 * time.Second)
	resp3, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy with large list", 200, resp3)
	assertField(t, "deploy", deployBody, "status", "deployed")
	waitForStatus(t, caddyURL+"/get", 200, 10*time.Second)

	// Step 4: Verify matching works — 10.0.0.x IPs are in the list,
	// and Docker bridge IPs (172.x) are NOT. Since our test client
	// uses a Docker bridge IP, we should NOT be blocked.
	t.Run("Docker bridge IP not in 10.x.x.x list", func(t *testing.T) {
		code, err := httpGetCode(caddyURL + "/e2e-large-list-test")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		// Docker bridge IP is typically 172.x.x.x, NOT in the 10.x.x.x list.
		if code == 403 {
			t.Errorf("expected non-403 (client IP not in 10.x list), got 403")
		}
	})

	// Step 5: Verify deploy and proxy still work after loading 10K items.
	t.Run("proxy healthy after large list", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "healthy", 200, resp)
	})
}
