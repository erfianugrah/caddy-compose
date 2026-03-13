package e2e_test

import (
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  Service Readiness
// ════════════════════════════════════════════════════════════════════

func TestServiceReadiness(t *testing.T) {
	waitForService(t, "Caddy admin", caddyAdmin+"/config/", 60*time.Second)
	waitForService(t, "wafctl API", wafctlURL+"/api/health", 60*time.Second)
	waitForService(t, "httpbun upstream", caddyURL+"/get", 60*time.Second)
}

// ════════════════════════════════════════════════════════════════════
//  0.5. Blocklist Refresh — populates ipsum managed lists + redeploy
// ════════════════════════════════════════════════════════════════════

func TestBlocklistRefresh(t *testing.T) {
	// Download real IPsum data from GitHub and populate the 8 per-level
	// managed lists. This also triggers deployAll() which regenerates
	// policy-rules.json with resolved list items, ensuring the policy
	// engine has a valid rule set for all subsequent tests.
	resp, body := httpPostDeploy(t, wafctlURL+"/api/blocklist/refresh", struct{}{})
	if resp.StatusCode != 200 {
		t.Fatalf("blocklist refresh failed: %d %s", resp.StatusCode, string(body))
	}
	t.Logf("blocklist refresh: %s", string(body))

	// Verify managed lists were created.
	resp2, body2 := httpGet(t, wafctlURL+"/api/lists")
	assertCode(t, "list managed lists", 200, resp2)
	listCount := jsonArrayLen(body2)
	if listCount < 8 {
		t.Errorf("expected at least 8 ipsum managed lists, got %d", listCount)
	}
	t.Logf("managed lists after refresh: %d", listCount)

	// Verify blocklist stats show loaded IPs.
	resp3, body3 := httpGet(t, wafctlURL+"/api/blocklist/stats")
	assertCode(t, "blocklist stats", 200, resp3)
	blockedIPs := jsonInt(body3, "blocked_ips")
	if blockedIPs < 1000 {
		t.Errorf("expected >1000 blocked IPs after refresh, got %d", blockedIPs)
	}
	t.Logf("blocked IPs after refresh: %d", blockedIPs)

	// Wait for policy engine hot-reload to pick up the new rules.
	waitForStatus(t, caddyURL+"/get", 200, 10*time.Second)
}
