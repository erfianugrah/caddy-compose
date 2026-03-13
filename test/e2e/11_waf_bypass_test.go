package e2e_test

import (
	"fmt"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// 17. End-to-End: WAF Bypass via Exclusion (legacy SecRule path)
// ════════════════════════════════════════════════════════════════════

func TestE2EWAFBypass(t *testing.T) {
	sqliURL := caddyURL + "/get?id=1%27%20OR%20%271%27=%271"

	// Step 1: Confirm blocked before exclusion.
	t.Run("pre-exclusion blocked", func(t *testing.T) {
		code, err := httpGetCode(sqliURL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 403 {
			t.Fatalf("expected 403 (WAF block), got %d — WAF not working", code)
		}
	})

	// Step 2: Create allow exclusion for /get path.
	payload := map[string]any{
		"name":        "e2e-bypass",
		"type":        "allow",
		"description": "E2E bypass test",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "path", "operator": "begins_with", "value": "/get"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create bypass exclusion", 201, resp)
	bypassID := mustGetID(t, body)

	// Step 3: Deploy — must succeed fully (not "partial").
	resp2, deployBody := httpPostDeploy(t, fmt.Sprintf("%s/api/config/deploy", wafctlURL), struct{}{})
	assertCode(t, "deploy bypass", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")

	// Step 4: Verify bypass works — SQLi should now pass through.
	t.Run("post-exclusion passes", func(t *testing.T) {
		waitForStatus(t, sqliURL, 200, 10*time.Second)
	})

	// Step 5: Cleanup — delete exclusion and redeploy.
	cleanup(t, fmt.Sprintf("%s/api/exclusions/%s", wafctlURL, bypassID))
	_, redeployBody := httpPostDeploy(t, fmt.Sprintf("%s/api/config/deploy", wafctlURL), struct{}{})
	assertField(t, "redeploy", redeployBody, "status", "deployed")

	// Step 6: Verify WAF re-enabled — SQLi must be blocked again.
	t.Run("post-cleanup blocked", func(t *testing.T) {
		waitForStatus(t, sqliURL, 403, 10*time.Second)
	})
}
