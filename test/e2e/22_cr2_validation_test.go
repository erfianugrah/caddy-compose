package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// --- CR2-5: Priority bands (5-pass evaluation) ---

// TestPolicyPriorityBands verifies that generated policy rules use the 5-pass
// priority bands: allow=[50,100), block=[100,200), skip=[200,300),
// rate_limit=[300,400), detect=[400,500).
func TestPolicyPriorityBands(t *testing.T) {
	// Create a block rule.
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-prio-block", "type": "block", "enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": "/e2e-prio-block-" + t.Name()},
		},
	})
	assertCode(t, "create block", 201, resp)
	blockID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+blockID) })

	// Create an allow rule.
	resp, body = httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-prio-allow", "type": "allow", "enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": "/e2e-prio-allow-" + t.Name()},
		},
	})
	assertCode(t, "create allow", 201, resp)
	allowID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+allowID) })

	// Create a rate limit rule via unified API.
	resp, body = httpPost(t, wafctlURL+"/api/rules", map[string]any{
		"name": "e2e-prio-rl", "type": "rate_limit", "service": "*",
		"rate_limit_key": "client_ip", "rate_limit_events": 999,
		"rate_limit_window": "1m", "rate_limit_action": "deny", "enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": "/e2e-prio-rl-" + t.Name()},
		},
	})
	assertCode(t, "create rl", 201, resp)
	rlID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+rlID) })

	// Call the generate (preview) endpoint.
	resp, body = httpPost(t, wafctlURL+"/api/config/generate", struct{}{})
	assertCode(t, "generate", 200, resp)

	// Parse policy_rules from the response.
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(body, &outer); err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}
	var policyFile struct {
		Rules []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Type     string `json:"type"`
			Priority int    `json:"priority"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(outer["policy_rules"], &policyFile); err != nil {
		t.Fatalf("unmarshal policy_rules: %v", err)
	}

	// Find our three rules by name.
	var blockPrio, allowPrio, rlPrio int
	var found int
	for _, r := range policyFile.Rules {
		switch r.Name {
		case "e2e-prio-block":
			blockPrio = r.Priority
			found++
		case "e2e-prio-allow":
			allowPrio = r.Priority
			found++
		case "e2e-prio-rl":
			rlPrio = r.Priority
			found++
		}
	}
	if found != 3 {
		t.Fatalf("expected 3 rules in generated output, found %d matching our names", found)
	}

	// Verify priority bands (5-pass: allow<block<skip<rl<detect).
	if allowPrio < 50 || allowPrio >= 100 {
		t.Errorf("allow priority %d not in [50,100)", allowPrio)
	}
	if blockPrio < 100 || blockPrio >= 200 {
		t.Errorf("block priority %d not in [100,200)", blockPrio)
	}
	if rlPrio < 300 || rlPrio >= 400 {
		t.Errorf("rl priority %d not in [300,400)", rlPrio)
	}

	// Verify ordering: allow < block < rate_limit.
	if allowPrio >= blockPrio {
		t.Errorf("allow priority %d should be < block priority %d", allowPrio, blockPrio)
	}
	if blockPrio >= rlPrio {
		t.Errorf("block priority %d should be < rl priority %d", blockPrio, rlPrio)
	}
	t.Logf("priorities: allow=%d block=%d rl=%d", allowPrio, blockPrio, rlPrio)
}

// TestPolicyPriorityAllowOverridesBlock creates both a block and an allow rule
// for the same path and verifies allow wins. Under the 5-pass model, allow
// (pass 1, priority 50) terminates before block (pass 2, priority 100) runs.
func TestPolicyPriorityAllowOverridesBlock(t *testing.T) {
	testPath := "/e2e-prio-conflict-" + time.Now().Format("150405")

	// Create a block rule first and verify it blocks.
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-prio-block-conflict", "type": "block", "enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": testPath},
		},
	})
	assertCode(t, "create block", 201, resp)
	blockID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+blockID) })

	// Deploy and confirm block works.
	deployAndWaitForStatus(t, caddyURL+testPath, 403)

	// Now add an allow rule for the same path.
	resp, body = httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-prio-allow-conflict", "type": "allow", "enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": testPath},
		},
	})
	assertCode(t, "create allow", 201, resp)
	allowID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+allowID) })

	// Deploy — allow should now override the block.
	// httpbun returns 404 for unknown paths, so "not 403" means allow won.
	deployAndWaitForStatus(t, caddyURL+testPath, 404)

	// Verify the allow wins — request passes through WAF (404 from backend, not 403 from block).
	resp2, _ := httpGetRetry(t, caddyURL+testPath, 3)
	if resp2.StatusCode == 403 {
		t.Errorf("expected non-403 (allow wins over block in 5-pass), got 403")
	}
	t.Logf("allow override status: %d (expected 404 from backend, not 403 from block)", resp2.StatusCode)

	// Clean up.
	cleanup(t, wafctlURL+"/api/exclusions/"+allowID)
	cleanup(t, wafctlURL+"/api/exclusions/"+blockID)
	deployWAF(t)
}

// --- CR2-4: Backup/restore partial failure warning ---

// TestBackupRestorePartialFailureWarning verifies that restoring a backup with
// invalid data produces a "partial" status and includes a warning message.
func TestBackupRestorePartialFailureWarning(t *testing.T) {
	// Take a clean backup first.
	_, backupBody := httpGet(t, wafctlURL+"/api/backup")

	// Tamper with the exclusions store: inject an invalid exclusion type.
	var backup map[string]json.RawMessage
	if err := json.Unmarshal(backupBody, &backup); err != nil {
		t.Fatalf("unmarshal backup: %v", err)
	}
	backup["exclusions"] = json.RawMessage(`[{"name":"bad-excl","type":"completely_invalid","enabled":true}]`)

	tamperedJSON, _ := json.Marshal(backup)

	resp, body := httpPost(t, wafctlURL+"/api/backup/restore", json.RawMessage(tamperedJSON))
	assertCode(t, "partial restore", 200, resp)

	status := jsonField(body, "status")
	if status != "partial" {
		t.Errorf("expected status=partial, got %q", status)
	}

	warning := jsonField(body, "warning")
	if warning == "" {
		t.Error("expected non-empty warning on partial restore")
	} else if !strings.Contains(warning, "Partial restore") {
		t.Errorf("warning should contain 'Partial restore', got %q", warning)
	}

	// Check that the results map indicates the exclusions failure.
	exclResult := jsonField(body, "results.exclusions")
	if !strings.HasPrefix(exclResult, "failed") {
		t.Errorf("expected exclusions result to start with 'failed', got %q", exclResult)
	}

	t.Logf("status=%q warning=%q exclusions=%q", status, warning, exclResult)

	// Restore the clean backup to fix state.
	resp2, _ := httpPost(t, wafctlURL+"/api/backup/restore", json.RawMessage(backupBody))
	assertCode(t, "clean restore", 200, resp2)
}

// --- CR2-24: Blocklist check endpoint validates IP format ---

// TestBlocklistCheckInvalidIP verifies that the check endpoint rejects invalid IPs.
func TestBlocklistCheckInvalidIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
	}{
		{"not an IP", "not-an-ip"},
		{"too many octets", "1.2.3.4.5"},
		{"letters only", "abcdef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := httpGet(t, wafctlURL+"/api/blocklist/check/"+tt.ip)
			if resp.StatusCode != 400 {
				t.Errorf("expected 400 for %q, got %d: %s", tt.ip, resp.StatusCode, body)
			}
		})
	}
}

// --- CR2-9: Backup/restore response includes results map ---

// TestBackupRestoreSuccessStatus verifies that a clean restore returns
// status="restored" and a results map with per-store details.
func TestBackupRestoreSuccessStatus(t *testing.T) {
	// Take backup.
	_, backupBody := httpGet(t, wafctlURL+"/api/backup")

	// Restore the same backup.
	resp, body := httpPost(t, wafctlURL+"/api/backup/restore", json.RawMessage(backupBody))
	assertCode(t, "restore", 200, resp)

	status := jsonField(body, "status")
	if status != "restored" {
		t.Errorf("expected status=restored, got %q", status)
	}

	// Verify results map exists with at least the config store.
	configResult := jsonField(body, "results.waf_config")
	if configResult == "" {
		t.Error("expected results.waf_config in restore response")
	}

	warning := jsonField(body, "warning")
	if warning != "" {
		t.Errorf("expected no warning on clean restore, got %q", warning)
	}
}
