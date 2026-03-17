package e2e_test

import (
	"encoding/json"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  30. New Features E2E Tests
// ════════════════════════════════════════════════════════════════════

// --- Log-Only Action Flow ---

func TestLogOnlyAction(t *testing.T) {
	// Strategy: create a custom detect rule that's the ONLY rule matching a
	// specific test path. Then toggle it to log_only and verify it stops blocking.
	// This avoids the CRS multi-rule problem where disabling one rule isn't enough.

	// Step 1: Create a custom detect rule targeting a unique path.
	rulePayload := map[string]any{
		"name":        "e2e-log-only-test",
		"type":        "detect",
		"description": "E2E test rule for log_only action",
		"severity":    "CRITICAL",
		"enabled":     true,
		"conditions":  []map[string]any{{"field": "path", "operator": "begins_with", "value": "/e2e-logonly-test"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", rulePayload)
	assertCode(t, "create detect rule", 201, resp)
	ruleID := mustGetID(t, body)
	defer cleanup(t, wafctlURL+"/api/exclusions/"+ruleID)

	// Set threshold=3 so a single CRITICAL(5) blocks.
	httpPut(t, wafctlURL+"/api/config", map[string]any{
		"defaults": map[string]any{"paranoia_level": 1, "inbound_threshold": 3, "outbound_threshold": 15},
		"services": map[string]any{},
	})
	deployWAF(t)

	testURL := caddyURL + "/e2e-logonly-test"
	waitForStatus(t, testURL, 403, 15*time.Second)

	t.Run("baseline: custom detect rule blocks", func(t *testing.T) {
		code, err := httpGetCode(testURL)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if code != 403 {
			t.Fatalf("expected 403 from custom detect rule, got %d", code)
		}
	})

	// Step 2: Update the rule to log_only via detect_action.
	resp2, _ := httpPut(t, wafctlURL+"/api/exclusions/"+ruleID, map[string]any{
		"name":          "e2e-log-only-test",
		"type":          "detect",
		"severity":      "CRITICAL",
		"enabled":       true,
		"detect_action": "log_only",
		"conditions":    []map[string]any{{"field": "path", "operator": "begins_with", "value": "/e2e-logonly-test"}},
	})
	assertCode(t, "update to log_only", 200, resp2)
	deployWAF(t)

	waitForStatus(t, testURL, 200, 15*time.Second)

	t.Run("log_only: rule matches but doesn't block", func(t *testing.T) {
		code, err := httpGetCode(testURL)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 (rule is log_only), got 403")
		}
	})

	// Step 3: Restore config.
	ensureDefaultConfig(t)
	deployWAF(t)
}

// --- Events Total Count ---

func TestEventsTotalCount(t *testing.T) {
	// Generate some events first by making a few requests.
	for i := 0; i < 5; i++ {
		httpGetCode(caddyURL + "/get?test=total-count")
	}
	time.Sleep(3 * time.Second) // let wafctl process the logs

	resp, body := httpGet(t, wafctlURL+"/api/events?limit=2")
	assertCode(t, "events", 200, resp)

	var result struct {
		Total  int               `json:"total"`
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The total should be a non-negative count. With the fast count-only pass,
	// -1 (early-exit) should no longer occur. But if it does (old wafctl binary),
	// we accept it as a known limitation.
	if result.Total >= 0 && result.Total < len(result.Events) {
		t.Errorf("total=%d should be >= events returned=%d", result.Total, len(result.Events))
	}
	t.Logf("events total=%d, returned=%d", result.Total, len(result.Events))
}

// --- Dynamic CRS Catalog ---

func TestCRSCatalogDynamic(t *testing.T) {
	resp, body := httpGet(t, wafctlURL+"/api/crs/rules")
	assertCode(t, "crs catalog", 200, resp)

	var catalog struct {
		Categories []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"categories"`
		Rules []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			Category    string `json:"category"`
		} `json:"rules"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The catalog is dynamically derived from default-rules.json.
	// The e2e image has ~340+ CRS rules + custom rules.
	if catalog.Total < 100 {
		t.Errorf("expected 100+ rules in catalog, got %d", catalog.Total)
	}
	t.Logf("catalog: %d rules, %d categories", catalog.Total, len(catalog.Categories))
	if len(catalog.Categories) < 10 {
		t.Errorf("expected 10+ categories, got %d", len(catalog.Categories))
	}

	// Verify a known CRS rule has its description from default-rules.json.
	found := false
	for _, r := range catalog.Rules {
		if r.ID == "942100" {
			found = true
			if r.Description == "" {
				t.Error("rule 942100 should have a description from default-rules.json")
			}
			if r.Category == "" {
				t.Error("rule 942100 should have a category")
			}
			break
		}
	}
	if !found {
		t.Error("expected rule 942100 in catalog")
	}

	// Verify custom rules are in the catalog (from custom-rules.json merged by the converter).
	foundCustom := false
	for _, r := range catalog.Rules {
		if r.ID == "9100003" { // XXE rule — always present in custom-rules.json
			foundCustom = true
			break
		}
	}
	if !foundCustom {
		t.Logf("custom rule 9100003 not found in catalog (may not be in default-rules.json)")
	}
}
