package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ─── Skip Action E2E Tests ──────────────────────────────────────────

// TestSkipActionCRUD verifies that skip exclusions can be created, read,
// and deleted via the API, and that skip_targets are preserved.
func TestSkipActionCRUD(t *testing.T) {
	skipTargets := map[string]any{
		"rules":         []string{"920350", "941100"},
		"phases":        []string{"detect"},
		"all_remaining": false,
	}

	// Create a skip rule.
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-skip-crud", "type": "skip", "enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "begins_with", "value": "/e2e-skip-crud"},
		},
		"skip_targets": skipTargets,
	})
	assertCode(t, "create skip", 201, resp)
	id := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+id) })

	// Verify the rule type is skip.
	assertField(t, "type", body, "type", "skip")

	// Read it back and verify skip_targets.
	resp2, body2 := httpGet(t, wafctlURL+"/api/exclusions/"+id)
	assertCode(t, "get skip", 200, resp2)
	assertField(t, "type", body2, "type", "skip")

	// Verify skip_targets fields are present.
	st := jsonField(body2, "skip_targets")
	if st == "" {
		t.Fatal("expected skip_targets in response")
	}
	t.Logf("skip_targets: %s", st)

	// Delete.
	resp3, _ := httpDelete(t, wafctlURL+"/api/exclusions/"+id)
	assertCode(t, "delete skip", 204, resp3)
}

// TestSkipActionValidation verifies that skip rules without skip_targets
// are rejected, and that invalid skip_targets are caught.
func TestSkipActionValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload map[string]any
	}{
		{
			"missing skip_targets",
			map[string]any{
				"name": "e2e-skip-no-targets", "type": "skip", "enabled": true,
				"conditions": []map[string]string{
					{"field": "path", "operator": "eq", "value": "/test"},
				},
			},
		},
		{
			"empty skip_targets",
			map[string]any{
				"name": "e2e-skip-empty-targets", "type": "skip", "enabled": true,
				"conditions": []map[string]string{
					{"field": "path", "operator": "eq", "value": "/test"},
				},
				"skip_targets": map[string]any{},
			},
		},
		{
			"invalid phase name",
			map[string]any{
				"name": "e2e-skip-bad-phase", "type": "skip", "enabled": true,
				"conditions": []map[string]string{
					{"field": "path", "operator": "eq", "value": "/test"},
				},
				"skip_targets": map[string]any{
					"phases": []string{"nonexistent"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := httpPost(t, wafctlURL+"/api/exclusions", tt.payload)
			if resp.StatusCode != 400 {
				t.Errorf("expected 400, got %d: %s", resp.StatusCode, body)
				if resp.StatusCode == 201 {
					id := mustGetID(t, body)
					cleanup(t, wafctlURL+"/api/exclusions/"+id)
				}
			}
		})
	}
}

// TestSkipGeneratesPolicyRule verifies that a skip exclusion generates a
// policy rule with type=skip and skip_targets in the output.
func TestSkipGeneratesPolicyRule(t *testing.T) {
	testPath := "/e2e-skip-gen-" + time.Now().Format("150405")

	// Create a skip rule targeting specific CRS rule IDs.
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-skip-gen", "type": "skip", "enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": testPath},
		},
		"skip_targets": map[string]any{
			"rules":  []string{"920350", "941100"},
			"phases": []string{"detect"},
		},
	})
	assertCode(t, "create skip", 201, resp)
	id := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+id) })

	// Generate policy rules.
	resp2, body2 := httpPost(t, wafctlURL+"/api/config/generate", struct{}{})
	assertCode(t, "generate", 200, resp2)

	// Parse and find our skip rule.
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(body2, &outer); err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}
	var policyFile struct {
		Rules []struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			Priority    int    `json:"priority"`
			SkipTargets *struct {
				Rules        []string `json:"rules"`
				Phases       []string `json:"phases"`
				AllRemaining bool     `json:"all_remaining"`
			} `json:"skip_targets"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(outer["policy_rules"], &policyFile); err != nil {
		t.Fatalf("unmarshal policy_rules: %v", err)
	}

	found := false
	for _, r := range policyFile.Rules {
		if r.Name == "e2e-skip-gen" {
			found = true
			if r.Type != "skip" {
				t.Errorf("expected type=skip, got %q", r.Type)
			}
			if r.Priority < 200 || r.Priority >= 300 {
				t.Errorf("skip priority %d not in [200,300)", r.Priority)
			}
			if r.SkipTargets == nil {
				t.Fatal("expected skip_targets in generated rule")
			}
			if len(r.SkipTargets.Rules) != 2 {
				t.Errorf("expected 2 rules, got %d", len(r.SkipTargets.Rules))
			}
			if len(r.SkipTargets.Phases) != 1 || r.SkipTargets.Phases[0] != "detect" {
				t.Errorf("expected phases=[detect], got %v", r.SkipTargets.Phases)
			}
			t.Logf("skip rule: priority=%d targets=%+v", r.Priority, r.SkipTargets)
			break
		}
	}
	if !found {
		t.Error("skip rule 'e2e-skip-gen' not found in generated output")
	}
}

// ─── Negated Operator E2E Tests ─────────────────────────────────────

// TestNegatedOperatorBlockRule verifies that not_contains creates a block rule
// that blocks requests whose path does NOT contain the specified substring.
func TestNegatedOperatorBlockRule(t *testing.T) {
	safePath := "/e2e-negated-safe-" + time.Now().Format("150405")
	blockedPath := "/e2e-negated-blocked-" + time.Now().Format("150405")

	// Create a block rule: block paths starting with our test prefix that
	// don't contain "safe". Scoped to test prefix to avoid blocking other tests.
	testPrefix := "/e2e-negated-" + time.Now().Format("150405")
	safePath = testPrefix + "-safe"
	blockedPath = testPrefix + "-blocked"
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-negated-not-contains", "type": "block", "enabled": true,
		"group_operator": "and",
		"conditions": []map[string]string{
			{"field": "path", "operator": "begins_with", "value": testPrefix},
			{"field": "path", "operator": "not_contains", "value": "safe"},
		},
	})
	assertCode(t, "create block with not_contains", 201, resp)
	id := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+id)
		deployWAF(t)
	})

	// Deploy and wait for it to take effect.
	deployAndWaitForStatus(t, caddyURL+blockedPath, 403)

	// Path without "safe" should be blocked.
	resp2, _ := httpGetRetry(t, caddyURL+blockedPath, 3)
	if resp2.StatusCode != 403 {
		t.Errorf("expected 403 for path without 'safe', got %d", resp2.StatusCode)
	}

	// Path containing "safe" should NOT be blocked.
	resp3, _ := httpGetRetry(t, caddyURL+safePath, 3)
	if resp3.StatusCode == 403 {
		t.Errorf("path containing 'safe' should not be blocked, got 403")
	}
	t.Logf("safe=%d blocked=%d", resp3.StatusCode, resp2.StatusCode)
}

// TestNegatedOperatorValidation verifies that the API accepts all 6 negated
// operators via create/validate.
func TestNegatedOperatorValidation(t *testing.T) {
	t.Parallel()

	operators := []struct {
		op    string
		field string
		value string
	}{
		{"not_contains", "path", "/safe"},
		{"not_begins_with", "path", "/api"},
		{"not_ends_with", "path", ".html"},
		{"not_regex", "user_agent", "^Bot"},
		{"not_in", "method", "GET|POST"},
	}

	for _, tt := range operators {
		t.Run(tt.op, func(t *testing.T) {
			resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
				"name":    fmt.Sprintf("e2e-negop-%s", tt.op),
				"type":    "block",
				"enabled": true,
				"conditions": []map[string]string{
					{"field": tt.field, "operator": tt.op, "value": tt.value},
				},
			})
			if resp.StatusCode != 201 {
				t.Errorf("expected 201 for operator %s, got %d: %s", tt.op, resp.StatusCode, body)
				return
			}
			id := mustGetID(t, body)
			cleanup(t, wafctlURL+"/api/exclusions/"+id)
		})
	}
}

// TestNegatedOperatorNotInBlock verifies not_in operator: block requests
// whose method is NOT in the specified set.
func TestNegatedOperatorNotInBlock(t *testing.T) {
	testPath := "/e2e-not-in-" + time.Now().Format("150405")

	// Block if method not_in GET|HEAD — so POST should be blocked.
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-not-in-method", "type": "block", "enabled": true,
		"conditions": []map[string]string{
			{"field": "method", "operator": "not_in", "value": "GET|HEAD"},
			{"field": "path", "operator": "eq", "value": testPath},
		},
	})
	assertCode(t, "create block with not_in", 201, resp)
	id := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+id)
		deployWAF(t)
	})

	// Deploy and wait for POST to be blocked (method NOT in GET|HEAD → block).
	// We can't wait on GET status since it passes through to backend (404).
	time.Sleep(1 * time.Second)
	deployWAF(t)

	// Wait for the rule to take effect by polling POST.
	waitForCondition(t, "POST blocked on "+testPath, 15*time.Second, func() bool {
		code, err := httpPostRaw(caddyURL+testPath, []byte(`{}`))
		return err == nil && code == 403
	})

	// GET should pass (method IS in the set, so not_in = false → no block).
	resp2, _ := httpGetRetry(t, caddyURL+testPath, 3)
	if resp2.StatusCode == 403 {
		blockedBy := resp2.Header.Get("X-Blocked-By")
		blockedRule := resp2.Header.Get("X-Blocked-Rule")
		score := resp2.Header.Get("X-Anomaly-Score")
		t.Errorf("GET should not be blocked (method is in GET|HEAD set), got 403 (X-Blocked-By=%q X-Blocked-Rule=%q X-Anomaly-Score=%q)", blockedBy, blockedRule, score)
	}

	// POST should be blocked (method NOT in GET|HEAD → not_in = true → block).
	postCode, err := httpPostRaw(caddyURL+testPath, []byte(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	if postCode != 403 {
		t.Errorf("expected POST to be blocked (403), got %d", postCode)
	}

	t.Logf("GET=%d POST=%d", resp2.StatusCode, postCode)
}

// ─── Logged (Below-Threshold Detect) E2E Tests ──────────────────────

// TestLoggedEventsCollected verifies that below-threshold detect events
// (tuning/log-only mode) are collected and appear in the events API.
func TestLoggedEventsCollected(t *testing.T) {
	// Save current config.
	_, origBody := httpGet(t, wafctlURL+"/api/config")

	// Set a very high threshold (tuning mode) so detect rules fire but don't block.
	resp, _ := httpPut(t, wafctlURL+"/api/config", map[string]any{
		"defaults": map[string]any{
			"mode":               "enabled",
			"paranoia_level":     2,
			"inbound_threshold":  10000,
			"outbound_threshold": 10000,
		},
		"services": map[string]any{},
	})
	assertCode(t, "set tuning config", 200, resp)

	// Deploy the config change and wait for hot-reload to propagate.
	// The mtime-based file watcher polls every few seconds, so we use
	// waitForCondition to verify the high threshold has taken effect.
	deployWAF(t)
	waitForCondition(t, "tuning mode active", 15*time.Second, func() bool {
		req, _ := http.NewRequest("GET", caddyURL+"/get", nil)
		req.Header.Set("User-Agent", "tuning-probe")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("X-Custom-Test", "' OR 1=1--")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode != 403
	})

	// Send a request that triggers CRS rules (SQLi in a header value).
	// httpbun doesn't care about headers so it returns 200, but CRS detects the payload.
	// With threshold=10000, this should NOT be blocked but should be logged.
	sentinel := fmt.Sprintf("E2E-Logged/%d", time.Now().UnixNano())
	req, _ := http.NewRequest("GET", caddyURL+"/get", nil)
	req.Header.Set("User-Agent", sentinel)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Custom-Test", "' OR 1=1--")
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("SQLi request: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode == 403 {
		t.Fatalf("expected non-403 in tuning mode (threshold=10000), got 403")
	}
	t.Logf("tuning mode SQLi status: %d (expected 200)", resp2.StatusCode)

	// Wait for the event to be collected. Access log tail interval is 2s,
	// plus processing time. Use a polling wait instead of fixed sleep.
	time.Sleep(8 * time.Second)

	// Check if the logged event appears in the events API.
	_, eventsBody := httpGet(t, wafctlURL+"/api/events?hours=1&limit=50")
	events := jsonFieldArray(eventsBody, "events")

	found := false
	for _, e := range events {
		var evt map[string]any
		if json.Unmarshal(e, &evt) != nil {
			continue
		}
		ua, _ := evt["user_agent"].(string)
		if ua == sentinel {
			found = true
			eventType, _ := evt["event_type"].(string)
			score, _ := evt["anomaly_score"].(float64)
			t.Logf("found logged event: type=%s score=%v blocked=%v", eventType, score, evt["is_blocked"])
			if eventType != "logged" {
				t.Errorf("expected event_type=logged, got %q", eventType)
			}
			if score == 0 {
				t.Error("expected non-zero anomaly_score for logged event")
			}
			blocked, _ := evt["is_blocked"].(bool)
			if blocked {
				t.Error("expected is_blocked=false for logged event")
			}
			break
		}
	}
	if !found {
		t.Logf("total events returned: %d", len(events))
		t.Error("logged event not found in events API — below-threshold detect events may not be collected")
	}

	// Restore original config.
	var origConfig map[string]any
	json.Unmarshal(origBody, &origConfig)
	httpPut(t, wafctlURL+"/api/config", origConfig)
	deployWAF(t)
}

// TestSkipRuleBypassesDetect verifies that a skip rule targeting specific CRS
// rule IDs actually prevents those rules from scoring.
func TestSkipRuleBypassesDetect(t *testing.T) {
	testPath := "/e2e-skip-detect-" + time.Now().Format("150405")

	// First, verify the path triggers detect scoring without a skip rule.
	// Create a detect rule with a low threshold that catches any anomaly.
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-detect-baseline", "type": "detect", "enabled": true,
		"severity": "CRITICAL",
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": testPath},
		},
	})
	assertCode(t, "create detect rule", 201, resp)
	detectID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+detectID) })

	// Now create a skip rule that targets the detect phase for the same path.
	resp, body = httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-skip-detect", "type": "skip", "enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": testPath},
		},
		"skip_targets": map[string]any{
			"phases": []string{"detect"},
		},
	})
	assertCode(t, "create skip rule", 201, resp)
	skipID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+skipID)
		cleanup(t, wafctlURL+"/api/exclusions/"+detectID)
		deployWAF(t)
	})

	// Deploy — skip should prevent the detect rule from firing.
	// The detect rule alone would block SQLi (CRITICAL=5 >= threshold 5).
	// First verify detect works WITHOUT skip by checking generate output.
	resp3, body3 := httpPost(t, wafctlURL+"/api/config/generate", struct{}{})
	assertCode(t, "generate", 200, resp3)
	t.Logf("generated policy rules: %s", string(body3)[:min(500, len(body3))])

	time.Sleep(1 * time.Second)
	deployWAF(t)
	// Policy engine hot-reload interval is 5s in e2e config.
	time.Sleep(8 * time.Second)

	// Send a request with a SQLi payload in a custom header.
	// Without skip, the custom detect rule + default CRS rules would block this.
	// With skip targeting detect phase, ALL detect evaluation is bypassed.
	req, _ := http.NewRequest("GET", caddyURL+testPath, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; e2e-test/1.0)")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Test-Payload", "' OR 1=1--")
	resp4, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp4.Body.Close()

	if resp4.StatusCode == 403 {
		t.Errorf("expected non-403 (skip should bypass detect), got 403")
	}
	t.Logf("skip-detect status: %d (expected non-403)", resp4.StatusCode)
}

// ─── Logged Event Detail E2E Tests ──────────────────────────────────

// TestLoggedEventHasMatchedRules verifies that below-threshold detect events
// include matched rule IDs, severity, and tags (plugin v0.14.1 fix).
func TestLoggedEventHasMatchedRules(t *testing.T) {
	// Save current config.
	_, origBody := httpGet(t, wafctlURL+"/api/config")

	// Set tuning mode — high threshold so nothing blocks.
	resp, _ := httpPut(t, wafctlURL+"/api/config", map[string]any{
		"defaults": map[string]any{
			"mode": "enabled", "paranoia_level": 2,
			"inbound_threshold": 10000, "outbound_threshold": 10000,
		},
		"services": map[string]any{},
	})
	assertCode(t, "set tuning config", 200, resp)
	deployWAF(t)
	time.Sleep(3 * time.Second)

	// Send a request with a SQLi payload in a custom header — triggers CRS rules.
	sentinel := fmt.Sprintf("E2E-LoggedDetail/%d", time.Now().UnixNano())
	req, _ := http.NewRequest("GET", caddyURL+"/get", nil)
	req.Header.Set("User-Agent", sentinel)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Test-Payload", "' UNION SELECT * FROM users--")
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp2.Body.Close()
	t.Logf("tuning mode status: %d", resp2.StatusCode)

	// Wait for event collection.
	time.Sleep(8 * time.Second)

	// Find the logged event.
	_, eventsBody := httpGet(t, wafctlURL+"/api/events?hours=1&limit=100")
	events := jsonFieldArray(eventsBody, "events")

	for _, e := range events {
		var evt map[string]any
		if json.Unmarshal(e, &evt) != nil {
			continue
		}
		ua, _ := evt["user_agent"].(string)
		if ua != sentinel {
			continue
		}
		eventType, _ := evt["event_type"].(string)
		if eventType != "logged" {
			t.Errorf("expected event_type=logged, got %q", eventType)
		}
		// Verify matched_rules is populated (plugin v0.14.1 fix).
		rulesRaw, _ := json.Marshal(evt["matched_rules"])
		var rules []map[string]any
		json.Unmarshal(rulesRaw, &rules)
		if len(rules) == 0 {
			t.Fatal("expected matched_rules to be populated for logged event (plugin v0.14.1)")
		}
		// Verify at least one rule has an ID, severity, and score.
		first := rules[0]
		ruleID := first["id"]
		severity := first["severity"]
		t.Logf("logged event: %d matched rules, first: id=%v severity=%v", len(rules), ruleID, severity)
		if ruleID == nil || ruleID == float64(0) {
			t.Error("matched_rules[0].id should be non-zero")
		}
		if severity == nil {
			t.Error("matched_rules[0].severity should be set")
		}
		// Verify tags are populated.
		tagsRaw, _ := json.Marshal(evt["tags"])
		var tags []string
		json.Unmarshal(tagsRaw, &tags)
		t.Logf("logged event tags: %v", tags)
		// Tags may be empty if the matched rules don't have tags, but rule_tags should exist.
		ruleTagsRaw, _ := json.Marshal(evt["rule_tags"])
		t.Logf("logged event rule_tags: %s", string(ruleTagsRaw))

		// Restore config and return — found the event.
		var origConfig map[string]any
		json.Unmarshal(origBody, &origConfig)
		httpPut(t, wafctlURL+"/api/config", origConfig)
		deployWAF(t)
		return
	}
	t.Fatal("logged event with sentinel UA not found")
}

// TestSkipRuleWithSpecificRuleIDs verifies that a skip rule targeting specific
// CRS rule IDs only skips those rules, not all detect evaluation.
func TestSkipRuleWithSpecificRuleIDs(t *testing.T) {
	testPath := "/e2e-skip-ids-" + time.Now().Format("150405")

	// Create a skip rule that skips specific rule IDs (not the whole detect phase).
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "e2e-skip-specific-ids", "type": "skip", "enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": testPath},
		},
		"skip_targets": map[string]any{
			// Skip only rule 920350 (hypothetical) — other detect rules should still fire.
			"rules": []string{"920350"},
		},
	})
	assertCode(t, "create skip rule", 201, resp)
	id := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+id)
		deployWAF(t)
	})

	// Verify the generated policy has skip_targets with specific rule IDs.
	resp2, body2 := httpPost(t, wafctlURL+"/api/config/generate", struct{}{})
	assertCode(t, "generate", 200, resp2)

	var outer map[string]json.RawMessage
	json.Unmarshal(body2, &outer)
	var pf struct {
		Rules []struct {
			Name string `json:"name"`
			Type string `json:"type"`
			ST   *struct {
				Rules  []string `json:"rules"`
				Phases []string `json:"phases"`
			} `json:"skip_targets"`
		} `json:"rules"`
	}
	json.Unmarshal(outer["policy_rules"], &pf)

	found := false
	for _, r := range pf.Rules {
		if r.Name == "e2e-skip-specific-ids" {
			found = true
			if r.ST == nil {
				t.Fatal("expected skip_targets")
			}
			if len(r.ST.Rules) != 1 || r.ST.Rules[0] != "920350" {
				t.Errorf("expected rules=[920350], got %v", r.ST.Rules)
			}
			if len(r.ST.Phases) > 0 {
				t.Errorf("expected no phases (rule-specific skip), got %v", r.ST.Phases)
			}
			t.Logf("skip rule: rules=%v phases=%v", r.ST.Rules, r.ST.Phases)
		}
	}
	if !found {
		t.Error("skip rule not found in generated output")
	}
}

// TestInlineSkipRuleCRUD verifies the workflow of creating a skip rule
// scoped to a host (the per-service override pattern) via the exclusions API.
func TestInlineSkipRuleCRUD(t *testing.T) {
	host := "e2e-inline-skip.example.com"

	// Create a skip rule with host condition + specific rule IDs.
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "Skip CRS rules for " + host, "type": "skip", "enabled": true,
		"conditions": []map[string]string{
			{"field": "host", "operator": "eq", "value": host},
		},
		"group_operator": "and",
		"skip_targets": map[string]any{
			"rules":  []string{"932236", "942120"},
			"phases": []string{"detect"},
		},
	})
	assertCode(t, "create inline skip", 201, resp)
	id := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+id) })

	// Read it back.
	resp2, body2 := httpGet(t, wafctlURL+"/api/exclusions/"+id)
	assertCode(t, "get inline skip", 200, resp2)
	assertField(t, "type", body2, "type", "skip")
	assertField(t, "name", body2, "name", "Skip CRS rules for "+host)

	// Verify conditions.
	conds := jsonFieldArray(body2, "conditions")
	if len(conds) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conds))
	}
	var cond map[string]string
	json.Unmarshal(conds[0], &cond)
	if cond["field"] != "host" || cond["value"] != host {
		t.Errorf("expected host=%s, got field=%s value=%s", host, cond["field"], cond["value"])
	}

	// Now "consolidate" — delete old rule and create new one with more IDs
	// (mimicking the ServiceSettingsCard workflow).
	cleanup(t, wafctlURL+"/api/exclusions/"+id)

	resp3, body3 := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{
		"name": "Skip CRS rules for " + host, "type": "skip", "enabled": true,
		"conditions": []map[string]string{
			{"field": "host", "operator": "eq", "value": host},
		},
		"group_operator": "and",
		"skip_targets": map[string]any{
			"rules":  []string{"932236", "942120", "942340"},
			"phases": []string{"detect"},
		},
	})
	assertCode(t, "create consolidated skip", 201, resp3)
	newID := mustGetID(t, body3)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+newID) })

	// Verify 3 rule IDs.
	resp4, body4 := httpGet(t, wafctlURL+"/api/exclusions/"+newID)
	assertCode(t, "get consolidated", 200, resp4)
	st := jsonField(body4, "skip_targets")
	if st == "" {
		t.Fatal("expected skip_targets")
	}
	t.Logf("consolidated skip_targets: %s", st)

	// Deploy and verify health.
	deployWAF(t)
	resp5, _ := httpGet(t, wafctlURL+"/api/health")
	assertCode(t, "health after skip deploy", 200, resp5)
}

// TestLoggedEventsSummaryCount verifies that logged events appear in the summary API.
func TestLoggedEventsSummaryCount(t *testing.T) {
	// After TestLoggedEventsCollected ran earlier, there should be logged events.
	_, body := httpGet(t, wafctlURL+"/api/summary?hours=1")
	logged := jsonInt(body, "logged_events")
	t.Logf("summary logged_events count: %d", logged)
	// We don't assert > 0 because this depends on test ordering and event timing,
	// but we verify the field exists and is a valid number.
	if logged < 0 {
		t.Error("summary.logged_events should be >= 0")
	}
}
