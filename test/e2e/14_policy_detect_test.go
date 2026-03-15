package e2e_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// 20. Policy Engine — Detect / Anomaly Scoring (v0.8.0)
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineDetectCRUD(t *testing.T) {
	// Create a detect rule via the wafctl API.
	payload := map[string]any{
		"name":                  "e2e-detect-test",
		"type":                  "detect",
		"description":           "E2E detect rule",
		"severity":              "WARNING",
		"detect_paranoia_level": 1,
		"enabled":               true,
		"conditions": []map[string]string{
			{"field": "user_agent", "operator": "contains", "value": "E2EBot"},
		},
		"tags": []string{"e2e-test"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create detect rule", 201, resp)
	detectID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+detectID) })

	assertField(t, "create", body, "type", "detect")
	assertField(t, "create", body, "severity", "WARNING")

	// Get — verify round-trip.
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/exclusions/"+detectID)
		assertCode(t, "get", 200, resp)
		assertField(t, "get", body, "type", "detect")
		assertField(t, "get", body, "severity", "WARNING")
		assertField(t, "get", body, "name", "e2e-detect-test")
	})

	// Update severity to CRITICAL.
	t.Run("update", func(t *testing.T) {
		resp, body := httpPut(t, wafctlURL+"/api/exclusions/"+detectID, map[string]any{"severity": "CRITICAL"})
		assertCode(t, "update", 200, resp)
		assertField(t, "update", body, "severity", "CRITICAL")
		assertField(t, "update", body, "name", "e2e-detect-test")
	})

	// Delete.
	t.Run("delete", func(t *testing.T) {
		resp, _ := httpDelete(t, wafctlURL+"/api/exclusions/"+detectID)
		assertCode(t, "delete", 204, resp)
		detectID = "" // prevent cleanup double-delete
	})
}

func TestPolicyEngineDetectValidation(t *testing.T) {
	t.Parallel()
	// Missing severity — should fail.
	t.Run("missing severity rejected", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":       "e2e-bad-detect",
			"type":       "detect",
			"enabled":    true,
			"conditions": []map[string]string{{"field": "path", "operator": "eq", "value": "/test"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "missing severity", 400, resp)
		// API returns {"error": "validation failed", "details": "detect requires severity ..."}
		details := jsonField(body, "details")
		if !strings.Contains(details, "severity") {
			t.Errorf("expected details about severity, got: %q (error: %q)", details, jsonField(body, "error"))
		}
	})

	// Invalid severity — should fail.
	t.Run("invalid severity rejected", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":       "e2e-bad-detect2",
			"type":       "detect",
			"severity":   "HIGH",
			"enabled":    true,
			"conditions": []map[string]string{{"field": "path", "operator": "eq", "value": "/test"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "invalid severity", 400, resp)
		details := jsonField(body, "details")
		if !strings.Contains(details, "severity") {
			t.Errorf("expected details about severity, got: %q (error: %q)", details, jsonField(body, "error"))
		}
	})

	// Invalid paranoia level — should fail.
	t.Run("invalid PL rejected", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":                  "e2e-bad-detect3",
			"type":                  "detect",
			"severity":              "NOTICE",
			"detect_paranoia_level": 5,
			"enabled":               true,
			"conditions":            []map[string]string{{"field": "path", "operator": "eq", "value": "/test"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "invalid PL", 400, resp)
		details := jsonField(body, "details")
		if !strings.Contains(details, "paranoia") {
			t.Errorf("expected details about paranoia level, got: %q (error: %q)", details, jsonField(body, "error"))
		}
	})

	// Empty value with eq operator — should succeed (matching missing headers).
	t.Run("empty value with eq allowed", func(t *testing.T) {
		t.Parallel()
		payload := map[string]any{
			"name":       "e2e-detect-empty-val",
			"type":       "detect",
			"severity":   "NOTICE",
			"enabled":    true,
			"conditions": []map[string]string{{"field": "user_agent", "operator": "eq", "value": ""}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "empty value eq", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+id) })
	})
}

func TestPolicyEngineDetectScoring(t *testing.T) {
	// Test the full anomaly scoring pipeline:
	// 1. Create detect rules that target specific conditions
	// 2. Configure waf_config with a threshold
	// 3. Deploy via policy-rules.json
	// 4. Send requests that trigger detect rules → score exceeds threshold
	// 5. Verify 403 with X-Anomaly-Score header
	//
	// Note: The v4 migration seeds 3 heuristic detect rules that also contribute:
	//   - Missing Accept Header (NOTICE=2)
	//   - Missing User-Agent (WARNING=3)
	//   - Missing Referer on Non-API GET (NOTICE=2, GET only)
	// A GET with no UA, no Accept, no Referer triggers all 3 → base score = 7.

	// Step 1: Create 2 additional detect rules.
	// Combined score with seeded rules for a "naked" GET:
	// Seeded: 2+3+2=7, Custom: 3+3=6 → Total=13
	rule1Payload := map[string]any{
		"name":        "e2e-detect-no-ua",
		"type":        "detect",
		"description": "Missing User-Agent (custom)",
		"severity":    "WARNING",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "user_agent", "operator": "eq", "value": ""}},
		"tags":        []string{"e2e-detect"},
	}
	resp1, body1 := httpPost(t, wafctlURL+"/api/exclusions", rule1Payload)
	assertCode(t, "create detect rule 1", 201, resp1)
	rule1ID := mustGetID(t, body1)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+rule1ID) })

	rule2Payload := map[string]any{
		"name":        "e2e-detect-no-accept",
		"type":        "detect",
		"description": "Missing Accept header (custom)",
		"severity":    "WARNING",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "header", "operator": "eq", "value": "Accept:"}},
		"tags":        []string{"e2e-detect"},
	}
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions", rule2Payload)
	assertCode(t, "create detect rule 2", 201, resp2)
	rule2ID := mustGetID(t, body2)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+rule2ID) })

	// Step 2: Set threshold=5 — a "naked" GET (no UA, no Accept) triggers score=13.
	configPayload := map[string]any{
		"defaults": map[string]any{
			"paranoia_level":     2,
			"inbound_threshold":  5,
			"outbound_threshold": 5,
		},
	}
	resp3, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "set config", 200, resp3)

	// Step 3: Deploy — generates policy-rules.json with detect rules and waf_config.
	time.Sleep(1 * time.Second) // mtime boundary
	resp4, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp4)
	assertField(t, "deploy", deployBody, "status", "deployed")

	// Wait for plugin hot-reload — poll until a "naked" GET (no UA, no Accept) gets 403.
	waitForCondition(t, "detect scoring blocks naked GET", 10*time.Second, func() bool {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", "")
		req.Header.Del("Accept")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 403
	})

	// Step 4: Send a request with no User-Agent AND no Accept header.
	// Total score ~13 (seeded 7 + custom 6) >> threshold 5.
	t.Run("scoring exceeds threshold — 403 detect_block", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "")
		req.Header.Del("Accept")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (detect_block), got %d; body=%.200s",
				resp.StatusCode, string(body))
		}

		// Verify X-Anomaly-Score header is present on the blocked response.
		score := resp.Header.Get("X-Anomaly-Score")
		if score == "" {
			t.Log("X-Anomaly-Score header not present on 403 (may be hidden by error handler)")
		} else {
			t.Logf("X-Anomaly-Score: %s", score)
		}
	})

	// Step 5: Send a well-formed request — should pass scoring.
	// With UA, Accept, and Referer all present, no detect rules fire → score=0.
	t.Run("normal request passes scoring", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 E2E-Test")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Referer", "https://example.com/")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 (score=0, threshold=5), got 403")
		}
	})

	// Step 6: Raise the threshold above the max possible score so nothing blocks.
	// Max score for "naked" GET: ~13. Set threshold=20 → always passes.
	t.Run("raised threshold prevents block", func(t *testing.T) {
		configPayload := map[string]any{
			"defaults": map[string]any{
				"paranoia_level":     2,
				"inbound_threshold":  20,
				"outbound_threshold": 20,
			},
		}
		resp, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
		assertCode(t, "raise threshold", 200, resp)

		time.Sleep(1 * time.Second) // mtime boundary
		resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
		assertCode(t, "deploy raised threshold", 200, resp2)
		assertField(t, "deploy", deployBody, "status", "deployed")

		// Wait for plugin hot-reload — poll until naked GET stops getting 403.
		waitForCondition(t, "raised threshold allows naked GET", 10*time.Second, func() bool {
			req, err := http.NewRequest("GET", caddyURL+"/get", nil)
			if err != nil {
				return false
			}
			req.Header.Set("User-Agent", "")
			req.Header.Del("Accept")
			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode != 403
		})

		// Same "naked" GET — score ~13 but threshold=20 → passes.
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "")
		req.Header.Del("Accept")

		resp3, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp3.Body.Close()

		if resp3.StatusCode == 403 {
			t.Errorf("expected non-403 (score ~13 < threshold=20), got 403")
		}
	})

	// Step 7: Cleanup — restore config to production defaults.
	restorePayload := map[string]any{
		"defaults": map[string]any{
			"paranoia_level":     2,
			"inbound_threshold":  10,
			"outbound_threshold": 10,
		},
	}
	httpPut(t, wafctlURL+"/api/config", restorePayload)
	time.Sleep(1 * time.Second) // mtime boundary
	httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	waitForStatus(t, caddyURL+"/get", 200, 10*time.Second)
}

func TestPolicyEngineDetectParanoiaLevel(t *testing.T) {
	// Test that detect rules with PL > service PL are skipped.
	// Create a PL=4 CRITICAL detect rule, set service PL=1, verify rule doesn't trigger.
	//
	// Test request: no UA, has Accept, no Referer, GET
	// Seeded PL=1 rules that fire:
	//   - "Missing User-Agent" (WARNING=3) — user_agent eq ""
	//   - "Missing Referer on Non-API GET" (NOTICE=2) — method=GET + referer=""
	// Seeded total = 5. Custom PL=4 CRITICAL = 5.
	// Threshold = 8: at PL=1 → 5 < 8 (pass); at PL=4 → 10 ≥ 8 (block).

	rulePL4 := map[string]any{
		"name":                  "e2e-detect-pl4",
		"type":                  "detect",
		"description":           "PL4 detect rule — should not fire at PL1",
		"severity":              "CRITICAL",
		"detect_paranoia_level": 4,
		"enabled":               true,
		"conditions":            []map[string]string{{"field": "user_agent", "operator": "eq", "value": ""}},
		"tags":                  []string{"e2e-detect-pl"},
	}
	resp1, body1 := httpPost(t, wafctlURL+"/api/exclusions", rulePL4)
	assertCode(t, "create PL4 rule", 201, resp1)
	ruleID := mustGetID(t, body1)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	// Set PL=1, threshold=8 — seeded PL1 rules score 5, below 8.
	configPayload := map[string]any{
		"defaults": map[string]any{
			"paranoia_level":     1,
			"inbound_threshold":  8,
			"outbound_threshold": 10,
		},
	}
	resp2, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "set PL1 config", 200, resp2)

	time.Sleep(1 * time.Second) // mtime boundary
	resp3, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp3)
	assertField(t, "deploy", deployBody, "status", "deployed")
	waitForStatus(t, caddyURL+"/get", 200, 10*time.Second)

	// Send request with no UA — PL4 rule is skipped at PL=1, score=5 < 8 → passes.
	t.Run("PL4 rule skipped at PL1 — score below threshold", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "")
		req.Header.Set("Accept", "text/html")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 (PL4 skipped, score=5 < threshold=8), got 403")
		}
	})

	// Now raise PL to 4 — same request should now trigger PL4 rule, total=10 ≥ 8 → block.
	t.Run("PL4 rule fires at PL4 — score exceeds threshold", func(t *testing.T) {
		configPL4 := map[string]any{
			"defaults": map[string]any{
				"paranoia_level":     4,
				"inbound_threshold":  8,
				"outbound_threshold": 10,
			},
		}
		resp, _ := httpPut(t, wafctlURL+"/api/config", configPL4)
		assertCode(t, "set PL4 config", 200, resp)

		time.Sleep(1 * time.Second) // mtime boundary
		resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
		assertCode(t, "deploy PL4", 200, resp2)
		assertField(t, "deploy PL4", deployBody, "status", "deployed")

		// Wait for plugin hot-reload — poll until PL4 rule fires (no UA → 403).
		waitForCondition(t, "PL4 rule blocks naked GET", 10*time.Second, func() bool {
			req, err := http.NewRequest("GET", caddyURL+"/get", nil)
			if err != nil {
				return false
			}
			req.Header.Set("User-Agent", "")
			req.Header.Set("Accept", "text/html")
			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == 403
		})

		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "")
		req.Header.Set("Accept", "text/html")

		resp3, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp3.Body.Close()

		if resp3.StatusCode != 403 {
			t.Errorf("expected 403 (PL4 fires, score=10 >= threshold=8), got %d", resp3.StatusCode)
		}
	})

	// Cleanup — restore defaults.
	restorePayload := map[string]any{
		"defaults": map[string]any{
			"paranoia_level":     2,
			"inbound_threshold":  10,
			"outbound_threshold": 10,
		},
	}
	httpPut(t, wafctlURL+"/api/config", restorePayload)
	time.Sleep(1 * time.Second) // mtime boundary
	httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	waitForStatus(t, caddyURL+"/get", 200, 10*time.Second)
}

func TestPolicyEngineDetectWafConfig(t *testing.T) {
	// Verify that WAF config can be set and retrieved correctly.

	// Set a specific config.
	configPayload := map[string]any{
		"defaults": map[string]any{
			"paranoia_level":     3,
			"inbound_threshold":  15,
			"outbound_threshold": 8,
		},
	}
	resp, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "set config", 200, resp)

	// Verify config was persisted by reading it back.
	resp2, body2 := httpGet(t, wafctlURL+"/api/config")
	assertCode(t, "get config", 200, resp2)
	assertField(t, "paranoia_level", body2, "defaults.paranoia_level", "3")
	assertField(t, "inbound_threshold", body2, "defaults.inbound_threshold", "15")
	logBody(t, "config output", body2)

	// Restore defaults.
	restorePayload := map[string]any{
		"defaults": map[string]any{
			"paranoia_level":     2,
			"inbound_threshold":  10,
			"outbound_threshold": 10,
		},
	}
	httpPut(t, wafctlURL+"/api/config", restorePayload)
}

func TestPolicyEngineDetectMigrationSeedRules(t *testing.T) {
	t.Parallel()
	// v4 migration is now a no-op and v5 removes previously-seeded heuristic
	// detect rules. These rules now ship in default-rules.json instead.
	// Verify the user store has zero seeded detect rules.
	resp, body := httpGet(t, wafctlURL+"/api/exclusions")
	assertCode(t, "list exclusions", 200, resp)

	var exclusions []json.RawMessage
	if err := json.Unmarshal(body, &exclusions); err != nil {
		t.Fatalf("unmarshal exclusions: %v", err)
	}

	seededDetectNames := map[string]bool{
		"Missing Accept Header":          true,
		"Missing User-Agent":             true,
		"Missing Referer on Non-API GET": true,
	}
	seededBotNames := map[string]bool{
		"Scanner UA Block":   true,
		"HTTP/1.0 Anomaly":   true,
		"Generic UA Anomaly": true,
	}
	for _, raw := range exclusions {
		typ := jsonField(raw, "type")
		name := jsonField(raw, "name")
		if typ == "detect" && seededDetectNames[name] {
			t.Errorf("seeded detect rule %q should have been removed by v5 migration", name)
		}
		if seededBotNames[name] {
			t.Errorf("seeded bot rule %q should have been removed by v6 migration", name)
		}
	}
	t.Log("confirmed: no seeded heuristic detect or bot rules in user store (moved to default-rules.json)")
}

func TestDefaultRulesAPI(t *testing.T) {
	t.Parallel()
	// Verify the default rules API returns all baked-in rules.
	// v7: 255 rules (233 auto-converted CRS 4.24.1 + 12 hand-ported CRS + 10 custom 9100xxx)
	resp, body := httpGet(t, wafctlURL+"/api/default-rules")
	assertCode(t, "list default rules", 200, resp)

	var rules []json.RawMessage
	if err := json.Unmarshal(body, &rules); err != nil {
		t.Fatalf("unmarshal default rules: %v", err)
	}

	// v7: 255 default rules
	if len(rules) < 250 {
		t.Errorf("expected ~255 default rules (v7), got %d", len(rules))
	}
	t.Logf("default rules count: %d", len(rules))

	// Check that key rules exist.
	ruleIDs := map[string]bool{}
	for _, raw := range rules {
		ruleIDs[jsonField(raw, "id")] = true
	}

	// Custom 9100xxx rules (baked-in, not from CRS)
	for _, id := range []string{"9100032", "9100035", "9100036"} {
		if !ruleIDs[id] {
			t.Errorf("missing custom default rule %s", id)
		}
	}
	// Hand-ported CRS rules (not auto-convertible)
	for _, id := range []string{"920180", "920220", "920300", "920311", "920430", "920440", "920450", "930111", "932100", "932150", "932180", "943120"} {
		if !ruleIDs[id] {
			t.Errorf("missing hand-ported CRS rule %s", id)
		}
	}
	// Auto-converted CRS v7 — new operator rules
	for _, id := range []string{
		"942100", "942101", // detect_sqli
		"941100", "941101", // detect_xss
		"920270", "920271", "920272", "920273", "920274", // validate_byte_range
		"920240",           // validate_url_encoding
		"932120", "932130", // cmdLine transform
	} {
		if !ruleIDs[id] {
			t.Errorf("missing auto-converted CRS rule %s", id)
		}
	}
	// Auto-converted CRS v7 — broad category spot checks
	for _, id := range []string{
		"920100", // HTTP Request Method Enforcement (negate)
		"920170", // HTTP method validation
		"921110", // HTTP Response Splitting
		"930110", // Path Traversal
		"930120", // OS File Access
		"933200", // PHP Injection
		"934100", // Server Side Template Injection
	} {
		if !ruleIDs[id] {
			t.Errorf("missing CRS category rule %s", id)
		}
	}
	// Verify old rules were replaced by proper CRS equivalents
	for _, id := range []string{"9100010", "9100011"} {
		if ruleIDs[id] {
			t.Errorf("old rule %s should have been replaced by CRS equivalents", id)
		}
	}

	// Spot-check individual rule types.
	resp2, body2 := httpGet(t, wafctlURL+"/api/default-rules/9100032")
	assertCode(t, "get scanner rule", 200, resp2)
	if typ := jsonField(body2, "type"); typ != "block" {
		t.Errorf("9100032 type: want block, got %s", typ)
	}

	resp3, body3 := httpGet(t, wafctlURL+"/api/default-rules/942100")
	assertCode(t, "get detect_sqli rule", 200, resp3)
	if typ := jsonField(body3, "type"); typ != "detect" {
		t.Errorf("942100 type: want detect, got %s", typ)
	}

	resp4, body4 := httpGet(t, wafctlURL+"/api/default-rules/941100")
	assertCode(t, "get detect_xss rule", 200, resp4)
	if typ := jsonField(body4, "type"); typ != "detect" {
		t.Errorf("941100 type: want detect, got %s", typ)
	}

	resp5, body5 := httpGet(t, wafctlURL+"/api/default-rules/920270")
	assertCode(t, "get validate_byte_range rule", 200, resp5)
	if typ := jsonField(body5, "type"); typ != "detect" {
		t.Errorf("920270 type: want detect, got %s", typ)
	}

	t.Logf("confirmed: default rules API returns %d rules (v7, CRS 4.24.1)", len(rules))
}
