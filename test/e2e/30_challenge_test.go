package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// ════════════════════════════════════════════════════════════════════
//  30. Challenge Rule Type (PoW)
// ════════════════════════════════════════════════════════════════════

func TestChallengeCRUD(t *testing.T) {
	// Create a challenge rule.
	var ruleID string
	t.Run("create", func(t *testing.T) {
		payload := map[string]any{
			"name":                 "e2e-challenge-browsers",
			"type":                 "challenge",
			"description":          "E2E: challenge browser-like UA",
			"enabled":              true,
			"challenge_difficulty": 4,
			"challenge_algorithm":  "fast",
			"challenge_ttl":        "24h",
			"conditions": []map[string]string{
				{"field": "user_agent", "operator": "contains", "value": "Mozilla"},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "create challenge", 201, resp)
		ruleID = mustGetID(t, body)
		assertField(t, "create", body, "type", "challenge")
		assertField(t, "create", body, "challenge_difficulty", "4")
		assertField(t, "create", body, "challenge_algorithm", "fast")
		assertField(t, "create", body, "challenge_ttl", "24h")
	})

	if ruleID == "" {
		t.Fatal("no rule id, cannot continue CRUD tests")
	}
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

	// Get — verify challenge fields are persisted.
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rules/"+ruleID)
		assertCode(t, "get", 200, resp)
		assertField(t, "get", body, "name", "e2e-challenge-browsers")
		assertField(t, "get", body, "type", "challenge")
		assertField(t, "get", body, "challenge_difficulty", "4")
		assertField(t, "get", body, "challenge_algorithm", "fast")
	})

	// Update — change difficulty.
	t.Run("update-difficulty", func(t *testing.T) {
		resp, body := httpPut(t, wafctlURL+"/api/rules/"+ruleID, map[string]any{
			"challenge_difficulty": 8,
		})
		assertCode(t, "update", 200, resp)
		assertField(t, "update", body, "challenge_difficulty", "8")
		// Name should be preserved.
		assertField(t, "update", body, "name", "e2e-challenge-browsers")
	})

	// Delete.
	t.Run("delete", func(t *testing.T) {
		resp, _ := httpDelete(t, wafctlURL+"/api/rules/"+ruleID)
		assertCode(t, "delete", 204, resp)
		ruleID = "" // prevent double-delete in cleanup
	})
}

func TestChallengeValidation(t *testing.T) {
	t.Run("missing-conditions", func(t *testing.T) {
		payload := map[string]any{
			"name":    "no-conditions",
			"type":    "challenge",
			"enabled": true,
		}
		resp, _ := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "missing conditions", 400, resp)
	})

	t.Run("difficulty-too-high", func(t *testing.T) {
		payload := map[string]any{
			"name":                 "too-hard",
			"type":                 "challenge",
			"enabled":              true,
			"challenge_difficulty": 17,
			"conditions":           []map[string]string{{"field": "path", "operator": "eq", "value": "/"}},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "difficulty too high", 400, resp)
	})

	t.Run("invalid-algorithm", func(t *testing.T) {
		payload := map[string]any{
			"name":                "bad-algo",
			"type":                "challenge",
			"enabled":             true,
			"challenge_algorithm": "turbo",
			"conditions":          []map[string]string{{"field": "path", "operator": "eq", "value": "/"}},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "invalid algorithm", 400, resp)
	})

	t.Run("invalid-ttl", func(t *testing.T) {
		payload := map[string]any{
			"name":          "bad-ttl",
			"type":          "challenge",
			"enabled":       true,
			"challenge_ttl": "forever",
			"conditions":    []map[string]string{{"field": "path", "operator": "eq", "value": "/"}},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "invalid ttl", 400, resp)
	})

	t.Run("valid-defaults", func(t *testing.T) {
		payload := map[string]any{
			"name":       "defaults-only",
			"type":       "challenge",
			"enabled":    true,
			"conditions": []map[string]string{{"field": "user_agent", "operator": "contains", "value": "Bot"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "valid defaults", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+id) })

		// Defaults should be applied (difficulty 0 = use default of 4).
		assertField(t, "defaults", body, "type", "challenge")
	})
}

func TestChallengePriorityBand(t *testing.T) {
	// Ensure clean state.
	ensureDefaultConfig(t)

	// Create rules of different types to verify ordering.
	var ids []string
	createRule := func(name, ruleType string, extra map[string]any) string {
		payload := map[string]any{
			"name":    name,
			"type":    ruleType,
			"enabled": true,
			"conditions": []map[string]string{
				{"field": "path", "operator": "eq", "value": "/e2e-priority-test"},
			},
		}
		for k, v := range extra {
			payload[k] = v
		}
		resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "create "+name, 201, resp)
		id := mustGetID(t, body)
		ids = append(ids, id)
		return id
	}

	// Create in reverse priority order to verify sorting.
	createRule("e2e-detect-priority", "detect", map[string]any{"severity": "WARNING"})
	createRule("e2e-challenge-priority", "challenge", map[string]any{
		"challenge_difficulty": 4,
	})
	createRule("e2e-block-priority", "block", nil)
	createRule("e2e-allow-priority", "allow", nil)

	t.Cleanup(func() {
		for _, id := range ids {
			cleanup(t, wafctlURL+"/api/rules/"+id)
		}
	})

	// Deploy and read policy-rules.json via the generate-config endpoint.
	resp, body := httpPost(t, wafctlURL+"/api/config/generate", nil)
	assertCode(t, "generate config", 200, resp)

	// Parse the generated rules.
	var file struct {
		Rules []struct {
			Type     string `json:"type"`
			Priority int    `json:"priority"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(body, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Find our test rules by checking which types are present.
	typePriorities := make(map[string]int)
	for _, r := range file.Rules {
		// Only track the first occurrence of each type (our test rules).
		if _, exists := typePriorities[r.Type]; !exists {
			typePriorities[r.Type] = r.Priority
		}
	}

	// Verify ordering: allow < block < challenge < detect.
	allowP := typePriorities["allow"]
	blockP := typePriorities["block"]
	challengeP := typePriorities["challenge"]
	detectP := typePriorities["detect"]

	t.Logf("priorities: allow=%d block=%d challenge=%d detect=%d", allowP, blockP, challengeP, detectP)

	if allowP >= blockP {
		t.Errorf("allow (%d) should be before block (%d)", allowP, blockP)
	}
	if blockP >= challengeP {
		t.Errorf("block (%d) should be before challenge (%d)", blockP, challengeP)
	}
	if challengeP >= detectP {
		t.Errorf("challenge (%d) should be before detect (%d)", challengeP, detectP)
	}

	// Challenge should be in the 150-199 band.
	if challengeP < 150 || challengeP >= 200 {
		t.Errorf("challenge priority %d not in 150-199 band", challengeP)
	}
}

func TestChallengeInPolicyRulesJSON(t *testing.T) {
	ensureDefaultConfig(t)

	// Create a challenge rule.
	payload := map[string]any{
		"name":                 "e2e-challenge-json",
		"type":                 "challenge",
		"enabled":              true,
		"challenge_difficulty": 6,
		"challenge_algorithm":  "slow",
		"challenge_ttl":        "1h",
		"service":              "*",
		"conditions": []map[string]string{
			{"field": "user_agent", "operator": "regex", "value": "(?i)GPTBot"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

	// Generate policy config.
	resp, body = httpPost(t, wafctlURL+"/api/config/generate", nil)
	assertCode(t, "generate", 200, resp)

	// Find the challenge rule in the output.
	var file struct {
		Rules []struct {
			ID        string `json:"id"`
			Type      string `json:"type"`
			Challenge *struct {
				Difficulty int    `json:"difficulty"`
				Algorithm  string `json:"algorithm"`
				TTLSeconds int    `json:"ttl_seconds"`
				BindIP     bool   `json:"bind_ip"`
			} `json:"challenge,omitempty"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(body, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var found bool
	for _, r := range file.Rules {
		if r.ID == ruleID {
			found = true
			if r.Type != "challenge" {
				t.Errorf("type = %q, want challenge", r.Type)
			}
			if r.Challenge == nil {
				t.Fatal("challenge config is nil in policy-rules output")
			}
			if r.Challenge.Difficulty != 6 {
				t.Errorf("difficulty = %d, want 6", r.Challenge.Difficulty)
			}
			if r.Challenge.Algorithm != "slow" {
				t.Errorf("algorithm = %q, want slow", r.Challenge.Algorithm)
			}
			if r.Challenge.TTLSeconds != 3600 {
				t.Errorf("ttl_seconds = %d, want 3600", r.Challenge.TTLSeconds)
			}
			break
		}
	}
	if !found {
		t.Errorf("challenge rule %s not found in generated policy-rules", ruleID)
	}
}

func TestChallengeSkipInteraction(t *testing.T) {
	ensureDefaultConfig(t)

	// Create a skip rule targeting the challenge phase.
	var ids []string
	create := func(name string, payload map[string]any) string {
		resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "create "+name, 201, resp)
		id := mustGetID(t, body)
		ids = append(ids, id)
		return id
	}

	// Skip rule: skip challenge phase for /health.
	create("e2e-skip-challenge", map[string]any{
		"name":    "e2e-skip-challenge",
		"type":    "skip",
		"enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": "/health"},
		},
		"skip_targets": map[string]any{
			"phases": []string{"challenge"},
		},
	})

	t.Cleanup(func() {
		for _, id := range ids {
			cleanup(t, wafctlURL+"/api/rules/"+id)
		}
	})

	// Generate config and verify the skip_targets includes "challenge".
	resp, body := httpPost(t, wafctlURL+"/api/config/generate", nil)
	assertCode(t, "generate", 200, resp)

	var file struct {
		Rules []struct {
			Type        string `json:"type"`
			Name        string `json:"name"`
			SkipTargets *struct {
				Phases []string `json:"phases,omitempty"`
			} `json:"skip_targets,omitempty"`
		} `json:"rules"`
	}
	json.Unmarshal(body, &file)

	for _, r := range file.Rules {
		if r.Name == "e2e-skip-challenge" && r.SkipTargets != nil {
			found := false
			for _, p := range r.SkipTargets.Phases {
				if p == "challenge" {
					found = true
				}
			}
			if !found {
				t.Error("skip_targets.phases should contain 'challenge'")
			}
			return
		}
	}
	t.Error("skip rule not found in generated config")
}

func TestChallengeTypeInExclusionsList(t *testing.T) {
	// Create a challenge rule, then verify it shows up in the list endpoint.
	payload := map[string]any{
		"name":       "e2e-challenge-list",
		"type":       "challenge",
		"enabled":    true,
		"conditions": []map[string]string{{"field": "path", "operator": "eq", "value": "/test"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

	// List all rules and find the challenge rule.
	resp, body = httpGet(t, wafctlURL+"/api/rules")
	assertCode(t, "list", 200, resp)

	var rules []map[string]any
	json.Unmarshal(body, &rules)

	found := false
	for _, r := range rules {
		if id, _ := r["id"].(string); id == ruleID {
			found = true
			if typ, _ := r["type"].(string); typ != "challenge" {
				t.Errorf("type = %q, want challenge", typ)
			}
		}
	}
	if !found {
		t.Error("challenge rule not found in list")
	}
}

func TestChallengeBulkUpdate(t *testing.T) {
	// Create a challenge rule, disable it via bulk update.
	payload := map[string]any{
		"name":       "e2e-challenge-bulk",
		"type":       "challenge",
		"enabled":    true,
		"conditions": []map[string]string{{"field": "ip", "operator": "eq", "value": "1.2.3.4"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

	// Bulk disable.
	bulkPayload := map[string]any{
		"ids":    []string{ruleID},
		"action": "disable",
	}
	resp, body = httpPost(t, wafctlURL+"/api/rules/bulk", bulkPayload)
	assertCode(t, "bulk disable", 200, resp)

	// Verify disabled.
	resp, body = httpGet(t, wafctlURL+"/api/rules/"+ruleID)
	assertCode(t, "get disabled", 200, resp)

	enabled, ok := jsonFieldBool(body, "enabled")
	if !ok {
		t.Fatal("could not read enabled field")
	}
	if enabled {
		t.Error("expected rule to be disabled after bulk update")
	}
}

func TestChallengeHMACKeyInConfig(t *testing.T) {
	ensureDefaultConfig(t)

	// Create a challenge rule so the HMAC key gets injected.
	payload := map[string]any{
		"name":       "e2e-challenge-hmac",
		"type":       "challenge",
		"enabled":    true,
		"conditions": []map[string]string{{"field": "path", "operator": "eq", "value": "/hmac-test"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

	// Deploy (which triggers HMAC key injection).
	status := deployWAF(t)
	if status != "ok" {
		t.Errorf("deploy status = %q, want ok", status)
	}

	// The config/generate endpoint returns the policy-rules.json content.
	// Challenge config should have an hmac_key when challenge rules exist.
	resp, body = httpPost(t, wafctlURL+"/api/config/generate", nil)
	assertCode(t, "generate", 200, resp)

	hmacKey := jsonField(body, "challenge_config.hmac_key")
	if hmacKey == "" {
		t.Error("challenge_config.hmac_key should be non-empty when challenge rules exist")
	}
	if len(hmacKey) != 64 {
		t.Errorf("hmac_key length = %d, want 64 hex chars", len(hmacKey))
	}
	// Verify it's valid hex.
	for _, c := range hmacKey {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("hmac_key contains non-hex character: %c", c)
			break
		}
	}
}
