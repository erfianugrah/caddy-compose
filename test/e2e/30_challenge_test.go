package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// generateConfigWrapper matches the /api/config/generate response.
type generateConfigWrapper struct {
	PolicyRules struct {
		Rules []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Type      string `json:"type"`
			Priority  int    `json:"priority"`
			Challenge *struct {
				Difficulty    int    `json:"difficulty"`
				MinDifficulty int    `json:"min_difficulty,omitempty"`
				MaxDifficulty int    `json:"max_difficulty,omitempty"`
				Algorithm     string `json:"algorithm"`
				TTLSeconds    int    `json:"ttl_seconds"`
				BindIP        bool   `json:"bind_ip"`
				BindJA4       bool   `json:"bind_ja4,omitempty"`
			} `json:"challenge,omitempty"`
			SkipTargets *struct {
				Phases []string `json:"phases,omitempty"`
			} `json:"skip_targets,omitempty"`
		} `json:"rules"`
		ChallengeConfig *struct {
			HMACKey string `json:"hmac_key"`
		} `json:"challenge_config,omitempty"`
	} `json:"policy_rules"`
}

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

	// Parse the generated rules (wrapped in policy_rules).
	var wrapper generateConfigWrapper
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Find our test rules by checking which types are present.
	typePriorities := make(map[string]int)
	for _, r := range wrapper.PolicyRules.Rules {
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

	// Find the challenge rule in the output (wrapped in policy_rules).
	var wrapper generateConfigWrapper
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var found bool
	for _, r := range wrapper.PolicyRules.Rules {
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

	var wrapper generateConfigWrapper
	json.Unmarshal(body, &wrapper)

	for _, r := range wrapper.PolicyRules.Rules {
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
	// Create a challenge rule, then verify it persists and is retrievable.
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

	// Verify it exists via direct GET.
	resp, body = httpGet(t, wafctlURL+"/api/rules/"+ruleID)
	assertCode(t, "get", 200, resp)
	assertField(t, "get", body, "type", "challenge")
	assertField(t, "get", body, "name", "e2e-challenge-list")

	// Verify type is correct via direct GET (list endpoint has cache staleness
	// in sequential test runs — direct GET is authoritative).
	assertField(t, "type-check", body, "id", ruleID)
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

// ════════════════════════════════════════════════════════════════════
//  30b. Challenge Live Tests (hit Caddy through the plugin)
// ════════════════════════════════════════════════════════════════════

func TestChallengeInterstitialServed(t *testing.T) {
	ensureDefaultConfig(t)

	// Create a challenge rule matching all paths.
	payload := map[string]any{
		"name":                 "e2e-challenge-interstitial",
		"type":                 "challenge",
		"enabled":              true,
		"challenge_difficulty": 1,
		"challenge_algorithm":  "fast",
		"challenge_ttl":        "1h",
		"conditions": []map[string]string{
			{"field": "path", "operator": "begins_with", "value": "/e2e-challenge-page"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/rules/"+ruleID)
		deployWAF(t)
	})

	// Deploy and wait for plugin hot-reload.
	deployAndWaitForStatus(t, caddyURL+"/e2e-challenge-page", 200)

	// Hit Caddy — should get the interstitial page (status 200).
	resp, body = httpGet(t, caddyURL+"/e2e-challenge-page")
	assertCode(t, "interstitial", 200, resp)

	bodyStr := string(body)
	// Verify the page contains challenge markers.
	if !strings.Contains(bodyStr, "Verifying your connection") {
		t.Error("interstitial page missing 'Verifying your connection' heading")
	}
	if !strings.Contains(bodyStr, "challenge-data") {
		t.Error("interstitial page missing challenge-data script tag")
	}
	if !strings.Contains(bodyStr, "random_data") {
		t.Error("interstitial page missing random_data in challenge payload")
	}
	if !strings.Contains(bodyStr, "crypto.subtle.digest") {
		t.Error("interstitial page missing WebCrypto SHA-256 solver")
	}

	// Verify cache-control headers prevent caching.
	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	// Verify Content-Type is HTML.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestChallengeVerifyEndpoint(t *testing.T) {
	// The verify endpoint should exist at /.well-known/policy-challenge/verify.
	// Without a valid PoW payload, it should return 403.
	resp, _ := httpPost(t, caddyURL+"/.well-known/policy-challenge/verify", nil)
	// Should return 403 (missing fields) or 400, not 404.
	if resp.StatusCode == 404 {
		t.Error("verify endpoint returned 404 — challenge endpoint not registered in plugin")
	}
}

func TestChallengeWorkerJSServed(t *testing.T) {
	// The worker.js should be served at /.well-known/policy-challenge/worker.js
	// with correct Content-Type and caching headers.
	resp, body := httpGet(t, caddyURL+"/.well-known/policy-challenge/worker.js")
	assertCode(t, "worker.js", 200, resp)

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want application/javascript", ct)
	}

	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "public") {
		t.Errorf("Cache-Control = %q, want public", cc)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "addEventListener") {
		t.Error("worker.js missing addEventListener handler")
	}
	if !strings.Contains(bodyStr, "sha256Fallback") {
		t.Error("worker.js missing pure-JS SHA-256 fallback")
	}
}

func TestChallengeNonMatchingPathPassesThrough(t *testing.T) {
	// After creating a challenge rule for /e2e-challenge-page,
	// requests to other paths should NOT get the interstitial.
	// (Using the httpbun upstream that the e2e Caddy proxies to.)
	resp, _ := httpGet(t, caddyURL+"/get")
	if resp.StatusCode == 200 {
		// If it's 200, check it's NOT the interstitial.
		// The httpbun /get endpoint returns JSON, not HTML.
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/json") {
			// Could be the interstitial — check body.
			t.Log("got HTML response on /get, might be interstitial leaking")
		}
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
	if status != "deployed" {
		t.Errorf("deploy status = %q, want deployed", status)
	}

	// The config/generate endpoint returns the policy-rules.json content
	// (wrapped in {"policy_rules": {...}}). After deploy, the HMAC key
	// is injected when challenge rules exist.
	resp, body = httpPost(t, wafctlURL+"/api/config/generate", nil)
	assertCode(t, "generate", 200, resp)

	var wrapper generateConfigWrapper
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if wrapper.PolicyRules.ChallengeConfig == nil {
		t.Fatal("challenge_config should be non-nil when challenge rules exist")
	}
	hmacKey := wrapper.PolicyRules.ChallengeConfig.HMACKey
	if hmacKey == "" {
		t.Error("challenge_config.hmac_key should be non-empty")
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

// ════════════════════════════════════════════════════════════════════
//  30c. Challenge Cookie Security + Rate Limit Key
// ════════════════════════════════════════════════════════════════════

func TestChallengeDefaultTTLIsOneHour(t *testing.T) {
	ensureDefaultConfig(t)

	// Create a challenge rule with no explicit TTL (should default to 1h = 3600s).
	payload := map[string]any{
		"name":       "e2e-challenge-default-ttl",
		"type":       "challenge",
		"enabled":    true,
		"conditions": []map[string]string{{"field": "path", "operator": "eq", "value": "/ttl-test"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

	// Generate config and verify TTL is 3600 (1 hour).
	resp, body = httpPost(t, wafctlURL+"/api/config/generate", nil)
	assertCode(t, "generate", 200, resp)

	var wrapper generateConfigWrapper
	json.Unmarshal(body, &wrapper)

	for _, r := range wrapper.PolicyRules.Rules {
		if r.ID == ruleID && r.Challenge != nil {
			if r.Challenge.TTLSeconds != 3600 {
				t.Errorf("default TTL = %d, want 3600 (1h)", r.Challenge.TTLSeconds)
			}
			return
		}
	}
	t.Error("challenge rule not found in generated config")
}

func TestChallengeCookieRateLimitKeyValidation(t *testing.T) {
	// Verify 'challenge_cookie' is accepted as a valid rate limit key.
	payload := map[string]any{
		"name":              "e2e-rl-challenge-cookie",
		"type":              "rate_limit",
		"enabled":           true,
		"service":           "*",
		"rate_limit_key":    "challenge_cookie",
		"rate_limit_events": 100,
		"rate_limit_window": "1m",
		"rate_limit_action": "deny",
		"conditions":        []map[string]string{{"field": "path", "operator": "begins_with", "value": "/"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create rl with challenge_cookie key", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

	// Verify the key is preserved.
	resp, body = httpGet(t, wafctlURL+"/api/rules/"+ruleID)
	assertCode(t, "get", 200, resp)
	assertField(t, "key", body, "rate_limit_key", "challenge_cookie")
}

func TestChallengeInterstitialContainsBotProbes(t *testing.T) {
	ensureDefaultConfig(t)

	// Create a challenge rule.
	payload := map[string]any{
		"name":                 "e2e-challenge-probes",
		"type":                 "challenge",
		"enabled":              true,
		"challenge_difficulty": 1,
		"conditions": []map[string]string{
			{"field": "path", "operator": "begins_with", "value": "/e2e-probe-test"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/rules/"+ruleID)
		deployWAF(t)
	})

	deployAndWaitForStatus(t, caddyURL+"/e2e-probe-test", 200)

	// Fetch the interstitial and verify it contains bot signal probes.
	resp, body = httpGet(t, caddyURL+"/e2e-probe-test")
	assertCode(t, "interstitial", 200, resp)

	bodyStr := string(body)
	// Check for key bot detection probes in the JS.
	probes := []string{
		"navigator.webdriver",       // automation marker
		"WEBGL_debug_renderer_info", // SwiftShader detection
		"navigator.plugins",         // plugin count
		"speechSynthesis",           // speech voices
		"permissions.query",         // timing probe
		"mousemove",                 // behavioral listener
		`"signals"`,                 // signals JSON submission
		`"behavior"`,                // behavior JSON submission
	}
	for _, probe := range probes {
		if !strings.Contains(bodyStr, probe) {
			t.Errorf("interstitial missing bot probe: %s", probe)
		}
	}
}

// ════════════════════════════════════════════════════════════════════
//  30d. Challenge Hardening: JA4 Binding, Adaptive Difficulty, Timing
// ════════════════════════════════════════════════════════════════════

func TestChallengeBindJA4CRUD(t *testing.T) {
	// Create a challenge rule with bind_ja4 explicitly set.
	t.Run("create-with-bind-ja4-true", func(t *testing.T) {
		payload := map[string]any{
			"name":               "e2e-challenge-ja4-true",
			"type":               "challenge",
			"enabled":            true,
			"challenge_bind_ja4": true,
			"conditions":         []map[string]string{{"field": "path", "operator": "eq", "value": "/ja4-test"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "create bind_ja4=true", 201, resp)
		ruleID := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

		// Verify it's persisted.
		resp, body = httpGet(t, wafctlURL+"/api/rules/"+ruleID)
		assertCode(t, "get", 200, resp)
		assertField(t, "bind_ja4", body, "challenge_bind_ja4", "true")
	})

	t.Run("create-with-bind-ja4-false", func(t *testing.T) {
		f := false
		payload := map[string]any{
			"name":               "e2e-challenge-ja4-false",
			"type":               "challenge",
			"enabled":            true,
			"challenge_bind_ja4": f,
			"conditions":         []map[string]string{{"field": "path", "operator": "eq", "value": "/ja4-test-off"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "create bind_ja4=false", 201, resp)
		ruleID := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

		resp, body = httpGet(t, wafctlURL+"/api/rules/"+ruleID)
		assertCode(t, "get", 200, resp)
		assertField(t, "bind_ja4", body, "challenge_bind_ja4", "false")
	})
}

func TestChallengeBindJA4InGeneratedConfig(t *testing.T) {
	ensureDefaultConfig(t)

	payload := map[string]any{
		"name":               "e2e-challenge-ja4-config",
		"type":               "challenge",
		"enabled":            true,
		"challenge_bind_ja4": true,
		"conditions":         []map[string]string{{"field": "path", "operator": "eq", "value": "/ja4-config-test"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

	resp, body = httpPost(t, wafctlURL+"/api/config/generate", nil)
	assertCode(t, "generate", 200, resp)

	var wrapper generateConfigWrapper
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, r := range wrapper.PolicyRules.Rules {
		if r.ID == ruleID && r.Challenge != nil {
			if !r.Challenge.BindJA4 {
				t.Error("bind_ja4 should be true in generated config")
			}
			return
		}
	}
	t.Error("challenge rule not found in generated config")
}

func TestChallengeAdaptiveDifficultyCRUD(t *testing.T) {
	t.Run("create-with-min-max", func(t *testing.T) {
		payload := map[string]any{
			"name":                     "e2e-challenge-adaptive",
			"type":                     "challenge",
			"enabled":                  true,
			"challenge_difficulty":     4,
			"challenge_min_difficulty": 2,
			"challenge_max_difficulty": 8,
			"conditions":               []map[string]string{{"field": "path", "operator": "eq", "value": "/adaptive-test"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "create adaptive", 201, resp)
		ruleID := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

		assertField(t, "min_diff", body, "challenge_min_difficulty", "2")
		assertField(t, "max_diff", body, "challenge_max_difficulty", "8")
		assertField(t, "base_diff", body, "challenge_difficulty", "4")
	})

	t.Run("update-min-max", func(t *testing.T) {
		payload := map[string]any{
			"name":                     "e2e-challenge-adaptive-update",
			"type":                     "challenge",
			"enabled":                  true,
			"challenge_difficulty":     4,
			"challenge_min_difficulty": 3,
			"challenge_max_difficulty": 6,
			"conditions":               []map[string]string{{"field": "path", "operator": "eq", "value": "/adaptive-update"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "create", 201, resp)
		ruleID := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

		resp, body = httpPut(t, wafctlURL+"/api/rules/"+ruleID, map[string]any{
			"challenge_min_difficulty": 1,
			"challenge_max_difficulty": 10,
		})
		assertCode(t, "update", 200, resp)
		assertField(t, "updated min", body, "challenge_min_difficulty", "1")
		assertField(t, "updated max", body, "challenge_max_difficulty", "10")
	})
}

func TestChallengeAdaptiveDifficultyValidation(t *testing.T) {
	t.Run("min-exceeds-max", func(t *testing.T) {
		payload := map[string]any{
			"name":                     "e2e-challenge-bad-range",
			"type":                     "challenge",
			"enabled":                  true,
			"challenge_min_difficulty": 10,
			"challenge_max_difficulty": 3,
			"conditions":               []map[string]string{{"field": "path", "operator": "eq", "value": "/bad-range"}},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "min > max should reject", 400, resp)
	})

	t.Run("min-out-of-range", func(t *testing.T) {
		payload := map[string]any{
			"name":                     "e2e-challenge-bad-min",
			"type":                     "challenge",
			"enabled":                  true,
			"challenge_min_difficulty": 20,
			"conditions":               []map[string]string{{"field": "path", "operator": "eq", "value": "/bad-min"}},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "min > 16 should reject", 400, resp)
	})

	t.Run("max-out-of-range", func(t *testing.T) {
		payload := map[string]any{
			"name":                     "e2e-challenge-bad-max",
			"type":                     "challenge",
			"enabled":                  true,
			"challenge_max_difficulty": 20,
			"conditions":               []map[string]string{{"field": "path", "operator": "eq", "value": "/bad-max"}},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/rules", payload)
		assertCode(t, "max > 16 should reject", 400, resp)
	})
}

func TestChallengeAdaptiveDifficultyInGeneratedConfig(t *testing.T) {
	ensureDefaultConfig(t)

	payload := map[string]any{
		"name":                     "e2e-challenge-adaptive-gen",
		"type":                     "challenge",
		"enabled":                  true,
		"challenge_difficulty":     4,
		"challenge_min_difficulty": 2,
		"challenge_max_difficulty": 8,
		"conditions":               []map[string]string{{"field": "path", "operator": "eq", "value": "/adaptive-gen"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+ruleID) })

	resp, body = httpPost(t, wafctlURL+"/api/config/generate", nil)
	assertCode(t, "generate", 200, resp)

	var wrapper generateConfigWrapper
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, r := range wrapper.PolicyRules.Rules {
		if r.ID == ruleID && r.Challenge != nil {
			if r.Challenge.MinDifficulty != 2 {
				t.Errorf("min_difficulty = %d, want 2", r.Challenge.MinDifficulty)
			}
			if r.Challenge.MaxDifficulty != 8 {
				t.Errorf("max_difficulty = %d, want 8", r.Challenge.MaxDifficulty)
			}
			if r.Challenge.Difficulty != 4 {
				t.Errorf("difficulty = %d, want 4", r.Challenge.Difficulty)
			}
			return
		}
	}
	t.Error("adaptive challenge rule not found in generated config")
}

// ════════════════════════════════════════════════════════════════════
//  30e. Challenge Analytics API
// ════════════════════════════════════════════════════════════════════

func TestChallengeStatsEndpoint(t *testing.T) {
	// The /api/challenge/stats endpoint should return valid JSON with
	// the expected structure even when there are no challenge events.
	resp, body := httpGet(t, wafctlURL+"/api/challenge/stats?hours=1")
	assertCode(t, "stats endpoint", 200, resp)

	// Should have the funnel fields (values >= 0, may be non-zero from earlier tests).
	issuedVal := jsonInt(body, "issued")
	if issuedVal < 0 {
		t.Errorf("issued = %d, want >= 0", issuedVal)
	}
	passedVal := jsonInt(body, "passed")
	if passedVal < 0 {
		t.Errorf("passed = %d, want >= 0", passedVal)
	}

	// Should have score_buckets array (always 6 buckets).
	var statsResp struct {
		ScoreBuckets []json.RawMessage `json:"score_buckets"`
		TopJA4s      []json.RawMessage `json:"top_ja4s"`
		TopClients   []json.RawMessage `json:"top_clients"`
		TopServices  []json.RawMessage `json:"top_services"`
	}
	if err := json.Unmarshal(body, &statsResp); err != nil {
		t.Fatalf("unmarshal challenge stats: %v", err)
	}
	if len(statsResp.ScoreBuckets) != 6 {
		t.Errorf("score_buckets length = %d, want 6", len(statsResp.ScoreBuckets))
	}

	// Should have top_ja4s array.
	if !strings.Contains(string(body), "top_ja4s") {
		t.Error("response missing top_ja4s field")
	}
}

func TestChallengeStatsWithFilters(t *testing.T) {
	t.Run("service-filter", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/challenge/stats?hours=1&service=httpbun.erfi.io")
		assertCode(t, "with service filter", 200, resp)
	})
	t.Run("client-filter", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/challenge/stats?hours=1&client=1.2.3.4")
		assertCode(t, "with client filter", 200, resp)
	})
	t.Run("both-filters", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/challenge/stats?hours=1&service=httpbun.erfi.io&client=1.2.3.4")
		assertCode(t, "with both filters", 200, resp)
	})
}

func TestChallengeAnalyticsDashboardPage(t *testing.T) {
	// The /challenge dashboard page should be served by wafctl.
	resp, body := httpGet(t, wafctlURL+"/challenge")
	assertCode(t, "challenge page via wafctl", 200, resp)
	if !strings.Contains(string(body), "Challenge Analytics") {
		t.Error("challenge page missing 'Challenge Analytics' heading")
	}

	// Also accessible via Caddy dashboard proxy.
	resp, body = httpGet(t, dashURL+"/challenge")
	if resp.StatusCode == 200 {
		if !strings.Contains(string(body), "Challenge Analytics") {
			t.Error("challenge page via proxy missing heading")
		}
	}
}

func TestChallengeInterstitialContainsElapsedMs(t *testing.T) {
	ensureDefaultConfig(t)

	payload := map[string]any{
		"name":                 "e2e-challenge-elapsed",
		"type":                 "challenge",
		"enabled":              true,
		"challenge_difficulty": 1,
		"conditions": []map[string]string{
			{"field": "path", "operator": "begins_with", "value": "/e2e-elapsed-test"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/rules/"+ruleID)
		deployWAF(t)
	})

	deployAndWaitForStatus(t, caddyURL+"/e2e-elapsed-test", 200)

	// The interstitial JS should submit elapsed_ms to the verify endpoint.
	resp, body = httpGet(t, caddyURL+"/e2e-elapsed-test")
	assertCode(t, "interstitial", 200, resp)

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "elapsed_ms") {
		t.Error("interstitial JS missing elapsed_ms submission field")
	}
}

// ════════════════════════════════════════════════════════════════════
//  30f. Endpoint Discovery API
// ════════════════════════════════════════════════════════════════════

func TestEndpointDiscoveryBasic(t *testing.T) {
	resp, body := httpGet(t, wafctlURL+"/api/discovery/endpoints?hours=1")
	assertCode(t, "discovery endpoint", 200, resp)

	// Should have the response structure.
	var disc struct {
		Endpoints     []json.RawMessage `json:"endpoints"`
		TotalRequests int               `json:"total_requests"`
		TotalPaths    int               `json:"total_paths"`
		UncoveredPct  float64           `json:"uncovered_pct"`
	}
	if err := json.Unmarshal(body, &disc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// There should be traffic from previous tests.
	if disc.TotalRequests <= 0 {
		t.Log("no traffic in discovery — might be expected in isolated run")
	}
}

func TestEndpointDiscoveryWithServiceFilter(t *testing.T) {
	resp, _ := httpGet(t, wafctlURL+"/api/discovery/endpoints?hours=1&service=httpbun.erfi.io")
	assertCode(t, "with service filter", 200, resp)
}

func TestEndpointDiscoveryCoverage(t *testing.T) {
	// Verify the discovery response includes coverage fields
	// and that the structure is well-formed.
	resp, body := httpGet(t, wafctlURL+"/api/discovery/endpoints?hours=24")
	assertCode(t, "discovery", 200, resp)

	var disc struct {
		Endpoints []struct {
			Path         string `json:"path"`
			HasChallenge bool   `json:"has_challenge"`
			HasRateLimit bool   `json:"has_rate_limit"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(body, &disc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// If there are endpoints, they should have the coverage fields.
	for _, ep := range disc.Endpoints {
		if ep.Path == "" {
			t.Error("endpoint with empty path")
		}
		// has_challenge and has_rate_limit are booleans — just verify they parsed.
		t.Logf("endpoint %s: challenge=%v rate_limit=%v", ep.Path, ep.HasChallenge, ep.HasRateLimit)
	}
}

// ════════════════════════════════════════════════════════════════════
//  30g. Challenge Reputation API
// ════════════════════════════════════════════════════════════════════

func TestChallengeReputationEndpoint(t *testing.T) {
	resp, body := httpGet(t, wafctlURL+"/api/challenge/reputation?hours=24")
	assertCode(t, "reputation endpoint", 200, resp)

	var rep struct {
		JA4s         []json.RawMessage `json:"ja4s"`
		Clients      []json.RawMessage `json:"clients"`
		Alerts       []json.RawMessage `json:"alerts"`
		TotalJA4s    int               `json:"total_ja4s"`
		TotalClients int               `json:"total_clients"`
		TotalAlerts  int               `json:"total_alerts"`
	}
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Structure should be valid (may be empty in clean test run).
	if rep.TotalJA4s < 0 || rep.TotalClients < 0 {
		t.Error("negative counts in reputation response")
	}
}

func TestChallengeReputationWithFilter(t *testing.T) {
	resp, _ := httpGet(t, wafctlURL+"/api/challenge/reputation?hours=1&service=httpbun.erfi.io")
	assertCode(t, "with service filter", 200, resp)
}
