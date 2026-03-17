package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// ════════════════════════════════════════════════════════════════════
// 25. Unified Rules API, Phase Field, Deploy, Backup Overrides
// ════════════════════════════════════════════════════════════════════

// --- Unified /api/rules CRUD with mixed types ---

func TestUnifiedRulesCRUD(t *testing.T) {
	// Create an allow rule via /api/rules
	resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
		"name":    "e2e-unified-allow",
		"type":    "allow",
		"enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": "/e2e-unified-allow-test"},
		},
	})
	assertCode(t, "create allow", 201, resp)
	allowID := mustGetID(t, body)

	// Create a rate_limit rule via /api/rules
	resp, body = httpPost(t, wafctlURL+"/api/rules", map[string]any{
		"name":              "e2e-unified-rl",
		"type":              "rate_limit",
		"service":           "*",
		"rate_limit_key":    "client_ip",
		"rate_limit_events": 999,
		"rate_limit_window": "1m",
		"rate_limit_action": "deny",
		"enabled":           true,
	})
	assertCode(t, "create rate_limit", 201, resp)
	rlID := mustGetID(t, body)

	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/rules/"+allowID)
		cleanup(t, wafctlURL+"/api/rules/"+rlID)
	})

	t.Run("list contains both types", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rules")
		assertCode(t, "list", 200, resp)
		s := string(body)
		if !strings.Contains(s, "e2e-unified-allow") {
			t.Error("list missing allow rule")
		}
		if !strings.Contains(s, "e2e-unified-rl") {
			t.Error("list missing rate_limit rule")
		}
	})

	t.Run("get allow by ID", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rules/"+allowID)
		assertCode(t, "get allow", 200, resp)
		assertField(t, "type", body, "type", "allow")
	})

	t.Run("get rate_limit by ID", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rules/"+rlID)
		assertCode(t, "get rl", 200, resp)
		assertField(t, "type", body, "type", "rate_limit")
		if jsonField(body, "rate_limit_key") != "client_ip" {
			t.Errorf("expected rate_limit_key=client_ip, got %q", jsonField(body, "rate_limit_key"))
		}
	})

	t.Run("update rate_limit", func(t *testing.T) {
		resp, body := httpPut(t, wafctlURL+"/api/rules/"+rlID, map[string]any{
			"name":              "e2e-unified-rl-updated",
			"type":              "rate_limit",
			"service":           "*",
			"rate_limit_key":    "client_ip",
			"rate_limit_events": 500,
			"rate_limit_window": "30s",
			"rate_limit_action": "log_only",
			"enabled":           true,
		})
		assertCode(t, "update", 200, resp)
		if jsonInt(body, "rate_limit_events") != 500 {
			t.Errorf("expected rate_limit_events=500, got %d", jsonInt(body, "rate_limit_events"))
		}
	})

	t.Run("delete via unified API", func(t *testing.T) {
		resp, _ := httpDelete(t, wafctlURL+"/api/rules/"+allowID)
		assertCode(t, "delete", 204, resp)
		allowID = "" // prevent double cleanup
	})
}

// --- /api/deploy unified endpoint ---

func TestUnifiedDeploy(t *testing.T) {
	resp, body := httpPostDeploy(t, wafctlURL+"/api/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp)
	assertField(t, "status", body, "status", "deployed")
}

// --- Phase field validation ---

func TestPhaseFieldValidation(t *testing.T) {
	t.Run("inbound phase accepted", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-phase-inbound", "type": "block", "enabled": true,
			"phase": "inbound",
			"conditions": []map[string]string{
				{"field": "path", "operator": "eq", "value": "/e2e-phase-inbound"},
			},
		})
		assertCode(t, "create inbound", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/rules/"+id)
	})

	t.Run("outbound phase accepted with response_status", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-phase-outbound", "type": "detect", "enabled": true,
			"phase":    "outbound",
			"severity": "WARNING",
			"conditions": []map[string]string{
				{"field": "response_status", "operator": "eq", "value": "500"},
			},
		})
		assertCode(t, "create outbound detect", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/rules/"+id)
	})

	t.Run("outbound block with response_header", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-outbound-header", "type": "block", "enabled": true,
			"phase": "outbound",
			"conditions": []map[string]string{
				{"field": "response_header", "operator": "contains", "value": "X-Debug"},
			},
		})
		assertCode(t, "create outbound block", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/rules/"+id)
	})

	t.Run("invalid phase rejected", func(t *testing.T) {
		resp, _ := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-phase-bad", "type": "block", "enabled": true,
			"phase": "sideways",
			"conditions": []map[string]string{
				{"field": "path", "operator": "eq", "value": "/e2e-phase-bad"},
			},
		})
		if resp.StatusCode == 201 {
			t.Error("expected rejection for invalid phase 'sideways', got 201")
		}
	})

	t.Run("inbound rejects response_status", func(t *testing.T) {
		resp, _ := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-inbound-status", "type": "block", "enabled": true,
			"conditions": []map[string]string{
				{"field": "response_status", "operator": "eq", "value": "500"},
			},
		})
		if resp.StatusCode == 201 {
			t.Error("expected rejection for response_status on inbound rule, got 201")
		}
	})

	t.Run("phase roundtrip", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-phase-roundtrip", "type": "detect", "enabled": true,
			"phase":    "outbound",
			"severity": "NOTICE",
			"conditions": []map[string]string{
				{"field": "response_header", "operator": "contains", "value": "error"},
			},
		})
		assertCode(t, "create", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+id) })

		resp2, body2 := httpGet(t, wafctlURL+"/api/rules/"+id)
		assertCode(t, "get", 200, resp2)
		phase := jsonField(body2, "phase")
		if phase != "outbound" {
			t.Errorf("expected phase=outbound, got %q", phase)
		}
	})
}

// --- Backup includes default_rule_overrides ---

func TestBackupIncludesDefaultRuleOverrides(t *testing.T) {
	// Override a default rule
	resp, _ := httpPut(t, wafctlURL+"/api/default-rules/920270", map[string]any{"enabled": false})
	if resp.StatusCode != 200 {
		t.Skipf("cannot override default rule 920270 (status %d)", resp.StatusCode)
	}
	t.Cleanup(func() {
		httpDelete(t, wafctlURL+"/api/default-rules/920270")
	})

	// Take backup
	resp2, body2 := httpGet(t, wafctlURL+"/api/backup")
	assertCode(t, "backup", 200, resp2)

	var backup map[string]json.RawMessage
	json.Unmarshal(body2, &backup)

	overrides, ok := backup["default_rule_overrides"]
	if !ok {
		t.Fatal("backup missing default_rule_overrides field")
	}
	if string(overrides) == "null" || string(overrides) == "{}" {
		t.Error("expected non-empty default_rule_overrides in backup")
	}

	var overridesMap map[string]json.RawMessage
	json.Unmarshal(overrides, &overridesMap)
	if _, ok := overridesMap["920270"]; !ok {
		t.Error("expected rule 920270 in default_rule_overrides")
	}
	t.Logf("default_rule_overrides contains %d entries", len(overridesMap))
}

// --- Unified /api/rules aliases work alongside /api/exclusions ---

func TestRulesExclusionsAlias(t *testing.T) {
	// Create via /api/rules
	resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
		"name": "e2e-alias-test", "type": "block", "enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "eq", "value": "/e2e-alias-test"},
		},
	})
	assertCode(t, "create via /api/rules", 201, resp)
	id := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+id) })

	// Read via /api/exclusions (alias)
	resp2, body2 := httpGet(t, wafctlURL+"/api/exclusions/"+id)
	assertCode(t, "get via /api/exclusions alias", 200, resp2)
	assertField(t, "name", body2, "name", "e2e-alias-test")
}

// --- Phase field appears in generated policy rules ---

func TestPhaseInGeneratedPolicyRules(t *testing.T) {
	// Create an outbound detect rule
	resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
		"name": "e2e-gen-outbound", "type": "detect", "enabled": true,
		"phase":    "outbound",
		"severity": "WARNING",
		"conditions": []map[string]string{
			{"field": "response_status", "operator": "eq", "value": "500"},
		},
	})
	assertCode(t, "create outbound rule", 201, resp)
	id := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+id) })

	// Generate policy rules (preview)
	resp2, body2 := httpPost(t, wafctlURL+"/api/config/generate", struct{}{})
	assertCode(t, "generate", 200, resp2)

	// Check the generated rules contain phase=outbound
	s := string(body2)
	if !strings.Contains(s, `"phase":"outbound"`) {
		t.Error("generated policy rules should contain phase:outbound for outbound rule")
	}
	if !strings.Contains(s, "e2e-gen-outbound") {
		t.Error("generated policy rules should contain our test rule")
	}
}

// --- Rate limit rule validation via unified API ---

func TestRateLimitValidationUnified(t *testing.T) {
	t.Run("missing service rejected", func(t *testing.T) {
		resp, _ := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-rl-no-svc", "type": "rate_limit", "enabled": true,
			"rate_limit_key": "client_ip", "rate_limit_events": 100,
			"rate_limit_window": "1m",
		})
		if resp.StatusCode == 201 {
			t.Error("expected rejection for rate_limit without service")
		}
	})

	t.Run("missing key rejected", func(t *testing.T) {
		resp, _ := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-rl-no-key", "type": "rate_limit", "enabled": true,
			"service": "*", "rate_limit_events": 100, "rate_limit_window": "1m",
		})
		if resp.StatusCode == 201 {
			t.Error("expected rejection for rate_limit without key")
		}
	})

	t.Run("missing window rejected", func(t *testing.T) {
		resp, _ := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-rl-no-window", "type": "rate_limit", "enabled": true,
			"service": "*", "rate_limit_key": "client_ip", "rate_limit_events": 100,
		})
		if resp.StatusCode == 201 {
			t.Error("expected rejection for rate_limit without window")
		}
	})

	t.Run("invalid action rejected", func(t *testing.T) {
		resp, _ := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-rl-bad-action", "type": "rate_limit", "enabled": true,
			"service": "*", "rate_limit_key": "client_ip", "rate_limit_events": 100,
			"rate_limit_window": "1m", "rate_limit_action": "explode",
		})
		if resp.StatusCode == 201 {
			t.Error("expected rejection for invalid rate_limit_action")
		}
	})

	t.Run("valid rate_limit accepted", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-rl-valid", "type": "rate_limit", "enabled": true,
			"service": "*", "rate_limit_key": "client_ip",
			"rate_limit_events": 100, "rate_limit_window": "1m",
			"rate_limit_action": "log_only",
		})
		assertCode(t, "create valid rl", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/rules/"+id)
	})
}

// --- response_header rule type ---

func TestResponseHeaderRuleCRUD(t *testing.T) {
	t.Run("create with header_set", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-resp-hdr-set", "type": "response_header", "enabled": true,
			"header_set": map[string]string{
				"X-Custom-Header": "e2e-test-value",
				"Cache-Control":   "no-store",
			},
			"conditions": []map[string]string{
				{"field": "host", "operator": "eq", "value": "test.example.test"},
			},
		})
		assertCode(t, "create header_set", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+id) })

		// Verify roundtrip
		resp2, body2 := httpGet(t, wafctlURL+"/api/rules/"+id)
		assertCode(t, "get", 200, resp2)
		assertField(t, "type", body2, "type", "response_header")
		// Phase should be outbound (auto-set for response_header)
		phase := jsonField(body2, "phase")
		if phase != "" && phase != "outbound" {
			t.Errorf("expected phase=outbound or empty, got %q", phase)
		}
	})

	t.Run("create with header_remove", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-resp-hdr-remove", "type": "response_header", "enabled": true,
			"header_remove": []string{"Server", "X-Powered-By"},
		})
		assertCode(t, "create header_remove", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/rules/"+id)
	})

	t.Run("create with header_default (set-if-absent)", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-resp-hdr-default", "type": "response_header", "enabled": true,
			"header_default": map[string]string{
				"Cache-Control": "public, max-age=604800",
			},
			"conditions": []map[string]string{
				{"field": "path", "operator": "ends_with", "value": ".css"},
			},
		})
		assertCode(t, "create header_default", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/rules/"+id)
	})

	t.Run("create with mixed actions", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-resp-hdr-mixed", "type": "response_header", "enabled": true,
			"service":        "media.example.test",
			"header_set":     map[string]string{"X-Frame-Options": "SAMEORIGIN"},
			"header_remove":  []string{"X-Powered-By"},
			"header_default": map[string]string{"Referrer-Policy": "strict-origin-when-cross-origin"},
		})
		assertCode(t, "create mixed", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/rules/"+id)
	})

	t.Run("rejected without any header action", func(t *testing.T) {
		resp, _ := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-resp-hdr-empty", "type": "response_header", "enabled": true,
		})
		if resp.StatusCode == 201 {
			t.Error("expected rejection for response_header with no header actions")
		}
	})

	t.Run("rejected with inbound phase", func(t *testing.T) {
		resp, _ := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-resp-hdr-inbound", "type": "response_header", "enabled": true,
			"phase":      "inbound",
			"header_set": map[string]string{"X-Test": "value"},
		})
		if resp.StatusCode == 201 {
			t.Error("expected rejection for response_header with phase=inbound")
		}
	})

	t.Run("appears in generated policy rules", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules", map[string]any{
			"name": "e2e-resp-hdr-gen", "type": "response_header", "enabled": true,
			"header_set": map[string]string{"X-E2E-Header": "generated"},
		})
		assertCode(t, "create", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rules/"+id) })

		resp2, body2 := httpPost(t, wafctlURL+"/api/config/generate", struct{}{})
		assertCode(t, "generate", 200, resp2)
		s := string(body2)
		if !strings.Contains(s, "X-E2E-Header") {
			t.Error("generated policy rules should contain the response header rule")
		}
		if !strings.Contains(s, `"response_header"`) {
			t.Error("generated policy rules should contain type=response_header")
		}
	})
}

// --- Rule Templates API ---

func TestRuleTemplatesAPI(t *testing.T) {
	t.Run("list templates", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rules/templates")
		assertCode(t, "list templates", 200, resp)
		templates := jsonArrayLen(body)
		if templates < 2 {
			t.Errorf("expected at least 2 templates, got %d", templates)
		}
		s := string(body)
		if !strings.Contains(s, "cache-static-assets") {
			t.Error("missing cache-static-assets template")
		}
		if !strings.Contains(s, "security-headers-baseline") {
			t.Error("missing security-headers-baseline template")
		}
	})

	t.Run("apply cache template", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/rules/templates/cache-static-assets/apply", struct{}{})
		assertCode(t, "apply template", 201, resp)
		created := jsonInt(body, "created")
		if created < 3 {
			t.Errorf("expected at least 3 rules created, got %d", created)
		}
		t.Logf("cache-static-assets template created %d rules", created)

		// Clean up created rules
		t.Cleanup(func() {
			rules := jsonFieldArray(body, "rules")
			for _, raw := range rules {
				id := jsonField(raw, "id")
				if id != "" {
					cleanup(t, wafctlURL+"/api/rules/"+id)
				}
			}
		})
	})

	t.Run("apply nonexistent template", func(t *testing.T) {
		resp, _ := httpPost(t, wafctlURL+"/api/rules/templates/does-not-exist/apply", struct{}{})
		if resp.StatusCode != 404 {
			t.Errorf("expected 404 for nonexistent template, got %d", resp.StatusCode)
		}
	})
}

// --- CORS Store API ---

func TestCORSStoreAPI(t *testing.T) {
	t.Run("get default", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/cors")
		assertCode(t, "get cors", 200, resp)
	})

	t.Run("update and verify", func(t *testing.T) {
		corsConfig := map[string]any{
			"enabled": true,
			"global": map[string]any{
				"allowed_origins": []string{"https://app.example.test", "https://api.example.test"},
				"allowed_methods": []string{"GET", "POST", "PUT", "DELETE"},
				"allowed_headers": []string{"Content-Type", "Authorization"},
				"max_age":         3600,
			},
			"per_service": map[string]any{
				"media.example.test": map[string]any{
					"allowed_origins":   []string{"https://media.example.test"},
					"allow_credentials": true,
				},
			},
		}
		resp, _ := httpPut(t, wafctlURL+"/api/cors", corsConfig)
		assertCode(t, "update cors", 200, resp)

		resp2, body2 := httpGet(t, wafctlURL+"/api/cors")
		assertCode(t, "re-read cors", 200, resp2)

		var cfg struct {
			Global struct {
				AllowedOrigins []string `json:"allowed_origins"`
				MaxAge         int      `json:"max_age"`
			} `json:"global"`
			PerService map[string]struct {
				AllowCredentials bool `json:"allow_credentials"`
			} `json:"per_service"`
		}
		json.Unmarshal(body2, &cfg)

		if len(cfg.Global.AllowedOrigins) != 2 {
			t.Errorf("expected 2 origins, got %d", len(cfg.Global.AllowedOrigins))
		}
		if cfg.Global.MaxAge != 3600 {
			t.Errorf("expected max_age=3600, got %d", cfg.Global.MaxAge)
		}
		svc, ok := cfg.PerService["media.example.test"]
		if !ok {
			t.Fatal("media.example.test not in per_service")
		}
		if !svc.AllowCredentials {
			t.Error("expected allow_credentials=true for media")
		}
	})

	t.Run("cors in deploy output", func(t *testing.T) {
		resp, body := httpPostDeploy(t, wafctlURL+"/api/deploy", struct{}{})
		assertCode(t, "deploy", 200, resp)
		assertField(t, "status", body, "status", "deployed")
	})

	t.Cleanup(func() {
		httpPut(t, wafctlURL+"/api/cors", map[string]any{
			"global":      map[string]any{},
			"per_service": map[string]any{},
		})
		deployWAF(t)
	})
}
