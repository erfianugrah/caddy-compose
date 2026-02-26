package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Generator tests ---

func TestGenerateConfigBasic(t *testing.T) {
	ResetRuleIDCounter()

	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8},
		Services: map[string]WAFServiceSettings{},
	}

	exclusions := []RuleExclusion{
		{Name: "Remove 920420", Type: "remove_by_id", RuleID: "920420", Enabled: true},
		{Name: "Remove sqli tag", Type: "remove_by_tag", RuleTag: "attack-sqli", Enabled: true},
		{Name: "Update target", Type: "update_target_by_id", RuleID: "941100", Variable: "ARGS:body", Enabled: true},
		{Name: "Runtime remove", Type: "runtime_remove_by_id", RuleID: "942100", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/hook"}}, Enabled: true},
		{Name: "Runtime remove target", Type: "runtime_remove_target_by_id", RuleID: "943100", Variable: "ARGS:data", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/webhook"}}, Enabled: true},
	}

	result := GenerateConfigs(cfg, exclusions)

	// Pre-CRS should NOT contain CRS setup rules — those are in the Caddyfile WAF tiers.
	if strings.Contains(result.PreCRS, "blocking_paranoia_level") {
		t.Error("pre-crs should not contain paranoia level (managed by Caddyfile tiers)")
	}
	if strings.Contains(result.PreCRS, "inbound_anomaly_score_threshold") {
		t.Error("pre-crs should not contain inbound threshold (managed by Caddyfile tiers)")
	}
	if strings.Contains(result.PreCRS, "SecRuleEngine") {
		t.Error("pre-crs should not contain SecRuleEngine (managed by Caddyfile tiers)")
	}
	// Pre-CRS should contain runtime exclusions.
	if !strings.Contains(result.PreCRS, "ruleRemoveById=942100") {
		t.Error("pre-crs should contain runtime removal")
	}
	if !strings.Contains(result.PreCRS, "ruleRemoveTargetById=943100") {
		t.Error("pre-crs should contain runtime target removal")
	}

	// Post-CRS checks.
	if !strings.Contains(result.PostCRS, "SecRuleRemoveById 920420") {
		t.Error("post-crs should contain SecRuleRemoveById 920420")
	}
	if !strings.Contains(result.PostCRS, `SecRuleRemoveByTag "attack-sqli"`) {
		t.Error("post-crs should contain SecRuleRemoveByTag attack-sqli")
	}
	if !strings.Contains(result.PostCRS, `SecRuleUpdateTargetById 941100 "!ARGS:body"`) {
		t.Error("post-crs should contain SecRuleUpdateTargetById")
	}

	// Runtime exclusions should NOT be in post-CRS.
	if strings.Contains(result.PostCRS, "942100") {
		t.Error("post-crs should not contain runtime exclusions")
	}
	// Configure-time exclusions should NOT be in pre-CRS (as SecRuleRemoveById).
	if strings.Contains(result.PreCRS, "SecRuleRemoveById") {
		t.Error("pre-crs should not contain SecRuleRemoveById")
	}
}

func TestGenerateConfigEmpty(t *testing.T) {
	ResetRuleIDCounter()

	cfg := defaultConfig()
	result := GenerateConfigs(cfg, nil)

	// Pre-CRS should NOT contain CRS setup — those are per-tier in the Caddyfile.
	if strings.Contains(result.PreCRS, "blocking_paranoia_level") {
		t.Error("pre-crs should not contain paranoia level (managed by Caddyfile tiers)")
	}
	if strings.Contains(result.PreCRS, "SecRuleEngine") {
		t.Error("pre-crs should not contain SecRuleEngine (managed by Caddyfile tiers)")
	}
	// Pre-CRS should just have the header, no rules.
	if strings.Contains(result.PreCRS, "SecRule") {
		t.Error("pre-crs should have no rules with no exclusions")
	}
	// Post-CRS should just have the header.
	if strings.Contains(result.PostCRS, "SecRule") {
		t.Error("post-crs should have no rules with no exclusions")
	}
}

// --- WAF Settings Generator tests ---

// --- WAF Settings Generator tests ---

func TestGenerateWAFSettingsDefaults(t *testing.T) {
	cfg := defaultConfig()
	output := GenerateWAFSettings(cfg)

	if !strings.Contains(output, "paranoia_level=1") {
		t.Error("should contain default paranoia_level=1")
	}
	if !strings.Contains(output, "blocking_paranoia_level=1") {
		t.Error("should contain default blocking_paranoia_level=1")
	}
	if !strings.Contains(output, "inbound_anomaly_score_threshold=5") {
		t.Error("should contain default inbound threshold=5")
	}
	if !strings.Contains(output, "outbound_anomaly_score_threshold=4") {
		t.Error("should contain default outbound threshold=4")
	}
	// Should NOT contain ctl:ruleEngine=Off for default enabled mode.
	if strings.Contains(output, "ctl:ruleEngine=Off") {
		t.Error("enabled mode should not disable rule engine")
	}
}

func TestGenerateWAFSettingsDetectionOnly(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "detection_only", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	// Detection-only mode should use threshold 10000.
	if !strings.Contains(output, "inbound_anomaly_score_threshold=10000") {
		t.Error("detection_only should set inbound threshold to 10000")
	}
	if !strings.Contains(output, "outbound_anomaly_score_threshold=10000") {
		t.Error("detection_only should set outbound threshold to 10000")
	}
	// Detection-only mode MUST emit SecRuleEngine DetectionOnly as a
	// config-time directive. High thresholds alone are insufficient — Coraza
	// can still block on individual rules before anomaly scoring evaluates.
	if !strings.Contains(output, "SecRuleEngine DetectionOnly") {
		t.Error("detection_only should contain SecRuleEngine DetectionOnly")
	}
}

func TestGenerateWAFSettingsDisabled(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "disabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	if !strings.Contains(output, "SecRuleEngine Off") {
		t.Error("disabled mode should contain SecRuleEngine Off")
	}
}

func TestGenerateWAFSettingsPerService(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{
			"httpbun.erfi.io": {Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 3, OutboundThreshold: 3},
			"qbit.erfi.io":    {Mode: "disabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	output := GenerateWAFSettings(cfg)

	// httpbun override
	if !strings.Contains(output, `@streq httpbun.erfi.io`) {
		t.Error("should contain httpbun SERVER_NAME check")
	}
	if !strings.Contains(output, "paranoia_level=2") {
		t.Error("httpbun should have paranoia_level=2")
	}

	// qbit disabled
	if !strings.Contains(output, `@streq qbit.erfi.io`) {
		t.Error("should contain qbit SERVER_NAME check")
	}
	if !strings.Contains(output, "ctl:ruleEngine=Off") {
		t.Error("qbit should have ctl:ruleEngine=Off")
	}
}

func TestGenerateWAFSettingsDisabledGroups(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, DisabledGroups: []string{"attack-sqli"}},
		Services: map[string]WAFServiceSettings{
			"test.erfi.io": {Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, DisabledGroups: []string{"attack-sqli", "attack-xss"}},
		},
	}
	output := GenerateWAFSettings(cfg)

	// Default group should be disabled globally.
	if !strings.Contains(output, "ctl:ruleRemoveByTag=attack-sqli") {
		t.Error("should disable attack-sqli globally")
	}
	// Per-service: xss should be disabled for test.erfi.io (sqli is already global).
	if !strings.Contains(output, "ctl:ruleRemoveByTag=attack-xss") {
		t.Error("should disable attack-xss for test.erfi.io")
	}
}

func TestGenerateWAFSettingsNoUnnecessaryOverrides(t *testing.T) {
	// Service with same settings as defaults should NOT generate overrides.
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{
			"same.erfi.io": {Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	output := GenerateWAFSettings(cfg)

	if strings.Contains(output, "@streq same.erfi.io") {
		t.Error("service with identical settings should not generate a SERVER_NAME override")
	}
}

func TestGenerateWAFSettingsDeterministic(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{
			"b.erfi.io": {Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 5, OutboundThreshold: 4},
			"a.erfi.io": {Mode: "enabled", ParanoiaLevel: 3, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	// Generate twice, verify same output (sorted by hostname).
	out1 := GenerateWAFSettings(cfg)
	out2 := GenerateWAFSettings(cfg)

	// Strip timestamps (they differ).
	strip := func(s string) string {
		lines := strings.Split(s, "\n")
		var filtered []string
		for _, l := range lines {
			if !strings.Contains(l, "Generated:") {
				filtered = append(filtered, l)
			}
		}
		return strings.Join(filtered, "\n")
	}
	if strip(out1) != strip(out2) {
		t.Error("WAF settings should be deterministic")
	}

	// Verify alphabetical order.
	aIdx := strings.Index(out1, "a.erfi.io")
	bIdx := strings.Index(out1, "b.erfi.io")
	if aIdx > bIdx {
		t.Error("services should be sorted alphabetically (a before b)")
	}
}

func TestGenerateWAFSettingsReEnableEngine(t *testing.T) {
	// Bug #1: When default mode is "disabled", services with "enabled" or
	// "detection_only" must get ctl:ruleEngine=On to override the global Off.
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "disabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{
			"active.erfi.io":   {Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 5, OutboundThreshold: 4},
			"logonly.erfi.io":  {Mode: "detection_only", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
			"alsodead.erfi.io": {Mode: "disabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	output := GenerateWAFSettings(cfg)

	// Global Off should be present as a config-time directive.
	if !strings.Contains(output, "SecRuleEngine Off") {
		t.Error("should contain global SecRuleEngine Off")
	}

	// active.erfi.io should get ctl:ruleEngine=On.
	activeIdx := strings.Index(output, "active.erfi.io")
	if activeIdx < 0 {
		t.Fatal("should contain active.erfi.io")
	}
	afterActive := output[activeIdx:]
	if !strings.Contains(afterActive, "ctl:ruleEngine=On") {
		t.Error("active.erfi.io should have ctl:ruleEngine=On")
	}

	// logonly.erfi.io should get ctl:ruleEngine=DetectionOnly (not just On).
	// detection_only mode must use DetectionOnly so Coraza logs but never blocks.
	logonlyIdx := strings.Index(output, "logonly.erfi.io")
	if logonlyIdx < 0 {
		t.Fatal("should contain logonly.erfi.io")
	}
	afterLogonly := output[logonlyIdx:]
	if !strings.Contains(afterLogonly, "ctl:ruleEngine=DetectionOnly") {
		t.Error("logonly.erfi.io should have ctl:ruleEngine=DetectionOnly")
	}

	// alsodead.erfi.io should NOT appear (same as default: disabled).
	if strings.Contains(output, "alsodead.erfi.io") {
		t.Error("alsodead.erfi.io should not generate output (same mode as default)")
	}
}

// TestGenerateWAFSettingsAllModeTransitions tests every combination of
// global default mode and per-service override mode to ensure the correct
// SecRuleEngine / ctl:ruleEngine directives are emitted.

// TestGenerateWAFSettingsAllModeTransitions tests every combination of
// global default mode and per-service override mode to ensure the correct
// SecRuleEngine / ctl:ruleEngine directives are emitted.
func TestGenerateWAFSettingsAllModeTransitions(t *testing.T) {
	modes := []string{"enabled", "detection_only", "disabled"}
	base := WAFServiceSettings{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}

	for _, globalMode := range modes {
		for _, svcMode := range modes {
			name := "global_" + globalMode + "_svc_" + svcMode
			t.Run(name, func(t *testing.T) {
				defaults := base
				defaults.Mode = globalMode
				svc := base
				svc.Mode = svcMode
				cfg := WAFConfig{
					Defaults: defaults,
					Services: map[string]WAFServiceSettings{
						"test.erfi.io": svc,
					},
				}
				output := GenerateWAFSettings(cfg)

				// Global SecRuleEngine directive should always be present.
				switch globalMode {
				case "enabled":
					if !strings.Contains(output, "SecRuleEngine On") {
						t.Error("global enabled should emit SecRuleEngine On")
					}
				case "detection_only":
					if !strings.Contains(output, "SecRuleEngine DetectionOnly") {
						t.Error("global detection_only should emit SecRuleEngine DetectionOnly")
					}
					if !strings.Contains(output, "anomaly_score_threshold=10000") {
						t.Error("global detection_only should set thresholds to 10000")
					}
				case "disabled":
					if !strings.Contains(output, "SecRuleEngine Off") {
						t.Error("global disabled should emit SecRuleEngine Off")
					}
				}

				// Per-service engine override when modes differ.
				svcSection := ""
				idx := strings.Index(output, "test.erfi.io")
				if idx >= 0 {
					svcSection = output[idx:]
				}

				if globalMode == svcMode {
					// Same mode → no per-service override needed (skip if
					// paranoia/thresholds also match).
					if svcSection != "" && strings.Contains(svcSection, "ctl:ruleEngine") {
						t.Error("same mode should not emit per-service ctl:ruleEngine")
					}
				} else {
					switch {
					case svcMode == "disabled" && globalMode != "disabled":
						if !strings.Contains(svcSection, "ctl:ruleEngine=Off") {
							t.Error("svc disabled (global non-disabled) should emit ctl:ruleEngine=Off")
						}
					case svcMode == "detection_only":
						if !strings.Contains(svcSection, "ctl:ruleEngine=DetectionOnly") {
							t.Error("svc detection_only should emit ctl:ruleEngine=DetectionOnly")
						}
					case svcMode == "enabled" && (globalMode == "disabled" || globalMode == "detection_only"):
						if !strings.Contains(svcSection, "ctl:ruleEngine=On") {
							t.Error("svc enabled (global " + globalMode + ") should emit ctl:ruleEngine=On")
						}
					}
				}
			})
		}
	}
}

// TestGenerateWAFSettingsEnabledEmitsSecRuleEngineOn verifies that the default
// "enabled" mode explicitly emits SecRuleEngine On, since the Caddyfile no
// longer contains this directive.

// TestGenerateWAFSettingsEnabledEmitsSecRuleEngineOn verifies that the default
// "enabled" mode explicitly emits SecRuleEngine On, since the Caddyfile no
// longer contains this directive.
func TestGenerateWAFSettingsEnabledEmitsSecRuleEngineOn(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	if !strings.Contains(output, "SecRuleEngine On") {
		t.Error("enabled mode must emit SecRuleEngine On")
	}
	if strings.Contains(output, "SecRuleEngine Off") || strings.Contains(output, "SecRuleEngine DetectionOnly") {
		t.Error("enabled mode should not emit Off or DetectionOnly")
	}
	// Verify paranoia and thresholds are emitted with actual values (not 10000).
	if !strings.Contains(output, "paranoia_level=2") {
		t.Error("should set paranoia_level=2")
	}
	if !strings.Contains(output, "inbound_anomaly_score_threshold=10") {
		t.Error("should set inbound threshold to 10")
	}
}

// TestGenerateWAFSettingsDetectionOnlyToBlocking tests switching from
// detection_only global to per-service blocking (enabled) mode.

// TestGenerateWAFSettingsDetectionOnlyToBlocking tests switching from
// detection_only global to per-service blocking (enabled) mode.
func TestGenerateWAFSettingsDetectionOnlyToBlocking(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{Mode: "detection_only", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		Services: map[string]WAFServiceSettings{
			"strict.erfi.io": {Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	output := GenerateWAFSettings(cfg)

	// Global should be DetectionOnly.
	if !strings.Contains(output, "SecRuleEngine DetectionOnly") {
		t.Error("global should be SecRuleEngine DetectionOnly")
	}

	// strict.erfi.io should re-enable blocking.
	idx := strings.Index(output, "strict.erfi.io")
	if idx < 0 {
		t.Fatal("should contain strict.erfi.io")
	}
	after := output[idx:]
	if !strings.Contains(after, "ctl:ruleEngine=On") {
		t.Error("strict.erfi.io should have ctl:ruleEngine=On to override DetectionOnly")
	}
}

// TestGenerateWAFSettingsPlaceholderContainsSecRuleEngine verifies the
// placeholder file written by ensureCorazaDir includes SecRuleEngine On.

// TestGenerateWAFSettingsPlaceholderContainsSecRuleEngine verifies the
// placeholder file written by ensureCorazaDir includes SecRuleEngine On.
func TestGenerateWAFSettingsPlaceholderContainsSecRuleEngine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "coraza")
	if err := ensureCorazaDir(dir); err != nil {
		t.Fatalf("ensureCorazaDir failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "custom-waf-settings.conf"))
	if err != nil {
		t.Fatalf("reading placeholder: %v", err)
	}
	if !strings.Contains(string(data), "SecRuleEngine On") {
		t.Error("placeholder custom-waf-settings.conf should contain SecRuleEngine On")
	}
}

// --- Generate config endpoint test ---

func TestGenerateConfigEndpoint(t *testing.T) {
	cs := newTestConfigStore(t)
	es := newTestExclusionStore(t)

	cs.Update(WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8},
		Services: map[string]WAFServiceSettings{},
	})

	es.Create(RuleExclusion{
		Name:    "Test",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/config/generate", handleGenerateConfig(cs, es))

	req := httptest.NewRequest("POST", "/api/config/generate", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	// Pre-CRS exclusions should NOT contain CRS setup — those are in waf_settings.
	if strings.Contains(resp["pre_crs_conf"], "blocking_paranoia_level") {
		t.Error("pre-crs should not contain paranoia level (managed by waf_settings)")
	}
	if !strings.Contains(resp["post_crs_conf"], "SecRuleRemoveById 920420") {
		t.Error("should contain exclusion")
	}
	// WAF settings should contain paranoia level.
	if !strings.Contains(resp["waf_settings"], "paranoia_level=2") {
		t.Error("waf_settings should contain paranoia_level=2")
	}
}

// --- UUID generation test ---

// --- UUID generation test ---

func TestGenerateUUID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateUUID()
		if seen[id] {
			t.Fatalf("duplicate UUID: %s", id)
		}
		seen[id] = true

		// Basic format check: should contain hyphens.
		parts := strings.Split(id, "-")
		if len(parts) != 5 {
			t.Errorf("UUID format: want 5 parts, got %d in %s", len(parts), id)
		}
	}
}

// --- SnapshotSince test ---

// --- Enhanced generator tests (method chaining, path operators) ---

func TestGenerateWithMethodFilter(t *testing.T) {
	ResetRuleIDCounter()

	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:   "POST-only upload exclusion",
			Type:   "runtime_remove_by_id",
			RuleID: "942100",
			Conditions: []Condition{
				{Field: "method", Operator: "eq", Value: "POST"},
				{Field: "path", Operator: "eq", Value: "/api/upload"},
			},
			Enabled: true,
		},
	}

	result := GenerateConfigs(cfg, exclusions)

	// Should have a chained rule: METHOD match then URI match
	if !strings.Contains(result.PreCRS, `REQUEST_METHOD "@streq POST"`) {
		t.Error("pre-crs should contain REQUEST_METHOD chain for POST")
	}
	if !strings.Contains(result.PreCRS, "chain") {
		t.Error("pre-crs should contain chain action for method filter")
	}
	if !strings.Contains(result.PreCRS, "ruleRemoveById=942100") {
		t.Error("pre-crs should contain the ctl action")
	}
}

func TestGenerateWithMultiMethodFilter(t *testing.T) {
	ResetRuleIDCounter()

	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:   "POST|PUT upload exclusion",
			Type:   "runtime_remove_by_id",
			RuleID: "942100",
			Conditions: []Condition{
				{Field: "method", Operator: "in", Value: "POST|PUT"},
				{Field: "path", Operator: "eq", Value: "/api/upload"},
			},
			Enabled: true,
		},
	}

	result := GenerateConfigs(cfg, exclusions)

	// Multiple methods should use @pm with space-separated values (not pipe-separated)
	if !strings.Contains(result.PreCRS, `@pm POST PUT`) {
		t.Errorf("pre-crs should use @pm with space-separated methods, got:\n%s", result.PreCRS)
	}
	if !strings.Contains(result.PreCRS, "chain") {
		t.Error("pre-crs should contain chain action")
	}
}

func TestGenerateWithPathOperator(t *testing.T) {
	ResetRuleIDCounter()

	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:       "Regex path exclusion",
			Type:       "runtime_remove_by_id",
			RuleID:     "941100",
			Conditions: []Condition{{Field: "path", Operator: "regex", Value: "^/api/v[0-9]+/webhook"}},
			Enabled:    true,
		},
		{
			Name:       "Prefix path exclusion",
			Type:       "runtime_remove_by_tag",
			RuleTag:    "attack-sqli",
			Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/api/"}},
			Enabled:    true,
		},
	}

	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, `@rx ^/api/v[0-9]+/webhook`) {
		t.Error("pre-crs should contain @rx operator")
	}
	if !strings.Contains(result.PreCRS, `@beginsWith /api/`) {
		t.Error("pre-crs should contain @beginsWith operator")
	}
}

func TestGenerateWithMethodAndOperator(t *testing.T) {
	ResetRuleIDCounter()

	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:     "POST + regex combo",
			Type:     "runtime_remove_target_by_id",
			RuleID:   "943100",
			Variable: "ARGS:data",
			Conditions: []Condition{
				{Field: "method", Operator: "eq", Value: "POST"},
				{Field: "path", Operator: "regex", Value: "^/webhook/"},
			},
			Enabled: true,
		},
	}

	result := GenerateConfigs(cfg, exclusions)

	// Should have chained: METHOD then URI with @rx
	if !strings.Contains(result.PreCRS, `REQUEST_METHOD "@streq POST"`) {
		t.Error("should contain method match")
	}
	if !strings.Contains(result.PreCRS, `@rx ^/webhook/`) {
		t.Error("should contain @rx operator")
	}
	if !strings.Contains(result.PreCRS, "ruleRemoveTargetById=943100;ARGS:data") {
		t.Error("should contain target removal action")
	}
}

// --- Condition validation tests ---

// --- Condition validation tests ---

func TestValidateConditionFields(t *testing.T) {
	// Valid: all field types with appropriate operators
	validCases := []Condition{
		{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
		{Field: "ip", Operator: "eq", Value: "1.2.3.4"},
		{Field: "path", Operator: "eq", Value: "/api/"},
		{Field: "path", Operator: "regex", Value: "^/api/v[0-9]+/"},
		{Field: "path", Operator: "begins_with", Value: "/api/"},
		{Field: "host", Operator: "eq", Value: "radarr.erfi.io"},
		{Field: "method", Operator: "eq", Value: "POST"},
		{Field: "method", Operator: "in", Value: "GET|POST"},
		{Field: "user_agent", Operator: "regex", Value: "BadBot.*"},
		{Field: "header", Operator: "eq", Value: "X-Custom:value"},
		{Field: "query", Operator: "contains", Value: "debug=true"},
		{Field: "country", Operator: "eq", Value: "US"},
		{Field: "country", Operator: "neq", Value: "CN"},
		{Field: "country", Operator: "in", Value: "US GB DE"},
		{Field: "cookie", Operator: "eq", Value: "session:abc"},
		{Field: "cookie", Operator: "contains", Value: "token:xyz"},
		{Field: "body", Operator: "contains", Value: "test"},
		{Field: "body", Operator: "regex", Value: "password=.*"},
		{Field: "args", Operator: "eq", Value: "action:test"},
		{Field: "uri_path", Operator: "begins_with", Value: "/api/"},
		{Field: "uri_path", Operator: "ends_with", Value: ".php"},
		{Field: "referer", Operator: "contains", Value: "example.com"},
		{Field: "response_header", Operator: "eq", Value: "X-Test:val"},
		{Field: "response_status", Operator: "eq", Value: "200"},
		{Field: "response_status", Operator: "in", Value: "200 301 404"},
		{Field: "http_version", Operator: "eq", Value: "HTTP/1.1"},
		{Field: "http_version", Operator: "neq", Value: "HTTP/1.0"},
	}

	for _, c := range validCases {
		e := RuleExclusion{
			Name:       "test",
			Type:       "allow",
			Conditions: []Condition{c},
		}
		if err := validateExclusion(e); err != nil {
			t.Errorf("condition %s/%s should be valid, got: %v", c.Field, c.Operator, err)
		}
	}

	// Invalid field
	e := RuleExclusion{
		Name:       "test",
		Type:       "allow",
		Conditions: []Condition{{Field: "invalid_field", Operator: "eq", Value: "x"}},
	}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for invalid condition field")
	}

	// Invalid operator for field
	e.Conditions = []Condition{{Field: "ip", Operator: "begins_with", Value: "1.2.3.4"}}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for invalid operator on ip field")
	}

	// Empty value
	e.Conditions = []Condition{{Field: "path", Operator: "eq", Value: ""}}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for empty condition value")
	}

	// Invalid method value
	e.Conditions = []Condition{{Field: "method", Operator: "eq", Value: "INVALID"}}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for invalid method value")
	}

	// Partially invalid method
	e.Conditions = []Condition{{Field: "method", Operator: "in", Value: "GET|INVALID"}}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for partially invalid method value")
	}
}

func TestValidateGroupOperator(t *testing.T) {
	base := RuleExclusion{
		Name:       "test",
		Type:       "allow",
		Conditions: []Condition{{Field: "ip", Operator: "eq", Value: "1.2.3.4"}},
	}

	for _, op := range []string{"", "and", "or"} {
		e := base
		e.GroupOp = op
		if err := validateExclusion(e); err != nil {
			t.Errorf("group_operator %q should be valid, got: %v", op, err)
		}
	}

	e := base
	e.GroupOp = "invalid"
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for invalid group_operator")
	}
}

// --- Quick Action validation tests ---

// --- Quick Action validation tests ---

func TestValidateAllowAction(t *testing.T) {
	// Valid: allow by IP
	e := RuleExclusion{Name: "Allow my IP", Type: "allow", Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "195.240.81.42"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("allow by IP should be valid: %v", err)
	}

	// Valid: allow by path
	e = RuleExclusion{Name: "Allow API", Type: "allow", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/health"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("allow by path should be valid: %v", err)
	}

	// Invalid: no conditions
	e = RuleExclusion{Name: "Empty allow", Type: "allow"}
	if err := validateExclusion(e); err == nil {
		t.Error("allow with no conditions should fail validation")
	}
}

func TestValidateBlockAction(t *testing.T) {
	// Valid: block by IP
	e := RuleExclusion{Name: "Block bad IP", Type: "block", Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "10.0.0.1"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("block by IP should be valid: %v", err)
	}

	// Valid: block by UA
	e = RuleExclusion{Name: "Block bot", Type: "block", Conditions: []Condition{{Field: "user_agent", Operator: "regex", Value: "BadBot/1.0"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("block by UA should be valid: %v", err)
	}

	// Invalid: no conditions
	e = RuleExclusion{Name: "Empty block", Type: "block"}
	if err := validateExclusion(e); err == nil {
		t.Error("block with no conditions should fail validation")
	}
}

func TestValidateSkipRuleAction(t *testing.T) {
	// Valid: skip rule by ID + path
	e := RuleExclusion{Name: "Skip 920420", Type: "skip_rule", RuleID: "920420", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/socket.io/"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("skip_rule should be valid: %v", err)
	}

	// Invalid: no rule ID/tag
	e = RuleExclusion{Name: "Skip nothing", Type: "skip_rule", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/"}}}
	if err := validateExclusion(e); err == nil {
		t.Error("skip_rule without rule_id or rule_tag should fail")
	}

	// Invalid: no conditions
	e = RuleExclusion{Name: "Skip everywhere", Type: "skip_rule", RuleID: "920420"}
	if err := validateExclusion(e); err == nil {
		t.Error("skip_rule without conditions should fail")
	}

	// Valid: multiple space-separated rule IDs
	e = RuleExclusion{Name: "Skip multi", Type: "skip_rule", RuleID: "932235 932300 942430",
		Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/graphql"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("multiple space-separated rule IDs should be valid: %v", err)
	}

	// Valid: comma-separated rule IDs
	e = RuleExclusion{Name: "Skip multi comma", Type: "skip_rule", RuleID: "932235,932300",
		Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/graphql"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("comma-separated rule IDs should be valid: %v", err)
	}

	// Valid: range
	e = RuleExclusion{Name: "Skip range", Type: "skip_rule", RuleID: "932000-932999",
		Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/api"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("range rule ID should be valid: %v", err)
	}

	// Valid: mixed IDs and range
	e = RuleExclusion{Name: "Skip mixed", Type: "skip_rule", RuleID: "932235 941100-941199 942430",
		Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/graphql"}}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("mixed IDs and ranges should be valid: %v", err)
	}

	// Invalid: non-numeric rule ID
	e = RuleExclusion{Name: "Skip bad", Type: "skip_rule", RuleID: "abc",
		Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/api"}}}
	if err := validateExclusion(e); err == nil {
		t.Error("non-numeric rule_id should fail validation")
	}

	// Invalid: partial bad token in multi-ID
	e = RuleExclusion{Name: "Skip partial bad", Type: "skip_rule", RuleID: "932235 bad 942430",
		Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/api"}}}
	if err := validateExclusion(e); err == nil {
		t.Error("multi-ID with non-numeric token should fail validation")
	}
}

func TestValidateRawAction(t *testing.T) {
	// Valid
	e := RuleExclusion{Name: "Custom rule", Type: "raw", RawRule: "SecRule REQUEST_URI \"@streq /test\" \"id:10001,phase:1,pass,nolog\""}
	if err := validateExclusion(e); err != nil {
		t.Errorf("raw with raw_rule should be valid: %v", err)
	}

	// Invalid: no raw_rule
	e = RuleExclusion{Name: "Empty raw", Type: "raw"}
	if err := validateExclusion(e); err == nil {
		t.Error("raw without raw_rule should fail")
	}
}

// --- Quick Action generator tests ---

// --- Quick Action generator tests ---

func TestGenerateAllowByIP(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Allow my IP", Type: "allow", Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "195.240.81.42"}}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "@ipMatch 195.240.81.42") {
		t.Error("expected @ipMatch in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "ctl:ruleEngine=Off") {
		t.Error("expected ctl:ruleEngine=Off in pre-CRS output for allow action")
	}
}

func TestGenerateAllowByIPAndPath(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Allow my IP on API", Type: "allow", Conditions: []Condition{
			{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
			{Field: "path", Operator: "begins_with", Value: "/api/"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "@ipMatch 10.0.0.0/8") {
		t.Error("expected @ipMatch in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "chain") {
		t.Error("expected chain for IP+path allow rule")
	}
	if !strings.Contains(result.PreCRS, "@beginsWith /api/") {
		t.Error("expected @beginsWith in chained rule")
	}
}

func TestGenerateBlockByIP(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block bad actor", Type: "block", Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "192.168.1.100"}}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "@ipMatch 192.168.1.100") {
		t.Error("expected @ipMatch in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "deny,status:403") {
		t.Error("expected deny action in pre-CRS output")
	}
}

func TestGenerateBlockByUA(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block bad bot", Type: "block", Conditions: []Condition{{Field: "user_agent", Operator: "regex", Value: "BadBot.*"}}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_HEADERS:User-Agent") {
		t.Error("expected User-Agent check in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "@rx BadBot.*") {
		t.Error("expected @rx operator for UA pattern")
	}
}

func TestGenerateSkipRule(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Skip 920420 for socket.io", Type: "skip_rule", RuleID: "920420", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/socket.io/"}}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveById=920420") {
		t.Error("expected ctl:ruleRemoveById in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "@streq /socket.io/") {
		t.Error("expected path condition in pre-CRS output")
	}
}

func TestGenerateSkipRuleByTag(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Skip SQLi for API", Type: "skip_rule", RuleTag: "attack-sqli", Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/api/v3/"}}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveByTag=attack-sqli") {
		t.Error("expected ctl:ruleRemoveByTag in pre-CRS output")
	}
}

func TestGenerateRawRule(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	rawDirective := "SecRule REQUEST_URI \"@streq /admin\" \"id:10001,phase:1,deny,status:403,t:none,log\""
	exclusions := []RuleExclusion{
		{Name: "Custom block admin", Type: "raw", RawRule: rawDirective, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, rawDirective) {
		t.Error("expected raw rule verbatim in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "# Custom block admin") {
		t.Error("expected name comment in pre-CRS output")
	}
}

// --- GeoIP country condition tests ---

// --- GeoIP country condition tests ---

func TestValidateCountryCondition(t *testing.T) {
	// Valid: country with eq, neq, in operators
	validCases := []Condition{
		{Field: "country", Operator: "eq", Value: "CN"},
		{Field: "country", Operator: "neq", Value: "US"},
		{Field: "country", Operator: "in", Value: "CN RU KP"},
	}
	for _, c := range validCases {
		e := RuleExclusion{
			Name:       "test country",
			Type:       "block",
			Conditions: []Condition{c},
		}
		if err := validateExclusion(e); err != nil {
			t.Errorf("country condition %s/%s should be valid, got: %v", c.Field, c.Operator, err)
		}
	}

	// Invalid operator for country field
	e := RuleExclusion{
		Name:       "test country",
		Type:       "block",
		Conditions: []Condition{{Field: "country", Operator: "regex", Value: "CN"}},
	}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for invalid operator on country field")
	}

	// Invalid: begins_with not valid for country
	e.Conditions = []Condition{{Field: "country", Operator: "begins_with", Value: "C"}}
	if err := validateExclusion(e); err == nil {
		t.Error("expected error for begins_with on country field")
	}
}

func TestGenerateBlockByCountry(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block CN", Type: "block", Conditions: []Condition{
			{Field: "country", Operator: "eq", Value: "CN"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_HEADERS:Cf-Ipcountry") {
		t.Error("expected REQUEST_HEADERS:Cf-Ipcountry variable in pre-CRS output")
	}
	if !strings.Contains(result.PreCRS, "@streq CN") {
		t.Error("expected @streq CN for country eq condition")
	}
	if !strings.Contains(result.PreCRS, "deny,status:403") {
		t.Error("expected deny action for country block")
	}
}

func TestGenerateBlockByCountryList(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block sanctioned countries", Type: "block", Conditions: []Condition{
			{Field: "country", Operator: "in", Value: "CN RU KP IR"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_HEADERS:Cf-Ipcountry") {
		t.Error("expected Cf-Ipcountry header variable")
	}
	if !strings.Contains(result.PreCRS, "@pm CN RU KP IR") {
		t.Error("expected @pm operator for country in condition")
	}
}

func TestGenerateAllowByCountry(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Allow US traffic", Type: "allow", Conditions: []Condition{
			{Field: "country", Operator: "eq", Value: "US"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_HEADERS:Cf-Ipcountry") {
		t.Error("expected Cf-Ipcountry variable for country allow")
	}
	if !strings.Contains(result.PreCRS, "ctl:ruleEngine=Off") {
		t.Error("expected ctl:ruleEngine=Off for allow action")
	}
}

func TestGenerateBlockByCountryAndPath(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block CN on API", Type: "block", Conditions: []Condition{
			{Field: "country", Operator: "eq", Value: "CN"},
			{Field: "path", Operator: "begins_with", Value: "/api/"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_HEADERS:Cf-Ipcountry") {
		t.Error("expected Cf-Ipcountry variable")
	}
	if !strings.Contains(result.PreCRS, "chain") {
		t.Error("expected chain for country+path AND condition")
	}
	if !strings.Contains(result.PreCRS, "@beginsWith /api/") {
		t.Error("expected path condition in chained rule")
	}
}

func TestGenerateSkipRuleByCountry(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Skip 920420 for DE", Type: "skip_rule", RuleID: "920420", Conditions: []Condition{
			{Field: "country", Operator: "eq", Value: "DE"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_HEADERS:Cf-Ipcountry") {
		t.Error("expected Cf-Ipcountry variable for skip_rule")
	}
	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveById=920420") {
		t.Error("expected ctl:ruleRemoveById for skip_rule action")
	}
}

// --- New condition field tests (cookie, body, args, uri_path, referer, response_header, response_status, http_version) ---

// --- New condition field tests (cookie, body, args, uri_path, referer, response_header, response_status, http_version) ---

func TestValidateNewConditionFields(t *testing.T) {
	validCases := []Condition{
		{Field: "cookie", Operator: "eq", Value: "session:abc123"},
		{Field: "cookie", Operator: "contains", Value: "authelia_session:random"},
		{Field: "cookie", Operator: "regex", Value: "token:^[a-f0-9]+$"},
		{Field: "cookie", Operator: "neq", Value: "debug:true"},
		{Field: "body", Operator: "contains", Value: "<script>"},
		{Field: "body", Operator: "regex", Value: "password=.*"},
		{Field: "args", Operator: "eq", Value: "action:delete"},
		{Field: "args", Operator: "contains", Value: "q:SELECT"},
		{Field: "args", Operator: "regex", Value: "cmd:^ls\\s"},
		{Field: "args", Operator: "neq", Value: "format:json"},
		{Field: "uri_path", Operator: "eq", Value: "/api/v1/upload"},
		{Field: "uri_path", Operator: "begins_with", Value: "/api/"},
		{Field: "uri_path", Operator: "ends_with", Value: ".php"},
		{Field: "uri_path", Operator: "contains", Value: "/admin/"},
		{Field: "uri_path", Operator: "regex", Value: "^/api/v[0-9]+/"},
		{Field: "uri_path", Operator: "neq", Value: "/health"},
		{Field: "referer", Operator: "eq", Value: "https://example.com"},
		{Field: "referer", Operator: "contains", Value: "example.com"},
		{Field: "referer", Operator: "regex", Value: "^https://.*\\.erfi\\.io"},
		{Field: "referer", Operator: "neq", Value: "https://bad.com"},
		{Field: "response_header", Operator: "eq", Value: "Content-Type:application/json"},
		{Field: "response_header", Operator: "contains", Value: "X-Custom:value"},
		{Field: "response_header", Operator: "regex", Value: "Server:nginx.*"},
		{Field: "response_status", Operator: "eq", Value: "403"},
		{Field: "response_status", Operator: "neq", Value: "200"},
		{Field: "response_status", Operator: "in", Value: "401 403 500"},
		{Field: "http_version", Operator: "eq", Value: "HTTP/1.0"},
		{Field: "http_version", Operator: "neq", Value: "HTTP/2.0"},
	}

	for _, c := range validCases {
		e := RuleExclusion{
			Name:       "test",
			Type:       "allow",
			Conditions: []Condition{c},
		}
		if err := validateExclusion(e); err != nil {
			t.Errorf("condition %s/%s/%s should be valid, got: %v", c.Field, c.Operator, c.Value, err)
		}
	}

	// Invalid: operator not supported for field
	invalidCases := []Condition{
		{Field: "cookie", Operator: "begins_with", Value: "name:val"},
		{Field: "body", Operator: "eq", Value: "test"},
		{Field: "args", Operator: "ip_match", Value: "name:val"},
		{Field: "uri_path", Operator: "ip_match", Value: "/test"},
		{Field: "referer", Operator: "in", Value: "a b c"},
		{Field: "response_header", Operator: "neq", Value: "H:v"},
		{Field: "response_status", Operator: "contains", Value: "40"},
		{Field: "http_version", Operator: "contains", Value: "HTTP"},
	}

	for _, c := range invalidCases {
		e := RuleExclusion{
			Name:       "test",
			Type:       "allow",
			Conditions: []Condition{c},
		}
		if err := validateExclusion(e); err == nil {
			t.Errorf("condition %s/%s should be invalid, but passed", c.Field, c.Operator)
		}
	}
}

func TestGenerateBlockByCookie(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block bad cookie", Type: "block", Conditions: []Condition{
			{Field: "cookie", Operator: "contains", Value: "tracking:malicious"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_COOKIES:tracking") {
		t.Error("expected REQUEST_COOKIES:tracking variable")
	}
	if !strings.Contains(result.PreCRS, "@contains malicious") {
		t.Error("expected @contains operator for cookie value")
	}
	if !strings.Contains(result.PreCRS, "deny,status:403") {
		t.Error("expected deny action")
	}
}

func TestGenerateSkipRuleByCookie(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Skip RCE for authelia cookie", Type: "skip_rule", RuleID: "932240 942290", Conditions: []Condition{
			{Field: "cookie", Operator: "regex", Value: "authelia_session:.*"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_COOKIES:authelia_session") {
		t.Error("expected REQUEST_COOKIES:authelia_session variable")
	}
	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveById=932240") {
		t.Error("expected ctl:ruleRemoveById=932240")
	}
	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveById=942290") {
		t.Error("expected ctl:ruleRemoveById=942290")
	}
}

func TestGenerateBlockByBody(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block script in body", Type: "block", Conditions: []Condition{
			{Field: "body", Operator: "contains", Value: "<script>alert"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_BODY") {
		t.Error("expected REQUEST_BODY variable")
	}
	if !strings.Contains(result.PreCRS, "@contains <script>alert") {
		t.Error("expected @contains for body content")
	}
}

func TestGenerateBlockByArgs(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block delete action", Type: "block", Conditions: []Condition{
			{Field: "args", Operator: "eq", Value: "action:delete"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "ARGS:action") {
		t.Error("expected ARGS:action variable")
	}
	if !strings.Contains(result.PreCRS, "@streq delete") {
		t.Error("expected @streq for args value")
	}
}

func TestGenerateAllowByURIPath(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Allow uploads", Type: "allow", Conditions: []Condition{
			{Field: "uri_path", Operator: "begins_with", Value: "/uploads/"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_FILENAME") {
		t.Error("expected REQUEST_FILENAME variable for uri_path")
	}
	if !strings.Contains(result.PreCRS, "@beginsWith /uploads/") {
		t.Error("expected @beginsWith operator")
	}
}

func TestGenerateBlockByReferer(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block spam referer", Type: "block", Conditions: []Condition{
			{Field: "referer", Operator: "contains", Value: "spam-site.com"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_HEADERS:Referer") {
		t.Error("expected REQUEST_HEADERS:Referer variable")
	}
	if !strings.Contains(result.PreCRS, "@contains spam-site.com") {
		t.Error("expected @contains for referer value")
	}
}

func TestGenerateBlockByResponseStatus(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block on 500", Type: "block", Conditions: []Condition{
			{Field: "response_status", Operator: "eq", Value: "500"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "RESPONSE_STATUS") {
		t.Error("expected RESPONSE_STATUS variable")
	}
	if !strings.Contains(result.PreCRS, "@streq 500") {
		t.Error("expected @streq for response status")
	}
}

func TestGenerateBlockByHTTPVersion(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block HTTP/1.0", Type: "block", Conditions: []Condition{
			{Field: "http_version", Operator: "eq", Value: "HTTP/1.0"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_PROTOCOL") {
		t.Error("expected REQUEST_PROTOCOL variable")
	}
	if !strings.Contains(result.PreCRS, "@streq HTTP/1.0") {
		t.Error("expected @streq for HTTP version")
	}
}

func TestGenerateBlockByResponseHeader(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block by server header", Type: "block", Conditions: []Condition{
			{Field: "response_header", Operator: "contains", Value: "Server:nginx"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "RESPONSE_HEADERS:Server") {
		t.Error("expected RESPONSE_HEADERS:Server variable")
	}
	if !strings.Contains(result.PreCRS, "@contains nginx") {
		t.Error("expected @contains for response header value")
	}
}

func TestGenerateCookieWithoutColon(t *testing.T) {
	// Cookie without colon should match all cookies
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Block by any cookie", Type: "block", Conditions: []Condition{
			{Field: "cookie", Operator: "contains", Value: "malicious_value"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "REQUEST_COOKIES") {
		t.Error("expected REQUEST_COOKIES variable (no specific cookie name)")
	}
	if !strings.Contains(result.PreCRS, "@contains malicious_value") {
		t.Error("expected @contains for cookie value")
	}
}

func TestGenerateMultiConditionWithNewFields(t *testing.T) {
	// Combine new fields with existing fields
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Skip rule for specific cookie on specific host", Type: "skip_rule", RuleID: "932240", Conditions: []Condition{
			{Field: "host", Operator: "eq", Value: "dockge.erfi.io"},
			{Field: "cookie", Operator: "regex", Value: "authelia_session:.*"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "SERVER_NAME") {
		t.Error("expected SERVER_NAME for host condition")
	}
	if !strings.Contains(result.PreCRS, "REQUEST_COOKIES:authelia_session") {
		t.Error("expected REQUEST_COOKIES:authelia_session for cookie condition")
	}
	if !strings.Contains(result.PreCRS, "chain") {
		t.Error("expected chain for multi-condition rule")
	}
}

// --- Runtime surgical exclusion (ctl:ruleRemoveTargetByTag) ---

// --- Runtime surgical exclusion (ctl:ruleRemoveTargetByTag) ---

func TestGenerateRuntimeRemoveTargetByTag(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:     "Exclude authelia cookie from CRS for all requests",
			Type:     "runtime_remove_target_by_tag",
			RuleTag:  "OWASP_CRS",
			Variable: "REQUEST_COOKIES:authelia_session",
			Conditions: []Condition{
				{Field: "path", Operator: "regex", Value: ".*"},
			},
			Enabled: true,
		},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveTargetByTag=OWASP_CRS;REQUEST_COOKIES:authelia_session") {
		t.Errorf("expected ctl:ruleRemoveTargetByTag action, got:\n%s", result.PreCRS)
	}
}

func TestGenerateRuntimeRemoveTargetByTagConditional(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:     "Exclude authelia cookie from RCE rules on dockge",
			Type:     "runtime_remove_target_by_tag",
			RuleTag:  "attack-rce",
			Variable: "REQUEST_COOKIES:authelia_session",
			Conditions: []Condition{
				{Field: "host", Operator: "eq", Value: "dockge.erfi.io"},
			},
			Enabled: true,
		},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveTargetByTag=attack-rce;REQUEST_COOKIES:authelia_session") {
		t.Errorf("expected ctl:ruleRemoveTargetByTag with attack-rce tag, got:\n%s", result.PreCRS)
	}
	if !strings.Contains(result.PreCRS, "SERVER_NAME") {
		t.Error("expected SERVER_NAME condition for host")
	}
}

func TestValidateRuntimeRemoveTargetByTag(t *testing.T) {
	// Valid
	e := RuleExclusion{
		Name:     "test",
		Type:     "runtime_remove_target_by_tag",
		RuleTag:  "OWASP_CRS",
		Variable: "REQUEST_COOKIES:authelia_session",
		Conditions: []Condition{
			{Field: "path", Operator: "regex", Value: ".*"},
		},
	}
	if err := validateExclusion(e); err != nil {
		t.Errorf("valid runtime_remove_target_by_tag should pass: %v", err)
	}

	// Missing rule_tag
	e2 := e
	e2.RuleTag = ""
	if err := validateExclusion(e2); err == nil {
		t.Error("expected error for missing rule_tag")
	}

	// Missing variable
	e3 := e
	e3.Variable = ""
	if err := validateExclusion(e3); err == nil {
		t.Error("expected error for missing variable")
	}

	// Missing conditions
	e4 := e
	e4.Conditions = nil
	if err := validateExclusion(e4); err == nil {
		t.Error("expected error for missing conditions on runtime type")
	}
}

// --- Honeypot exclusion tests ---

// --- Honeypot exclusion tests ---

func TestValidateHoneypotExclusion(t *testing.T) {
	// Valid: honeypot with path conditions
	e := RuleExclusion{
		Name: "WordPress honeypot",
		Type: "honeypot",
		Conditions: []Condition{
			{Field: "path", Operator: "in", Value: "/wp-admin/ /wp-login.php /xmlrpc.php"},
		},
	}
	if err := validateExclusion(e); err != nil {
		t.Errorf("valid honeypot should pass, got: %v", err)
	}

	// Valid: honeypot with eq operator
	e.Conditions = []Condition{{Field: "path", Operator: "eq", Value: "/phpmyadmin"}}
	if err := validateExclusion(e); err != nil {
		t.Errorf("honeypot with eq path should be valid, got: %v", err)
	}

	// Invalid: honeypot with no conditions
	e.Conditions = nil
	if err := validateExclusion(e); err == nil {
		t.Error("honeypot without conditions should fail")
	}

	// Invalid: honeypot with non-path condition
	e.Conditions = []Condition{{Field: "ip", Operator: "eq", Value: "1.2.3.4"}}
	if err := validateExclusion(e); err == nil {
		t.Error("honeypot with ip condition should fail")
	}

	// Invalid: honeypot with country condition
	e.Conditions = []Condition{{Field: "country", Operator: "eq", Value: "CN"}}
	if err := validateExclusion(e); err == nil {
		t.Error("honeypot with country condition should fail")
	}
}

func TestGenerateHoneypotSingle(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "WP paths", Type: "honeypot", Conditions: []Condition{
			{Field: "path", Operator: "in", Value: "/wp-admin/ /wp-login.php /xmlrpc.php"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "id:9100021") {
		t.Error("expected rule ID 9100021 for dynamic honeypot")
	}
	if !strings.Contains(result.PreCRS, "@pm /wp-admin/ /wp-login.php /xmlrpc.php") {
		t.Error("expected @pm with all honeypot paths")
	}
	if !strings.Contains(result.PreCRS, "tag:'honeypot'") {
		t.Error("expected honeypot tag")
	}
	if !strings.Contains(result.PreCRS, "deny") {
		t.Error("expected deny action for honeypot")
	}
	if !strings.Contains(result.PreCRS, "Dynamic Honeypot Paths") {
		t.Error("expected section header comment")
	}
}

func TestGenerateHoneypotMultipleGroups(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "WP paths", Type: "honeypot", Conditions: []Condition{
			{Field: "path", Operator: "in", Value: "/wp-admin/ /wp-login.php"},
		}, Enabled: true},
		{Name: "PHP panels", Type: "honeypot", Conditions: []Condition{
			{Field: "path", Operator: "in", Value: "/phpmyadmin /adminer"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	// Should consolidate into ONE SecRule
	if strings.Count(result.PreCRS, "id:9100021") != 1 {
		t.Error("expected exactly one honeypot rule (consolidated)")
	}
	// All paths merged
	if !strings.Contains(result.PreCRS, "/wp-admin/") {
		t.Error("expected /wp-admin/ in consolidated rule")
	}
	if !strings.Contains(result.PreCRS, "/phpmyadmin") {
		t.Error("expected /phpmyadmin in consolidated rule")
	}
	// Group names in comments
	if !strings.Contains(result.PreCRS, "WP paths") {
		t.Error("expected group name in comments")
	}
	if !strings.Contains(result.PreCRS, "PHP panels") {
		t.Error("expected group name in comments")
	}
}

func TestGenerateHoneypotDedup(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Group A", Type: "honeypot", Conditions: []Condition{
			{Field: "path", Operator: "in", Value: "/wp-admin/ /.env"},
		}, Enabled: true},
		{Name: "Group B", Type: "honeypot", Conditions: []Condition{
			{Field: "path", Operator: "in", Value: "/.env /phpmyadmin"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	// /.env should appear only once in the @pm pattern
	count := strings.Count(result.PreCRS, "/.env")
	if count != 1 {
		t.Errorf("expected /.env once in @pm rule, found %d times", count)
	}
}

func TestGenerateHoneypotDisabledSkipped(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	// In production, EnabledExclusions() filters before calling GenerateConfigs.
	// Simulate: pass no enabled honeypots.
	exclusions := []RuleExclusion{}
	result := GenerateConfigs(cfg, exclusions)

	if strings.Contains(result.PreCRS, "9100021") {
		t.Error("no honeypot exclusions should not generate a rule")
	}
}

func TestGenerateHoneypotWithEqOperator(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Single path", Type: "honeypot", Conditions: []Condition{
			{Field: "path", Operator: "eq", Value: "/phpmyadmin"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	if !strings.Contains(result.PreCRS, "@pm /phpmyadmin") {
		t.Error("expected @pm with single path from eq condition")
	}
}

func TestGenerateHoneypotMixedWithQuickActions(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{Name: "Allow trusted IP", Type: "allow", Conditions: []Condition{
			{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
		}, Enabled: true},
		{Name: "WP traps", Type: "honeypot", Conditions: []Condition{
			{Field: "path", Operator: "in", Value: "/wp-admin/ /wp-login.php"},
		}, Enabled: true},
		{Name: "Block bad UA", Type: "block", Conditions: []Condition{
			{Field: "user_agent", Operator: "contains", Value: "BadBot"},
		}, Enabled: true},
	}
	result := GenerateConfigs(cfg, exclusions)

	// All three should appear in pre-CRS
	if !strings.Contains(result.PreCRS, "ctl:ruleEngine=Off") {
		t.Error("expected allow rule in pre-CRS")
	}
	if !strings.Contains(result.PreCRS, "id:9100021") {
		t.Error("expected honeypot rule in pre-CRS")
	}
	if !strings.Contains(result.PreCRS, "BadBot") {
		t.Error("expected block rule in pre-CRS")
	}
}

// --- Deploy tests ---

// ─── Multi-rule-ID skip_rule bug tests ──────────────────────────────

func TestConditionAction_MultipleRuleIDs(t *testing.T) {
	// Bug: when RuleID contains space-separated IDs like "932235 932300 942430",
	// conditionAction produces "ctl:ruleRemoveById=932235 932300 942430" which
	// is invalid — Coraza only accepts a single ID or a range per ctl action.
	// The fix should emit multiple ctl: actions, one per rule ID.

	tests := []struct {
		name      string
		exclusion RuleExclusion
		wantParts []string // each must appear in the output
		wantNot   []string // each must NOT appear in the output
	}{
		{
			name: "single rule ID unchanged",
			exclusion: RuleExclusion{
				Type:   "skip_rule",
				RuleID: "932235",
			},
			wantParts: []string{"ctl:ruleRemoveById=932235"},
		},
		{
			name: "multiple space-separated rule IDs get separate ctl actions",
			exclusion: RuleExclusion{
				Type:   "skip_rule",
				RuleID: "932235 932300 942430",
			},
			wantParts: []string{
				"ctl:ruleRemoveById=932235",
				"ctl:ruleRemoveById=932300",
				"ctl:ruleRemoveById=942430",
			},
			wantNot: []string{
				"ctl:ruleRemoveById=932235 932300",
				"ctl:ruleRemoveById=932235 932300 942430",
			},
		},
		{
			name: "comma-separated rule IDs also handled",
			exclusion: RuleExclusion{
				Type:   "skip_rule",
				RuleID: "932235,932300",
			},
			wantParts: []string{
				"ctl:ruleRemoveById=932235",
				"ctl:ruleRemoveById=932300",
			},
		},
		{
			name: "range preserved as-is",
			exclusion: RuleExclusion{
				Type:   "skip_rule",
				RuleID: "932000-932999",
			},
			wantParts: []string{"ctl:ruleRemoveById=932000-932999"},
		},
		{
			name: "mixed IDs and range",
			exclusion: RuleExclusion{
				Type:   "skip_rule",
				RuleID: "932235 941100-941199 942430",
			},
			wantParts: []string{
				"ctl:ruleRemoveById=932235",
				"ctl:ruleRemoveById=941100-941199",
				"ctl:ruleRemoveById=942430",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := conditionAction(tt.exclusion)
			for _, want := range tt.wantParts {
				if !strings.Contains(got, want) {
					t.Errorf("conditionAction() = %q, want it to contain %q", got, want)
				}
			}
			for _, bad := range tt.wantNot {
				if strings.Contains(got, bad) {
					t.Errorf("conditionAction() = %q, should NOT contain %q", got, bad)
				}
			}
		})
	}
}

func TestGenerateConfigs_MultiRuleIDSkipRule(t *testing.T) {
	// End-to-end: a skip_rule exclusion with multiple rule IDs should generate
	// valid SecRules with separate ctl:ruleRemoveById actions.
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode:              "enabled",
			ParanoiaLevel:     1,
			InboundThreshold:  5,
			OutboundThreshold: 4,
		},
	}

	exclusions := []RuleExclusion{
		{
			ID:      "test-multi-id",
			Name:    "Skip multiple rules for graphql",
			Type:    "skip_rule",
			RuleID:  "932235 932300 932236 942430",
			Enabled: true,
			Conditions: []Condition{
				{Field: "uri", Operator: "beginsWith", Value: "/graphql"},
			},
		},
	}

	result := GenerateConfigs(cfg, exclusions)

	// The pre-CRS output should have separate ctl actions for each rule ID.
	for _, id := range []string{"932235", "932300", "932236", "942430"} {
		want := "ctl:ruleRemoveById=" + id
		if !strings.Contains(result.PreCRS, want) {
			t.Errorf("pre-CRS should contain %q but doesn't.\nFull output:\n%s", want, result.PreCRS)
		}
	}

	// It should NOT have the broken space-separated form.
	if strings.Contains(result.PreCRS, "ctl:ruleRemoveById=932235 932300") {
		t.Errorf("pre-CRS should NOT contain space-separated rule IDs in a single ctl action.\nFull output:\n%s", result.PreCRS)
	}
}

// ─── CRS v4 Extended Settings Generator Tests ──────────────────────

func TestGenerateWAFSettingsBlockingParanoiaLevel(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "enabled", ParanoiaLevel: 3, InboundThreshold: 10, OutboundThreshold: 8,
			BlockingParanoiaLevel: 1,
		},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	// Should detect at PL3 but block at PL1.
	if !strings.Contains(output, "paranoia_level=3") {
		t.Error("should set paranoia_level=3")
	}
	if !strings.Contains(output, "blocking_paranoia_level=1") {
		t.Error("should set blocking_paranoia_level=1 (explicit)")
	}
	if !strings.Contains(output, "detection_paranoia_level=3") {
		t.Error("detection_paranoia_level should default to PL when not explicitly set")
	}
}

func TestGenerateWAFSettingsDetectionParanoiaLevel(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4,
			DetectionParanoiaLevel: 4,
		},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	if !strings.Contains(output, "blocking_paranoia_level=1") {
		t.Error("blocking_paranoia_level should default to PL1")
	}
	if !strings.Contains(output, "detection_paranoia_level=4") {
		t.Error("should set detection_paranoia_level=4")
	}
}

func TestGenerateWAFSettingsExtendedSettings(t *testing.T) {
	earlyBlocking := true
	enforceBody := true
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8,
			EarlyBlocking:             &earlyBlocking,
			SamplingPercentage:        50,
			ReportingLevel:            3,
			EnforceBodyprocURLEncoded: &enforceBody,
			AllowedMethods:            "GET HEAD POST",
			AllowedHTTPVersions:       "HTTP/1.1 HTTP/2 HTTP/2.0",
			MaxNumArgs:                500,
			ArgNameLength:             200,
			ArgLength:                 800,
			TotalArgLength:            128000,
			MaxFileSize:               10485760,
			CombinedFileSizes:         20971520,
			CRSExclusions:             []string{"wordpress", "nextcloud"},
		},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	checks := []string{
		"tx.early_blocking=1",
		"tx.sampling_percentage=50",
		"tx.reporting_level=3",
		"tx.enforce_bodyproc_urlencoded=1",
		"tx.allowed_methods=GET HEAD POST",
		"tx.allowed_http_versions=HTTP/1.1 HTTP/2 HTTP/2.0",
		"tx.max_num_args=500",
		"tx.arg_name_length=200",
		"tx.arg_length=800",
		"tx.total_arg_length=128000",
		"tx.max_file_size=10485760",
		"tx.combined_file_sizes=20971520",
		"tx.crs_exclusions_wordpress=1",
		"tx.crs_exclusions_nextcloud=1",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output should contain %q", check)
		}
	}
}

func TestGenerateWAFSettingsExtendedDefaultsOmitted(t *testing.T) {
	// When no extended settings are set, no extra SecAction should be emitted.
	cfg := defaultConfig()
	output := GenerateWAFSettings(cfg)

	// Should NOT contain any of the extended settings.
	notExpected := []string{
		"tx.early_blocking",
		"tx.sampling_percentage",
		"tx.reporting_level",
		"tx.enforce_bodyproc_urlencoded",
		"tx.allowed_methods",
		"tx.allowed_http_versions",
		"tx.restricted_extensions",
		"tx.restricted_headers",
		"tx.max_num_args",
		"tx.arg_name_length",
		"tx.arg_length",
		"tx.total_arg_length",
		"tx.max_file_size",
		"tx.combined_file_sizes",
		"tx.crs_exclusions_",
	}
	for _, ne := range notExpected {
		if strings.Contains(output, ne) {
			t.Errorf("output should NOT contain %q when using defaults", ne)
		}
	}
}

func TestGenerateWAFSettingsPerServiceExtended(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4,
		},
		Services: map[string]WAFServiceSettings{
			"wp.erfi.io": {
				Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4,
				CRSExclusions: []string{"wordpress"},
				MaxNumArgs:    1000,
			},
		},
	}
	output := GenerateWAFSettings(cfg)

	// Service should get its own rules for extended settings.
	if !strings.Contains(output, "@streq wp.erfi.io") {
		t.Error("should contain wp.erfi.io SERVER_NAME check")
	}
	if !strings.Contains(output, "tx.crs_exclusions_wordpress=1") {
		t.Error("should contain crs_exclusions_wordpress for wp.erfi.io")
	}
	if !strings.Contains(output, "tx.max_num_args=1000") {
		t.Error("should contain max_num_args=1000 for wp.erfi.io")
	}
}

func TestGenerateWAFSettingsPerServiceBPLOverride(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8,
			BlockingParanoiaLevel: 1,
		},
		Services: map[string]WAFServiceSettings{
			"strict.erfi.io": {
				Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8,
				BlockingParanoiaLevel: 2, // Override BPL to match PL
			},
		},
	}
	output := GenerateWAFSettings(cfg)

	// Service should get a BPL override because BPL differs from default's effective BPL.
	idx := strings.Index(output, "strict.erfi.io")
	if idx < 0 {
		t.Fatal("should contain strict.erfi.io")
	}
	after := output[idx:]
	if !strings.Contains(after, "blocking_paranoia_level=2") {
		t.Error("strict.erfi.io should have blocking_paranoia_level=2")
	}
}

func TestGenerateWAFSettingsRestrictedExtensions(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4,
			RestrictedExtensions: ".asa .asax .backup .bak .bat",
			RestrictedHeaders:    "/accept-charset/ /content-encoding/ /proxy/",
		},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	if !strings.Contains(output, "tx.restricted_extensions=.asa .asax .backup .bak .bat") {
		t.Error("should contain restricted_extensions")
	}
	if !strings.Contains(output, "tx.restricted_headers=/accept-charset/ /content-encoding/ /proxy/") {
		t.Error("should contain restricted_headers")
	}
}

func TestGenerateWAFSettingsAllowedRequestContentType(t *testing.T) {
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4,
			AllowedRequestContentType: "|application/x-www-form-urlencoded| |multipart/form-data| |application/json|",
		},
		Services: map[string]WAFServiceSettings{},
	}
	output := GenerateWAFSettings(cfg)

	if !strings.Contains(output, "tx.allowed_request_content_type=") {
		t.Error("should contain allowed_request_content_type")
	}
}

func TestGenerateWAFSettingsServiceExtendedIdenticalToDefaults(t *testing.T) {
	// Service with same extended settings as defaults should NOT produce extra output.
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4,
			MaxNumArgs: 500,
		},
		Services: map[string]WAFServiceSettings{
			"same.erfi.io": {
				Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4,
				MaxNumArgs: 500,
			},
		},
	}
	output := GenerateWAFSettings(cfg)

	if strings.Contains(output, "@streq same.erfi.io") {
		t.Error("service with identical extended settings should not generate a SERVER_NAME override")
	}
}

// ─── Policy event logging tests ─────────────────────────────────────

// ─── Policy event logging tests ─────────────────────────────────────

func TestConditionAction_LogWithMsg(t *testing.T) {
	// All policy actions should use log (not nolog) with a msg: tag
	// so that Coraza writes audit entries for policy-matched requests.
	// They also include logdata:'%{MATCHED_VAR}' to capture what matched.

	tests := []struct {
		name      string
		exclusion RuleExclusion
		wantParts []string
		wantNot   []string
	}{
		{
			name:      "skip_rule logs with msg and logdata",
			exclusion: RuleExclusion{Name: "Skip 920420", Type: "skip_rule", RuleID: "920420"},
			wantParts: []string{"log", "msg:'Policy Skip: Skip 920420'", "logdata:'%{MATCHED_VAR}'", "ctl:ruleRemoveById=920420"},
			wantNot:   []string{"nolog"},
		},
		{
			name:      "allow logs with msg and logdata",
			exclusion: RuleExclusion{Name: "Allow my IP", Type: "allow"},
			wantParts: []string{"log", "msg:'Policy Allow: Allow my IP'", "logdata:'%{MATCHED_VAR}'", "ctl:ruleEngine=Off"},
			wantNot:   []string{"nolog"},
		},
		{
			name:      "block logs with msg and logdata",
			exclusion: RuleExclusion{Name: "Block bad actor", Type: "block"},
			wantParts: []string{"log", "msg:'Policy Block: Block bad actor'", "logdata:'%{MATCHED_VAR}'", "deny,status:403"},
			wantNot:   []string{"nolog"},
		},
		{
			name:      "skip_rule by tag logs with msg and logdata",
			exclusion: RuleExclusion{Name: "Skip RCE", Type: "skip_rule", RuleTag: "attack-rce"},
			wantParts: []string{"log", "msg:'Policy Skip: Skip RCE'", "logdata:'%{MATCHED_VAR}'", "ctl:ruleRemoveByTag=attack-rce"},
			wantNot:   []string{"nolog"},
		},
		{
			name:      "multi-ID skip logs with msg and logdata",
			exclusion: RuleExclusion{Name: "Skip multi", Type: "skip_rule", RuleID: "932235 932300"},
			wantParts: []string{"log", "msg:'Policy Skip: Skip multi'", "logdata:'%{MATCHED_VAR}'", "ctl:ruleRemoveById=932235", "ctl:ruleRemoveById=932300"},
			wantNot:   []string{"nolog"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := conditionAction(tt.exclusion)
			for _, want := range tt.wantParts {
				if !strings.Contains(got, want) {
					t.Errorf("conditionAction() = %q, want it to contain %q", got, want)
				}
			}
			for _, bad := range tt.wantNot {
				if strings.Contains(got, bad) {
					t.Errorf("conditionAction() = %q, should NOT contain %q", got, bad)
				}
			}
		})
	}
}
