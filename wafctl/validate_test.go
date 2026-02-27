package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- ValidateGeneratedConfig tests ---

func TestValidateGeneratedConfig_ValidConfig(t *testing.T) {
	preCRS := `# WAF Pre-CRS Configuration
SecRule SERVER_NAME "@streq sonarr.erfi.io" "id:9500001,phase:1,pass,t:none,log,msg:'Policy Skip: test rule',logdata:'%{MATCHED_VAR}',ctl:ruleRemoveById=920420,chain"
  SecRule REQUEST_URI "@beginsWith /signalr/" "t:none"
`
	postCRS := `# WAF Post-CRS Configuration
SecRuleRemoveById 920420
`
	settings := `SecAction "id:9700001,phase:1,pass,t:none,nolog,setvar:tx.paranoia_level=2"
SecRuleEngine On
`

	result := ValidateGeneratedConfig(preCRS, postCRS, settings)

	if !result.Valid {
		t.Errorf("expected valid config, got warnings: %v", result.Warnings)
	}
	if result.TotalRules != 2 {
		t.Errorf("expected 2 rules, got %d", result.TotalRules)
	}
	if len(result.RuleIDs) != 2 {
		t.Errorf("expected 2 rule IDs, got %v", result.RuleIDs)
	}
}

func TestValidateGeneratedConfig_UnbalancedQuotes(t *testing.T) {
	// Simulate a broken msg field with unbalanced single quotes.
	preCRS := `SecRule SERVER_NAME "@streq test.io" "id:9500001,phase:1,pass,t:none,log,msg:'broken quote"
`
	result := ValidateGeneratedConfig(preCRS, "", "")

	if result.Valid {
		t.Error("expected invalid config due to unbalanced quotes")
	}

	foundError := false
	for _, w := range result.Warnings {
		if w.Level == "error" && strings.Contains(w.Message, "unbalanced single quotes") {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Errorf("expected unbalanced quotes error, got warnings: %v", result.Warnings)
	}
}

func TestValidateGeneratedConfig_SelfReference(t *testing.T) {
	// Rule 9500001 with ctl:ruleRemoveById=9500001 (self-reference).
	preCRS := `SecRule SERVER_NAME "@streq test.io" "id:9500001,phase:1,pass,t:none,log,msg:'test',ctl:ruleRemoveById=9500001"
`
	result := ValidateGeneratedConfig(preCRS, "", "")

	foundError := false
	for _, w := range result.Warnings {
		if w.Level == "error" && strings.Contains(w.Message, "self-referencing") {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Errorf("expected self-reference error, got warnings: %v", result.Warnings)
	}
}

func TestValidateGeneratedConfig_CommasInMsg(t *testing.T) {
	// Commas inside msg:'...' — should produce a warning.
	preCRS := `SecRule SERVER_NAME "@streq test.io" "id:9500001,phase:1,pass,t:none,log,msg:'Skip 920271, 942430, 942440 for test'"
`
	result := ValidateGeneratedConfig(preCRS, "", "")

	foundWarning := false
	for _, w := range result.Warnings {
		if w.Level == "warning" && strings.Contains(w.Message, "commas inside msg") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Errorf("expected comma-in-msg warning, got warnings: %v", result.Warnings)
	}

	// Should still be valid (warning, not error).
	if !result.Valid {
		t.Error("commas in msg should be a warning, not an error")
	}
}

func TestValidateGeneratedConfig_EmptyConfig(t *testing.T) {
	result := ValidateGeneratedConfig("", "", "")
	if !result.Valid {
		t.Error("empty config should be valid")
	}
	if result.TotalRules != 0 {
		t.Errorf("expected 0 rules, got %d", result.TotalRules)
	}
}

func TestValidateGeneratedConfig_BackslashContinuation(t *testing.T) {
	// Honeypot rule with backslash continuations.
	preCRS := `SecRule REQUEST_URI "@pm /wp-login.php /wp-admin/" \
    "id:9100021,\
    phase:1,\
    deny,\
    status:403,\
    log,\
    msg:'Honeypot: dynamic path probe',\
    logdata:'%{REQUEST_URI}',\
    tag:'honeypot',\
    tag:'custom-rules',\
    severity:'CRITICAL'"
`
	result := ValidateGeneratedConfig(preCRS, "", "")

	if !result.Valid {
		t.Errorf("honeypot rule should be valid, got warnings: %v", result.Warnings)
	}
	if result.TotalRules != 1 {
		t.Errorf("expected 1 rule, got %d", result.TotalRules)
	}
}

// --- extractQuotedSegments tests ---

func TestExtractQuotedSegments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int
		wantLast string
	}{
		{
			name:     "SecRule with 3 segments",
			input:    `SecRule SERVER_NAME "@streq test" "id:1,phase:1,pass"`,
			wantLen:  2,
			wantLast: "id:1,phase:1,pass",
		},
		{
			name:     "SecAction with 1 segment",
			input:    `SecAction "id:1,phase:1,deny"`,
			wantLen:  1,
			wantLast: "id:1,phase:1,deny",
		},
		{
			name:     "chained sub-rule",
			input:    `  SecRule REQUEST_URI "@beginsWith /test" "t:none"`,
			wantLen:  2,
			wantLast: "t:none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments := extractQuotedSegments(tt.input)
			if len(segments) != tt.wantLen {
				t.Errorf("expected %d segments, got %d: %v", tt.wantLen, len(segments), segments)
			}
			if len(segments) > 0 && segments[len(segments)-1] != tt.wantLast {
				t.Errorf("last segment = %q, want %q", segments[len(segments)-1], tt.wantLast)
			}
		})
	}
}

// --- checkQuoteBalance tests ---

func TestCheckQuoteBalance(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantError bool
	}{
		{
			name:      "balanced quotes",
			line:      `SecRule X "@streq Y" "id:1,phase:1,msg:'hello world'"`,
			wantError: false,
		},
		{
			name:      "unbalanced quotes",
			line:      `SecRule X "@streq Y" "id:1,phase:1,msg:'hello world"`,
			wantError: true,
		},
		{
			name:      "escaped quote inside",
			line:      `SecRule X "@streq Y" "id:1,phase:1,msg:'it\'s fine'"`,
			wantError: false,
		},
		{
			name:      "no quotes at all",
			line:      `SecRule X "@streq Y" "id:1,phase:1,pass"`,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := checkQuoteBalance(tt.line, 1, "1", "test")
			hasError := false
			for _, w := range warnings {
				if w.Level == "error" {
					hasError = true
				}
			}
			if hasError != tt.wantError {
				t.Errorf("checkQuoteBalance() error = %v, want %v, warnings: %v", hasError, tt.wantError, warnings)
			}
		})
	}
}

// --- escapeSecRuleMsgValue tests ---

func TestEscapeSecRuleMsgValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple name", "simple name"},
		{"name with, comma", "name with; comma"},
		{"Skip 920271, 942430, 942440", "Skip 920271; 942430; 942440"},
		{"it's a test", `it\'s a test`},
		{`quote "inside"`, `quote \"inside\"`},
		{"newline\ninjection", "newlineinjection"},
		{"comma, and 'quote'", `comma; and \'quote\'`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeSecRuleMsgValue(tt.input)
			if got != tt.want {
				t.Errorf("escapeSecRuleMsgValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- Self-reference prevention tests ---

func TestBuildSkipRuleAction_SelfReferenceFiltered(t *testing.T) {
	// If rule_id contains the generated ID, it should be filtered out.
	action := buildSkipRuleAction("9500011 920420", "test rule", "9500011")
	if strings.Contains(action, "ruleRemoveById=9500011") {
		t.Errorf("self-referencing ID should be filtered: %s", action)
	}
	if !strings.Contains(action, "ruleRemoveById=920420") {
		t.Errorf("non-self ID should be preserved: %s", action)
	}
}

func TestBuildSkipRuleAction_AllSelfReference(t *testing.T) {
	// If ALL tokens are self-references, should produce pass without ctl.
	action := buildSkipRuleAction("9500001", "test rule", "9500001")
	if strings.Contains(action, "ctl:ruleRemoveById") {
		t.Errorf("all-self-reference should produce no ctl action: %s", action)
	}
	if !strings.Contains(action, "pass") {
		t.Errorf("should still have pass: %s", action)
	}
}

func TestBuildSkipRuleAction_NoSelfReference(t *testing.T) {
	// Normal case — no self-reference.
	action := buildSkipRuleAction("920420", "test rule", "9500001")
	if !strings.Contains(action, "ruleRemoveById=920420") {
		t.Errorf("normal ID should be preserved: %s", action)
	}
}

// --- validateGeneratedRuleIDs tests ---

func TestValidateGeneratedRuleIDs_SelfReference(t *testing.T) {
	exclusions := []RuleExclusion{
		{
			ID:      "test-id",
			Name:    "Self-ref rule",
			Type:    "skip_rule",
			RuleID:  "9500001", // This is the ID that will be generated for this exclusion.
			Enabled: true,
			Conditions: []Condition{
				{Field: "host", Operator: "eq", Value: "test.io"},
			},
		},
	}

	warnings := validateGeneratedRuleIDs(exclusions)

	foundSelfRef := false
	for _, w := range warnings {
		if strings.Contains(w.Message, "own generated ID") {
			foundSelfRef = true
			break
		}
	}
	if !foundSelfRef {
		t.Errorf("expected self-reference warning, got: %v", warnings)
	}
}

func TestValidateGeneratedRuleIDs_NoSelfReference(t *testing.T) {
	exclusions := []RuleExclusion{
		{
			ID:      "test-id",
			Name:    "Normal rule",
			Type:    "skip_rule",
			RuleID:  "920420",
			Enabled: true,
			Conditions: []Condition{
				{Field: "host", Operator: "eq", Value: "test.io"},
			},
		},
	}

	warnings := validateGeneratedRuleIDs(exclusions)

	for _, w := range warnings {
		if w.Level == "error" {
			t.Errorf("unexpected error: %s", w.Message)
		}
	}
}

// --- Integration test: validate endpoint ---

func TestHandleValidateConfig(t *testing.T) {
	configStore := newTestConfigStore(t)
	exclStore := NewExclusionStore(newTestExclusionStorePath(t))

	// Create a few exclusions.
	exclStore.Create(RuleExclusion{
		Name:    "Test skip",
		Type:    "skip_rule",
		RuleID:  "920420",
		Enabled: true,
		Conditions: []Condition{
			{Field: "host", Operator: "eq", Value: "test.io"},
		},
	})

	handler := handleValidateConfig(configStore, exclStore)
	req := httptest.NewRequest("POST", "/api/config/validate", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"valid"`) {
		t.Errorf("response should contain 'valid' field: %s", body)
	}
	if !strings.Contains(body, `"total_rules"`) {
		t.Errorf("response should contain 'total_rules' field: %s", body)
	}
}

func TestHandleValidateConfig_WithConfigs(t *testing.T) {
	configStore := newTestConfigStore(t)
	exclStore := NewExclusionStore(newTestExclusionStorePath(t))

	handler := handleValidateConfig(configStore, exclStore)
	req := httptest.NewRequest("POST", "/api/config/validate?include_configs=true", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"pre_crs_conf"`) {
		t.Errorf("response should contain pre_crs_conf when include_configs=true: %s", body)
	}
}

// --- Integration: generated config with commas now uses semicolons ---

func TestGenerateConfig_CommasInNameSanitized(t *testing.T) {
	ResetRuleIDCounter()
	cfg := defaultConfig()
	exclusions := []RuleExclusion{
		{
			Name:    "Skip 920271, 942430, 942440 for /socket.io/",
			Type:    "skip_rule",
			RuleID:  "920271 942430 942440",
			Enabled: true,
			Conditions: []Condition{
				{Field: "path", Operator: "begins_with", Value: "/socket.io/"},
				{Field: "host", Operator: "eq", Value: "test.io"},
			},
			GroupOp: "and",
		},
	}

	result := GenerateConfigs(cfg, exclusions)

	// The msg field should have semicolons instead of commas.
	if strings.Contains(result.PreCRS, "msg:'Policy Skip: Skip 920271, 942430") {
		t.Error("commas in rule name should be sanitized to semicolons in msg field")
	}
	if !strings.Contains(result.PreCRS, "msg:'Policy Skip: Skip 920271; 942430; 942440") {
		t.Errorf("expected semicolons in msg field, got:\n%s", result.PreCRS)
	}

	// The ctl:ruleRemoveById actions should still work.
	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveById=920271") {
		t.Error("ctl:ruleRemoveById=920271 should be present")
	}
	if !strings.Contains(result.PreCRS, "ctl:ruleRemoveById=942430") {
		t.Error("ctl:ruleRemoveById=942430 should be present")
	}
}

// Helper: create a test exclusion store path.
func newTestExclusionStorePath(t *testing.T) string {
	t.Helper()
	return newTestExclusionStore(t).filePath
}
