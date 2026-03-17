package main

import (
	"testing"
)

func TestConvertSimpleRule(t *testing.T) {
	input := `SecRule ARGS|REQUEST_COOKIES "@rx (?i)etc/passwd" "id:930120,phase:2,block,capture,t:none,msg:'OS file access attempt',tag:'attack-lfi',tag:'paranoia-level/1',tag:'OWASP_CRS',severity:'CRITICAL',setvar:'tx.lfi_score=+%{tx.critical_anomaly_score}'"`

	rules, err := ParseFile(input, "REQUEST-930-APPLICATION-ATTACK-LFI.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "REQUEST-930-APPLICATION-ATTACK-LFI.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 converted rule, got %d", len(result))
	}

	pr := result[0]
	if pr.ID != "930120" {
		t.Errorf("ID: got %q", pr.ID)
	}
	if pr.Type != "detect" {
		t.Errorf("Type: got %q", pr.Type)
	}
	if pr.Severity != "CRITICAL" {
		t.Errorf("Severity: got %q", pr.Severity)
	}
	if pr.ParanoiaLevel != 1 {
		t.Errorf("ParanoiaLevel: got %d", pr.ParanoiaLevel)
	}
	if len(pr.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(pr.Conditions))
	}

	cond := pr.Conditions[0]
	if cond.Operator != "regex" {
		t.Errorf("Operator: got %q, want regex", cond.Operator)
	}
	if cond.Value != "(?i)etc/passwd" {
		t.Errorf("Value: got %q", cond.Value)
	}
	if cond.MultiMatch {
		t.Error("MultiMatch should be false for rule without multiMatch action")
	}

	// Tags should exclude OWASP_CRS and paranoia-level
	for _, tag := range pr.Tags {
		if tag == "OWASP_CRS" {
			t.Error("OWASP_CRS tag should be filtered out")
		}
		if tag == "paranoia-level/1" {
			t.Error("paranoia-level tag should be filtered out")
		}
	}
	// Should have attack-lfi
	found := false
	for _, tag := range pr.Tags {
		if tag == "attack-lfi" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected attack-lfi tag, got %v", pr.Tags)
	}
}

func TestSkipParanoiaGating(t *testing.T) {
	input := `SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:932011,phase:1,pass,nolog,tag:'OWASP_CRS',skipAfter:END-REQUEST-932"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "test.conf")

	if len(result) != 0 {
		t.Errorf("expected 0 converted rules (paranoia gating), got %d", len(result))
	}
	if converter.report.SkippedRules == 0 {
		t.Error("expected skipped rules > 0")
	}
}

func TestSkipFlowControlRanges(t *testing.T) {
	tests := []struct {
		id   string
		skip bool
	}{
		{"901100", true},  // initialization
		{"949110", true},  // blocking evaluation
		{"980170", true},  // correlation
		{"932230", false}, // detection rule
		{"920350", false}, // detection rule
	}

	for _, tt := range tests {
		input := `SecRule ARGS "@rx test" "id:` + tt.id + `,phase:2,block,msg:'Test'"`
		rules, err := ParseFile(input, "test.conf")
		if err != nil {
			t.Fatalf("ParseFile for %s: %v", tt.id, err)
		}

		converter := NewConverter(nil)
		result := converter.Convert(rules, "test.conf")

		if tt.skip && len(result) != 0 {
			t.Errorf("rule %s: expected skip, got %d rules", tt.id, len(result))
		}
		if !tt.skip && len(result) != 1 {
			t.Errorf("rule %s: expected conversion, got %d rules", tt.id, len(result))
		}
	}
}

func TestResponsePhaseConverted(t *testing.T) {
	input := `SecRule RESPONSE_BODY "@rx password" "id:950001,phase:4,block,msg:'Data Leakage',severity:'ERROR'"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "test.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 outbound rule, got %d", len(result))
	}
	if result[0].Phase != "outbound" {
		t.Errorf("expected phase=outbound, got %q", result[0].Phase)
	}
	if result[0].Conditions[0].Field != "response_body" {
		t.Errorf("expected field=response_body, got %q", result[0].Conditions[0].Field)
	}
}

func TestConvertWithTransforms(t *testing.T) {
	input := `SecRule ARGS "@rx test" "id:100001,phase:2,block,t:none,t:urlDecodeUni,t:lowercase,t:cmdLine,msg:'Test',severity:'WARNING'"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "test.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}

	cond := result[0].Conditions[0]
	// Plugin uses camelCase transform names matching CRS conventions
	expected := []string{"urlDecodeUni", "lowercase", "cmdLine"}
	if len(cond.Transforms) != len(expected) {
		t.Fatalf("transforms: got %v, want %v", cond.Transforms, expected)
	}
	for i, tr := range cond.Transforms {
		if tr != expected[i] {
			t.Errorf("transform[%d]: got %q, want %q", i, tr, expected[i])
		}
	}
}

func TestConvertPMOperator(t *testing.T) {
	input := `SecRule ARGS "@pm word1 word2 word3" "id:100002,phase:2,block,msg:'Test',severity:'WARNING'"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "test.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}

	cond := result[0].Conditions[0]
	if cond.Operator != "phrase_match" {
		t.Errorf("operator: got %q, want phrase_match", cond.Operator)
	}
	if len(cond.ListItems) != 3 {
		t.Errorf("list_items: got %d items, want 3", len(cond.ListItems))
	}
	if cond.Value != "" {
		t.Errorf("value should be empty for phrase_match, got %q", cond.Value)
	}
}

func TestConvertChain(t *testing.T) {
	input := `SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json" "id:200001,phase:2,block,chain,msg:'JSON attack',severity:'CRITICAL'"

SecRule REQUEST_BODY "@rx evil" "t:none"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 chained rule, got %d", len(rules))
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "test.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 converted rule, got %d", len(result))
	}

	pr := result[0]
	if pr.GroupOp != "and" {
		t.Errorf("group_op: got %q, want and", pr.GroupOp)
	}
	if len(pr.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(pr.Conditions))
	}

	// First condition: Content-Type header check
	if pr.Conditions[0].Field != "content_type" {
		t.Errorf("condition[0].Field: got %q, want content_type", pr.Conditions[0].Field)
	}

	// Second condition: body check
	if pr.Conditions[1].Field != "body" {
		t.Errorf("condition[1].Field: got %q, want body", pr.Conditions[1].Field)
	}
}

func TestConvertNegatedOperator(t *testing.T) {
	input := `SecRule ARGS "!@rx ^safe" "id:100003,phase:2,block,msg:'Not safe',severity:'WARNING'"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "test.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}
	if !result[0].Conditions[0].Negate {
		t.Error("expected negate=true for !@rx")
	}
}

func TestMapCRSTags(t *testing.T) {
	tags := []string{
		"application-multi",
		"language-shell",
		"platform-unix",
		"attack-rce",
		"paranoia-level/1",
		"OWASP_CRS",
		"capec/1000/152/248/88",
		"PCI/6.5.2",
	}

	result := mapCRSTags(tags)
	expected := []string{"application-multi", "language-shell", "platform-unix", "attack-rce"}

	if len(result) != len(expected) {
		t.Fatalf("got %d tags, want %d: %v", len(result), len(expected), result)
	}
	for i, tag := range result {
		if tag != expected[i] {
			t.Errorf("tag[%d]: got %q, want %q", i, tag, expected[i])
		}
	}
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CRITICAL", "CRITICAL"},
		{"ERROR", "ERROR"},
		{"WARNING", "WARNING"},
		{"NOTICE", "NOTICE"},
		{"2", "CRITICAL"},
		{"5", "NOTICE"},
	}

	for _, tt := range tests {
		got := mapSeverity(tt.input)
		if got != tt.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestReportCounts(t *testing.T) {
	// Parse a mix of detection and flow-control rules
	input := `SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:932011,phase:1,pass,nolog,skipAfter:END"
SecRule ARGS "@rx test" "id:932230,phase:2,block,msg:'Test',severity:'CRITICAL',tag:'paranoia-level/1'"
SecRule RESPONSE_BODY "@rx leak" "id:950001,phase:4,block,msg:'Leak',severity:'ERROR'"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	converter.Convert(rules, "test.conf")

	r := converter.report
	if r.TotalRules != 3 {
		t.Errorf("TotalRules: got %d, want 3", r.TotalRules)
	}
	if r.ConvertedRules != 2 {
		t.Errorf("ConvertedRules: got %d, want 2 (1 inbound + 1 outbound)", r.ConvertedRules)
	}
	if r.SkippedRules != 1 {
		t.Errorf("SkippedRules: got %d, want 1 (flow control only)", r.SkippedRules)
	}
}

func TestConvertMultiMatch(t *testing.T) {
	// Rule with multiMatch action flag — should set multi_match on condition
	input := `SecRule ARGS "@detectSQLi" "id:942100,phase:2,deny,status:403,capture,multiMatch,t:none,t:urlDecodeUni,t:removeComments,msg:'SQL injection detected via libinjection',tag:'attack-sqli',tag:'paranoia-level/1',severity:'CRITICAL'"`

	rules, err := ParseFile(input, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 converted rule, got %d", len(result))
	}

	pr := result[0]
	if pr.ID != "942100" {
		t.Errorf("ID: got %q, want 942100", pr.ID)
	}
	if len(pr.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(pr.Conditions))
	}

	cond := pr.Conditions[0]
	if cond.Operator != "detect_sqli" {
		t.Errorf("Operator: got %q, want detect_sqli", cond.Operator)
	}
	if !cond.MultiMatch {
		t.Error("MultiMatch should be true for rule with multiMatch action")
	}
	// Should have transforms (urlDecodeUni, removeComments — t:none is stripped)
	if len(cond.Transforms) == 0 {
		t.Error("expected transforms on multiMatch rule")
	}
}

func TestConvertMultiMatchChain(t *testing.T) {
	// Head rule with multiMatch, chained to a second rule without it
	input := `SecRule ARGS "@rx evil" "id:900001,phase:2,block,multiMatch,t:none,t:lowercase,msg:'Test chain multiMatch',tag:'paranoia-level/1',severity:'WARNING',chain"
SecRule REQUEST_URI "@rx /target" "t:none"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "test.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 converted rule, got %d", len(result))
	}

	pr := result[0]
	if len(pr.Conditions) != 2 {
		t.Fatalf("expected 2 conditions (head + chain), got %d", len(pr.Conditions))
	}

	// Head condition should have multiMatch
	if !pr.Conditions[0].MultiMatch {
		t.Error("head condition should have MultiMatch=true")
	}
	// Chain condition should NOT have multiMatch (it's on the chain link's own actions)
	if pr.Conditions[1].MultiMatch {
		t.Error("chain condition should have MultiMatch=false (not in its actions)")
	}
}

// --- Numeric operator tests ---

func TestConvertNamedHeaderCount(t *testing.T) {
	// CRS: &REQUEST_HEADERS:Host @eq 0 → count:host eq 0 (header missing check)
	input := `SecRule &REQUEST_HEADERS:Host "@eq 0" "id:920280,phase:1,block,msg:'Request missing a Host header',severity:'WARNING',tag:'attack-protocol',tag:'paranoia-level/1'"`

	rules, err := ParseFile(input, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 converted rule, got %d", len(result))
	}

	pr := result[0]
	if pr.Conditions[0].Field != "count:host" {
		t.Errorf("Field: expected 'count:host', got %q", pr.Conditions[0].Field)
	}
	if pr.Conditions[0].Operator != "eq" {
		t.Errorf("Operator: expected 'eq', got %q", pr.Conditions[0].Operator)
	}
	if pr.Conditions[0].Value != "0" {
		t.Errorf("Value: expected '0', got %q", pr.Conditions[0].Value)
	}
}

func TestConvertNamedHeaderCount_NonShortcut(t *testing.T) {
	// &REQUEST_HEADERS:Transfer-Encoding → count:header:Transfer-Encoding
	input := `SecRule &REQUEST_HEADERS:Transfer-Encoding "@gt 1" "id:920210,phase:1,block,msg:'Multiple Transfer-Encoding',severity:'WARNING',tag:'attack-protocol',tag:'paranoia-level/1'"`

	rules, err := ParseFile(input, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 converted rule, got %d", len(result))
	}

	if result[0].Conditions[0].Field != "count:header:Transfer-Encoding" {
		t.Errorf("Field: expected 'count:header:Transfer-Encoding', got %q", result[0].Conditions[0].Field)
	}
}

func TestConvertCountAggregateField(t *testing.T) {
	// &ARGS_NAMES (aggregate field) should use count: pseudo-field
	input := `SecRule &ARGS_NAMES "@gt 255" "id:920300,phase:2,block,msg:'Too many arguments',severity:'CRITICAL',tag:'attack-protocol',tag:'paranoia-level/1'"`

	rules, err := ParseFile(input, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 converted rule, got %d", len(result))
	}

	pr := result[0]
	// Aggregate field should keep count: prefix
	if pr.Conditions[0].Field != "count:all_args_names" {
		t.Errorf("Field: expected 'count:all_args_names', got %q", pr.Conditions[0].Field)
	}
	if pr.Conditions[0].Operator != "gt" {
		t.Errorf("Operator: expected 'gt', got %q", pr.Conditions[0].Operator)
	}
	if pr.Conditions[0].Value != "255" {
		t.Errorf("Value: expected '255', got %q", pr.Conditions[0].Value)
	}
}

func TestConvertWithinLiteralValue(t *testing.T) {
	// @within with a literal value (not a TX variable reference)
	input := `SecRule REQUEST_PROTOCOL "!@within HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0" "id:920180,phase:1,block,msg:'Unsupported protocol',severity:'WARNING',tag:'attack-protocol',tag:'paranoia-level/1'"`

	rules, err := ParseFile(input, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 converted rule, got %d", len(result))
	}

	pr := result[0]
	if pr.Conditions[0].Operator != "in" {
		t.Errorf("Operator: expected 'in', got %q", pr.Conditions[0].Operator)
	}
	if !pr.Conditions[0].Negate {
		t.Error("expected Negate=true for !@within")
	}
	// Space-separated values should become pipe-separated
	expected := "HTTP/2|HTTP/2.0|HTTP/3|HTTP/3.0"
	if pr.Conditions[0].Value != expected {
		t.Errorf("Value: expected %q, got %q", expected, pr.Conditions[0].Value)
	}
}

func TestConvertWithinTXVariable_Skipped(t *testing.T) {
	// @within with a TX variable reference — should be skipped (not convertible)
	input := `SecRule REQUEST_METHOD "!@within %{tx.allowed_methods}" "id:911100,phase:1,block,msg:'Method not allowed',severity:'CRITICAL',tag:'attack-protocol',tag:'paranoia-level/1'"`

	rules, err := ParseFile(input, "REQUEST-911-METHOD-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "REQUEST-911-METHOD-ENFORCEMENT.conf")

	if len(result) != 0 {
		t.Errorf("expected 0 converted rules (TX ref should be skipped), got %d", len(result))
	}
}

func TestConvertChainWithTXLink_HeadPreserved(t *testing.T) {
	// Head condition checks real field, chain link checks TX variable.
	// Chain link should be dropped but head preserved.
	input := `SecRule REQUEST_HEADERS:Content-Type "@rx ^application/" \
	"id:920420,phase:1,block,capture,msg:'Content type check',severity:'CRITICAL',tag:'attack-protocol',tag:'paranoia-level/1',chain"
	SecRule TX:content_type "!@within %{tx.allowed_request_content_type}" "t:lowercase"`

	rules, err := ParseFile(input, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")

	if len(result) != 1 {
		t.Fatalf("expected 1 converted rule (head preserved, TX chain dropped), got %d", len(result))
	}

	pr := result[0]
	if pr.ID != "920420" {
		t.Errorf("ID: got %q", pr.ID)
	}
	// Head condition should be present
	if len(pr.Conditions) != 1 {
		t.Errorf("expected 1 condition (head only, chain TX link dropped), got %d", len(pr.Conditions))
	}
	if pr.Conditions[0].Field != "content_type" {
		t.Errorf("Field: expected 'content_type', got %q", pr.Conditions[0].Field)
	}
}
