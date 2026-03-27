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

	// ARGS|REQUEST_COOKIES maps to 2 fields (all_args_values, all_cookies),
	// so the condition should be an OR group with 2 sub-conditions.
	if cond.GroupOp != "or" {
		t.Errorf("GroupOp: got %q, want or", cond.GroupOp)
	}
	if len(cond.Group) != 2 {
		t.Fatalf("expected 2 sub-conditions in group, got %d", len(cond.Group))
	}

	// Sub-conditions should be sorted by field name: all_args_values, all_cookies
	if cond.Group[0].Field != "all_args_values" {
		t.Errorf("Group[0].Field: got %q, want all_args_values", cond.Group[0].Field)
	}
	if cond.Group[1].Field != "all_cookies" {
		t.Errorf("Group[1].Field: got %q, want all_cookies", cond.Group[1].Field)
	}

	// Each sub-condition should have the same operator and value
	for i, sub := range cond.Group {
		if sub.Operator != "regex" {
			t.Errorf("Group[%d].Operator: got %q, want regex", i, sub.Operator)
		}
		if sub.Value != "(?i)etc/passwd" {
			t.Errorf("Group[%d].Value: got %q", i, sub.Value)
		}
		if sub.MultiMatch {
			t.Errorf("Group[%d].MultiMatch should be false", i)
		}
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
	// response_body is not yet supported by the plugin, so the rule should
	// be skipped. Use response_status (supported) for the outbound phase test.
	input := `SecRule RESPONSE_STATUS "@rx ^5\d{2}$" "id:950001,phase:4,block,msg:'Server Error',severity:'ERROR'"`

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
	if result[0].Conditions[0].Field != "response_status" {
		t.Errorf("expected field=response_status, got %q", result[0].Conditions[0].Field)
	}
}

func TestResponseBodySkippedAsUnsupported(t *testing.T) {
	// response_body is not supported by the plugin — rules using it should be skipped.
	input := `SecRule RESPONSE_BODY "@rx password" "id:950099,phase:4,block,msg:'Data Leakage',severity:'ERROR'"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "test.conf")

	if len(result) != 0 {
		t.Errorf("expected 0 rules (response_body unsupported), got %d", len(result))
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

	// First condition: Content-Type header check (mapped to header:Content-Type)
	if pr.Conditions[0].Field != "header:Content-Type" {
		t.Errorf("condition[0].Field: got %q, want header:Content-Type", pr.Conditions[0].Field)
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
	if r.ConvertedRules != 1 {
		t.Errorf("ConvertedRules: got %d, want 1 (ARGS rule only; RESPONSE_BODY unsupported)", r.ConvertedRules)
	}
	if r.SkippedRules != 2 {
		t.Errorf("SkippedRules: got %d, want 2 (1 flow control + 1 unsupported field)", r.SkippedRules)
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
	if pr.Conditions[0].Field != "header:Content-Type" {
		t.Errorf("Field: expected 'header:Content-Type', got %q", pr.Conditions[0].Field)
	}
}

func TestBuildFieldCondition_SingleField(t *testing.T) {
	// Single field should produce a direct condition, not a group.
	input := `SecRule REQUEST_BODY "@rx test" "id:800001,phase:2,block,msg:'Test',severity:'CRITICAL'"`
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
	if cond.Field != "body" {
		t.Errorf("Field: got %q, want body", cond.Field)
	}
	if cond.Operator != "regex" {
		t.Errorf("Operator: got %q, want regex", cond.Operator)
	}
	if len(cond.Group) != 0 {
		t.Errorf("single-field condition should not have a group, got %d", len(cond.Group))
	}
}

func TestBuildFieldCondition_MultiFieldGroup(t *testing.T) {
	// Multiple fields spanning args + cookies + body + specific headers
	// should produce an OR group, NOT request_combined.
	input := `SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer "@rx attack" "id:800002,phase:2,block,msg:'Multi-field test',severity:'CRITICAL'"`
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

	// Should be a group condition, NOT a direct field
	if cond.GroupOp != "or" {
		t.Fatalf("expected OR group, got GroupOp=%q Field=%q", cond.GroupOp, cond.Field)
	}

	// Collect fields from group
	fields := make(map[string]bool)
	for _, sub := range cond.Group {
		fields[sub.Field] = true
		if sub.Operator != "regex" {
			t.Errorf("sub-condition field=%q has operator %q, want regex", sub.Field, sub.Operator)
		}
	}

	// Must NOT contain request_combined or all_headers
	if fields["request_combined"] {
		t.Error("group should not contain request_combined")
	}
	if fields["all_headers"] {
		t.Error("group should not contain all_headers — only named headers")
	}

	// Must contain the specific fields
	for _, want := range []string{"all_args_values", "all_args_names", "all_cookies", "all_cookies_names", "body", "user_agent", "referer"} {
		if !fields[want] {
			t.Errorf("missing expected field %q in group", want)
		}
	}
}

func TestBuildFieldCondition_ExcludesDistributed(t *testing.T) {
	// Excludes should be distributed to matching fields only.
	// !REQUEST_COOKIES:/__utm/ should only appear on cookie fields.
	input := `SecRule ARGS|REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/ "@rx test" "id:800003,phase:2,block,msg:'Exclude test',severity:'CRITICAL'"`
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
	if cond.GroupOp != "or" {
		t.Fatalf("expected OR group, got GroupOp=%q", cond.GroupOp)
	}

	for _, sub := range cond.Group {
		switch sub.Field {
		case "all_cookies":
			// Cookie field should have the cookie exclude
			if len(sub.Excludes) == 0 {
				t.Error("all_cookies should have cookie excludes")
			}
		case "all_args_values":
			// Args field should NOT have cookie excludes
			if len(sub.Excludes) != 0 {
				t.Errorf("all_args_values should not have excludes, got %v", sub.Excludes)
			}
		}
	}
}

func TestConvertChainWithTXLink_CatchAllHeadSkipped(t *testing.T) {
	// Head uses @rx ^.*$ (catch-all) with a chain link that checks TX variables.
	// The chain link gets dropped (TX variables are unconvertible). With the
	// catch-all head alone, the rule matches everything — it should be skipped.
	// This is the pattern used by CRS 920450/920451 (restricted headers).
	input := `SecRule REQUEST_HEADERS_NAMES "@rx ^.*$" \
	"id:800010,phase:1,block,capture,msg:'Header restricted',severity:'CRITICAL',tag:'paranoia-level/1',chain"
	SecRule TX:/^header_920450_/ "@within %{tx.restricted_headers}" "t:lowercase"`

	rules, err := ParseFile(input, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	converter := NewConverter(nil)
	result := converter.Convert(rules, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf")

	if len(result) != 0 {
		t.Errorf("expected 0 rules (catch-all head with dropped chain should be skipped), got %d", len(result))
	}
}

func TestSortRules_StableOrder(t *testing.T) {
	rules := []PolicyRule{
		{ID: "920450", Name: "CRS version"},
		{ID: "920450", Name: "Custom version"},
		{ID: "920100", Name: "Rule 100"},
	}

	SortRules(rules)

	if rules[0].ID != "920100" {
		t.Errorf("expected 920100 first, got %s", rules[0].ID)
	}
	// Stable sort preserves relative order: CRS version before Custom version
	if rules[1].Name != "CRS version" {
		t.Errorf("expected stable order preserved: CRS before Custom, got %q then %q",
			rules[1].Name, rules[2].Name)
	}
}
