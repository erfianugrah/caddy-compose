package main

import (
	"strings"
	"testing"
)

func TestJoinContinuationLines(t *testing.T) {
	input := "line1 \\\nline2 \\\nline3\nline4"
	lines := joinContinuationLines(input)

	if len(lines) != 2 {
		t.Fatalf("expected 2 logical lines, got %d", len(lines))
	}
	if lines[0].text != "line1 line2 line3" {
		t.Errorf("line 0: got %q", lines[0].text)
	}
	if lines[0].origLine != 1 {
		t.Errorf("line 0 origLine: got %d, want 1", lines[0].origLine)
	}
	if lines[1].text != "line4" {
		t.Errorf("line 1: got %q", lines[1].text)
	}
}

func TestParseVariables(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"ARGS", 1},
		{"ARGS|REQUEST_COOKIES", 2},
		{"REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|ARGS_NAMES|ARGS|XML:/*", 5},
		{"REQUEST_HEADERS:User-Agent", 1},
		{"&ARGS", 1},
	}

	for _, tt := range tests {
		vars := parseVariables(tt.input)
		if len(vars) != tt.want {
			t.Errorf("parseVariables(%q): got %d vars, want %d", tt.input, len(vars), tt.want)
		}
	}
}

func TestSplitVariables_EscapedSlash(t *testing.T) {
	// Regex key containing an escaped slash should not prematurely close the regex.
	tests := []struct {
		input string
		want  int
		desc  string
	}{
		{`REQUEST_COOKIES:/^path\/to\/thing$/|ARGS`, 2, "escaped slashes in regex"},
		{`!REQUEST_COOKIES:/^foo\/bar$/|ARGS|ARGS_NAMES`, 3, "negated escaped slashes"},
		{`REQUEST_COOKIES:/__utm/|ARGS`, 2, "simple regex (no escaped slashes)"},
		{`REQUEST_COOKIES:/^a\/b\/c$/`, 1, "single var with escaped slashes"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			parts := splitVariables(tt.input)
			if len(parts) != tt.want {
				t.Errorf("splitVariables(%q): got %d parts %v, want %d", tt.input, len(parts), parts, tt.want)
			}
		})
	}
}

func TestParseVariable_Negation(t *testing.T) {
	vars := parseVariables("REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|ARGS")
	if len(vars) != 3 {
		t.Fatalf("expected 3 vars, got %d", len(vars))
	}

	// !REQUEST_COOKIES:/__utm/
	neg := vars[1]
	if !neg.IsNegation {
		t.Error("expected IsNegation=true")
	}
	if neg.Name != "REQUEST_COOKIES" {
		t.Errorf("name: got %q, want REQUEST_COOKIES", neg.Name)
	}
	if neg.Key != "__utm" {
		t.Errorf("key: got %q, want __utm", neg.Key)
	}
	if !neg.KeyIsRegex {
		t.Error("expected KeyIsRegex=true for /__utm/")
	}
}

func TestParseVariable_Count(t *testing.T) {
	vars := parseVariables("&ARGS")
	if len(vars) != 1 {
		t.Fatalf("expected 1 var, got %d", len(vars))
	}
	if !vars[0].IsCount {
		t.Error("expected IsCount=true")
	}
	if vars[0].Name != "ARGS" {
		t.Errorf("name: got %q, want ARGS", vars[0].Name)
	}
}

func TestParseVariable_XML(t *testing.T) {
	vars := parseVariables("XML:/*")
	if len(vars) != 1 {
		t.Fatalf("expected 1 var, got %d", len(vars))
	}
	if vars[0].Name != "XML" {
		t.Errorf("name: got %q, want XML", vars[0].Name)
	}
	if vars[0].Key != "/*" {
		t.Errorf("key: got %q, want /*", vars[0].Key)
	}
}

func TestParseOperator(t *testing.T) {
	tests := []struct {
		input   string
		name    string
		value   string
		negated bool
	}{
		{`@rx (?i)foo`, "rx", "(?i)foo", false},
		{`@pm word1 word2 word3`, "pm", "word1 word2 word3", false},
		{`@pmFromFile unix-shell.data`, "pmFromFile", "unix-shell.data", false},
		{`@detectSQLi`, "detectSQLi", "", false},
		{`!@rx pattern`, "rx", "pattern", true},
		{`@streq value`, "streq", "value", false},
		{`@contains test`, "contains", "test", false},
	}

	for _, tt := range tests {
		op := parseOperator(tt.input)
		if op.Name != tt.name {
			t.Errorf("parseOperator(%q).Name = %q, want %q", tt.input, op.Name, tt.name)
		}
		if op.Value != tt.value {
			t.Errorf("parseOperator(%q).Value = %q, want %q", tt.input, op.Value, tt.value)
		}
		if op.Negated != tt.negated {
			t.Errorf("parseOperator(%q).Negated = %v, want %v", tt.input, op.Negated, tt.negated)
		}
	}
}

func TestParseActions(t *testing.T) {
	input := `id:932230,phase:2,block,capture,t:none,t:cmdLine,msg:'Remote Command Execution: Unix Command Injection',tag:'attack-rce',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.rce_score=+%{tx.critical_anomaly_score}'`
	actions := parseActions(input)

	// Check a few key actions
	if actionValue(actions, "id") != "932230" {
		t.Errorf("id: got %q", actionValue(actions, "id"))
	}
	if actionValue(actions, "phase") != "2" {
		t.Errorf("phase: got %q", actionValue(actions, "phase"))
	}
	if actionValue(actions, "msg") != "Remote Command Execution: Unix Command Injection" {
		t.Errorf("msg: got %q", actionValue(actions, "msg"))
	}
	if actionValue(actions, "severity") != "CRITICAL" {
		t.Errorf("severity: got %q", actionValue(actions, "severity"))
	}
	if !hasAction(actions, "block") {
		t.Error("expected 'block' action")
	}
	if !hasAction(actions, "capture") {
		t.Error("expected 'capture' action")
	}

	// Check transforms
	transforms := extractTransforms(actions)
	if len(transforms) != 1 || transforms[0] != "cmdLine" {
		t.Errorf("transforms: got %v, want [cmdLine]", transforms)
	}

	// Check tags
	tags := extractTags(actions)
	if len(tags) < 2 {
		t.Errorf("expected at least 2 tags, got %d", len(tags))
	}
}

func TestParseSecRule(t *testing.T) {
	// A simplified but representative CRS rule
	input := `SecRule ARGS|REQUEST_COOKIES "@rx (?i)etc/passwd" "id:930120,phase:2,block,capture,t:none,msg:'OS file access attempt',tag:'attack-lfi',tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.lfi_score=+%{tx.critical_anomaly_score}'"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]
	if rule.ID != "930120" {
		t.Errorf("ID: got %q, want 930120", rule.ID)
	}
	if rule.Phase != 2 {
		t.Errorf("Phase: got %d, want 2", rule.Phase)
	}
	if rule.Msg != "OS file access attempt" {
		t.Errorf("Msg: got %q", rule.Msg)
	}
	if rule.Severity != "CRITICAL" {
		t.Errorf("Severity: got %q", rule.Severity)
	}
	if len(rule.Variables) != 2 {
		t.Errorf("Variables: got %d, want 2", len(rule.Variables))
	}
	if rule.Operator.Name != "rx" {
		t.Errorf("Operator: got %q, want rx", rule.Operator.Name)
	}
	if rule.ParanoiaLevel != 1 {
		t.Errorf("ParanoiaLevel: got %d, want 1", rule.ParanoiaLevel)
	}
}

func TestParseMultiLineRule(t *testing.T) {
	input := `SecRule ARGS "@rx test" \
    "id:999001,\
    phase:2,\
    block,\
    msg:'Test rule',\
    severity:'WARNING'"
`
	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "999001" {
		t.Errorf("ID: got %q, want 999001", rules[0].ID)
	}
	if rules[0].Msg != "Test rule" {
		t.Errorf("Msg: got %q", rules[0].Msg)
	}
}

func TestParseChainedRules(t *testing.T) {
	input := `SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json" \
    "id:200001,\
    phase:2,\
    block,\
    chain,\
    msg:'JSON body attack'"

SecRule REQUEST_BODY "@rx malicious" \
    "t:none,\
    tag:'attack-generic'"
`
	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (chain), got %d", len(rules))
	}
	if rules[0].Chain == nil {
		t.Fatal("expected chain to be set")
	}
	if rules[0].ID != "200001" {
		t.Errorf("chain head ID: got %q", rules[0].ID)
	}
	if rules[0].Chain.Operator.Value != "malicious" {
		t.Errorf("chain tail operator value: got %q", rules[0].Chain.Operator.Value)
	}
}

func TestSkipComments(t *testing.T) {
	input := `# This is a comment
# Another comment
SecRule ARGS "@rx test" "id:100001,phase:2,block,msg:'Test'"
# Trailing comment`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestSkipSecMarker(t *testing.T) {
	input := `SecMarker "END-REQUEST-932-APPLICATION-ATTACK-RCE"
SecRule ARGS "@rx test" "id:100001,phase:2,block,msg:'Test'"`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestValidateRE2(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
	}{
		{`(?i)foo`, true},
		{`\btest\b`, true},
		{`(?:group)`, true},
		{`(?s)dotall`, true},
		// Possessive quantifiers — should be auto-fixed
		{`x++`, true},
		{`x*+`, true},
		// Valid RE2 patterns from CRS
		{`!-\d`, true},
		{`^\(\s*\)\s+\{`, true},
	}

	for _, tt := range tests {
		_, err := ValidateRE2(tt.input)
		if tt.ok && err != nil {
			t.Errorf("ValidateRE2(%q): unexpected error: %v", tt.input, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("ValidateRE2(%q): expected error", tt.input)
		}
	}
}

func TestExtractQuotedString(t *testing.T) {
	tests := []struct {
		input   string
		content string
		rest    string
		err     bool
	}{
		{`"hello" world`, "hello", "world", false},
		{`"it's \"fine\"" done`, `it's "fine"`, "done", false},
		{`"" trailing`, "", "trailing", false},
		{`no-quote`, "", "", true},
		// Backslashes are literal in SecRule syntax (regex patterns)
		{`"@rx \x5c\x0b" rest`, `@rx \x5c\x0b`, "rest", false},
		{`"@rx (?:test)\s+" next`, `@rx (?:test)\s+`, "next", false},
		{`"@rx \(foo\)" end`, `@rx \(foo\)`, "end", false},
	}

	for _, tt := range tests {
		content, rest, err := extractQuotedString(tt.input)
		if tt.err {
			if err == nil {
				t.Errorf("extractQuotedString(%q): expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("extractQuotedString(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if content != tt.content {
			t.Errorf("extractQuotedString(%q): content = %q, want %q", tt.input, content, tt.content)
		}
		if rest != tt.rest {
			t.Errorf("extractQuotedString(%q): rest = %q, want %q", tt.input, rest, tt.rest)
		}
	}
}

func TestParseTripleChain(t *testing.T) {
	input := `SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json" \
    "id:300001,\
    phase:2,\
    block,\
    chain,\
    msg:'Triple chain test'"

SecRule REQUEST_BODY "@rx evil" \
    "t:none,\
    chain"

SecRule ARGS:action "@streq delete" \
    "t:none,\
    tag:'attack-generic'"
`
	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (triple chain), got %d", len(rules))
	}
	head := rules[0]
	if head.ID != "300001" {
		t.Errorf("chain head ID: got %q", head.ID)
	}
	if head.Chain == nil {
		t.Fatal("expected chain link 1")
	}
	if head.Chain.Operator.Value != "evil" {
		t.Errorf("chain link 1 operator: got %q", head.Chain.Operator.Value)
	}
	if head.Chain.Chain == nil {
		t.Fatal("expected chain link 2 (triple chain)")
	}
	if head.Chain.Chain.Operator.Value != "delete" {
		t.Errorf("chain link 2 operator: got %q, want delete", head.Chain.Chain.Operator.Value)
	}
}

func TestSkipSecRuleUpdateTargetById(t *testing.T) {
	input := `SecRuleUpdateTargetById 932240 "!REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
SecRuleUpdateTargetById 941100 "!REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
SecRule ARGS "@rx test" "id:100001,phase:2,block,msg:'Test'"
SecRuleRemoveById 123456`

	rules, err := ParseFile(input, "test.conf")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (skipping update/remove directives), got %d", len(rules))
	}
	if rules[0].ID != "100001" {
		t.Errorf("ID: got %q, want 100001", rules[0].ID)
	}
}

func TestParseFileWithUpdates_CollectsTargetUpdates(t *testing.T) {
	input := `SecRuleUpdateTargetById 932240 "!REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
SecRuleUpdateTargetById 941100 "!REQUEST_COOKIES:__gads"
SecRuleUpdateTargetById 930120 !ARGS_NAMES:json.profile
SecRule ARGS "@rx test" "id:100001,phase:2,block,msg:'Test'"
SecRuleRemoveById 123456`

	result := ParseFileWithUpdates(input, "test.conf")
	if result.err != nil {
		t.Fatalf("parse error: %v", result.err)
	}

	// Should have 1 rule and 3 target updates
	if len(result.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(result.Rules))
	}
	if len(result.Updates) != 3 {
		t.Fatalf("expected 3 target updates, got %d", len(result.Updates))
	}

	// Check first update: 932240 !REQUEST_COOKIES:/^_ga.../
	upd := result.Updates[0]
	if upd.TargetRuleID != "932240" {
		t.Errorf("update[0] TargetRuleID: got %q", upd.TargetRuleID)
	}
	if len(upd.Variables) != 1 {
		t.Fatalf("update[0] expected 1 variable, got %d", len(upd.Variables))
	}
	v := upd.Variables[0]
	if !v.IsNegation {
		t.Error("update[0] variable should be negation")
	}
	if v.Name != "REQUEST_COOKIES" {
		t.Errorf("update[0] variable name: got %q", v.Name)
	}
	if !v.KeyIsRegex {
		t.Error("update[0] variable key should be regex")
	}

	// Check third update: 930120 !ARGS_NAMES:json.profile (unquoted)
	upd3 := result.Updates[2]
	if upd3.TargetRuleID != "930120" {
		t.Errorf("update[2] TargetRuleID: got %q", upd3.TargetRuleID)
	}
	v3 := upd3.Variables[0]
	if v3.Name != "ARGS_NAMES" {
		t.Errorf("update[2] variable name: got %q", v3.Name)
	}
	if v3.Key != "json.profile" {
		t.Errorf("update[2] variable key: got %q", v3.Key)
	}
	if v3.KeyIsRegex {
		t.Error("update[2] variable key should NOT be regex")
	}
}

func TestSplitActions_QuotedComma(t *testing.T) {
	// Commas inside single quotes should not split
	input := `msg:'Remote Command Execution: Unix Command Injection',tag:'attack-rce'`
	parts := splitActions(input)
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d: %v", len(parts), parts)
	}
	if !strings.Contains(parts[0], "Remote Command Execution: Unix Command Injection") {
		t.Errorf("part 0: %q", parts[0])
	}
}
