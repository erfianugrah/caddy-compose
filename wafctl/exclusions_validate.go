package main

import (
	"fmt"
	"regexp"
	"strings"
)

// SecRule field validation patterns — restrict user-supplied values that are
// interpolated directly into ModSecurity directives to prevent injection.
var (
	// ruleTagRe matches valid CRS tag names: letters, digits, /, _, -, .
	// e.g. "language/php", "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"
	ruleTagRe = regexp.MustCompile(`^[a-zA-Z0-9/_.\-]+$`)

	// variableRe matches valid SecRule variable expressions: letters, digits,
	// _, :, !, |, and . — e.g. "ARGS:foo", "!REQUEST_COOKIES:/^__utm/",
	// "REQUEST_HEADERS:User-Agent"
	variableRe = regexp.MustCompile(`^[a-zA-Z0-9_:!.|/^\-]+$`)

	// namedFieldNameRe matches the name portion of named condition fields
	// (header, cookie, args, response_header) — the part before ':' in the
	// value. e.g. "User-Agent", "X-Forwarded-For", "__session"
	namedFieldNameRe = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

	// eventTagRe validates event classification tags: lowercase alphanumeric
	// and hyphens, must start with a letter or digit. Max 50 chars enforced
	// separately. Examples: "scanner", "bot-detection", "blocklist-ipsum".
	eventTagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

// namedConditionFields are condition fields where the value has a "Name:value"
// format and the Name portion is interpolated into the SecRule variable.
var namedConditionFields = map[string]bool{
	"header":          true,
	"cookie":          true,
	"args":            true,
	"response_header": true,
	"body_form":       true,
}

// jsonPathNameRe validates JSON dot-path names used by body_json conditions.
// Allows dots for path navigation, alphanumeric characters, underscores, and
// array indices (digits). Leading dot is optional.
var jsonPathNameRe = regexp.MustCompile(`^\.?[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)*$`)

// validateConditions validates a slice of conditions against a set of allowed fields.
// Pass nil for allowedFields to use validConditionFields (all fields allowed).
func validateConditions(conditions []Condition, allowedFields map[string]bool) error {
	if allowedFields == nil {
		allowedFields = validConditionFields
	}
	for i, c := range conditions {
		if !allowedFields[c.Field] {
			return fmt.Errorf("condition[%d]: invalid field %q", i, c.Field)
		}
		ops, ok := validOperatorsForField[c.Field]
		if !ok || !ops[c.Operator] {
			return fmt.Errorf("condition[%d]: invalid operator %q for field %q", i, c.Operator, c.Field)
		}
		// Empty value is allowed for eq/neq operators (matching empty/missing
		// headers, user-agents, etc. is a legitimate detect rule pattern).
		// All other operators require a non-empty value.
		if c.Value == "" && c.Operator != "eq" && c.Operator != "neq" {
			return fmt.Errorf("condition[%d]: value is required", i)
		}
		// Validate method values.
		if c.Field == "method" {
			validMethods := map[string]bool{
				"GET": true, "POST": true, "PUT": true, "DELETE": true,
				"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
			}
			for _, m := range splitPipe(c.Value) {
				if !validMethods[m] {
					return fmt.Errorf("condition[%d]: invalid HTTP method %q", i, m)
				}
			}
		}
		// Validate named field names (header, cookie, args, response_header, body_form).
		// The "Name:value" format uses the Name as a SecRule variable suffix;
		// restrict it to safe characters to prevent directive injection.
		if namedConditionFields[c.Field] && strings.Contains(c.Value, ":") {
			name := c.Value[:strings.Index(c.Value, ":")]
			if name != "" && !namedFieldNameRe.MatchString(name) {
				return fmt.Errorf("condition[%d]: invalid %s name %q (letters, digits, hyphens, underscores only)", i, c.Field, name)
			}
		}
		// Validate body_json dot-path names separately (allows dots for path navigation).
		if c.Field == "body_json" && strings.Contains(c.Value, ":") {
			name := c.Value[:strings.Index(c.Value, ":")]
			if name != "" && !jsonPathNameRe.MatchString(name) {
				return fmt.Errorf("condition[%d]: invalid body_json path %q (dot-separated alphanumeric segments)", i, name)
			}
		}
		// Validate regex patterns — Go uses RE2 (no lookaheads/lookbehinds).
		// Catches PCRE-only patterns like (?!...) and (?<=...) early.
		if c.Operator == "regex" && c.Value != "" {
			if _, err := regexp.Compile(c.Value); err != nil {
				return fmt.Errorf("condition[%d]: invalid regex %q: %v", i, c.Value, err)
			}
		}
		// Validate transforms — must be known names from the policy engine plugin.
		for _, t := range c.Transforms {
			if !validTransforms[t] {
				return fmt.Errorf("condition[%d]: unknown transform %q", i, t)
			}
		}
		// Reject control characters in condition values.
		if strings.ContainsAny(c.Value, "\n\r") {
			return fmt.Errorf("condition[%d]: value must not contain newlines", i)
		}
	}
	return nil
}

// validateExclusion checks that the exclusion has required fields.
func validateExclusion(e RuleExclusion) error {
	if e.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Reject control characters in the name (used in SecRule comments and msg fields).
	if strings.ContainsAny(e.Name, "\n\r") {
		return fmt.Errorf("name must not contain newlines")
	}
	if !validExclusionTypes[e.Type] {
		return fmt.Errorf("invalid exclusion type: %q", e.Type)
	}

	// Validate group operator.
	if !validGroupOperators[e.GroupOp] {
		return fmt.Errorf("invalid group_operator: %q (must be \"and\" or \"or\")", e.GroupOp)
	}

	// Validate tags: max 10 tags, each lowercase alphanumeric + hyphens, max 50 chars.
	if len(e.Tags) > 10 {
		return fmt.Errorf("too many tags: %d (max 10)", len(e.Tags))
	}
	for i, tag := range e.Tags {
		if len(tag) > 50 {
			return fmt.Errorf("tag[%d] too long: %d chars (max 50)", i, len(tag))
		}
		if !eventTagRe.MatchString(tag) {
			return fmt.Errorf("invalid tag[%d] %q (lowercase alphanumeric and hyphens only, must start with letter or digit)", i, tag)
		}
	}

	// Validate conditions — policy engine types (allow/block) only
	// support request-phase fields; SecRule types support all fields.
	var allowedFields map[string]bool
	if IsPolicyEngineType(e.Type) {
		allowedFields = validPolicyEngineFields
	}
	if err := validateConditions(e.Conditions, allowedFields); err != nil {
		return err
	}

	// Type-specific validation.
	switch e.Type {
	case "allow", "block":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("%s requires at least one condition", e.Type)
		}
	case "anomaly":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("anomaly requires at least one condition")
		}
		if e.AnomalyScore < 1 || e.AnomalyScore > 10 {
			return fmt.Errorf("anomaly_score must be between 1 and 10, got %d", e.AnomalyScore)
		}
		if e.AnomalyParanoiaLevel != 0 && (e.AnomalyParanoiaLevel < 1 || e.AnomalyParanoiaLevel > 4) {
			return fmt.Errorf("anomaly_paranoia_level must be between 1 and 4, got %d", e.AnomalyParanoiaLevel)
		}
	case "detect":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("detect requires at least one condition")
		}
		validSeverities := map[string]bool{
			"CRITICAL": true,
			"ERROR":    true,
			"WARNING":  true,
			"NOTICE":   true,
		}
		if !validSeverities[e.Severity] {
			return fmt.Errorf("detect requires severity (CRITICAL, ERROR, WARNING, NOTICE), got %q", e.Severity)
		}
		if e.DetectParanoiaLevel != 0 && (e.DetectParanoiaLevel < 1 || e.DetectParanoiaLevel > 4) {
			return fmt.Errorf("detect_paranoia_level must be between 0 and 4, got %d", e.DetectParanoiaLevel)
		}
	case "skip_rule":
		if e.RuleID == "" && e.RuleTag == "" {
			return fmt.Errorf("skip_rule requires rule_id or rule_tag")
		}
		if e.RuleID != "" {
			if err := validateRuleIDField(e.RuleID); err != nil {
				return fmt.Errorf("invalid rule_id: %w", err)
			}
		}
		if e.RuleTag != "" {
			if !ruleTagRe.MatchString(e.RuleTag) {
				return fmt.Errorf("invalid rule_tag %q (letters, digits, /, _, -, . only)", e.RuleTag)
			}
		}
		if len(e.Conditions) == 0 {
			return fmt.Errorf("skip_rule requires at least one condition")
		}
	case "raw":
		if e.RawRule == "" {
			return fmt.Errorf("raw_rule is required for type \"raw\"")
		}

	// Advanced types — these still use RuleID/RuleTag/Variable directly
	case "remove_by_id", "update_target_by_id", "runtime_remove_by_id", "runtime_remove_target_by_id":
		if e.RuleID == "" {
			return fmt.Errorf("rule_id is required for type %q", e.Type)
		}
		if err := validateRuleIDField(e.RuleID); err != nil {
			return fmt.Errorf("invalid rule_id: %w", err)
		}
	case "remove_by_tag", "update_target_by_tag", "runtime_remove_by_tag", "runtime_remove_target_by_tag":
		if e.RuleTag == "" {
			return fmt.Errorf("rule_tag is required for type %q", e.Type)
		}
		if !ruleTagRe.MatchString(e.RuleTag) {
			return fmt.Errorf("invalid rule_tag %q (letters, digits, /, _, -, . only)", e.RuleTag)
		}
	}

	// Variable required for update_target types.
	switch e.Type {
	case "update_target_by_id", "update_target_by_tag", "runtime_remove_target_by_id", "runtime_remove_target_by_tag":
		if e.Variable == "" {
			return fmt.Errorf("variable is required for type %q", e.Type)
		}
		if !variableRe.MatchString(e.Variable) {
			return fmt.Errorf("invalid variable %q (letters, digits, _, :, !, |, ., / only)", e.Variable)
		}
	}

	// Runtime advanced types need at least a path condition.
	switch e.Type {
	case "runtime_remove_by_id", "runtime_remove_by_tag", "runtime_remove_target_by_id", "runtime_remove_target_by_tag":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("conditions required for runtime type %q (need at least a path condition)", e.Type)
		}
	}

	return nil
}

// validateRuleIDField checks that a rule_id field contains valid IDs.
// Accepts a single ID (e.g. "932235"), a range (e.g. "932000-932999"),
// or multiple space/comma-separated IDs and ranges.
func validateRuleIDField(field string) error {
	normalized := strings.ReplaceAll(field, ",", " ")
	tokens := strings.Fields(normalized)
	if len(tokens) == 0 {
		return fmt.Errorf("empty rule_id")
	}
	for _, tok := range tokens {
		if !isValidRuleIDToken(tok) {
			return fmt.Errorf("invalid rule ID %q (must be a number or a range like 932000-932999)", tok)
		}
	}
	return nil
}

// isValidRuleIDToken returns true if the token is a valid rule ID (all digits)
// or a valid range (digits-digits).
func isValidRuleIDToken(tok string) bool {
	if tok == "" {
		return false
	}
	// Check for range: digits-digits
	if idx := strings.Index(tok, "-"); idx > 0 && idx < len(tok)-1 {
		return isAllDigits(tok[:idx]) && isAllDigits(tok[idx+1:])
	}
	return isAllDigits(tok)
}

// isAllDigits returns true if every byte in s is an ASCII digit.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// splitPipe splits a pipe-delimited string and trims whitespace.
func splitPipe(s string) []string {
	var parts []string
	for _, p := range strings.Split(s, "|") {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}
