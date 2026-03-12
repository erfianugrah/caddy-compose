package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Validation patterns for condition fields and event tags.
var (
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
// format — the part before ':' is the field name (e.g., header name, cookie name).
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

// numericOperators are operators that require a numeric Value.
var numericOperators = map[string]bool{"gt": true, "ge": true, "lt": true, "le": true}

// validateConditions validates a slice of conditions against a set of allowed fields.
// Pass nil for allowedFields to use validConditionFields (all fields allowed).
func validateConditions(conditions []Condition, allowedFields map[string]bool) error {
	if allowedFields == nil {
		allowedFields = validConditionFields
	}
	for i, c := range conditions {
		// Handle count: pseudo-field — "count:all_args", etc.
		// Resolve the underlying field for validation, then check it's an aggregate field.
		fieldForValidation := c.Field
		if strings.HasPrefix(c.Field, "count:") {
			underlying := c.Field[len("count:"):]
			if !validAggregateFields[underlying] {
				return fmt.Errorf("condition[%d]: count: requires an aggregate field, got %q", i, underlying)
			}
			if !numericOperators[c.Operator] {
				return fmt.Errorf("condition[%d]: count: fields require a numeric operator (gt, ge, lt, le), got %q", i, c.Operator)
			}
			// Use the underlying aggregate field for field allowlist validation.
			fieldForValidation = underlying
		}
		if !allowedFields[fieldForValidation] {
			return fmt.Errorf("condition[%d]: invalid field %q", i, c.Field)
		}

		// Operator validation: numeric operators are valid on any field.
		// phrase_match is checked against the per-field operator map.
		if !numericOperators[c.Operator] {
			ops, ok := validOperatorsForField[fieldForValidation]
			if !ok || !ops[c.Operator] {
				return fmt.Errorf("condition[%d]: invalid operator %q for field %q", i, c.Operator, c.Field)
			}
		}

		// Empty value is allowed for eq/neq (matching empty/missing headers),
		// phrase_match (patterns come from ListItems), and exists.
		if c.Value == "" && c.Operator != "eq" && c.Operator != "neq" && c.Operator != "phrase_match" && c.Operator != "exists" {
			return fmt.Errorf("condition[%d]: value is required", i)
		}
		// phrase_match requires list_items.
		if c.Operator == "phrase_match" && len(c.ListItems) == 0 {
			return fmt.Errorf("condition[%d]: phrase_match requires list_items (pattern list)", i)
		}
		// Numeric operators require a parseable numeric value.
		// For named fields (header, cookie, args, etc.), the value is "Name:number" —
		// extract the portion after ':' for numeric parsing. Same for body_json ("dotpath:number").
		if numericOperators[c.Operator] {
			numStr := c.Value
			if namedConditionFields[c.Field] || c.Field == "body_json" {
				if idx := strings.Index(numStr, ":"); idx >= 0 {
					numStr = numStr[idx+1:]
				}
			}
			if _, err := strconv.ParseFloat(numStr, 64); err != nil {
				return fmt.Errorf("condition[%d]: numeric operator %q requires a numeric value, got %q", i, c.Operator, c.Value)
			}
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
		// The "Name:value" format uses the Name as a policy engine variable suffix;
		// restrict it to safe characters to prevent injection.
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
	// Reject control characters in the name.
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

	// Validate conditions — all types only support request-phase fields.
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
