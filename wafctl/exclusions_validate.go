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
		// phrase_match/not_phrase_match (patterns come from ListItems), and exists.
		if c.Value == "" && c.Operator != "eq" && c.Operator != "neq" && c.Operator != "phrase_match" && c.Operator != "not_phrase_match" && c.Operator != "exists" {
			return fmt.Errorf("condition[%d]: value is required", i)
		}
		// phrase_match and not_phrase_match require list_items.
		if (c.Operator == "phrase_match" || c.Operator == "not_phrase_match") && len(c.ListItems) == 0 {
			return fmt.Errorf("condition[%d]: %s requires list_items (pattern list)", i, c.Operator)
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
		// Validate method values (skip for list operators — value is a list name, not a method).
		if c.Field == "method" && c.Operator != "in_list" && c.Operator != "not_in_list" {
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
		if (c.Operator == "regex" || c.Operator == "not_regex") && c.Value != "" {
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

	// Validate conditions — rate_limit uses a restricted field set,
	// other policy engine types use the full set.
	if e.Type != "rate_limit" {
		var allowedFields map[string]bool
		if IsPolicyEngineType(e.Type) {
			allowedFields = validPolicyEngineFields
		}
		if err := validateConditions(e.Conditions, allowedFields); err != nil {
			return err
		}
	}

	// Type-specific validation.
	switch e.Type {
	case "allow", "block":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("%s requires at least one condition", e.Type)
		}
	case "skip":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("skip requires at least one condition")
		}
		if e.SkipTargets == nil {
			return fmt.Errorf("skip requires skip_targets")
		}
		if err := validateSkipTargets(e.SkipTargets); err != nil {
			return err
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
	case "rate_limit":
		// Service is required for rate limit rules.
		if e.Service == "" {
			return fmt.Errorf("rate_limit requires service (hostname or \"*\")")
		}
		if strings.ContainsAny(e.Service, "\n\r") {
			return fmt.Errorf("service must not contain newlines")
		}
		// Key validation.
		if e.RateLimitKey == "" {
			return fmt.Errorf("rate_limit requires rate_limit_key")
		}
		if !validRLKeyPattern.MatchString(e.RateLimitKey) {
			return fmt.Errorf("invalid rate_limit_key %q (must be client_ip, path, static, client_ip+path, client_ip+method, header:<name>, or cookie:<name>)", e.RateLimitKey)
		}
		// Events and window.
		if e.RateLimitEvents < 1 {
			return fmt.Errorf("rate_limit_events must be at least 1")
		}
		if e.RateLimitEvents > 100000 {
			return fmt.Errorf("rate_limit_events must be at most 100000")
		}
		if e.RateLimitWindow == "" {
			return fmt.Errorf("rate_limit requires rate_limit_window")
		}
		if !validWindowPattern.MatchString(e.RateLimitWindow) {
			return fmt.Errorf("rate_limit_window must be a duration like 1m, 30s, 1h")
		}
		// Action validation.
		if !validRLActions[e.RateLimitAction] {
			return fmt.Errorf("invalid rate_limit_action %q (must be \"deny\" or \"log_only\")", e.RateLimitAction)
		}
		// Priority.
		if e.Priority < 0 || e.Priority > 999 {
			return fmt.Errorf("priority must be 0-999")
		}
		// GroupOp "or" not yet supported for multi-condition RL rules.
		if e.GroupOp == "or" && len(e.Conditions) > 1 {
			return fmt.Errorf("group_operator \"or\" is not yet supported for rate limit rules with multiple conditions")
		}
		// RL rules use the restricted condition field set (request-phase only).
		if err := validateConditions(e.Conditions, validRLConditionFields); err != nil {
			return err
		}
		return nil // Skip the general condition validation below (already done).
	}

	return nil
}

// validSkipPhases are the phases that can be targeted by a skip rule.
var validSkipPhases = map[string]bool{
	"detect":     true,
	"rate_limit": true,
	"block":      true,
}

// validateSkipTargets validates the skip_targets of a skip rule.
func validateSkipTargets(st *SkipTargets) error {
	// At least one target must be specified.
	if !st.AllRemaining && len(st.Rules) == 0 && len(st.Phases) == 0 {
		return fmt.Errorf("skip_targets must specify at least one of: rules, phases, or all_remaining")
	}
	for i, phase := range st.Phases {
		if !validSkipPhases[phase] {
			return fmt.Errorf("skip_targets.phases[%d]: invalid phase %q (must be detect, rate_limit, or block)", i, phase)
		}
	}
	// Validate rule IDs are non-empty strings.
	for i, ruleID := range st.Rules {
		if ruleID == "" {
			return fmt.Errorf("skip_targets.rules[%d]: rule ID must not be empty", i)
		}
		if strings.ContainsAny(ruleID, "\n\r") {
			return fmt.Errorf("skip_targets.rules[%d]: rule ID must not contain newlines", i)
		}
	}
	return nil
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
