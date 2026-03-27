package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ─── SecRule Parser ────────────────────────────────────────────────
//
// Parses CRS .conf files into []SecRule AST nodes.
// Handles: multi-line continuations, quoted strings with escaped quotes,
// pipe-separated variables with negation, operator parsing, action parsing,
// SecAction, SecMarker (skipped), chain resolution.

// ParseFile parses a CRS .conf file content into SecRule AST nodes.
// filename is used for error reporting and source tracking.
func ParseFile(content, filename string) ([]SecRule, error) {
	result := ParseFileWithUpdates(content, filename)
	if result.err != nil {
		return nil, result.err
	}
	return result.Rules, nil
}

// parseFileResult wraps ParseResult with an error for internal use.
type parseFileResult struct {
	ParseResult
	err error
}

// ParseFileWithUpdates parses a CRS .conf file into SecRule AST nodes AND
// SecRuleUpdateTargetById directives. The updates are collected separately
// so they can be applied to rules from other files after all parsing is complete.
func ParseFileWithUpdates(content, filename string) parseFileResult {
	// Phase 1: Join continuation lines (trailing \)
	lines := joinContinuationLines(content)

	var rules []SecRule
	var updates []TargetUpdate
	var chainHead *SecRule // tracks the start of a chain

	for i, line := range lines {
		lineNum := line.origLine
		text := strings.TrimSpace(line.text)

		// Skip empty lines and comments
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		// Parse SecRuleUpdateTargetById → collect as TargetUpdate
		if strings.HasPrefix(text, "SecRuleUpdateTargetById") {
			if upd, ok := parseSecRuleUpdateTargetById(text); ok {
				updates = append(updates, upd)
			}
			continue
		}

		// Skip directives we don't process
		if strings.HasPrefix(text, "SecMarker") ||
			strings.HasPrefix(text, "SecRuleUpdateTargetByTag") ||
			strings.HasPrefix(text, "SecRuleRemoveById") ||
			strings.HasPrefix(text, "SecRuleUpdateActionById") ||
			strings.HasPrefix(text, "SecComponentSignature") {
			continue
		}

		// SecAction — parse but mark as flow-control
		if strings.HasPrefix(text, "SecAction") {
			rule, err := parseSecAction(text, filename, lineNum)
			if err != nil {
				return parseFileResult{err: fmt.Errorf("%s:%d: %w", filename, lineNum, err)}
			}
			if chainHead != nil {
				chainHead.Chain = rule
				rules = append(rules, *chainHead)
				chainHead = nil
			} else if hasAction(rule.Actions, "chain") {
				chainHead = rule
			} else {
				rules = append(rules, *rule)
			}
			continue
		}

		// SecRule — the main directive
		if strings.HasPrefix(text, "SecRule") {
			rule, err := parseSecRule(text, filename, lineNum)
			if err != nil {
				return parseFileResult{err: fmt.Errorf("%s:%d: parse error: %w", filename, lineNum, err)}
			}

			if chainHead != nil {
				// Walk to end of existing chain
				tail := chainHead
				for tail.Chain != nil {
					tail = tail.Chain
				}
				// Append this rule at the tail
				tail.Chain = rule
				if !hasAction(rule.Actions, "chain") {
					// End of chain — emit the complete chain
					rules = append(rules, *chainHead)
					chainHead = nil
				}
			} else if hasAction(rule.Actions, "chain") {
				chainHead = rule
			} else {
				rules = append(rules, *rule)
			}
			continue
		}

		// Unknown directive — skip with warning
		_ = i // suppress unused
	}

	// Dangling chain (shouldn't happen in valid CRS)
	if chainHead != nil {
		rules = append(rules, *chainHead)
	}

	return parseFileResult{ParseResult: ParseResult{Rules: rules, Updates: updates}}
}

// ─── Line joining ──────────────────────────────────────────────────

type sourceLine struct {
	text     string
	origLine int // original line number (1-based)
}

// joinContinuationLines joins lines ending with \ into single logical lines.
func joinContinuationLines(content string) []sourceLine {
	rawLines := strings.Split(content, "\n")
	var result []sourceLine
	var buf strings.Builder
	startLine := 1

	for i, line := range rawLines {
		lineNum := i + 1
		trimmed := strings.TrimRight(line, " \t\r")

		if strings.HasSuffix(trimmed, "\\") {
			if buf.Len() == 0 {
				startLine = lineNum
			}
			// Remove trailing \ and append
			buf.WriteString(strings.TrimSuffix(trimmed, "\\"))
			continue
		}

		if buf.Len() > 0 {
			buf.WriteString(trimmed)
			result = append(result, sourceLine{text: buf.String(), origLine: startLine})
			buf.Reset()
		} else {
			result = append(result, sourceLine{text: trimmed, origLine: lineNum})
		}
	}

	// Flush any remaining buffer
	if buf.Len() > 0 {
		result = append(result, sourceLine{text: buf.String(), origLine: startLine})
	}

	return result
}

// ─── SecRule parsing ───────────────────────────────────────────────

// parseSecRule parses a "SecRule VARS OP ACTIONS" line.
func parseSecRule(line, filename string, lineNum int) (*SecRule, error) {
	// Remove "SecRule " prefix
	rest := strings.TrimPrefix(line, "SecRule ")
	rest = strings.TrimSpace(rest)

	// Parse the three sections: VARIABLES "OPERATOR" "ACTIONS"
	// Variables end at the first space before the quoted operator
	vars, rest, err := extractFirstToken(rest)
	if err != nil {
		return nil, fmt.Errorf("extracting variables: %w", err)
	}

	op, rest, err := extractQuotedString(rest)
	if err != nil {
		return nil, fmt.Errorf("extracting operator: %w", err)
	}

	actions, _, err := extractQuotedString(rest)
	if err != nil {
		return nil, fmt.Errorf("extracting actions: %w", err)
	}

	// Parse each section
	variables := parseVariables(vars)
	operator := parseOperator(op)
	actionList := parseActions(actions)

	rule := &SecRule{
		Variables:  variables,
		Operator:   operator,
		Actions:    actionList,
		File:       filename,
		Line:       lineNum,
		Transforms: extractTransforms(actionList),
		Tags:       extractTags(actionList),
	}

	// Extract metadata from actions
	rule.ID = actionValue(actionList, "id")
	rule.Msg = actionValue(actionList, "msg")
	rule.Severity = actionValue(actionList, "severity")
	if p := actionValue(actionList, "phase"); p != "" {
		rule.Phase, _ = strconv.Atoi(p)
	}

	// Extract paranoia level from tags
	for _, tag := range rule.Tags {
		if strings.HasPrefix(tag, "paranoia-level/") {
			pl, _ := strconv.Atoi(strings.TrimPrefix(tag, "paranoia-level/"))
			rule.ParanoiaLevel = pl
		}
	}

	return rule, nil
}

// parseSecAction parses a "SecAction ACTIONS" line (no variables or operator).
func parseSecAction(line, filename string, lineNum int) (*SecRule, error) {
	rest := strings.TrimPrefix(line, "SecAction ")
	rest = strings.TrimSpace(rest)

	actions, _, err := extractQuotedString(rest)
	if err != nil {
		return nil, fmt.Errorf("extracting SecAction actions: %w", err)
	}

	actionList := parseActions(actions)

	rule := &SecRule{
		Actions: actionList,
		File:    filename,
		Line:    lineNum,
		Tags:    extractTags(actionList),
	}
	rule.ID = actionValue(actionList, "id")
	rule.Msg = actionValue(actionList, "msg")
	if p := actionValue(actionList, "phase"); p != "" {
		rule.Phase, _ = strconv.Atoi(p)
	}

	return rule, nil
}

// ─── Token extraction ──────────────────────────────────────────────

// extractFirstToken extracts the first whitespace-delimited token from s.
func extractFirstToken(s string) (token, rest string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("empty input")
	}

	// Variables can't be quoted, so just find the first space before a quote
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i], strings.TrimSpace(s[i+1:]), nil
		}
	}
	return s, "", nil
}

// extractQuotedString extracts a "quoted string" from SecRule syntax.
// In SecRule syntax, backslashes are literal (part of regex patterns like \x5c,
// \s, \d, etc.). Only \" is treated as an escaped quote inside the string.
// This is NOT C-style string escaping.
func extractQuotedString(s string) (content, rest string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", nil
	}

	if s[0] != '"' {
		return "", "", fmt.Errorf("expected opening quote, got: %q", s[:min(20, len(s))])
	}

	// Find matching close quote. Only \" is an escape sequence; all other
	// backslashes are literal and must be preserved (regex patterns).
	var buf strings.Builder
	i := 1
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
			// Escaped quote → literal "
			buf.WriteByte('"')
			i += 2
			continue
		}
		if s[i] == '"' {
			return buf.String(), strings.TrimSpace(s[i+1:]), nil
		}
		buf.WriteByte(s[i])
		i++
	}
	return "", "", fmt.Errorf("unterminated quoted string")
}

// ─── Variable parsing ──────────────────────────────────────────────

// parseVariables parses a pipe-separated variable list.
// e.g., "REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|ARGS_NAMES|ARGS|XML:/*"
func parseVariables(s string) []Variable {
	parts := splitVariables(s)
	var vars []Variable
	for _, part := range parts {
		vars = append(vars, parseOneVariable(part))
	}
	return vars
}

// splitVariables splits on | but respects regex key patterns /.../.
// Handles escaped slashes (\/) inside regex patterns — they don't
// close the regex delimiter.
func splitVariables(s string) []string {
	var parts []string
	var buf strings.Builder
	inRegex := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '/' && !inRegex {
			// Check if this starts a regex key (after a colon)
			if buf.Len() > 0 && strings.HasSuffix(buf.String(), ":") {
				inRegex = true
			}
			buf.WriteByte(ch)
		} else if ch == '/' && inRegex {
			// Only close regex if this slash is NOT escaped.
			if i > 0 && s[i-1] == '\\' {
				// Escaped slash inside regex — keep going.
				buf.WriteByte(ch)
			} else {
				buf.WriteByte(ch)
				inRegex = false
			}
		} else if ch == '|' && !inRegex {
			if buf.Len() > 0 {
				parts = append(parts, buf.String())
				buf.Reset()
			}
		} else {
			buf.WriteByte(ch)
		}
	}
	if buf.Len() > 0 {
		parts = append(parts, buf.String())
	}
	return parts
}

// parseOneVariable parses a single variable like "!REQUEST_COOKIES:/__utm/"
func parseOneVariable(s string) Variable {
	v := Variable{}

	// Count prefix
	if strings.HasPrefix(s, "&") {
		v.IsCount = true
		s = s[1:]
	}

	// Negation prefix
	if strings.HasPrefix(s, "!") {
		v.IsNegation = true
		s = s[1:]
	}

	// Split name:key
	colonIdx := strings.Index(s, ":")
	if colonIdx >= 0 {
		v.Name = s[:colonIdx]
		key := s[colonIdx+1:]

		// Check if key is a regex /pattern/
		if strings.HasPrefix(key, "/") && strings.HasSuffix(key, "/") && len(key) > 1 {
			v.KeyIsRegex = true
			v.Key = key[1 : len(key)-1] // strip slashes
		} else {
			v.Key = key
		}
	} else {
		v.Name = s
	}

	return v
}

// ─── Operator parsing ──────────────────────────────────────────────

// parseOperator parses an operator string like "@rx pattern" or "!@pm word1 word2"
func parseOperator(s string) Operator {
	op := Operator{}
	s = strings.TrimSpace(s)

	// Check for negation
	if strings.HasPrefix(s, "!") {
		op.Negated = true
		s = s[1:]
	}

	// Check for @ prefix
	if strings.HasPrefix(s, "@") {
		s = s[1:]
		// Find operator name (until first space)
		spIdx := strings.IndexByte(s, ' ')
		if spIdx >= 0 {
			op.Name = s[:spIdx]
			op.Value = strings.TrimSpace(s[spIdx+1:])
		} else {
			// Operator with no value (e.g., @detectSQLi)
			op.Name = s
		}
	} else {
		// No @ prefix — implicit @rx
		op.Name = "rx"
		op.Value = s
	}

	return op
}

// ─── Action parsing ────────────────────────────────────────────────

// parseActions parses a comma-separated action list.
// Handles quoted values within actions: msg:'foo, bar', tag:'baz'
func parseActions(s string) []Action {
	var actions []Action

	s = strings.TrimSpace(s)
	if s == "" {
		return actions
	}

	// Split by comma, but respect single-quoted values
	parts := splitActions(s)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for key:value or key:'value'
		colonIdx := strings.Index(part, ":")
		if colonIdx >= 0 {
			key := part[:colonIdx]
			val := part[colonIdx+1:]

			// Strip surrounding quotes from value
			val = stripQuotes(val)

			actions = append(actions, Action{Key: key, Value: val})
		} else {
			// Flag action (no value): block, pass, capture, chain, etc.
			actions = append(actions, Action{Key: part})
		}
	}

	return actions
}

// splitActions splits on comma, respecting single-quoted strings.
func splitActions(s string) []string {
	var parts []string
	var buf strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' {
			if inQuote {
				// Check for escaped quote
				if i+1 < len(s) && s[i+1] == '\'' {
					buf.WriteByte('\'')
					i++
					continue
				}
				inQuote = false
			} else {
				inQuote = true
			}
			buf.WriteByte(ch)
		} else if ch == ',' && !inQuote {
			parts = append(parts, buf.String())
			buf.Reset()
		} else {
			buf.WriteByte(ch)
		}
	}
	if buf.Len() > 0 {
		parts = append(parts, buf.String())
	}

	return parts
}

// stripQuotes removes surrounding single quotes from a string.
func stripQuotes(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

// ─── Action helpers ────────────────────────────────────────────────

// actionValue returns the value of the first action with the given key.
func actionValue(actions []Action, key string) string {
	for _, a := range actions {
		if a.Key == key {
			return a.Value
		}
	}
	return ""
}

// hasAction returns true if any action has the given key.
func hasAction(actions []Action, key string) bool {
	for _, a := range actions {
		if a.Key == key {
			return true
		}
	}
	return false
}

// extractTransforms returns transform names from t:xxx actions.
func extractTransforms(actions []Action) []string {
	var transforms []string
	for _, a := range actions {
		if a.Key == "t" && a.Value != "none" {
			transforms = append(transforms, a.Value)
		}
	}
	return transforms
}

// extractTags returns tag values from tag:xxx actions.
func extractTags(actions []Action) []string {
	var tags []string
	for _, a := range actions {
		if a.Key == "tag" {
			tags = append(tags, a.Value)
		}
	}
	return tags
}

// ─── Regex validation ──────────────────────────────────────────────

// possessiveRe matches possessive quantifiers: ++, *+, ?+, }+
var possessiveRe = regexp.MustCompile(`[+*?}]\+`)

// atomicGroupRe matches atomic groups: (?>...)
var atomicGroupRe = regexp.MustCompile(`\(\?>`)

// ValidateRE2 checks if a regex is compatible with Go's RE2 engine.
// Returns the (possibly fixed) regex and any error.
func ValidateRE2(pattern string) (string, error) {
	// Try to fix common PCRE-isms
	fixed := pattern

	// Convert possessive quantifiers to greedy (safe for detection)
	// e.g., x++ → x+, x*+ → x*, x?+ → x?
	fixed = possessiveRe.ReplaceAllStringFunc(fixed, func(m string) string {
		return m[:len(m)-1] // strip trailing +
	})

	// Convert atomic groups to non-capturing groups
	fixed = atomicGroupRe.ReplaceAllString(fixed, "(?:")

	// Try to compile
	_, err := regexp.Compile(fixed)
	if err != nil {
		return pattern, fmt.Errorf("RE2 incompatible: %w", err)
	}

	return fixed, nil
}

// ─── SecRuleUpdateTargetById Parser ────────────────────────────────

// parseSecRuleUpdateTargetById parses a directive like:
//
//	SecRuleUpdateTargetById 932240 "!REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
//	SecRuleUpdateTargetById 930120 !ARGS_NAMES:json.profile
//
// Returns a TargetUpdate with the rule ID and variable exclusions.
func parseSecRuleUpdateTargetById(text string) (TargetUpdate, bool) {
	// Strip the directive prefix
	rest := strings.TrimPrefix(text, "SecRuleUpdateTargetById")
	rest = strings.TrimSpace(rest)

	// Split into rule ID and variable spec
	parts := strings.SplitN(rest, " ", 2)
	if len(parts) != 2 {
		return TargetUpdate{}, false
	}

	ruleID := strings.TrimSpace(parts[0])
	varSpec := strings.TrimSpace(parts[1])

	// Strip surrounding quotes if present
	if len(varSpec) >= 2 && varSpec[0] == '"' && varSpec[len(varSpec)-1] == '"' {
		varSpec = varSpec[1 : len(varSpec)-1]
	}

	// Parse the variable spec using the existing variable parser.
	// These are typically negation variables like !REQUEST_COOKIES:/__utm/
	vars := parseVariables(varSpec)
	if len(vars) == 0 {
		return TargetUpdate{}, false
	}

	return TargetUpdate{
		TargetRuleID: ruleID,
		Variables:    vars,
	}, true
}
