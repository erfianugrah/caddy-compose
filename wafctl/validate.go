package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// ─── Config Validation ─────────────────────────────────────────────
//
// Validates generated SecRule config text before deploying to Caddy/Coraza.
// Catches common issues that cause Coraza's seclang parser to silently
// stop loading rules from a file, which is extremely hard to debug at
// runtime.

// RuleWarning describes a potential issue in a generated config line.
type RuleWarning struct {
	Line    int    `json:"line"`
	RuleID  string `json:"rule_id,omitempty"`
	Level   string `json:"level"` // "error", "warning", "info"
	Message string `json:"message"`
}

// ValidateResult is the output of ValidateGeneratedConfig.
type ValidateResult struct {
	TotalRules  int           `json:"total_rules"`
	TotalLines  int           `json:"total_lines"`
	RuleIDs     []string      `json:"rule_ids"`
	Warnings    []RuleWarning `json:"warnings"`
	Valid       bool          `json:"valid"` // no errors (warnings are OK)
	PreCRSConf  string        `json:"pre_crs_conf,omitempty"`
	PostCRSConf string        `json:"post_crs_conf,omitempty"`
	WAFSettings string        `json:"waf_settings,omitempty"`
}

// validateRuleIDRe extracts the rule ID from a SecRule/SecAction line.
var validateRuleIDRe = regexp.MustCompile(`\bid:(\d+)\b`)

// ValidateGeneratedConfig checks the generated pre-CRS and post-CRS config
// text for common issues that would cause Coraza to fail parsing.
func ValidateGeneratedConfig(preCRS, postCRS, wafSettings string) ValidateResult {
	result := ValidateResult{Valid: true}

	// Validate each config section.
	preCRSWarnings := validateConfigSection(preCRS, "pre-crs")
	postCRSWarnings := validateConfigSection(postCRS, "post-crs")
	settingsWarnings := validateConfigSection(wafSettings, "waf-settings")

	result.Warnings = append(result.Warnings, preCRSWarnings...)
	result.Warnings = append(result.Warnings, postCRSWarnings...)
	result.Warnings = append(result.Warnings, settingsWarnings...)

	// Count rules and extract IDs from pre-CRS.
	result.RuleIDs, result.TotalRules = extractRuleIDs(preCRS)
	postIDs, postCount := extractRuleIDs(postCRS)
	result.RuleIDs = append(result.RuleIDs, postIDs...)
	result.TotalRules += postCount
	settingsIDs, settingsCount := extractRuleIDs(wafSettings)
	result.RuleIDs = append(result.RuleIDs, settingsIDs...)
	result.TotalRules += settingsCount

	result.TotalLines = strings.Count(preCRS, "\n") + strings.Count(postCRS, "\n") + strings.Count(wafSettings, "\n")

	// Check for any errors (not just warnings).
	for _, w := range result.Warnings {
		if w.Level == "error" {
			result.Valid = false
			break
		}
	}

	return result
}

// validateConfigSection checks a single config file's text for issues.
func validateConfigSection(content, section string) []RuleWarning {
	if strings.TrimSpace(content) == "" {
		return nil
	}

	var warnings []RuleWarning
	lines := strings.Split(content, "\n")

	// Track state for multi-line rules (backslash continuation).
	var fullLine strings.Builder
	startLineNum := 0

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Handle backslash continuation.
		if strings.HasSuffix(trimmed, `\`) {
			if fullLine.Len() == 0 {
				startLineNum = lineNum
			}
			fullLine.WriteString(strings.TrimSuffix(trimmed, `\`))
			continue
		}

		// Complete the line.
		if fullLine.Len() > 0 {
			fullLine.WriteString(trimmed)
			trimmed = fullLine.String()
			lineNum = startLineNum
			fullLine.Reset()
			startLineNum = 0
		}

		// Now validate the complete directive line.
		w := validateDirectiveLine(trimmed, lineNum, section)
		warnings = append(warnings, w...)
	}

	return warnings
}

// validateDirectiveLine checks a single complete SecRule/SecAction line.
func validateDirectiveLine(line string, lineNum int, section string) []RuleWarning {
	var warnings []RuleWarning

	// Extract the rule ID if present.
	ruleID := ""
	if m := validateRuleIDRe.FindStringSubmatch(line); len(m) > 1 {
		ruleID = m[1]
	}

	// Check for unbalanced single quotes in action strings.
	if strings.HasPrefix(line, "SecRule") || strings.HasPrefix(line, "SecAction") {
		w := checkQuoteBalance(line, lineNum, ruleID, section)
		warnings = append(warnings, w...)
	}

	// Check for self-referencing ctl:ruleRemoveById.
	if ruleID != "" && strings.Contains(line, "ctl:ruleRemoveById=") {
		w := checkSelfReference(line, lineNum, ruleID, section)
		warnings = append(warnings, w...)
	}

	// Check for commas inside msg:'...' values (defensive warning).
	if strings.Contains(line, "msg:'") {
		w := checkMsgCommas(line, lineNum, ruleID, section)
		warnings = append(warnings, w...)
	}

	// Check for very long action strings that might cause issues.
	if idx := strings.Index(line, `"`); idx >= 0 {
		// Find the actions portion (between first and last double quotes).
		lastIdx := strings.LastIndex(line, `"`)
		if lastIdx > idx {
			actions := line[idx+1 : lastIdx]
			if len(actions) > 4096 {
				warnings = append(warnings, RuleWarning{
					Line:    lineNum,
					RuleID:  ruleID,
					Level:   "warning",
					Message: fmt.Sprintf("[%s] very long action string (%d chars) in rule %s", section, len(actions), ruleID),
				})
			}
		}
	}

	return warnings
}

// checkQuoteBalance verifies that single quotes in the action string are balanced.
// Coraza's parseActions uses single quotes to delimit msg:'...', logdata:'...', etc.
// An unbalanced quote causes the parser to misinterpret commas as action separators,
// potentially creating malformed actions that stop file parsing.
func checkQuoteBalance(line string, lineNum int, ruleID, section string) []RuleWarning {
	// Extract the actions portion — everything between the outermost double quotes
	// after the variable and operator parts.
	actionsStr := extractActionsString(line)
	if actionsStr == "" {
		return nil
	}

	inQuotes := false
	for i := 0; i < len(actionsStr); i++ {
		c := actionsStr[i]
		// Skip escaped characters (same logic as Coraza's parseActions).
		if i > 0 && actionsStr[i-1] == '\\' {
			continue
		}
		if c == '\'' {
			inQuotes = !inQuotes
		}
	}

	if inQuotes {
		return []RuleWarning{{
			Line:    lineNum,
			RuleID:  ruleID,
			Level:   "error",
			Message: fmt.Sprintf("[%s] unbalanced single quotes in actions of rule %s — Coraza will misparse this and may stop loading subsequent rules", section, ruleID),
		}}
	}
	return nil
}

// checkSelfReference detects rules that contain ctl:ruleRemoveById pointing to
// their own rule ID. This causes Coraza to remove the rule during its own execution,
// which may have unpredictable effects.
func checkSelfReference(line string, lineNum int, ruleID, section string) []RuleWarning {
	pattern := "ctl:ruleRemoveById=" + ruleID
	if strings.Contains(line, pattern) {
		return []RuleWarning{{
			Line:    lineNum,
			RuleID:  ruleID,
			Level:   "error",
			Message: fmt.Sprintf("[%s] rule %s contains self-referencing ctl:ruleRemoveById=%s — this removes the rule during its own execution", section, ruleID, ruleID),
		}}
	}
	return nil
}

// checkMsgCommas warns about commas inside msg:'...' values. While Coraza's
// parseActions respects single-quoted values, this is a common source of issues
// and worth flagging for inspection.
func checkMsgCommas(line string, lineNum int, ruleID, section string) []RuleWarning {
	// Find msg:'...' content.
	msgIdx := strings.Index(line, "msg:'")
	if msgIdx < 0 {
		return nil
	}

	// Find the closing single quote (respecting backslash escapes).
	start := msgIdx + 5 // after "msg:'"
	for i := start; i < len(line); i++ {
		if line[i] == '\'' && (i == 0 || line[i-1] != '\\') {
			// Found closing quote. Check content for commas.
			msgContent := line[start:i]
			if strings.Contains(msgContent, ",") {
				return []RuleWarning{{
					Line:    lineNum,
					RuleID:  ruleID,
					Level:   "warning",
					Message: fmt.Sprintf("[%s] rule %s has commas inside msg:'...' value — safe per spec but verify Coraza handles it correctly: %q", section, ruleID, truncate(msgContent, 80)),
				}}
			}
			break
		}
	}
	return nil
}

// extractActionsString pulls the actions portion from a SecRule or SecAction line.
// For SecRule: the third double-quoted segment.
// For SecAction: the first double-quoted segment.
func extractActionsString(line string) string {
	if strings.HasPrefix(line, "SecAction") {
		// SecAction "actions"
		idx := strings.Index(line, `"`)
		if idx < 0 {
			return ""
		}
		lastIdx := strings.LastIndex(line, `"`)
		if lastIdx <= idx {
			return ""
		}
		return line[idx+1 : lastIdx]
	}

	// SecRule VARIABLE "operator" "actions"
	// Find the third double-quoted segment. We need to handle escaped quotes.
	segments := extractQuotedSegments(line)
	if len(segments) >= 3 {
		return segments[2]
	}
	// For chained sub-rules: SecRule VARIABLE "operator" "actions"
	if len(segments) >= 2 {
		return segments[1]
	}
	return ""
}

// extractQuotedSegments extracts all double-quoted segments from a line,
// handling escaped double quotes within segments.
func extractQuotedSegments(line string) []string {
	var segments []string
	inQuote := false
	var current strings.Builder

	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' && (i == 0 || line[i-1] != '\\') {
			if inQuote {
				segments = append(segments, current.String())
				current.Reset()
				inQuote = false
			} else {
				inQuote = true
			}
		} else if inQuote {
			current.WriteByte(c)
		}
	}
	return segments
}

// extractRuleIDs finds all rule IDs in the generated config text.
func extractRuleIDs(content string) ([]string, int) {
	matches := validateRuleIDRe.FindAllStringSubmatch(content, -1)
	ids := make([]string, 0, len(matches))
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			ids = append(ids, m[1])
		}
	}
	return ids, len(ids)
}

// truncate shortens a string to maxLen, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ─── Deploy-time Validation Logging ────────────────────────────────

// logValidationResult logs a summary of config validation for deploy diagnostics.
func logValidationResult(result ValidateResult) {
	log.Printf("[validate] generated %d rules across %d lines", result.TotalRules, result.TotalLines)
	if len(result.RuleIDs) > 0 {
		log.Printf("[validate] rule IDs: %s", strings.Join(result.RuleIDs, ", "))
	}
	for _, w := range result.Warnings {
		switch w.Level {
		case "error":
			log.Printf("[validate] ERROR line %d (rule %s): %s", w.Line, w.RuleID, w.Message)
		case "warning":
			log.Printf("[validate] WARNING line %d (rule %s): %s", w.Line, w.RuleID, w.Message)
		default:
			log.Printf("[validate] INFO line %d: %s", w.Line, w.Message)
		}
	}
	if result.Valid {
		log.Printf("[validate] config validation passed")
	} else {
		log.Printf("[validate] config validation FAILED — deploy may cause Coraza to stop loading rules")
	}
}

// ─── Self-Reference Prevention in Generator ────────────────────────

// validateGeneratedRuleIDs checks that skip_rule exclusions don't generate
// ctl:ruleRemoveById actions that reference the rule's own generated ID.
// This is called during generation to detect and fix the issue proactively.
func validateGeneratedRuleIDs(exclusions []RuleExclusion) []RuleWarning {
	var warnings []RuleWarning
	idGen := newRuleIDGen()

	for _, e := range filterExclusions(exclusions, true) {
		switch e.Type {
		case "allow", "block", "skip_rule":
			// These types consume one ID per condition group.
			if len(e.Conditions) == 0 {
				continue
			}

			groupOp := e.GroupOp
			if groupOp == "" {
				groupOp = "and"
			}

			// Count how many IDs this exclusion will consume.
			var conditions []Condition
			for _, c := range e.Conditions {
				if c.Field == "host" && c.Value == "*" {
					continue
				}
				conditions = append(conditions, c)
			}

			if len(conditions) == 0 {
				// Unconditional SecAction — one ID.
				nextID := idGen.next()
				if e.Type == "skip_rule" {
					w := checkSkipRuleSelfRef(e, nextID)
					warnings = append(warnings, w...)
				}
			} else if groupOp == "and" {
				// AND: one chained rule — one ID.
				nextID := idGen.next()
				if e.Type == "skip_rule" {
					w := checkSkipRuleSelfRef(e, nextID)
					warnings = append(warnings, w...)
				}
			} else {
				// OR: one rule per condition.
				for range conditions {
					nextID := idGen.next()
					if e.Type == "skip_rule" {
						w := checkSkipRuleSelfRef(e, nextID)
						warnings = append(warnings, w...)
					}
				}
			}
		case "honeypot":
			// Honeypot uses fixed ID 9100021, no self-ref risk.
		case "raw":
			// Raw rules have user-supplied IDs, skip.
		default:
			// Runtime exclusions.
			if len(e.Conditions) > 0 {
				idGen.next()
			} else {
				idGen.next()
			}
		}
	}

	return warnings
}

// checkSkipRuleSelfRef checks if a skip_rule exclusion's rule_id field
// contains the generated rule ID (which would create a self-reference).
func checkSkipRuleSelfRef(e RuleExclusion, generatedID string) []RuleWarning {
	if e.RuleID == "" {
		return nil
	}

	// Normalize and check each token.
	normalized := strings.ReplaceAll(e.RuleID, ",", " ")
	tokens := strings.Fields(normalized)
	for _, tok := range tokens {
		if tok == generatedID {
			return []RuleWarning{{
				Level:   "error",
				RuleID:  generatedID,
				Message: fmt.Sprintf("exclusion %q (ID: %s) has rule_id containing its own generated ID %s — this would create a self-referencing ctl:ruleRemoveById", e.Name, e.ID, generatedID),
			}}
		}
	}
	return nil
}
