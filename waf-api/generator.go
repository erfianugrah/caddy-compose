package main

import (
	"fmt"
	"strings"
	"time"
)

// GenerateConfigs produces pre-crs.conf and post-crs.conf text from the
// current WAF config and enabled exclusions.
func GenerateConfigs(cfg WAFConfig, exclusions []RuleExclusion) GenerateResponse {
	pre := generatePreCRS(cfg, exclusions)
	post := generatePostCRS(cfg, exclusions)
	return GenerateResponse{
		PreCRS:  pre,
		PostCRS: post,
	}
}

// generatePreCRS builds the pre-CRS configuration file.
func generatePreCRS(cfg WAFConfig, exclusions []RuleExclusion) string {
	var b strings.Builder

	b.WriteString("# ============================================================\n")
	b.WriteString("# WAF Pre-CRS Configuration\n")
	b.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("# This file is loaded BEFORE the CRS rules.\n")
	b.WriteString("# ============================================================\n\n")

	// CRS Setup Variables
	b.WriteString("# --- CRS Setup ---\n")
	b.WriteString(fmt.Sprintf("SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d\"\n", cfg.ParanoiaLevel))
	b.WriteString(fmt.Sprintf("SecAction \"id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=%d\"\n", cfg.ParanoiaLevel))
	b.WriteString(fmt.Sprintf("SecAction \"id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", cfg.InboundThreshold))
	b.WriteString(fmt.Sprintf("SecAction \"id:900111,phase:1,pass,t:none,nolog,setvar:tx.outbound_anomaly_score_threshold=%d\"\n", cfg.OutboundThreshold))
	b.WriteString(fmt.Sprintf("\nSecRuleEngine %s\n", cfg.RuleEngine))
	b.WriteString("\n")

	// Pre-CRS exclusions: quick actions, runtime ctl: rules, and raw rules.
	preCRSExclusions := filterExclusions(exclusions, true)
	if len(preCRSExclusions) > 0 {
		var quickActions, runtimeExcl, rawRules []RuleExclusion
		for _, e := range preCRSExclusions {
			switch e.Type {
			case "allow", "block", "skip_rule":
				quickActions = append(quickActions, e)
			case "raw":
				rawRules = append(rawRules, e)
			default:
				runtimeExcl = append(runtimeExcl, e)
			}
		}

		if len(quickActions) > 0 {
			b.WriteString("# --- Quick Actions ---\n")
			b.WriteString("# Allow/block/skip rules generated from the Policy Engine UI.\n\n")
			for _, e := range quickActions {
				writeExclusionComment(&b, e)
				writeConditionRule(&b, e)
				b.WriteString("\n")
			}
		}

		if len(runtimeExcl) > 0 {
			b.WriteString("# --- Runtime Exclusions ---\n")
			b.WriteString("# These use ctl: actions to conditionally remove rules at request time.\n\n")
			for _, e := range runtimeExcl {
				writeExclusionComment(&b, e)
				writeAdvancedRuntimeRule(&b, e)
				b.WriteString("\n")
			}
		}

		if len(rawRules) > 0 {
			b.WriteString("# --- Raw Rules ---\n")
			b.WriteString("# Custom SecRule directives from the raw editor.\n\n")
			for _, e := range rawRules {
				writeExclusionComment(&b, e)
				b.WriteString(e.RawRule)
				if !strings.HasSuffix(e.RawRule, "\n") {
					b.WriteString("\n")
				}
				b.WriteString("\n")
			}
		}
	}

	return b.String()
}

// generatePostCRS builds the post-CRS configuration file.
func generatePostCRS(_ WAFConfig, exclusions []RuleExclusion) string {
	var b strings.Builder

	b.WriteString("# ============================================================\n")
	b.WriteString("# WAF Post-CRS Configuration\n")
	b.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("# This file is loaded AFTER the CRS rules.\n")
	b.WriteString("# ============================================================\n\n")

	configTimeExclusions := filterExclusions(exclusions, false)
	if len(configTimeExclusions) > 0 {
		b.WriteString("# --- Configure-time Exclusions ---\n")
		b.WriteString("# These permanently remove or modify rules after CRS is loaded.\n\n")

		for _, e := range configTimeExclusions {
			writeExclusionComment(&b, e)

			switch e.Type {
			case "remove_by_id":
				b.WriteString(fmt.Sprintf("SecRuleRemoveById %s\n", e.RuleID))
			case "remove_by_tag":
				b.WriteString(fmt.Sprintf("SecRuleRemoveByTag \"%s\"\n", e.RuleTag))
			case "update_target_by_id":
				b.WriteString(fmt.Sprintf("SecRuleUpdateTargetById %s \"!%s\"\n", e.RuleID, e.Variable))
			case "update_target_by_tag":
				b.WriteString(fmt.Sprintf("SecRuleUpdateTargetByTag \"%s\" \"!%s\"\n", e.RuleTag, e.Variable))
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

// Pre-CRS types: runtime exclusions + quick actions + raw rules go before CRS.
var preCRSTypes = map[string]bool{
	"runtime_remove_by_id":        true,
	"runtime_remove_by_tag":       true,
	"runtime_remove_target_by_id": true,
	"allow":                       true,
	"block":                       true,
	"skip_rule":                   true,
	"raw":                         true,
}

// filterExclusions splits exclusions into pre-CRS and post-CRS (configure-time).
func filterExclusions(exclusions []RuleExclusion, preCRS bool) []RuleExclusion {
	var result []RuleExclusion
	for _, e := range exclusions {
		if preCRSTypes[e.Type] == preCRS {
			result = append(result, e)
		}
	}
	return result
}

// ─── Condition → SecRule mapping ────────────────────────────────────

// conditionVariable maps a condition field to its SecRule variable.
func conditionVariable(c Condition) string {
	switch c.Field {
	case "ip":
		return "REMOTE_ADDR"
	case "path":
		return "REQUEST_URI"
	case "host":
		return "SERVER_NAME"
	case "method":
		return "REQUEST_METHOD"
	case "user_agent":
		return "REQUEST_HEADERS:User-Agent"
	case "header":
		// Header field value format: "Header-Name:value" — extract the header name.
		if idx := strings.Index(c.Value, ":"); idx > 0 {
			return fmt.Sprintf("REQUEST_HEADERS:%s", c.Value[:idx])
		}
		return "REQUEST_HEADERS"
	case "query":
		return "QUERY_STRING"
	default:
		return "REQUEST_URI"
	}
}

// conditionOperator maps a condition operator to its SecRule operator string.
// Returns (operator_string, negate).
func conditionOperator(c Condition) (string, bool) {
	switch c.Operator {
	case "eq":
		return "@streq", false
	case "neq":
		return "@streq", true
	case "contains":
		return "@contains", false
	case "begins_with":
		return "@beginsWith", false
	case "ends_with":
		return "@endsWith", false
	case "regex":
		return "@rx", false
	case "ip_match":
		return "@ipMatch", false
	case "not_ip_match":
		return "@ipMatch", true
	case "in":
		return "@pm", false
	default:
		return "@streq", false
	}
}

// conditionValue extracts the value to match. For headers, strips the "name:" prefix.
func conditionValue(c Condition) string {
	if c.Field == "header" {
		if idx := strings.Index(c.Value, ":"); idx > 0 {
			return strings.TrimSpace(c.Value[idx+1:])
		}
	}
	return c.Value
}

// formatSecRuleOperator builds the full operator string like "@streq /path" or "!@ipMatch 1.2.3.4".
func formatSecRuleOperator(c Condition) string {
	op, negate := conditionOperator(c)
	val := escapeSecRuleValue(conditionValue(c))
	if negate {
		return fmt.Sprintf("\"!%s %s\"", op, val)
	}
	return fmt.Sprintf("\"%s %s\"", op, val)
}

// ─── Rule writers ───────────────────────────────────────────────────

// writeConditionRule generates SecRule(s) for allow/block/skip_rule exclusions
// based on the conditions array.
func writeConditionRule(b *strings.Builder, e RuleExclusion) {
	if len(e.Conditions) == 0 {
		return
	}

	groupOp := e.GroupOp
	if groupOp == "" {
		groupOp = "and"
	}

	// Determine the action string.
	action := conditionAction(e)

	if groupOp == "and" {
		// AND: chain all conditions into one rule.
		writeChainedRule(b, e.Conditions, action)
	} else {
		// OR: each condition gets its own standalone rule with the same action.
		for _, c := range e.Conditions {
			writeChainedRule(b, []Condition{c}, action)
		}
	}
}

// conditionAction returns the SecRule action string for an exclusion type.
func conditionAction(e RuleExclusion) string {
	switch e.Type {
	case "allow":
		return "allow,t:none,nolog"
	case "block":
		return fmt.Sprintf("deny,status:403,t:none,log,msg:'Blocked by policy: %s'", escapeSecRuleValue(e.Name))
	case "skip_rule":
		if e.RuleID != "" {
			return fmt.Sprintf("pass,t:none,nolog,ctl:ruleRemoveById=%s", e.RuleID)
		}
		if e.RuleTag != "" {
			return fmt.Sprintf("pass,t:none,nolog,ctl:ruleRemoveByTag=%s", e.RuleTag)
		}
		return "pass,t:none,nolog"
	default:
		return "pass,t:none,nolog"
	}
}

// writeChainedRule writes a single SecRule (possibly chained) for a set of conditions.
// The first condition gets the rule ID and action; subsequent conditions are chained.
func writeChainedRule(b *strings.Builder, conditions []Condition, action string) {
	ruleID := generateRuleID()

	for i, c := range conditions {
		variable := conditionVariable(c)
		operator := formatSecRuleOperator(c)

		if i == 0 {
			// First rule gets the ID and action.
			if len(conditions) > 1 {
				// Chain: first rule includes id + chain action.
				b.WriteString(fmt.Sprintf("SecRule %s %s \"id:%s,phase:1,%s,chain\"\n",
					variable, operator, ruleID, action))
			} else {
				// Single condition, no chain.
				b.WriteString(fmt.Sprintf("SecRule %s %s \"id:%s,phase:1,%s\"\n",
					variable, operator, ruleID, action))
			}
		} else if i < len(conditions)-1 {
			// Middle chained rules — no id, just chain.
			b.WriteString(fmt.Sprintf("  SecRule %s %s \"t:none,chain\"\n",
				variable, operator))
		} else {
			// Last chained rule — no chain keyword.
			b.WriteString(fmt.Sprintf("  SecRule %s %s \"t:none\"\n",
				variable, operator))
		}
	}
}

// writeAdvancedRuntimeRule generates a SecRule for advanced runtime exclusion types
// using conditions for path matching and ctl: actions.
func writeAdvancedRuntimeRule(b *strings.Builder, e RuleExclusion) {
	var ctlAction string
	switch e.Type {
	case "runtime_remove_by_id":
		ctlAction = fmt.Sprintf("ctl:ruleRemoveById=%s", e.RuleID)
	case "runtime_remove_by_tag":
		ctlAction = fmt.Sprintf("ctl:ruleRemoveByTag=%s", e.RuleTag)
	case "runtime_remove_target_by_id":
		ctlAction = fmt.Sprintf("ctl:ruleRemoveTargetById=%s;%s", e.RuleID, e.Variable)
	default:
		return
	}

	action := fmt.Sprintf("pass,t:none,nolog,%s", ctlAction)

	if len(e.Conditions) > 0 {
		writeChainedRule(b, e.Conditions, action)
	} else {
		// Fallback: unconditional (shouldn't happen with validation, but be safe).
		ruleID := generateRuleID()
		b.WriteString(fmt.Sprintf("SecAction \"id:%s,phase:1,%s\"\n", ruleID, action))
	}
}

// writeExclusionComment writes the standard comment block for an exclusion.
func writeExclusionComment(b *strings.Builder, e RuleExclusion) {
	b.WriteString(fmt.Sprintf("# %s\n", e.Name))
	if e.Description != "" {
		b.WriteString(fmt.Sprintf("# %s\n", e.Description))
	}
	// Summarize conditions in comments for readability.
	for _, c := range e.Conditions {
		b.WriteString(fmt.Sprintf("# Condition: %s %s %s\n", c.Field, c.Operator, c.Value))
	}
}

// escapeSecRuleValue escapes special characters for SecRule patterns.
func escapeSecRuleValue(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

// ruleIDCounter is a simple counter for generating unique rule IDs in the
// 9500000+ range (reserved for local exclusions).
var ruleIDCounter int

// generateRuleID produces a unique rule ID for generated SecRules.
func generateRuleID() string {
	ruleIDCounter++
	return fmt.Sprintf("95%05d", ruleIDCounter)
}

// ResetRuleIDCounter resets the counter (useful for deterministic tests).
func ResetRuleIDCounter() {
	ruleIDCounter = 0
}
