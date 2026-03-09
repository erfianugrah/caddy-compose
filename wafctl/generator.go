package main

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// GenerateConfigs produces pre-crs.conf and post-crs.conf text from the
// current WAF config and enabled exclusions.
// Each call uses its own rule ID counter, making it safe for concurrent use.
//
// When listStore is non-nil, in_list/not_in_list conditions are resolved
// by expanding managed list items inline. For IP lists this uses @ipMatch;
// for string/hostname lists this uses @pm (known substring limitation for Coraza).
func GenerateConfigs(cfg WAFConfig, exclusions []RuleExclusion, listStore *ManagedListStore) GenerateResponse {
	// Pre-resolve in_list/not_in_list conditions for SecRule generation.
	if listStore != nil {
		resolved := make([]RuleExclusion, len(exclusions))
		copy(resolved, exclusions)
		for i := range resolved {
			resolved[i].Conditions = resolveSecRuleListConditions(resolved[i].Conditions, listStore)
		}
		exclusions = resolved
	}
	idGen := newRuleIDGen()
	pre := generatePreCRS(cfg, exclusions, idGen)
	post := generatePostCRS(cfg, exclusions)
	return GenerateResponse{
		PreCRS:  pre,
		PostCRS: post,
	}
}

// generatePreCRS builds the pre-CRS configuration file.
func generatePreCRS(cfg WAFConfig, exclusions []RuleExclusion, idGen *ruleIDGen) string {
	var b strings.Builder

	b.WriteString("# ============================================================\n")
	b.WriteString("# WAF Pre-CRS Configuration\n")
	b.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("# This file is loaded BEFORE the CRS rules.\n")
	b.WriteString("# ============================================================\n\n")

	// CRS setup (paranoia level, thresholds) is generated separately via
	// GenerateWAFSettings() → custom-waf-settings.conf, positioned between
	// @crs-setup.conf.example and @owasp_crs/*.conf in the Caddyfile.

	// Pre-CRS exclusions: quick actions, runtime ctl: rules, and raw rules.
	preCRSExclusions := filterExclusions(exclusions, true)
	if len(preCRSExclusions) > 0 {
		var quickActions, runtimeExcl, rawRules []RuleExclusion
		for _, e := range preCRSExclusions {
			switch e.Type {
			case "allow", "block", "skip_rule", "anomaly":
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
				writeConditionRule(&b, e, idGen)
				b.WriteString("\n")
			}
		}

		if len(runtimeExcl) > 0 {
			b.WriteString("# --- Runtime Exclusions ---\n")
			b.WriteString("# These use ctl: actions to conditionally remove rules at request time.\n\n")
			for _, e := range runtimeExcl {
				writeExclusionComment(&b, e)
				writeAdvancedRuntimeRule(&b, e, idGen)
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
				b.WriteString(fmt.Sprintf("SecRuleUpdateTargetById %s \"!%s\"\n", e.RuleID, strings.TrimPrefix(e.Variable, "!")))
			case "update_target_by_tag":
				b.WriteString(fmt.Sprintf("SecRuleUpdateTargetByTag \"%s\" \"!%s\"\n", e.RuleTag, strings.TrimPrefix(e.Variable, "!")))
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

// Pre-CRS types: runtime exclusions + quick actions + raw rules go before CRS.
var preCRSTypes = map[string]bool{
	"runtime_remove_by_id":         true,
	"runtime_remove_by_tag":        true,
	"runtime_remove_target_by_id":  true,
	"runtime_remove_target_by_tag": true,
	"allow":                        true,
	"block":                        true,
	"skip_rule":                    true,
	"anomaly":                      true,
	"raw":                          true,
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

// ─── Rule writers ───────────────────────────────────────────────────

// writeConditionRule generates SecRule(s) for allow/block/skip_rule exclusions
// based on the conditions array.
func writeConditionRule(b *strings.Builder, e RuleExclusion, idGen *ruleIDGen) {
	if len(e.Conditions) == 0 {
		return
	}

	// Filter out "all services" wildcard conditions (host == "*").
	// These mean "apply globally" — no host restriction needed.
	var conditions []Condition
	for _, c := range e.Conditions {
		if c.Field == "host" && c.Value == "*" {
			continue
		}
		conditions = append(conditions, c)
	}

	groupOp := e.GroupOp
	if groupOp == "" {
		groupOp = "and"
	}

	// Determine the action string.
	// Peek at the next generated ID so we can filter out self-references
	// in skip_rule exclusions (prevents ctl:ruleRemoveById=<own_id>).
	action := conditionAction(e, idGen.peek())

	if len(conditions) == 0 {
		// All conditions were wildcards — emit a SecAction (unconditional).
		ruleID := idGen.next()
		b.WriteString(fmt.Sprintf("SecAction \"id:%s,phase:1,%s\"\n", ruleID, action))
		return
	}

	if groupOp == "and" {
		// AND: chain all conditions into one rule.
		writeChainedRule(b, conditions, action, idGen)
	} else {
		// OR: each condition gets its own standalone rule with the same action.
		for _, c := range conditions {
			// For OR groups, each condition gets its own ID.
			// Re-compute action with the next ID to filter self-refs correctly.
			action = conditionAction(e, idGen.peek())
			writeChainedRule(b, []Condition{c}, action, idGen)
		}
	}
}

// conditionAction returns the SecRule action string for an exclusion type.
// selfID is the generated rule ID for this exclusion, used to filter out
// self-referencing ctl:ruleRemoveById actions in skip_rule exclusions.
// All policy actions include logdata:'%{MATCHED_VAR}' so the audit log
// captures what the condition actually matched (IP, path, hostname, etc.),
// giving events the same level of detail as CRS blocked/logged events.
func conditionAction(e RuleExclusion, selfID string) string {
	var base string
	switch e.Type {
	case "allow":
		// ctl:ruleEngine=Off disables the WAF for the entire transaction.
		// Bare "allow" only stops evaluation for the current phase, which
		// can let later-phase rules still fire. This is the canonical
		// ModSecurity/Coraza pattern for a full WAF bypass.
		base = fmt.Sprintf("pass,t:none,log,msg:'Policy Allow: %s',logdata:'%%{MATCHED_VAR}',ctl:ruleEngine=Off", escapeSecRuleMsgValue(e.Name))
	case "block":
		base = fmt.Sprintf("deny,status:403,t:none,log,msg:'Policy Block: %s',logdata:'%%{MATCHED_VAR}'", escapeSecRuleMsgValue(e.Name))
	case "anomaly":
		pl := e.AnomalyParanoiaLevel
		if pl < 1 || pl > 4 {
			pl = 1
		}
		base = fmt.Sprintf("pass,t:none,log,msg:'Policy Anomaly: %s',logdata:'%%{MATCHED_VAR}',setvar:'tx.anomaly_score_pl%d=+%d'",
			escapeSecRuleMsgValue(e.Name), pl, e.AnomalyScore)
	case "skip_rule":
		escapedName := escapeSecRuleMsgValue(e.Name)
		if e.RuleID != "" {
			base = buildSkipRuleAction(e.RuleID, escapedName, selfID)
		} else if e.RuleTag != "" {
			base = fmt.Sprintf("pass,t:none,log,msg:'Policy Skip: %s',logdata:'%%{MATCHED_VAR}',ctl:ruleRemoveByTag=%s", escapedName, e.RuleTag)
		} else {
			base = fmt.Sprintf("pass,t:none,log,msg:'Policy Skip: %s',logdata:'%%{MATCHED_VAR}'", escapedName)
		}
	default:
		base = "pass,t:none,log"
	}

	// Append policy tags so they appear in the audit log's matched_rules[].tags.
	// Convention: prefix with "policy:" to distinguish from CRS tags.
	base += formatPolicyTags(e.Tags)
	return base
}

// formatPolicyTags returns SecRule tag actions for the given tags.
// Each tag is emitted as tag:'policy:<tag>'. Returns empty string if no tags.
func formatPolicyTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	var b strings.Builder
	for _, tag := range tags {
		b.WriteString(",tag:'policy:")
		b.WriteString(escapeSecRuleValue(tag))
		b.WriteString("'")
	}
	return b.String()
}

// buildSkipRuleAction builds a SecRule action string that removes one or more
// rule IDs. Coraza's ctl:ruleRemoveById only accepts a single ID or a
// hyphenated range per action, so when the user specifies multiple IDs
// (space- or comma-separated) we emit a separate ctl action for each.
// selfID is the generated ID of the containing rule — any matching token
// is silently filtered out to prevent self-referencing ctl:ruleRemoveById.
func buildSkipRuleAction(ruleIDField string, escapedName string, selfID string) string {
	// Normalize: replace commas with spaces, then split on whitespace.
	normalized := strings.ReplaceAll(ruleIDField, ",", " ")
	tokens := strings.Fields(normalized)

	// Filter out self-referencing IDs.
	var filtered []string
	for _, tok := range tokens {
		if tok == selfID {
			log.Printf("[generator] WARNING: skip_rule %q tried to remove its own generated ID %s — filtering out", escapedName, selfID)
			continue
		}
		filtered = append(filtered, tok)
	}
	tokens = filtered

	msgPart := fmt.Sprintf("msg:'Policy Skip: %s'", escapedName)
	logdataPart := "logdata:'%{MATCHED_VAR}'"

	if len(tokens) == 0 {
		// All tokens were self-references — emit pass with no ctl action.
		return fmt.Sprintf("pass,t:none,log,%s,%s", msgPart, logdataPart)
	}

	if len(tokens) <= 1 {
		// Single ID or range.
		return fmt.Sprintf("pass,t:none,log,%s,%s,ctl:ruleRemoveById=%s", msgPart, logdataPart, tokens[0])
	}

	// Multiple IDs/ranges — emit one ctl:ruleRemoveById per token.
	var parts []string
	parts = append(parts, "pass", "t:none", "log", msgPart, logdataPart)
	for _, tok := range tokens {
		parts = append(parts, fmt.Sprintf("ctl:ruleRemoveById=%s", tok))
	}
	return strings.Join(parts, ",")
}

// splitCTLActions splits a SecRule action string into non-ctl parts and ctl parts.
// Coraza requires ctl: actions on the LAST rule of a chain to fire reliably.
// Returns (nonCTL, ctlParts). If no ctl: actions exist, ctlParts is empty.
func splitCTLActions(action string) (string, []string) {
	parts := strings.Split(action, ",")
	var nonCTL, ctlParts []string
	for _, p := range parts {
		if strings.HasPrefix(strings.TrimSpace(p), "ctl:") {
			ctlParts = append(ctlParts, strings.TrimSpace(p))
		} else {
			nonCTL = append(nonCTL, p)
		}
	}
	return strings.Join(nonCTL, ","), ctlParts
}

// writeChainedRule writes a single SecRule (possibly chained) for a set of conditions.
// For chains with ctl: actions, the ctl: parts are moved to the LAST rule in the
// chain — Coraza ignores ctl: actions on the first rule of a chain.
func writeChainedRule(b *strings.Builder, conditions []Condition, action string, idGen *ruleIDGen) {
	ruleID := idGen.next()

	if len(conditions) == 1 {
		// Single condition, no chain needed.
		variable := conditionVariable(conditions[0])
		operator := formatSecRuleOperator(conditions[0])
		b.WriteString(fmt.Sprintf("SecRule %s %s \"id:%s,phase:1,%s\"\n",
			variable, operator, ruleID, action))
		return
	}

	// Multi-condition chain: split ctl: actions to last rule.
	firstAction, ctlParts := splitCTLActions(action)

	for i, c := range conditions {
		variable := conditionVariable(c)
		operator := formatSecRuleOperator(c)

		if i == 0 {
			// First rule: id + non-ctl action + chain.
			b.WriteString(fmt.Sprintf("SecRule %s %s \"id:%s,phase:1,%s,chain\"\n",
				variable, operator, ruleID, firstAction))
		} else if i < len(conditions)-1 {
			// Middle chained rules — just chain.
			b.WriteString(fmt.Sprintf("  SecRule %s %s \"t:none,chain\"\n",
				variable, operator))
		} else {
			// Last chained rule — gets ctl: actions.
			if len(ctlParts) > 0 {
				b.WriteString(fmt.Sprintf("  SecRule %s %s \"t:none,%s\"\n",
					variable, operator, strings.Join(ctlParts, ",")))
			} else {
				b.WriteString(fmt.Sprintf("  SecRule %s %s \"t:none\"\n",
					variable, operator))
			}
		}
	}
}

// writeAdvancedRuntimeRule generates a SecRule for advanced runtime exclusion types
// using conditions for path matching and ctl: actions.
func writeAdvancedRuntimeRule(b *strings.Builder, e RuleExclusion, idGen *ruleIDGen) {
	var ctlAction string
	switch e.Type {
	case "runtime_remove_by_id":
		ctlAction = fmt.Sprintf("ctl:ruleRemoveById=%s", e.RuleID)
	case "runtime_remove_by_tag":
		ctlAction = fmt.Sprintf("ctl:ruleRemoveByTag=%s", e.RuleTag)
	case "runtime_remove_target_by_id":
		ctlAction = fmt.Sprintf("ctl:ruleRemoveTargetById=%s;%s", e.RuleID, strings.TrimPrefix(e.Variable, "!"))
	case "runtime_remove_target_by_tag":
		ctlAction = fmt.Sprintf("ctl:ruleRemoveTargetByTag=%s;%s", e.RuleTag, strings.TrimPrefix(e.Variable, "!"))
	default:
		return
	}

	action := fmt.Sprintf("pass,t:none,nolog,%s", ctlAction)

	// Filter out "all services" wildcard conditions.
	var conditions []Condition
	for _, c := range e.Conditions {
		if c.Field == "host" && c.Value == "*" {
			continue
		}
		conditions = append(conditions, c)
	}

	if len(conditions) > 0 {
		writeChainedRule(b, conditions, action, idGen)
	} else {
		// Unconditional — either no conditions or all were wildcards.
		ruleID := idGen.next()
		b.WriteString(fmt.Sprintf("SecAction \"id:%s,phase:1,%s\"\n", ruleID, action))
	}
}

// writeExclusionComment writes the standard comment block for an exclusion.
func writeExclusionComment(b *strings.Builder, e RuleExclusion) {
	b.WriteString(fmt.Sprintf("# %s\n", sanitizeComment(e.Name)))
	if e.Description != "" {
		b.WriteString(fmt.Sprintf("# %s\n", sanitizeComment(e.Description)))
	}
	// Summarize conditions in comments for readability.
	for _, c := range e.Conditions {
		b.WriteString(fmt.Sprintf("# Condition: %s %s %s\n", c.Field, c.Operator, sanitizeComment(c.Value)))
	}
}
