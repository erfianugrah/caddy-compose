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
// This includes:
// - CRS setup variables (paranoia level, thresholds)
// - Runtime exclusions (ctl: actions that must be evaluated before CRS rules)
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

	// Runtime exclusions
	runtimeExclusions := filterExclusions(exclusions, true)
	if len(runtimeExclusions) > 0 {
		b.WriteString("# --- Runtime Exclusions ---\n")
		b.WriteString("# These use ctl: actions to conditionally remove rules at request time.\n\n")

		for _, e := range runtimeExclusions {
			b.WriteString(fmt.Sprintf("# %s\n", e.Name))
			if e.Description != "" {
				b.WriteString(fmt.Sprintf("# %s\n", e.Description))
			}
			if e.Service != "" {
				b.WriteString(fmt.Sprintf("# Service: %s\n", e.Service))
			}

			switch e.Type {
			case "runtime_remove_by_id":
				writeRuntimeRemoveByID(&b, e)
			case "runtime_remove_by_tag":
				writeRuntimeRemoveByTag(&b, e)
			case "runtime_remove_target_by_id":
				writeRuntimeRemoveTargetByID(&b, e)
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

// generatePostCRS builds the post-CRS configuration file.
// This includes:
// - Configure-time exclusions (SecRuleRemoveById, SecRuleUpdateTargetById, etc.)
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
			b.WriteString(fmt.Sprintf("# %s\n", e.Name))
			if e.Description != "" {
				b.WriteString(fmt.Sprintf("# %s\n", e.Description))
			}
			if e.Service != "" {
				b.WriteString(fmt.Sprintf("# Service: %s\n", e.Service))
			}

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

// filterExclusions splits exclusions into runtime (pre-CRS) and configure-time (post-CRS).
func filterExclusions(exclusions []RuleExclusion, runtime bool) []RuleExclusion {
	var result []RuleExclusion
	for _, e := range exclusions {
		isRuntime := strings.HasPrefix(e.Type, "runtime_")
		if isRuntime == runtime {
			result = append(result, e)
		}
	}
	return result
}

// writeRuntimeRemoveByID generates a SecRule that uses ctl:ruleRemoveById.
func writeRuntimeRemoveByID(b *strings.Builder, e RuleExclusion) {
	uri := escapeSecRuleValue(e.Condition)
	b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleRemoveById=%s\"\n",
		uri, generateRuleID(), e.RuleID))
}

// writeRuntimeRemoveByTag generates a SecRule that uses ctl:ruleRemoveByTag.
func writeRuntimeRemoveByTag(b *strings.Builder, e RuleExclusion) {
	uri := escapeSecRuleValue(e.Condition)
	b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleRemoveByTag=%s\"\n",
		uri, generateRuleID(), e.RuleTag))
}

// writeRuntimeRemoveTargetByID generates a SecRule that uses ctl:ruleRemoveTargetById.
func writeRuntimeRemoveTargetByID(b *strings.Builder, e RuleExclusion) {
	uri := escapeSecRuleValue(e.Condition)
	b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleRemoveTargetById=%s;%s\"\n",
		uri, generateRuleID(), e.RuleID, e.Variable))
}

// escapeSecRuleValue escapes special characters for SecRule patterns.
func escapeSecRuleValue(s string) string {
	// For @streq, the value is literal — no regex escaping needed.
	// Just ensure no double-quotes in the value.
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
