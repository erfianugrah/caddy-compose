package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// detectionOnlyThreshold is the anomaly score threshold used in detection_only
// mode. Set high enough that no request will be blocked, so everything is
// logged but nothing is denied.
const detectionOnlyThreshold = 10000

// GenerateConfigs produces pre-crs.conf and post-crs.conf text from the
// current WAF config and enabled exclusions.
// Each call uses its own rule ID counter, making it safe for concurrent use.
func GenerateConfigs(cfg WAFConfig, exclusions []RuleExclusion) GenerateResponse {
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
		var quickActions, runtimeExcl, rawRules, honeypotRules []RuleExclusion
		for _, e := range preCRSExclusions {
			switch e.Type {
			case "allow", "block", "skip_rule":
				quickActions = append(quickActions, e)
			case "honeypot":
				honeypotRules = append(honeypotRules, e)
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

		if len(honeypotRules) > 0 {
			writeHoneypotRule(&b, honeypotRules)
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
	"honeypot":                     true,
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
	case "country":
		return "REQUEST_HEADERS:Cf-Ipcountry"
	case "cookie":
		// Cookie field value format: "CookieName:value" — extract the cookie name.
		if idx := strings.Index(c.Value, ":"); idx > 0 {
			return fmt.Sprintf("REQUEST_COOKIES:%s", c.Value[:idx])
		}
		return "REQUEST_COOKIES"
	case "body":
		return "REQUEST_BODY"
	case "args":
		// Args field value format: "ParamName:value" — extract the parameter name.
		if idx := strings.Index(c.Value, ":"); idx > 0 {
			return fmt.Sprintf("ARGS:%s", c.Value[:idx])
		}
		return "ARGS"
	case "uri_path":
		return "REQUEST_FILENAME"
	case "referer":
		return "REQUEST_HEADERS:Referer"
	case "response_header":
		// Response header value format: "Header-Name:value" — extract the header name.
		if idx := strings.Index(c.Value, ":"); idx > 0 {
			return fmt.Sprintf("RESPONSE_HEADERS:%s", c.Value[:idx])
		}
		return "RESPONSE_HEADERS"
	case "response_status":
		return "RESPONSE_STATUS"
	case "http_version":
		return "REQUEST_PROTOCOL"
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

// conditionValue extracts the value to match.
// For named fields (header, cookie, args, response_header), strips the "name:" prefix.
func conditionValue(c Condition) string {
	switch c.Field {
	case "header", "cookie", "args", "response_header":
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
	action := conditionAction(e)

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
			writeChainedRule(b, []Condition{c}, action, idGen)
		}
	}
}

// conditionAction returns the SecRule action string for an exclusion type.
// All policy actions include logdata:'%{MATCHED_VAR}' so the audit log
// captures what the condition actually matched (IP, path, hostname, etc.),
// giving events the same level of detail as CRS blocked/logged events.
func conditionAction(e RuleExclusion) string {
	switch e.Type {
	case "allow":
		// ctl:ruleEngine=Off disables the WAF for the entire transaction.
		// Bare "allow" only stops evaluation for the current phase, which
		// can let later-phase rules still fire. This is the canonical
		// ModSecurity/Coraza pattern for a full WAF bypass.
		return fmt.Sprintf("pass,t:none,log,msg:'Policy Allow: %s',logdata:'%%{MATCHED_VAR}',ctl:ruleEngine=Off", escapeSecRuleValue(e.Name))
	case "block":
		return fmt.Sprintf("deny,status:403,t:none,log,msg:'Policy Block: %s',logdata:'%%{MATCHED_VAR}'", escapeSecRuleValue(e.Name))
	case "skip_rule":
		escapedName := escapeSecRuleValue(e.Name)
		if e.RuleID != "" {
			return buildSkipRuleAction(e.RuleID, escapedName)
		}
		if e.RuleTag != "" {
			return fmt.Sprintf("pass,t:none,log,msg:'Policy Skip: %s',logdata:'%%{MATCHED_VAR}',ctl:ruleRemoveByTag=%s", escapedName, e.RuleTag)
		}
		return fmt.Sprintf("pass,t:none,log,msg:'Policy Skip: %s',logdata:'%%{MATCHED_VAR}'", escapedName)
	default:
		return "pass,t:none,log"
	}
}

// buildSkipRuleAction builds a SecRule action string that removes one or more
// rule IDs. Coraza's ctl:ruleRemoveById only accepts a single ID or a
// hyphenated range per action, so when the user specifies multiple IDs
// (space- or comma-separated) we emit a separate ctl action for each.
func buildSkipRuleAction(ruleIDField string, escapedName string) string {
	// Normalize: replace commas with spaces, then split on whitespace.
	normalized := strings.ReplaceAll(ruleIDField, ",", " ")
	tokens := strings.Fields(normalized)

	msgPart := fmt.Sprintf("msg:'Policy Skip: %s'", escapedName)
	logdataPart := "logdata:'%{MATCHED_VAR}'"

	if len(tokens) <= 1 {
		// Single ID or range.
		return fmt.Sprintf("pass,t:none,log,%s,%s,ctl:ruleRemoveById=%s", msgPart, logdataPart, strings.TrimSpace(ruleIDField))
	}

	// Multiple IDs/ranges — emit one ctl:ruleRemoveById per token.
	var parts []string
	parts = append(parts, "pass", "t:none", "log", msgPart, logdataPart)
	for _, tok := range tokens {
		parts = append(parts, fmt.Sprintf("ctl:ruleRemoveById=%s", tok))
	}
	return strings.Join(parts, ",")
}

// writeChainedRule writes a single SecRule (possibly chained) for a set of conditions.
// The first condition gets the rule ID and action; subsequent conditions are chained.
func writeChainedRule(b *strings.Builder, conditions []Condition, action string, idGen *ruleIDGen) {
	ruleID := idGen.next()

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

// writeHoneypotRule consolidates all honeypot exclusions into a single SecRule
// using @pm (Aho-Corasick substring match) on REQUEST_URI. Uses rule ID 9100021
// (within the 9100020-9100029 honeypot range) so the logparser classifies
// matches as honeypot events.
func writeHoneypotRule(b *strings.Builder, honeypots []RuleExclusion) {
	// Collect all paths from all honeypot exclusions.
	var allPaths []string
	var names []string
	for _, e := range honeypots {
		names = append(names, e.Name)
		for _, c := range e.Conditions {
			if c.Field != "path" {
				continue
			}
			// For "in" operator, value is space-separated paths.
			// For "eq", "contains", "begins_with", it's a single path.
			if c.Operator == "in" {
				for _, p := range strings.Fields(c.Value) {
					if p != "" {
						allPaths = append(allPaths, p)
					}
				}
			} else if c.Value != "" {
				allPaths = append(allPaths, c.Value)
			}
		}
	}

	if len(allPaths) == 0 {
		return
	}

	// Deduplicate paths while preserving order.
	seen := make(map[string]bool, len(allPaths))
	deduped := make([]string, 0, len(allPaths))
	for _, p := range allPaths {
		if !seen[p] {
			seen[p] = true
			deduped = append(deduped, p)
		}
	}

	b.WriteString("# --- Dynamic Honeypot Paths ---\n")
	b.WriteString("# Consolidated from Policy Engine honeypot groups:\n")
	for _, n := range names {
		b.WriteString(fmt.Sprintf("#   - %s\n", n))
	}
	b.WriteString(fmt.Sprintf("# Total paths: %d\n", len(deduped)))
	b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@pm %s\" \\\n", strings.Join(deduped, " ")))
	b.WriteString("    \"id:9100021,\\\n")
	b.WriteString("    phase:1,\\\n")
	b.WriteString("    deny,\\\n")
	b.WriteString("    status:403,\\\n")
	b.WriteString("    log,\\\n")
	b.WriteString("    msg:'Honeypot: dynamic path probe',\\\n")
	b.WriteString("    logdata:'%{REQUEST_URI}',\\\n")
	b.WriteString("    tag:'honeypot',\\\n")
	b.WriteString("    tag:'custom-rules',\\\n")
	b.WriteString("    severity:'CRITICAL'\"\n\n")
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

// ruleIDGen is a per-invocation counter for generating unique rule IDs
// in the 9500000+ range (reserved for local exclusions).
// Using a struct instead of a package-level variable prevents concurrent
// calls from producing duplicate IDs.
type ruleIDGen struct {
	counter int
}

func newRuleIDGen() *ruleIDGen {
	return &ruleIDGen{}
}

func (g *ruleIDGen) next() string {
	g.counter++
	return fmt.Sprintf("95%05d", g.counter)
}

// ResetRuleIDCounter is kept for backward compatibility in tests.
// It is now a no-op since rule IDs are generated per-invocation.
func ResetRuleIDCounter() {
	// no-op: rule IDs are now per-invocation via ruleIDGen
}

// ─── WAF Settings Generator ────────────────────────────────────────

// GenerateWAFSettings produces custom-waf-settings.conf content.
// This file is positioned between @crs-setup.conf.example and @owasp_crs/*.conf
// in the Caddyfile, so it overrides CRS defaults before CRS rules evaluate them.
//
// It generates:
//   - Default SecAction for paranoia level and anomaly thresholds
//   - Per-service SecRule SERVER_NAME overrides for custom settings
//   - Per-service ctl:ruleRemoveByTag for disabled rule groups
//   - Per-service ctl:ruleEngine=Off for disabled services
func GenerateWAFSettings(cfg WAFConfig) string {
	var b strings.Builder
	idGen := newSettingsIDGen()

	b.WriteString("# ============================================================\n")
	b.WriteString("# WAF Dynamic Settings\n")
	b.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("# Loaded AFTER @crs-setup.conf.example, BEFORE @owasp_crs/*.conf\n")
	b.WriteString("# ============================================================\n\n")

	// --- Defaults ---
	b.WriteString("# --- Global Defaults ---\n")
	b.WriteString("# Override CRS setup defaults. Applied to all services.\n")
	b.WriteString("# Per-service overrides below can further modify these values.\n\n")

	d := cfg.Defaults
	// For detection_only mode, thresholds are set high (log everything, block nothing).
	inT, outT := d.InboundThreshold, d.OutboundThreshold
	if d.Mode == "detection_only" {
		inT, outT = detectionOnlyThreshold, detectionOnlyThreshold
	}

	b.WriteString(fmt.Sprintf("SecAction \"id:%s,phase:1,pass,t:none,nolog,"+
		"setvar:tx.paranoia_level=%d,"+
		"setvar:tx.blocking_paranoia_level=%d,"+
		"setvar:tx.detection_paranoia_level=%d\"\n",
		idGen.next(), d.ParanoiaLevel, d.ParanoiaLevel, d.ParanoiaLevel))
	b.WriteString(fmt.Sprintf("SecAction \"id:%s,phase:1,pass,t:none,nolog,"+
		"setvar:tx.inbound_anomaly_score_threshold=%d,"+
		"setvar:tx.outbound_anomaly_score_threshold=%d\"\n\n",
		idGen.next(), inT, outT))

	// Emit SecRuleEngine directive based on the global mode.
	// This is a config-time directive (not per-request ctl), making the
	// generator the single source of truth for the WAF engine state.
	// The Caddyfile must NOT contain its own SecRuleEngine directive.
	switch d.Mode {
	case "disabled":
		b.WriteString("SecRuleEngine Off\n\n")
	case "detection_only":
		b.WriteString("SecRuleEngine DetectionOnly\n\n")
	default: // "enabled"
		b.WriteString("SecRuleEngine On\n\n")
	}

	// Default disabled groups.
	for _, tag := range d.DisabledGroups {
		b.WriteString(fmt.Sprintf("SecAction \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleRemoveByTag=%s\"\n",
			idGen.next(), tag))
	}
	if len(d.DisabledGroups) > 0 {
		b.WriteString("\n")
	}

	// --- Per-service overrides ---
	if len(cfg.Services) > 0 {
		b.WriteString("# --- Per-Service Overrides ---\n")
		b.WriteString("# Each rule matches SERVER_NAME for the specific service hostname.\n")
		b.WriteString("# Only fires within that service's coraza_waf instance.\n\n")

		// Sort for deterministic output.
		hosts := sortedKeys(cfg.Services)
		for _, host := range hosts {
			ss := cfg.Services[host]
			writeServiceOverride(&b, host, ss, d, idGen)
		}
	}

	return b.String()
}

// writeServiceOverride generates SecRule(s) for a single service override.
func writeServiceOverride(b *strings.Builder, host string, ss, defaults WAFServiceSettings, idGen *settingsIDGen) {
	escapedHost := escapeSecRuleValue(host)

	// If disabled, generate ctl:ruleEngine=Off (only if default is not already disabled).
	if ss.Mode == "disabled" && defaults.Mode != "disabled" {
		b.WriteString(fmt.Sprintf("# %s\n", host))
		b.WriteString(fmt.Sprintf("SecRule SERVER_NAME \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleEngine=Off\"\n\n",
			escapedHost, idGen.next()))
		return // No further overrides needed for disabled services.
	}

	// Determine if we need to change the rule engine mode for this service.
	// Possible transitions:
	//   default=disabled      + service=blocking       → ctl:ruleEngine=On
	//   default=disabled      + service=detection_only → ctl:ruleEngine=DetectionOnly
	//   default=detection_only + service=blocking      → ctl:ruleEngine=On
	//   default=blocking      + service=detection_only → ctl:ruleEngine=DetectionOnly
	var engineOverride string
	if ss.Mode != defaults.Mode {
		switch {
		case ss.Mode == "detection_only":
			engineOverride = "DetectionOnly"
		case defaults.Mode == "disabled" || defaults.Mode == "detection_only":
			// Service is "blocking" (the default/empty mode) but global is
			// disabled or detection_only — re-enable full blocking.
			engineOverride = "On"
		}
	}

	// For detection_only, override thresholds to log everything.
	inT, outT := ss.InboundThreshold, ss.OutboundThreshold
	if ss.Mode == "detection_only" {
		inT, outT = detectionOnlyThreshold, detectionOnlyThreshold
	}

	// Check if paranoia or thresholds differ from defaults.
	defInT, defOutT := defaults.InboundThreshold, defaults.OutboundThreshold
	if defaults.Mode == "detection_only" {
		defInT, defOutT = detectionOnlyThreshold, detectionOnlyThreshold
	}

	needsParanoiaOverride := ss.ParanoiaLevel != defaults.ParanoiaLevel
	needsThresholdOverride := inT != defInT || outT != defOutT

	// Disabled rule groups (unique to this service, not already in defaults).
	defaultDisabled := make(map[string]bool, len(defaults.DisabledGroups))
	for _, tag := range defaults.DisabledGroups {
		defaultDisabled[tag] = true
	}
	var extraGroups []string
	for _, tag := range ss.DisabledGroups {
		if !defaultDisabled[tag] {
			extraGroups = append(extraGroups, tag)
		}
	}

	// Skip this service entirely if it produces no output (identical to defaults).
	if engineOverride == "" && !needsParanoiaOverride && !needsThresholdOverride && len(extraGroups) == 0 {
		return
	}

	b.WriteString(fmt.Sprintf("# %s\n", host))

	// Emit engine override when the service mode differs from the global default.
	if engineOverride != "" {
		b.WriteString(fmt.Sprintf("SecRule SERVER_NAME \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleEngine=%s\"\n",
			escapedHost, idGen.next(), engineOverride))
	}

	if needsParanoiaOverride || needsThresholdOverride {
		var setvars []string
		if needsParanoiaOverride {
			setvars = append(setvars,
				fmt.Sprintf("setvar:tx.paranoia_level=%d", ss.ParanoiaLevel),
				fmt.Sprintf("setvar:tx.blocking_paranoia_level=%d", ss.ParanoiaLevel),
				fmt.Sprintf("setvar:tx.detection_paranoia_level=%d", ss.ParanoiaLevel),
			)
		}
		if needsThresholdOverride {
			setvars = append(setvars,
				fmt.Sprintf("setvar:tx.inbound_anomaly_score_threshold=%d", inT),
				fmt.Sprintf("setvar:tx.outbound_anomaly_score_threshold=%d", outT),
			)
		}
		b.WriteString(fmt.Sprintf("SecRule SERVER_NAME \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,%s\"\n",
			escapedHost, idGen.next(), strings.Join(setvars, ",")))
	}

	for _, tag := range extraGroups {
		b.WriteString(fmt.Sprintf("SecRule SERVER_NAME \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleRemoveByTag=%s\"\n",
			escapedHost, idGen.next(), tag))
	}

	b.WriteString("\n")
}

// sortedKeys returns map keys sorted alphabetically.
func sortedKeys(m map[string]WAFServiceSettings) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// settingsIDGen generates unique rule IDs in the 97xxxxx range
// for WAF settings overrides (separate from exclusion IDs in 95xxxxx).
type settingsIDGen struct {
	counter int
}

func newSettingsIDGen() *settingsIDGen {
	return &settingsIDGen{}
}

func (g *settingsIDGen) next() string {
	g.counter++
	return fmt.Sprintf("97%05d", g.counter)
}
