package main

import (
	"encoding/json"
	"log"
	"sort"
	"time"
)

// ─── Policy Engine Types ───────────────────────────────────────────
//
// These types mirror the caddy-policy-engine plugin's data model.
// wafctl generates a policy-rules.json file that the plugin reads
// and hot-reloads via mtime polling.

// PolicyRulesFile is the top-level JSON structure written to policy-rules.json.
type PolicyRulesFile struct {
	Rules           []PolicyRule                 `json:"rules"`
	RateLimitConfig *PolicyRateLimitGlobalConfig `json:"rate_limit_config,omitempty"`
	Generated       string                       `json:"generated"`
	Version         int                          `json:"version"`
}

// PolicyRule is a single policy rule as consumed by the Caddy plugin.
type PolicyRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Service    string                 `json:"service,omitempty"`
	Conditions []PolicyCondition      `json:"conditions"`
	GroupOp    string                 `json:"group_op"`
	RateLimit  *PolicyRateLimitConfig `json:"rate_limit,omitempty"`
	Tags       []string               `json:"tags,omitempty"`
	Enabled    bool                   `json:"enabled"`
	Priority   int                    `json:"priority"`
}

// PolicyRateLimitConfig holds per-rule rate limit parameters.
// Mirrors the caddy-policy-engine plugin's RateLimitConfig type.
type PolicyRateLimitConfig struct {
	Key    string `json:"key"`
	Events int    `json:"events"`
	Window string `json:"window"`
	Action string `json:"action,omitempty"`
}

// PolicyRateLimitGlobalConfig holds global rate limit settings.
// Mirrors the caddy-policy-engine plugin's RateLimitGlobalConfig type.
type PolicyRateLimitGlobalConfig struct {
	SweepInterval string  `json:"sweep_interval,omitempty"`
	Jitter        float64 `json:"jitter,omitempty"`
}

// PolicyCondition represents a single match condition for the plugin.
type PolicyCondition struct {
	Field     string   `json:"field"`
	Operator  string   `json:"operator"`
	Value     string   `json:"value"`
	ListItems []string `json:"list_items,omitempty"` // resolved by wafctl before writing
	ListKind  string   `json:"list_kind,omitempty"`  // "ip", "hostname", "string", "asn"
}

// policyEngineTypes are the exclusion types handled by the Caddy policy
// engine plugin instead of Coraza SecRules.
var policyEngineTypes = map[string]bool{
	"allow": true,
	"block": true,
}

// policyTypePriority assigns a base priority per exclusion type.
// Lower values evaluate first. Block (deny) → Allow (bypass) → Rate Limit.
// This ensures deny rules take precedence over allow rules, and both
// take precedence over rate limiting.
var policyTypePriority = map[string]int{
	"block":      100,
	"allow":      200,
	"rate_limit": 300,
}

// GeneratePolicyRules converts exclusions into the plugin's JSON format.
// Only allow/block types are included. All other types remain
// in SecRule generation (generator.go).
//
// This is a convenience wrapper around GeneratePolicyRulesWithRL with no
// rate limit rules. Use GeneratePolicyRulesWithRL when RL rules should
// also be included in the policy-rules.json output.
func GeneratePolicyRules(exclusions []RuleExclusion, listStore *ManagedListStore) ([]byte, error) {
	return GeneratePolicyRulesWithRL(exclusions, nil, RateLimitGlobalConfig{}, listStore)
}

// GeneratePolicyRulesWithRL converts exclusions and rate limit rules into
// the plugin's JSON format. WAF exclusions (allow/block) and rate limit
// rules are merged into a single rules array, sorted by priority.
//
// Priority bands: block=100-199, allow=200-299, rate_limit=300+.
// Within rate_limit, rules with explicit Priority use it directly (offset
// by 300); rules without explicit Priority get 300 + their store index.
//
// When rlRules is nil or empty, the output is identical to GeneratePolicyRules.
//
// The global RL config (sweep interval, jitter) is included in the output
// when any rate limit rules are present.
func GeneratePolicyRulesWithRL(exclusions []RuleExclusion, rlRules []RateLimitRule, rlGlobal RateLimitGlobalConfig, listStore *ManagedListStore) ([]byte, error) {
	var rules []PolicyRule

	// Convert WAF exclusions (allow/block).
	for i, e := range exclusions {
		if !policyEngineTypes[e.Type] {
			continue
		}

		conditions := convertConditions(e.Conditions, listStore)

		basePriority := policyTypePriority[e.Type]
		// Add store index as tiebreaker (0-99 range, capped).
		tiebreaker := i
		if tiebreaker > 99 {
			tiebreaker = 99
		}

		groupOp := e.GroupOp
		if groupOp == "" {
			groupOp = "and"
		}

		rules = append(rules, PolicyRule{
			ID:         e.ID,
			Name:       e.Name,
			Type:       e.Type,
			Conditions: conditions,
			GroupOp:    groupOp,
			Tags:       e.Tags,
			Enabled:    e.Enabled,
			Priority:   basePriority + tiebreaker,
		})
	}

	// Convert rate limit rules.
	for i, rl := range rlRules {
		conditions := convertConditions(rl.Conditions, listStore)

		// Determine priority: use explicit Priority if set, otherwise
		// use the RL base (300) + store index as tiebreaker.
		priority := policyTypePriority["rate_limit"]
		if rl.Priority > 0 {
			priority += rl.Priority
		} else {
			tiebreaker := i
			if tiebreaker > 99 {
				tiebreaker = 99
			}
			priority += tiebreaker
		}

		groupOp := rl.GroupOp
		if groupOp == "" {
			groupOp = "and"
		}

		action := rl.Action
		if action == "" {
			action = "deny"
		}

		rules = append(rules, PolicyRule{
			ID:         rl.ID,
			Name:       rl.Name,
			Type:       "rate_limit",
			Service:    rl.Service,
			Conditions: conditions,
			GroupOp:    groupOp,
			RateLimit: &PolicyRateLimitConfig{
				Key:    rl.Key,
				Events: rl.Events,
				Window: rl.Window,
				Action: action,
			},
			Tags:     rl.Tags,
			Enabled:  rl.Enabled,
			Priority: priority,
		})
	}

	// Sort by priority (lower first), then by ID for deterministic output.
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})

	file := PolicyRulesFile{
		Rules:     rules,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
	}

	// Include global RL config when rate limit rules are present.
	if len(rlRules) > 0 {
		file.RateLimitConfig = &PolicyRateLimitGlobalConfig{
			SweepInterval: rlGlobal.SweepInterval,
			Jitter:        rlGlobal.Jitter,
		}
	}

	// Use indented JSON for readability (hot-reloaded by plugin, not perf-critical).
	return json.MarshalIndent(file, "", "  ")
}

// convertConditions translates wafctl Conditions to PolicyConditions,
// resolving managed list references along the way.
func convertConditions(conditions []Condition, listStore *ManagedListStore) []PolicyCondition {
	result := make([]PolicyCondition, len(conditions))
	for j, c := range conditions {
		pc := PolicyCondition{
			Field:    c.Field,
			Operator: c.Operator,
			Value:    c.Value,
		}
		// Resolve managed list references.
		if (c.Operator == "in_list" || c.Operator == "not_in_list") && listStore != nil {
			pc.ListItems, pc.ListKind = resolveListItems(listStore, c.Value)
		}
		result[j] = pc
	}
	return result
}

// IsPolicyEngineType returns true if the exclusion type is handled by
// the Caddy policy engine plugin rather than Coraza SecRules.
func IsPolicyEngineType(typ string) bool {
	return policyEngineTypes[typ]
}

// FilterSecRuleExclusions returns only the exclusions that should generate
// SecRules (i.e., NOT handled by the policy engine plugin).
// When policyEngineEnabled is false, all exclusions are returned unchanged.
func FilterSecRuleExclusions(exclusions []RuleExclusion, policyEngineEnabled bool) []RuleExclusion {
	if !policyEngineEnabled {
		return exclusions
	}
	filtered := make([]RuleExclusion, 0, len(exclusions))
	for _, e := range exclusions {
		if !policyEngineTypes[e.Type] {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// resolveListItems looks up a managed list by name and returns its items and kind.
// Returns empty items if the list is not found (condition won't match anything).
func resolveListItems(ls *ManagedListStore, listName string) ([]string, string) {
	if ls == nil || listName == "" {
		return nil, ""
	}
	lists := ls.List()
	for _, l := range lists {
		if l.Name == listName {
			// Return a copy so mutations don't affect the store.
			items := make([]string, len(l.Items))
			copy(items, l.Items)
			return items, l.Kind
		}
	}
	log.Printf("[policy] warning: managed list %q not found, condition will not match", listName)
	return nil, ""
}
