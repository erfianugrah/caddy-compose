package main

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// ─── Policy Engine Types ───────────────────────────────────────────
//
// These types mirror the caddy-policy-engine plugin's data model.
// wafctl generates a policy-rules.json file that the plugin reads
// and hot-reloads via mtime polling.

// PolicyRulesFile is the top-level JSON structure written to policy-rules.json.
type PolicyRulesFile struct {
	Rules     []PolicyRule `json:"rules"`
	Generated string       `json:"generated"`
	Version   int          `json:"version"`
}

// PolicyRule is a single policy rule as consumed by the Caddy plugin.
type PolicyRule struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Conditions []PolicyCondition `json:"conditions"`
	GroupOp    string            `json:"group_op"`
	Enabled    bool              `json:"enabled"`
	Priority   int               `json:"priority"`
}

// PolicyCondition represents a single match condition for the plugin.
type PolicyCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// policyEngineTypes are the exclusion types handled by the Caddy policy
// engine plugin instead of Coraza SecRules.
var policyEngineTypes = map[string]bool{
	"allow":    true,
	"block":    true,
	"honeypot": true,
}

// policyTypePriority assigns a base priority per exclusion type.
// Lower values evaluate first. Honeypot (traps) → Block (deny) → Allow (bypass).
// This ensures deny rules take precedence over allow rules.
var policyTypePriority = map[string]int{
	"honeypot": 100,
	"block":    200,
	"allow":    300,
}

// GeneratePolicyRules converts exclusions into the plugin's JSON format.
// Only allow/block/honeypot types are included. All other types remain
// in SecRule generation (generator.go).
//
// Priority is assigned by type (honeypot < block < allow), with the
// exclusion's store order as a stable tiebreaker within each type.
func GeneratePolicyRules(exclusions []RuleExclusion) ([]byte, error) {
	var rules []PolicyRule

	for i, e := range exclusions {
		if !policyEngineTypes[e.Type] {
			continue
		}

		conditions := make([]PolicyCondition, len(e.Conditions))
		for j, c := range e.Conditions {
			conditions[j] = PolicyCondition{
				Field:    c.Field,
				Operator: c.Operator,
				Value:    c.Value,
			}
		}

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
			Enabled:    e.Enabled,
			Priority:   basePriority + tiebreaker,
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

	// Use indented JSON for readability (hot-reloaded by plugin, not perf-critical).
	return json.MarshalIndent(file, "", "  ")
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

// splitHoneypotPaths extracts all path values from honeypot exclusion
// conditions, handling both single-value and space-separated "in" values.
// This is used for display/summary purposes.
func splitHoneypotPaths(conditions []Condition) []string {
	var paths []string
	for _, c := range conditions {
		if c.Field != "path" {
			continue
		}
		if c.Operator == "in" {
			for _, p := range strings.Fields(c.Value) {
				if p != "" {
					paths = append(paths, p)
				}
			}
		} else if c.Value != "" {
			paths = append(paths, c.Value)
		}
	}
	return paths
}
