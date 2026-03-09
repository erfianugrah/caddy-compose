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
	Tags       []string          `json:"tags,omitempty"`
	Enabled    bool              `json:"enabled"`
	Priority   int               `json:"priority"`
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
// Lower values evaluate first. Block (deny) → Allow (bypass).
// This ensures deny rules take precedence over allow rules.
var policyTypePriority = map[string]int{
	"block": 100,
	"allow": 200,
}

// GeneratePolicyRules converts exclusions into the plugin's JSON format.
// Only allow/block types are included. All other types remain
// in SecRule generation (generator.go).
//
// Priority is assigned by type (block < allow), with the
// exclusion's store order as a stable tiebreaker within each type.
//
// When listStore is non-nil, in_list/not_in_list conditions are resolved
// by looking up the list name (stored in the Value field) and populating
// ListItems and ListKind in the output. If a list is not found, the
// condition is written with an empty ListItems (no match).
func GeneratePolicyRules(exclusions []RuleExclusion, listStore *ManagedListStore) ([]byte, error) {
	var rules []PolicyRule

	for i, e := range exclusions {
		if !policyEngineTypes[e.Type] {
			continue
		}

		conditions := make([]PolicyCondition, len(e.Conditions))
		for j, c := range e.Conditions {
			pc := PolicyCondition{
				Field:    c.Field,
				Operator: c.Operator,
				Value:    c.Value,
			}
			// Resolve managed list references.
			if (c.Operator == "in_list" || c.Operator == "not_in_list") && listStore != nil {
				pc.ListItems, pc.ListKind = resolveListItems(listStore, c.Value)
			}
			conditions[j] = pc
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
			Tags:       e.Tags,
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
