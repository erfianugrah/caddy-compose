package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ─── CRS → Policy Engine Converter ─────────────────────────────────
//
// Converts parsed SecRule AST nodes into PolicyRule JSON structures
// for the caddy-policy-engine plugin.

// Converter holds state for the conversion process.
type Converter struct {
	dataFiles *DataFileResolver
	report    *Report
}

// NewConverter creates a converter with the given data file resolver.
func NewConverter(dataFiles *DataFileResolver) *Converter {
	return &Converter{
		dataFiles: dataFiles,
		report:    NewReport(),
	}
}

// Convert processes a set of parsed SecRules from a single .conf file
// and returns the converted PolicyRules.
func (c *Converter) Convert(rules []SecRule, filename string) []PolicyRule {
	category := categoryFromFilename(filename)
	var result []PolicyRule

	for _, rule := range rules {
		if c.shouldSkip(rule, filename) {
			continue
		}

		pr, err := c.convertRule(rule, category, filename)
		if err != nil {
			c.report.SkippedOther = append(c.report.SkippedOther, SkippedRule{
				ID:     rule.ID,
				Reason: err.Error(),
				File:   filename,
			})
			c.report.SkippedRules++
			c.addCategoryStat(category, false)
			continue
		}

		result = append(result, *pr)
		c.report.ConvertedRules++
		c.addCategoryStat(category, true)
	}

	return result
}

// ─── Skip logic ────────────────────────────────────────────────────

// skipRuleRanges defines CRS rule ID ranges to skip (flow control, not detection).
var skipRuleRanges = [][2]int{
	{901000, 901999}, // Initialization
	{905000, 905999}, // Common exceptions
	{949000, 949999}, // Blocking evaluation (inbound)
	{959000, 959999}, // Blocking evaluation (outbound)
	{980000, 980999}, // Correlation / logging
	{999000, 999999}, // User exceptions placeholder
}

// paranoia gating pattern: TX:DETECTION_PARANOIA_LEVEL @lt N + skipAfter
var paranoiaGateRe = regexp.MustCompile(`^9\d{2}01[12]$`)

func (c *Converter) shouldSkip(rule SecRule, filename string) bool {
	c.report.TotalRules++

	// Skip rules with no ID (shouldn't happen in valid CRS)
	if rule.ID == "" {
		c.report.SkippedFlowControl = append(c.report.SkippedFlowControl, SkippedRule{
			ID: "(no id)", Reason: "no rule ID", File: filename,
		})
		c.report.SkippedRules++
		return true
	}

	// Skip SecAction (no variables)
	if len(rule.Variables) == 0 && rule.Operator.Name == "" {
		c.report.SkippedFlowControl = append(c.report.SkippedFlowControl, SkippedRule{
			ID: rule.ID, Reason: "SecAction (no variables)", File: filename,
		})
		c.report.SkippedRules++
		c.addCategoryStat(categoryFromFilename(filename), false)
		return true
	}

	// Skip by rule ID range
	ruleNum, err := strconv.Atoi(rule.ID)
	if err == nil {
		for _, r := range skipRuleRanges {
			if ruleNum >= r[0] && ruleNum <= r[1] {
				c.report.SkippedFlowControl = append(c.report.SkippedFlowControl, SkippedRule{
					ID: rule.ID, Reason: fmt.Sprintf("flow control range %d-%d", r[0], r[1]), File: filename,
				})
				c.report.SkippedRules++
				c.addCategoryStat(categoryFromFilename(filename), false)
				return true
			}
		}
	}

	// Skip paranoia gating rules (e.g., 932011, 932012)
	if paranoiaGateRe.MatchString(rule.ID) {
		c.report.SkippedFlowControl = append(c.report.SkippedFlowControl, SkippedRule{
			ID: rule.ID, Reason: "paranoia gating rule", File: filename,
		})
		c.report.SkippedRules++
		c.addCategoryStat(categoryFromFilename(filename), false)
		return true
	}

	// Skip rules with skipAfter (paranoia level transitions)
	if hasAction(rule.Actions, "skipAfter") {
		c.report.SkippedFlowControl = append(c.report.SkippedFlowControl, SkippedRule{
			ID: rule.ID, Reason: "skipAfter action (paranoia gating)", File: filename,
		})
		c.report.SkippedRules++
		c.addCategoryStat(categoryFromFilename(filename), false)
		return true
	}

	// Skip response-phase rules (phase 3 or 4)
	if rule.Phase == 3 || rule.Phase == 4 {
		c.report.SkippedResponsePhase = append(c.report.SkippedResponsePhase, SkippedRule{
			ID: rule.ID, Reason: fmt.Sprintf("response phase %d", rule.Phase), File: filename,
		})
		c.report.SkippedRules++
		c.addCategoryStat(categoryFromFilename(filename), false)
		return true
	}

	// Skip rules that only do setvar (no detection operator)
	if rule.Operator.Name == "" || rule.Operator.Name == "unconditionalMatch" {
		c.report.SkippedFlowControl = append(c.report.SkippedFlowControl, SkippedRule{
			ID: rule.ID, Reason: "no detection operator", File: filename,
		})
		c.report.SkippedRules++
		c.addCategoryStat(categoryFromFilename(filename), false)
		return true
	}

	// Skip rules that only check TX variables (internal CRS state)
	if allVariablesAreTX(rule.Variables) {
		c.report.SkippedFlowControl = append(c.report.SkippedFlowControl, SkippedRule{
			ID: rule.ID, Reason: "TX-only variables (internal state)", File: filename,
		})
		c.report.SkippedRules++
		c.addCategoryStat(categoryFromFilename(filename), false)
		return true
	}

	// Skip data-extraction helper rules (pass + nolog, no msg/severity).
	// These only capture/setvar for downstream rules — they don't detect anything.
	// Example: 922140 (counter init), 922150 (multipart header extraction).
	if hasAction(rule.Actions, "pass") && hasAction(rule.Actions, "nolog") &&
		!hasAction(rule.Actions, "block") && !hasAction(rule.Actions, "deny") {
		msg := actionValue(rule.Actions, "msg")
		sev := actionValue(rule.Actions, "severity")
		if msg == "" && sev == "" {
			c.report.SkippedFlowControl = append(c.report.SkippedFlowControl, SkippedRule{
				ID: rule.ID, Reason: "data-extraction helper (pass+nolog, no msg/severity)", File: filename,
			})
			c.report.SkippedRules++
			c.addCategoryStat(categoryFromFilename(filename), false)
			return true
		}
	}

	return false
}

func allVariablesAreTX(vars []Variable) bool {
	for _, v := range vars {
		if v.IsNegation {
			continue
		}
		if v.Name != "TX" {
			return false
		}
	}
	return true
}

// ─── Conversion ────────────────────────────────────────────────────

func (c *Converter) convertRule(rule SecRule, category, filename string) (*PolicyRule, error) {
	// Map operator
	opName, supported, note := mapOperator(rule.Operator)
	if !supported {
		c.report.MissingOperators[rule.Operator.Name]++
		return nil, fmt.Errorf("unsupported operator @%s: %s", rule.Operator.Name, note)
	}

	// Map transforms
	transforms, missingTransforms := mapTransforms(rule.Transforms)
	for _, t := range missingTransforms {
		c.report.MissingTransforms[t]++
	}

	// Map variables → fields
	fields, _, varIssues := mapVariablesToConditions(rule.Variables, rule.Operator)
	for _, issue := range varIssues {
		if strings.HasPrefix(issue, "unknown variable") {
			varName := strings.TrimPrefix(issue, "unknown variable ")
			c.report.MissingVariables[varName]++
		}
	}

	if len(fields) == 0 {
		return nil, fmt.Errorf("no mappable variables")
	}

	// Consolidate fields
	field := consolidateFields(fields)

	// Resolve operator value
	operatorValue := rule.Operator.Value
	var listItems []string

	switch rule.Operator.Name {
	case "pmFromFile", "pmFromDataset":
		// Resolve data file contents
		if c.dataFiles != nil {
			items, err := c.dataFiles.Resolve(rule.Operator.Value)
			if err != nil {
				return nil, fmt.Errorf("resolving data file %s: %w", rule.Operator.Value, err)
			}
			listItems = items
			operatorValue = "" // value is in list_items
		}
	case "pm":
		// Split space-separated phrases into list_items
		listItems = splitPMPatterns(rule.Operator.Value)
		operatorValue = ""
	case "rx":
		// Validate regex against RE2
		fixed, err := ValidateRE2(rule.Operator.Value)
		if err != nil {
			c.report.SkippedPCRERegex = append(c.report.SkippedPCRERegex, SkippedRule{
				ID: rule.ID, Reason: err.Error(), File: filename,
			})
			return nil, fmt.Errorf("PCRE regex: %w", err)
		}
		operatorValue = fixed
	}

	// Build condition
	cond := PolicyCondition{
		Field:      field,
		Operator:   opName,
		Value:      operatorValue,
		Negate:     rule.Operator.Negated,
		MultiMatch: hasAction(rule.Actions, "multiMatch"),
		Transforms: transforms,
		ListItems:  listItems,
	}

	// Handle chains → multi-condition AND rule
	conditions := []PolicyCondition{cond}
	if rule.Chain != nil {
		chainConds, err := c.convertChain(rule.Chain, filename)
		if err != nil {
			return nil, fmt.Errorf("chain conversion: %w", err)
		}
		conditions = append(conditions, chainConds...)
	}

	// Map severity
	severity := mapSeverity(rule.Severity)

	// Map tags
	tags := mapCRSTags(rule.Tags)

	// Build the policy rule
	pr := &PolicyRule{
		ID:            rule.ID,
		Name:          rule.Msg,
		Type:          "detect",
		Conditions:    conditions,
		GroupOp:       "and",
		Severity:      severity,
		ParanoiaLevel: rule.ParanoiaLevel,
		Tags:          tags,
		Enabled:       true,
		Priority:      400, // detect rules base priority
		Description:   rule.Msg,
		Category:      category,
		CRSFile:       filepath.Base(filename),
	}

	return pr, nil
}

// convertChain recursively converts chained rules into conditions.
func (c *Converter) convertChain(rule *SecRule, filename string) ([]PolicyCondition, error) {
	// Map operator
	opName, supported, note := mapOperator(rule.Operator)
	if !supported {
		return nil, fmt.Errorf("chain: unsupported operator @%s: %s", rule.Operator.Name, note)
	}

	// Map transforms
	transforms, _ := mapTransforms(rule.Transforms)

	// Map variables
	fields, _, _ := mapVariablesToConditions(rule.Variables, rule.Operator)
	if len(fields) == 0 {
		return nil, fmt.Errorf("chain: no mappable variables")
	}
	field := consolidateFields(fields)

	// Resolve operator
	operatorValue := rule.Operator.Value
	var listItems []string

	switch rule.Operator.Name {
	case "pmFromFile", "pmFromDataset":
		if c.dataFiles != nil {
			items, err := c.dataFiles.Resolve(rule.Operator.Value)
			if err != nil {
				return nil, fmt.Errorf("chain: resolving data file %s: %w", rule.Operator.Value, err)
			}
			listItems = items
			operatorValue = ""
		}
	case "pm":
		listItems = splitPMPatterns(rule.Operator.Value)
		operatorValue = ""
	case "rx":
		fixed, err := ValidateRE2(rule.Operator.Value)
		if err != nil {
			return nil, fmt.Errorf("chain: PCRE regex: %w", err)
		}
		operatorValue = fixed
	}

	cond := PolicyCondition{
		Field:      field,
		Operator:   opName,
		Value:      operatorValue,
		Negate:     rule.Operator.Negated,
		MultiMatch: hasAction(rule.Actions, "multiMatch"),
		Transforms: transforms,
		ListItems:  listItems,
	}

	conditions := []PolicyCondition{cond}

	// Recurse for deeper chains
	if rule.Chain != nil {
		more, err := c.convertChain(rule.Chain, filename)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, more...)
	}

	return conditions, nil
}

// ─── Helpers ───────────────────────────────────────────────────────

// splitPMPatterns splits a @pm pattern string into individual phrases.
// @pm uses space-separated values.
func splitPMPatterns(s string) []string {
	parts := strings.Fields(s)
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// categoryFromFilename extracts the CRS category from a .conf filename.
// e.g., "REQUEST-932-APPLICATION-ATTACK-RCE.conf" → "REQUEST-932-APPLICATION-ATTACK-RCE"
func categoryFromFilename(filename string) string {
	base := filepath.Base(filename)
	return strings.TrimSuffix(base, ".conf")
}

// addCategoryStat increments the category statistics.
func (c *Converter) addCategoryStat(category string, converted bool) {
	stat := c.report.CategoryStats[category]
	stat.Total++
	if converted {
		stat.Converted++
	} else {
		stat.Skipped++
	}
	c.report.CategoryStats[category] = stat
}

// ─── Sorting ───────────────────────────────────────────────────────

// SortRules sorts PolicyRules by numeric ID.
func SortRules(rules []PolicyRule) {
	sort.Slice(rules, func(i, j int) bool {
		ni, _ := strconv.Atoi(rules[i].ID)
		nj, _ := strconv.Atoi(rules[j].ID)
		return ni < nj
	})
}
