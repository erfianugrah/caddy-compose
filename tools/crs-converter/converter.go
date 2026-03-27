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

	// Response-phase rules (phase 3 or 4) are converted with phase: "outbound".
	// These rules evaluate against response headers and body after the upstream responds.

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

// ─── Special-Case Rule Conversion ──────────────────────────────────
//
// Some CRS rules use patterns too complex for generic conversion (TX regex
// key iteration, REQBODY_PROCESSOR, dynamic host comparison). These are
// converted via hardcoded logic that produces equivalent plugin conditions.

func (c *Converter) convertSpecialCase(rule SecRule, category, filename string) *PolicyRule {
	switch rule.ID {
	case "920450":
		// Restricted headers (basic): any request header name in the restricted list → block.
		// Use "in" for exact name matching (not phrase_match which does substring matching
		// and would match "proxy" inside "proxy-connection").
		items := parseSlashWrapped(crsDefaultRestrictedHeaders)
		return c.buildSpecialDetect(rule, category, filename, []PolicyCondition{{
			Field:      "all_headers_names",
			Operator:   "in",
			Value:      strings.Join(items, "|"),
			Transforms: []string{"lowercase"},
		}})

	case "920451":
		// Restricted headers (extended, PL2): same pattern as 920450.
		items := parseSlashWrapped(crsDefaultRestrictedHeadersExtended)
		return c.buildSpecialDetect(rule, category, filename, []PolicyCondition{{
			Field:      "all_headers_names",
			Operator:   "in",
			Value:      strings.Join(items, "|"),
			Transforms: []string{"lowercase"},
		}})

	case "920540":
		// Unicode escape bypass for non-JSON requests.
		// CRS: REQBODY_PROCESSOR !@streq JSON → check for \uXXXX in args/headers/URI.
		// We approximate: Content-Type not containing "json" AND args/headers match \uXXXX.
		return c.buildSpecialDetect(rule, category, filename, []PolicyCondition{
			{
				Field:    "content_type",
				Operator: "contains",
				Value:    "json",
				Negate:   true, // NOT contains json
			},
			{
				Group: []PolicyCondition{
					{Field: "all_args_values", Operator: "regex", Value: `(?i)\\x5cu[0-9a-f]{4}`},
					{Field: "all_args_names", Operator: "regex", Value: `(?i)\\x5cu[0-9a-f]{4}`},
					{Field: "all_headers", Operator: "regex", Value: `(?i)\\x5cu[0-9a-f]{4}`},
					{Field: "path", Operator: "regex", Value: `(?i)\\x5cu[0-9a-f]{4}`},
				},
				GroupOp: "or",
			},
		})

	case "931130":
		// RFI off-domain reference: URL in args pointing to external host.
		// CRS captures hostname from URL, compares to Host header.
		// We approximate: args contain a URL scheme with a hostname that's
		// different from the request host. Emit as a regex that matches full
		// URLs — the head regex alone already detects RFI attempt patterns.
		// The host comparison (chain) is a precision optimization, not the
		// core detection. Include the head regex as-is.
		opValue := rule.Operator.Value
		fixed, err := ValidateRE2(opValue)
		if err != nil {
			return nil // fall through to generic (will be skipped)
		}
		transforms, _ := mapTransforms(rule.Transforms)
		return c.buildSpecialDetect(rule, category, filename, []PolicyCondition{{
			Group: []PolicyCondition{
				{Field: "all_args_values", Operator: "regex", Value: fixed, Transforms: transforms},
				{Field: "all_args_names", Operator: "regex", Value: fixed, Transforms: transforms},
			},
			GroupOp: "or",
		}})
	}
	return nil
}

// buildSpecialDetect creates a detect PolicyRule from hand-crafted conditions.
func (c *Converter) buildSpecialDetect(rule SecRule, category, filename string, conditions []PolicyCondition) *PolicyRule {
	severity := mapSeverity(rule.Severity)
	tags := mapCRSTags(rule.Tags)
	phase := ""
	if rule.Phase == 3 || rule.Phase == 4 {
		phase = "outbound"
	}
	return &PolicyRule{
		ID:            rule.ID,
		Name:          rule.Msg,
		Type:          "detect",
		Phase:         phase,
		Conditions:    conditions,
		GroupOp:       "and",
		Severity:      severity,
		ParanoiaLevel: rule.ParanoiaLevel,
		Tags:          tags,
		Enabled:       true,
		Priority:      400,
		Description:   rule.Msg,
		Category:      category,
		CRSFile:       filepath.Base(filename),
	}
}

// parseSlashWrapped parses a slash-wrapped list like "/value1/ /value2/" into individual items.
func parseSlashWrapped(s string) []string {
	var items []string
	for _, item := range strings.Fields(s) {
		item = strings.Trim(item, "/")
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

// ─── CRS TX Default Values ─────────────────────────────────────────
//
// These are the default CRS TX variable values from REQUEST-901-INITIALIZATION.conf.
// When the converter encounters @within %{tx.allowed_*} or %{tx.restricted_*},
// it substitutes the CRS defaults. Per-service overrides are handled by the
// plugin's WafConfig (for 911100/920430) or as customizable rule overrides
// in the wafctl dashboard.

// crsDefaultContentTypes is the default allowed Content-Type list (pipe-wrapped).
var crsDefaultContentTypes = "|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json|"

// crsDefaultCharsets is the default allowed charset list (pipe-wrapped).
var crsDefaultCharsets = "|utf-8| |iso-8859-1| |iso-8859-15| |windows-1252|"

// crsDefaultRestrictedExtensions is the default restricted file extensions (slash-wrapped).
var crsDefaultRestrictedExtensions = ".asa/ .asax/ .ascx/ .axd/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .rdb/ .resources/ .resx/ .sql/ .swp/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/"

// crsDefaultRestrictedHeaders is the default restricted header names (slash-wrapped).
var crsDefaultRestrictedHeaders = "/content-encoding/ /proxy/ /lock-token/ /content-range/ /if/ /x-http-method-override/ /x-http-method/ /x-method-override/ /x-middleware-subrequest/ /expect/"

// crsDefaultRestrictedHeadersExtended is the extended restricted header names.
var crsDefaultRestrictedHeadersExtended = "/accept-charset/"

// flattenTXWithinChain attempts to flatten a chain rule where the chain link
// uses @within or !@within against a TX variable reference (e.g., %{tx.allowed_*}).
// Returns the flattened conditions if successful, or nil if the chain pattern
// is not recognized.
func (c *Converter) flattenTXWithinChain(rule SecRule, headFields []string, headCond PolicyCondition) []PolicyCondition {
	if rule.Chain == nil {
		return nil
	}
	chain := rule.Chain
	if chain.Operator.Name != "within" {
		return nil
	}
	opVal := chain.Operator.Value

	// Determine which TX variable reference is being used.
	var allowedList string
	var opName string

	switch {
	case strings.Contains(opVal, "%{tx.allowed_request_content_type_charset}") || strings.Contains(opVal, "%{TX.allowed_request_content_type_charset}"):
		allowedList = crsDefaultCharsets
		opName = "phrase_match" // pipe-delimited → phrase match
	case strings.Contains(opVal, "%{tx.allowed_request_content_type}") || strings.Contains(opVal, "%{TX.allowed_request_content_type}"):
		allowedList = crsDefaultContentTypes
		opName = "phrase_match"
	case strings.Contains(opVal, "%{tx.restricted_extensions}") || strings.Contains(opVal, "%{TX.restricted_extensions}"):
		allowedList = crsDefaultRestrictedExtensions
		opName = "phrase_match"
	case strings.Contains(opVal, "%{tx.restricted_headers}") || strings.Contains(opVal, "%{TX.restricted_headers}"):
		allowedList = crsDefaultRestrictedHeaders
		opName = "phrase_match"
	case strings.Contains(opVal, "%{tx.restricted_headers_extended}") || strings.Contains(opVal, "%{TX.restricted_headers_extended}"):
		allowedList = crsDefaultRestrictedHeadersExtended
		opName = "phrase_match"
	default:
		return nil // unknown TX variable reference
	}

	// Parse the allowed list into individual items.
	// CRS uses pipe-wrapped or slash-wrapped items:
	// "|value1| |value2|" or "value1/ value2/"
	var items []string
	for _, item := range strings.Fields(allowedList) {
		item = strings.Trim(item, "|/")
		if item != "" {
			items = append(items, item)
		}
	}
	if len(items) == 0 {
		return nil
	}

	// Map transforms from the chain link.
	transforms, _ := mapTransforms(chain.Transforms)

	// The head condition captures a value via regex group, the chain checks it.
	// CRS uses TX:1 (first capture group). After the plugin's tx fix:
	// tx:0 = full match, tx:1 = first capture group. Use tx:1.
	chainCond := PolicyCondition{
		Field:      "tx:1",
		Operator:   opName,
		Negate:     chain.Operator.Negated,
		Transforms: transforms,
		ListItems:  items,
	}

	return []PolicyCondition{headCond, chainCond}
}

// ─── Conversion ────────────────────────────────────────────────────

func (c *Converter) convertRule(rule SecRule, category, filename string) (*PolicyRule, error) {
	// Special-case rules that can't be handled by generic conversion.
	if pr := c.convertSpecialCase(rule, category, filename); pr != nil {
		return pr, nil
	}

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
	fields, excludeVars, varIssues := mapVariablesToConditions(rule.Variables, rule.Operator)
	for _, issue := range varIssues {
		if strings.HasPrefix(issue, "unknown variable") {
			varName := strings.TrimPrefix(issue, "unknown variable ")
			c.report.MissingVariables[varName]++
		}
	}

	if len(fields) == 0 {
		return nil, fmt.Errorf("no mappable variables")
	}

	// Filter out fields the plugin cannot evaluate. An unsupported field
	// in a non-negated condition silently never matches (dead branch). In
	// a negated condition it ALWAYS matches (false positive). Either way,
	// including it is wrong.
	var supportedFields []string
	var droppedFields []string
	for _, f := range fields {
		if isFieldSupported(f) {
			supportedFields = append(supportedFields, f)
		} else {
			droppedFields = append(droppedFields, f)
		}
	}
	if len(droppedFields) > 0 {
		for _, f := range droppedFields {
			c.report.MissingVariables[f]++
		}
	}
	if len(supportedFields) == 0 {
		return nil, fmt.Errorf("all fields unsupported by plugin: %s", strings.Join(droppedFields, ", "))
	}
	fields = supportedFields

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
	case "within":
		// CRS @within checks if a value is in a space-delimited list.
		// Convert to "in" operator with pipe-delimited value.
		// Skip if value references TX variables (%{tx.*}).
		if strings.Contains(operatorValue, "%{tx.") || strings.Contains(operatorValue, "%{TX") {
			return nil, fmt.Errorf("@within with TX variable reference: %s", operatorValue)
		}
		operatorValue = strings.Join(strings.Fields(operatorValue), "|")
	}

	// Convert negation variable exclusions to exclude patterns.
	// CRS uses !REQUEST_COOKIES:/__utm/ to skip specific variables.
	var excludes []string
	for _, v := range excludeVars {
		var prefix string
		switch v.Name {
		case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES":
			prefix = "cookie:"
		case "ARGS", "ARGS_GET", "ARGS_POST", "ARGS_NAMES":
			prefix = "args:"
		case "REQUEST_HEADERS":
			prefix = "header:"
		default:
			continue
		}
		if v.Key != "" {
			excludes = append(excludes, prefix+v.Key)
		}
	}

	// Build condition. For multi-field rules, emit an OR group with one
	// sub-condition per field — this preserves the exact CRS variable scope
	// instead of collapsing to request_combined (which is too broad).
	cond := buildFieldCondition(fields, opName, operatorValue,
		rule.Operator.Negated, hasAction(rule.Actions, "multiMatch"),
		transforms, listItems, excludes)

	var conditions []PolicyCondition
	conditions = append(conditions, cond)
	if rule.Chain != nil {
		// First, try to flatten known CRS chain patterns where the chain link
		// checks a captured value against a baked-in TX allowlist/blocklist.
		if flattened := c.flattenTXWithinChain(rule, fields, cond); flattened != nil {
			conditions = flattened
		} else {
			// Generic chain conversion.
			chainConds, err := c.convertChain(rule.Chain, filename)
			if err != nil {
				return nil, fmt.Errorf("chain conversion: %w", err)
			}

			// If ALL chain conditions were dropped (TX variables, unsupported
			// fields, @within %{tx.*}), the head condition alone is overbroad —
			// the chain existed to narrow the match. Skip the entire rule.
			if len(chainConds) == 0 {
				return nil, fmt.Errorf("chain conditions dropped — head alone is overbroad (@%s %q)", rule.Operator.Name, rule.Operator.Value)
			}
			conditions = append(conditions, chainConds...)
		}
	}

	// Map severity
	severity := mapSeverity(rule.Severity)

	// Map tags
	tags := mapCRSTags(rule.Tags)

	// Determine phase: response-phase rules (CRS phase 3/4) are outbound.
	phase := ""
	if rule.Phase == 3 || rule.Phase == 4 {
		phase = "outbound"
	}

	// Build the policy rule
	pr := &PolicyRule{
		ID:            rule.ID,
		Name:          rule.Msg,
		Type:          "detect",
		Phase:         phase,
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
// TX capture references (TX:0, TX:1, TX:content_type) are converted to
// tx:N fields that the plugin reads from its per-request capture context.
// Chain links with %{tx.*} variable references in operator values are
// unconvertible (server-configured allowlists) and cause the link to be skipped.
func (c *Converter) convertChain(rule *SecRule, filename string) ([]PolicyCondition, error) {
	// Map operator
	opName, supported, _ := mapOperator(rule.Operator)

	// Map transforms
	transforms, _ := mapTransforms(rule.Transforms)

	// Check if this chain link uses TX capture variables.
	// TX:0, TX:1 → tx:0, tx:1 (regex capture references from head rule)
	// TX:content_type → tx:content_type (CRS setvar-derived captures)
	// TX:/^pattern/ → skip (regex-keyed TX iteration, not convertible)
	var txFields []string
	isTXOnly := true
	for _, v := range rule.Variables {
		if v.IsNegation {
			continue
		}
		if v.Name == "TX" {
			if v.KeyIsRegex {
				// TX:/^pattern/ — iterating TX variables by regex key, not convertible.
				isTXOnly = true
				txFields = nil
				break
			}
			if v.Key != "" {
				txFields = append(txFields, "tx:"+v.Key)
			}
		} else if v.Name == "MATCHED_VARS" || v.Name == "MATCHED_VAR" {
			// MATCHED_VARS/MATCHED_VAR: CRS uses these to re-examine what the
			// head matched. The plugin's TX capture context stores the head's
			// capture in tx:0, which serves the same purpose.
			txFields = append(txFields, "tx:0")
		} else {
			isTXOnly = false
		}
	}

	// Map non-TX variables → plugin fields.
	fields, _, _ := mapVariablesToConditions(rule.Variables, rule.Operator)
	var chainSupported []string
	for _, f := range fields {
		if isFieldSupported(f) {
			chainSupported = append(chainSupported, f)
		}
	}
	fields = chainSupported

	// If all variables are TX/MATCHED_VARS, use the tx: fields instead.
	if isTXOnly && len(txFields) > 0 {
		fields = txFields
	}

	skipThisLink := !supported || len(fields) == 0

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
	case "within":
		if strings.Contains(operatorValue, "%{tx.") || strings.Contains(operatorValue, "%{TX") {
			skipThisLink = true
		} else {
			operatorValue = strings.Join(strings.Fields(operatorValue), "|")
		}
	}

	// Skip chain links whose operator value references TX variables (%{tx.*}).
	// These are dynamic comparisons between captured values that the plugin
	// cannot evaluate (e.g., TX:2 @lt %{tx.1} — comparing two captures).
	if !skipThisLink && (strings.Contains(operatorValue, "%{tx.") || strings.Contains(operatorValue, "%{TX") || strings.Contains(operatorValue, "%{request_headers.")) {
		skipThisLink = true
	}

	var conditions []PolicyCondition

	if !skipThisLink {
		cond := buildFieldCondition(fields, opName, operatorValue,
			rule.Operator.Negated, hasAction(rule.Actions, "multiMatch"),
			transforms, listItems, nil)
		conditions = append(conditions, cond)
	}

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

// isNumericOp returns true for numeric comparison operators.
func isNumericOp(op string) bool {
	return op == "eq" || op == "neq" || op == "gt" || op == "ge" || op == "lt" || op == "le"
}

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

// SortRules sorts PolicyRules by numeric ID. Uses stable sort to preserve
// relative order of rules with the same ID (e.g., custom rules appended
// after CRS rules).
func SortRules(rules []PolicyRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		ni, _ := strconv.Atoi(rules[i].ID)
		nj, _ := strconv.Atoi(rules[j].ID)
		return ni < nj
	})
}
