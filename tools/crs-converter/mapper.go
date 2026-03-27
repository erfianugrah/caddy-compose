package main

import (
	"sort"
	"strings"
)

// ─── Variable Mapping ──────────────────────────────────────────────
//
// Maps SecRule variables to policy engine condition fields.
// CRS rules often use pipe-separated variable combos; we map to the
// most appropriate multi-value field in the policy engine.

// separateArgs controls whether ARGS_GET/ARGS_POST map to dedicated fields
// (query_args_values/post_args_values) or fall back to all_args_values.
// Enable with -separate-args when the plugin supports the new fields.
var separateArgs = false

// variableMap maps individual SecRule variable names to policy engine fields.
// When separateArgs is true, ARGS_GET/ARGS_POST map to dedicated fields;
// otherwise they fall back to all_args_values (wider matching, fewer missed detections).
var variableMap = map[string]string{
	// Request args
	"ARGS":                "all_args_values",
	"ARGS_NAMES":          "all_args_names",
	"ARGS_GET":            "all_args_values", // overridden to "query_args_values" when separateArgs=true
	"ARGS_GET_NAMES":      "all_args_names",  // overridden to "query_args_names" when separateArgs=true
	"ARGS_POST":           "all_args_values", // overridden to "post_args_values" when separateArgs=true
	"ARGS_POST_NAMES":     "all_args_names",  // overridden to "post_args_names" when separateArgs=true
	"ARGS_COMBINED_SIZE":  "",                // size check — handled by plugin enforceProtocolLimits()
	"REQUEST_BODY_LENGTH": "content_length",  // approximate: use Content-Length header value

	// Request cookies
	"REQUEST_COOKIES":       "all_cookies",
	"REQUEST_COOKIES_NAMES": "all_cookies_names",

	// Request headers
	"REQUEST_HEADERS":       "all_headers",
	"REQUEST_HEADERS_NAMES": "all_headers_names",

	// Specific headers (when using :Name syntax, these override)
	// Handled by named field logic in mapVariablesToField

	// Request line/URI
	"REQUEST_URI":      "path",
	"REQUEST_URI_RAW":  "path", // raw URI — map to path (encoding preserved by plugin)
	"REQUEST_FILENAME": "uri_path",
	"REQUEST_BASENAME": "request_basename",
	"REQUEST_LINE":     "request_line",
	"QUERY_STRING":     "query",
	"REQUEST_METHOD":   "method",
	"REQUEST_PROTOCOL": "http_version",

	// Network
	"REMOTE_ADDR": "ip",
	"SERVER_NAME": "host",

	// Body
	"REQUEST_BODY": "body",

	// Files (multipart upload field names and original filenames)
	"FILES":       "files",
	"FILES_NAMES": "files_names",

	// XML body content (text nodes + attribute values)
	"XML": "xml",

	// Response (outbound — phase 3/4)
	"RESPONSE_STATUS":       "response_status",
	"RESPONSE_HEADERS":      "response_header",
	"RESPONSE_BODY":         "response_body",
	"RESPONSE_CONTENT_TYPE": "response_content_type",

	// Multipart
	"MULTIPART_PART_HEADERS":       "multipart_part_headers",
	"MULTIPART_STRICT_ERROR":       "multipart_strict_error", // NEEDED in plugin (strict error flag)
	"MULTIPART_UNMATCHED_BOUNDARY": "",                       // rare — skip

	// Internal (skip)
	"TX":                 "",
	"MATCHED_VAR":        "",
	"MATCHED_VAR_NAME":   "",
	"MATCHED_VARS":       "",
	"MATCHED_VARS_NAMES": "",
	"RULE":               "",
	"UNIQUE_ID":          "",
	"DURATION":           "",
	"HIGHEST_SEVERITY":   "",
	"ENV":                "",
	"REQBODY_ERROR":      "reqbody_error", // NEEDED in plugin
	"REQBODY_PROCESSOR":  "",              // approximated in convertRule via content_type check
}

// initSeparateArgs updates variableMap to use dedicated GET/POST fields
// when the -separate-args flag is enabled. Call after flag.Parse().
func initSeparateArgs() {
	if !separateArgs {
		return
	}
	variableMap["ARGS_GET"] = "query_args_values"
	variableMap["ARGS_GET_NAMES"] = "query_args_names"
	variableMap["ARGS_POST"] = "post_args_values"
	variableMap["ARGS_POST_NAMES"] = "post_args_names"
}

// headerShortcuts maps well-known REQUEST_HEADERS:Name to plugin fields.
// Only include shortcuts that the plugin natively supports as first-class fields.
// Others use the generic "header:Name" format.
var headerShortcuts = map[string]string{
	"User-Agent":     "user_agent",
	"Referer":        "referer",
	"Content-Type":   "content_type",
	"Content-Length": "content_length",
	"Cf-Ipcountry":   "country",
	"Host":           "host",
}

// pluginSupportedFields are the fields the caddy-policy-engine plugin can
// actually evaluate. Fields not in this set produce empty values, causing
// negated conditions to always match (false positives) and non-negated
// conditions to never match (dead rules).
var pluginSupportedFields = map[string]bool{
	// Scalar request fields
	"ip": true, "path": true, "host": true, "method": true,
	"user_agent": true, "query": true, "country": true,
	"body": true, "body_json": true, "body_form": true,
	"uri_path": true, "referer": true, "http_version": true,
	"ja4": true, "challenge_history": true,
	"header": true, "cookie": true, "args": true,
	"request_line": true, "request_basename": true,
	"content_type": true, "content_length": true,
	"files": true, "files_names": true,
	"xml": true, "multipart_part_headers": true,
	// Aggregate fields
	"all_args": true, "all_args_values": true, "all_args_names": true,
	"query_args_values": true, "query_args_names": true,
	"post_args_values": true, "post_args_names": true,
	"all_headers": true, "all_headers_names": true,
	"all_cookies": true, "all_cookies_names": true,
	"request_combined": true,
	// Response fields (outbound phase)
	"response_header": true, "response_status": true,
	"response_content_type": true, "response_body": true,
}

// isFieldSupported returns true if the plugin can evaluate this field.
func isFieldSupported(field string) bool {
	if pluginSupportedFields[field] {
		return true
	}
	// Named access: header:X, cookie:X, args:X, tx:N
	if strings.HasPrefix(field, "header:") || strings.HasPrefix(field, "cookie:") ||
		strings.HasPrefix(field, "args:") || strings.HasPrefix(field, "tx:") {
		return true
	}
	// count: on supported fields
	if strings.HasPrefix(field, "count:") {
		base := strings.TrimPrefix(field, "count:")
		return pluginSupportedFields[base] ||
			strings.HasPrefix(base, "header:") ||
			strings.HasPrefix(base, "cookie:") ||
			strings.HasPrefix(base, "args:")
	}
	return false
}

// multiFields are the aggregate (multi-value) fields that support the
// count: pseudo-field in the policy engine plugin.
var multiFields = map[string]bool{
	"all_args":          true,
	"all_args_values":   true,
	"all_args_names":    true,
	"query_args_values": true,
	"query_args_names":  true,
	"post_args_values":  true,
	"post_args_names":   true,
	"all_headers":       true,
	"all_headers_names": true,
	"all_cookies":       true,
	"all_cookies_names": true,
	"request_combined":  true,
}

// ─── Operator Mapping ──────────────────────────────────────────────

// operatorMap maps SecRule operator names to policy engine operators.
var operatorMap = map[string]string{
	"rx":                "regex",
	"pm":                "phrase_match",
	"pmFromFile":        "phrase_match", // resolve file contents to list_items
	"pmFromDataset":     "phrase_match", // same treatment
	"streq":             "eq",
	"contains":          "contains",
	"beginsWith":        "begins_with",
	"endsWith":          "ends_with",
	"ipMatch":           "ip_match",
	"ipMatchFromFile":   "ip_match", // resolve file contents
	"detectSQLi":        "detect_sqli",
	"detectXSS":         "detect_xss",
	"validateByteRange": "validate_byte_range",

	// Numeric comparison — supported by the policy engine plugin (gt, ge, lt, le
	// are valid on any field, eq is valid per-field). Many CRS rules using these
	// operate on TX variables (flow control) and are filtered by the TX-only skip,
	// but others check real request fields (content-length, header counts, etc.).
	"lt": "lt",
	"le": "le",
	"gt": "gt",
	"ge": "ge",
	"eq": "eq",

	// Set membership — CRS @within checks if value appears in a space-delimited
	// list. Most CRS @within rules reference TX variables (allowed_methods, etc.)
	// which are filtered by the TX-only skip. The few with literal values are
	// converted to "in" with pipe-delimited value.
	"within": "in",

	// Unconditional — used by SecAction
	"unconditionalMatch": "",

	// Not used by CRS detection rules
	"rbl":                  "",
	"inspectFile":          "",
	"restpath":             "",
	"geoLookup":            "",
	"noMatch":              "",
	"validateUrlEncoding":  "validate_url_encoding",
	"validateUtf8Encoding": "validate_utf8_encoding",
}

// ─── Transform Mapping ─────────────────────────────────────────────

// transformMap maps SecRule transform names to policy engine transforms.
// Plugin uses camelCase names matching CRS t:xxx conventions.
var transformMap = map[string]string{
	"none":               "", // implicit — empty transform list
	"urlDecodeUni":       "urlDecodeUni",
	"lowercase":          "lowercase",
	"jsDecode":           "jsDecode",
	"htmlEntityDecode":   "htmlEntityDecode",
	"utf8toUnicode":      "utf8toUnicode",
	"removeNulls":        "removeNulls",
	"cssDecode":          "cssDecode",
	"cmdLine":            "cmdLine",
	"replaceComments":    "removeComments", // CRS replaces with space; plugin removes entirely — same detection effect
	"normalizePath":      "normalizePath",
	"removeWhitespace":   "removeWhitespace",
	"escapeSeqDecode":    "escapeSeqDecode",
	"compressWhitespace": "compressWhitespace",
	"normalizePathWin":   "normalizePathWin",
	"length":             "length",
	"base64Decode":       "base64Decode",
	"sha1":               "sha1",
	"hexEncode":          "hexEncode",
	"removeCommentsChar": "removeCommentsChar", // NEEDED in plugin — strips /*, */, --, #
	"urlDecode":          "urlDecode",
	"base64DecodeExt":    "base64Decode", // maps to same impl
	"trim":               "trim",
	"trimLeft":           "trimLeft",
	"trimRight":          "trimRight",
}

// ─── Severity Mapping ──────────────────────────────────────────────

// severityMap maps CRS severity strings to policy engine severity.
var severityMap = map[string]string{
	"CRITICAL": "CRITICAL",
	"ERROR":    "ERROR",
	"WARNING":  "WARNING",
	"NOTICE":   "NOTICE",
	"0":        "", // numeric 0 = not set
	"2":        "CRITICAL",
	"3":        "ERROR",
	"4":        "WARNING",
	"5":        "NOTICE",
}

// ─── Variable Combo Mapping ────────────────────────────────────────

// mapVariablesToConditions converts a SecRule's variable list into
// one or more PolicyConditions. Returns the field(s) and any
// variable-level issues for the report.
//
// Strategy:
//  1. If all variables map to the same field → single condition
//  2. If variables map to different fields → one condition per field
//  3. Named variables (HEADER:Name) → field:Name syntax
//  4. Negation variables (!VAR:key) → noted but not directly expressible
//     (CRS uses these to exclude specific cookies from matching)
func mapVariablesToConditions(vars []Variable, op Operator) (fields []string, excludes []Variable, issues []string) {
	fieldSet := make(map[string]bool)

	for _, v := range vars {
		if v.IsNegation {
			excludes = append(excludes, v)
			continue
		}

		// Count prefix (&VARIABLE) — CRS uses & to count variable occurrences.
		// The plugin supports count: on aggregate fields (returns element count)
		// and scalar fields (returns 0 or 1 for absent/present).
		// Named header counts like &REQUEST_HEADERS:Host map to count:host.
		if v.IsCount {
			// Named header count: &REQUEST_HEADERS:Host → count:host
			if v.Name == "REQUEST_HEADERS" && v.Key != "" {
				if shortcut, ok := headerShortcuts[v.Key]; ok {
					fieldSet["count:"+shortcut] = true
				} else {
					fieldSet["count:header:"+v.Key] = true
				}
				continue
			}
			// Named multipart header count
			if v.Name == "MULTIPART_PART_HEADERS" {
				fieldSet["count:multipart_part_headers"] = true
				continue
			}
			// Aggregate or scalar variable count
			if field, ok := variableMap[v.Name]; ok && field != "" {
				fieldSet["count:"+field] = true
				continue
			}
			issues = append(issues, "count prefix (&) on unmappable variable "+v.Name)
			continue
		}

		// Named header access
		if v.Name == "REQUEST_HEADERS" && v.Key != "" {
			if shortcut, ok := headerShortcuts[v.Key]; ok {
				fieldSet[shortcut] = true
				continue
			}
			fieldSet["header:"+v.Key] = true
			continue
		}

		// Named cookie access
		if v.Name == "REQUEST_COOKIES" && v.Key != "" && !v.KeyIsRegex {
			fieldSet["cookie:"+v.Key] = true
			continue
		}

		// Named args access
		if v.Name == "ARGS" && v.Key != "" {
			fieldSet["args:"+v.Key] = true
			continue
		}

		// Standard mapping
		if field, ok := variableMap[v.Name]; ok {
			if field == "" {
				issues = append(issues, "unmappable variable "+v.Name)
				continue
			}
			fieldSet[field] = true
		} else {
			issues = append(issues, "unknown variable "+v.Name)
		}
	}

	for f := range fieldSet {
		fields = append(fields, f)
	}
	return fields, excludes, issues
}

// ─── Per-Field Condition Builder ───────────────────────────────────
//
// CRS rules typically check multiple variables with OR semantics:
// ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_BODY|
// REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|XML:/*
//
// Instead of collapsing these to "request_combined" (which is too broad
// and causes false positives), we emit one condition per field wrapped
// in an OR group. This preserves the exact variable scope of each CRS
// rule — if the original rule only checks User-Agent and Referer, the
// converted rule checks exactly those fields, not all headers.

// buildFieldCondition creates a PolicyCondition from the given fields and
// shared operator/value/transforms. If there is only one field, it returns
// a direct condition. If there are multiple fields, it returns a condition
// group with OR semantics — one sub-condition per field.
//
// The excludes parameter contains variable exclusion patterns (e.g.,
// "cookie:__utm*") which are distributed to the relevant sub-conditions
// based on prefix matching (cookie: → cookie fields, header: → header
// fields, args: → args fields).
func buildFieldCondition(fields []string, opName, operatorValue string, negate, multiMatch bool, transforms, listItems, excludes []string) PolicyCondition {
	// Sort fields for deterministic output.
	sort.Strings(fields)

	if len(fields) == 1 {
		return PolicyCondition{
			Field:      fields[0],
			Operator:   opName,
			Value:      operatorValue,
			Negate:     negate,
			MultiMatch: multiMatch,
			Transforms: transforms,
			ListItems:  listItems,
			Excludes:   excludes,
		}
	}

	// Multiple fields → OR group with one sub-condition per field.
	group := make([]PolicyCondition, 0, len(fields))
	for _, f := range fields {
		sub := PolicyCondition{
			Field:      f,
			Operator:   opName,
			Value:      operatorValue,
			Negate:     negate,
			MultiMatch: multiMatch,
			Transforms: transforms,
			ListItems:  listItems,
		}
		// Distribute excludes to matching fields only.
		sub.Excludes = matchExcludes(f, excludes)
		group = append(group, sub)
	}

	return PolicyCondition{
		Group:   group,
		GroupOp: "or",
	}
}

// matchExcludes returns the subset of excludes relevant to the given field.
// Exclude patterns are prefixed: "cookie:" for cookie fields, "header:" for
// header fields, "args:" for args fields. An exclude matches a field if:
//   - cookie:* matches all_cookies, all_cookies_names, cookie:*
//   - header:* matches all_headers, all_headers_names, header:*, user_agent, referer, content_type, host
//   - args:*   matches all_args, all_args_values, all_args_names, args:*
//
// Excludes with no matching field are attached to request_combined or body
// fields (conservative — keeps the exclusion active).
func matchExcludes(field string, excludes []string) []string {
	if len(excludes) == 0 {
		return nil
	}

	var matched []string
	for _, ex := range excludes {
		if excludeMatchesField(ex, field) {
			matched = append(matched, ex)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	return matched
}

// headerFields are fields that represent request header values.
var headerFields = map[string]bool{
	"all_headers": true, "all_headers_names": true,
	"user_agent": true, "referer": true, "content_type": true,
	"content_length": true, "host": true,
}

func excludeMatchesField(exclude, field string) bool {
	switch {
	case strings.HasPrefix(exclude, "cookie:"):
		return field == "all_cookies" || field == "all_cookies_names" ||
			strings.HasPrefix(field, "cookie:")
	case strings.HasPrefix(exclude, "header:"):
		return headerFields[field] || strings.HasPrefix(field, "header:")
	case strings.HasPrefix(exclude, "args:"):
		return field == "all_args" || field == "all_args_values" ||
			field == "all_args_names" ||
			field == "query_args_values" || field == "query_args_names" ||
			field == "post_args_values" || field == "post_args_names" ||
			strings.HasPrefix(field, "args:")
	default:
		// Unknown prefix — attach to body/combined as a conservative fallback.
		return field == "body" || field == "request_combined"
	}
}

// ─── Helpers ───────────────────────────────────────────────────────

// mapOperator converts a SecRule operator to a policy engine operator.
// Returns the operator name, whether it's supported, and optional notes.
func mapOperator(op Operator) (string, bool, string) {
	if mapped, ok := operatorMap[op.Name]; ok {
		if mapped == "" {
			return "", false, "flow-control operator: @" + op.Name
		}
		return mapped, true, ""
	}
	return "", false, "unknown operator: @" + op.Name
}

// mapTransforms converts SecRule transforms to policy engine transform list.
func mapTransforms(transforms []string) ([]string, []string) {
	var mapped []string
	var missing []string

	for _, t := range transforms {
		if t == "none" {
			continue
		}
		if m, ok := transformMap[t]; ok {
			if m != "" {
				mapped = append(mapped, m)
			}
		} else {
			missing = append(missing, t)
		}
	}

	return mapped, missing
}

// mapSeverity converts a CRS severity to policy engine severity.
func mapSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if mapped, ok := severityMap[s]; ok {
		return mapped
	}
	return s
}

// mapCRSTags filters CRS tags to policy-relevant tags.
// Strips internal CRS tags (OWASP_CRS, ver, capec, PCI) and keeps
// attack category tags.
func mapCRSTags(tags []string) []string {
	var result []string
	for _, tag := range tags {
		// Skip internal CRS tags
		if tag == "OWASP_CRS" ||
			strings.HasPrefix(tag, "OWASP_CRS/") ||
			strings.HasPrefix(tag, "capec/") ||
			strings.HasPrefix(tag, "PCI/") ||
			strings.HasPrefix(tag, "paranoia-level/") ||
			strings.HasPrefix(tag, "ver:") {
			continue
		}
		result = append(result, tag)
	}
	return result
}
