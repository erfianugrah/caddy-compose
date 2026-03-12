package main

import (
	"strings"
)

// ─── Variable Mapping ──────────────────────────────────────────────
//
// Maps SecRule variables to policy engine condition fields.
// CRS rules often use pipe-separated variable combos; we map to the
// most appropriate multi-value field in the policy engine.

// variableMap maps individual SecRule variable names to policy engine fields.
var variableMap = map[string]string{
	// Request args
	"ARGS":                "all_args_values",
	"ARGS_NAMES":          "all_args_names",
	"ARGS_GET":            "all_args_values", // TODO: separate GET args field
	"ARGS_GET_NAMES":      "all_args_names",  // TODO: separate GET arg names
	"ARGS_POST":           "all_args_values", // TODO: separate POST args field
	"ARGS_POST_NAMES":     "all_args_names",  // TODO: separate POST arg names
	"ARGS_COMBINED_SIZE":  "",                // size check — skip
	"REQUEST_BODY_LENGTH": "",                // size check — skip

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
	"REQUEST_BASENAME": "request_basename", // NEEDED in plugin
	"REQUEST_LINE":     "request_line",     // NEEDED in plugin
	"QUERY_STRING":     "query",
	"REQUEST_METHOD":   "method",
	"REQUEST_PROTOCOL": "http_version",

	// Network
	"REMOTE_ADDR": "ip",
	"SERVER_NAME": "host",

	// Body
	"REQUEST_BODY": "body",

	// Files
	"FILES":       "files",       // NEEDED in plugin
	"FILES_NAMES": "files_names", // NEEDED in plugin

	// XML
	"XML": "xml", // NEEDED in plugin

	// Response (deferred — phase 3/4)
	"RESPONSE_STATUS":       "response_status",
	"RESPONSE_HEADERS":      "response_headers",
	"RESPONSE_BODY":         "response_body",
	"RESPONSE_CONTENT_TYPE": "response_content_type",

	// Multipart
	"MULTIPART_PART_HEADERS":       "multipart_part_headers", // NEEDED in plugin
	"MULTIPART_STRICT_ERROR":       "multipart_strict_error", // NEEDED in plugin
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
	"REQBODY_PROCESSOR":  "",              // internal CRS state — skip
}

// headerShortcuts maps well-known REQUEST_HEADERS:Name to plugin fields.
var headerShortcuts = map[string]string{
	"User-Agent":     "user_agent",
	"Referer":        "referer",
	"Content-Type":   "content_type",
	"Content-Length": "content_length",
	"Cf-Ipcountry":   "country",
	"Host":           "host",
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

	// Numeric / flow control — handled by scoring system, not needed
	"lt":     "",
	"le":     "",
	"gt":     "",
	"ge":     "",
	"eq":     "",
	"within": "",

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

		// Skip count prefix variables — these are for CRS internal checks
		if v.IsCount {
			issues = append(issues, "count prefix (&) on "+v.Name)
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

// ─── Common CRS variable combos → single field ────────────────────
//
// CRS rules almost always use one of a few standard variable combos.
// We detect these and map to the appropriate multi-value field.

// consolidateFields merges multiple fields into a single multi-value
// field when they represent a standard CRS combo.
func consolidateFields(fields []string) string {
	if len(fields) == 1 {
		return fields[0]
	}

	// Sort for canonical comparison
	set := make(map[string]bool)
	for _, f := range fields {
		set[f] = true
	}

	// Most common CRS combo: ARGS + ARGS_NAMES + REQUEST_COOKIES + REQUEST_COOKIES_NAMES + XML
	// Maps to: all_args_values (which the plugin evaluates against all request data)
	if set["all_args_values"] && set["all_args_names"] &&
		set["all_cookies"] && set["all_cookies_names"] {
		return "all_args_values"
	}

	// Common: ARGS + ARGS_NAMES + REQUEST_COOKIES_NAMES + XML
	if set["all_args_values"] && set["all_cookies_names"] {
		return "all_args_values"
	}

	// Common: REQUEST_HEADERS + REQUEST_LINE
	if set["all_headers"] && set["request_line"] {
		return "all_headers"
	}

	// Common: just ARGS variants
	if set["all_args_values"] {
		return "all_args_values"
	}

	// Default: use the first field (will be a single-condition rule)
	return fields[0]
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
