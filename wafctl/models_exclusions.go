package main

import "time"

// ─── WAF Policy Engine: Exclusions & Configuration ──────────────────────────

// Condition represents a single match condition in an exclusion or rate limit rule.
type Condition struct {
	Field    string `json:"field"`    // "ip", "path", "host", "method", "user_agent", "header", "query", "country", "cookie", "body", "body_json", "body_form", "args", "uri_path", "referer", "response_header", "response_status", "http_version"
	Operator string `json:"operator"` // "eq", "neq", "contains", "begins_with", "ends_with", "regex", "ip_match", "not_ip_match", "in"
	Value    string `json:"value"`
}

// RuleExclusion is a single WAF policy engine rule (allow, block, skip_rule, anomaly, honeypot, raw, etc.).
type RuleExclusion struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	Description          string      `json:"description"`
	Type                 string      `json:"type"`
	Conditions           []Condition `json:"conditions,omitempty"`             // Dynamic conditions (field/operator/value)
	GroupOp              string      `json:"group_operator,omitempty"`         // "and" (default) or "or"
	RuleID               string      `json:"rule_id,omitempty"`                // For skip_rule + advanced types
	RuleTag              string      `json:"rule_tag,omitempty"`               // For skip_rule + advanced types
	Variable             string      `json:"variable,omitempty"`               // For advanced target types
	RawRule              string      `json:"raw_rule,omitempty"`               // Raw SecRule directive for raw editor
	AnomalyScore         int         `json:"anomaly_score,omitempty"`          // For anomaly type: score points to add (1-10)
	AnomalyParanoiaLevel int         `json:"anomaly_paranoia_level,omitempty"` // For anomaly type: paranoia level 1-4 (default 1)
	Tags                 []string    `json:"tags,omitempty"`                   // Event classification tags (e.g., "scanner", "honeypot", "blocklist")
	Enabled              bool        `json:"enabled"`
	CreatedAt            time.Time   `json:"created_at"`
	UpdatedAt            time.Time   `json:"updated_at"`
}

// ─── WAF Configuration ──────────────────────────────────────────────────────

// WAFConfig holds the WAF configuration with per-service overrides.
// Defaults are applied to any service without an explicit override.
// Services map hostname → per-service overrides.
type WAFConfig struct {
	Defaults WAFServiceSettings            `json:"defaults"`
	Services map[string]WAFServiceSettings `json:"services"`
}

// WAFServiceSettings controls WAF behavior for a service (or as defaults).
type WAFServiceSettings struct {
	// Mode: "enabled" (blocking), "detection_only" (log-only), "disabled" (ctl:ruleEngine=Off)
	Mode string `json:"mode"`
	// ParanoiaLevel: CRS paranoia level 1-4 (higher = more rules, more false positives)
	ParanoiaLevel int `json:"paranoia_level"`
	// InboundThreshold: anomaly score threshold for inbound requests (lower = stricter)
	InboundThreshold int `json:"inbound_threshold"`
	// OutboundThreshold: anomaly score threshold for outbound responses
	OutboundThreshold int `json:"outbound_threshold"`
	// DisabledGroups: CRS rule group tags to disable (e.g. "attack-sqli", "attack-xss")
	DisabledGroups []string `json:"disabled_groups,omitempty"`

	// ─── CRS v4 Extended Settings ───────────────────────────────────
	// All fields use omitempty so existing configs are unaffected.
	// Zero/empty values mean "use CRS default" (no setvar emitted).

	// BlockingParanoiaLevel: CRS v4's primary tuning knob. Detect at PL3 but only
	// block at PL1. When 0, equals ParanoiaLevel (legacy behavior).
	BlockingParanoiaLevel int `json:"blocking_paranoia_level,omitempty"`
	// DetectionParanoiaLevel: when 0, equals ParanoiaLevel (legacy behavior).
	DetectionParanoiaLevel int `json:"detection_paranoia_level,omitempty"`
	// EarlyBlocking: block at phase 1/2 before full request inspection. Default 0.
	EarlyBlocking *bool `json:"early_blocking,omitempty"`
	// SamplingPercentage: percentage of requests to inspect (1-100). Default 100.
	SamplingPercentage int `json:"sampling_percentage,omitempty"`
	// ReportingLevel: PL for reporting. When 0, equals ParanoiaLevel.
	ReportingLevel int `json:"reporting_level,omitempty"`
	// EnforceBodyprocURLEncoded: force body processor for url-encoded POSTs. Default 0.
	EnforceBodyprocURLEncoded *bool `json:"enforce_bodyproc_urlencoded,omitempty"`

	// ─── Request Policy Settings ────────────────────────────────────
	// AllowedMethods: space-separated HTTP methods (rule 911100). Default "GET HEAD POST OPTIONS".
	AllowedMethods string `json:"allowed_methods,omitempty"`
	// AllowedRequestContentType: space-separated content types (rule 920420).
	AllowedRequestContentType string `json:"allowed_request_content_type,omitempty"`
	// AllowedHTTPVersions: space-separated versions (rule 920230). Default "HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0".
	AllowedHTTPVersions string `json:"allowed_http_versions,omitempty"`
	// RestrictedExtensions: space-separated file extensions to block (rule 920440).
	RestrictedExtensions string `json:"restricted_extensions,omitempty"`
	// RestrictedHeaders: slash-delimited headers to block (rule 920450).
	RestrictedHeaders string `json:"restricted_headers,omitempty"`

	// ─── Argument Limits ────────────────────────────────────────────
	// MaxNumArgs: maximum number of arguments (rule 920300). Default 255.
	MaxNumArgs int `json:"max_num_args,omitempty"`
	// ArgNameLength: max argument name length (rule 920310). Default 100.
	ArgNameLength int `json:"arg_name_length,omitempty"`
	// ArgLength: max argument value length (rule 920320). Default 400.
	ArgLength int `json:"arg_length,omitempty"`
	// TotalArgLength: max total arguments length (rule 920330). Default 64000.
	TotalArgLength int `json:"total_arg_length,omitempty"`

	// ─── File Upload Limits ─────────────────────────────────────────
	// MaxFileSize: max individual file size in bytes (rule 920400). Default 1048576.
	MaxFileSize int `json:"max_file_size,omitempty"`
	// CombinedFileSizes: max combined file upload size (rule 920410). Default 1048576.
	CombinedFileSizes int `json:"combined_file_sizes,omitempty"`

	// ─── CRS Built-in Exclusion Profiles ────────────────────────────
	// CRSExclusions: list of CRS v4 built-in exclusion profile names to enable.
	// Each name maps to tx.crs_exclusions_<name>=1 (e.g. "wordpress", "nextcloud").
	CRSExclusions []string `json:"crs_exclusions,omitempty"`
}

// ─── Validation Maps ────────────────────────────────────────────────────────

// Valid WAF modes
var validWAFModes = map[string]bool{
	"enabled":        true,
	"detection_only": true,
	"disabled":       true,
}

// Valid CRS v4 built-in exclusion profile names (tx.crs_exclusions_<name>=1).
// See: https://coreruleset.org/docs/concepts/exclusion_profiles/
var validCRSExclusions = map[string]bool{
	"cpanel":     true,
	"drupal":     true,
	"dokuwiki":   true,
	"nextcloud":  true,
	"phpbb":      true,
	"phpmyadmin": true,
	"wordpress":  true,
	"xenforo":    true,
}

// Valid CRS rule group tags that can be disabled
var validRuleGroupTags = map[string]bool{
	"attack-protocol":         true, // Protocol Enforcement (920xxx) + Protocol Attack (921xxx)
	"attack-lfi":              true, // Local File Inclusion (930xxx)
	"attack-rfi":              true, // Remote File Inclusion (931xxx)
	"attack-rce":              true, // Remote Code Execution (932xxx)
	"attack-injection-php":    true, // PHP Injection (933xxx)
	"attack-injection-nodejs": true, // Node.js Injection (934xxx)
	"attack-xss":              true, // Cross-Site Scripting (941xxx)
	"attack-sqli":             true, // SQL Injection (942xxx)
	"attack-fixation":         true, // Session Fixation (943xxx)
	"attack-injection-java":   true, // Java Injection (944xxx)
}

// Valid exclusion types
var validExclusionTypes = map[string]bool{
	// Advanced (ModSecurity directive types)
	"remove_by_id":                 true,
	"remove_by_tag":                true,
	"update_target_by_id":          true,
	"update_target_by_tag":         true,
	"runtime_remove_by_id":         true,
	"runtime_remove_by_tag":        true,
	"runtime_remove_target_by_id":  true,
	"runtime_remove_target_by_tag": true,
	// Quick Actions (condition-based)
	"allow":     true, // Whitelist — bypass WAF checks
	"block":     true, // Deny requests
	"skip_rule": true, // Skip specific CRS rules
	"anomaly":   true, // Add anomaly score points (heuristic signal)
	// Honeypot (dynamic path groups)
	"honeypot": true, // Known-bad path traps — instant deny
	// Raw editor
	"raw": true, // Raw SecRule directive
}

// Valid condition fields
var validConditionFields = map[string]bool{
	"ip":              true,
	"path":            true,
	"host":            true,
	"method":          true,
	"user_agent":      true,
	"header":          true,
	"query":           true,
	"country":         true,
	"cookie":          true,
	"body":            true,
	"body_json":       true,
	"body_form":       true,
	"args":            true,
	"uri_path":        true,
	"referer":         true,
	"response_header": true,
	"response_status": true,
	"http_version":    true,
}

// validPolicyEngineFields are the condition fields supported by the Caddy
// policy engine plugin. Only request-phase fields are available — response_header
// and response_status are rejected because the plugin runs before the backend.
// This is the same set as RL condition fields plus "args" (query string args).
var validPolicyEngineFields = map[string]bool{
	"ip":           true,
	"path":         true,
	"host":         true,
	"method":       true,
	"user_agent":   true,
	"header":       true,
	"query":        true,
	"country":      true,
	"cookie":       true,
	"body":         true,
	"body_json":    true,
	"body_form":    true,
	"args":         true,
	"uri_path":     true,
	"referer":      true,
	"http_version": true,
}

// Valid operators per field type
var validOperatorsForField = map[string]map[string]bool{
	"ip": {
		"eq": true, "neq": true, "ip_match": true, "not_ip_match": true,
		"in_list": true, "not_in_list": true,
	},
	"path": {
		"eq": true, "neq": true, "contains": true, "begins_with": true,
		"ends_with": true, "regex": true, "in": true,
		"in_list": true, "not_in_list": true,
	},
	"host": {
		"eq": true, "neq": true, "contains": true,
		"in_list": true, "not_in_list": true,
	},
	"method": {
		"eq": true, "neq": true, "in": true,
		"in_list": true, "not_in_list": true,
	},
	"user_agent": {
		"eq": true, "contains": true, "regex": true, "in": true,
		"in_list": true, "not_in_list": true,
	},
	"header": {
		"eq": true, "contains": true, "regex": true,
		"in_list": true, "not_in_list": true,
	},
	"query": {
		"contains": true, "regex": true,
		"in_list": true, "not_in_list": true,
	},
	"country": {
		"eq": true, "neq": true, "in": true,
		"in_list": true, "not_in_list": true,
	},
	"cookie": {
		"eq": true, "neq": true, "contains": true, "regex": true,
		"in_list": true, "not_in_list": true,
	},
	"body": {
		"eq": true, "contains": true, "begins_with": true, "ends_with": true, "regex": true,
		"in_list": true, "not_in_list": true,
	},
	"body_json": {
		"eq": true, "contains": true, "regex": true, "exists": true,
		"in_list": true, "not_in_list": true,
	},
	"body_form": {
		"eq": true, "contains": true, "regex": true,
		"in_list": true, "not_in_list": true,
	},
	"args": {
		"eq": true, "neq": true, "contains": true, "regex": true,
		"in_list": true, "not_in_list": true,
	},
	"uri_path": {
		"eq": true, "neq": true, "contains": true, "begins_with": true,
		"ends_with": true, "regex": true,
		"in_list": true, "not_in_list": true,
	},
	"referer": {
		"eq": true, "neq": true, "contains": true, "regex": true,
		"in_list": true, "not_in_list": true,
	},
	"response_header": {
		"eq": true, "contains": true, "regex": true,
		"in_list": true, "not_in_list": true,
	},
	"response_status": {
		"eq": true, "neq": true, "in": true,
		"in_list": true, "not_in_list": true,
	},
	"http_version": {
		"eq": true, "neq": true,
		"in_list": true, "not_in_list": true,
	},
}

// Valid group operators
var validGroupOperators = map[string]bool{
	"":    true, // default = "and"
	"and": true,
	"or":  true,
}
