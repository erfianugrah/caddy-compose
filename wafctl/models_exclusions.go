package main

import "time"

// ─── WAF Policy Engine: Exclusions & Configuration ──────────────────────────

// Condition represents a single match condition in an exclusion or rate limit rule.
type Condition struct {
	Field      string   `json:"field"`    // single: "ip", "path", "host", etc. | aggregate: "all_args", "all_headers", etc. | count: "count:all_args", etc.
	Operator   string   `json:"operator"` // "eq", "neq", "contains", "not_contains", "begins_with", "not_begins_with", "ends_with", "not_ends_with", "regex", "not_regex", "ip_match", "not_ip_match", "in", "not_in", "phrase_match", "not_phrase_match", "gt", "ge", "lt", "le"
	Value      string   `json:"value"`
	Transforms []string `json:"transforms,omitempty"`  // ordered transform chain: "lowercase", "urlDecode", "htmlEntityDecode", etc.
	Negate     bool     `json:"negate,omitempty"`      // CRS !@ prefix — inverts operator result
	MultiMatch bool     `json:"multi_match,omitempty"` // CRS multiMatch — run operator at each transform stage
	ListItems  []string `json:"list_items,omitempty"`  // patterns for phrase_match (inline, not from managed list)
}

// SkipTargets specifies what a "skip" rule should bypass.
// Used only when RuleExclusion.Type == "skip".
type SkipTargets struct {
	Rules        []string `json:"rules,omitempty"`         // Specific rule IDs to skip
	Phases       []string `json:"phases,omitempty"`        // Entire phases: "detect", "rate_limit", "block"
	AllRemaining bool     `json:"all_remaining,omitempty"` // Skip everything below this rule
}

// RuleExclusion is a single WAF policy engine rule.
// Types: allow, block, challenge, skip, detect, rate_limit, response_header.
type RuleExclusion struct {
	// ─── Common fields (all types) ──────────────────────────────────
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Type        string      `json:"type"`                     // allow|block|challenge|skip|detect|rate_limit|response_header
	Phase       string      `json:"phase,omitempty"`          // "inbound" (default) or "outbound" for response-phase rules
	Conditions  []Condition `json:"conditions,omitempty"`     // Dynamic conditions (field/operator/value)
	GroupOp     string      `json:"group_operator,omitempty"` // "and" (default) or "or"
	Service     string      `json:"service,omitempty"`        // hostname, "*", or short name — scopes rule to a service
	Priority    int         `json:"priority,omitempty"`       // Explicit ordering within type band (0 = auto from position)
	Tags        []string    `json:"tags,omitempty"`           // Event classification tags (e.g., "scanner", "honeypot", "blocklist")
	Enabled     bool        `json:"enabled"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`

	// ─── skip-only ──────────────────────────────────────────────────
	SkipTargets *SkipTargets `json:"skip_targets,omitempty"` // What to bypass

	// ─── detect-only ────────────────────────────────────────────────
	Severity            string `json:"severity,omitempty"`              // CRITICAL, ERROR, WARNING, NOTICE
	DetectParanoiaLevel int    `json:"detect_paranoia_level,omitempty"` // 1-4 (0 = all levels)
	DetectAction        string `json:"detect_action,omitempty"`         // "" (default=score) or "log_only" (evaluate & log but don't add to anomaly score)

	// ─── rate_limit-only ────────────────────────────────────────────
	RateLimitKey    string `json:"rate_limit_key,omitempty"`    // "client_ip", "header:X-API-Key", "client_ip+path", etc.
	RateLimitEvents int    `json:"rate_limit_events,omitempty"` // Max events in window
	RateLimitWindow string `json:"rate_limit_window,omitempty"` // Duration: "1m", "30s", "1h"
	RateLimitAction string `json:"rate_limit_action,omitempty"` // "deny" (default 429) or "log_only"

	// ─── challenge-only ─────────────────────────────────────────────
	// Proof-of-work challenge settings. Plugin serves an interstitial page
	// requiring SHA-256 hashcash before proxying to upstream.
	ChallengeDifficulty int    `json:"challenge_difficulty,omitempty"` // Leading hex zeros in SHA-256 (1-16, default 4)
	ChallengeAlgorithm  string `json:"challenge_algorithm,omitempty"`  // "fast" (default) or "slow"
	ChallengeTTL        string `json:"challenge_ttl,omitempty"`        // Cookie lifetime: "1h" (default), "24h", "7d"
	ChallengeBindIP     *bool  `json:"challenge_bind_ip,omitempty"`    // Bind cookie to client IP (default true)

	// ─── response_header-only ───────────────────────────────────────
	// Actions on response headers. Multiple can be combined in one rule.
	// Plugin applies these to matching responses (conditions + phase=outbound).
	HeaderSet     map[string]string `json:"header_set,omitempty"`     // Set header (overrides existing)
	HeaderAdd     map[string]string `json:"header_add,omitempty"`     // Add header (appends, preserves existing)
	HeaderRemove  []string          `json:"header_remove,omitempty"`  // Remove headers by name
	HeaderDefault map[string]string `json:"header_default,omitempty"` // Set only if not already present (? prefix in Caddyfile)
}

// ─── WAF Configuration ──────────────────────────────────────────────────────

// WAFConfig holds the WAF configuration with per-service overrides.
// Defaults are applied to any service without an explicit override.
// Services map hostname → per-service overrides.
type WAFConfig struct {
	Defaults        WAFServiceSettings            `json:"defaults"`
	Services        map[string]WAFServiceSettings `json:"services"`
	RateLimitGlobal RateLimitGlobalConfig         `json:"rate_limit_global,omitempty"` // Global RL settings (sweep interval, jitter)
}

// WAFServiceSettings controls WAF behavior for a service (or as defaults).
type WAFServiceSettings struct {
	// ParanoiaLevel: CRS paranoia level 1-4 (higher = more rules, more false positives)
	ParanoiaLevel int `json:"paranoia_level"`
	// InboundThreshold: anomaly score threshold for inbound requests (lower = stricter)
	InboundThreshold int `json:"inbound_threshold"`
	// OutboundThreshold: anomaly score threshold for outbound responses
	OutboundThreshold int `json:"outbound_threshold"`
	// DisabledCategories: CRS rule ID prefixes to skip (e.g., "942" for SQLi, "941" for XSS).
	// Per-service overrides replace the global list (not merge).
	DisabledCategories []string `json:"disabled_categories,omitempty"`
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

// Valid exclusion types — policy engine only.
var validExclusionTypes = map[string]bool{
	"allow":           true, // Full bypass — terminates evaluation immediately
	"block":           true, // Deny requests (403)
	"challenge":       true, // Proof-of-work interstitial (SHA-256 hashcash)
	"skip":            true, // Selective bypass — carries skip_targets (non-terminating)
	"detect":          true, // Anomaly scoring via policy engine (CRITICAL/ERROR/WARNING/NOTICE)
	"rate_limit":      true, // Sliding window rate limiting (429 or log_only)
	"response_header": true, // Set/add/remove/default response headers
}

// Valid condition fields
var validConditionFields = map[string]bool{
	"ip":               true,
	"path":             true,
	"host":             true,
	"method":           true,
	"user_agent":       true,
	"header":           true,
	"query":            true,
	"country":          true,
	"cookie":           true,
	"body":             true,
	"body_json":        true,
	"body_form":        true,
	"args":             true,
	"uri_path":         true,
	"referer":          true,
	"response_header":  true,
	"response_status":  true,
	"http_version":     true,
	"request_combined": true,
}

// validPolicyEngineFields are the inbound (request-phase) condition fields
// supported by the Caddy policy engine plugin.
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
	// v0.9.0: aggregate fields (multi-variable inspection)
	"all_args":          true,
	"all_args_values":   true,
	"all_args_names":    true,
	"all_headers":       true,
	"all_headers_names": true,
	"all_cookies":       true,
	"all_cookies_names": true,
	"request_combined":  true,
}

// validOutboundFields are the response-phase condition fields available when
// phase="outbound". These are in addition to all inbound fields.
var validOutboundFields = map[string]bool{
	"response_header":       true,
	"response_status":       true,
	"response_content_type": true,
}

// validPhases are the valid values for the Phase field on a rule.
var validPhases = map[string]bool{
	"":         true, // default = inbound
	"inbound":  true,
	"outbound": true,
}

// validTransforms are the transform function names supported by the policy
// engine plugin (v0.8.1+). Transforms are applied left-to-right to the
// extracted field value before operator evaluation.
var validTransforms = map[string]bool{
	// Phase 1 — covers ~90% of CRS usage
	"lowercase":          true,
	"urlDecode":          true,
	"urlDecodeUni":       true,
	"htmlEntityDecode":   true,
	"normalizePath":      true,
	"normalizePathWin":   true,
	"removeNulls":        true,
	"compressWhitespace": true,
	"removeWhitespace":   true,
	// Phase 2 — extended transforms
	"base64Decode":   true,
	"hexDecode":      true,
	"jsDecode":       true,
	"cssDecode":      true,
	"utf8toUnicode":  true,
	"removeComments": true,
	"trim":           true,
	"length":         true,
}

// validAggregateFields are the multi-variable fields that can be used with count:.
var validAggregateFields = map[string]bool{
	"all_args":          true,
	"all_args_values":   true,
	"all_args_names":    true,
	"all_headers":       true,
	"all_headers_names": true,
	"all_cookies":       true,
	"all_cookies_names": true,
	"request_combined":  true,
}

// Valid operators per field type.
// Negated operators (not_contains, not_begins_with, not_ends_with, not_regex,
// not_in, not_phrase_match) are the explicit-negation variants added in plugin
// v0.10.0. They mirror their positive counterparts per field.
var validOperatorsForField = map[string]map[string]bool{
	// --- IP field: CIDR-aware matching + set operators ---
	"ip": {
		"eq": true, "neq": true,
		"in": true, "not_in": true,
		"ip_match": true, "not_ip_match": true,
		"in_list": true, "not_in_list": true,
	},
	// --- String fields: full operator set ---
	"path": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"host": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"user_agent": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"header": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"query": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"cookie": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"body": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"body_json": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"exists":       true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"body_form": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"args": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"uri_path": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"referer": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"response_header": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	// --- Enum fields: set-based operators ---
	"method": {
		"eq": true, "neq": true, "in": true, "not_in": true,
		"in_list": true, "not_in_list": true,
	},
	"country": {
		"eq": true, "neq": true, "in": true, "not_in": true,
		"in_list": true, "not_in_list": true,
	},
	"response_status": {
		"eq": true, "neq": true, "in": true, "not_in": true,
		"in_list": true, "not_in_list": true,
	},
	"response_content_type": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"in": true, "not_in": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"http_version": {
		"eq": true, "neq": true, "in": true, "not_in": true,
		"in_list": true, "not_in_list": true,
	},
	// v0.9.0: aggregate fields — support all string operators + negated variants
	"all_args": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"all_args_values": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"all_args_names": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"all_headers": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"all_headers_names": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"all_cookies": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	"all_cookies_names": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
	// v0.10.0: request_combined — all request variables concatenated (CRS multi-variable rules)
	"request_combined": {
		"eq": true, "neq": true, "contains": true, "not_contains": true,
		"begins_with": true, "not_begins_with": true,
		"ends_with": true, "not_ends_with": true,
		"regex": true, "not_regex": true,
		"phrase_match": true, "not_phrase_match": true,
		"in_list": true, "not_in_list": true,
	},
}

// Valid group operators
var validGroupOperators = map[string]bool{
	"":    true, // default = "and"
	"and": true,
	"or":  true,
}
