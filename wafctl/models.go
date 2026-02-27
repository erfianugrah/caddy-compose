package main

import "time"

// ─── CRS Scoring & Evaluation Rule IDs ──────────────────────────────────────
// These rules perform anomaly score evaluation and are excluded from
// per-rule analysis (they summarize, not detect).

var scoringRuleIDs = map[int]bool{
	949110: true, // Inbound Anomaly Score Exceeded
	959100: true, // Outbound Anomaly Score Exceeded
	980170: true, // Anomaly Scores (correlation/logging)
}

// isScoringRule returns true for CRS evaluation/scoring rule IDs that should
// be skipped when analysing individual rule matches.
func isScoringRule(id int) bool {
	return id == 0 || scoringRuleIDs[id]
}

// ─── CRS Rule ID Ranges ─────────────────────────────────────────────────────

const (
	// Policy engine generated rules.
	policyRuleIDMin = 9500000
	policyRuleIDMax = 9599999

	// Honeypot path rules.
	honeypotRuleIDMin = 9100020
	honeypotRuleIDMax = 9100029

	// Scanner UA drop rule.
	scannerDropRuleID = 9100032

	// CRS outbound rule range.
	crsOutboundMin = 950000
	crsOutboundMax = 979999
)

// ─── Top-N Result Limits ────────────────────────────────────────────────────

const (
	// topNSummary is the number of top items returned in summary endpoints.
	topNSummary = 10

	// topNAnalytics is the number of top items returned in analytics/detail endpoints.
	topNAnalytics = 20
)

// ─── CRS Severity-to-Score Mapping ──────────────────────────────────────────
// Maps CRS severity levels to anomaly score points per the CRS spec.

var severityScoreMap = map[int]int{
	2: 5, // CRITICAL
	3: 4, // ERROR
	4: 3, // WARNING
	5: 2, // NOTICE
}

// Raw JSON structure from Coraza audit log

type AuditLogEntry struct {
	Transaction Transaction    `json:"transaction"`
	Messages    []AuditMessage `json:"messages,omitempty"`
}

// AuditMessage represents a matched rule in the Coraza audit log (part H).
type AuditMessage struct {
	Actionset string           `json:"actionset"`
	Message   string           `json:"message"`
	Data      AuditMessageData `json:"data"`
}

type AuditMessageData struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`
	ID       int      `json:"id"`
	Rev      string   `json:"rev"`
	Msg      string   `json:"msg"`
	Data     string   `json:"data"`
	Severity int      `json:"severity"`
	Ver      string   `json:"ver"`
	Tags     []string `json:"tags"`
}

type Transaction struct {
	Timestamp       string   `json:"timestamp"`
	UnixTimestamp   int64    `json:"unix_timestamp"`
	ID              string   `json:"id"`
	ClientIP        string   `json:"client_ip"`
	ClientPort      int      `json:"client_port"`
	HostIP          string   `json:"host_ip"`
	HostPort        int      `json:"host_port"`
	ServerID        string   `json:"server_id"`
	Request         Request  `json:"request"`
	Response        Response `json:"response"`
	Producer        Producer `json:"producer"`
	HighestSeverity string   `json:"highest_severity"`
	IsInterrupted   bool     `json:"is_interrupted"`
}

type Request struct {
	Method      string              `json:"method"`
	Protocol    string              `json:"protocol"`
	URI         string              `json:"uri"`
	HTTPVersion string              `json:"http_version"`
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body"`
	Files       []string            `json:"files"`
	Args        map[string]string   `json:"args"`
	Length      int                 `json:"length"`
}

type Response struct {
	Protocol string              `json:"protocol"`
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers"`
	Body     string              `json:"body"`
}

type Producer struct {
	Connector  string   `json:"connector"`
	Version    string   `json:"version"`
	Server     string   `json:"server"`
	RuleEngine string   `json:"rule_engine"`
	Stopwatch  string   `json:"stopwatch"`
	Rulesets   []string `json:"rulesets"`
}

// Normalized internal event used for indexing

type Event struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	ClientIP       string    `json:"client_ip"`
	Service        string    `json:"service"`
	Method         string    `json:"method"`
	URI            string    `json:"uri"`
	Protocol       string    `json:"protocol"`
	IsBlocked      bool      `json:"is_blocked"`
	ResponseStatus int       `json:"response_status"`
	UserAgent      string    `json:"user_agent"`
	Country        string    `json:"country,omitempty"` // ISO 3166-1 alpha-2 country code (e.g., "US", "DE")
	EventType      string    `json:"event_type"`        // "blocked", "logged", "rate_limited", "ipsum_blocked", "policy_skip", "policy_allow", "policy_block", "honeypot", "scanner"
	// How the request was blocked: "anomaly_inbound", "anomaly_outbound", "direct", or ""
	BlockedBy string `json:"blocked_by,omitempty"`
	// Rule match data (from audit log messages/part H)
	RuleID               int      `json:"rule_id,omitempty"`
	RuleMsg              string   `json:"rule_msg,omitempty"`
	Severity             int      `json:"severity,omitempty"`
	AnomalyScore         int      `json:"anomaly_score,omitempty"`
	OutboundAnomalyScore int      `json:"outbound_anomaly_score,omitempty"`
	MatchedData          string   `json:"matched_data,omitempty"`
	RuleTags             []string `json:"rule_tags,omitempty"`
	// All matched rules (not just the primary/best one)
	MatchedRules []MatchedRule `json:"matched_rules,omitempty"`
	// Request context for full payload inspection
	RequestHeaders map[string][]string `json:"request_headers,omitempty"`
	RequestBody    string              `json:"request_body,omitempty"`
	RequestArgs    map[string]string   `json:"request_args,omitempty"`
}

// MatchedRule represents a single CRS rule match from the audit log.
type MatchedRule struct {
	ID          int      `json:"id"`
	Msg         string   `json:"msg"`
	Severity    int      `json:"severity"`
	MatchedData string   `json:"matched_data,omitempty"`
	File        string   `json:"file,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// API response types

type SummaryResponse struct {
	TotalEvents      int             `json:"total_events"`
	BlockedEvents    int             `json:"blocked_events"`
	LoggedEvents     int             `json:"logged_events"`
	RateLimited      int             `json:"rate_limited"`
	IpsumBlocked     int             `json:"ipsum_blocked"`
	PolicyEvents     int             `json:"policy_events"`
	HoneypotEvents   int             `json:"honeypot_events"`
	ScannerEvents    int             `json:"scanner_events"`
	UniqueClients    int             `json:"unique_clients"`
	UniqueServices   int             `json:"unique_services"`
	EventsByHour     []HourCount     `json:"events_by_hour"`
	TopServices      []ServiceCount  `json:"top_services"`
	TopClients       []ClientCount   `json:"top_clients"`
	TopCountries     []CountryCount  `json:"top_countries"`
	TopURIs          []URICount      `json:"top_uris"`
	ServiceBreakdown []ServiceDetail `json:"service_breakdown"`
	RecentEvents     []Event         `json:"recent_events"`
}

type HourCount struct {
	Hour         string `json:"hour"`
	Count        int    `json:"count"`
	Blocked      int    `json:"blocked"`
	Logged       int    `json:"logged"`
	RateLimited  int    `json:"rate_limited"`
	IpsumBlocked int    `json:"ipsum_blocked"`
	Honeypot     int    `json:"honeypot"`
	Scanner      int    `json:"scanner"`
	Policy       int    `json:"policy"`
}

type ServiceCount struct {
	Service      string `json:"service"`
	Count        int    `json:"count"`
	Blocked      int    `json:"blocked"`
	Logged       int    `json:"logged"`
	RateLimited  int    `json:"rate_limited"`
	IpsumBlocked int    `json:"ipsum_blocked"`
	Honeypot     int    `json:"honeypot"`
	Scanner      int    `json:"scanner"`
	Policy       int    `json:"policy"`
}

type ClientCount struct {
	Client       string `json:"client"`
	Country      string `json:"country,omitempty"`
	Count        int    `json:"count"`
	Blocked      int    `json:"blocked"`
	RateLimited  int    `json:"rate_limited"`
	IpsumBlocked int    `json:"ipsum_blocked"`
	Honeypot     int    `json:"honeypot"`
	Scanner      int    `json:"scanner"`
	Policy       int    `json:"policy"`
}

// Blocklist API response types

type BlocklistStatsResponse struct {
	BlockedIPs  int    `json:"blocked_ips"`
	LastUpdated string `json:"last_updated"`
	Source      string `json:"source"`
	MinScore    int    `json:"min_score"`
	FilePath    string `json:"file_path"`
}

type BlocklistCheckResponse struct {
	IP      string `json:"ip"`
	Blocked bool   `json:"blocked"`
	Source  string `json:"source"`
}

// BlocklistRefreshResponse is returned by the refresh endpoint after
// downloading and applying a fresh IPsum blocklist.
type BlocklistRefreshResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	BlockedIPs  int    `json:"blocked_ips"`
	MinScore    int    `json:"min_score"`
	LastUpdated string `json:"last_updated"`
	Reloaded    bool   `json:"reloaded"`
}

type URICount struct {
	URI   string `json:"uri"`
	Count int    `json:"count"`
}

type EventsResponse struct {
	Total  int     `json:"total"`
	Events []Event `json:"events"`
}

type ServiceURI struct {
	URI     string `json:"uri"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
}

type ServiceRule struct {
	RuleID  int    `json:"rule_id"`
	RuleMsg string `json:"rule_msg"`
	Count   int    `json:"count"`
}

type ServiceDetail struct {
	Service      string        `json:"service"`
	Total        int           `json:"total"`
	Blocked      int           `json:"blocked"`
	Logged       int           `json:"logged"`
	RateLimited  int           `json:"rate_limited"`
	IpsumBlocked int           `json:"ipsum_blocked"`
	Honeypot     int           `json:"honeypot"`
	Scanner      int           `json:"scanner"`
	Policy       int           `json:"policy"`
	TopURIs      []ServiceURI  `json:"top_uris,omitempty"`
	TopRules     []ServiceRule `json:"top_rules,omitempty"`
}

type ServicesResponse struct {
	Services []ServiceDetail `json:"services"`
}

type HealthResponse struct {
	Status     string         `json:"status"`
	Version    string         `json:"version"`
	CRSVersion string         `json:"crs_version"`
	Uptime     string         `json:"uptime"`
	Stores     map[string]any `json:"stores"`
}

// IP Lookup response

type IPLookupResponse struct {
	IP          string          `json:"ip"`
	Total       int             `json:"total"`
	Blocked     int             `json:"blocked"`
	FirstSeen   *time.Time      `json:"first_seen"`
	LastSeen    *time.Time      `json:"last_seen"`
	Services    []ServiceDetail `json:"services"`
	Events      []Event         `json:"events"`
	EventsTotal int             `json:"events_total"`
}

// Rule Exclusion model

type Condition struct {
	Field    string `json:"field"`    // "ip", "path", "host", "method", "user_agent", "header", "query", "country", "cookie", "body", "args", "uri_path", "referer", "response_header", "response_status", "http_version"
	Operator string `json:"operator"` // "eq", "neq", "contains", "begins_with", "ends_with", "regex", "ip_match", "not_ip_match", "in"
	Value    string `json:"value"`
}

type RuleExclusion struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Type        string      `json:"type"`
	Conditions  []Condition `json:"conditions,omitempty"`     // Dynamic conditions (field/operator/value)
	GroupOp     string      `json:"group_operator,omitempty"` // "and" (default) or "or"
	RuleID      string      `json:"rule_id,omitempty"`        // For skip_rule + advanced types
	RuleTag     string      `json:"rule_tag,omitempty"`       // For skip_rule + advanced types
	Variable    string      `json:"variable,omitempty"`       // For advanced target types
	RawRule     string      `json:"raw_rule,omitempty"`       // Raw SecRule directive for raw editor
	Enabled     bool        `json:"enabled"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// WAF Configuration model — per-service dynamic WAF settings.
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

// Config generation response

type GenerateResponse struct {
	PreCRS  string `json:"pre_crs_conf"`
	PostCRS string `json:"post_crs_conf"`
}

// API error response

type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// Exclusion export/import wrapper

type ExclusionExport struct {
	Version    int             `json:"version"`
	ExportedAt time.Time       `json:"exported_at"`
	Exclusions []RuleExclusion `json:"exclusions"`
}

// Analytics response types

type TopBlockedIP struct {
	ClientIP  string  `json:"client_ip"`
	Country   string  `json:"country,omitempty"`
	Total     int     `json:"total"`
	Blocked   int     `json:"blocked"`
	BlockRate float64 `json:"block_rate"`
	FirstSeen string  `json:"first_seen"`
	LastSeen  string  `json:"last_seen"`
}

// CountryCount represents request counts grouped by country code.
type CountryCount struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
}

type TopTargetedURI struct {
	URI      string   `json:"uri"`
	Total    int      `json:"total"`
	Blocked  int      `json:"blocked"`
	Services []string `json:"services"`
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
	"args":            true,
	"uri_path":        true,
	"referer":         true,
	"response_header": true,
	"response_status": true,
	"http_version":    true,
}

// Valid operators per field type
var validOperatorsForField = map[string]map[string]bool{
	"ip": {
		"eq": true, "neq": true, "ip_match": true, "not_ip_match": true,
	},
	"path": {
		"eq": true, "neq": true, "contains": true, "begins_with": true,
		"ends_with": true, "regex": true, "in": true,
	},
	"host": {
		"eq": true, "neq": true, "contains": true,
	},
	"method": {
		"eq": true, "neq": true, "in": true,
	},
	"user_agent": {
		"eq": true, "contains": true, "regex": true,
	},
	"header": {
		"eq": true, "contains": true, "regex": true,
	},
	"query": {
		"contains": true, "regex": true,
	},
	"country": {
		"eq": true, "neq": true, "in": true,
	},
	"cookie": {
		"eq": true, "neq": true, "contains": true, "regex": true,
	},
	"body": {
		"contains": true, "regex": true,
	},
	"args": {
		"eq": true, "neq": true, "contains": true, "regex": true,
	},
	"uri_path": {
		"eq": true, "neq": true, "contains": true, "begins_with": true,
		"ends_with": true, "regex": true,
	},
	"referer": {
		"eq": true, "neq": true, "contains": true, "regex": true,
	},
	"response_header": {
		"eq": true, "contains": true, "regex": true,
	},
	"response_status": {
		"eq": true, "neq": true, "in": true,
	},
	"http_version": {
		"eq": true, "neq": true,
	},
}

// Valid group operators
var validGroupOperators = map[string]bool{
	"":    true, // default = "and"
	"and": true,
	"or":  true,
}

// ─── Rate Limit Policy Engine ───────────────────────────────────────

// RateLimitRule is a single rate-limiting policy with conditions and key config.
// Analogous to RuleExclusion for the WAF policy engine.
type RateLimitRule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Service     string      `json:"service"`                  // hostname or "*" for all services
	Conditions  []Condition `json:"conditions,omitempty"`     // Reuse existing Condition type
	GroupOp     string      `json:"group_operator,omitempty"` // "and" (default) or "or"
	Key         string      `json:"key"`                      // "client_ip", "header:X-API-Key", "client_ip+path", "static", etc.
	Events      int         `json:"events"`                   // Max events in window
	Window      string      `json:"window"`                   // Duration string: "1m", "30s", "1h"
	Action      string      `json:"action,omitempty"`         // "deny" (default 429) or "log_only"
	Priority    int         `json:"priority,omitempty"`       // Lower = evaluated first (0 = default)
	Enabled     bool        `json:"enabled"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// RateLimitRuleConfig wraps the list of rules plus global settings.
type RateLimitRuleConfig struct {
	Rules  []RateLimitRule       `json:"rules"`
	Global RateLimitGlobalConfig `json:"global"`
}

// RateLimitGlobalConfig holds settings applied to all generated rate_limit blocks.
type RateLimitGlobalConfig struct {
	Jitter        float64 `json:"jitter,omitempty"`         // 0.0–1.0, randomize Retry-After
	SweepInterval string  `json:"sweep_interval,omitempty"` // e.g. "1m" (default)
	Distributed   bool    `json:"distributed,omitempty"`    // Enable cross-instance RL
	ReadInterval  string  `json:"read_interval,omitempty"`  // Distributed: how often to read other instances
	WriteInterval string  `json:"write_interval,omitempty"` // Distributed: how often to write own state
	PurgeAge      string  `json:"purge_age,omitempty"`      // Distributed: age for purging stale state
}

// RateLimitRuleExport wraps rules for export/import.
type RateLimitRuleExport struct {
	Version    int                   `json:"version"`
	ExportedAt time.Time             `json:"exported_at"`
	Rules      []RateLimitRule       `json:"rules"`
	Global     RateLimitGlobalConfig `json:"global"`
}

// RateLimitDeployResponse is returned by the rate limit deploy endpoint.
type RateLimitDeployResponse struct {
	Status    string   `json:"status"`
	Message   string   `json:"message"`
	Files     []string `json:"files"`
	Reloaded  bool     `json:"reloaded"`
	Timestamp string   `json:"timestamp"`
}

// RateLimitZone is the legacy zone model, kept for migration only.
type RateLimitZone struct {
	Name    string `json:"name"`
	Events  int    `json:"events"`
	Window  string `json:"window"`
	Enabled bool   `json:"enabled"`
}

// Valid rate limit rule keys
var validRLKeys = map[string]bool{
	"client_ip":        true,
	"path":             true,
	"static":           true,
	"client_ip+path":   true,
	"client_ip+method": true,
}

// validRLKeyPrefixes are key prefixes that take a parameter (e.g. "header:X-API-Key")
var validRLKeyPrefixes = []string{"header:", "cookie:"}

// Valid rate limit actions
var validRLActions = map[string]bool{
	"":         true, // default = "deny"
	"deny":     true,
	"log_only": true,
}

// rlConditionFields are the subset of condition fields valid for rate limit rules.
// Response-phase fields are excluded since rate limiting is a request-phase decision.
var validRLConditionFields = map[string]bool{
	"ip":           true,
	"path":         true,
	"host":         true,
	"method":       true,
	"user_agent":   true,
	"header":       true,
	"query":        true,
	"country":      true,
	"cookie":       true,
	"uri_path":     true,
	"referer":      true,
	"http_version": true,
}

// Valid hours filter values
var validHours = map[int]bool{
	1:   true,
	6:   true,
	24:  true,
	72:  true,
	168: true,
}
