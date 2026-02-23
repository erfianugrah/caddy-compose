package main

import "time"

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

type ServiceDetail struct {
	Service      string `json:"service"`
	Total        int    `json:"total"`
	Blocked      int    `json:"blocked"`
	Logged       int    `json:"logged"`
	RateLimited  int    `json:"rate_limited"`
	IpsumBlocked int    `json:"ipsum_blocked"`
	Honeypot     int    `json:"honeypot"`
	Scanner      int    `json:"scanner"`
	Policy       int    `json:"policy"`
}

type ServicesResponse struct {
	Services []ServiceDetail `json:"services"`
}

type HealthResponse struct {
	Status string `json:"status"`
}

// IP Lookup response

type IPLookupResponse struct {
	IP        string          `json:"ip"`
	Total     int             `json:"total"`
	Blocked   int             `json:"blocked"`
	FirstSeen *time.Time      `json:"first_seen"`
	LastSeen  *time.Time      `json:"last_seen"`
	Services  []ServiceDetail `json:"services"`
	Events    []Event         `json:"events"`
}

// Rule Exclusion model

type Condition struct {
	Field    string `json:"field"`    // "ip", "path", "host", "method", "user_agent", "header", "query"
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
}

// Valid WAF modes
var validWAFModes = map[string]bool{
	"enabled":        true,
	"detection_only": true,
	"disabled":       true,
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
	"remove_by_id":                true,
	"remove_by_tag":               true,
	"update_target_by_id":         true,
	"update_target_by_tag":        true,
	"runtime_remove_by_id":        true,
	"runtime_remove_by_tag":       true,
	"runtime_remove_target_by_id": true,
	// Quick Actions (condition-based)
	"allow":     true, // Whitelist — bypass WAF checks
	"block":     true, // Deny requests
	"skip_rule": true, // Skip specific CRS rules
	// Raw editor
	"raw": true, // Raw SecRule directive
}

// Valid condition fields
var validConditionFields = map[string]bool{
	"ip":         true,
	"path":       true,
	"host":       true,
	"method":     true,
	"user_agent": true,
	"header":     true,
	"query":      true,
}

// Valid operators per field type
var validOperatorsForField = map[string]map[string]bool{
	"ip": {
		"eq": true, "neq": true, "ip_match": true, "not_ip_match": true,
	},
	"path": {
		"eq": true, "neq": true, "contains": true, "begins_with": true,
		"ends_with": true, "regex": true,
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
}

// Valid group operators
var validGroupOperators = map[string]bool{
	"":    true, // default = "and"
	"and": true,
	"or":  true,
}

// Rate limit zone configuration

type RateLimitZone struct {
	Name    string `json:"name"`
	Events  int    `json:"events"`  // Max events in window
	Window  string `json:"window"`  // Duration string (e.g. "1m", "30s", "1h")
	Enabled bool   `json:"enabled"` // Whether rate limiting is active for this zone
}

type RateLimitConfig struct {
	Zones []RateLimitZone `json:"zones"`
}

// RateLimitDeployResponse is returned by the rate limit deploy endpoint.
type RateLimitDeployResponse struct {
	Status    string   `json:"status"`
	Message   string   `json:"message"`
	Files     []string `json:"files"`
	Reloaded  bool     `json:"reloaded"`
	Timestamp string   `json:"timestamp"`
}

// Valid hours filter values
var validHours = map[int]bool{
	1:   true,
	6:   true,
	24:  true,
	72:  true,
	168: true,
}
