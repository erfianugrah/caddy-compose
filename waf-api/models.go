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
	// Rule match data (from audit log messages/part H)
	RuleID      int      `json:"rule_id,omitempty"`
	RuleMsg     string   `json:"rule_msg,omitempty"`
	Severity    int      `json:"severity,omitempty"`
	MatchedData string   `json:"matched_data,omitempty"`
	RuleTags    []string `json:"rule_tags,omitempty"`
}

// API response types

type SummaryResponse struct {
	TotalEvents      int             `json:"total_events"`
	BlockedEvents    int             `json:"blocked_events"`
	LoggedEvents     int             `json:"logged_events"`
	UniqueClients    int             `json:"unique_clients"`
	UniqueServices   int             `json:"unique_services"`
	EventsByHour     []HourCount     `json:"events_by_hour"`
	TopServices      []ServiceCount  `json:"top_services"`
	TopClients       []ClientCount   `json:"top_clients"`
	TopURIs          []URICount      `json:"top_uris"`
	ServiceBreakdown []ServiceDetail `json:"service_breakdown"`
	RecentBlocks     []Event         `json:"recent_blocks"`
}

type HourCount struct {
	Hour    string `json:"hour"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
	Logged  int    `json:"logged"`
}

type ServiceCount struct {
	Service string `json:"service"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
	Logged  int    `json:"logged"`
}

type ClientCount struct {
	Client  string `json:"client"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
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
	Service string `json:"service"`
	Total   int    `json:"total"`
	Blocked int    `json:"blocked"`
	Logged  int    `json:"logged"`
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

// WAF Configuration model

type WAFConfig struct {
	ParanoiaLevel     int                      `json:"paranoia_level"`
	InboundThreshold  int                      `json:"inbound_threshold"`
	OutboundThreshold int                      `json:"outbound_threshold"`
	RuleEngine        string                   `json:"rule_engine"`
	Services          map[string]ServiceConfig `json:"services"`
}

type ServiceConfig struct {
	Profile string `json:"profile"`
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
	Total     int     `json:"total"`
	Blocked   int     `json:"blocked"`
	BlockRate float64 `json:"block_rate"`
	FirstSeen string  `json:"first_seen"`
	LastSeen  string  `json:"last_seen"`
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
