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

// CFProxyStatsResponse is returned by the CF proxy stats endpoint.
type CFProxyStatsResponse struct {
	CIDRCount   int    `json:"cidr_count"`
	LastUpdated string `json:"last_updated"`
	Source      string `json:"source"`
	FilePath    string `json:"file_path"`
}

// CFProxyRefreshResponse is returned by the CF proxy refresh endpoint.
type CFProxyRefreshResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	CIDRCount   int    `json:"cidr_count"`
	IPv4Count   int    `json:"ipv4_count"`
	IPv6Count   int    `json:"ipv6_count"`
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
