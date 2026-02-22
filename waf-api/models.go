package main

import "time"

// Raw JSON structure from Coraza audit log

type AuditLogEntry struct {
	Transaction Transaction `json:"transaction"`
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
}

// API response types

type SummaryResponse struct {
	TotalEvents    int            `json:"total_events"`
	BlockedEvents  int            `json:"blocked_events"`
	LoggedEvents   int            `json:"logged_events"`
	UniqueClients  int            `json:"unique_clients"`
	UniqueServices int            `json:"unique_services"`
	EventsByHour   []HourCount    `json:"events_by_hour"`
	TopServices    []ServiceCount `json:"top_services"`
	TopClients     []ClientCount  `json:"top_clients"`
	TopURIs        []URICount     `json:"top_uris"`
}

type HourCount struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

type ServiceCount struct {
	Service string `json:"service"`
	Count   int    `json:"count"`
}

type ClientCount struct {
	Client string `json:"client"`
	Count  int    `json:"count"`
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

type RuleExclusion struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        string    `json:"type"`
	RuleID      string    `json:"rule_id"`
	RuleTag     string    `json:"rule_tag"`
	Variable    string    `json:"variable"`
	Condition   string    `json:"condition"`
	Service     string    `json:"service"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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

// Valid exclusion types
var validExclusionTypes = map[string]bool{
	"remove_by_id":                true,
	"remove_by_tag":               true,
	"update_target_by_id":         true,
	"update_target_by_tag":        true,
	"runtime_remove_by_id":        true,
	"runtime_remove_by_tag":       true,
	"runtime_remove_target_by_id": true,
}

// Valid hours filter values
var validHours = map[int]bool{
	1:   true,
	6:   true,
	24:  true,
	72:  true,
	168: true,
}
