package main

import "time"

// ─── Top-N Result Limits ────────────────────────────────────────────────────

const (
	// topNSummary is the number of top items returned in summary endpoints.
	topNSummary = 10

	// topNAnalytics is the number of top items returned in analytics/detail endpoints.
	topNAnalytics = 20
)

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
	EventType      string    `json:"event_type"`        // "detect_block", "logged", "rate_limited", "policy_skip", "policy_allow", "policy_block"
	Tags           []string  `json:"tags,omitempty"`    // Event classification tags from matched policy rules (e.g., "scanner", "honeypot", "blocklist")
	// How the request was blocked: "anomaly_inbound", "anomaly_outbound", "direct", or ""
	BlockedBy string `json:"blocked_by,omitempty"`
	// Rule match data (from policy engine detection)
	RuleID               int      `json:"rule_id,omitempty"`
	RuleMsg              string   `json:"rule_msg,omitempty"`
	Severity             int      `json:"severity,omitempty"`
	AnomalyScore         int      `json:"anomaly_score,omitempty"`
	OutboundAnomalyScore int      `json:"outbound_anomaly_score,omitempty"`
	MatchedData          string   `json:"matched_data,omitempty"`
	RuleTags             []string `json:"rule_tags,omitempty"`
	// All matched rules (not just the primary/best one)
	MatchedRules []MatchedRule `json:"matched_rules,omitempty"`
	// Caddy-generated UUID for request correlation
	RequestID string `json:"request_id,omitempty"`
	// Request context for full payload inspection
	RequestHeaders map[string][]string `json:"request_headers,omitempty"`
	RequestBody    string              `json:"request_body,omitempty"`
	RequestArgs    map[string]string   `json:"request_args,omitempty"`
	// JA4 TLS fingerprint + challenge fields
	JA4                 string `json:"ja4,omitempty"`                  // JA4 TLS fingerprint from listener wrapper
	ChallengeBotScore   int    `json:"challenge_bot_score,omitempty"`  // bot signal score (0-100) at challenge time
	ChallengeJTI        string `json:"challenge_jti,omitempty"`        // challenge cookie token ID
	ChallengeDifficulty int    `json:"challenge_difficulty,omitempty"` // selected difficulty (after adaptive)
	ChallengeElapsedMs  int    `json:"challenge_elapsed_ms,omitempty"` // client-reported solve time in ms
	ChallengePreScore   int    `json:"challenge_pre_score,omitempty"`  // pre-signal score (L1/L2/L5) that drove difficulty
	// DDoS mitigator fields (populated for ddos_blocked/ddos_jailed events)
	DDoSAction      string `json:"ddos_action,omitempty"`
	DDoSFingerprint string `json:"ddos_fingerprint,omitempty"`
	DDoSScore       string `json:"ddos_score,omitempty"` // behavioral anomaly score
}

// MatchedRule represents a single CRS or policy engine rule match.
type MatchedRule struct {
	ID          int                 `json:"id"`
	Name        string              `json:"name,omitempty"` // rule name/ID string (e.g., "9100034", "920350") — used for PE detect rules
	Msg         string              `json:"msg"`
	Severity    int                 `json:"severity"`
	MatchedData string              `json:"matched_data,omitempty"`
	File        string              `json:"file,omitempty"`
	Tags        []string            `json:"tags,omitempty"`
	Matches     []MatchedRuleDetail `json:"matches,omitempty"` // per-condition match details (detect rules only)
}

// MatchedRuleDetail represents per-condition match data from a detect rule.
// Mirrors the policy engine's matchDetail struct.
type MatchedRuleDetail struct {
	Field       string `json:"field"`                  // condition field (e.g., "all_args_values", "header")
	VarName     string `json:"var_name"`               // CRS-style variable name (e.g., "ARGS:username", "REQUEST_HEADERS:User-Agent")
	Value       string `json:"value,omitempty"`        // actual input value that was tested (truncated)
	MatchedData string `json:"matched_data,omitempty"` // regex group 0, phrase_match hit, or matched literal
	Operator    string `json:"operator,omitempty"`     // operator name (e.g., "regex", "phrase_match")
}

// API response types

type TagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

type SummaryResponse struct {
	TotalEvents      int             `json:"total_events"`
	TotalBlocked     int             `json:"total_blocked"`
	LoggedEvents     int             `json:"logged_events"`
	RateLimited      int             `json:"rate_limited"`
	PolicyEvents     int             `json:"policy_events"`
	PolicyBlocked    int             `json:"policy_blocked"`
	DetectBlocked    int             `json:"detect_blocked"`
	DDoSBlocked      int             `json:"ddos_blocked"`
	PolicyAllowed    int             `json:"policy_allowed"`
	PolicySkipped    int             `json:"policy_skipped"`
	ChallengeIssued  int             `json:"challenge_issued"`
	ChallengePassed  int             `json:"challenge_passed"`
	ChallengeFailed  int             `json:"challenge_failed"`
	UniqueClients    int             `json:"unique_clients"`
	UniqueServices   int             `json:"unique_services"`
	TagCounts        []TagCount      `json:"tag_counts,omitempty"`
	EventsByHour     []HourCount     `json:"events_by_hour"`
	TopServices      []ServiceCount  `json:"top_services"`
	TopClients       []ClientCount   `json:"top_clients"`
	TopCountries     []CountryCount  `json:"top_countries"`
	TopURIs          []URICount      `json:"top_uris"`
	ServiceBreakdown []ServiceDetail `json:"service_breakdown"`
	RecentEvents     []Event         `json:"recent_events"`
}

type HourCount struct {
	Hour            string `json:"hour"`
	Count           int    `json:"count"`
	TotalBlocked    int    `json:"total_blocked"`
	Logged          int    `json:"logged"`
	RateLimited     int    `json:"rate_limited"`
	PolicyBlock     int    `json:"policy_block"`
	DetectBlock     int    `json:"detect_block"`
	DDoSBlocked     int    `json:"ddos_blocked"`
	PolicyAllow     int    `json:"policy_allow"`
	PolicySkip      int    `json:"policy_skip"`
	ChallengeIssued int    `json:"challenge_issued"`
	ChallengePassed int    `json:"challenge_passed"`
	ChallengeFailed int    `json:"challenge_failed"`
}

type ServiceCount struct {
	Service         string `json:"service"`
	Count           int    `json:"count"`
	TotalBlocked    int    `json:"total_blocked"`
	Logged          int    `json:"logged"`
	RateLimited     int    `json:"rate_limited"`
	PolicyBlock     int    `json:"policy_block"`
	DetectBlock     int    `json:"detect_block"`
	DDoSBlocked     int    `json:"ddos_blocked"`
	PolicyAllow     int    `json:"policy_allow"`
	PolicySkip      int    `json:"policy_skip"`
	ChallengeIssued int    `json:"challenge_issued"`
	ChallengePassed int    `json:"challenge_passed"`
	ChallengeFailed int    `json:"challenge_failed"`
}

type ClientCount struct {
	Client          string `json:"client"`
	Country         string `json:"country,omitempty"`
	Count           int    `json:"count"`
	TotalBlocked    int    `json:"total_blocked"`
	RateLimited     int    `json:"rate_limited"`
	PolicyBlock     int    `json:"policy_block"`
	DetectBlock     int    `json:"detect_block"`
	DDoSBlocked     int    `json:"ddos_blocked"`
	PolicyAllow     int    `json:"policy_allow"`
	PolicySkip      int    `json:"policy_skip"`
	ChallengeIssued int    `json:"challenge_issued"`
	ChallengePassed int    `json:"challenge_passed"`
	ChallengeFailed int    `json:"challenge_failed"`
}

// Blocklist API response types

type BlocklistStatsResponse struct {
	BlockedIPs  int    `json:"blocked_ips"`
	LastUpdated string `json:"last_updated"`
	Source      string `json:"source"`
	MinScore    int    `json:"min_score"`
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
	URI          string `json:"uri"`
	Count        int    `json:"count"`
	TotalBlocked int    `json:"total_blocked"`
}

type ServiceRule struct {
	RuleID  int    `json:"rule_id"`
	RuleMsg string `json:"rule_msg"`
	Count   int    `json:"count"`
}

type ServiceDetail struct {
	Service         string        `json:"service"`
	Total           int           `json:"total"`
	TotalBlocked    int           `json:"total_blocked"`
	Logged          int           `json:"logged"`
	RateLimited     int           `json:"rate_limited"`
	PolicyBlock     int           `json:"policy_block"`
	DetectBlock     int           `json:"detect_block"`
	DDoSBlocked     int           `json:"ddos_blocked"`
	PolicyAllow     int           `json:"policy_allow"`
	PolicySkip      int           `json:"policy_skip"`
	ChallengeIssued int           `json:"challenge_issued"`
	ChallengePassed int           `json:"challenge_passed"`
	ChallengeFailed int           `json:"challenge_failed"`
	TopURIs         []ServiceURI  `json:"top_uris,omitempty"`
	TopRules        []ServiceRule `json:"top_rules,omitempty"`
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

type GeoIPInfo struct {
	Country   string `json:"country,omitempty"`   // ISO 3166-1 alpha-2 (e.g., "US")
	City      string `json:"city,omitempty"`      // City name
	Region    string `json:"region,omitempty"`    // Region/state name
	Timezone  string `json:"timezone,omitempty"`  // IANA timezone (e.g., "America/New_York")
	ASN       string `json:"asn,omitempty"`       // AS number (e.g., "AS13335")
	Org       string `json:"org,omitempty"`       // Organization/ISP name
	ASDomain  string `json:"as_domain,omitempty"` // AS domain (e.g., "cloudflare.com")
	Network   string `json:"network,omitempty"`   // CIDR network (e.g., "1.0.0.0/24")
	Continent string `json:"continent,omitempty"` // Continent name (e.g., "Europe")
	Source    string `json:"source,omitempty"`    // Resolution source: "cf_header", "mmdb", "api"
}

// RoutingInfo holds BGP routing intelligence from Team Cymru DNS and RIPE.
type RoutingInfo struct {
	IsAnnounced bool   `json:"is_announced"`           // Whether the prefix is BGP-announced
	ASNumber    string `json:"as_number,omitempty"`    // AS number without "AS" prefix (e.g., "13335")
	ASName      string `json:"as_name,omitempty"`      // AS holder name (e.g., "CLOUDFLARENET - Cloudflare, Inc., US")
	Route       string `json:"route,omitempty"`        // BGP route/prefix (e.g., "1.1.1.0/24")
	ROACount    int    `json:"roa_count,omitempty"`    // Number of validating ROAs
	ROAValidity string `json:"roa_validity,omitempty"` // RPKI status: "valid", "invalid", "unknown", "not_found"
	RIR         string `json:"rir,omitempty"`          // Regional Internet Registry (e.g., "apnic", "arin", "ripe")
	AllocDate   string `json:"alloc_date,omitempty"`   // IP allocation date (e.g., "2011-08-11")
}

// NetworkType holds IP classification flags.
type NetworkType struct {
	IsAnycast bool   `json:"is_anycast,omitempty"` // Anycast IP (inferred from known anycast ASNs)
	IsDC      bool   `json:"is_dc,omitempty"`      // Datacenter/hosting provider
	OrgType   string `json:"org_type,omitempty"`   // "isp", "hosting", "education", "government", "business"
}

// ReputationInfo holds IP reputation data from multiple sources.
type ReputationInfo struct {
	Status      string            `json:"status"`                 // "clean", "suspicious", "malicious", "known_good"
	Sources     []ReputationEntry `json:"sources,omitempty"`      // Per-source breakdown
	IpsumListed bool              `json:"ipsum_listed,omitempty"` // On our IPsum blocklist
}

// ReputationEntry is a single reputation source result.
type ReputationEntry struct {
	Source         string `json:"source"`                   // "greynoise", "stopforumspam", "shodan"
	Status         string `json:"status"`                   // "clean", "malicious", "benign", "noisy"
	Classification string `json:"classification,omitempty"` // GreyNoise: "benign", "malicious", "unknown"
	Name           string `json:"name,omitempty"`           // GreyNoise: known identity (e.g., "Cloudflare Public DNS")
	LastSeen       string `json:"last_seen,omitempty"`      // When the source last observed this IP
}

// ShodanInfo holds Shodan InternetDB data (free, no API key).
type ShodanInfo struct {
	Ports     []int    `json:"ports,omitempty"`     // Open ports
	Hostnames []string `json:"hostnames,omitempty"` // Reverse DNS hostnames
	Tags      []string `json:"tags,omitempty"`      // Shodan tags (e.g., "cloud", "vpn")
	CPEs      []string `json:"cpes,omitempty"`      // CPE identifiers (e.g., "cpe:/a:cloudflare:cloudflare")
	Vulns     []string `json:"vulns,omitempty"`     // Known CVEs
}

// IPIntelligence is the enriched IP intelligence response that wraps all data sources.
type IPIntelligence struct {
	GeoIP      *GeoIPInfo      `json:"geoip,omitempty"`
	Routing    *RoutingInfo    `json:"routing,omitempty"`
	NetType    *NetworkType    `json:"network_type,omitempty"`
	Reputation *ReputationInfo `json:"reputation,omitempty"`
	Shodan     *ShodanInfo     `json:"shodan,omitempty"`
}

type IPLookupResponse struct {
	IP           string          `json:"ip"`
	GeoIP        *GeoIPInfo      `json:"geoip,omitempty"`
	Intelligence *IPIntelligence `json:"intelligence,omitempty"`
	Total        int             `json:"total"`
	TotalBlocked int             `json:"total_blocked"`
	FirstSeen    *time.Time      `json:"first_seen"`
	LastSeen     *time.Time      `json:"last_seen"`
	Services     []ServiceDetail `json:"services"`
	EventsByHour []HourCount     `json:"events_by_hour"`
	Events       []Event         `json:"events"`
	EventsTotal  int             `json:"events_total"`
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
	ClientIP     string  `json:"client_ip"`
	Country      string  `json:"country,omitempty"`
	Total        int     `json:"total"`
	TotalBlocked int     `json:"total_blocked"`
	BlockRate    float64 `json:"block_rate"`
	FirstSeen    string  `json:"first_seen"`
	LastSeen     string  `json:"last_seen"`
}

// CountryCount represents request counts grouped by country code.
type CountryCount struct {
	Country      string `json:"country"`
	Count        int    `json:"count"`
	TotalBlocked int    `json:"total_blocked"`
}

type TopTargetedURI struct {
	URI          string   `json:"uri"`
	Total        int      `json:"total"`
	TotalBlocked int      `json:"total_blocked"`
	Services     []string `json:"services"`
}
