package main

import "time"

// ─── General Log Viewer ─────────────────────────────────────────────────────

// GeneralLogEvent is a lightweight representation of any HTTP request/response
// from the Caddy combined access log. Unlike Event (WAF-specific) or
// RateLimitEvent (429/ipsum only), this captures ALL access log entries for
// general debugging of CSP, CORS, security headers, network errors, etc.
type GeneralLogEvent struct {
	Timestamp       time.Time          `json:"timestamp"`
	ClientIP        string             `json:"client_ip"`
	Country         string             `json:"country,omitempty"`
	Service         string             `json:"service"`
	Method          string             `json:"method"`
	URI             string             `json:"uri"`
	Protocol        string             `json:"protocol"`
	Status          int                `json:"status"`
	Size            int                `json:"size"`
	Duration        float64            `json:"duration"` // seconds
	UserAgent       string             `json:"user_agent"`
	Logger          string             `json:"logger,omitempty"`
	Level           string             `json:"level,omitempty"` // "info", "error"
	SecurityHeaders SecurityHeaderInfo `json:"security_headers"`
}

// SecurityHeaderInfo tracks the presence and values of security-relevant
// response headers. Presence booleans are cheap to aggregate; values are
// stored for debugging when present.
type SecurityHeaderInfo struct {
	HasCSP                 bool   `json:"has_csp"`
	CSP                    string `json:"csp,omitempty"`
	HasHSTS                bool   `json:"has_hsts"`
	HSTS                   string `json:"hsts,omitempty"`
	HasXContentTypeOptions bool   `json:"has_x_content_type_options"`
	XContentTypeOptions    string `json:"x_content_type_options,omitempty"`
	HasXFrameOptions       bool   `json:"has_x_frame_options"`
	XFrameOptions          string `json:"x_frame_options,omitempty"`
	HasReferrerPolicy      bool   `json:"has_referrer_policy"`
	ReferrerPolicy         string `json:"referrer_policy,omitempty"`
	HasCORSOrigin          bool   `json:"has_cors_origin"`
	CORSOrigin             string `json:"cors_origin,omitempty"`
	HasPermissionsPolicy   bool   `json:"has_permissions_policy"`
	PermissionsPolicy      string `json:"permissions_policy,omitempty"`
}

// GeneralLogsResponse is the paginated response for GET /api/logs.
type GeneralLogsResponse struct {
	Total  int               `json:"total"`
	Events []GeneralLogEvent `json:"events"`
}

// GeneralLogsSummary is the aggregated response for GET /api/logs/summary.
type GeneralLogsSummary struct {
	TotalRequests      int                   `json:"total_requests"`
	ErrorCount         int                   `json:"error_count"`        // 5xx
	ClientErrorCount   int                   `json:"client_error_count"` // 4xx
	AvgDuration        float64               `json:"avg_duration"`       // seconds
	P50Duration        float64               `json:"p50_duration"`
	P95Duration        float64               `json:"p95_duration"`
	P99Duration        float64               `json:"p99_duration"`
	StatusDistribution map[string]int        `json:"status_distribution"` // "2xx", "3xx", "4xx", "5xx"
	TopServices        []GeneralServiceCount `json:"top_services"`
	TopURIs            []GeneralURICount     `json:"top_uris"`
	TopClients         []GeneralClientCount  `json:"top_clients"`
	HeaderCompliance   []HeaderCompliance    `json:"header_compliance"`
	RecentErrors       []GeneralLogEvent     `json:"recent_errors"`
}

// GeneralServiceCount is a per-service summary for the general log viewer.
type GeneralServiceCount struct {
	Service     string  `json:"service"`
	Count       int     `json:"count"`
	ErrorCount  int     `json:"error_count"`
	ErrorRate   float64 `json:"error_rate"`
	AvgDuration float64 `json:"avg_duration"`
}

// GeneralURICount is a per-URI summary for the general log viewer.
type GeneralURICount struct {
	URI         string  `json:"uri"`
	Count       int     `json:"count"`
	ErrorCount  int     `json:"error_count"`
	AvgDuration float64 `json:"avg_duration"`
}

// GeneralClientCount is a per-client summary for the general log viewer.
type GeneralClientCount struct {
	ClientIP   string `json:"client_ip"`
	Country    string `json:"country,omitempty"`
	Count      int    `json:"count"`
	ErrorCount int    `json:"error_count"`
}

// HeaderCompliance tracks security header presence rates per service.
type HeaderCompliance struct {
	Service                 string  `json:"service"`
	Total                   int     `json:"total"`
	CSPRate                 float64 `json:"csp_rate"`
	HSTSRate                float64 `json:"hsts_rate"`
	XContentTypeOptionsRate float64 `json:"x_content_type_options_rate"`
	XFrameOptionsRate       float64 `json:"x_frame_options_rate"`
	ReferrerPolicyRate      float64 `json:"referrer_policy_rate"`
	CORSOriginRate          float64 `json:"cors_origin_rate"`
	PermissionsPolicyRate   float64 `json:"permissions_policy_rate"`
}
