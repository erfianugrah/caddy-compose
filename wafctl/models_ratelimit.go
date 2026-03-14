package main

import "time"

// ─── Rate Limit Policy Engine ───────────────────────────────────────────────

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
	Tags        []string    `json:"tags,omitempty"`           // Event classification tags (e.g., "api", "auth", "brute-force")
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

// ─── Rate Limit Validation Maps ─────────────────────────────────────────────

// validRLKeyPrefixes are key prefixes that take a parameter (e.g. "header:X-API-Key")
var validRLKeyPrefixes = []string{"header:", "cookie:", "body_json:", "body_form:"}

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
	"body":         true,
	"body_json":    true,
	"body_form":    true,
	"uri_path":     true,
	"referer":      true,
	"http_version": true,
}
