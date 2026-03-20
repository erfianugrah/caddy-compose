package main

import (
	"fmt"
	"regexp"
	"time"
)

// ─── Rate Limit Policy Engine ───────────────────────────────────────────────

// RateLimitRule is used by access log enrichment (rl_analytics.go) to match
// 429 events to rule tags for the event stream. The unified ExclusionStore
// now manages rate_limit rules via RuleExclusion, but this type is kept for
// backward compatibility with the access log enrichment pipeline and backup format.
type RateLimitRule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Service     string      `json:"service"`
	Conditions  []Condition `json:"conditions,omitempty"`
	GroupOp     string      `json:"group_operator,omitempty"`
	Key         string      `json:"key"`
	Events      int         `json:"events"`
	Window      string      `json:"window"`
	Action      string      `json:"action,omitempty"`
	Priority    int         `json:"priority,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	Enabled     bool        `json:"enabled"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
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

// ─── Rate Limit Validation ──────────────────────────────────────────────────

// validWindowPattern matches duration strings: number + unit (s, m, h).
var validWindowPattern = regexp.MustCompile(`^\d+[smh]$`)

// validRLKeyPattern matches key formats: plain keys or prefix:name keys.
// body_json: accepts dot-paths (e.g. body_json:.user.api_key), body_form: accepts field names.
var validRLKeyPattern = regexp.MustCompile(`^(client_ip|path|static|client_ip\+path|client_ip\+method|challenge_cookie|header:[A-Za-z0-9_-]+|cookie:[A-Za-z0-9_-]+|body_json:\.?[A-Za-z0-9_.]+|body_form:[A-Za-z0-9_-]+)$`)

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

// validateRateLimitGlobal checks the global config.
func validateRateLimitGlobal(cfg RateLimitGlobalConfig) error {
	if cfg.Jitter < 0 || cfg.Jitter > 1 {
		return fmt.Errorf("jitter must be between 0.0 and 1.0")
	}
	if cfg.SweepInterval != "" && !validWindowPattern.MatchString(cfg.SweepInterval) {
		return fmt.Errorf("sweep_interval must be a duration like 1m, 30s, 1h")
	}
	if cfg.ReadInterval != "" && !validWindowPattern.MatchString(cfg.ReadInterval) {
		return fmt.Errorf("read_interval must be a duration like 5s, 10s")
	}
	if cfg.WriteInterval != "" && !validWindowPattern.MatchString(cfg.WriteInterval) {
		return fmt.Errorf("write_interval must be a duration like 5s, 10s")
	}
	if cfg.PurgeAge != "" && !validWindowPattern.MatchString(cfg.PurgeAge) {
		return fmt.Errorf("purge_age must be a duration like 1m, 5m")
	}
	return nil
}
