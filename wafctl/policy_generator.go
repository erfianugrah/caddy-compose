package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ─── Policy Engine Types ───────────────────────────────────────────
//
// These types mirror the caddy-policy-engine plugin's data model.
// wafctl generates a policy-rules.json file that the plugin reads
// and hot-reloads via mtime polling.

// PolicyRulesFile is the top-level JSON structure written to policy-rules.json.
type PolicyRulesFile struct {
	Rules           []PolicyRule                 `json:"rules"`
	RateLimitConfig *PolicyRateLimitGlobalConfig `json:"rate_limit_config,omitempty"`
	ResponseHeaders *PolicyResponseHeaderConfig  `json:"response_headers,omitempty"`
	WafConfig       *PolicyWafConfig             `json:"waf_config,omitempty"`
	Generated       string                       `json:"generated"`
	Version         int                          `json:"version"`
}

// PolicyRule is a single policy rule as consumed by the Caddy plugin.
type PolicyRule struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Service       string                 `json:"service,omitempty"`
	Conditions    []PolicyCondition      `json:"conditions"`
	GroupOp       string                 `json:"group_op"`
	RateLimit     *PolicyRateLimitConfig `json:"rate_limit,omitempty"`
	Severity      string                 `json:"severity,omitempty"`       // For detect: CRITICAL, ERROR, WARNING, NOTICE
	ParanoiaLevel int                    `json:"paranoia_level,omitempty"` // For detect: 1-4 (0 = all levels)
	Tags          []string               `json:"tags,omitempty"`
	Enabled       bool                   `json:"enabled"`
	Priority      int                    `json:"priority"`
}

// PolicyRateLimitConfig holds per-rule rate limit parameters.
// Mirrors the caddy-policy-engine plugin's RateLimitConfig type.
type PolicyRateLimitConfig struct {
	Key    string `json:"key"`
	Events int    `json:"events"`
	Window string `json:"window"`
	Action string `json:"action,omitempty"`
}

// PolicyRateLimitGlobalConfig holds global rate limit settings.
// Mirrors the caddy-policy-engine plugin's RateLimitGlobalConfig type.
type PolicyRateLimitGlobalConfig struct {
	SweepInterval string  `json:"sweep_interval,omitempty"`
	Jitter        float64 `json:"jitter,omitempty"`
}

// ─── WAF Config Types ──────────────────────────────────────────────
//
// These types mirror the caddy-policy-engine plugin's WafConfig.
// wafctl converts its WAFConfig (models_exclusions.go) into this format
// so the plugin can resolve per-service paranoia levels and thresholds
// for anomaly scoring.

// PolicyWafConfig holds global WAF settings for the anomaly scoring engine.
type PolicyWafConfig struct {
	ParanoiaLevel     int                               `json:"paranoia_level"`
	InboundThreshold  int                               `json:"inbound_threshold"`
	OutboundThreshold int                               `json:"outbound_threshold"`
	PerService        map[string]PolicyWafServiceConfig `json:"per_service,omitempty"`
}

// PolicyWafServiceConfig holds per-service WAF overrides.
type PolicyWafServiceConfig struct {
	ParanoiaLevel     int `json:"paranoia_level,omitempty"`
	InboundThreshold  int `json:"inbound_threshold,omitempty"`
	OutboundThreshold int `json:"outbound_threshold,omitempty"`
}

// PolicyCondition represents a single match condition for the plugin.
type PolicyCondition struct {
	Field      string   `json:"field"`
	Operator   string   `json:"operator"`
	Value      string   `json:"value"`
	Transforms []string `json:"transforms,omitempty"` // ordered transform chain applied before operator
	ListItems  []string `json:"list_items,omitempty"` // resolved by wafctl before writing
	ListKind   string   `json:"list_kind,omitempty"`  // "ip", "hostname", "string", "asn"
}

// policyEngineTypes are the exclusion types handled by the Caddy policy
// engine plugin instead of Coraza SecRules.
var policyEngineTypes = map[string]bool{
	"allow":  true,
	"block":  true,
	"detect": true,
}

// policyTypePriority assigns a base priority per exclusion type.
// Lower values evaluate first. Block (deny) → Allow (bypass) → Rate Limit.
// This ensures deny rules take precedence over allow rules, and both
// take precedence over rate limiting.
var policyTypePriority = map[string]int{
	"block":      100,
	"allow":      200,
	"rate_limit": 300,
	"detect":     400,
}

// GeneratePolicyRules converts exclusions into the plugin's JSON format.
// Only allow/block types are included. All other types remain
// in SecRule generation (generator.go).
//
// This is a convenience wrapper around GeneratePolicyRulesWithRL with no
// rate limit rules. Use GeneratePolicyRulesWithRL when RL rules should
// also be included in the policy-rules.json output.
func GeneratePolicyRules(exclusions []RuleExclusion, listStore *ManagedListStore) ([]byte, error) {
	return GeneratePolicyRulesWithRL(exclusions, nil, RateLimitGlobalConfig{}, listStore, nil, nil, nil)
}

// GeneratePolicyRulesWithRL converts exclusions and rate limit rules into
// the plugin's JSON format. WAF exclusions (allow/block) and rate limit
// rules are merged into a single rules array, sorted by priority.
//
// Priority bands: block=100-199, allow=200-299, rate_limit=300+.
// Within rate_limit, rules with explicit Priority use it directly (offset
// by 300); rules without explicit Priority get 300 + their store index.
//
// When rlRules is nil or empty, the output is identical to GeneratePolicyRules.
//
// The global RL config (sweep interval, jitter) is included in the output
// when any rate limit rules are present.
//
// respHeaders is included in the output when non-nil, enabling the plugin
// to inject CSP and security headers without Caddy reload.
//
// wafConfig is included in the output when non-nil, enabling the plugin's
// anomaly scoring engine with per-service paranoia levels and thresholds.
func GeneratePolicyRulesWithRL(exclusions []RuleExclusion, rlRules []RateLimitRule, rlGlobal RateLimitGlobalConfig, listStore *ManagedListStore, serviceMap map[string]string, respHeaders *PolicyResponseHeaderConfig, wafConfig *PolicyWafConfig) ([]byte, error) {
	var rules []PolicyRule

	// Convert WAF exclusions (allow/block/detect).
	for i, e := range exclusions {
		if !policyEngineTypes[e.Type] {
			continue
		}

		conditions := convertConditions(e.Conditions, listStore)

		basePriority := policyTypePriority[e.Type]
		// Add store index as tiebreaker (0-99 range, capped).
		tiebreaker := i
		if tiebreaker > 99 {
			tiebreaker = 99
		}

		groupOp := e.GroupOp
		if groupOp == "" {
			groupOp = "and"
		}

		pr := PolicyRule{
			ID:         e.ID,
			Name:       e.Name,
			Type:       e.Type,
			Conditions: conditions,
			GroupOp:    groupOp,
			Tags:       e.Tags,
			Enabled:    e.Enabled,
			Priority:   basePriority + tiebreaker,
		}

		// Detect rules carry severity and paranoia level for the plugin's
		// anomaly scoring engine.
		if e.Type == "detect" {
			pr.Severity = e.Severity
			pr.ParanoiaLevel = e.DetectParanoiaLevel
		}

		rules = append(rules, pr)
	}

	// Convert rate limit rules.
	for i, rl := range rlRules {
		conditions := convertConditions(rl.Conditions, listStore)

		// Determine priority: use explicit Priority if set, otherwise
		// use the RL base (300) + store index as tiebreaker.
		priority := policyTypePriority["rate_limit"]
		if rl.Priority > 0 {
			priority += rl.Priority
		} else {
			tiebreaker := i
			if tiebreaker > 99 {
				tiebreaker = 99
			}
			priority += tiebreaker
		}

		groupOp := rl.GroupOp
		if groupOp == "" {
			groupOp = "and"
		}

		action := rl.Action
		if action == "" {
			action = "deny"
		}

		rules = append(rules, PolicyRule{
			ID:         rl.ID,
			Name:       rl.Name,
			Type:       "rate_limit",
			Service:    resolveServiceName(rl.Service, serviceMap),
			Conditions: conditions,
			GroupOp:    groupOp,
			RateLimit: &PolicyRateLimitConfig{
				Key:    rl.Key,
				Events: rl.Events,
				Window: rl.Window,
				Action: action,
			},
			Tags:     rl.Tags,
			Enabled:  rl.Enabled,
			Priority: priority,
		})
	}

	// Sort by priority (lower first), then by ID for deterministic output.
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})

	file := PolicyRulesFile{
		Rules:           rules,
		ResponseHeaders: respHeaders,
		WafConfig:       wafConfig,
		Generated:       time.Now().UTC().Format(time.RFC3339),
		Version:         1,
	}

	// Include global RL config when rate limit rules are present.
	if len(rlRules) > 0 {
		file.RateLimitConfig = &PolicyRateLimitGlobalConfig{
			SweepInterval: rlGlobal.SweepInterval,
			Jitter:        rlGlobal.Jitter,
		}
	}

	// Use indented JSON for readability (hot-reloaded by plugin, not perf-critical).
	return json.MarshalIndent(file, "", "  ")
}

// convertConditions translates wafctl Conditions to PolicyConditions,
// resolving managed list references along the way.
func convertConditions(conditions []Condition, listStore *ManagedListStore) []PolicyCondition {
	result := make([]PolicyCondition, len(conditions))
	for j, c := range conditions {
		pc := PolicyCondition{
			Field:      c.Field,
			Operator:   c.Operator,
			Value:      c.Value,
			Transforms: c.Transforms,
		}
		// Resolve managed list references.
		if (c.Operator == "in_list" || c.Operator == "not_in_list") && listStore != nil {
			pc.ListItems, pc.ListKind = resolveListItems(listStore, c.Value)
		}
		// Pass through inline list items for phrase_match.
		if c.Operator == "phrase_match" && len(c.ListItems) > 0 {
			pc.ListItems = c.ListItems
		}
		result[j] = pc
	}
	return result
}

// IsPolicyEngineType returns true if the exclusion type is handled by
// the Caddy policy engine plugin rather than Coraza SecRules.
func IsPolicyEngineType(typ string) bool {
	return policyEngineTypes[typ]
}

// FilterSecRuleExclusions returns only the exclusions that should generate
// SecRules (i.e., NOT handled by the policy engine plugin).
// When policyEngineEnabled is false, all exclusions are returned unchanged.
func FilterSecRuleExclusions(exclusions []RuleExclusion, policyEngineEnabled bool) []RuleExclusion {
	if !policyEngineEnabled {
		return exclusions
	}
	filtered := make([]RuleExclusion, 0, len(exclusions))
	for _, e := range exclusions {
		if !policyEngineTypes[e.Type] {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// ─── Service Name Resolution ──────────────────────────────────────

// siteBlockPattern matches Caddyfile top-level site addresses like:
//
//	httpbun.erfi.io {
//	caddy-prometheus.erfi.io {
//
// It requires at least two dot-separated segments (FQDN) and captures the
// full hostname. Port-only blocks like ":8080 {" are excluded.
var siteBlockPattern = regexp.MustCompile(`(?m)^([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)\s*\{`)

// BuildServiceFQDNMap parses the Caddyfile and builds a mapping from short
// service names to FQDNs. For a site block "httpbun.erfi.io {", the short
// name is "httpbun" (everything before the first dot). This allows the
// policy engine generator to resolve RL rules that use short service names
// (from Caddyfile auto-discovery) to the FQDNs that the plugin sees in
// the Host header.
//
// Returns nil if the Caddyfile cannot be read or contains no FQDN blocks.
func BuildServiceFQDNMap(caddyfilePath string) map[string]string {
	if caddyfilePath == "" {
		return nil
	}
	data, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return nil
	}

	m := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		matches := siteBlockPattern.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		fqdn := matches[1]
		// Short name = everything before the first dot.
		short := fqdn
		if idx := strings.Index(fqdn, "."); idx > 0 {
			short = fqdn[:idx]
		}
		// Only map if short != fqdn (skip bare hostnames without dots).
		if short != fqdn {
			m[short] = fqdn
		}
	}
	return m
}

// resolveServiceName maps a short service name to its FQDN using the
// provided map. If the service already contains a dot (is already an FQDN)
// or is a wildcard, it is returned unchanged. If no mapping is found,
// the original name is returned.
func resolveServiceName(service string, serviceMap map[string]string) string {
	if service == "" || service == "*" || strings.Contains(service, ".") {
		return service
	}
	if serviceMap == nil {
		return service
	}
	if fqdn, ok := serviceMap[service]; ok {
		return fqdn
	}
	return service
}

// ─── Response Header Types ─────────────────────────────────────────
//
// These types mirror the caddy-policy-engine plugin's response header config.
// wafctl builds this from the CSP store and hardcoded security headers,
// then includes it in policy-rules.json for hot-reload.

// PolicyResponseHeaderConfig holds CSP and security header configuration.
type PolicyResponseHeaderConfig struct {
	CSP      *PolicyCSPConfig            `json:"csp,omitempty"`
	Security *PolicySecurityHeaderConfig `json:"security,omitempty"`
}

// PolicyCSPConfig holds global and per-service CSP policies.
type PolicyCSPConfig struct {
	Enabled        *bool                             `json:"enabled,omitempty"` // nil = true
	GlobalDefaults CSPPolicy                         `json:"global_defaults"`
	Services       map[string]PolicyCSPServiceConfig `json:"services"`
}

// PolicyCSPServiceConfig holds the CSP configuration for a single service.
type PolicyCSPServiceConfig struct {
	Mode       string    `json:"mode"`        // "set", "default", "none"
	ReportOnly bool      `json:"report_only"` // Content-Security-Policy-Report-Only
	Inherit    bool      `json:"inherit"`     // merge on top of GlobalDefaults
	Policy     CSPPolicy `json:"policy"`
}

// PolicySecurityHeaderConfig holds static security headers.
type PolicySecurityHeaderConfig struct {
	Enabled    *bool                                    `json:"enabled,omitempty"` // nil = true
	Headers    map[string]string                        `json:"headers,omitempty"`
	Remove     []string                                 `json:"remove,omitempty"`
	PerService map[string]PolicySecurityServiceOverride `json:"per_service,omitempty"`
}

// PolicySecurityServiceOverride holds per-service security header overrides.
type PolicySecurityServiceOverride struct {
	Headers map[string]string `json:"headers,omitempty"`
	Remove  []string          `json:"remove,omitempty"`
}

// DefaultSecurityHeaders returns the standard security headers used by all services.
// These match the (security_headers_base) Caddyfile snippet.
func DefaultSecurityHeaders() *PolicySecurityHeaderConfig {
	return &PolicySecurityHeaderConfig{
		Headers: map[string]string{
			"Strict-Transport-Security":         "max-age=63072000; includeSubDomains; preload",
			"X-Content-Type-Options":            "nosniff",
			"X-Frame-Options":                   "SAMEORIGIN",
			"Referrer-Policy":                   "strict-origin-when-cross-origin",
			"Permissions-Policy":                "camera=(), microphone=(), geolocation=(), payment=()",
			"Cross-Origin-Opener-Policy":        "same-origin",
			"Cross-Origin-Resource-Policy":      "cross-origin",
			"X-Permitted-Cross-Domain-Policies": "none",
		},
		Remove: []string{"Server", "X-Powered-By"},
	}
}

// BuildPolicyResponseHeaders constructs the response header config for the
// policy engine plugin from the CSP store and security header store.
// The CSP policy data and service FQDNs are resolved so the plugin gets
// FQDN-keyed services matching the Host headers it sees in production.
func BuildPolicyResponseHeaders(cspStore *CSPStore, secStore *SecurityHeaderStore, serviceMap map[string]string) *PolicyResponseHeaderConfig {
	resp := &PolicyResponseHeaderConfig{}

	// Build security header config from store (or defaults).
	if secStore != nil {
		cfg := secStore.Get()
		enabled := cfg.Enabled == nil || *cfg.Enabled
		sec := &PolicySecurityHeaderConfig{
			Headers: cfg.Headers,
			Remove:  cfg.Remove,
		}
		if !enabled {
			sec.Enabled = boolPtr(false)
		}
		// Build per-service overrides, keyed by FQDN.
		if len(cfg.Services) > 0 {
			sec.PerService = make(map[string]PolicySecurityServiceOverride)
			for svc := range cfg.Services {
				fqdn := resolveServiceName(svc, serviceMap)
				resolved := resolveSecurityHeaders(cfg, svc)
				sec.PerService[fqdn] = PolicySecurityServiceOverride{
					Headers: resolved.Headers,
					Remove:  resolved.Remove,
				}
				// Also map the short name if different from FQDN.
				if fqdn != svc {
					sec.PerService[svc] = PolicySecurityServiceOverride{
						Headers: resolved.Headers,
						Remove:  resolved.Remove,
					}
				}
			}
		}
		resp.Security = sec
	} else {
		resp.Security = DefaultSecurityHeaders()
	}

	// Build CSP config from store.
	if cspStore != nil {
		cspCfg := cspStore.Get()
		services := make(map[string]PolicyCSPServiceConfig)
		for svc, sc := range cspCfg.Services {
			fqdn := resolveServiceName(svc, serviceMap)
			services[fqdn] = PolicyCSPServiceConfig{
				Mode:       sc.Mode,
				ReportOnly: sc.ReportOnly,
				Inherit:    sc.Inherit,
				Policy:     sc.Policy,
			}
		}
		resp.CSP = &PolicyCSPConfig{
			Enabled:        cspCfg.Enabled,
			GlobalDefaults: cspCfg.GlobalDefaults,
			Services:       services,
		}
	}

	return resp
}

// ─── WAF Config Builder ────────────────────────────────────────────

// BuildPolicyWafConfig converts the wafctl WAFConfig into the plugin's
// PolicyWafConfig format. Per-service entries are keyed by FQDN using the
// provided serviceMap so the plugin can match Host headers in production.
//
// Returns nil if cs is nil (anomaly scoring disabled — backward compatible).
func BuildPolicyWafConfig(cs *ConfigStore, serviceMap map[string]string) *PolicyWafConfig {
	if cs == nil {
		return nil
	}
	cfg := cs.Get()

	pwc := &PolicyWafConfig{
		ParanoiaLevel:     cfg.Defaults.ParanoiaLevel,
		InboundThreshold:  cfg.Defaults.InboundThreshold,
		OutboundThreshold: cfg.Defaults.OutboundThreshold,
	}

	if len(cfg.Services) > 0 {
		pwc.PerService = make(map[string]PolicyWafServiceConfig, len(cfg.Services))
		for svc, ss := range cfg.Services {
			fqdn := resolveServiceName(svc, serviceMap)
			psc := PolicyWafServiceConfig{
				ParanoiaLevel:     ss.ParanoiaLevel,
				InboundThreshold:  ss.InboundThreshold,
				OutboundThreshold: ss.OutboundThreshold,
			}
			pwc.PerService[fqdn] = psc
			// Also map the short name if different from FQDN.
			if fqdn != svc {
				pwc.PerService[svc] = psc
			}
		}
	}

	return pwc
}

// resolveListItems looks up a managed list by name and returns its items and kind.
// Returns empty items if the list is not found (condition won't match anything).
func resolveListItems(ls *ManagedListStore, listName string) ([]string, string) {
	if ls == nil || listName == "" {
		return nil, ""
	}
	lists := ls.List()
	for _, l := range lists {
		if l.Name == listName {
			// Return a copy so mutations don't affect the store.
			items := make([]string, len(l.Items))
			copy(items, l.Items)
			return items, l.Kind
		}
	}
	log.Printf("[policy] warning: managed list %q not found, condition will not match", listName)
	return nil, ""
}
