package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── Policy Engine Types ───────────────────────────────────────────
//
// These types mirror the caddy-policy-engine plugin's data model.
// wafctl generates a policy-rules.json file that the plugin reads
// and hot-reloads via mtime polling.

// PolicyRulesFile is the top-level JSON structure written to policy-rules.json.
type PolicyRulesFile struct {
	Rules                []PolicyRule                 `json:"rules"`
	DisabledDefaultRules []string                     `json:"disabled_default_rules,omitempty"`
	RateLimitConfig      *PolicyRateLimitGlobalConfig `json:"rate_limit_config,omitempty"`
	ResponseHeaders      *PolicyResponseHeaderConfig  `json:"response_headers,omitempty"`
	WafConfig            *PolicyWafConfig             `json:"waf_config,omitempty"`
	ChallengeConfig      *PolicyChallengeGlobalConfig `json:"challenge_config,omitempty"`
	Generated            string                       `json:"generated"`
	Version              int                          `json:"version"`
}

// PolicyChallengeGlobalConfig holds global challenge settings written to policy-rules.json.
// The plugin reads these at load time to provision HMAC key and default settings.
type PolicyChallengeGlobalConfig struct {
	HMACKey string `json:"hmac_key,omitempty"` // Hex-encoded 32-byte HMAC-SHA256 key for cookie signing
}

// PolicyRule is a single policy rule as consumed by the Caddy plugin.
type PolicyRule struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Phase         string                 `json:"phase,omitempty"` // "inbound" (default) or "outbound" for response-phase rules
	Service       string                 `json:"service,omitempty"`
	Conditions    []PolicyCondition      `json:"conditions"`
	GroupOp       string                 `json:"group_op"`
	RateLimit     *PolicyRateLimitConfig `json:"rate_limit,omitempty"`
	SkipTargets   *PolicySkipTargets     `json:"skip_targets,omitempty"`   // For skip: what to bypass
	Challenge     *PolicyChallengeConfig `json:"challenge,omitempty"`      // For challenge: PoW settings
	Severity      string                 `json:"severity,omitempty"`       // For detect: CRITICAL, ERROR, WARNING, NOTICE
	ParanoiaLevel int                    `json:"paranoia_level,omitempty"` // For detect: 1-4 (0 = all levels)
	Action        string                 `json:"action,omitempty"`         // For detect: "" (default=score) or "log_only" (evaluate but don't score)
	// Response header actions (for response_header type)
	HeaderSet     map[string]string `json:"header_set,omitempty"`     // Set (overwrite)
	HeaderAdd     map[string]string `json:"header_add,omitempty"`     // Add (append)
	HeaderRemove  []string          `json:"header_remove,omitempty"`  // Remove
	HeaderDefault map[string]string `json:"header_default,omitempty"` // Set if not present
	Tags          []string          `json:"tags,omitempty"`
	Enabled       bool              `json:"enabled"`
	Priority      int               `json:"priority"`
	// CRS metadata — populated by the crs-converter at build time, preserved
	// through DefaultRuleStore for catalog/enrichment use at runtime.
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"` // e.g., "REQUEST-932-APPLICATION-ATTACK-RCE"
	CRSFile     string `json:"crs_file,omitempty"` // source .conf filename
}

// PolicyChallengeConfig holds per-rule challenge settings for the plugin.
type PolicyChallengeConfig struct {
	Difficulty int    `json:"difficulty"`  // Leading hex zeros in SHA-256 (1-16, default 4)
	Algorithm  string `json:"algorithm"`   // "fast" (default) or "slow"
	TTLSeconds int    `json:"ttl_seconds"` // Cookie lifetime in seconds (default 604800 = 7d)
	BindIP     bool   `json:"bind_ip"`     // Bind cookie to client IP (default true)
}

// PolicySkipTargets mirrors the plugin's SkipTargets type.
type PolicySkipTargets struct {
	Rules        []string `json:"rules,omitempty"`
	Phases       []string `json:"phases,omitempty"`
	AllRemaining bool     `json:"all_remaining,omitempty"`
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
	ParanoiaLevel      int                               `json:"paranoia_level"`
	InboundThreshold   int                               `json:"inbound_threshold"`
	OutboundThreshold  int                               `json:"outbound_threshold"`
	DisabledCategories []string                          `json:"disabled_categories,omitempty"`
	PerService         map[string]PolicyWafServiceConfig `json:"per_service,omitempty"`
}

// PolicyWafServiceConfig holds per-service WAF overrides.
type PolicyWafServiceConfig struct {
	ParanoiaLevel      int      `json:"paranoia_level,omitempty"`
	InboundThreshold   int      `json:"inbound_threshold,omitempty"`
	OutboundThreshold  int      `json:"outbound_threshold,omitempty"`
	DisabledCategories []string `json:"disabled_categories,omitempty"`
}

// PolicyCondition represents a single match condition for the plugin.
type PolicyCondition struct {
	Field      string   `json:"field,omitempty"`
	Operator   string   `json:"operator,omitempty"`
	Value      string   `json:"value,omitempty"`
	Transforms []string `json:"transforms,omitempty"`
	Negate     bool     `json:"negate,omitempty"`
	MultiMatch bool     `json:"multi_match,omitempty"`
	ListItems  []string `json:"list_items,omitempty"`
	ListKind   string   `json:"list_kind,omitempty"`
	// Nested condition group
	Group   []PolicyCondition `json:"group,omitempty"`
	GroupOp string            `json:"group_op,omitempty"`
}

// policyEngineTypes are the exclusion types handled by the Caddy policy engine plugin.
var policyEngineTypes = map[string]bool{
	"allow":           true,
	"block":           true,
	"challenge":       true,
	"skip":            true,
	"detect":          true,
	"rate_limit":      true,
	"response_header": true,
}

// policyTypePriority assigns a base priority per exclusion type.
// Lower values evaluate first. The 7-pass evaluation order:
//
//	Pass 1 — Allow (50-99):            full bypass, terminates immediately
//	Pass 2 — Block (100-149):          deny list, terminates on match
//	Pass 3 — Challenge (150-199):      proof-of-work interstitial
//	Pass 4 — Skip (200-299):           selective bypass, non-terminating
//	Pass 5 — Rate Limit (300-399):     sliding window counters
//	Pass 6 — Detect (400-499):         CRS anomaly scoring
//	Pass 7 — Response Header (500-599): set/add/remove/default response headers
var policyTypePriority = map[string]int{
	"allow":           50,
	"block":           100,
	"challenge":       150,
	"skip":            200,
	"rate_limit":      300,
	"detect":          400,
	"response_header": 500,
}

// GeneratePolicyRules converts exclusions into the plugin's JSON format.
//
// This is a convenience wrapper around GeneratePolicyRulesWithRL with no
// global RL config. Use GeneratePolicyRulesWithRL when RL global settings
// should also be included in the policy-rules.json output.
func GeneratePolicyRules(exclusions []RuleExclusion, listStore *ManagedListStore) ([]byte, error) {
	return GeneratePolicyRulesWithRL(exclusions, RateLimitGlobalConfig{}, listStore, nil, nil, nil)
}

// GeneratePolicyRulesWithRL converts exclusions into the plugin's JSON format.
// All rule types (allow/block/skip/detect/rate_limit) come from the unified
// ExclusionStore via the exclusions parameter.
//
// Priority bands: allow=50-99, block=100-199, skip=200-299, rate_limit=300-399, detect=400-499.
//
// The global RL config (sweep interval, jitter) is included in the output
// when any rate_limit rules are present in the exclusions.
//
// respHeaders is included in the output when non-nil, enabling the plugin
// to inject CSP and security headers without Caddy reload.
//
// wafConfig is included in the output when non-nil, enabling the plugin's
// anomaly scoring engine with per-service paranoia levels and thresholds.
func GeneratePolicyRulesWithRL(exclusions []RuleExclusion, rlGlobal RateLimitGlobalConfig, listStore *ManagedListStore, serviceMap map[string]string, respHeaders *PolicyResponseHeaderConfig, wafConfig *PolicyWafConfig) ([]byte, error) {
	var rules []PolicyRule

	// Convert WAF exclusions (allow/block/skip/detect).
	for i, e := range exclusions {
		if !policyEngineTypes[e.Type] {
			continue
		}

		conditions := convertConditions(e.Conditions, listStore)

		basePriority := policyTypePriority[e.Type]
		// Add store index as tiebreaker (0-999 range, capped).
		tiebreaker := i
		if tiebreaker > 999 {
			if tiebreaker == 1000 {
				log.Printf("[policy] warning: >1000 rules of type %q — priority tiebreaker capped at 999; ordering may be indeterminate", e.Type)
			}
			tiebreaker = 999
		}

		groupOp := e.GroupOp
		if groupOp == "" {
			groupOp = "and"
		}

		pr := PolicyRule{
			ID:         e.ID,
			Name:       e.Name,
			Type:       e.Type,
			Phase:      e.Phase, // "" (inbound default) or "outbound"
			Conditions: conditions,
			GroupOp:    groupOp,
			Tags:       e.Tags,
			Enabled:    e.Enabled,
			Priority:   basePriority + tiebreaker,
		}

		// Detect rules carry severity, paranoia level, and action for the
		// plugin's anomaly scoring engine.
		if e.Type == "detect" {
			pr.Severity = e.Severity
			pr.ParanoiaLevel = e.DetectParanoiaLevel
			pr.Action = e.DetectAction
		}

		// Skip rules carry skip_targets for the plugin's selective bypass.
		if e.Type == "skip" && e.SkipTargets != nil {
			pr.SkipTargets = &PolicySkipTargets{
				Rules:        e.SkipTargets.Rules,
				Phases:       e.SkipTargets.Phases,
				AllRemaining: e.SkipTargets.AllRemaining,
			}
		}

		// Rate limit rules carry rate limit config + per-service scoping.
		if e.Type == "rate_limit" {
			action := e.RateLimitAction
			if action == "" {
				action = "deny"
			}
			pr.Service = resolveServiceName(e.Service, serviceMap)
			pr.RateLimit = &PolicyRateLimitConfig{
				Key:    e.RateLimitKey,
				Events: e.RateLimitEvents,
				Window: e.RateLimitWindow,
				Action: action,
			}
			// Use explicit priority if set, otherwise tiebreaker from store index.
			// Cap at 99 to prevent bleeding into the detect band (400+).
			if e.Priority > 0 {
				cappedPriority := e.Priority
				if cappedPriority > 99 {
					cappedPriority = 99
					log.Printf("[policy] warning: rate_limit rule %q priority %d capped to 99 to stay within band", e.ID, e.Priority)
				}
				pr.Priority = policyTypePriority["rate_limit"] + cappedPriority
			}
		}

		// Challenge rules carry PoW configuration.
		if e.Type == "challenge" {
			diff := e.ChallengeDifficulty
			if diff == 0 {
				diff = 4
			}
			algo := e.ChallengeAlgorithm
			if algo == "" {
				algo = "fast"
			}
			ttlSec := 7 * 24 * 3600 // default 7 days
			if e.ChallengeTTL != "" {
				if d, err := parseExtendedDuration(e.ChallengeTTL); err == nil {
					ttlSec = int(d.Seconds())
				}
			}
			bindIP := true
			if e.ChallengeBindIP != nil {
				bindIP = *e.ChallengeBindIP
			}
			pr.Challenge = &PolicyChallengeConfig{
				Difficulty: diff,
				Algorithm:  algo,
				TTLSeconds: ttlSec,
				BindIP:     bindIP,
			}
		}

		// Response header rules carry header actions.
		if e.Type == "response_header" {
			pr.HeaderSet = e.HeaderSet
			pr.HeaderAdd = e.HeaderAdd
			pr.HeaderRemove = e.HeaderRemove
			pr.HeaderDefault = e.HeaderDefault
			// Force outbound phase for response_header rules.
			if pr.Phase == "" {
				pr.Phase = "outbound"
			}
		}

		// Per-service scoping for any rule type.
		if e.Service != "" && e.Type != "rate_limit" {
			pr.Service = resolveServiceName(e.Service, serviceMap)
		}

		rules = append(rules, pr)
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

	// Include global RL config when rate limit rules are present in the exclusions.
	hasRLRules := false
	for _, r := range rules {
		if r.Type == "rate_limit" {
			hasRLRules = true
			break
		}
	}
	if hasRLRules {
		file.RateLimitConfig = &PolicyRateLimitGlobalConfig{
			SweepInterval: rlGlobal.SweepInterval,
			Jitter:        rlGlobal.Jitter,
		}
	}

	// Note: ChallengeConfig (HMAC key) is injected by the deploy pipeline
	// after this function returns, via SetChallengeConfig on the unmarshalled
	// PolicyRulesFile. This avoids changing this function's signature.

	// Use indented JSON for readability (hot-reloaded by plugin, not perf-critical).
	return json.MarshalIndent(file, "", "  ")
}

// ApplyDefaultRuleOverrides injects overridden default rules into the
// PolicyRulesFile and sets DisabledDefaultRules. Call this after
// GeneratePolicyRulesWithRL and before writing to disk.
//
// Overridden defaults are appended to the rules array so the plugin's
// merge-by-ID logic replaces the baked defaults. Disabled defaults are
// listed in DisabledDefaultRules so the plugin filters them out.
func ApplyDefaultRuleOverrides(data []byte, ds *DefaultRuleStore) ([]byte, error) {
	if ds == nil {
		return data, nil
	}

	overridden := ds.GetOverriddenRules()
	disabled := ds.GetDisabledIDs()

	// Fast path: no overrides, no changes needed.
	if len(overridden) == 0 && len(disabled) == 0 {
		return data, nil
	}

	var file PolicyRulesFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}

	// Append overridden rules (plugin replaces defaults by matching ID).
	// Only add rules that are still enabled — disabled ones go to the
	// DisabledDefaultRules list instead.
	for _, r := range overridden {
		if r.Enabled {
			file.Rules = append(file.Rules, r)
		}
	}

	// Set disabled default rule IDs.
	if len(disabled) > 0 {
		file.DisabledDefaultRules = disabled
	}

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
			Negate:     c.Negate,
			MultiMatch: c.MultiMatch,
		}
		// Resolve managed list references.
		if (c.Operator == "in_list" || c.Operator == "not_in_list") && listStore != nil {
			pc.ListItems, pc.ListKind = resolveListItems(listStore, c.Value)
		}
		// Pass through inline list items for phrase_match and not_phrase_match.
		if (c.Operator == "phrase_match" || c.Operator == "not_phrase_match") && len(c.ListItems) > 0 {
			pc.ListItems = c.ListItems
		}
		result[j] = pc
	}
	return result
}

// IsPolicyEngineType returns true if the exclusion type is handled by
// the Caddy policy engine plugin.
func IsPolicyEngineType(typ string) bool {
	return policyEngineTypes[typ]
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

// fqdnCache caches the result of BuildServiceFQDNMap keyed by Caddyfile mtime.
// Avoids re-reading and re-parsing the file on every deploy/preview call.
var fqdnCache struct {
	mu    sync.Mutex
	path  string
	mtime time.Time
	data  map[string]string
}

// ResetFQDNCache clears the FQDN cache. Exported for use in tests and benchmarks
// to prevent cross-test contamination from the global cache.
func ResetFQDNCache() {
	fqdnCache.mu.Lock()
	defer fqdnCache.mu.Unlock()
	fqdnCache.path = ""
	fqdnCache.mtime = time.Time{}
	fqdnCache.data = nil
}

// BuildServiceFQDNMap parses the Caddyfile and builds a mapping from short
// service names to FQDNs. For a site block "httpbun.erfi.io {", the short
// name is "httpbun" (everything before the first dot). This allows the
// policy engine generator to resolve RL rules that use short service names
// (from Caddyfile auto-discovery) to the FQDNs that the plugin sees in
// the Host header.
//
// Results are cached and invalidated when the Caddyfile mtime changes.
// Returns nil if the Caddyfile cannot be read or contains no FQDN blocks.
func BuildServiceFQDNMap(caddyfilePath string) map[string]string {
	if caddyfilePath == "" {
		return nil
	}

	// Fast path: check mtime and return cached result.
	fi, err := os.Stat(caddyfilePath)
	if err != nil {
		return nil
	}
	mtime := fi.ModTime()

	fqdnCache.mu.Lock()
	defer fqdnCache.mu.Unlock()

	if fqdnCache.path == caddyfilePath && fqdnCache.mtime.Equal(mtime) && fqdnCache.data != nil {
		return fqdnCache.data
	}

	// Cache miss — re-read and re-parse.
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

	fqdnCache.path = caddyfilePath
	fqdnCache.mtime = mtime
	fqdnCache.data = m
	return m
}

// mapServiceBoth maps a value to both the FQDN and the short name in the given map.
// This ensures the plugin can match by either the original short name or
// the resolved FQDN from the Host header.
func mapServiceBoth[V any](m map[string]V, svc string, serviceMap map[string]string, val V) {
	fqdn := resolveServiceName(svc, serviceMap)
	m[fqdn] = val
	if fqdn != svc {
		m[svc] = val
	}
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

// PolicyResponseHeaderConfig holds CSP, security header, and CORS configuration.
type PolicyResponseHeaderConfig struct {
	CSP      *PolicyCSPConfig            `json:"csp,omitempty"`
	Security *PolicySecurityHeaderConfig `json:"security,omitempty"`
	CORS     *PolicyCORSConfig           `json:"cors,omitempty"`
}

// PolicyCORSConfig holds global and per-service CORS settings.
type PolicyCORSConfig struct {
	Enabled    *bool                   `json:"enabled,omitempty"` // nil = true
	Global     CORSSettings            `json:"global"`
	PerService map[string]CORSSettings `json:"per_service,omitempty"`
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
// policy engine plugin from the CSP store, security header store, and CORS store.
// The CSP policy data and service FQDNs are resolved so the plugin gets
// FQDN-keyed services matching the Host headers it sees in production.
func BuildPolicyResponseHeaders(cspStore *CSPStore, secStore *SecurityHeaderStore, corsStore *CORSStore, serviceMap map[string]string) *PolicyResponseHeaderConfig {
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
				resolved := resolveSecurityHeaders(cfg, svc)
				override := PolicySecurityServiceOverride{
					Headers: resolved.Headers,
					Remove:  resolved.Remove,
				}
				mapServiceBoth(sec.PerService, svc, serviceMap, override)
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

	// Build CORS config from store.
	if corsStore != nil {
		corsCfg := corsStore.Get()
		perService := make(map[string]CORSSettings)
		for svc, cs := range corsCfg.PerService {
			mapServiceBoth(perService, svc, serviceMap, cs)
		}
		resp.CORS = &PolicyCORSConfig{
			Enabled:    corsCfg.Enabled,
			Global:     corsCfg.Global,
			PerService: perService,
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
		ParanoiaLevel:      cfg.Defaults.ParanoiaLevel,
		InboundThreshold:   cfg.Defaults.InboundThreshold,
		OutboundThreshold:  cfg.Defaults.OutboundThreshold,
		DisabledCategories: cfg.Defaults.DisabledCategories,
	}

	if len(cfg.Services) > 0 {
		pwc.PerService = make(map[string]PolicyWafServiceConfig, len(cfg.Services))
		for svc, ss := range cfg.Services {
			psc := PolicyWafServiceConfig{
				ParanoiaLevel:      ss.ParanoiaLevel,
				InboundThreshold:   ss.InboundThreshold,
				OutboundThreshold:  ss.OutboundThreshold,
				DisabledCategories: ss.DisabledCategories,
			}
			mapServiceBoth(pwc.PerService, svc, serviceMap, psc)
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
