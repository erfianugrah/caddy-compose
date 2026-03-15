package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── Security Header Data Model ─────────────────────────────────────────────

// SecurityHeaderConfig is the top-level security header configuration.
type SecurityHeaderConfig struct {
	// Enabled controls whether security headers are injected.
	// Uses *bool so that existing JSON files without the field default to true.
	Enabled *bool `json:"enabled,omitempty"`

	// Profile is a named preset that determines the baseline headers.
	// One of: "strict", "default", "relaxed", "api", "custom".
	// When a known profile is set, Headers/Remove are populated from
	// the profile defaults at load time but can be overridden.
	Profile string `json:"profile"`

	// Headers maps header names to values (e.g. "X-Content-Type-Options": "nosniff").
	Headers map[string]string `json:"headers,omitempty"`

	// Remove lists headers to strip from responses (e.g. "Server", "X-Powered-By").
	Remove []string `json:"remove,omitempty"`

	// Services holds per-service overrides keyed by short service name.
	Services map[string]SecurityServiceConfig `json:"services,omitempty"`
}

// SecurityServiceConfig holds per-service security header overrides.
type SecurityServiceConfig struct {
	// Profile overrides the global profile for this service.
	// Empty string means "inherit global".
	Profile string `json:"profile,omitempty"`

	// Headers are per-service header overrides. Non-empty values replace
	// the global header; empty string removes the header for this service.
	Headers map[string]string `json:"headers,omitempty"`

	// Remove lists additional headers to strip for this service.
	Remove []string `json:"remove,omitempty"`
}

// ─── Profiles ───────────────────────────────────────────────────────────────

// SecurityProfile defines a named preset of security headers.
type SecurityProfile struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Headers     map[string]string `json:"headers"`
	Remove      []string          `json:"remove"`
}

// securityProfiles defines the built-in presets.
var securityProfiles = map[string]SecurityProfile{
	"strict": {
		Name:        "strict",
		Description: "Maximum security — restrictive COOP/CORP, DENY framing",
		Headers: map[string]string{
			"Strict-Transport-Security":         "max-age=63072000; includeSubDomains; preload",
			"X-Content-Type-Options":            "nosniff",
			"X-Frame-Options":                   "DENY",
			"Referrer-Policy":                   "no-referrer",
			"Permissions-Policy":                "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()",
			"Cross-Origin-Opener-Policy":        "same-origin",
			"Cross-Origin-Resource-Policy":      "same-origin",
			"Cross-Origin-Embedder-Policy":      "require-corp",
			"X-Permitted-Cross-Domain-Policies": "none",
		},
		Remove: []string{"Server", "X-Powered-By"},
	},
	"default": {
		Name:        "default",
		Description: "Balanced security — SAMEORIGIN framing, cross-origin resources allowed",
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
	},
	"relaxed": {
		Name:        "relaxed",
		Description: "Relaxed security — allows popups, cross-origin embedding",
		Headers: map[string]string{
			"Strict-Transport-Security":         "max-age=31536000; includeSubDomains",
			"X-Content-Type-Options":            "nosniff",
			"X-Frame-Options":                   "SAMEORIGIN",
			"Referrer-Policy":                   "strict-origin-when-cross-origin",
			"Permissions-Policy":                "camera=(), microphone=(), geolocation=()",
			"Cross-Origin-Opener-Policy":        "same-origin-allow-popups",
			"Cross-Origin-Resource-Policy":      "cross-origin",
			"X-Permitted-Cross-Domain-Policies": "none",
		},
		Remove: []string{"Server", "X-Powered-By"},
	},
	"api": {
		Name:        "api",
		Description: "API-only — minimal headers, no framing restrictions",
		Headers: map[string]string{
			"Strict-Transport-Security":    "max-age=63072000; includeSubDomains; preload",
			"X-Content-Type-Options":       "nosniff",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Resource-Policy": "cross-origin",
		},
		Remove: []string{"Server", "X-Powered-By"},
	},
}

// validProfiles is the set of valid profile names.
var validProfiles = map[string]bool{
	"strict":  true,
	"default": true,
	"relaxed": true,
	"api":     true,
	"custom":  true,
}

// ─── Validation ─────────────────────────────────────────────────────────────

// secHeaderNameRe validates security header names.
var secHeaderNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

// secServiceNameRe validates service names — same as CSP.
var secServiceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// validateSecurityHeaderConfig checks the config for invalid values.
func validateSecurityHeaderConfig(cfg SecurityHeaderConfig) error {
	if cfg.Profile != "" && !validProfiles[cfg.Profile] {
		return fmt.Errorf("invalid profile %q (must be one of: strict, default, relaxed, api, custom)", cfg.Profile)
	}
	for name, value := range cfg.Headers {
		if !secHeaderNameRe.MatchString(name) {
			return fmt.Errorf("header %q: invalid header name", name)
		}
		if strings.ContainsAny(value, "\n\r") {
			return fmt.Errorf("header %q: value contains newline characters", name)
		}
	}
	for _, h := range cfg.Remove {
		if !secHeaderNameRe.MatchString(h) {
			return fmt.Errorf("remove %q: invalid header name", h)
		}
	}
	for svc, sc := range cfg.Services {
		if !secServiceNameRe.MatchString(svc) {
			return fmt.Errorf("service %q: invalid service name", svc)
		}
		if sc.Profile != "" && !validProfiles[sc.Profile] {
			return fmt.Errorf("service %q: invalid profile %q", svc, sc.Profile)
		}
		for name, value := range sc.Headers {
			if !secHeaderNameRe.MatchString(name) {
				return fmt.Errorf("service %q: header %q: invalid header name", svc, name)
			}
			if strings.ContainsAny(value, "\n\r") {
				return fmt.Errorf("service %q: header %q: value contains newline characters", svc, name)
			}
		}
		for _, h := range sc.Remove {
			if !secHeaderNameRe.MatchString(h) {
				return fmt.Errorf("service %q: remove %q: invalid header name", svc, h)
			}
		}
	}
	return nil
}

// ─── Resolution ─────────────────────────────────────────────────────────────

// ResolvedSecurityHeaders is the effective config for a service after
// merging global + per-service overrides.
type ResolvedSecurityHeaders struct {
	Headers map[string]string `json:"headers"`
	Remove  []string          `json:"remove"`
}

// resolveSecurityHeaders computes the effective headers for a service.
func resolveSecurityHeaders(cfg SecurityHeaderConfig, service string) ResolvedSecurityHeaders {
	// Start from global headers.
	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	remove := make([]string, len(cfg.Remove))
	copy(remove, cfg.Remove)

	// Apply per-service overrides.
	sc, ok := cfg.Services[service]
	if !ok {
		return ResolvedSecurityHeaders{Headers: headers, Remove: remove}
	}

	// If the service has its own profile, start from profile defaults.
	if sc.Profile != "" && sc.Profile != "custom" {
		if prof, exists := securityProfiles[sc.Profile]; exists {
			headers = make(map[string]string)
			for k, v := range prof.Headers {
				headers[k] = v
			}
			remove = make([]string, len(prof.Remove))
			copy(remove, prof.Remove)
		}
	}

	// Overlay service-level header overrides.
	for name, value := range sc.Headers {
		if value == "" {
			// Empty string means remove this header entirely.
			delete(headers, name)
		} else {
			headers[name] = value
		}
	}

	// Add service-level removals (deduplicated).
	seen := make(map[string]bool)
	for _, h := range remove {
		seen[h] = true
	}
	for _, h := range sc.Remove {
		if !seen[h] {
			remove = append(remove, h)
			seen[h] = true
		}
	}

	return ResolvedSecurityHeaders{Headers: headers, Remove: remove}
}

// ─── Default Configuration ──────────────────────────────────────────────────

// defaultSecurityHeaderConfig returns the default config using the "default" profile.
func defaultSecurityHeaderConfig() SecurityHeaderConfig {
	prof := securityProfiles["default"]
	headers := make(map[string]string)
	for k, v := range prof.Headers {
		headers[k] = v
	}
	removeCopy := make([]string, len(prof.Remove))
	copy(removeCopy, prof.Remove)
	return SecurityHeaderConfig{
		Enabled:  boolPtr(true),
		Profile:  "default",
		Headers:  headers,
		Remove:   removeCopy,
		Services: make(map[string]SecurityServiceConfig),
	}
}

// ─── Security Header Store ──────────────────────────────────────────────────

// SecurityHeaderStore manages security header configuration with file-backed persistence.
type SecurityHeaderStore struct {
	mu   sync.RWMutex
	cfg  SecurityHeaderConfig
	path string
}

// NewSecurityHeaderStore creates a security header store, loading from path if it exists.
func NewSecurityHeaderStore(path string) *SecurityHeaderStore {
	s := &SecurityHeaderStore{
		cfg:  defaultSecurityHeaderConfig(),
		path: path,
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("warning: could not read security headers config %s: %v", path, err)
		}
		return s
	}
	var cfg SecurityHeaderConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("warning: could not parse security headers config %s: %v", path, err)
		return s
	}
	if cfg.Services == nil {
		cfg.Services = make(map[string]SecurityServiceConfig)
	}
	// Backfill headers from profile if empty (first-time migration).
	if cfg.Profile != "" && cfg.Profile != "custom" && len(cfg.Headers) == 0 {
		if prof, ok := securityProfiles[cfg.Profile]; ok {
			cfg.Headers = make(map[string]string)
			for k, v := range prof.Headers {
				cfg.Headers[k] = v
			}
			cfg.Remove = make([]string, len(prof.Remove))
			copy(cfg.Remove, prof.Remove)
		}
	}
	s.cfg = cfg
	log.Printf("loaded security headers config: profile=%s, %d services", cfg.Profile, len(cfg.Services))
	return s
}

// Get returns a deep copy of the current config.
func (s *SecurityHeaderStore) Get() SecurityHeaderConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deepCopy()
}

// Update replaces the entire config (validated before save).
func (s *SecurityHeaderStore) Update(cfg SecurityHeaderConfig) (SecurityHeaderConfig, error) {
	if cfg.Services == nil {
		cfg.Services = make(map[string]SecurityServiceConfig)
	}
	if err := validateSecurityHeaderConfig(cfg); err != nil {
		return SecurityHeaderConfig{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.cfg
	s.cfg = cfg
	if err := s.saveLocked(); err != nil {
		s.cfg = old
		return SecurityHeaderConfig{}, err
	}
	return s.deepCopy(), nil
}

// Resolve returns the effective headers for a service.
func (s *SecurityHeaderStore) Resolve(service string) ResolvedSecurityHeaders {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return resolveSecurityHeaders(s.cfg, service)
}

func (s *SecurityHeaderStore) deepCopy() SecurityHeaderConfig {
	cp := SecurityHeaderConfig{
		Enabled: copyBoolPtr(s.cfg.Enabled),
		Profile: s.cfg.Profile,
		Headers: copyStringMap(s.cfg.Headers),
		Remove:  copyStringSlice(s.cfg.Remove),
	}
	cp.Services = make(map[string]SecurityServiceConfig, len(s.cfg.Services))
	for k, v := range s.cfg.Services {
		cp.Services[k] = SecurityServiceConfig{
			Profile: v.Profile,
			Headers: copyStringMap(v.Headers),
			Remove:  copyStringSlice(v.Remove),
		}
	}
	return cp
}

func (s *SecurityHeaderStore) saveLocked() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling security headers config: %w", err)
	}
	return atomicWriteFile(s.path, data, 0644)
}

// StoreInfo returns info for the health endpoint.
func (s *SecurityHeaderStore) StoreInfo() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	enabled := s.cfg.Enabled == nil || *s.cfg.Enabled
	return map[string]any{
		"profile":  s.cfg.Profile,
		"services": len(s.cfg.Services),
		"enabled":  enabled,
	}
}

// ─── HTTP Handlers ──────────────────────────────────────────────────────────

// handleGetSecurityHeaders returns the full security header configuration.
func handleGetSecurityHeaders(store *SecurityHeaderStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, store.Get())
	}
}

// handleUpdateSecurityHeaders replaces the entire security header configuration.
func handleUpdateSecurityHeaders(store *SecurityHeaderStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg SecurityHeaderConfig
		if _, failed := decodeJSON(w, r, &cfg); failed {
			return
		}
		updated, err := store.Update(cfg)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

// handleListSecurityProfiles returns the available security header profiles.
func handleListSecurityProfiles() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		profiles := make([]SecurityProfile, 0, len(securityProfiles))
		names := make([]string, 0, len(securityProfiles))
		for k := range securityProfiles {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			profiles = append(profiles, securityProfiles[name])
		}
		writeJSON(w, http.StatusOK, profiles)
	}
}

// SecurityHeaderDeployResponse is returned by the security headers deploy endpoint.
type SecurityHeaderDeployResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	Reloaded  bool   `json:"reloaded"`
	Timestamp string `json:"timestamp"`
}

// handleDeploySecurityHeaders generates security header config and triggers policy engine hot-reload.
func handleDeploySecurityHeaders(store *SecurityHeaderStore, cspStore *CSPStore, cs *ConfigStore, es *ExclusionStore, ls *ManagedListStore, ds *DefaultRuleStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		deployMu.Lock()
		defer deployMu.Unlock()

		allExclusions := es.EnabledExclusions()
		rlGlobal := cs.Get().RateLimitGlobal
		svcMap := BuildServiceFQDNMap(deployCfg.CaddyfilePath)
		respHeaders := BuildPolicyResponseHeaders(cspStore, store, svcMap)
		wafCfg := BuildPolicyWafConfig(cs, svcMap)
		policyData, err := GeneratePolicyRulesWithRL(allExclusions, rlGlobal, ls, svcMap, respHeaders, wafCfg)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error:   "failed to generate policy rules",
				Details: err.Error(),
			})
			return
		}
		policyData, err = ApplyDefaultRuleOverrides(policyData, ds)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error:   "failed to apply default rule overrides",
				Details: err.Error(),
			})
			return
		}
		if err := atomicWriteFile(deployCfg.PolicyRulesFile, policyData, 0644); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error:   "failed to write policy rules file",
				Details: err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, SecurityHeaderDeployResponse{
			Status:    "ok",
			Message:   "Security headers updated in policy-rules.json (hot-reload)",
			Reloaded:  false,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// SecurityHeaderPreviewResponse shows the resolved headers per service.
type SecurityHeaderPreviewResponse struct {
	Global   ResolvedSecurityHeaders            `json:"global"`
	Services map[string]ResolvedSecurityHeaders `json:"services"`
}

// handlePreviewSecurityHeaders returns the resolved headers per service without deploying.
func handlePreviewSecurityHeaders(store *SecurityHeaderStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		cfg := store.Get()
		global := resolveSecurityHeaders(cfg, "")
		services := make(map[string]ResolvedSecurityHeaders)

		// Explicitly configured services.
		for svc := range cfg.Services {
			services[svc] = resolveSecurityHeaders(cfg, svc)
		}

		// Discover services from Caddyfile.
		discovered := discoverCaddyfileServices(deployCfg.CaddyfilePath)
		for _, svc := range discovered {
			if _, exists := services[svc]; exists {
				continue
			}
			services[svc] = global
		}

		writeJSON(w, http.StatusOK, SecurityHeaderPreviewResponse{
			Global:   global,
			Services: services,
		})
	}
}
