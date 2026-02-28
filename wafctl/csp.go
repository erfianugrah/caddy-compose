package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── CSP Data Model ─────────────────────────────────────────────────────────

// CSPPolicy holds the structured CSP directives plus a raw escape hatch.
// Each directive field is a slice of source values (e.g. ["'self'", "data:", "https:"]).
// Empty/nil slices mean "not set" — the directive is omitted from the header.
type CSPPolicy struct {
	DefaultSrc  []string `json:"default_src,omitempty"`
	ScriptSrc   []string `json:"script_src,omitempty"`
	StyleSrc    []string `json:"style_src,omitempty"`
	ImgSrc      []string `json:"img_src,omitempty"`
	FontSrc     []string `json:"font_src,omitempty"`
	ConnectSrc  []string `json:"connect_src,omitempty"`
	MediaSrc    []string `json:"media_src,omitempty"`
	FrameSrc    []string `json:"frame_src,omitempty"`
	WorkerSrc   []string `json:"worker_src,omitempty"`
	ObjectSrc   []string `json:"object_src,omitempty"`
	ChildSrc    []string `json:"child_src,omitempty"`
	ManifestSrc []string `json:"manifest_src,omitempty"`
	BaseURI     []string `json:"base_uri,omitempty"`
	FormAction  []string `json:"form_action,omitempty"`
	FrameAnc    []string `json:"frame_ancestors,omitempty"`

	// UpgradeInsecureRequests is a standalone boolean directive (no values).
	UpgradeInsecureRequests bool `json:"upgrade_insecure_requests,omitempty"`

	// RawDirectives are appended verbatim to the CSP header string.
	// Use for exotic directives not covered by the structured fields.
	RawDirectives string `json:"raw_directives,omitempty"`
}

// CSPServiceConfig holds the CSP configuration for a single service.
type CSPServiceConfig struct {
	// Mode controls how the CSP header is applied:
	//   "set"     — always set CSP (overwrite any upstream header)
	//   "default" — only set if upstream didn't send one (Caddy ? prefix)
	//   "none"    — do not add CSP for this service
	Mode string `json:"mode"`

	// ReportOnly uses Content-Security-Policy-Report-Only instead of enforcing.
	ReportOnly bool `json:"report_only"`

	// Inherit: if true, start from GlobalDefaults and merge this service's policy
	// on top. If false, use this service's policy as-is.
	Inherit bool `json:"inherit"`

	// Policy is the per-service CSP directive overrides.
	Policy CSPPolicy `json:"policy"`
}

// CSPConfig is the top-level CSP configuration.
type CSPConfig struct {
	// Enabled controls whether CSP headers are emitted at all.
	// When false, all generated files are comment-only placeholders.
	// Uses *bool so that existing JSON files without the field default to true.
	Enabled        *bool                       `json:"enabled,omitempty"`
	GlobalDefaults CSPPolicy                   `json:"global_defaults"`
	Services       map[string]CSPServiceConfig `json:"services"`
}

// cspEnabled returns whether CSP is enabled (nil defaults to true).
func cspEnabled(cfg CSPConfig) bool {
	return cfg.Enabled == nil || *cfg.Enabled
}

// ─── Validation ─────────────────────────────────────────────────────────────

// Valid CSP modes.
var validCSPModes = map[string]bool{
	"set":     true,
	"default": true,
	"none":    true,
}

// validateCSPConfig checks the config for invalid values.
func validateCSPConfig(cfg CSPConfig) error {
	if err := validateCSPPolicy(cfg.GlobalDefaults); err != nil {
		return fmt.Errorf("global_defaults: %w", err)
	}
	for svc, sc := range cfg.Services {
		if !validCSPModes[sc.Mode] {
			return fmt.Errorf("service %q: invalid mode %q (must be set, default, or none)", svc, sc.Mode)
		}
		if err := validateCSPPolicy(sc.Policy); err != nil {
			return fmt.Errorf("service %q: %w", svc, err)
		}
	}
	return nil
}

// validateCSPPolicy checks individual source values for obviously invalid content.
func validateCSPPolicy(p CSPPolicy) error {
	// Check all directive slices for embedded newlines or semicolons.
	allDirectives := map[string][]string{
		"default_src":     p.DefaultSrc,
		"script_src":      p.ScriptSrc,
		"style_src":       p.StyleSrc,
		"img_src":         p.ImgSrc,
		"font_src":        p.FontSrc,
		"connect_src":     p.ConnectSrc,
		"media_src":       p.MediaSrc,
		"frame_src":       p.FrameSrc,
		"worker_src":      p.WorkerSrc,
		"object_src":      p.ObjectSrc,
		"child_src":       p.ChildSrc,
		"manifest_src":    p.ManifestSrc,
		"base_uri":        p.BaseURI,
		"form_action":     p.FormAction,
		"frame_ancestors": p.FrameAnc,
	}
	for name, values := range allDirectives {
		for _, v := range values {
			if strings.ContainsAny(v, "\n\r;") {
				return fmt.Errorf("%s: value %q contains invalid characters", name, v)
			}
		}
	}
	if strings.ContainsAny(p.RawDirectives, "\n\r") {
		return fmt.Errorf("raw_directives: contains newline characters")
	}
	return nil
}

// ─── CSP Header Builder ─────────────────────────────────────────────────────

// buildCSPHeader constructs the CSP header string from a policy.
func buildCSPHeader(p CSPPolicy) string {
	var parts []string

	directives := []struct {
		name   string
		values []string
	}{
		{"default-src", p.DefaultSrc},
		{"script-src", p.ScriptSrc},
		{"style-src", p.StyleSrc},
		{"img-src", p.ImgSrc},
		{"font-src", p.FontSrc},
		{"connect-src", p.ConnectSrc},
		{"media-src", p.MediaSrc},
		{"frame-src", p.FrameSrc},
		{"worker-src", p.WorkerSrc},
		{"object-src", p.ObjectSrc},
		{"child-src", p.ChildSrc},
		{"manifest-src", p.ManifestSrc},
		{"base-uri", p.BaseURI},
		{"form-action", p.FormAction},
		{"frame-ancestors", p.FrameAnc},
	}

	for _, d := range directives {
		if len(d.values) > 0 {
			parts = append(parts, d.name+" "+strings.Join(d.values, " "))
		}
	}

	if p.UpgradeInsecureRequests {
		parts = append(parts, "upgrade-insecure-requests")
	}

	if p.RawDirectives != "" {
		parts = append(parts, strings.TrimSpace(p.RawDirectives))
	}

	return strings.Join(parts, "; ")
}

// mergeCSPPolicy overlays the override on top of the base.
// Non-empty override slices replace the base; empty slices keep the base.
func mergeCSPPolicy(base, override CSPPolicy) CSPPolicy {
	merged := base
	if len(override.DefaultSrc) > 0 {
		merged.DefaultSrc = override.DefaultSrc
	}
	if len(override.ScriptSrc) > 0 {
		merged.ScriptSrc = override.ScriptSrc
	}
	if len(override.StyleSrc) > 0 {
		merged.StyleSrc = override.StyleSrc
	}
	if len(override.ImgSrc) > 0 {
		merged.ImgSrc = override.ImgSrc
	}
	if len(override.FontSrc) > 0 {
		merged.FontSrc = override.FontSrc
	}
	if len(override.ConnectSrc) > 0 {
		merged.ConnectSrc = override.ConnectSrc
	}
	if len(override.MediaSrc) > 0 {
		merged.MediaSrc = override.MediaSrc
	}
	if len(override.FrameSrc) > 0 {
		merged.FrameSrc = override.FrameSrc
	}
	if len(override.WorkerSrc) > 0 {
		merged.WorkerSrc = override.WorkerSrc
	}
	if len(override.ObjectSrc) > 0 {
		merged.ObjectSrc = override.ObjectSrc
	}
	if len(override.ChildSrc) > 0 {
		merged.ChildSrc = override.ChildSrc
	}
	if len(override.ManifestSrc) > 0 {
		merged.ManifestSrc = override.ManifestSrc
	}
	if len(override.BaseURI) > 0 {
		merged.BaseURI = override.BaseURI
	}
	if len(override.FormAction) > 0 {
		merged.FormAction = override.FormAction
	}
	if len(override.FrameAnc) > 0 {
		merged.FrameAnc = override.FrameAnc
	}
	if override.UpgradeInsecureRequests {
		merged.UpgradeInsecureRequests = true
	}
	if override.RawDirectives != "" {
		merged.RawDirectives = override.RawDirectives
	}
	return merged
}

// ─── Default Configuration ──────────────────────────────────────────────────

// boolPtr returns a pointer to the given bool value.
func boolPtr(v bool) *bool { return &v }

// defaultCSPConfig returns the pragmatic baseline for reverse-proxied apps.
func defaultCSPConfig() CSPConfig {
	return CSPConfig{
		Enabled: boolPtr(true),
		GlobalDefaults: CSPPolicy{
			DefaultSrc:              []string{"'self'"},
			ScriptSrc:               []string{"'self'", "'unsafe-inline'"},
			StyleSrc:                []string{"'self'", "'unsafe-inline'"},
			ImgSrc:                  []string{"'self'", "data:"},
			FontSrc:                 []string{"'self'", "data:"},
			ConnectSrc:              []string{"'self'", "wss:"},
			ObjectSrc:               []string{"'none'"},
			BaseURI:                 []string{"'self'"},
			FrameAnc:                []string{"'self'"},
			UpgradeInsecureRequests: true,
		},
		Services: make(map[string]CSPServiceConfig),
	}
}

// ─── CSP Store ──────────────────────────────────────────────────────────────

// CSPStore manages CSP configuration with file-backed persistence.
type CSPStore struct {
	mu   sync.RWMutex
	cfg  CSPConfig
	path string
}

// NewCSPStore creates a CSP store, loading from path if it exists.
func NewCSPStore(path string) *CSPStore {
	s := &CSPStore{
		cfg:  defaultCSPConfig(),
		path: path,
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("warning: could not read CSP config %s: %v", path, err)
		}
		return s
	}
	var cfg CSPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("warning: could not parse CSP config %s: %v", path, err)
		return s
	}
	if cfg.Services == nil {
		cfg.Services = make(map[string]CSPServiceConfig)
	}
	s.cfg = cfg
	log.Printf("loaded CSP config: %d service overrides", len(cfg.Services))
	return s
}

// Get returns a deep copy of the current CSP config.
func (s *CSPStore) Get() CSPConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deepCopy()
}

// Update replaces the entire CSP config (validated before save).
func (s *CSPStore) Update(cfg CSPConfig) (CSPConfig, error) {
	if cfg.Services == nil {
		cfg.Services = make(map[string]CSPServiceConfig)
	}
	if err := validateCSPConfig(cfg); err != nil {
		return CSPConfig{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.cfg
	s.cfg = cfg
	if err := s.saveLocked(); err != nil {
		s.cfg = old
		return CSPConfig{}, err
	}
	return s.deepCopy(), nil
}

// ServiceNames returns a sorted list of all configured service names.
func (s *CSPStore) ServiceNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.cfg.Services))
	for k := range s.cfg.Services {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// ResolvePolicy returns the effective CSP policy for a service after merging
// with global defaults (if inherit is true).
func (s *CSPStore) ResolvePolicy(service string) (CSPPolicy, CSPServiceConfig) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sc, ok := s.cfg.Services[service]
	if !ok {
		// No override — use global defaults with "set" mode.
		return s.cfg.GlobalDefaults, CSPServiceConfig{Mode: "set", Inherit: true}
	}
	if sc.Mode == "none" {
		return CSPPolicy{}, sc
	}
	if sc.Inherit {
		return mergeCSPPolicy(s.cfg.GlobalDefaults, sc.Policy), sc
	}
	return sc.Policy, sc
}

func (s *CSPStore) deepCopy() CSPConfig {
	data, _ := json.Marshal(s.cfg)
	var copy CSPConfig
	json.Unmarshal(data, &copy)
	if copy.Services == nil {
		copy.Services = make(map[string]CSPServiceConfig)
	}
	return copy
}

func (s *CSPStore) saveLocked() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling CSP config: %w", err)
	}
	return atomicWriteFile(s.path, data, 0644)
}

// StoreInfo returns info for the health endpoint.
func (s *CSPStore) StoreInfo() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"services": len(s.cfg.Services),
		"enabled":  cspEnabled(s.cfg),
	}
}

// ─── HTTP Handlers ──────────────────────────────────────────────────────────

// handleGetCSP returns the full CSP configuration.
func handleGetCSP(store *CSPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, store.Get())
	}
}

// handleUpdateCSP replaces the entire CSP configuration.
func handleUpdateCSP(store *CSPStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg CSPConfig
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

// CSPDeployResponse is returned by the CSP deploy endpoint.
type CSPDeployResponse struct {
	Status    string   `json:"status"`
	Message   string   `json:"message"`
	Files     []string `json:"files"`
	Reloaded  bool     `json:"reloaded"`
	Timestamp string   `json:"timestamp"`
}

// handleDeployCSP generates CSP config files and reloads Caddy.
func handleDeployCSP(store *CSPStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		files := GenerateCSPConfigs(store, deployCfg.CaddyfilePath)

		written, err := writeCSPFiles(deployCfg.CSPDir, files)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error:   "failed to write CSP configs",
				Details: err.Error(),
			})
			return
		}

		// Collect all config file paths for the reload fingerprint.
		var configPaths []string
		for _, f := range written {
			configPaths = append(configPaths, filepath.Join(deployCfg.CSPDir, f))
		}

		reloaded := false
		if err := reloadCaddy(deployCfg.CaddyfilePath, deployCfg.CaddyAdminURL, configPaths...); err != nil {
			log.Printf("CSP deploy: Caddy reload failed: %v", err)
		} else {
			reloaded = true
		}

		writeJSON(w, http.StatusOK, CSPDeployResponse{
			Status:    "ok",
			Message:   fmt.Sprintf("generated %d CSP files", len(written)),
			Files:     written,
			Reloaded:  reloaded,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// CSPPreviewResponse contains the rendered CSP header strings per service.
type CSPPreviewResponse struct {
	Services map[string]CSPPreviewEntry `json:"services"`
}

// CSPPreviewEntry shows the rendered CSP for a single service.
type CSPPreviewEntry struct {
	Mode       string `json:"mode"`
	ReportOnly bool   `json:"report_only"`
	Header     string `json:"header"`
}

// handlePreviewCSP returns the rendered CSP header strings for all services
// without deploying. Includes Caddyfile-discovered services that inherit
// global defaults even when they have no explicit override.
// When CSP is globally disabled, returns an empty services map.
func handlePreviewCSP(store *CSPStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		cfg := store.Get()
		result := make(map[string]CSPPreviewEntry)

		if !cspEnabled(cfg) {
			writeJSON(w, http.StatusOK, CSPPreviewResponse{Services: result})
			return
		}

		// 1. Explicitly configured services.
		for service, sc := range cfg.Services {
			if sc.Mode == "none" {
				result[service] = CSPPreviewEntry{Mode: "none"}
				continue
			}
			policy, _ := store.ResolvePolicy(service)
			result[service] = CSPPreviewEntry{
				Mode:       sc.Mode,
				ReportOnly: sc.ReportOnly,
				Header:     buildCSPHeader(policy),
			}
		}

		// 2. Caddyfile-discovered services — check for FQDN parent configs first,
		//    then fall back to global defaults.
		discovered := scanCaddyfileCSPServices(deployCfg.CaddyfilePath)
		for _, svc := range discovered {
			if _, exists := result[svc]; exists {
				continue
			}

			// Check if this FQDN has a parent short-name override.
			if parentSC, ok := findParentServiceConfig(svc, cfg.Services); ok {
				if parentSC.Mode == "none" {
					result[svc] = CSPPreviewEntry{Mode: "none"}
					continue
				}
				var policy CSPPolicy
				if parentSC.Inherit {
					policy = mergeCSPPolicy(cfg.GlobalDefaults, parentSC.Policy)
				} else {
					policy = parentSC.Policy
				}
				result[svc] = CSPPreviewEntry{
					Mode:       parentSC.Mode,
					ReportOnly: parentSC.ReportOnly,
					Header:     buildCSPHeader(policy),
				}
				continue
			}

			policy, sc := store.ResolvePolicy(svc)
			header := buildCSPHeader(policy)
			if header == "" {
				continue
			}
			result[svc] = CSPPreviewEntry{
				Mode:       sc.Mode,
				ReportOnly: sc.ReportOnly,
				Header:     header,
			}
		}

		writeJSON(w, http.StatusOK, CSPPreviewResponse{Services: result})
	}
}
