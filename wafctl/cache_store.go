package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
)

// ─── Cache Control Store ────────────────────────────────────────────────────
//
// Manages path-based Cache-Control response headers for the policy engine plugin.
// Rules match response paths by file extension or glob pattern and set
// Cache-Control headers (with set-if-absent support via the "default" mode).
//
// The plugin applies these rules to responses after reverse proxying, similar
// to the Caddyfile (static_cache) snippet but managed via API + hot-reload.

// CacheRule is a single cache-control rule that matches paths by pattern.
type CacheRule struct {
	// Pattern matches the response path. Supports file extension globs:
	// "*.woff2", "*.{css,js}", "/_astro/*", "/static/*".
	Pattern string `json:"pattern"`

	// Value is the Cache-Control header value to set.
	// Example: "public, max-age=31536000, immutable"
	Value string `json:"value"`

	// Mode controls how the header is applied:
	//   "set"     — always set (overrides upstream Cache-Control)
	//   "default" — set only if upstream did not send Cache-Control (? prefix in Caddyfile)
	// Default: "default" (matches Caddyfile ?Cache-Control behavior).
	Mode string `json:"mode,omitempty"`
}

// CacheConfig holds the complete cache-control configuration.
type CacheConfig struct {
	// Enabled controls whether cache-control rules are applied.
	Enabled *bool `json:"enabled,omitempty"` // nil = true

	// GlobalRules apply to all services.
	GlobalRules []CacheRule `json:"global_rules,omitempty"`

	// PerService holds service-specific cache rules. Keyed by hostname or short name.
	// Per-service rules are evaluated after global rules.
	PerService map[string][]CacheRule `json:"per_service,omitempty"`
}

// CacheStore manages cache-control configuration with file-backed persistence.
type CacheStore struct {
	mu   sync.RWMutex
	cfg  CacheConfig
	path string
}

// NewCacheStore creates a new cache store and loads existing data from disk.
func NewCacheStore(filePath string) *CacheStore {
	s := &CacheStore{
		path: filePath,
		cfg: CacheConfig{
			PerService: make(map[string][]CacheRule),
		},
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err == nil {
			if err := json.Unmarshal(data, &s.cfg); err != nil {
				log.Printf("[cache] invalid config: %v", err)
			} else {
				if s.cfg.PerService == nil {
					s.cfg.PerService = make(map[string][]CacheRule)
				}
				log.Printf("[cache] loaded %d global rules, %d services from %s",
					len(s.cfg.GlobalRules), len(s.cfg.PerService), filePath)
			}
		}
	}
	return s
}

// Get returns a deep copy of the current configuration.
func (s *CacheStore) Get() CacheConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cp := CacheConfig{
		Enabled:     copyBoolPtr(s.cfg.Enabled),
		GlobalRules: make([]CacheRule, len(s.cfg.GlobalRules)),
		PerService:  make(map[string][]CacheRule, len(s.cfg.PerService)),
	}
	copy(cp.GlobalRules, s.cfg.GlobalRules)
	for k, v := range s.cfg.PerService {
		rules := make([]CacheRule, len(v))
		copy(rules, v)
		cp.PerService[k] = rules
	}
	return cp
}

// Update replaces the configuration and persists to disk.
func (s *CacheStore) Update(cfg CacheConfig) (CacheConfig, error) {
	if cfg.PerService == nil {
		cfg.PerService = make(map[string][]CacheRule)
	}
	if err := validateCacheConfig(cfg); err != nil {
		return CacheConfig{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.cfg
	s.cfg = cfg
	if err := s.save(); err != nil {
		s.cfg = old
		return CacheConfig{}, err
	}
	return s.Get(), nil
}

func (s *CacheStore) save() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling cache config: %w", err)
	}
	return atomicWriteFile(s.path, data, 0644)
}

// ─── HTTP Handlers ──────────────────────────────────────────────────────────

// handleGetCache returns the full cache-control configuration.
func handleGetCache(store *CacheStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, store.Get())
	}
}

// handleUpdateCache replaces the entire cache-control configuration.
func handleUpdateCache(store *CacheStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg CacheConfig
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

// StoreInfo returns info for the health endpoint.
func (s *CacheStore) StoreInfo() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	enabled := s.cfg.Enabled == nil || *s.cfg.Enabled
	return map[string]any{
		"enabled":      enabled,
		"global_rules": len(s.cfg.GlobalRules),
		"services":     len(s.cfg.PerService),
	}
}

// ─── Validation ─────────────────────────────────────────────────────────────

var validCacheModes = map[string]bool{
	"":        true, // default = "default"
	"set":     true,
	"default": true,
}

func validateCacheConfig(cfg CacheConfig) error {
	for i, r := range cfg.GlobalRules {
		if err := validateCacheRule(r); err != nil {
			return fmt.Errorf("global_rules[%d]: %w", i, err)
		}
	}
	for svc, rules := range cfg.PerService {
		for i, r := range rules {
			if err := validateCacheRule(r); err != nil {
				return fmt.Errorf("per_service[%s][%d]: %w", svc, i, err)
			}
		}
	}
	return nil
}

func validateCacheRule(r CacheRule) error {
	if r.Pattern == "" {
		return fmt.Errorf("pattern is required")
	}
	if r.Value == "" {
		return fmt.Errorf("value is required")
	}
	if !validCacheModes[r.Mode] {
		return fmt.Errorf("invalid mode %q (must be \"set\" or \"default\")", r.Mode)
	}
	return nil
}
