package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
)

// ─── CORS Data Model ────────────────────────────────────────────────────────

// CORSConfig is the top-level CORS configuration.
type CORSConfig struct {
	// Enabled controls whether CORS headers are injected.
	// Uses *bool so that existing JSON files without the field default to true.
	Enabled *bool `json:"enabled,omitempty"`

	// Global holds the default CORS settings for all services.
	Global CORSSettings `json:"global"`

	// PerService holds per-service CORS overrides keyed by short service name.
	PerService map[string]CORSSettings `json:"per_service,omitempty"`
}

// CORSSettings holds CORS header values for a single scope (global or per-service).
type CORSSettings struct {
	AllowedOrigins   []string `json:"allowed_origins,omitempty"`
	AllowedMethods   []string `json:"allowed_methods,omitempty"`
	AllowedHeaders   []string `json:"allowed_headers,omitempty"`
	ExposedHeaders   []string `json:"exposed_headers,omitempty"`
	MaxAge           int      `json:"max_age,omitempty"`
	AllowCredentials bool     `json:"allow_credentials,omitempty"`
}

// ─── Validation ─────────────────────────────────────────────────────────────

// validateCORSConfig checks the config for invalid values.
func validateCORSConfig(cfg CORSConfig) error {
	enabled := cfg.Enabled == nil || *cfg.Enabled
	if enabled && len(cfg.Global.AllowedOrigins) == 0 {
		return fmt.Errorf("allowed_origins must be non-empty when CORS is enabled")
	}
	for svc := range cfg.PerService {
		if !secServiceNameRe.MatchString(svc) {
			return fmt.Errorf("service %q: invalid service name", svc)
		}
	}
	return nil
}

// ─── Default Configuration ──────────────────────────────────────────────────

// defaultCORSConfig returns a sensible default (disabled, no origins).
func defaultCORSConfig() CORSConfig {
	return CORSConfig{
		Enabled:    boolPtr(false),
		Global:     CORSSettings{},
		PerService: make(map[string]CORSSettings),
	}
}

// ─── CORS Store ─────────────────────────────────────────────────────────────

// CORSStore manages CORS configuration with file-backed persistence.
type CORSStore struct {
	mu   sync.RWMutex
	cfg  CORSConfig
	path string
}

// NewCORSStore creates a CORS store, loading from path if it exists.
func NewCORSStore(path string) *CORSStore {
	s := &CORSStore{
		cfg:  defaultCORSConfig(),
		path: path,
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[cors] warning: could not read CORS config %s: %v", path, err)
		}
		return s
	}
	var cfg CORSConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[cors] warning: could not parse CORS config %s: %v", path, err)
		return s
	}
	if cfg.PerService == nil {
		cfg.PerService = make(map[string]CORSSettings)
	}
	s.cfg = cfg
	log.Printf("[cors] loaded CORS config: %d per-service overrides", len(cfg.PerService))
	return s
}

// Get returns a deep copy of the current config.
func (s *CORSStore) Get() CORSConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deepCopy()
}

// Update replaces the entire config (validated before save).
func (s *CORSStore) Update(cfg CORSConfig) (CORSConfig, error) {
	if cfg.PerService == nil {
		cfg.PerService = make(map[string]CORSSettings)
	}
	if err := validateCORSConfig(cfg); err != nil {
		return CORSConfig{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.cfg
	s.cfg = cfg
	if err := s.saveLocked(); err != nil {
		s.cfg = old
		return CORSConfig{}, err
	}
	return s.deepCopy(), nil
}

func (s *CORSStore) deepCopy() CORSConfig {
	cp := CORSConfig{
		Enabled: copyBoolPtr(s.cfg.Enabled),
		Global:  copyCORSSettings(s.cfg.Global),
	}
	cp.PerService = make(map[string]CORSSettings, len(s.cfg.PerService))
	for k, v := range s.cfg.PerService {
		cp.PerService[k] = copyCORSSettings(v)
	}
	return cp
}

func copyCORSSettings(cs CORSSettings) CORSSettings {
	return CORSSettings{
		AllowedOrigins:   copyStringSlice(cs.AllowedOrigins),
		AllowedMethods:   copyStringSlice(cs.AllowedMethods),
		AllowedHeaders:   copyStringSlice(cs.AllowedHeaders),
		ExposedHeaders:   copyStringSlice(cs.ExposedHeaders),
		MaxAge:           cs.MaxAge,
		AllowCredentials: cs.AllowCredentials,
	}
}

func (s *CORSStore) saveLocked() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling CORS config: %w", err)
	}
	return atomicWriteFile(s.path, data, 0644)
}

// StoreInfo returns info for the health endpoint.
func (s *CORSStore) StoreInfo() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	enabled := s.cfg.Enabled == nil || *s.cfg.Enabled
	return map[string]any{
		"per_service": len(s.cfg.PerService),
		"enabled":     enabled,
	}
}

// ─── HTTP Handlers ──────────────────────────────────────────────────────────

// handleGetCORS returns the full CORS configuration.
func handleGetCORS(store *CORSStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, store.Get())
	}
}

// handleUpdateCORS replaces the entire CORS configuration.
func handleUpdateCORS(store *CORSStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg CORSConfig
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
