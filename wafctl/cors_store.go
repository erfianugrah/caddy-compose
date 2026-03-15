package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
)

// ─── CORS Store ─────────────────────────────────────────────────────────────
//
// Manages CORS (Cross-Origin Resource Sharing) configuration for the policy
// engine plugin. Replaces the Caddyfile (cors) snippet with hot-reloadable,
// per-service CORS config managed via API.
//
// The plugin handles both preflight (OPTIONS) and normal CORS responses,
// including origin validation against the allowed origins list.

// CORSConfig holds the complete CORS configuration.
type CORSConfig struct {
	// Enabled controls whether CORS headers are injected.
	Enabled *bool `json:"enabled,omitempty"` // nil = true

	// Global defaults applied to all services unless overridden.
	Global CORSSettings `json:"global"`

	// PerService holds per-service CORS overrides. Keyed by hostname or short name.
	PerService map[string]CORSSettings `json:"per_service,omitempty"`
}

// CORSSettings holds CORS configuration for a scope (global or per-service).
type CORSSettings struct {
	// AllowedOrigins is a list of allowed origin patterns.
	// Supports exact origins ("https://app.erfi.io") and regex patterns
	// ("^https://[a-z0-9-]+\\.erfi\\.io$"). Empty means no CORS headers.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`

	// AllowedMethods for Access-Control-Allow-Methods header.
	// Default: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
	AllowedMethods []string `json:"allowed_methods,omitempty"`

	// AllowedHeaders for Access-Control-Allow-Headers header.
	// Default: ["Content-Type", "Authorization"]
	AllowedHeaders []string `json:"allowed_headers,omitempty"`

	// ExposedHeaders for Access-Control-Expose-Headers header.
	ExposedHeaders []string `json:"exposed_headers,omitempty"`

	// MaxAge for Access-Control-Max-Age header (in seconds).
	// Default: 3600 (1 hour).
	MaxAge int `json:"max_age,omitempty"`

	// AllowCredentials controls Access-Control-Allow-Credentials header.
	AllowCredentials bool `json:"allow_credentials,omitempty"`
}

// CORSStore manages CORS configuration with file-backed persistence.
type CORSStore struct {
	mu   sync.RWMutex
	cfg  CORSConfig
	path string
}

// NewCORSStore creates a new CORS store and loads existing data from disk.
func NewCORSStore(filePath string) *CORSStore {
	s := &CORSStore{
		path: filePath,
		cfg: CORSConfig{
			PerService: make(map[string]CORSSettings),
		},
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err == nil {
			if err := json.Unmarshal(data, &s.cfg); err != nil {
				log.Printf("[cors] invalid config: %v", err)
			} else {
				if s.cfg.PerService == nil {
					s.cfg.PerService = make(map[string]CORSSettings)
				}
				log.Printf("[cors] loaded %d origins, %d services from %s",
					len(s.cfg.Global.AllowedOrigins), len(s.cfg.PerService), filePath)
			}
		}
	}
	return s
}

// Get returns a deep copy of the current configuration.
func (s *CORSStore) Get() CORSConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cp := CORSConfig{
		Enabled: copyBoolPtr(s.cfg.Enabled),
		Global: CORSSettings{
			AllowedOrigins:   copyStringSlice(s.cfg.Global.AllowedOrigins),
			AllowedMethods:   copyStringSlice(s.cfg.Global.AllowedMethods),
			AllowedHeaders:   copyStringSlice(s.cfg.Global.AllowedHeaders),
			ExposedHeaders:   copyStringSlice(s.cfg.Global.ExposedHeaders),
			MaxAge:           s.cfg.Global.MaxAge,
			AllowCredentials: s.cfg.Global.AllowCredentials,
		},
		PerService: make(map[string]CORSSettings, len(s.cfg.PerService)),
	}
	for k, v := range s.cfg.PerService {
		cp.PerService[k] = CORSSettings{
			AllowedOrigins:   copyStringSlice(v.AllowedOrigins),
			AllowedMethods:   copyStringSlice(v.AllowedMethods),
			AllowedHeaders:   copyStringSlice(v.AllowedHeaders),
			ExposedHeaders:   copyStringSlice(v.ExposedHeaders),
			MaxAge:           v.MaxAge,
			AllowCredentials: v.AllowCredentials,
		}
	}
	return cp
}

// Update replaces the configuration and persists to disk.
func (s *CORSStore) Update(cfg CORSConfig) (CORSConfig, error) {
	if cfg.PerService == nil {
		cfg.PerService = make(map[string]CORSSettings)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.cfg
	s.cfg = cfg
	if err := s.save(); err != nil {
		s.cfg = old
		return CORSConfig{}, err
	}
	return s.Get(), nil
}

func (s *CORSStore) save() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling CORS config: %w", err)
	}
	return atomicWriteFile(s.path, data, 0644)
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

// StoreInfo returns info for the health endpoint.
func (s *CORSStore) StoreInfo() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	enabled := s.cfg.Enabled == nil || *s.cfg.Enabled
	return map[string]any{
		"enabled":  enabled,
		"origins":  len(s.cfg.Global.AllowedOrigins),
		"services": len(s.cfg.PerService),
	}
}
