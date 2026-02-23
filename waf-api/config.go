package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
)

// ConfigStore manages WAF configuration with file-backed persistence.
type ConfigStore struct {
	mu       sync.RWMutex
	config   WAFConfig
	filePath string
}

// NewConfigStore creates a new config store and loads existing data from disk.
func NewConfigStore(filePath string) *ConfigStore {
	s := &ConfigStore{
		filePath: filePath,
		config:   defaultConfig(),
	}
	s.load()
	return s
}

// defaultConfig returns sensible defaults for WAF configuration.
func defaultConfig() WAFConfig {
	return WAFConfig{
		Defaults: WAFServiceSettings{
			Mode:              "enabled",
			ParanoiaLevel:     1,
			InboundThreshold:  5,
			OutboundThreshold: 4,
		},
		Services: make(map[string]WAFServiceSettings),
	}
}

// defaultServiceSettings returns the default WAF service settings.
func defaultServiceSettings() WAFServiceSettings {
	return defaultConfig().Defaults
}

// load reads the config from the JSON file on disk.
// Supports migration from the old flat config format.
func (s *ConfigStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("config file not found at %s, using defaults", s.filePath)
			return
		}
		log.Printf("error reading config file: %v", err)
		return
	}

	// Try new format first.
	var cfg WAFConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("error parsing config file: %v", err)
		return
	}

	// Migration: detect old format by checking if Defaults has zero values
	// and the raw JSON has the old fields (paranoia_level at root level).
	if cfg.Defaults.Mode == "" {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err == nil {
			if _, hasOldField := raw["rule_engine"]; hasOldField {
				cfg = migrateOldConfig(data)
				log.Printf("migrated config from old format")
			} else {
				// New format but missing mode — set defaults.
				cfg.Defaults = defaultServiceSettings()
			}
		}
	}

	if cfg.Services == nil {
		cfg.Services = make(map[string]WAFServiceSettings)
	}

	// Validate loaded/migrated config. If invalid, log warning and use defaults.
	if err := validateConfig(cfg); err != nil {
		log.Printf("WARNING: loaded config is invalid (%v), using defaults", err)
		s.config = defaultConfig()
		return
	}

	s.config = cfg
	log.Printf("loaded config from %s", s.filePath)
}

// migrateOldConfig converts the old flat WAFConfig format to the new per-service format.
func migrateOldConfig(data []byte) WAFConfig {
	var old struct {
		ParanoiaLevel     int                        `json:"paranoia_level"`
		InboundThreshold  int                        `json:"inbound_threshold"`
		OutboundThreshold int                        `json:"outbound_threshold"`
		RuleEngine        string                     `json:"rule_engine"`
		Services          map[string]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal(data, &old); err != nil {
		return defaultConfig()
	}

	// Map old rule_engine to new mode.
	mode := "enabled"
	switch old.RuleEngine {
	case "Off":
		mode = "disabled"
	case "DetectionOnly":
		mode = "detection_only"
	}

	defaults := defaultConfig().Defaults
	pl := old.ParanoiaLevel
	if pl < 1 || pl > 4 {
		pl = defaults.ParanoiaLevel
	}
	inbound := old.InboundThreshold
	if inbound < 1 {
		inbound = defaults.InboundThreshold
	}
	outbound := old.OutboundThreshold
	if outbound < 1 {
		outbound = defaults.OutboundThreshold
	}

	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode:              mode,
			ParanoiaLevel:     pl,
			InboundThreshold:  inbound,
			OutboundThreshold: outbound,
		},
		Services: make(map[string]WAFServiceSettings),
	}

	// Migrate old per-service profiles.
	for svc, raw := range old.Services {
		var sc struct {
			Profile string `json:"profile"`
		}
		if err := json.Unmarshal(raw, &sc); err != nil {
			continue
		}
		svcMode := "enabled"
		svcPL := pl         // use clamped default paranoia level
		svcInT := inbound   // use clamped default inbound threshold
		svcOutT := outbound // use clamped default outbound threshold
		switch sc.Profile {
		case "strict":
			svcInT, svcOutT = 5, 4
		case "tuning":
			svcMode = "detection_only"
			svcInT, svcOutT = 10000, 10000
		case "off":
			svcMode = "disabled"
		}
		cfg.Services[svc] = WAFServiceSettings{
			Mode:              svcMode,
			ParanoiaLevel:     svcPL,
			InboundThreshold:  svcInT,
			OutboundThreshold: svcOutT,
		}
	}

	return cfg
}

// save writes the current config to the JSON file atomically.
func (s *ConfigStore) save() error {
	data, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling config: %w", err)
	}
	if err := atomicWriteFile(s.filePath, data, 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}
	return nil
}

// Get returns the current configuration.
func (s *ConfigStore) Get() WAFConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a deep copy.
	cp := s.config
	cp.Defaults.DisabledGroups = copyStringSlice(s.config.Defaults.DisabledGroups)
	cp.Services = make(map[string]WAFServiceSettings, len(s.config.Services))
	for k, v := range s.config.Services {
		v.DisabledGroups = copyStringSlice(v.DisabledGroups)
		cp.Services[k] = v
	}
	return cp
}

// Update replaces the configuration and persists to disk.
func (s *ConfigStore) Update(cfg WAFConfig) (WAFConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cfg.Services == nil {
		cfg.Services = make(map[string]WAFServiceSettings)
	}

	old := s.config
	s.config = cfg
	if err := s.save(); err != nil {
		s.config = old // roll back
		return WAFConfig{}, err
	}
	return cfg, nil
}

// copyStringSlice returns a copy of a string slice (nil-safe).
func copyStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	return cp
}

// validateConfig checks that the config has valid values.
func validateConfig(cfg WAFConfig) error {
	if err := validateServiceSettings("defaults", cfg.Defaults); err != nil {
		return err
	}
	for svc, ss := range cfg.Services {
		if err := validateServiceSettings(svc, ss); err != nil {
			return err
		}
	}
	return nil
}

// validateServiceSettings validates a single WAFServiceSettings.
func validateServiceSettings(name string, ss WAFServiceSettings) error {
	if !validWAFModes[ss.Mode] {
		return fmt.Errorf("%s: mode must be enabled, detection_only, or disabled (got %q)", name, ss.Mode)
	}
	if ss.ParanoiaLevel < 1 || ss.ParanoiaLevel > 4 {
		return fmt.Errorf("%s: paranoia_level must be between 1 and 4", name)
	}
	if ss.InboundThreshold < 1 {
		return fmt.Errorf("%s: inbound_threshold must be at least 1", name)
	}
	if ss.OutboundThreshold < 1 {
		return fmt.Errorf("%s: outbound_threshold must be at least 1", name)
	}
	for _, tag := range ss.DisabledGroups {
		if !validRuleGroupTags[tag] {
			return fmt.Errorf("%s: invalid rule group tag %q", name, tag)
		}
	}
	return nil
}
