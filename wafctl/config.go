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
// InboundThreshold 25 accommodates ~346 CRS rules at PL1 without false
// positives on legitimate requests. CRS v4.24.1 includes header presence
// checks (NOTICE=2) that accumulate on requests missing optional headers.
func defaultConfig() WAFConfig {
	return WAFConfig{
		Defaults: WAFServiceSettings{
			ParanoiaLevel:     1,
			InboundThreshold:  25,
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
			log.Printf("[config] config file not found at %s, using defaults", s.filePath)
			return
		}
		log.Printf("[config] error reading config file: %v", err)
		return
	}

	// Try new format first.
	var cfg WAFConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[config] error parsing config file: %v", err)
		return
	}

	// Migration: detect old format by checking if Defaults has zero values
	// and the raw JSON has the old fields (paranoia_level at root level).
	if cfg.Defaults.ParanoiaLevel == 0 {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err == nil {
			if _, hasOldField := raw["rule_engine"]; hasOldField {
				cfg = migrateOldConfig(data)
				log.Printf("[config] migrated config from old format")
			} else {
				// New format but missing paranoia_level — set defaults.
				cfg.Defaults = defaultServiceSettings()
			}
		}
	}

	if cfg.Services == nil {
		cfg.Services = make(map[string]WAFServiceSettings)
	}

	// Validate loaded/migrated config. If invalid, log warning and use defaults.
	if err := validateConfig(cfg); err != nil {
		log.Printf("[config] warning: loaded config is invalid (%v), using defaults", err)
		s.config = defaultConfig()
		return
	}

	s.config = cfg
	log.Printf("[config] loaded config from %s", s.filePath)
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

	// Map old rule_engine profiles to threshold values.
	// "Off" → detection-only (tuning thresholds 10000/10000)
	// "DetectionOnly" → detection-only (tuning thresholds 10000/10000)
	// Default/anything else → strict thresholds (5/4)
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

	// If old format had detection-only, use high thresholds.
	if old.RuleEngine == "DetectionOnly" || old.RuleEngine == "Off" {
		inbound = 10000
		outbound = 10000
	}

	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
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
		svcPL := pl         // use clamped default paranoia level
		svcInT := inbound   // use clamped default inbound threshold
		svcOutT := outbound // use clamped default outbound threshold
		switch sc.Profile {
		case "strict":
			svcInT, svcOutT = 5, 4
		case "tuning", "off":
			svcInT, svcOutT = 10000, 10000
		}
		cfg.Services[svc] = WAFServiceSettings{
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
	cp.Defaults.CRSExclusions = copyStringSlice(s.config.Defaults.CRSExclusions)
	cp.Defaults.DisabledCategories = copyStringSlice(s.config.Defaults.DisabledCategories)
	cp.Defaults.EarlyBlocking = copyBoolPtr(s.config.Defaults.EarlyBlocking)
	cp.Defaults.EnforceBodyprocURLEncoded = copyBoolPtr(s.config.Defaults.EnforceBodyprocURLEncoded)
	cp.Services = make(map[string]WAFServiceSettings, len(s.config.Services))
	for k, v := range s.config.Services {
		v.CRSExclusions = copyStringSlice(v.CRSExclusions)
		v.DisabledCategories = copyStringSlice(v.DisabledCategories)
		v.EarlyBlocking = copyBoolPtr(v.EarlyBlocking)
		v.EnforceBodyprocURLEncoded = copyBoolPtr(v.EnforceBodyprocURLEncoded)
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

// copyStringMap returns a copy of a string map (nil-safe).
func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

// copyBoolPtr returns a copy of a *bool pointer (nil-safe).
func copyBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
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
	if ss.ParanoiaLevel < 1 || ss.ParanoiaLevel > 4 {
		return fmt.Errorf("%s: paranoia_level must be between 1 and 4", name)
	}
	if ss.InboundThreshold < 1 {
		return fmt.Errorf("%s: inbound_threshold must be at least 1", name)
	}
	if ss.OutboundThreshold < 1 {
		return fmt.Errorf("%s: outbound_threshold must be at least 1", name)
	}
	// Validate disabled_categories — must be 3-4 digit CRS rule ID prefixes.
	for _, cat := range ss.DisabledCategories {
		if len(cat) < 3 || len(cat) > 4 {
			return fmt.Errorf("%s: disabled_categories entry %q must be a 3-4 digit CRS rule ID prefix", name, cat)
		}
		for _, c := range cat {
			if c < '0' || c > '9' {
				return fmt.Errorf("%s: disabled_categories entry %q must be numeric", name, cat)
			}
		}
	}

	// CRS v4 extended settings validation.
	if ss.BlockingParanoiaLevel != 0 && (ss.BlockingParanoiaLevel < 1 || ss.BlockingParanoiaLevel > 4) {
		return fmt.Errorf("%s: blocking_paranoia_level must be between 1 and 4", name)
	}
	if ss.DetectionParanoiaLevel != 0 && (ss.DetectionParanoiaLevel < 1 || ss.DetectionParanoiaLevel > 4) {
		return fmt.Errorf("%s: detection_paranoia_level must be between 1 and 4", name)
	}
	if ss.SamplingPercentage != 0 && (ss.SamplingPercentage < 1 || ss.SamplingPercentage > 100) {
		return fmt.Errorf("%s: sampling_percentage must be between 1 and 100", name)
	}
	if ss.ReportingLevel != 0 && (ss.ReportingLevel < 1 || ss.ReportingLevel > 4) {
		return fmt.Errorf("%s: reporting_level must be between 1 and 4", name)
	}

	// Argument limits (must be positive when set).
	if ss.MaxNumArgs < 0 {
		return fmt.Errorf("%s: max_num_args must be non-negative", name)
	}
	if ss.ArgNameLength < 0 {
		return fmt.Errorf("%s: arg_name_length must be non-negative", name)
	}
	if ss.ArgLength < 0 {
		return fmt.Errorf("%s: arg_length must be non-negative", name)
	}
	if ss.TotalArgLength < 0 {
		return fmt.Errorf("%s: total_arg_length must be non-negative", name)
	}

	// File limits (must be non-negative when set).
	if ss.MaxFileSize < 0 {
		return fmt.Errorf("%s: max_file_size must be non-negative", name)
	}
	if ss.CombinedFileSizes < 0 {
		return fmt.Errorf("%s: combined_file_sizes must be non-negative", name)
	}

	// CRS exclusion profiles.
	for _, excl := range ss.CRSExclusions {
		if !validCRSExclusions[excl] {
			return fmt.Errorf("%s: invalid CRS exclusion profile %q", name, excl)
		}
	}

	return nil
}
