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
		ParanoiaLevel:     1,
		InboundThreshold:  5,
		OutboundThreshold: 4,
		RuleEngine:        "On",
		Services:          make(map[string]ServiceConfig),
	}
}

// load reads the config from the JSON file on disk.
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

	var cfg WAFConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("error parsing config file: %v", err)
		return
	}

	if cfg.Services == nil {
		cfg.Services = make(map[string]ServiceConfig)
	}

	s.config = cfg
	log.Printf("loaded config from %s", s.filePath)
}

// save writes the current config to the JSON file.
func (s *ConfigStore) save() error {
	data, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling config: %w", err)
	}
	if err := os.WriteFile(s.filePath, data, 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}
	return nil
}

// Get returns the current configuration.
func (s *ConfigStore) Get() WAFConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy.
	cp := s.config
	cp.Services = make(map[string]ServiceConfig, len(s.config.Services))
	for k, v := range s.config.Services {
		cp.Services[k] = v
	}
	return cp
}

// Update replaces the configuration and persists to disk.
func (s *ConfigStore) Update(cfg WAFConfig) (WAFConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cfg.Services == nil {
		cfg.Services = make(map[string]ServiceConfig)
	}

	old := s.config
	s.config = cfg
	if err := s.save(); err != nil {
		s.config = old // roll back
		return WAFConfig{}, err
	}
	return cfg, nil
}

// validateConfig checks that the config has valid values.
func validateConfig(cfg WAFConfig) error {
	if cfg.ParanoiaLevel < 1 || cfg.ParanoiaLevel > 4 {
		return fmt.Errorf("paranoia_level must be between 1 and 4")
	}
	if cfg.InboundThreshold < 1 {
		return fmt.Errorf("inbound_threshold must be at least 1")
	}
	if cfg.OutboundThreshold < 1 {
		return fmt.Errorf("outbound_threshold must be at least 1")
	}
	validEngines := map[string]bool{"On": true, "Off": true, "DetectionOnly": true}
	if !validEngines[cfg.RuleEngine] {
		return fmt.Errorf("rule_engine must be On, Off, or DetectionOnly")
	}
	validProfiles := map[string]bool{"strict": true, "tuning": true, "off": true, "": true}
	for svc, sc := range cfg.Services {
		if !validProfiles[sc.Profile] {
			return fmt.Errorf("invalid profile %q for service %q (must be strict, tuning, or off)", sc.Profile, svc)
		}
	}
	return nil
}
