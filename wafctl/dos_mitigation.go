package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// ─── Jail File Format ───────────────────────────────────────────────

// jailFile is the JSON structure shared between the plugin and wafctl.
type jailFile struct {
	Version   int                      `json:"version"`
	Entries   map[string]jailFileEntry `json:"entries"`
	Whitelist []string                 `json:"whitelist,omitempty"` // Synced to plugin via jail.json
	UpdatedAt string                   `json:"updated_at"`
}

type jailFileEntry struct {
	ExpiresAt   string `json:"expires_at"`
	Infractions int32  `json:"infractions"`
	Reason      string `json:"reason"`
	JailedAt    string `json:"jailed_at"`
}

// ─── JailEntry (API response) ───────────────────────────────────────

// JailEntry is the API-facing representation of a jailed IP.
type JailEntry struct {
	IP          string `json:"ip"`
	ExpiresAt   string `json:"expires_at"`
	Infractions int32  `json:"infractions"`
	Reason      string `json:"reason"`
	JailedAt    string `json:"jailed_at"`
	TTL         string `json:"ttl"` // human-readable remaining time
}

// ─── JailStore ──────────────────────────────────────────────────────

// JailStore reads and writes the jail.json file shared with the plugin.
// It provides CRUD for manual jail/unjail via the API, and periodic
// reload from disk to pick up entries added by the plugin's auto-jail.
type JailStore struct {
	mu        sync.RWMutex
	filePath  string
	entries   map[string]jailFileEntry
	whitelist []string // current DDoS whitelist CIDRs, synced to plugin via jail.json
	lastCount int      // for quiet reload logging — only log when count changes
}

// NewJailStore creates a jail store and loads existing entries from disk.
func NewJailStore(filePath string) *JailStore {
	s := &JailStore{
		filePath: filePath,
		entries:  make(map[string]jailFileEntry),
	}
	s.load()
	return s
}

func (s *JailStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Printf("[dos] error reading jail file %s: %v", s.filePath, err)
		return
	}

	var jf jailFile
	if err := json.Unmarshal(data, &jf); err != nil {
		log.Printf("[dos] error parsing jail file: %v", err)
		return
	}

	now := time.Now()
	for ip, entry := range jf.Entries {
		expiresAt, err := time.Parse(time.RFC3339, entry.ExpiresAt)
		if err != nil {
			continue
		}
		if now.After(expiresAt) {
			continue // skip expired
		}
		s.entries[ip] = entry
	}
	count := len(s.entries)
	if count != s.lastCount {
		log.Printf("[dos] loaded %d jail entries from %s", count, s.filePath)
		s.lastCount = count
	}
}

// Reload re-reads the jail file from disk, replacing in-memory state.
// On failure (lock error, read error), preserves existing entries to avoid
// showing 0 jailed IPs when the plugin is actively enforcing them.
func (s *JailStore) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.entries
	s.entries = make(map[string]jailFileEntry)
	if err := withFileLock(s.filePath, func() error {
		s.load()
		return nil
	}); err != nil {
		log.Printf("[dos] jail reload failed, keeping %d previous entries: %v", len(old), err)
		s.entries = old
	}
}

// List returns all non-expired jail entries.
func (s *JailStore) List() []JailEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	result := make([]JailEntry, 0, len(s.entries))
	for ip, e := range s.entries {
		expiresAt, err := time.Parse(time.RFC3339, e.ExpiresAt)
		if err != nil || now.After(expiresAt) {
			continue
		}
		ttl := time.Until(expiresAt).Truncate(time.Second)
		result = append(result, JailEntry{
			IP:          ip,
			ExpiresAt:   e.ExpiresAt,
			Infractions: e.Infractions,
			Reason:      e.Reason,
			JailedAt:    e.JailedAt,
			TTL:         ttl.String(),
		})
	}
	return result
}

// Count returns the number of non-expired entries without allocating
// a full JailEntry slice.
func (s *JailStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, e := range s.entries {
		expiresAt, err := time.Parse(time.RFC3339, e.ExpiresAt)
		if err != nil || now.After(expiresAt) {
			continue
		}
		count++
	}
	return count
}

// Add creates a jail entry and persists to disk.
// The write lock is held through the save to prevent concurrent mutation.
func (s *JailStore) Add(ip, ttlStr, reason string) error {
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return err
	}

	now := time.Now()
	entry := jailFileEntry{
		ExpiresAt:   now.Add(ttl).UTC().Format(time.RFC3339),
		Infractions: 0,
		Reason:      reason,
		JailedAt:    now.UTC().Format(time.RFC3339),
	}

	s.mu.Lock()
	s.entries[ip] = entry
	err = s.saveLocked()
	s.mu.Unlock()

	return err
}

// Remove deletes a jail entry and persists to disk.
// The write lock is held through the save to prevent concurrent mutation.
func (s *JailStore) Remove(ip string) error {
	s.mu.Lock()
	delete(s.entries, ip)
	err := s.saveLocked()
	s.mu.Unlock()

	return err
}

// SetWhitelist updates the whitelist CIDRs that get synced to the plugin via jail.json.
// Called when the DDoS config is updated via the API.
func (s *JailStore) SetWhitelist(cidrs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.whitelist = cidrs
	if err := s.saveLocked(); err != nil {
		log.Printf("[dos] whitelist sync save failed: %v", err)
	}
}

// saveLocked marshals and writes the jail file to disk.
// Caller must hold s.mu (write lock).

func (s *JailStore) saveLocked() error {
	jf := jailFile{
		Version:   1,
		Entries:   make(map[string]jailFileEntry, len(s.entries)),
		Whitelist: s.whitelist,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for ip, e := range s.entries {
		jf.Entries[ip] = e
	}

	data, err := json.MarshalIndent(jf, "", "  ")
	if err != nil {
		return err
	}
	return withFileLock(s.filePath, func() error {
		return atomicWriteFile(s.filePath, data, 0644)
	})
}

// ─── DosConfig ──────────────────────────────────────────────────────

// DosConfig holds all DDoS mitigation settings editable via the dashboard.
type DosConfig struct {
	Enabled       bool     `json:"enabled"`
	Threshold     float64  `json:"threshold"`
	BasePenalty   string   `json:"base_penalty"`
	MaxPenalty    string   `json:"max_penalty"`
	EPSTrigger    float64  `json:"eps_trigger"`
	EPSCooldown   float64  `json:"eps_cooldown"`
	CooldownDelay string   `json:"cooldown_delay"`
	MaxBuckets    int      `json:"max_buckets"`
	MaxReports    int      `json:"max_reports"`
	Whitelist     []string `json:"whitelist"`
	KernelDrop    bool     `json:"kernel_drop"`
	Strategy      string   `json:"strategy"`
}

func defaultDosConfig() DosConfig {
	return DosConfig{
		Enabled:       true,
		Threshold:     0.65,
		BasePenalty:   "60s",
		MaxPenalty:    "24h",
		EPSTrigger:    50,
		EPSCooldown:   10,
		CooldownDelay: "30s",
		MaxBuckets:    10000,
		MaxReports:    100,
		Whitelist:     []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8", "::1/128"},
		KernelDrop:    false,
		Strategy:      "auto",
	}
}

// validDosStrategies are the allowed values for the DosConfig Strategy field.
var validDosStrategies = map[string]bool{
	"auto":      true,
	"full":      true,
	"ip_path":   true,
	"ip_only":   true,
	"path_ua":   true,
	"path_only": true,
}

// validateDosConfig validates a DosConfig before persisting.
func validateDosConfig(cfg DosConfig) error {
	// Validate strategy.
	if cfg.Strategy != "" && !validDosStrategies[cfg.Strategy] {
		return fmt.Errorf("invalid strategy %q", cfg.Strategy)
	}

	// Validate numeric thresholds are positive where they should be.
	if cfg.Threshold < 0 {
		return fmt.Errorf("threshold must be non-negative, got %f", cfg.Threshold)
	}
	if cfg.EPSTrigger < 0 {
		return fmt.Errorf("eps_trigger must be non-negative, got %f", cfg.EPSTrigger)
	}
	if cfg.EPSCooldown < 0 {
		return fmt.Errorf("eps_cooldown must be non-negative, got %f", cfg.EPSCooldown)
	}
	if cfg.MaxBuckets < 0 {
		return fmt.Errorf("max_buckets must be non-negative, got %d", cfg.MaxBuckets)
	}
	if cfg.MaxReports < 0 {
		return fmt.Errorf("max_reports must be non-negative, got %d", cfg.MaxReports)
	}

	// Validate durations.
	if cfg.BasePenalty != "" {
		if _, err := time.ParseDuration(cfg.BasePenalty); err != nil {
			return fmt.Errorf("invalid base_penalty duration %q: %w", cfg.BasePenalty, err)
		}
	}
	if cfg.MaxPenalty != "" {
		if _, err := time.ParseDuration(cfg.MaxPenalty); err != nil {
			return fmt.Errorf("invalid max_penalty duration %q: %w", cfg.MaxPenalty, err)
		}
	}
	if cfg.CooldownDelay != "" {
		if _, err := time.ParseDuration(cfg.CooldownDelay); err != nil {
			return fmt.Errorf("invalid cooldown_delay duration %q: %w", cfg.CooldownDelay, err)
		}
	}

	// Validate whitelist entries are valid CIDRs or IPs.
	for i, entry := range cfg.Whitelist {
		// Reject wildcard CIDRs that would whitelist everything.
		if entry == "0.0.0.0/0" || entry == "::/0" {
			return fmt.Errorf("whitelist[%d]: wildcard CIDR %q is not allowed", i, entry)
		}
		if net.ParseIP(entry) != nil {
			continue // bare IP is valid
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return fmt.Errorf("whitelist[%d]: invalid CIDR %q: %w", i, entry, err)
		}
	}

	return nil
}

// ─── DosConfigStore ─────────────────────────────────────────────────

// DosConfigStore manages DDoS mitigation settings with file-backed persistence.
type DosConfigStore struct {
	mu       sync.RWMutex
	config   DosConfig
	filePath string
}

// NewDosConfigStore loads config from disk or initializes with defaults.
func NewDosConfigStore(filePath string) *DosConfigStore {
	s := &DosConfigStore{
		filePath: filePath,
		config:   defaultDosConfig(),
	}
	s.load()
	return s
}

func (s *DosConfigStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return // use defaults
		}
		log.Printf("[dos] error reading config %s: %v", s.filePath, err)
		return
	}

	var cfg DosConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[dos] error parsing config: %v", err)
		return
	}
	s.config = cfg
	log.Printf("[dos] loaded config from %s", s.filePath)
}

// Get returns a copy of the current config.
func (s *DosConfigStore) Get() DosConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// Update replaces the config and persists to disk.
// The write lock is held through the file write to prevent concurrent mutation.
func (s *DosConfigStore) Update(cfg DosConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.config
	s.config = cfg

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		s.config = old // roll back
		return err
	}
	if err := atomicWriteFile(s.filePath, data, 0644); err != nil {
		s.config = old // roll back
		return err
	}
	return nil
}

// ─── DosStatus (API response) ───────────────────────────────────────

// DosStatus is the response for GET /api/dos/status.
type DosStatus struct {
	Mode       string    `json:"mode"`        // "normal" or "spike"
	EPS        float64   `json:"eps"`         // events per second (last 60s from access log)
	PeakEPS    float64   `json:"peak_eps"`    // peak EPS in current/last spike
	JailCount  int       `json:"jail_count"`  // number of jailed IPs
	KernelDrop bool      `json:"kernel_drop"` // nftables active
	Strategy   string    `json:"strategy"`    // active fingerprint strategy
	EPSHistory []float64 `json:"eps_history"` // EPS per 5s bucket for last 5 min (sparkline)
	DDoSEvents int       `json:"ddos_events"` // total DDoS block/jail events in store
	UpdatedAt  string    `json:"updated_at"`  // ISO timestamp of this response
}
