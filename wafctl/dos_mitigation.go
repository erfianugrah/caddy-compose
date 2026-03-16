package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// ─── Jail File Format ───────────────────────────────────────────────

// jailFile is the JSON structure shared between the plugin and wafctl.
type jailFile struct {
	Version   int                      `json:"version"`
	Entries   map[string]jailFileEntry `json:"entries"`
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
	mu       sync.RWMutex
	filePath string
	entries  map[string]jailFileEntry
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
	log.Printf("[dos] loaded %d jail entries from %s", len(s.entries), s.filePath)
}

// Reload re-reads the jail file from disk, replacing in-memory state.
func (s *JailStore) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[string]jailFileEntry)
	s.load()
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

// Count returns the number of non-expired entries.
func (s *JailStore) Count() int {
	return len(s.List())
}

// Add creates a jail entry and persists to disk.
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
	s.mu.Unlock()

	return s.save()
}

// Remove deletes a jail entry and persists to disk.
func (s *JailStore) Remove(ip string) error {
	s.mu.Lock()
	delete(s.entries, ip)
	s.mu.Unlock()

	return s.save()
}

func (s *JailStore) save() error {
	s.mu.RLock()
	jf := jailFile{
		Version:   1,
		Entries:   make(map[string]jailFileEntry, len(s.entries)),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for ip, e := range s.entries {
		jf.Entries[ip] = e
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(jf, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.filePath, data, 0644)
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
func (s *DosConfigStore) Update(cfg DosConfig) error {
	s.mu.Lock()
	s.config = cfg
	s.mu.Unlock()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.filePath, data, 0644)
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
