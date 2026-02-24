package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RateLimitStore manages rate limit configuration with file-backed persistence.
type RateLimitStore struct {
	mu       sync.RWMutex
	config   RateLimitConfig
	filePath string
}

// NewRateLimitStore creates a new rate limit store and loads existing data from disk.
// Starts with an empty config — zones are discovered from the Caddyfile at boot
// via MergeCaddyfileZones(), not hardcoded.
func NewRateLimitStore(filePath string) *RateLimitStore {
	s := &RateLimitStore{
		filePath: filePath,
		config:   RateLimitConfig{Zones: []RateLimitZone{}},
	}
	s.load()
	return s
}

// defaultZone returns a sensible default zone config for a newly discovered zone.
const defaultZoneEvents = 300
const defaultZoneWindow = "1m"

func defaultZone(name string) RateLimitZone {
	return RateLimitZone{
		Name:    name,
		Events:  defaultZoneEvents,
		Window:  defaultZoneWindow,
		Enabled: true,
	}
}

func (s *RateLimitStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("rate limit config not found at %s, starting empty", s.filePath)
			return
		}
		log.Printf("error reading rate limit config: %v", err)
		return
	}

	var cfg RateLimitConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("error parsing rate limit config: %v", err)
		return
	}

	if cfg.Zones == nil {
		cfg.Zones = []RateLimitZone{}
	}

	s.config = cfg
	log.Printf("loaded rate limit config from %s (%d zones)", s.filePath, len(cfg.Zones))
}

func (s *RateLimitStore) save() error {
	data, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling rate limit config: %w", err)
	}
	if err := atomicWriteFile(s.filePath, data, 0644); err != nil {
		return fmt.Errorf("error writing rate limit config: %w", err)
	}
	return nil
}

// Get returns the current rate limit configuration.
func (s *RateLimitStore) Get() RateLimitConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := RateLimitConfig{
		Zones: make([]RateLimitZone, len(s.config.Zones)),
	}
	copy(cp.Zones, s.config.Zones)
	return cp
}

// Update replaces the rate limit configuration and persists to disk.
func (s *RateLimitStore) Update(cfg RateLimitConfig) (RateLimitConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cfg.Zones == nil {
		cfg.Zones = []RateLimitZone{}
	}

	old := s.config
	s.config = cfg
	if err := s.save(); err != nil {
		s.config = old // roll back
		return RateLimitConfig{}, err
	}
	return cfg, nil
}

// GetZone returns a single zone by name, or nil if not found.
func (s *RateLimitStore) GetZone(name string) *RateLimitZone {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, z := range s.config.Zones {
		if z.Name == name {
			cp := z
			return &cp
		}
	}
	return nil
}

// ─── Validation ─────────────────────────────────────────────────────

// validWindowPattern matches duration strings: number + unit (s, m, h).
var validWindowPattern = regexp.MustCompile(`^\d+[smh]$`)

// validZoneNamePattern matches zone names: alphanumeric, hyphens, underscores.
var validZoneNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func validateRateLimitConfig(cfg RateLimitConfig) error {
	seen := make(map[string]bool)
	for i, z := range cfg.Zones {
		if z.Name == "" {
			return fmt.Errorf("zone[%d]: name is required", i)
		}
		if !validZoneNamePattern.MatchString(z.Name) {
			return fmt.Errorf("zone %q: name must be alphanumeric with hyphens/underscores only", z.Name)
		}
		if seen[z.Name] {
			return fmt.Errorf("zone %q: duplicate zone name", z.Name)
		}
		seen[z.Name] = true

		if z.Events < 1 {
			return fmt.Errorf("zone %q: events must be at least 1", z.Name)
		}
		if z.Events > 100000 {
			return fmt.Errorf("zone %q: events must be at most 100000", z.Name)
		}
		if z.Window == "" {
			return fmt.Errorf("zone %q: window is required", z.Name)
		}
		if !validWindowPattern.MatchString(z.Window) {
			return fmt.Errorf("zone %q: window must be a duration like 1m, 30s, 1h", z.Name)
		}
	}
	return nil
}

// ─── Zone File Generator ────────────────────────────────────────────

// generateZoneFile produces the Caddyfile snippet content for a single rate limit zone.
// If the zone is disabled, it returns a comment-only placeholder (no-op when imported).
func generateZoneFile(zone RateLimitZone) string {
	var b strings.Builder

	b.WriteString("# Managed by waf-api Rate Limit Engine\n")
	b.WriteString(fmt.Sprintf("# Zone: %s | Updated: %s\n", zone.Name, time.Now().UTC().Format(time.RFC3339)))

	if !zone.Enabled {
		b.WriteString("# Rate limiting disabled for this zone\n")
		return b.String()
	}

	b.WriteString(fmt.Sprintf("rate_limit {\n"))
	b.WriteString(fmt.Sprintf("\tzone %s {\n", zone.Name))
	b.WriteString("\t\tmatch {\n")
	b.WriteString("\t\t\tnot header Connection *Upgrade*\n")
	b.WriteString("\t\t}\n")
	b.WriteString("\t\tkey {http.request.remote.host}\n")
	b.WriteString(fmt.Sprintf("\t\tevents %d\n", zone.Events))
	b.WriteString(fmt.Sprintf("\t\twindow %s\n", zone.Window))
	b.WriteString("\t}\n")
	b.WriteString("}\n")

	// Response headers for rate limit visibility
	b.WriteString(fmt.Sprintf("header X-RateLimit-Limit \"%d\"\n", zone.Events))
	b.WriteString(fmt.Sprintf("header X-RateLimit-Policy \"%d;w=%s;name=\\\"%s\\\"\"\n", zone.Events, zone.Window, zone.Name))

	return b.String()
}

// zoneFileName returns the rate limit file name for a zone.
// Uses _rl suffix to prevent glob collisions (e.g. "caddy" vs "caddy-prometheus").
func zoneFileName(zoneName string) string {
	return zoneName + "_rl.caddy"
}

// writeZoneFiles writes all zone .caddy files to the rate limit directory.
// Returns the list of files written.
func writeZoneFiles(dir string, zones []RateLimitZone) ([]string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating rate limit dir %s: %w", dir, err)
	}

	var written []string
	for _, zone := range zones {
		content := generateZoneFile(zone)
		path := filepath.Join(dir, zoneFileName(zone.Name))
		if err := atomicWriteFile(path, []byte(content), 0644); err != nil {
			return written, fmt.Errorf("writing zone file %s: %w", path, err)
		}
		log.Printf("wrote rate limit zone file: %s (%d bytes, enabled=%v)", path, len(content), zone.Enabled)
		written = append(written, path)
	}

	return written, nil
}

// ensureRateLimitDir creates the rate limit directory if it doesn't exist.
// Called at startup.
func ensureRateLimitDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating rate limit dir %s: %w", dir, err)
	}
	log.Printf("rate limit directory ready: %s", dir)
	return nil
}

// rlImportPattern matches Caddyfile lines like:
//
//	import /data/caddy/rl/sonarr_rl*.caddy
//
// It captures the zone prefix (e.g. "sonarr_rl") so we can derive the
// zone name. The Caddy-side path (/data/caddy/rl/) differs from
// waf-api's mount (/data/rl/) — callers must use their own RateLimitDir.
var rlImportPattern = regexp.MustCompile(`import\s+\S*/rl/([a-zA-Z0-9_-]+_rl)\*\.caddy`)

// scanCaddyfileZones reads the Caddyfile and returns the set of rate limit
// zone file prefixes referenced by import globs (e.g. "sonarr_rl").
// Returns nil on read error (non-fatal — zones just won't be auto-discovered).
func scanCaddyfileZones(caddyfilePath string) []string {
	data, err := os.ReadFile(caddyfilePath)
	if err != nil {
		log.Printf("warning: cannot read Caddyfile at %s for zone scanning: %v", caddyfilePath, err)
		return nil
	}

	seen := make(map[string]bool)
	var prefixes []string
	for _, match := range rlImportPattern.FindAllStringSubmatch(string(data), -1) {
		prefix := match[1]
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

// syncCaddyfileZones discovers new zones from the Caddyfile and writes zone
// files for any that were added. This should be called before every Caddy
// reload to ensure zone files exist for all Caddyfile-referenced imports.
// Returns the number of new zones discovered.
func syncCaddyfileZones(rs *RateLimitStore, deployCfg DeployConfig) int {
	added := rs.MergeCaddyfileZones(deployCfg.CaddyfilePath)
	if added > 0 {
		// Write zone files only for the newly added zones — existing zones
		// already have files from boot or prior deploys. But it's simpler
		// and safe to write all zones (idempotent).
		cfg := rs.Get()
		if _, err := writeZoneFiles(deployCfg.RateLimitDir, cfg.Zones); err != nil {
			log.Printf("warning: failed to write zone files after Caddyfile sync: %v", err)
		}
	}
	return added
}

// MergeCaddyfileZones scans the Caddyfile for rate limit import globs and
// adds any missing zones to the store with sensible defaults. This makes
// the Caddyfile the source of truth for which zones exist — no hardcoded
// defaults needed. Returns the number of zones added. Persists to disk if
// any zones were added.
func (s *RateLimitStore) MergeCaddyfileZones(caddyfilePath string) int {
	if caddyfilePath == "" {
		return 0
	}

	prefixes := scanCaddyfileZones(caddyfilePath)
	if len(prefixes) == 0 {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing := make(map[string]bool, len(s.config.Zones))
	for _, z := range s.config.Zones {
		existing[z.Name] = true
	}

	added := 0
	for _, prefix := range prefixes {
		// Strip the _rl suffix to get the zone name.
		name := strings.TrimSuffix(prefix, "_rl")
		if existing[name] {
			continue
		}
		s.config.Zones = append(s.config.Zones, defaultZone(name))
		existing[name] = true
		added++
		log.Printf("discovered new zone %q from Caddyfile", name)
	}

	if added > 0 {
		if err := s.save(); err != nil {
			log.Printf("warning: failed to persist %d new zones: %v", added, err)
		} else {
			log.Printf("merged %d zone(s) from Caddyfile into rate limit config (%d total)", added, len(s.config.Zones))
		}
	}

	return added
}
