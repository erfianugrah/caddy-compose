package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// currentStoreVersion is the latest store schema version.
// Increment this and add a migration function when changing the store format
// or adding default seed rules.
const currentStoreVersion = 6

// storeFile is the versioned on-disk format for the exclusions store.
// Legacy stores (bare JSON arrays) are detected and migrated on load.
type storeFile struct {
	Version    int             `json:"version"`
	Exclusions []RuleExclusion `json:"exclusions"`
}

// ExclusionStore manages rule exclusions with file-backed persistence.
type ExclusionStore struct {
	mu         sync.RWMutex
	exclusions []RuleExclusion
	version    int
	filePath   string
}

// NewExclusionStore creates a new store and loads existing data from disk.
func NewExclusionStore(filePath string) *ExclusionStore {
	s := &ExclusionStore{filePath: filePath}
	s.load()
	return s
}

// storeMigration defines a single version migration step.
type storeMigration struct {
	toVersion int
	name      string
	migrate   func(exclusions []RuleExclusion) []RuleExclusion
}

// storeMigrations is the ordered list of migrations. Each runs once when the
// store version is below its toVersion.
var storeMigrations = []storeMigration{
	{toVersion: 1, name: "seed heuristic bot rules", migrate: migrateV0toV1},
	{toVersion: 2, name: "add event tags to rules", migrate: migrateV1toV2},
	{toVersion: 3, name: "seed ipsum block rules", migrate: migrateV2toV3},
	{toVersion: 4, name: "seed heuristic detect rules", migrate: migrateV3toV4},
	{toVersion: 5, name: "remove heuristic detect rules (now in default-rules.json)", migrate: migrateV4toV5},
	{toVersion: 6, name: "remove seeded bot rules (now in default-rules.json)", migrate: migrateV5toV6},
}

// load reads exclusions from the JSON file on disk. Handles both legacy
// bare-array format (v0) and versioned storeFile format.
func (s *ExclusionStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("exclusions file not found at %s, seeding defaults", s.filePath)
			s.exclusions = []RuleExclusion{}
			s.version = 0
			s.runMigrations()
			return
		}
		log.Printf("error reading exclusions file: %v", err)
		s.exclusions = []RuleExclusion{}
		s.version = currentStoreVersion
		return
	}

	// Try versioned format first.
	var sf storeFile
	if err := json.Unmarshal(data, &sf); err == nil && sf.Version > 0 {
		s.exclusions = sf.Exclusions
		s.version = sf.Version
		log.Printf("loaded %d exclusions from %s (store v%d)", len(sf.Exclusions), s.filePath, sf.Version)
		s.runMigrations()
		return
	}

	// Fall back to legacy bare-array format (v0).
	var exclusions []RuleExclusion
	if err := json.Unmarshal(data, &exclusions); err != nil {
		log.Printf("error parsing exclusions file: %v", err)
		s.exclusions = []RuleExclusion{}
		s.version = currentStoreVersion
		return
	}

	s.exclusions = exclusions
	s.version = 0
	log.Printf("loaded %d exclusions from %s (legacy format, migrating)", len(exclusions), s.filePath)
	s.runMigrations()
}

// runMigrations applies any pending migrations and saves if changes were made.
func (s *ExclusionStore) runMigrations() {
	if s.version >= currentStoreVersion {
		return
	}
	for _, m := range storeMigrations {
		if s.version < m.toVersion {
			before := len(s.exclusions)
			s.exclusions = m.migrate(s.exclusions)
			after := len(s.exclusions)
			s.version = m.toVersion
			log.Printf("migration v%d (%s): %d → %d exclusions", m.toVersion, m.name, before, after)
		}
	}
	s.version = currentStoreVersion
	if err := s.save(); err != nil {
		log.Printf("error saving after migration: %v", err)
	}
}

// save writes the current exclusions to the JSON file atomically
// using the versioned storeFile format.
func (s *ExclusionStore) save() error {
	sf := storeFile{
		Version:    currentStoreVersion,
		Exclusions: s.exclusions,
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling exclusions: %w", err)
	}
	if err := atomicWriteFile(s.filePath, data, 0644); err != nil {
		return fmt.Errorf("error writing exclusions file: %w", err)
	}
	return nil
}

// ─── Store Migrations ──────────────────────────────────────────────

// migrateV0toV1 seeds the default heuristic bot detection rules that were
// previously baked into coraza/pre-crs.conf. These become dynamic policy
// engine rules so they can be tuned, disabled, or extended at runtime.
func migrateV0toV1(exclusions []RuleExclusion) []RuleExclusion {
	now := time.Now().UTC()

	// Scanner UA block — hard block known attack tools.
	// Equivalent to old rule 9100032 (@pmFromFile scanner-useragents.txt).
	scannerUAs := "sqlmap havij nikto nuclei acunetix nessus qualys arachni whatweb wapiti " +
		"skipfish gobuster dirbuster dirb ffuf wfuzz feroxbuster nmap masscan zgrab censys " +
		"shodan netcraft burpsuite burp zaproxy zap httprobe subfinder amass httpx"

	// Generic UA anomaly — default library UAs get +5 anomaly.
	// Equivalent to old rule 9100035 (@pmFromFile generic-useragents.txt).
	genericUAs := "python-requests go-http-client libwww-perl lwp-trivial wget curl/ mechanize scrapy"

	seeds := []RuleExclusion{
		{
			ID:          generateUUIDv7(),
			Name:        "Scanner UA Block",
			Description: "Block known scanner/attack tool User-Agents (sqlmap, nikto, nuclei, etc.)",
			Type:        "block",
			Conditions: []Condition{
				{Field: "user_agent", Operator: "in", Value: scannerUAs},
			},
			GroupOp:   "and",
			Tags:      []string{"scanner", "bot-detection"},
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          generateUUIDv7(),
			Name:        "HTTP/1.0 Anomaly",
			Description: "+2 anomaly for HTTP/1.0 — modern clients use HTTP/1.1 or HTTP/2",
			Type:        "detect",
			Severity:    "NOTICE",
			Conditions: []Condition{
				{Field: "http_version", Operator: "eq", Value: "HTTP/1.0"},
			},
			GroupOp:              "and",
			Tags:                 []string{"bot-signal", "protocol"},
			AnomalyScore:         2,
			AnomalyParanoiaLevel: 1,
			Enabled:              true,
			CreatedAt:            now,
			UpdatedAt:            now,
		},
		{
			ID:          generateUUIDv7(),
			Name:        "Generic UA Anomaly",
			Description: "+5 anomaly for generic HTTP library User-Agents (python-requests, curl/, etc.)",
			Type:        "detect",
			Severity:    "WARNING",
			Conditions: []Condition{
				{Field: "user_agent", Operator: "in", Value: genericUAs},
			},
			GroupOp:              "and",
			Tags:                 []string{"bot-signal", "generic-ua"},
			AnomalyScore:         5,
			AnomalyParanoiaLevel: 1,
			Enabled:              true,
			CreatedAt:            now,
			UpdatedAt:            now,
		},
	}

	return append(exclusions, seeds...)
}

// migrateV1toV2 adds event classification tags to existing seeded rules and
// converts honeypot-type rules to block type with ["honeypot"] tag.
func migrateV1toV2(exclusions []RuleExclusion) []RuleExclusion {
	// Well-known seeded rule names → tags to backfill.
	seedTags := map[string][]string{
		"Scanner UA Block":   {"scanner", "bot-detection"},
		"HTTP/1.0 Anomaly":   {"bot-signal", "protocol"},
		"Generic UA Anomaly": {"bot-signal", "generic-ua"},
	}

	for i := range exclusions {
		e := &exclusions[i]

		// Backfill tags on known seeded rules (idempotent — skip if already tagged).
		if tags, ok := seedTags[e.Name]; ok && len(e.Tags) == 0 {
			e.Tags = tags
		}

		// Convert honeypot-type exclusions to block + ["honeypot"] tag.
		// The "honeypot" exclusion type is no longer valid; block + tag is
		// the canonical representation.
		if e.Type == "honeypot" {
			e.Type = "block"
			if !containsTag(e.Tags, "honeypot") {
				e.Tags = append(e.Tags, "honeypot")
			}
		}
	}

	return exclusions
}

// migrateV2toV3 seeds per-level IPsum block rules that use the policy engine
// plugin via in_list conditions against the ipsum-level-N managed lists.
// This replaces the legacy Caddy ipsum_block.caddy snippet approach.
func migrateV2toV3(exclusions []RuleExclusion) []RuleExclusion {
	// Check if any ipsum block rules already exist (idempotent).
	for _, e := range exclusions {
		if e.Type == "block" && containsTag(e.Tags, "ipsum") {
			return exclusions // already seeded
		}
	}

	now := time.Now().UTC()

	// Create one block rule per IPsum threat level (1–8).
	// Higher levels are more malicious; they're all block rules so priority
	// doesn't matter for behavior, but we order them level-8-first for clarity.
	for level := 8; level >= 1; level-- {
		name := fmt.Sprintf("IPsum Block (Level %d)", level)
		listName := ipsumLevelName(level)
		desc := fmt.Sprintf("Block IPs on IPsum threat level %d via managed list (auto-seeded, policy engine)", level)

		exclusions = append(exclusions, RuleExclusion{
			ID:          generateUUIDv7(),
			Name:        name,
			Description: desc,
			Type:        "block",
			Conditions: []Condition{
				{Field: "ip", Operator: "in_list", Value: listName},
			},
			GroupOp:   "and",
			Tags:      []string{"blocklist", "ipsum", listName},
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	return exclusions
}

// migrateV3toV4 previously seeded heuristic bot detection rules (detect type)
// for 9100030, 9100033, 9100034. These are now shipped as built-in default
// rules in default-rules.json (loaded by the policy engine plugin). The
// migration is kept as a no-op for version compatibility — existing stores
// at version 3 will advance to version 4 without adding duplicate rules.
func migrateV3toV4(exclusions []RuleExclusion) []RuleExclusion {
	return exclusions // no-op — heuristic detect rules are now in default-rules.json
}

// migrateV4toV5 removes heuristic detect rules that were seeded by v3→v4.
// These rules are now shipped as built-in defaults in default-rules.json
// (9100030, 9100033, 9100034). Removing the user-store copies
// avoids double-counting anomaly scores.
func migrateV4toV5(exclusions []RuleExclusion) []RuleExclusion {
	// Known names of the v4-seeded heuristic detect rules.
	remove := map[string]bool{
		"Missing Accept Header":          true,
		"Missing User-Agent":             true,
		"Missing Referer on Non-API GET": true,
	}

	filtered := make([]RuleExclusion, 0, len(exclusions))
	for _, e := range exclusions {
		if e.Type == "detect" && containsTag(e.Tags, "heuristic") && remove[e.Name] {
			continue // skip — now provided by default-rules.json
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// migrateV5toV6 removes the v1-seeded bot rules (Scanner UA Block, HTTP/1.0
// Anomaly, Generic UA Anomaly) which are now shipped as built-in default rules
// in default-rules.json (9100032, 9100035, 9100036). Keeping them in
// the user store would cause duplicate blocking/scoring.
func migrateV5toV6(exclusions []RuleExclusion) []RuleExclusion {
	remove := map[string]bool{
		"Scanner UA Block":   true,
		"HTTP/1.0 Anomaly":   true,
		"Generic UA Anomaly": true,
	}

	filtered := make([]RuleExclusion, 0, len(exclusions))
	for _, e := range exclusions {
		if remove[e.Name] {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// List returns all exclusions.
func (s *ExclusionStore) List() []RuleExclusion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]RuleExclusion, len(s.exclusions))
	copy(cp, s.exclusions)
	return cp
}

// Get returns a single exclusion by ID.
func (s *ExclusionStore) Get(id string) (RuleExclusion, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.exclusions {
		if e.ID == id {
			return e, true
		}
	}
	return RuleExclusion{}, false
}

// Create adds a new exclusion and persists to disk.
func (s *ExclusionStore) Create(e RuleExclusion) (RuleExclusion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e.ID = generateUUID()
	now := time.Now().UTC()
	e.CreatedAt = now
	e.UpdatedAt = now

	s.exclusions = append(s.exclusions, e)
	if err := s.save(); err != nil {
		// Roll back.
		s.exclusions = s.exclusions[:len(s.exclusions)-1]
		return RuleExclusion{}, err
	}
	return e, nil
}

// Update modifies an existing exclusion and persists to disk.
func (s *ExclusionStore) Update(id string, updated RuleExclusion) (RuleExclusion, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, e := range s.exclusions {
		if e.ID == id {
			// Preserve immutable fields.
			updated.ID = e.ID
			updated.CreatedAt = e.CreatedAt
			updated.UpdatedAt = time.Now().UTC()

			old := s.exclusions[i]
			s.exclusions[i] = updated
			if err := s.save(); err != nil {
				s.exclusions[i] = old // roll back
				return RuleExclusion{}, true, err
			}
			return updated, true, nil
		}
	}
	return RuleExclusion{}, false, nil
}

// Delete removes an exclusion by ID and persists to disk.
func (s *ExclusionStore) Delete(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, e := range s.exclusions {
		if e.ID == id {
			old := make([]RuleExclusion, len(s.exclusions))
			copy(old, s.exclusions)
			s.exclusions = append(s.exclusions[:i], s.exclusions[i+1:]...)
			if err := s.save(); err != nil {
				s.exclusions = old // roll back
				return true, err
			}
			return true, nil
		}
	}
	return false, nil
}

// Reorder rearranges exclusions to match the given ID order and persists.
// All existing IDs must be present exactly once.
func (s *ExclusionStore) Reorder(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(ids) != len(s.exclusions) {
		return fmt.Errorf("expected %d IDs, got %d", len(s.exclusions), len(ids))
	}

	// Build index for O(1) lookup.
	idx := make(map[string]int, len(s.exclusions))
	for i, e := range s.exclusions {
		idx[e.ID] = i
	}

	reordered := make([]RuleExclusion, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		i, ok := idx[id]
		if !ok {
			return fmt.Errorf("unknown exclusion ID: %s", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate ID: %s", id)
		}
		seen[id] = true
		reordered = append(reordered, s.exclusions[i])
	}

	old := s.exclusions
	s.exclusions = reordered
	if err := s.save(); err != nil {
		s.exclusions = old // roll back
		return err
	}
	return nil
}

// Import replaces all exclusions with the provided list and persists.
func (s *ExclusionStore) Import(exclusions []RuleExclusion) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for i := range exclusions {
		// Assign new IDs on import to avoid collisions.
		exclusions[i].ID = generateUUID()
		if exclusions[i].CreatedAt.IsZero() {
			exclusions[i].CreatedAt = now
		}
		exclusions[i].UpdatedAt = now
	}

	old := s.exclusions
	s.exclusions = exclusions
	if err := s.save(); err != nil {
		s.exclusions = old
		return err
	}
	return nil
}

// Export returns all exclusions wrapped in an export envelope.
func (s *ExclusionStore) Export() ExclusionExport {
	return ExclusionExport{
		Version:    1,
		ExportedAt: time.Now().UTC(),
		Exclusions: s.List(),
	}
}

// EnabledExclusions returns only enabled exclusions.
func (s *ExclusionStore) EnabledExclusions() []RuleExclusion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []RuleExclusion
	for _, e := range s.exclusions {
		if e.Enabled {
			result = append(result, e)
		}
	}
	return result
}
