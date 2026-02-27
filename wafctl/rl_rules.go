package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── Rate Limit Rule Store ──────────────────────────────────────────

// RateLimitRuleStore manages rate limit rules with file-backed persistence.
// Mirrors the ExclusionStore pattern: mutex-protected, atomic writes, rollback-on-error.
type RateLimitRuleStore struct {
	mu       sync.RWMutex
	config   RateLimitRuleConfig
	filePath string
}

// Default rate limit for auto-discovered services.
const (
	defaultRLEvents = 300
	defaultRLWindow = "1m"
)

// NewRateLimitRuleStore creates a new rule store and loads existing data from disk.
// If the file contains legacy zone format, it is auto-migrated.
func NewRateLimitRuleStore(filePath string) *RateLimitRuleStore {
	s := &RateLimitRuleStore{
		filePath: filePath,
		config:   RateLimitRuleConfig{Rules: []RateLimitRule{}},
	}
	s.load()
	return s
}

func (s *RateLimitRuleStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("rate limit rules not found at %s, starting empty", s.filePath)
			return
		}
		log.Printf("error reading rate limit rules: %v", err)
		return
	}

	// Try to detect legacy format: {"zones": [...]}
	var probe struct {
		Zones []json.RawMessage `json:"zones"`
		Rules []json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		log.Printf("error parsing rate limit config: %v", err)
		return
	}

	if len(probe.Zones) > 0 && len(probe.Rules) == 0 {
		// Legacy format detected — migrate.
		s.migrateFromV1(data)
		return
	}

	// New format.
	var cfg RateLimitRuleConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("error parsing rate limit rules: %v", err)
		return
	}
	if cfg.Rules == nil {
		cfg.Rules = []RateLimitRule{}
	}
	s.config = cfg
	log.Printf("loaded %d rate limit rules from %s", len(cfg.Rules), s.filePath)
}

// migrateFromV1 converts legacy {"zones":[...]} format to the new rule format.
func (s *RateLimitRuleStore) migrateFromV1(data []byte) {
	var legacy struct {
		Zones []RateLimitZone `json:"zones"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		log.Printf("error parsing legacy rate limit config: %v", err)
		return
	}

	// Back up the old file.
	backupPath := s.filePath + ".v1.bak"
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		log.Printf("warning: could not back up legacy rate limit config: %v", err)
	} else {
		log.Printf("backed up legacy rate limit config to %s", backupPath)
	}

	// Convert zones to rules.
	now := time.Now().UTC()
	rules := make([]RateLimitRule, len(legacy.Zones))
	for i, z := range legacy.Zones {
		rules[i] = RateLimitRule{
			ID:        generateUUID(),
			Name:      z.Name,
			Service:   z.Name,
			Key:       "client_ip",
			Events:    z.Events,
			Window:    z.Window,
			Enabled:   z.Enabled,
			CreatedAt: now,
			UpdatedAt: now,
		}
	}

	s.config = RateLimitRuleConfig{Rules: rules}
	if err := s.save(); err != nil {
		log.Printf("warning: failed to persist migrated rate limit rules: %v", err)
	} else {
		log.Printf("migrated %d legacy zones to rate limit rules", len(rules))
	}
}

func (s *RateLimitRuleStore) save() error {
	data, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling rate limit rules: %w", err)
	}
	if err := atomicWriteFile(s.filePath, data, 0644); err != nil {
		return fmt.Errorf("error writing rate limit rules: %w", err)
	}
	return nil
}

// ─── CRUD Operations ────────────────────────────────────────────────

// List returns all rules (deep copy).
func (s *RateLimitRuleStore) List() []RateLimitRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]RateLimitRule, len(s.config.Rules))
	copy(cp, s.config.Rules)
	return cp
}

// Get returns a single rule by ID (deep copy), or nil if not found.
func (s *RateLimitRuleStore) Get(id string) *RateLimitRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.config.Rules {
		if r.ID == id {
			cp := r
			return &cp
		}
	}
	return nil
}

// Create adds a new rule and persists to disk.
func (s *RateLimitRuleStore) Create(rule RateLimitRule) (RateLimitRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rule.ID = generateUUID()
	now := time.Now().UTC()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	s.config.Rules = append(s.config.Rules, rule)
	if err := s.save(); err != nil {
		// Roll back.
		s.config.Rules = s.config.Rules[:len(s.config.Rules)-1]
		return RateLimitRule{}, err
	}
	return rule, nil
}

// Update modifies an existing rule and persists to disk.
func (s *RateLimitRuleStore) Update(id string, updated RateLimitRule) (RateLimitRule, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, r := range s.config.Rules {
		if r.ID == id {
			// Preserve immutable fields.
			updated.ID = r.ID
			updated.CreatedAt = r.CreatedAt
			updated.UpdatedAt = time.Now().UTC()

			old := s.config.Rules[i]
			s.config.Rules[i] = updated
			if err := s.save(); err != nil {
				s.config.Rules[i] = old // roll back
				return RateLimitRule{}, true, err
			}
			return updated, true, nil
		}
	}
	return RateLimitRule{}, false, nil
}

// Delete removes a rule by ID and persists to disk.
func (s *RateLimitRuleStore) Delete(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, r := range s.config.Rules {
		if r.ID == id {
			old := make([]RateLimitRule, len(s.config.Rules))
			copy(old, s.config.Rules)
			s.config.Rules = append(s.config.Rules[:i], s.config.Rules[i+1:]...)
			if err := s.save(); err != nil {
				s.config.Rules = old // roll back
				return true, err
			}
			return true, nil
		}
	}
	return false, nil
}

// Reorder rearranges rules to match the given ID order and persists.
// All existing IDs must be present exactly once. Priority fields are
// auto-assigned from the new array position (0, 1, 2, ...).
func (s *RateLimitRuleStore) Reorder(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(ids) != len(s.config.Rules) {
		return fmt.Errorf("expected %d IDs, got %d", len(s.config.Rules), len(ids))
	}

	idx := make(map[string]int, len(s.config.Rules))
	for i, r := range s.config.Rules {
		idx[r.ID] = i
	}

	reordered := make([]RateLimitRule, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for pos, id := range ids {
		i, ok := idx[id]
		if !ok {
			return fmt.Errorf("unknown rule ID: %s", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate ID: %s", id)
		}
		seen[id] = true
		r := s.config.Rules[i]
		r.Priority = pos
		reordered = append(reordered, r)
	}

	old := make([]RateLimitRule, len(s.config.Rules))
	copy(old, s.config.Rules)
	s.config.Rules = reordered
	if err := s.save(); err != nil {
		s.config.Rules = old
		return err
	}
	return nil
}

// ─── Queries ────────────────────────────────────────────────────────

// GetGlobal returns the global rate limit configuration.
func (s *RateLimitRuleStore) GetGlobal() RateLimitGlobalConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Global
}

// UpdateGlobal replaces the global config and persists.
func (s *RateLimitRuleStore) UpdateGlobal(cfg RateLimitGlobalConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.config.Global
	s.config.Global = cfg
	if err := s.save(); err != nil {
		s.config.Global = old
		return err
	}
	return nil
}

// EnabledRules returns only enabled rules, sorted by priority (lower first).
func (s *RateLimitRuleStore) EnabledRules() []RateLimitRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []RateLimitRule
	for _, r := range s.config.Rules {
		if r.Enabled {
			result = append(result, r)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority < result[j].Priority
	})
	return result
}

// ListByService returns rules for a specific service (deep copy).
func (s *RateLimitRuleStore) ListByService(host string) []RateLimitRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []RateLimitRule
	for _, r := range s.config.Rules {
		if r.Service == host || r.Service == "*" {
			cp := r
			result = append(result, cp)
		}
	}
	return result
}

// ─── Import / Export ────────────────────────────────────────────────

// Export returns all rules wrapped in an export envelope.
func (s *RateLimitRuleStore) Export() RateLimitRuleExport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return RateLimitRuleExport{
		Version:    1,
		ExportedAt: time.Now().UTC(),
		Rules:      s.List(),
		Global:     s.config.Global,
	}
}

// Import replaces all rules with the provided list and persists.
func (s *RateLimitRuleStore) Import(rules []RateLimitRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for i := range rules {
		rules[i].ID = generateUUID()
		if rules[i].CreatedAt.IsZero() {
			rules[i].CreatedAt = now
		}
		rules[i].UpdatedAt = now
	}

	old := s.config.Rules
	s.config.Rules = rules
	if err := s.save(); err != nil {
		s.config.Rules = old
		return err
	}
	return nil
}

// ─── Caddyfile Auto-Discovery ───────────────────────────────────────

// rlImportPattern matches Caddyfile lines like:
//
//	import /data/caddy/rl/sonarr_rl*.caddy
//
// It captures the zone prefix (e.g. "sonarr_rl") so we can derive the
// service name. The Caddy-side path (/data/caddy/rl/) differs from
// wafctl's mount (/data/rl/) — callers must use their own RateLimitDir.
var rlImportPattern = regexp.MustCompile(`import\s+\S*/rl/([a-zA-Z0-9_-]+_rl)\*\.caddy`)

// scanCaddyfileServices reads the Caddyfile and returns the set of service
// names referenced by rate limit import globs.
func scanCaddyfileServices(caddyfilePath string) []string {
	data, err := os.ReadFile(caddyfilePath)
	if err != nil {
		log.Printf("warning: cannot read Caddyfile at %s for RL service scanning: %v", caddyfilePath, err)
		return nil
	}

	seen := make(map[string]bool)
	var names []string
	for _, match := range rlImportPattern.FindAllStringSubmatch(string(data), -1) {
		prefix := match[1]
		name := strings.TrimSuffix(prefix, "_rl")
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// MergeCaddyfileServices scans the Caddyfile for rate limit import globs
// and adds default rules for any new services not already covered.
// Returns the number of rules added.
func (s *RateLimitRuleStore) MergeCaddyfileServices(caddyfilePath string) int {
	if caddyfilePath == "" {
		return 0
	}

	services := scanCaddyfileServices(caddyfilePath)
	if len(services) == 0 {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Build a set of services that already have at least one rule.
	existing := make(map[string]bool, len(s.config.Rules))
	for _, r := range s.config.Rules {
		existing[r.Service] = true
	}

	added := 0
	now := time.Now().UTC()
	for _, svc := range services {
		if existing[svc] {
			continue
		}
		s.config.Rules = append(s.config.Rules, RateLimitRule{
			ID:        generateUUID(),
			Name:      svc,
			Service:   svc,
			Key:       "client_ip",
			Events:    defaultRLEvents,
			Window:    defaultRLWindow,
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		})
		existing[svc] = true
		added++
		log.Printf("discovered new RL service %q from Caddyfile", svc)
	}

	if added > 0 {
		if err := s.save(); err != nil {
			log.Printf("warning: failed to persist %d new RL rules: %v", added, err)
		} else {
			log.Printf("merged %d service(s) from Caddyfile into rate limit rules (%d total)", added, len(s.config.Rules))
		}
	}

	return added
}

// syncCaddyfileServices discovers new services from the Caddyfile and
// writes RL files for any that were added. Called before every Caddy reload.
func syncCaddyfileServices(rs *RateLimitRuleStore, deployCfg DeployConfig) int {
	added := rs.MergeCaddyfileServices(deployCfg.CaddyfilePath)
	if added > 0 {
		rules := rs.EnabledRules()
		global := rs.GetGlobal()
		files := GenerateRateLimitConfigs(rules, global, deployCfg.CaddyfilePath)
		if _, err := writeRLFiles(deployCfg.RateLimitDir, files); err != nil {
			log.Printf("warning: failed to write RL files after Caddyfile sync: %v", err)
		}
	}
	return added
}

// ─── Validation ─────────────────────────────────────────────────────

// validWindowPattern matches duration strings: number + unit (s, m, h).
var validWindowPattern = regexp.MustCompile(`^\d+[smh]$`)

// validRLKeyPattern matches key formats: plain keys or prefix:name keys.
// body_json: accepts dot-paths (e.g. body_json:.user.api_key), body_form: accepts field names.
var validRLKeyPattern = regexp.MustCompile(`^(client_ip|path|static|client_ip\+path|client_ip\+method|header:[A-Za-z0-9_-]+|cookie:[A-Za-z0-9_-]+|body_json:\.?[A-Za-z0-9_.]+|body_form:[A-Za-z0-9_-]+)$`)

// validateRateLimitRule checks that a rule has valid fields.
func validateRateLimitRule(rule RateLimitRule) error {
	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}
	if strings.ContainsAny(rule.Name, "\n\r") {
		return fmt.Errorf("name must not contain newlines")
	}
	if rule.Service == "" {
		return fmt.Errorf("service is required")
	}
	if strings.ContainsAny(rule.Service, "\n\r") {
		return fmt.Errorf("service must not contain newlines")
	}

	// Key validation.
	if rule.Key == "" {
		return fmt.Errorf("key is required")
	}
	if !validRLKeyPattern.MatchString(rule.Key) {
		return fmt.Errorf("invalid key %q (must be client_ip, path, static, client_ip+path, client_ip+method, header:<name>, or cookie:<name>)", rule.Key)
	}

	// Events and window.
	if rule.Events < 1 {
		return fmt.Errorf("events must be at least 1")
	}
	if rule.Events > 100000 {
		return fmt.Errorf("events must be at most 100000")
	}
	if rule.Window == "" {
		return fmt.Errorf("window is required")
	}
	if !validWindowPattern.MatchString(rule.Window) {
		return fmt.Errorf("window must be a duration like 1m, 30s, 1h")
	}

	// Action validation.
	if !validRLActions[rule.Action] {
		return fmt.Errorf("invalid action %q (must be \"deny\" or \"log_only\")", rule.Action)
	}

	// Priority.
	if rule.Priority < 0 || rule.Priority > 999 {
		return fmt.Errorf("priority must be 0-999")
	}

	// Group operator.
	if !validGroupOperators[rule.GroupOp] {
		return fmt.Errorf("invalid group_operator: %q (must be \"and\" or \"or\")", rule.GroupOp)
	}

	// Conditions — only request-phase fields allowed.
	if err := validateConditions(rule.Conditions, validRLConditionFields); err != nil {
		return err
	}

	return nil
}

// validateRateLimitGlobal checks the global config.
func validateRateLimitGlobal(cfg RateLimitGlobalConfig) error {
	if cfg.Jitter < 0 || cfg.Jitter > 1 {
		return fmt.Errorf("jitter must be between 0.0 and 1.0")
	}
	if cfg.SweepInterval != "" && !validWindowPattern.MatchString(cfg.SweepInterval) {
		return fmt.Errorf("sweep_interval must be a duration like 1m, 30s, 1h")
	}
	if cfg.ReadInterval != "" && !validWindowPattern.MatchString(cfg.ReadInterval) {
		return fmt.Errorf("read_interval must be a duration like 5s, 10s")
	}
	if cfg.WriteInterval != "" && !validWindowPattern.MatchString(cfg.WriteInterval) {
		return fmt.Errorf("write_interval must be a duration like 5s, 10s")
	}
	if cfg.PurgeAge != "" && !validWindowPattern.MatchString(cfg.PurgeAge) {
		return fmt.Errorf("purge_age must be a duration like 1m, 5m")
	}
	return nil
}

// ─── File Operations ────────────────────────────────────────────────

// ensureRateLimitDir creates the rate limit directory if it doesn't exist.
func ensureRateLimitDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating rate limit dir %s: %w", dir, err)
	}
	log.Printf("rate limit directory ready: %s", dir)
	return nil
}
