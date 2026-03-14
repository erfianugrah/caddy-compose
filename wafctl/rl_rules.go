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
	return s.listLocked()
}

// listLocked returns a deep copy of rules. Caller must hold s.mu (read or write).
func (s *RateLimitRuleStore) listLocked() []RateLimitRule {
	cp := make([]RateLimitRule, len(s.config.Rules))
	for i, r := range s.config.Rules {
		cp[i] = deepCopyRLRule(r)
	}
	return cp
}

// deepCopyRLRule returns a deep copy of a RateLimitRule, cloning all slices
// to prevent shared backing arrays from causing concurrent mutation bugs.
func deepCopyRLRule(r RateLimitRule) RateLimitRule {
	if r.Conditions != nil {
		conds := make([]Condition, len(r.Conditions))
		for i, c := range r.Conditions {
			conds[i] = c
			if c.Transforms != nil {
				conds[i].Transforms = make([]string, len(c.Transforms))
				copy(conds[i].Transforms, c.Transforms)
			}
			if c.ListItems != nil {
				conds[i].ListItems = make([]string, len(c.ListItems))
				copy(conds[i].ListItems, c.ListItems)
			}
		}
		r.Conditions = conds
	}
	if r.Tags != nil {
		tags := make([]string, len(r.Tags))
		copy(tags, r.Tags)
		r.Tags = tags
	}
	return r
}

// Get returns a single rule by ID (deep copy), or nil if not found.
func (s *RateLimitRuleStore) Get(id string) *RateLimitRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.config.Rules {
		if r.ID == id {
			cp := deepCopyRLRule(r)
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
			result = append(result, deepCopyRLRule(r))
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
		Rules:      s.listLocked(),
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
	if rule.GroupOp == "or" && len(rule.Conditions) > 1 {
		return fmt.Errorf("group_operator \"or\" is not yet supported for rate limit rules with multiple conditions")
	}

	// Tags: same constraints as exclusion tags — max 10, lowercase alphanumeric + hyphens, max 50 chars.
	if len(rule.Tags) > 10 {
		return fmt.Errorf("too many tags: %d (max 10)", len(rule.Tags))
	}
	for i, tag := range rule.Tags {
		if len(tag) > 50 {
			return fmt.Errorf("tag[%d] too long: %d chars (max 50)", i, len(tag))
		}
		if !eventTagRe.MatchString(tag) {
			return fmt.Errorf("invalid tag[%d] %q (lowercase alphanumeric and hyphens only, must start with letter or digit)", i, tag)
		}
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
