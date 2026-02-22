package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// atomicWriteFile writes data to a file atomically by first writing to a
// temporary file in the same directory, then renaming it to the target path.
// This prevents corruption if the process crashes mid-write.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up the temp file on any error.
	success := false
	defer func() {
		if !success {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	// Sync to ensure data is flushed to disk before rename.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	// Atomic rename: on POSIX, rename within the same filesystem is atomic.
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming temp file to %s: %w", path, err)
	}

	success = true
	return nil
}

// generateUUID produces a v4 UUID using crypto/rand.
func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: should never happen with crypto/rand.
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// generateUUIDv7 produces a UUIDv7 (RFC 9562): time-ordered with ms precision.
// First 48 bits = unix_ts_ms, next 4 = version (0111), 12 bits rand,
// 2 variant bits (10), 62 bits rand.
func generateUUIDv7() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	ms := uint64(time.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ExclusionStore manages rule exclusions with file-backed persistence.
type ExclusionStore struct {
	mu         sync.RWMutex
	exclusions []RuleExclusion
	filePath   string
}

// NewExclusionStore creates a new store and loads existing data from disk.
func NewExclusionStore(filePath string) *ExclusionStore {
	s := &ExclusionStore{filePath: filePath}
	s.load()
	return s
}

// load reads exclusions from the JSON file on disk.
func (s *ExclusionStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("exclusions file not found at %s, starting empty", s.filePath)
			s.exclusions = []RuleExclusion{}
			return
		}
		log.Printf("error reading exclusions file: %v", err)
		s.exclusions = []RuleExclusion{}
		return
	}

	var exclusions []RuleExclusion
	if err := json.Unmarshal(data, &exclusions); err != nil {
		log.Printf("error parsing exclusions file: %v", err)
		s.exclusions = []RuleExclusion{}
		return
	}

	s.exclusions = exclusions
	log.Printf("loaded %d exclusions from %s", len(exclusions), s.filePath)
}

// save writes the current exclusions to the JSON file atomically.
func (s *ExclusionStore) save() error {
	data, err := json.MarshalIndent(s.exclusions, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling exclusions: %w", err)
	}
	if err := atomicWriteFile(s.filePath, data, 0644); err != nil {
		return fmt.Errorf("error writing exclusions file: %w", err)
	}
	return nil
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
			old := s.exclusions
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

// validateExclusion checks that the exclusion has required fields.
func validateExclusion(e RuleExclusion) error {
	if e.Name == "" {
		return fmt.Errorf("name is required")
	}
	if !validExclusionTypes[e.Type] {
		return fmt.Errorf("invalid exclusion type: %q", e.Type)
	}

	// Validate group operator.
	if !validGroupOperators[e.GroupOp] {
		return fmt.Errorf("invalid group_operator: %q (must be \"and\" or \"or\")", e.GroupOp)
	}

	// Validate conditions.
	for i, c := range e.Conditions {
		if !validConditionFields[c.Field] {
			return fmt.Errorf("condition[%d]: invalid field %q", i, c.Field)
		}
		ops, ok := validOperatorsForField[c.Field]
		if !ok || !ops[c.Operator] {
			return fmt.Errorf("condition[%d]: invalid operator %q for field %q", i, c.Operator, c.Field)
		}
		if c.Value == "" {
			return fmt.Errorf("condition[%d]: value is required", i)
		}
		// Validate method values.
		if c.Field == "method" {
			validMethods := map[string]bool{
				"GET": true, "POST": true, "PUT": true, "DELETE": true,
				"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
			}
			for _, m := range splitPipe(c.Value) {
				if !validMethods[m] {
					return fmt.Errorf("condition[%d]: invalid HTTP method %q", i, m)
				}
			}
		}
	}

	// Type-specific validation.
	switch e.Type {
	case "allow", "block":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("%s requires at least one condition", e.Type)
		}
	case "skip_rule":
		if e.RuleID == "" && e.RuleTag == "" {
			return fmt.Errorf("skip_rule requires rule_id or rule_tag")
		}
		if len(e.Conditions) == 0 {
			return fmt.Errorf("skip_rule requires at least one condition")
		}
	case "raw":
		if e.RawRule == "" {
			return fmt.Errorf("raw_rule is required for type \"raw\"")
		}

	// Advanced types — these still use RuleID/RuleTag/Variable directly
	case "remove_by_id", "update_target_by_id", "runtime_remove_by_id", "runtime_remove_target_by_id":
		if e.RuleID == "" {
			return fmt.Errorf("rule_id is required for type %q", e.Type)
		}
	case "remove_by_tag", "update_target_by_tag", "runtime_remove_by_tag":
		if e.RuleTag == "" {
			return fmt.Errorf("rule_tag is required for type %q", e.Type)
		}
	}

	// Variable required for update_target types.
	switch e.Type {
	case "update_target_by_id", "update_target_by_tag", "runtime_remove_target_by_id":
		if e.Variable == "" {
			return fmt.Errorf("variable is required for type %q", e.Type)
		}
	}

	// Runtime advanced types need at least a path condition.
	switch e.Type {
	case "runtime_remove_by_id", "runtime_remove_by_tag", "runtime_remove_target_by_id":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("conditions required for runtime type %q (need at least a path condition)", e.Type)
		}
	}

	return nil
}

// splitPipe splits a pipe-delimited string and trims whitespace.
func splitPipe(s string) []string {
	var parts []string
	for _, p := range strings.Split(s, "|") {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}
