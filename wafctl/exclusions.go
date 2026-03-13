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

// load reads exclusions from the JSON file on disk.
func (s *ExclusionStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("exclusions file not found at %s, starting empty", s.filePath)
			s.exclusions = []RuleExclusion{}
			s.version = currentStoreVersion
			return
		}
		log.Printf("error reading exclusions file: %v", err)
		s.exclusions = []RuleExclusion{}
		s.version = currentStoreVersion
		return
	}

	var sf storeFile
	if err := json.Unmarshal(data, &sf); err == nil && sf.Version > 0 {
		s.exclusions = sf.Exclusions
		s.version = sf.Version
		log.Printf("loaded %d exclusions from %s (store v%d)", len(sf.Exclusions), s.filePath, sf.Version)
		return
	}

	// Legacy bare-array format — treat as current version.
	var exclusions []RuleExclusion
	if err := json.Unmarshal(data, &exclusions); err != nil {
		log.Printf("error parsing exclusions file: %v", err)
		s.exclusions = []RuleExclusion{}
		s.version = currentStoreVersion
		return
	}

	s.exclusions = exclusions
	s.version = currentStoreVersion
	log.Printf("loaded %d exclusions from %s (legacy format)", len(exclusions), s.filePath)
	if err := s.save(); err != nil {
		log.Printf("error saving after format upgrade: %v", err)
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

// List returns all exclusions (deep copies — safe to modify).
func (s *ExclusionStore) List() []RuleExclusion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]RuleExclusion, len(s.exclusions))
	for i, e := range s.exclusions {
		cp[i] = deepCopyExclusion(e)
	}
	return cp
}

// Get returns a single exclusion by ID (deep copy — safe to modify).
func (s *ExclusionStore) Get(id string) (RuleExclusion, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.exclusions {
		if e.ID == id {
			return deepCopyExclusion(e), true
		}
	}
	return RuleExclusion{}, false
}

// deepCopyExclusion returns a deep copy of a RuleExclusion, cloning all slices
// to prevent shared backing arrays from causing concurrent mutation bugs.
func deepCopyExclusion(e RuleExclusion) RuleExclusion {
	if e.Conditions != nil {
		conds := make([]Condition, len(e.Conditions))
		for i, c := range e.Conditions {
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
		e.Conditions = conds
	}
	if e.Tags != nil {
		tags := make([]string, len(e.Tags))
		copy(tags, e.Tags)
		e.Tags = tags
	}
	return e
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

// BulkUpdate applies an action to multiple exclusions by ID.
// Supported actions: "enable", "disable", "delete".
// Returns the count of exclusions actually changed.
func (s *ExclusionStore) BulkUpdate(ids []string, action string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}

	old := make([]RuleExclusion, len(s.exclusions))
	copy(old, s.exclusions)

	changed := 0
	now := time.Now().UTC()

	switch action {
	case "enable":
		for i := range s.exclusions {
			if idSet[s.exclusions[i].ID] && !s.exclusions[i].Enabled {
				s.exclusions[i].Enabled = true
				s.exclusions[i].UpdatedAt = now
				changed++
			}
		}
	case "disable":
		for i := range s.exclusions {
			if idSet[s.exclusions[i].ID] && s.exclusions[i].Enabled {
				s.exclusions[i].Enabled = false
				s.exclusions[i].UpdatedAt = now
				changed++
			}
		}
	case "delete":
		var kept []RuleExclusion
		for _, e := range s.exclusions {
			if idSet[e.ID] {
				changed++
			} else {
				kept = append(kept, e)
			}
		}
		s.exclusions = kept
	default:
		return 0, fmt.Errorf("unsupported bulk action: %s", action)
	}

	if changed > 0 {
		if err := s.save(); err != nil {
			s.exclusions = old
			return 0, err
		}
	}
	return changed, nil
}

// EnabledExclusions returns only enabled exclusions (deep copies).
func (s *ExclusionStore) EnabledExclusions() []RuleExclusion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []RuleExclusion
	for _, e := range s.exclusions {
		if e.Enabled {
			result = append(result, deepCopyExclusion(e))
		}
	}
	return result
}
