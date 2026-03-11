package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
)

// ─── Default Rules Store ──────────────────────────────────────────
//
// Manages baked-in default rules (shipped in default-rules.json) and
// user overrides. The baked file is read-only; overrides are stored
// separately and applied via JSON merge. On deploy, overridden rules
// are emitted as user rules in policy-rules.json so the plugin's
// existing merge-by-ID logic replaces the baked defaults.

// DefaultRulesFile is the on-disk format for default-rules.json
// (baked into the Docker image by the Dockerfile COPY).
type DefaultRulesFile struct {
	Version int          `json:"version"`
	Rules   []PolicyRule `json:"rules"`
}

// defaultRuleOverridesFile is the on-disk format for user overrides.
type defaultRuleOverridesFile struct {
	Overrides map[string]json.RawMessage `json:"overrides"`
}

// DefaultRuleStore reads baked default rules and manages user overrides.
type DefaultRuleStore struct {
	mu            sync.RWMutex
	defaults      []PolicyRule               // baked defaults (read-only)
	defaultsByID  map[string]PolicyRule      // index for fast lookup
	overrides     map[string]json.RawMessage // per-rule field overrides
	overridesFile string                     // path to writable overrides file
}

// NewDefaultRuleStore loads baked defaults from defaultsPath and user
// overrides from overridesPath. Missing files are handled gracefully.
func NewDefaultRuleStore(defaultsPath, overridesPath string) *DefaultRuleStore {
	ds := &DefaultRuleStore{
		defaultsByID:  make(map[string]PolicyRule),
		overrides:     make(map[string]json.RawMessage),
		overridesFile: overridesPath,
	}

	// Load baked defaults (read-only, from Docker image).
	if defaultsPath != "" {
		data, err := os.ReadFile(defaultsPath)
		if err != nil {
			log.Printf("[default-rules] no baked defaults at %s: %v", defaultsPath, err)
		} else {
			var f DefaultRulesFile
			if err := json.Unmarshal(data, &f); err != nil {
				log.Printf("[default-rules] invalid JSON in %s: %v", defaultsPath, err)
			} else {
				ds.defaults = f.Rules
				for _, r := range f.Rules {
					ds.defaultsByID[r.ID] = r
				}
				log.Printf("[default-rules] loaded %d baked default rules from %s (version %d)", len(f.Rules), defaultsPath, f.Version)
			}
		}
	}

	// Load user overrides (writable, from data volume).
	if overridesPath != "" {
		data, err := os.ReadFile(overridesPath)
		if err == nil {
			var f defaultRuleOverridesFile
			if err := json.Unmarshal(data, &f); err != nil {
				log.Printf("[default-rules] invalid overrides JSON in %s: %v", overridesPath, err)
			} else if f.Overrides != nil {
				ds.overrides = f.Overrides
				log.Printf("[default-rules] loaded %d overrides from %s", len(f.Overrides), overridesPath)
			}
		}
	}

	return ds
}

// List returns all default rules with overrides applied.
func (ds *DefaultRuleStore) List() []DefaultRuleResponse {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	result := make([]DefaultRuleResponse, len(ds.defaults))
	for i, def := range ds.defaults {
		override, hasOverride := ds.overrides[def.ID]
		merged := def
		var overrideFields []string
		if hasOverride {
			merged, overrideFields = ds.applyOverride(def, override)
		}
		result[i] = DefaultRuleResponse{
			PolicyRule:     merged,
			IsDefault:      true,
			HasOverride:    hasOverride,
			OverrideFields: overrideFields,
		}
	}
	return result
}

// Get returns a single default rule by ID with override applied.
func (ds *DefaultRuleStore) Get(id string) (DefaultRuleResponse, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	def, ok := ds.defaultsByID[id]
	if !ok {
		return DefaultRuleResponse{}, false
	}
	override, hasOverride := ds.overrides[id]
	merged := def
	var overrideFields []string
	if hasOverride {
		merged, overrideFields = ds.applyOverride(def, override)
	}
	return DefaultRuleResponse{
		PolicyRule:     merged,
		IsDefault:      true,
		HasOverride:    hasOverride,
		OverrideFields: overrideFields,
	}, true
}

// SetOverride stores a per-field override for a default rule.
// The override is a partial JSON object — only specified fields change.
func (ds *DefaultRuleStore) SetOverride(id string, override json.RawMessage) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, ok := ds.defaultsByID[id]; !ok {
		return errDefaultRuleNotFound
	}

	// Validate: ensure the override is a valid JSON object.
	var check map[string]json.RawMessage
	if err := json.Unmarshal(override, &check); err != nil {
		return err
	}

	// Don't allow changing the ID.
	delete(check, "id")

	cleaned, _ := json.Marshal(check)
	ds.overrides[id] = json.RawMessage(cleaned)
	return ds.saveLocked()
}

// RemoveOverride removes any user override for a default rule,
// reverting it to the baked default.
func (ds *DefaultRuleStore) RemoveOverride(id string) (bool, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, ok := ds.defaultsByID[id]; !ok {
		return false, errDefaultRuleNotFound
	}
	if _, ok := ds.overrides[id]; !ok {
		return false, nil // no override to remove
	}
	delete(ds.overrides, id)
	return true, ds.saveLocked()
}

// GetOverriddenRules returns default rules that have been modified by user
// overrides. These should be emitted as user rules in policy-rules.json
// so the plugin's merge-by-ID logic replaces the baked defaults.
func (ds *DefaultRuleStore) GetOverriddenRules() []PolicyRule {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	var rules []PolicyRule
	for id, override := range ds.overrides {
		def, ok := ds.defaultsByID[id]
		if !ok {
			continue
		}
		merged, _ := ds.applyOverride(def, override)
		rules = append(rules, merged)
	}
	return rules
}

// GetDisabledIDs returns IDs of default rules that have been disabled
// via override (enabled: false). These go into DisabledDefaultRules.
func (ds *DefaultRuleStore) GetDisabledIDs() []string {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	var ids []string
	for id, override := range ds.overrides {
		def, ok := ds.defaultsByID[id]
		if !ok {
			continue
		}
		merged, _ := ds.applyOverride(def, override)
		if !merged.Enabled {
			ids = append(ids, id)
		}
	}
	return ids
}

// applyOverride merges an override onto a default rule using JSON merge.
// Returns the merged rule and the list of overridden field names.
// Caller must hold at least ds.mu.RLock.
func (ds *DefaultRuleStore) applyOverride(def PolicyRule, override json.RawMessage) (PolicyRule, []string) {
	// Marshal default to map.
	defBytes, _ := json.Marshal(def)
	var defMap map[string]json.RawMessage
	_ = json.Unmarshal(defBytes, &defMap)

	// Parse override fields.
	var overMap map[string]json.RawMessage
	_ = json.Unmarshal(override, &overMap)

	// Track which fields were overridden.
	var fields []string
	for k, v := range overMap {
		if k == "id" {
			continue // never override ID
		}
		defMap[k] = v
		fields = append(fields, k)
	}

	// Unmarshal merged map back to PolicyRule.
	merged, _ := json.Marshal(defMap)
	var result PolicyRule
	_ = json.Unmarshal(merged, &result)
	// Ensure ID is always the original.
	result.ID = def.ID

	return result, fields
}

// saveLocked writes the overrides file to disk. Caller must hold ds.mu.Lock.
func (ds *DefaultRuleStore) saveLocked() error {
	f := defaultRuleOverridesFile{Overrides: ds.overrides}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(ds.overridesFile, data, 0644)
}

var errDefaultRuleNotFound = &defaultRuleError{"default rule not found"}

type defaultRuleError struct{ msg string }

func (e *defaultRuleError) Error() string { return e.msg }

// ─── API Response Type ────────────────────────────────────────────

// DefaultRuleResponse wraps a PolicyRule with override metadata.
type DefaultRuleResponse struct {
	PolicyRule
	IsDefault      bool     `json:"is_default"`
	HasOverride    bool     `json:"has_override"`
	OverrideFields []string `json:"override_fields,omitempty"`
}

// ─── HTTP Handlers ────────────────────────────────────────────────

func handleListDefaultRules(ds *DefaultRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, ds.List())
	}
}

func handleGetDefaultRule(ds *DefaultRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		rule, found := ds.Get(id)
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "default rule not found"})
			return
		}
		writeJSON(w, http.StatusOK, rule)
	}
}

func handleOverrideDefaultRule(ds *DefaultRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		var raw json.RawMessage
		if _, failed := decodeJSON(w, r, &raw); failed {
			return
		}

		if err := ds.SetOverride(id, raw); err != nil {
			if err == errDefaultRuleNotFound {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid override", Details: err.Error()})
			return
		}

		rule, _ := ds.Get(id)
		writeJSON(w, http.StatusOK, rule)
	}
}

func handleResetDefaultRule(ds *DefaultRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		removed, err := ds.RemoveOverride(id)
		if err != nil {
			if err == errDefaultRuleNotFound {
				writeJSON(w, http.StatusNotFound, ErrorResponse{Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to reset override", Details: err.Error()})
			return
		}
		if !removed {
			writeJSON(w, http.StatusOK, map[string]string{"status": "no override to remove"})
			return
		}
		rule, _ := ds.Get(id)
		writeJSON(w, http.StatusOK, rule)
	}
}
