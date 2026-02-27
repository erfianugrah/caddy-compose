package main

import (
	"crypto/rand"
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

// SecRule field validation patterns — restrict user-supplied values that are
// interpolated directly into ModSecurity directives to prevent injection.
var (
	// ruleTagRe matches valid CRS tag names: letters, digits, /, _, -, .
	// e.g. "language/php", "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"
	ruleTagRe = regexp.MustCompile(`^[a-zA-Z0-9/_.\-]+$`)

	// variableRe matches valid SecRule variable expressions: letters, digits,
	// _, :, !, |, and . — e.g. "ARGS:foo", "!REQUEST_COOKIES:/^__utm/",
	// "REQUEST_HEADERS:User-Agent"
	variableRe = regexp.MustCompile(`^[a-zA-Z0-9_:!.|/^\-]+$`)

	// namedFieldNameRe matches the name portion of named condition fields
	// (header, cookie, args, response_header) — the part before ':' in the
	// value. e.g. "User-Agent", "X-Forwarded-For", "__session"
	namedFieldNameRe = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
)

// namedConditionFields are condition fields where the value has a "Name:value"
// format and the Name portion is interpolated into the SecRule variable.
var namedConditionFields = map[string]bool{
	"header":          true,
	"cookie":          true,
	"args":            true,
	"response_header": true,
	"body_form":       true,
}

// jsonPathNameRe validates JSON dot-path names used by body_json conditions.
// Allows dots for path navigation, alphanumeric characters, underscores, and
// array indices (digits). Leading dot is optional.
var jsonPathNameRe = regexp.MustCompile(`^\.?[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)*$`)

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

// validateConditions validates a slice of conditions against a set of allowed fields.
// Pass nil for allowedFields to use validConditionFields (all fields allowed).
func validateConditions(conditions []Condition, allowedFields map[string]bool) error {
	if allowedFields == nil {
		allowedFields = validConditionFields
	}
	for i, c := range conditions {
		if !allowedFields[c.Field] {
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
		// Validate named field names (header, cookie, args, response_header, body_form).
		// The "Name:value" format uses the Name as a SecRule variable suffix;
		// restrict it to safe characters to prevent directive injection.
		if namedConditionFields[c.Field] && strings.Contains(c.Value, ":") {
			name := c.Value[:strings.Index(c.Value, ":")]
			if name != "" && !namedFieldNameRe.MatchString(name) {
				return fmt.Errorf("condition[%d]: invalid %s name %q (letters, digits, hyphens, underscores only)", i, c.Field, name)
			}
		}
		// Validate body_json dot-path names separately (allows dots for path navigation).
		if c.Field == "body_json" && strings.Contains(c.Value, ":") {
			name := c.Value[:strings.Index(c.Value, ":")]
			if name != "" && !jsonPathNameRe.MatchString(name) {
				return fmt.Errorf("condition[%d]: invalid body_json path %q (dot-separated alphanumeric segments)", i, name)
			}
		}
		// Reject control characters in condition values.
		if strings.ContainsAny(c.Value, "\n\r") {
			return fmt.Errorf("condition[%d]: value must not contain newlines", i)
		}
	}
	return nil
}

// validateExclusion checks that the exclusion has required fields.
func validateExclusion(e RuleExclusion) error {
	if e.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Reject control characters in the name (used in SecRule comments and msg fields).
	if strings.ContainsAny(e.Name, "\n\r") {
		return fmt.Errorf("name must not contain newlines")
	}
	if !validExclusionTypes[e.Type] {
		return fmt.Errorf("invalid exclusion type: %q", e.Type)
	}

	// Validate group operator.
	if !validGroupOperators[e.GroupOp] {
		return fmt.Errorf("invalid group_operator: %q (must be \"and\" or \"or\")", e.GroupOp)
	}

	// Validate conditions (all fields allowed for WAF exclusions).
	if err := validateConditions(e.Conditions, nil); err != nil {
		return err
	}

	// Type-specific validation.
	switch e.Type {
	case "allow", "block":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("%s requires at least one condition", e.Type)
		}
	case "honeypot":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("honeypot requires at least one path condition")
		}
		for i, c := range e.Conditions {
			if c.Field != "path" {
				return fmt.Errorf("honeypot condition[%d]: only 'path' field is allowed, got %q", i, c.Field)
			}
		}
	case "skip_rule":
		if e.RuleID == "" && e.RuleTag == "" {
			return fmt.Errorf("skip_rule requires rule_id or rule_tag")
		}
		if e.RuleID != "" {
			if err := validateRuleIDField(e.RuleID); err != nil {
				return fmt.Errorf("invalid rule_id: %w", err)
			}
		}
		if e.RuleTag != "" {
			if !ruleTagRe.MatchString(e.RuleTag) {
				return fmt.Errorf("invalid rule_tag %q (letters, digits, /, _, -, . only)", e.RuleTag)
			}
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
		if err := validateRuleIDField(e.RuleID); err != nil {
			return fmt.Errorf("invalid rule_id: %w", err)
		}
	case "remove_by_tag", "update_target_by_tag", "runtime_remove_by_tag", "runtime_remove_target_by_tag":
		if e.RuleTag == "" {
			return fmt.Errorf("rule_tag is required for type %q", e.Type)
		}
		if !ruleTagRe.MatchString(e.RuleTag) {
			return fmt.Errorf("invalid rule_tag %q (letters, digits, /, _, -, . only)", e.RuleTag)
		}
	}

	// Variable required for update_target types.
	switch e.Type {
	case "update_target_by_id", "update_target_by_tag", "runtime_remove_target_by_id", "runtime_remove_target_by_tag":
		if e.Variable == "" {
			return fmt.Errorf("variable is required for type %q", e.Type)
		}
		if !variableRe.MatchString(e.Variable) {
			return fmt.Errorf("invalid variable %q (letters, digits, _, :, !, |, ., / only)", e.Variable)
		}
	}

	// Runtime advanced types need at least a path condition.
	switch e.Type {
	case "runtime_remove_by_id", "runtime_remove_by_tag", "runtime_remove_target_by_id", "runtime_remove_target_by_tag":
		if len(e.Conditions) == 0 {
			return fmt.Errorf("conditions required for runtime type %q (need at least a path condition)", e.Type)
		}
	}

	return nil
}

// validateRuleIDField checks that a rule_id field contains valid IDs.
// Accepts a single ID (e.g. "932235"), a range (e.g. "932000-932999"),
// or multiple space/comma-separated IDs and ranges.
func validateRuleIDField(field string) error {
	normalized := strings.ReplaceAll(field, ",", " ")
	tokens := strings.Fields(normalized)
	if len(tokens) == 0 {
		return fmt.Errorf("empty rule_id")
	}
	for _, tok := range tokens {
		if !isValidRuleIDToken(tok) {
			return fmt.Errorf("invalid rule ID %q (must be a number or a range like 932000-932999)", tok)
		}
	}
	return nil
}

// isValidRuleIDToken returns true if the token is a valid rule ID (all digits)
// or a valid range (digits-digits).
func isValidRuleIDToken(tok string) bool {
	if tok == "" {
		return false
	}
	// Check for range: digits-digits
	if idx := strings.Index(tok, "-"); idx > 0 && idx < len(tok)-1 {
		return isAllDigits(tok[:idx]) && isAllDigits(tok[idx+1:])
	}
	return isAllDigits(tok)
}

// isAllDigits returns true if every byte in s is an ASCII digit.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
