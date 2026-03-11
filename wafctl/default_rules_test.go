package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── Default Rules Store Tests ────────────────────────────────────

func writeTestDefaultRules(t *testing.T, rules []PolicyRule) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "default-rules.json")
	f := DefaultRulesFile{Version: 1, Rules: rules}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func sampleDefaultRules() []PolicyRule {
	return []PolicyRule{
		{
			ID:       "9100030",
			Name:     "Heuristic Bot Signal: HTTP/1.0",
			Type:     "detect",
			Severity: "NOTICE",
			Conditions: []PolicyCondition{
				{Field: "http_version", Operator: "eq", Value: "HTTP/1.0"},
			},
			GroupOp:  "and",
			Tags:     []string{"bot-signal", "protocol"},
			Enabled:  true,
			Priority: 400,
		},
		{
			ID:       "9100033",
			Name:     "Heuristic Bot Signal: Generic UA",
			Type:     "detect",
			Severity: "NOTICE",
			Conditions: []PolicyCondition{
				{Field: "user_agent", Operator: "phrase_match", Value: "", ListItems: []string{"python-requests", "curl"}},
			},
			GroupOp:  "and",
			Tags:     []string{"bot-signal", "generic-ua"},
			Enabled:  true,
			Priority: 400,
		},
		{
			ID:       "9100034",
			Name:     "XXE External Entity",
			Type:     "detect",
			Severity: "CRITICAL",
			Conditions: []PolicyCondition{
				{Field: "body", Operator: "contains", Value: "<!ENTITY"},
			},
			GroupOp:  "and",
			Tags:     []string{"attack-xxe"},
			Enabled:  true,
			Priority: 400,
		},
	}
}

func TestNewDefaultRuleStore_LoadsDefaults(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	overridesPath := filepath.Join(t.TempDir(), "overrides.json")

	ds := NewDefaultRuleStore(defaultsPath, overridesPath)

	listed := ds.List()
	if len(listed) != len(rules) {
		t.Fatalf("expected %d rules, got %d", len(rules), len(listed))
	}
	for i, r := range listed {
		if r.ID != rules[i].ID {
			t.Errorf("rule %d: expected ID %s, got %s", i, rules[i].ID, r.ID)
		}
		if !r.IsDefault {
			t.Errorf("rule %d: expected is_default=true", i)
		}
		if r.HasOverride {
			t.Errorf("rule %d: expected has_override=false", i)
		}
	}
}

func TestNewDefaultRuleStore_MissingFiles(t *testing.T) {
	ds := NewDefaultRuleStore("/nonexistent/defaults.json", "/nonexistent/overrides.json")
	if len(ds.List()) != 0 {
		t.Error("expected empty list with missing files")
	}
}

func TestNewDefaultRuleStore_EmptyPaths(t *testing.T) {
	ds := NewDefaultRuleStore("", "")
	if len(ds.List()) != 0 {
		t.Error("expected empty list with empty paths")
	}
}

func TestDefaultRuleStore_Get(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// Existing rule.
	r, found := ds.Get("9100030")
	if !found {
		t.Fatal("expected to find rule 9100030")
	}
	if r.Name != "Heuristic Bot Signal: HTTP/1.0" {
		t.Errorf("unexpected name: %s", r.Name)
	}

	// Non-existent rule.
	_, found = ds.Get("nonexistent")
	if found {
		t.Error("expected not found for nonexistent ID")
	}
}

func TestDefaultRuleStore_SetOverride(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	overridesPath := filepath.Join(t.TempDir(), "overrides.json")
	ds := NewDefaultRuleStore(defaultsPath, overridesPath)

	// Override severity.
	err := ds.SetOverride("9100030", json.RawMessage(`{"severity":"WARNING"}`))
	if err != nil {
		t.Fatal(err)
	}

	r, _ := ds.Get("9100030")
	if r.Severity != "WARNING" {
		t.Errorf("expected severity WARNING, got %s", r.Severity)
	}
	if !r.HasOverride {
		t.Error("expected has_override=true after override")
	}
	if len(r.OverrideFields) != 1 || r.OverrideFields[0] != "severity" {
		t.Errorf("expected override_fields=[severity], got %v", r.OverrideFields)
	}

	// Original name should be unchanged.
	if r.Name != "Heuristic Bot Signal: HTTP/1.0" {
		t.Errorf("name should not change: %s", r.Name)
	}

	// Overrides file should exist on disk.
	if _, err := os.Stat(overridesPath); os.IsNotExist(err) {
		t.Error("overrides file should be created on disk")
	}
}

func TestDefaultRuleStore_SetOverride_IDIgnored(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// Try to override ID — should be silently ignored.
	err := ds.SetOverride("9100030", json.RawMessage(`{"id":"HACKED","severity":"ERROR"}`))
	if err != nil {
		t.Fatal(err)
	}

	r, _ := ds.Get("9100030")
	if r.ID != "9100030" {
		t.Errorf("ID should not be overridable: got %s", r.ID)
	}
	if r.Severity != "ERROR" {
		t.Errorf("severity should be overridden: got %s", r.Severity)
	}
}

func TestDefaultRuleStore_SetOverride_NotFound(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	err := ds.SetOverride("nonexistent", json.RawMessage(`{"enabled":false}`))
	if err != errDefaultRuleNotFound {
		t.Errorf("expected errDefaultRuleNotFound, got %v", err)
	}
}

func TestDefaultRuleStore_SetOverride_InvalidJSON(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	err := ds.SetOverride("9100030", json.RawMessage(`not valid json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDefaultRuleStore_RemoveOverride(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// Set an override.
	ds.SetOverride("9100030", json.RawMessage(`{"severity":"ERROR"}`))
	r, _ := ds.Get("9100030")
	if r.Severity != "ERROR" {
		t.Fatal("setup: override not applied")
	}

	// Remove it.
	removed, err := ds.RemoveOverride("9100030")
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Error("expected removed=true")
	}

	// Should revert to baked default.
	r, _ = ds.Get("9100030")
	if r.Severity != "NOTICE" {
		t.Errorf("expected severity reverted to NOTICE, got %s", r.Severity)
	}
	if r.HasOverride {
		t.Error("expected has_override=false after removal")
	}
}

func TestDefaultRuleStore_RemoveOverride_NoneExists(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	removed, err := ds.RemoveOverride("9100030")
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Error("expected removed=false when no override exists")
	}
}

func TestDefaultRuleStore_RemoveOverride_NotFound(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	_, err := ds.RemoveOverride("nonexistent")
	if err != errDefaultRuleNotFound {
		t.Errorf("expected errDefaultRuleNotFound, got %v", err)
	}
}

func TestDefaultRuleStore_GetOverriddenRules(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// No overrides → empty.
	if len(ds.GetOverriddenRules()) != 0 {
		t.Error("expected no overridden rules initially")
	}

	// Override two rules.
	ds.SetOverride("9100030", json.RawMessage(`{"severity":"WARNING"}`))
	ds.SetOverride("9100034", json.RawMessage(`{"tags":["attack-xxe","custom"]}`))

	overridden := ds.GetOverriddenRules()
	if len(overridden) != 2 {
		t.Fatalf("expected 2 overridden rules, got %d", len(overridden))
	}

	// Verify the overrides are applied.
	found := map[string]PolicyRule{}
	for _, r := range overridden {
		found[r.ID] = r
	}
	if found["9100030"].Severity != "WARNING" {
		t.Errorf("9100030 severity: want WARNING, got %s", found["9100030"].Severity)
	}
	if len(found["9100034"].Tags) != 2 || found["9100034"].Tags[1] != "custom" {
		t.Errorf("9100034 tags: want [attack-xxe,custom], got %v", found["9100034"].Tags)
	}
}

func TestDefaultRuleStore_GetDisabledIDs(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// No overrides → no disabled.
	if len(ds.GetDisabledIDs()) != 0 {
		t.Error("expected no disabled IDs initially")
	}

	// Disable one rule.
	ds.SetOverride("9100033", json.RawMessage(`{"enabled":false}`))

	disabled := ds.GetDisabledIDs()
	if len(disabled) != 1 || disabled[0] != "9100033" {
		t.Errorf("expected [9100033], got %v", disabled)
	}

	// Override without disabling — should not appear.
	ds.SetOverride("9100030", json.RawMessage(`{"severity":"ERROR"}`))
	disabled = ds.GetDisabledIDs()
	if len(disabled) != 1 {
		t.Errorf("expected 1 disabled ID, got %d", len(disabled))
	}
}

func TestDefaultRuleStore_Persistence(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	overridesPath := filepath.Join(t.TempDir(), "overrides.json")

	// Create store, set override, close.
	ds1 := NewDefaultRuleStore(defaultsPath, overridesPath)
	ds1.SetOverride("9100030", json.RawMessage(`{"severity":"ERROR"}`))
	ds1.SetOverride("9100033", json.RawMessage(`{"enabled":false}`))

	// Create new store from same files — overrides should persist.
	ds2 := NewDefaultRuleStore(defaultsPath, overridesPath)
	r, _ := ds2.Get("9100030")
	if r.Severity != "ERROR" {
		t.Errorf("persisted override not loaded: severity=%s", r.Severity)
	}
	disabled := ds2.GetDisabledIDs()
	if len(disabled) != 1 || disabled[0] != "9100033" {
		t.Errorf("persisted disabled not loaded: %v", disabled)
	}
}

func TestDefaultRuleStore_MultipleOverridesToSameRule(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// First override: change severity.
	ds.SetOverride("9100030", json.RawMessage(`{"severity":"WARNING"}`))
	r, _ := ds.Get("9100030")
	if r.Severity != "WARNING" {
		t.Fatal("first override not applied")
	}

	// Second override: replaces the first (not additive).
	ds.SetOverride("9100030", json.RawMessage(`{"severity":"ERROR","priority":999}`))
	r, _ = ds.Get("9100030")
	if r.Severity != "ERROR" {
		t.Errorf("second override severity: want ERROR, got %s", r.Severity)
	}
	if r.Priority != 999 {
		t.Errorf("second override priority: want 999, got %d", r.Priority)
	}
}

// ─── ApplyDefaultRuleOverrides Tests ──────────────────────────────

func TestApplyDefaultRuleOverrides_NilStore(t *testing.T) {
	input := []byte(`{"rules":[],"generated":"2026-01-01T00:00:00Z","version":1}`)
	out, err := ApplyDefaultRuleOverrides(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(input) {
		t.Error("nil store should return input unchanged")
	}
}

func TestApplyDefaultRuleOverrides_NoOverrides(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	input := []byte(`{"rules":[],"generated":"2026-01-01T00:00:00Z","version":1}`)
	out, err := ApplyDefaultRuleOverrides(input, ds)
	if err != nil {
		t.Fatal(err)
	}
	// No overrides → input should be unchanged.
	if string(out) != string(input) {
		t.Error("no overrides should return input unchanged")
	}
}

func TestApplyDefaultRuleOverrides_WithOverrides(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// Override severity on one rule.
	ds.SetOverride("9100030", json.RawMessage(`{"severity":"ERROR"}`))

	input := `{"rules":[{"id":"user-rule-1","name":"User Rule","type":"block","conditions":[],"group_op":"and","enabled":true,"priority":100}],"generated":"2026-01-01T00:00:00Z","version":1}`
	out, err := ApplyDefaultRuleOverrides([]byte(input), ds)
	if err != nil {
		t.Fatal(err)
	}

	var file PolicyRulesFile
	if err := json.Unmarshal(out, &file); err != nil {
		t.Fatal(err)
	}

	// Should have the original user rule + the overridden default.
	if len(file.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(file.Rules))
	}

	// Find the overridden default.
	var found bool
	for _, r := range file.Rules {
		if r.ID == "9100030" {
			found = true
			if r.Severity != "ERROR" {
				t.Errorf("overridden rule severity: want ERROR, got %s", r.Severity)
			}
		}
	}
	if !found {
		t.Error("overridden default rule 9100030 not found in output")
	}
}

func TestApplyDefaultRuleOverrides_DisabledRule(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// Disable a rule.
	ds.SetOverride("9100033", json.RawMessage(`{"enabled":false}`))

	input := `{"rules":[],"generated":"2026-01-01T00:00:00Z","version":1}`
	out, err := ApplyDefaultRuleOverrides([]byte(input), ds)
	if err != nil {
		t.Fatal(err)
	}

	var file PolicyRulesFile
	json.Unmarshal(out, &file)

	// Disabled rule should NOT appear in rules array.
	for _, r := range file.Rules {
		if r.ID == "9100033" {
			t.Error("disabled default rule should not be in rules array")
		}
	}

	// Should appear in DisabledDefaultRules.
	if len(file.DisabledDefaultRules) != 1 || file.DisabledDefaultRules[0] != "9100033" {
		t.Errorf("expected disabled_default_rules=[9100033], got %v", file.DisabledDefaultRules)
	}
}

func TestApplyDefaultRuleOverrides_MixedOverridesAndDisabled(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// Override one, disable another.
	ds.SetOverride("9100030", json.RawMessage(`{"severity":"ERROR"}`))
	ds.SetOverride("9100033", json.RawMessage(`{"enabled":false}`))

	input := `{"rules":[],"generated":"2026-01-01T00:00:00Z","version":1}`
	out, err := ApplyDefaultRuleOverrides([]byte(input), ds)
	if err != nil {
		t.Fatal(err)
	}

	var file PolicyRulesFile
	json.Unmarshal(out, &file)

	// Only the enabled override should be in rules.
	if len(file.Rules) != 1 {
		t.Fatalf("expected 1 rule (overridden, enabled), got %d", len(file.Rules))
	}
	if file.Rules[0].ID != "9100030" {
		t.Errorf("expected rule 9100030, got %s", file.Rules[0].ID)
	}

	// Disabled should be in disabled list.
	if len(file.DisabledDefaultRules) != 1 || file.DisabledDefaultRules[0] != "9100033" {
		t.Errorf("expected disabled=[9100033], got %v", file.DisabledDefaultRules)
	}
}

// ─── HTTP Handler Tests ───────────────────────────────────────────

func TestHandleListDefaultRules(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	req := httptest.NewRequest("GET", "/api/default-rules", nil)
	w := httptest.NewRecorder()
	handleListDefaultRules(ds).ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result []DefaultRuleResponse
	json.NewDecoder(w.Body).Decode(&result)
	if len(result) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(result))
	}
}

func TestHandleGetDefaultRule(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/default-rules/{id}", handleGetDefaultRule(ds))

	// Existing rule.
	req := httptest.NewRequest("GET", "/api/default-rules/9100030", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var r DefaultRuleResponse
	json.NewDecoder(w.Body).Decode(&r)
	if r.ID != "9100030" {
		t.Errorf("expected ID 9100030, got %s", r.ID)
	}

	// Non-existent rule.
	req = httptest.NewRequest("GET", "/api/default-rules/nonexistent", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("expected 404 for nonexistent, got %d", w.Code)
	}
}

func TestHandleOverrideDefaultRule(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/default-rules/{id}", handleOverrideDefaultRule(ds))
	mux.HandleFunc("GET /api/default-rules/{id}", handleGetDefaultRule(ds))

	// Override.
	req := httptest.NewRequest("PUT", "/api/default-rules/9100030",
		strings.NewReader(`{"severity":"ERROR"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var r DefaultRuleResponse
	json.NewDecoder(w.Body).Decode(&r)
	if r.Severity != "ERROR" {
		t.Errorf("expected severity ERROR, got %s", r.Severity)
	}
	if !r.HasOverride {
		t.Error("expected has_override=true")
	}

	// Override nonexistent.
	req = httptest.NewRequest("PUT", "/api/default-rules/nonexistent",
		strings.NewReader(`{"severity":"ERROR"}`))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleResetDefaultRule(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/default-rules/{id}", handleOverrideDefaultRule(ds))
	mux.HandleFunc("DELETE /api/default-rules/{id}/override", handleResetDefaultRule(ds))

	// Set an override first.
	req := httptest.NewRequest("PUT", "/api/default-rules/9100030",
		strings.NewReader(`{"severity":"ERROR"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("setup override: %d", w.Code)
	}

	// Reset it.
	req = httptest.NewRequest("DELETE", "/api/default-rules/9100030/override", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var r DefaultRuleResponse
	json.NewDecoder(w.Body).Decode(&r)
	if r.Severity != "NOTICE" {
		t.Errorf("expected severity reverted to NOTICE, got %s", r.Severity)
	}
	if r.HasOverride {
		t.Error("expected has_override=false after reset")
	}

	// Reset when no override — should still return 200.
	req = httptest.NewRequest("DELETE", "/api/default-rules/9100030/override", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200 for no-op reset, got %d", w.Code)
	}

	// Reset nonexistent rule.
	req = httptest.NewRequest("DELETE", "/api/default-rules/nonexistent/override", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}
