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

func TestApplyDefaultRuleOverrides_ExcludesPreserved(t *testing.T) {
	// Verify that the Excludes field on PolicyCondition survives a round-trip
	// through ApplyDefaultRuleOverrides (the bug was that Excludes was silently
	// dropped because PolicyCondition in wafctl was missing the field).
	rules := []PolicyRule{
		{
			ID:   "920273",
			Name: "Invalid character in request (outside of very strict set)",
			Type: "detect",
			Conditions: []PolicyCondition{
				{
					Field:    "all_args_values",
					Operator: "regex",
					Value:    "^[\\x00-\\x08]",
					Excludes: []string{"__utm", "authtoken"},
				},
			},
			GroupOp:  "and",
			Severity: "WARNING",
			Enabled:  true,
			Priority: 400,
		},
	}
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// Override severity to trigger inclusion in output.
	ds.SetOverride("920273", json.RawMessage(`{"severity":"ERROR"}`))

	input := `{"rules":[],"generated":"2026-01-01T00:00:00Z","version":1}`
	out, err := ApplyDefaultRuleOverrides([]byte(input), ds)
	if err != nil {
		t.Fatal(err)
	}

	var file PolicyRulesFile
	if err := json.Unmarshal(out, &file); err != nil {
		t.Fatal(err)
	}

	// Find the overridden rule.
	var found bool
	for _, r := range file.Rules {
		if r.ID == "920273" {
			found = true
			if len(r.Conditions) == 0 {
				t.Fatal("expected conditions on overridden rule")
			}
			if len(r.Conditions[0].Excludes) != 2 {
				t.Errorf("expected 2 excludes, got %d", len(r.Conditions[0].Excludes))
			}
			if r.Conditions[0].Excludes[0] != "__utm" || r.Conditions[0].Excludes[1] != "authtoken" {
				t.Errorf("excludes mismatch: %v", r.Conditions[0].Excludes)
			}
		}
	}
	if !found {
		t.Error("overridden rule 920273 not found in output")
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

	// Reset when no override — should still return 200 with a valid DefaultRuleResponse.
	req = httptest.NewRequest("DELETE", "/api/default-rules/9100030/override", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200 for no-op reset, got %d", w.Code)
	}
	// Verify the response is a valid DefaultRuleResponse (not a bare status map).
	var noopResp DefaultRuleResponse
	if err := json.NewDecoder(w.Body).Decode(&noopResp); err != nil {
		t.Fatalf("no-op reset: failed to decode response: %v", err)
	}
	if noopResp.ID != "9100030" {
		t.Errorf("no-op reset: expected id=9100030, got %s", noopResp.ID)
	}
	if noopResp.HasOverride {
		t.Error("no-op reset: expected has_override=false")
	}

	// Reset nonexistent rule.
	req = httptest.NewRequest("DELETE", "/api/default-rules/nonexistent/override", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ─── Bulk Actions Tests ───────────────────────────────────────────

func TestBulkOverride(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// Bulk override: disable two rules at once.
	changed, err := ds.BulkOverride(
		[]string{"9100030", "9100033"},
		json.RawMessage(`{"enabled":false}`),
	)
	if err != nil {
		t.Fatalf("BulkOverride: %v", err)
	}
	if changed != 2 {
		t.Errorf("expected 2 changed, got %d", changed)
	}

	// Verify both are disabled.
	for _, id := range []string{"9100030", "9100033"} {
		r, ok := ds.Get(id)
		if !ok {
			t.Fatalf("rule %s not found", id)
		}
		if r.Enabled {
			t.Errorf("rule %s should be disabled", id)
		}
		if !r.HasOverride {
			t.Errorf("rule %s should have override", id)
		}
	}

	// Unknown IDs are skipped.
	changed, err = ds.BulkOverride(
		[]string{"nonexistent", "9100030"},
		json.RawMessage(`{"severity":"ERROR"}`),
	)
	if err != nil {
		t.Fatalf("BulkOverride with unknown: %v", err)
	}
	if changed != 1 {
		t.Errorf("expected 1 changed (unknown skipped), got %d", changed)
	}

	// Verify merge: 9100030 should have both enabled=false AND severity=ERROR.
	r, _ := ds.Get("9100030")
	if r.Enabled {
		t.Error("9100030 should still be disabled after merge")
	}
	if r.Severity != "ERROR" {
		t.Errorf("9100030 severity should be ERROR, got %s", r.Severity)
	}
}

func TestBulkReset(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	// Set overrides first.
	ds.BulkOverride(
		[]string{"9100030", "9100033"},
		json.RawMessage(`{"enabled":false}`),
	)

	// Bulk reset.
	removed, err := ds.BulkReset([]string{"9100030", "9100033", "nonexistent"})
	if err != nil {
		t.Fatalf("BulkReset: %v", err)
	}
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}

	// Verify both are back to defaults.
	for _, id := range []string{"9100030", "9100033"} {
		r, ok := ds.Get(id)
		if !ok {
			t.Fatalf("rule %s not found", id)
		}
		if !r.Enabled {
			t.Errorf("rule %s should be enabled after reset", id)
		}
		if r.HasOverride {
			t.Errorf("rule %s should not have override after reset", id)
		}
	}
}

func TestHandleBulkDefaultRules(t *testing.T) {
	rules := sampleDefaultRules()
	defaultsPath := writeTestDefaultRules(t, rules)
	ds := NewDefaultRuleStore(defaultsPath, filepath.Join(t.TempDir(), "overrides.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/default-rules/bulk", handleBulkDefaultRules(ds))

	t.Run("override", func(t *testing.T) {
		body := `{"ids":["9100030","9100033"],"action":"override","override":{"enabled":false}}`
		req := httptest.NewRequest("POST", "/api/default-rules/bulk", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]int
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["changed"] != 2 {
			t.Errorf("expected changed=2, got %d", resp["changed"])
		}
	})

	t.Run("reset", func(t *testing.T) {
		body := `{"ids":["9100030","9100033"],"action":"reset"}`
		req := httptest.NewRequest("POST", "/api/default-rules/bulk", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]int
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["removed"] != 2 {
			t.Errorf("expected removed=2, got %d", resp["removed"])
		}
	})

	t.Run("empty_ids", func(t *testing.T) {
		body := `{"ids":[],"action":"override","override":{"enabled":false}}`
		req := httptest.NewRequest("POST", "/api/default-rules/bulk", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("invalid_action", func(t *testing.T) {
		body := `{"ids":["9100030"],"action":"delete"}`
		req := httptest.NewRequest("POST", "/api/default-rules/bulk", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("override_without_body", func(t *testing.T) {
		body := `{"ids":["9100030"],"action":"override"}`
		req := httptest.NewRequest("POST", "/api/default-rules/bulk", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})
}

// ─── CRS Build Output Validation ────────────────────────────────────

// TestCRSBuildOutputValid validates that the committed/generated default-rules.json
// is structurally correct and contains a reasonable number of CRS rules.
// This catches converter regressions and malformed build output.
func TestCRSBuildOutputValid(t *testing.T) {
	// Try the production baked-in path first, then fall back to the repo path.
	paths := []string{
		"/etc/caddy/waf/default-rules.json",
		filepath.Join("..", "waf", "default-rules.json"),
	}
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			t.Logf("loaded default-rules.json from %s (%d bytes)", p, len(data))
			break
		}
	}
	if data == nil {
		t.Skip("default-rules.json not found (expected in Docker image or repo root)")
	}

	// Parse the top-level structure.
	var raw struct {
		DefaultRules []json.RawMessage `json:"default_rules"`
		Version      int               `json:"version"`
		CRSVersion   string            `json:"crs_version"`
		Generated    string            `json:"generated"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse default-rules.json: %v", err)
	}

	// Version must be >= 7 (current format).
	if raw.Version < 7 {
		t.Errorf("version = %d, want >= 7", raw.Version)
	}

	// CRS version must be non-empty.
	if raw.CRSVersion == "" {
		t.Error("crs_version is empty")
	}

	// Must have at least 200 rules (CRS 4.x has 254).
	if len(raw.DefaultRules) < 200 {
		t.Errorf("only %d rules, expected >= 200", len(raw.DefaultRules))
	}

	// Spot-check: parse a few rules and verify required fields.
	type ruleCheck struct {
		ID            string `json:"id"`
		Type          string `json:"type"`
		ParanoiaLevel int    `json:"paranoia_level"`
		Enabled       bool   `json:"enabled"`
	}
	plCounts := map[int]int{}
	typeCounts := map[string]int{}
	for i, raw := range raw.DefaultRules {
		var r ruleCheck
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Errorf("rule[%d]: failed to parse: %v", i, err)
			continue
		}
		if r.ID == "" {
			t.Errorf("rule[%d]: empty ID", i)
		}
		// Custom rules (block/allow from custom-rules.json) don't have PL.
		// CRS detect rules must have PL 1-4.
		if r.Type == "detect" && (r.ParanoiaLevel < 1 || r.ParanoiaLevel > 4) {
			t.Errorf("rule[%d] (%s): detect rule has paranoia_level = %d, want 1-4", i, r.ID, r.ParanoiaLevel)
		}
		plCounts[r.ParanoiaLevel]++
		typeCounts[r.Type]++
	}

	t.Logf("CRS %s: %d rules (PL1=%d, PL2=%d, PL3=%d, PL4=%d)",
		raw.CRSVersion, len(raw.DefaultRules),
		plCounts[1], plCounts[2], plCounts[3], plCounts[4])

	// PL1 should have the most rules.
	if plCounts[1] < 100 {
		t.Errorf("PL1 has only %d rules, expected >= 100", plCounts[1])
	}
}
