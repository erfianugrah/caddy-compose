package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// --- CRS Catalog endpoint tests ---

func TestCRSRulesEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/crs/rules", handleCRSRules)

	req := httptest.NewRequest("GET", "/api/crs/rules", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var catalog CRSCatalogResponse
	if err := json.NewDecoder(rec.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total == 0 {
		t.Error("expected non-zero total rules")
	}
	if len(catalog.Categories) == 0 {
		t.Error("expected non-empty categories")
	}
	if len(catalog.Rules) != catalog.Total {
		t.Errorf("rules length %d != total %d", len(catalog.Rules), catalog.Total)
	}
}

// --- LookupCRSRule tests ---

func TestLookupCRSRule_CustomFallback(t *testing.T) {
	// With no DefaultRuleStore loaded, LookupCRSRule should still find
	// rules from the static customRulesFallback.
	r, ok := LookupCRSRule("9100032")
	if !ok {
		t.Fatal("expected to find custom rule 9100032 from fallback")
	}
	if r.Category != "bot-detection" {
		t.Errorf("expected category bot-detection, got %s", r.Category)
	}
	if r.Description == "" {
		t.Error("expected non-empty description")
	}
}

func TestLookupCRSRule_NotFound(t *testing.T) {
	_, ok := LookupCRSRule("999999")
	if ok {
		t.Error("expected not to find non-existent rule")
	}
}

// --- Dynamic catalog from DefaultRuleStore ---

// newTestDefaultRuleStore creates a DefaultRuleStore from a temporary
// default-rules.json file for testing.
func newTestDefaultRuleStore(t *testing.T, rules []PolicyRule) *DefaultRuleStore {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "default-rules.json")
	f := DefaultRulesFile{
		Version:      7,
		CRSVersion:   "4.24.1-test",
		DefaultRules: rules,
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return NewDefaultRuleStore(path, "")
}

func TestCRSCatalog_DynamicFromStore(t *testing.T) {
	ds := newTestDefaultRuleStore(t, []PolicyRule{
		{
			ID:            "920100",
			Name:          "Invalid HTTP Request Line",
			Type:          "detect",
			Severity:      "WARNING",
			ParanoiaLevel: 1,
			Tags:          []string{"attack-protocol"},
			Enabled:       true,
			Priority:      400,
			Description:   "Invalid HTTP Request Line",
			Category:      "REQUEST-920-PROTOCOL-ENFORCEMENT",
			CRSFile:       "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
		},
		{
			ID:            "942100",
			Name:          "SQL injection via libinjection",
			Type:          "detect",
			Severity:      "CRITICAL",
			ParanoiaLevel: 1,
			Tags:          []string{"attack-sqli"},
			Enabled:       true,
			Priority:      400,
			Description:   "SQL injection attack detected via libinjection",
			Category:      "REQUEST-942-APPLICATION-ATTACK-SQLI",
			CRSFile:       "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
		},
	})

	cat := NewCRSCatalog(ds)

	t.Run("Lookup from store", func(t *testing.T) {
		r, ok := cat.Lookup("920100")
		if !ok {
			t.Fatal("expected to find rule 920100")
		}
		if r.Description != "Invalid HTTP Request Line" {
			t.Errorf("expected description from store, got %q", r.Description)
		}
		if r.Category != "protocol-enforcement" {
			t.Errorf("expected normalized category, got %q", r.Category)
		}
		if r.Severity != "WARNING" {
			t.Errorf("expected severity WARNING, got %q", r.Severity)
		}
		if r.ParanoiaLvl != 1 {
			t.Errorf("expected paranoia level 1, got %d", r.ParanoiaLvl)
		}
	})

	t.Run("Lookup SQLi rule", func(t *testing.T) {
		r, ok := cat.Lookup("942100")
		if !ok {
			t.Fatal("expected to find rule 942100")
		}
		if r.Category != "sqli" {
			t.Errorf("expected normalized category sqli, got %q", r.Category)
		}
	})

	t.Run("Lookup falls back to custom", func(t *testing.T) {
		// Rule not in store, should fall back to customRulesFallback.
		r, ok := cat.Lookup("9100032")
		if !ok {
			t.Fatal("expected to find custom rule 9100032 via fallback")
		}
		if r.Category != "bot-detection" {
			t.Errorf("expected category bot-detection, got %q", r.Category)
		}
	})

	t.Run("GetCatalog includes store rules", func(t *testing.T) {
		resp := cat.GetCatalog()
		if resp.Total < 2 {
			t.Errorf("expected at least 2 rules from store, got %d", resp.Total)
		}

		// Store rules should be present.
		found920100 := false
		found942100 := false
		for _, r := range resp.Rules {
			if r.ID == "920100" {
				found920100 = true
			}
			if r.ID == "942100" {
				found942100 = true
			}
		}
		if !found920100 {
			t.Error("expected rule 920100 in catalog")
		}
		if !found942100 {
			t.Error("expected rule 942100 in catalog")
		}
	})

	t.Run("GetCatalog includes custom fallback rules", func(t *testing.T) {
		resp := cat.GetCatalog()
		// Custom rules not in the store should appear via fallback.
		foundCustom := false
		for _, r := range resp.Rules {
			if r.ID == "9100032" {
				foundCustom = true
				break
			}
		}
		if !foundCustom {
			t.Error("expected custom rule 9100032 in catalog via fallback")
		}
	})

	t.Run("GetCatalog has bot-detection category", func(t *testing.T) {
		resp := cat.GetCatalog()
		found := false
		for _, c := range resp.Categories {
			if c.ID == "bot-detection" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected bot-detection category in catalog")
		}
	})

	t.Run("GetCatalog deep copy", func(t *testing.T) {
		resp := cat.GetCatalog()
		if len(resp.Rules) == 0 || len(resp.Rules[0].Tags) == 0 {
			t.Skip("no rules with tags to test deep copy")
		}
		original := resp.Rules[0].Tags[0]
		resp.Rules[0].Tags[0] = "MUTATED"

		resp2 := cat.GetCatalog()
		if resp2.Rules[0].Tags[0] != original {
			t.Errorf("deep copy failed: store data was mutated")
		}
	})
}

func TestCRSCatalog_NilStore(t *testing.T) {
	cat := NewCRSCatalog(nil)

	t.Run("Lookup returns custom fallback only", func(t *testing.T) {
		_, ok := cat.Lookup("920100")
		if ok {
			t.Error("expected not to find CRS rule with nil store")
		}
		_, ok = cat.Lookup("9100032")
		if !ok {
			t.Error("expected to find custom rule from fallback with nil store")
		}
	})

	t.Run("GetCatalog returns custom fallback only", func(t *testing.T) {
		resp := cat.GetCatalog()
		if resp.Total != len(customRulesFallback) {
			t.Errorf("expected %d custom fallback rules, got %d", len(customRulesFallback), resp.Total)
		}
	})
}

func TestCategoryFromCRSFile(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"REQUEST-920-PROTOCOL-ENFORCEMENT", "protocol-enforcement"},
		{"REQUEST-942-APPLICATION-ATTACK-SQLI", "sqli"},
		{"REQUEST-941-APPLICATION-ATTACK-XSS", "xss"},
		{"REQUEST-932-APPLICATION-ATTACK-RCE", "rce"},
		{"REQUEST-913-SCANNER-DETECTION", "scanner-detection"},
		{"REQUEST-922-MULTIPART-ATTACK", "multipart-attack"},
		{"UNKNOWN-CATEGORY", "UNKNOWN-CATEGORY"}, // unmapped, returned as-is
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeCRSCategory(tc.input)
			if got != tc.want {
				t.Errorf("normalizeCRSCategory(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestCustomRuleFallbackIndex_NoDuplicates(t *testing.T) {
	if len(customRuleFallbackIndex) != len(customRulesFallback) {
		t.Errorf("expected %d entries in fallback index, got %d (duplicates?)",
			len(customRulesFallback), len(customRuleFallbackIndex))
	}
}

func TestCustomRules_AllHaveRequiredFields(t *testing.T) {
	for _, r := range customRulesFallback {
		if r.ID == "" {
			t.Error("custom rule has empty ID")
		}
		if r.Description == "" {
			t.Errorf("custom rule %s has empty description", r.ID)
		}
		if r.Category == "" {
			t.Errorf("custom rule %s has empty category", r.ID)
		}
		if r.Severity == "" {
			t.Errorf("custom rule %s has empty severity", r.ID)
		}
		if len(r.Tags) == 0 {
			t.Errorf("custom rule %s has no tags", r.ID)
		}
	}
}
