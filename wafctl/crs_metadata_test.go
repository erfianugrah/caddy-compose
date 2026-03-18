package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCRSMetadata_FromFile(t *testing.T) {
	meta := &CRSMetadata{
		CRSVersion:  "4.24.1",
		GeneratedAt: "2026-03-18T09:00:00Z",
		Categories: []CRSMetadataCategory{
			{ID: "sqli", Name: "SQL Injection", Prefix: "942", RuleRange: "942000-942999", Tag: "attack-sqli", Phase: "inbound", RuleCount: 50},
			{ID: "xss", Name: "Cross-Site Scripting", Prefix: "941", RuleRange: "941000-941999", Tag: "attack-xss", Phase: "inbound", RuleCount: 30},
		},
		CategoryMap: map[string]string{
			"REQUEST-942-APPLICATION-ATTACK-SQLI": "sqli",
			"REQUEST-941-APPLICATION-ATTACK-XSS":  "xss",
		},
		ValidPrefixes:   []string{"941", "942"},
		SeverityLevels:  map[string]int{"CRITICAL": 2, "ERROR": 3, "WARNING": 4, "NOTICE": 5},
		CustomRuleRange: "9100",
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "crs-metadata.json")
	data, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(path, data, 0644)

	loaded, err := LoadCRSMetadata(path)
	if err != nil {
		t.Fatalf("LoadCRSMetadata: %v", err)
	}

	if loaded.CRSVersion != "4.24.1" {
		t.Errorf("CRSVersion = %q, want 4.24.1", loaded.CRSVersion)
	}
	if len(loaded.Categories) != 2 {
		t.Errorf("categories = %d, want 2", len(loaded.Categories))
	}
	if loaded.NormalizeCategory("REQUEST-942-APPLICATION-ATTACK-SQLI") != "sqli" {
		t.Error("NormalizeCategory failed for 942")
	}
	if !loaded.IsValidPrefix("942") {
		t.Error("IsValidPrefix(942) should be true")
	}
	if loaded.IsValidPrefix("999") {
		t.Error("IsValidPrefix(999) should be false")
	}
	if loaded.SeverityToNumeric("CRITICAL") != 2 {
		t.Errorf("SeverityToNumeric(CRITICAL) = %d, want 2", loaded.SeverityToNumeric("CRITICAL"))
	}
}

func TestLoadCRSMetadata_Missing(t *testing.T) {
	_, err := LoadCRSMetadata("/nonexistent/crs-metadata.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestGetCRSMetadata_LoadedFromFixture(t *testing.T) {
	meta := GetCRSMetadata()

	// TestMain loads testdata/crs-metadata.json — verify it took effect
	if meta.CRSVersion != "4.24.1" {
		t.Errorf("CRSVersion = %q, want 4.24.1 (loaded from fixture)", meta.CRSVersion)
	}

	// Should have categories
	if len(meta.Categories) == 0 {
		t.Fatal("fixture should have categories")
	}

	// Should normalize known categories
	if meta.NormalizeCategory("REQUEST-942-APPLICATION-ATTACK-SQLI") != "sqli" {
		t.Error("NormalizeCategory failed for sqli")
	}

	// Should validate known prefixes
	if !meta.IsValidPrefix("920") {
		t.Error("IsValidPrefix(920) should be true")
	}
	if meta.IsValidPrefix("999") {
		t.Error("IsValidPrefix(999) should be false")
	}

	// Should have severity levels
	if meta.SeverityToNumeric("CRITICAL") != 2 {
		t.Errorf("CRITICAL = %d, want 2", meta.SeverityToNumeric("CRITICAL"))
	}
	if meta.SeverityToNumeric("UNKNOWN") != 0 {
		t.Errorf("UNKNOWN = %d, want 0", meta.SeverityToNumeric("UNKNOWN"))
	}
}

func TestNormalizeCRSCategory_Dynamic(t *testing.T) {
	// Uses metadata loaded from testdata/crs-metadata.json by TestMain.
	tests := []struct {
		input string
		want  string
	}{
		{"REQUEST-920-PROTOCOL-ENFORCEMENT", "protocol-enforcement"},
		{"REQUEST-942-APPLICATION-ATTACK-SQLI", "sqli"},
		{"REQUEST-934-APPLICATION-ATTACK-GENERIC", "generic-attack"},
		{"RESPONSE-950-DATA-LEAKAGES", "data-leakage"},
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

func TestCRSMetadataCategories_FromFixture(t *testing.T) {
	cats := crsMetadataCategories()
	if len(cats) == 0 {
		t.Fatal("expected non-empty categories from fixture")
	}
	// Verify a known category is present
	found := false
	for _, c := range cats {
		if c.ID == "sqli" {
			found = true
			if c.Name != "SQL Injection" {
				t.Errorf("sqli name = %q, want SQL Injection", c.Name)
			}
			break
		}
	}
	if !found {
		t.Error("expected sqli category in fallback metadata")
	}
}
