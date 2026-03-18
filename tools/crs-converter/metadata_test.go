package main

import (
	"testing"
)

func TestBuildMetadata_BasicStructure(t *testing.T) {
	rules := []PolicyRule{
		{ID: "920100", Category: "REQUEST-920-PROTOCOL-ENFORCEMENT", Severity: "WARNING"},
		{ID: "920200", Category: "REQUEST-920-PROTOCOL-ENFORCEMENT", Severity: "NOTICE"},
		{ID: "942100", Category: "REQUEST-942-APPLICATION-ATTACK-SQLI", Severity: "CRITICAL"},
		{ID: "942200", Category: "REQUEST-942-APPLICATION-ATTACK-SQLI", Severity: "CRITICAL"},
		{ID: "942300", Category: "REQUEST-942-APPLICATION-ATTACK-SQLI", Severity: "ERROR"},
		{ID: "950001", Category: "RESPONSE-950-DATA-LEAKAGES", Severity: "WARNING"},
	}

	meta := BuildMetadata(rules, "4.24.1")

	if meta.CRSVersion != "4.24.1" {
		t.Errorf("CRSVersion = %q, want 4.24.1", meta.CRSVersion)
	}
	if meta.GeneratedAt == "" {
		t.Error("GeneratedAt should be non-empty")
	}
	if len(meta.Categories) != 3 {
		t.Fatalf("expected 3 categories, got %d", len(meta.Categories))
	}

	// Verify categories are sorted by prefix
	if meta.Categories[0].Prefix != "920" {
		t.Errorf("first category prefix = %q, want 920", meta.Categories[0].Prefix)
	}
	if meta.Categories[1].Prefix != "942" {
		t.Errorf("second category prefix = %q, want 942", meta.Categories[1].Prefix)
	}
	if meta.Categories[2].Prefix != "950" {
		t.Errorf("third category prefix = %q, want 950", meta.Categories[2].Prefix)
	}

	// Verify category map
	if meta.CategoryMap["REQUEST-920-PROTOCOL-ENFORCEMENT"] != "protocol-enforcement" {
		t.Errorf("category map for 920 = %q, want protocol-enforcement",
			meta.CategoryMap["REQUEST-920-PROTOCOL-ENFORCEMENT"])
	}
	if meta.CategoryMap["REQUEST-942-APPLICATION-ATTACK-SQLI"] != "sqli" {
		t.Errorf("category map for 942 = %q, want sqli",
			meta.CategoryMap["REQUEST-942-APPLICATION-ATTACK-SQLI"])
	}
	if meta.CategoryMap["RESPONSE-950-DATA-LEAKAGES"] != "data-leakage" {
		t.Errorf("category map for 950 = %q, want data-leakage",
			meta.CategoryMap["RESPONSE-950-DATA-LEAKAGES"])
	}
}

func TestBuildMetadata_RuleCounts(t *testing.T) {
	rules := []PolicyRule{
		{ID: "920100", Category: "REQUEST-920-PROTOCOL-ENFORCEMENT"},
		{ID: "920200", Category: "REQUEST-920-PROTOCOL-ENFORCEMENT"},
		{ID: "920300", Category: "REQUEST-920-PROTOCOL-ENFORCEMENT"},
		{ID: "942100", Category: "REQUEST-942-APPLICATION-ATTACK-SQLI"},
	}

	meta := BuildMetadata(rules, "4.24.1")

	// Find protocol-enforcement category
	var protEnf CRSMetadataCategory
	for _, c := range meta.Categories {
		if c.ID == "protocol-enforcement" {
			protEnf = c
			break
		}
	}
	if protEnf.RuleCount != 3 {
		t.Errorf("protocol-enforcement rule_count = %d, want 3", protEnf.RuleCount)
	}
}

func TestBuildMetadata_ValidPrefixes(t *testing.T) {
	rules := []PolicyRule{
		{ID: "920100", Category: "REQUEST-920-PROTOCOL-ENFORCEMENT"},
		{ID: "942100", Category: "REQUEST-942-APPLICATION-ATTACK-SQLI"},
		{ID: "9100032", Category: "bot-detection"},
	}

	meta := BuildMetadata(rules, "4.24.1")

	prefixSet := make(map[string]bool)
	for _, p := range meta.ValidPrefixes {
		prefixSet[p] = true
	}

	if !prefixSet["920"] {
		t.Error("missing prefix 920")
	}
	if !prefixSet["942"] {
		t.Error("missing prefix 942")
	}
	if !prefixSet["9100"] {
		t.Error("missing prefix 9100 for custom rules")
	}
}

func TestBuildMetadata_SeverityLevels(t *testing.T) {
	meta := BuildMetadata(nil, "4.24.1")

	expected := map[string]int{
		"CRITICAL": 2,
		"ERROR":    3,
		"WARNING":  4,
		"NOTICE":   5,
	}
	for name, want := range expected {
		if got, ok := meta.SeverityLevels[name]; !ok || got != want {
			t.Errorf("SeverityLevels[%q] = %d, want %d", name, got, want)
		}
	}
}

func TestBuildMetadata_PhaseDetection(t *testing.T) {
	rules := []PolicyRule{
		{ID: "920100", Category: "REQUEST-920-PROTOCOL-ENFORCEMENT"},
		{ID: "950001", Category: "RESPONSE-950-DATA-LEAKAGES"},
	}

	meta := BuildMetadata(rules, "4.24.1")

	for _, c := range meta.Categories {
		switch c.ID {
		case "protocol-enforcement":
			if c.Phase != "inbound" {
				t.Errorf("protocol-enforcement phase = %q, want inbound", c.Phase)
			}
		case "data-leakage":
			if c.Phase != "outbound" {
				t.Errorf("data-leakage phase = %q, want outbound", c.Phase)
			}
		}
	}
}

func TestBuildMetadata_CategoryDetails(t *testing.T) {
	rules := []PolicyRule{
		{ID: "941100", Category: "REQUEST-941-APPLICATION-ATTACK-XSS"},
	}

	meta := BuildMetadata(rules, "4.24.1")

	if len(meta.Categories) != 1 {
		t.Fatalf("expected 1 category, got %d", len(meta.Categories))
	}
	c := meta.Categories[0]
	if c.ID != "xss" {
		t.Errorf("ID = %q, want xss", c.ID)
	}
	if c.Name != "Cross-Site Scripting" {
		t.Errorf("Name = %q, want Cross-Site Scripting", c.Name)
	}
	if c.Tag != "attack-xss" {
		t.Errorf("Tag = %q, want attack-xss", c.Tag)
	}
	if c.RuleRange != "941000-941999" {
		t.Errorf("RuleRange = %q, want 941000-941999", c.RuleRange)
	}
}

func TestBuildMetadata_UnknownCategory(t *testing.T) {
	rules := []PolicyRule{
		{ID: "960100", Category: "REQUEST-960-NEW-FUTURE-CATEGORY"},
	}

	meta := BuildMetadata(rules, "5.0.0")

	if len(meta.Categories) != 1 {
		t.Fatalf("expected 1 category, got %d", len(meta.Categories))
	}
	c := meta.Categories[0]
	// Should auto-generate an ID from the category string
	if c.ID == "" {
		t.Error("auto-generated ID should not be empty")
	}
	if c.Prefix != "960" {
		t.Errorf("Prefix = %q, want 960", c.Prefix)
	}
	// Category map should still map the full name
	if _, ok := meta.CategoryMap["REQUEST-960-NEW-FUTURE-CATEGORY"]; !ok {
		t.Error("category map should contain the unknown category")
	}
}

func TestBuildMetadata_CustomRuleRange(t *testing.T) {
	meta := BuildMetadata(nil, "4.24.1")
	if meta.CustomRuleRange != "9100" {
		t.Errorf("CustomRuleRange = %q, want 9100", meta.CustomRuleRange)
	}
}

func TestBuildMetadata_AllKnownCategories(t *testing.T) {
	// Verify every entry in categoryNameMap produces valid metadata
	for cat, info := range categoryNameMap {
		rules := []PolicyRule{{ID: "000001", Category: cat}}
		meta := BuildMetadata(rules, "test")

		if len(meta.Categories) != 1 {
			t.Errorf("%s: expected 1 category, got %d", cat, len(meta.Categories))
			continue
		}
		c := meta.Categories[0]
		if c.ID != info.ID {
			t.Errorf("%s: ID = %q, want %q", cat, c.ID, info.ID)
		}
		if c.Name != info.Name {
			t.Errorf("%s: Name = %q, want %q", cat, c.Name, info.Name)
		}
		if meta.CategoryMap[cat] != info.ID {
			t.Errorf("%s: CategoryMap = %q, want %q", cat, meta.CategoryMap[cat], info.ID)
		}
	}
}
