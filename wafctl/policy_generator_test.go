package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// ─── IsPolicyEngineType ──────────────────────────────────────────────

func TestIsPolicyEngineType(t *testing.T) {
	tests := []struct {
		typ  string
		want bool
	}{
		{"allow", true},
		{"block", true},
		{"honeypot", true},
		{"skip_rule", false},
		{"anomaly", false},
		{"raw", false},
		{"runtime_remove_by_id", false},
		{"runtime_remove_by_tag", false},
		{"runtime_remove_target_by_id", false},
		{"runtime_remove_target_by_tag", false},
		{"remove_by_id", false},
		{"remove_by_tag", false},
		{"update_target_by_id", false},
		{"update_target_by_tag", false},
		{"", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			got := IsPolicyEngineType(tt.typ)
			if got != tt.want {
				t.Errorf("IsPolicyEngineType(%q) = %v, want %v", tt.typ, got, tt.want)
			}
		})
	}
}

// ─── FilterSecRuleExclusions ─────────────────────────────────────────

func TestFilterSecRuleExclusions(t *testing.T) {
	allExclusions := []RuleExclusion{
		{ID: "1", Name: "Allow all from office", Type: "allow"},
		{ID: "2", Name: "Block bad IPs", Type: "block"},
		{ID: "3", Name: "Honeypot /admin", Type: "honeypot"},
		{ID: "4", Name: "Skip SQL injection", Type: "skip_rule"},
		{ID: "5", Name: "Anomaly boost", Type: "anomaly"},
		{ID: "6", Name: "Raw rule", Type: "raw"},
		{ID: "7", Name: "Remove rule 942100", Type: "remove_by_id"},
		{ID: "8", Name: "Runtime remove by tag", Type: "runtime_remove_by_tag"},
	}

	t.Run("disabled returns all", func(t *testing.T) {
		result := FilterSecRuleExclusions(allExclusions, false)
		if len(result) != len(allExclusions) {
			t.Errorf("expected %d exclusions, got %d", len(allExclusions), len(result))
		}
	})

	t.Run("enabled filters out allow/block/honeypot", func(t *testing.T) {
		result := FilterSecRuleExclusions(allExclusions, true)
		// Should have: skip_rule, anomaly, raw, remove_by_id, runtime_remove_by_tag = 5
		if len(result) != 5 {
			t.Errorf("expected 5 exclusions, got %d", len(result))
			for _, e := range result {
				t.Logf("  kept: %s (%s)", e.Name, e.Type)
			}
		}
		for _, e := range result {
			if IsPolicyEngineType(e.Type) {
				t.Errorf("should not contain policy engine type %q (exclusion %q)", e.Type, e.Name)
			}
		}
	})

	t.Run("enabled with no policy types returns all", func(t *testing.T) {
		secRuleOnly := []RuleExclusion{
			{ID: "1", Type: "skip_rule"},
			{ID: "2", Type: "anomaly"},
			{ID: "3", Type: "raw"},
		}
		result := FilterSecRuleExclusions(secRuleOnly, true)
		if len(result) != 3 {
			t.Errorf("expected 3 exclusions, got %d", len(result))
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		result := FilterSecRuleExclusions(nil, true)
		if len(result) != 0 {
			t.Errorf("expected 0 exclusions, got %d", len(result))
		}
	})
}

// ─── GeneratePolicyRules ─────────────────────────────────────────────

func TestGeneratePolicyRules(t *testing.T) {
	t.Run("empty exclusions", func(t *testing.T) {
		data, err := GeneratePolicyRules(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		if file.Version != 1 {
			t.Errorf("version = %d, want 1", file.Version)
		}
		if len(file.Rules) != 0 {
			t.Errorf("expected 0 rules, got %d", len(file.Rules))
		}
		if file.Generated == "" {
			t.Error("expected non-empty Generated timestamp")
		}
	})

	t.Run("filters non-policy types", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "1", Name: "Allow", Type: "allow", Enabled: true},
			{ID: "2", Name: "Skip", Type: "skip_rule", Enabled: true},
			{ID: "3", Name: "Block", Type: "block", Enabled: true},
			{ID: "4", Name: "Anomaly", Type: "anomaly", Enabled: true},
			{ID: "5", Name: "Honeypot", Type: "honeypot", Enabled: true},
			{ID: "6", Name: "Raw", Type: "raw", Enabled: true},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		// Only allow, block, honeypot should be included.
		if len(file.Rules) != 3 {
			t.Fatalf("expected 3 rules, got %d", len(file.Rules))
		}
		types := map[string]bool{}
		for _, r := range file.Rules {
			types[r.Type] = true
		}
		for _, want := range []string{"allow", "block", "honeypot"} {
			if !types[want] {
				t.Errorf("missing type %q in output", want)
			}
		}
	})

	t.Run("priority ordering: honeypot < block < allow", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "a1", Name: "Allow Office", Type: "allow", Enabled: true},
			{ID: "b1", Name: "Block Scanners", Type: "block", Enabled: true},
			{ID: "h1", Name: "Honeypot Admin", Type: "honeypot", Enabled: true},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		if len(file.Rules) != 3 {
			t.Fatalf("expected 3 rules, got %d", len(file.Rules))
		}
		// Order should be: honeypot (100+), block (200+), allow (300+)
		if file.Rules[0].Type != "honeypot" {
			t.Errorf("rules[0].Type = %q, want honeypot", file.Rules[0].Type)
		}
		if file.Rules[1].Type != "block" {
			t.Errorf("rules[1].Type = %q, want block", file.Rules[1].Type)
		}
		if file.Rules[2].Type != "allow" {
			t.Errorf("rules[2].Type = %q, want allow", file.Rules[2].Type)
		}
		// Verify priority values.
		if file.Rules[0].Priority < 100 || file.Rules[0].Priority >= 200 {
			t.Errorf("honeypot priority = %d, want [100,200)", file.Rules[0].Priority)
		}
		if file.Rules[1].Priority < 200 || file.Rules[1].Priority >= 300 {
			t.Errorf("block priority = %d, want [200,300)", file.Rules[1].Priority)
		}
		if file.Rules[2].Priority < 300 || file.Rules[2].Priority >= 400 {
			t.Errorf("allow priority = %d, want [300,400)", file.Rules[2].Priority)
		}
	})

	t.Run("tiebreaker within same type uses store order", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "b1", Name: "Block First", Type: "block", Enabled: true},
			{ID: "b2", Name: "Block Second", Type: "block", Enabled: true},
			{ID: "b3", Name: "Block Third", Type: "block", Enabled: true},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		// Within block type, should preserve store order via tiebreaker.
		if file.Rules[0].ID != "b1" || file.Rules[1].ID != "b2" || file.Rules[2].ID != "b3" {
			t.Errorf("expected b1,b2,b3 order, got %s,%s,%s",
				file.Rules[0].ID, file.Rules[1].ID, file.Rules[2].ID)
		}
		// Priorities should be 200, 201, 202.
		if file.Rules[0].Priority != 200 {
			t.Errorf("b1 priority = %d, want 200", file.Rules[0].Priority)
		}
		if file.Rules[1].Priority != 201 {
			t.Errorf("b2 priority = %d, want 201", file.Rules[1].Priority)
		}
		if file.Rules[2].Priority != 202 {
			t.Errorf("b3 priority = %d, want 202", file.Rules[2].Priority)
		}
	})

	t.Run("tiebreaker caps at 99", func(t *testing.T) {
		// Create 101 block rules to verify cap.
		var exclusions []RuleExclusion
		for i := 0; i < 101; i++ {
			exclusions = append(exclusions, RuleExclusion{
				ID:   "b" + time.Now().Format("150405") + fmt.Sprintf("%03d", i),
				Type: "block", Enabled: true, Name: "Block",
			})
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		// The last two rules (index 99 and 100) should both have priority 299
		// (200 + capped 99).
		last := file.Rules[len(file.Rules)-1]
		secondLast := file.Rules[len(file.Rules)-2]
		if last.Priority != 299 {
			t.Errorf("last rule priority = %d, want 299", last.Priority)
		}
		if secondLast.Priority != 299 {
			t.Errorf("second-to-last rule priority = %d, want 299", secondLast.Priority)
		}
	})

	t.Run("conditions are copied", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{
				ID: "1", Name: "Block path", Type: "block", Enabled: true,
				Conditions: []Condition{
					{Field: "path", Operator: "eq", Value: "/admin"},
					{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
				},
				GroupOp: "and",
			},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		if len(file.Rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(file.Rules))
		}
		r := file.Rules[0]
		if len(r.Conditions) != 2 {
			t.Fatalf("expected 2 conditions, got %d", len(r.Conditions))
		}
		if r.Conditions[0].Field != "path" || r.Conditions[0].Operator != "eq" || r.Conditions[0].Value != "/admin" {
			t.Errorf("condition 0 = %+v, want path/eq//admin", r.Conditions[0])
		}
		if r.Conditions[1].Field != "ip" || r.Conditions[1].Operator != "ip_match" || r.Conditions[1].Value != "10.0.0.0/8" {
			t.Errorf("condition 1 = %+v, want ip/ip_match/10.0.0.0/8", r.Conditions[1])
		}
		if r.GroupOp != "and" {
			t.Errorf("group_op = %q, want and", r.GroupOp)
		}
	})

	t.Run("empty group_op defaults to and", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "1", Name: "Test", Type: "allow", Enabled: true, GroupOp: ""},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		if file.Rules[0].GroupOp != "and" {
			t.Errorf("group_op = %q, want and", file.Rules[0].GroupOp)
		}
	})

	t.Run("or group_op preserved", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "1", Name: "Test", Type: "block", Enabled: true, GroupOp: "or"},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		if file.Rules[0].GroupOp != "or" {
			t.Errorf("group_op = %q, want or", file.Rules[0].GroupOp)
		}
	})

	t.Run("disabled rules are included with enabled=false", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "1", Name: "Disabled Block", Type: "block", Enabled: false},
			{ID: "2", Name: "Enabled Block", Type: "block", Enabled: true},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		if len(file.Rules) != 2 {
			t.Fatalf("expected 2 rules, got %d", len(file.Rules))
		}
		// Check that disabled state is preserved.
		foundDisabled := false
		foundEnabled := false
		for _, r := range file.Rules {
			if r.ID == "1" && !r.Enabled {
				foundDisabled = true
			}
			if r.ID == "2" && r.Enabled {
				foundEnabled = true
			}
		}
		if !foundDisabled {
			t.Error("disabled rule not found or not marked disabled")
		}
		if !foundEnabled {
			t.Error("enabled rule not found or not marked enabled")
		}
	})

	t.Run("rule fields are copied", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{
				ID:   "test-123",
				Name: "Block Office Admin",
				Type: "block",
				Conditions: []Condition{
					{Field: "host", Operator: "eq", Value: "office.example.com"},
				},
				GroupOp: "and",
				Enabled: true,
			},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		r := file.Rules[0]
		if r.ID != "test-123" {
			t.Errorf("ID = %q, want test-123", r.ID)
		}
		if r.Name != "Block Office Admin" {
			t.Errorf("Name = %q, want Block Office Admin", r.Name)
		}
		if r.Type != "block" {
			t.Errorf("Type = %q, want block", r.Type)
		}
	})

	t.Run("JSON round-trip stability", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "h1", Name: "Honeypot", Type: "honeypot", Enabled: true,
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/wp-admin"}}},
			{ID: "b1", Name: "Block", Type: "block", Enabled: true,
				Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "192.168.0.0/16"}}},
			{ID: "a1", Name: "Allow", Type: "allow", Enabled: true,
				Conditions: []Condition{{Field: "host", Operator: "eq", Value: "trusted.example.com"}}},
		}
		data1, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Decode and re-encode to verify structure.
		var file1 PolicyRulesFile
		if err := json.Unmarshal(data1, &file1); err != nil {
			t.Fatal(err)
		}
		data2, err := json.MarshalIndent(file1, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		var file2 PolicyRulesFile
		if err := json.Unmarshal(data2, &file2); err != nil {
			t.Fatal(err)
		}
		if len(file1.Rules) != len(file2.Rules) {
			t.Fatalf("round-trip rule count mismatch: %d vs %d", len(file1.Rules), len(file2.Rules))
		}
		for i := range file1.Rules {
			if file1.Rules[i].ID != file2.Rules[i].ID {
				t.Errorf("round-trip ID mismatch at [%d]: %q vs %q", i, file1.Rules[i].ID, file2.Rules[i].ID)
			}
			if file1.Rules[i].Priority != file2.Rules[i].Priority {
				t.Errorf("round-trip Priority mismatch at [%d]: %d vs %d", i, file1.Rules[i].Priority, file2.Rules[i].Priority)
			}
		}
	})

	t.Run("mixed types with conditions", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "a1", Name: "Allow Office", Type: "allow", Enabled: true,
				Conditions: []Condition{
					{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
					{Field: "host", Operator: "eq", Value: "internal.example.com"},
				}, GroupOp: "and"},
			{ID: "b1", Name: "Block Bad UA", Type: "block", Enabled: true,
				Conditions: []Condition{
					{Field: "user_agent", Operator: "contains", Value: "BadBot"},
				}},
			{ID: "h1", Name: "Honeypot Paths", Type: "honeypot", Enabled: true,
				Conditions: []Condition{
					{Field: "path", Operator: "in", Value: "/wp-admin /xmlrpc.php /wp-login.php"},
				}},
			// These should be excluded.
			{ID: "s1", Name: "Skip SQLi", Type: "skip_rule", Enabled: true,
				RuleID: "942100"},
			{ID: "r1", Name: "Custom Rule", Type: "raw", Enabled: true,
				RawRule: "SecRule REQUEST_URI \"@contains test\" \"id:99999,phase:1,deny\""},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		if len(file.Rules) != 3 {
			t.Fatalf("expected 3 rules, got %d", len(file.Rules))
		}
		// Verify ordering: honeypot, block, allow.
		if file.Rules[0].ID != "h1" {
			t.Errorf("first rule ID = %q, want h1", file.Rules[0].ID)
		}
		if file.Rules[1].ID != "b1" {
			t.Errorf("second rule ID = %q, want b1", file.Rules[1].ID)
		}
		if file.Rules[2].ID != "a1" {
			t.Errorf("third rule ID = %q, want a1", file.Rules[2].ID)
		}
		// Verify honeypot conditions.
		hp := file.Rules[0]
		if len(hp.Conditions) != 1 {
			t.Fatalf("honeypot conditions = %d, want 1", len(hp.Conditions))
		}
		if hp.Conditions[0].Operator != "in" {
			t.Errorf("honeypot operator = %q, want in", hp.Conditions[0].Operator)
		}
	})
}

// ─── splitHoneypotPaths ──────────────────────────────────────────────

func TestSplitHoneypotPaths(t *testing.T) {
	tests := []struct {
		name       string
		conditions []Condition
		want       []string
	}{
		{
			name:       "empty conditions",
			conditions: nil,
			want:       nil,
		},
		{
			name: "single eq path",
			conditions: []Condition{
				{Field: "path", Operator: "eq", Value: "/admin"},
			},
			want: []string{"/admin"},
		},
		{
			name: "in operator with multiple paths",
			conditions: []Condition{
				{Field: "path", Operator: "in", Value: "/wp-admin /xmlrpc.php /wp-login.php"},
			},
			want: []string{"/wp-admin", "/xmlrpc.php", "/wp-login.php"},
		},
		{
			name: "non-path fields are ignored",
			conditions: []Condition{
				{Field: "ip", Operator: "eq", Value: "10.0.0.1"},
				{Field: "path", Operator: "eq", Value: "/admin"},
				{Field: "host", Operator: "eq", Value: "example.com"},
			},
			want: []string{"/admin"},
		},
		{
			name: "multiple path conditions",
			conditions: []Condition{
				{Field: "path", Operator: "eq", Value: "/admin"},
				{Field: "path", Operator: "in", Value: "/wp-login.php /xmlrpc.php"},
			},
			want: []string{"/admin", "/wp-login.php", "/xmlrpc.php"},
		},
		{
			name: "empty value is skipped",
			conditions: []Condition{
				{Field: "path", Operator: "eq", Value: ""},
			},
			want: nil,
		},
		{
			name: "in operator with extra spaces",
			conditions: []Condition{
				{Field: "path", Operator: "in", Value: "  /admin   /login  "},
			},
			want: []string{"/admin", "/login"},
		},
		{
			name: "contains operator treated as single value",
			conditions: []Condition{
				{Field: "path", Operator: "contains", Value: "/admin"},
			},
			want: []string{"/admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitHoneypotPaths(tt.conditions)
			if len(got) != len(tt.want) {
				t.Fatalf("splitHoneypotPaths() returned %d paths, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("path[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ─── GeneratePolicyRules: Generated timestamp ────────────────────────

func TestGeneratePolicyRulesTimestamp(t *testing.T) {
	before := time.Now().UTC().Truncate(time.Second)
	data, err := GeneratePolicyRules([]RuleExclusion{
		{ID: "1", Type: "block", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC().Truncate(time.Second).Add(time.Second)

	var file PolicyRulesFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}

	ts, err := time.Parse(time.RFC3339, file.Generated)
	if err != nil {
		t.Fatalf("failed to parse Generated timestamp %q: %v", file.Generated, err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("Generated timestamp %v not between %v and %v", ts, before, after)
	}
}

// ─── GeneratePolicyRules: valid JSON output ──────────────────────────

func TestGeneratePolicyRulesValidJSON(t *testing.T) {
	exclusions := []RuleExclusion{
		{ID: "1", Name: "Test \"quotes\" and \\ backslashes", Type: "block", Enabled: true,
			Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/foo?bar=baz&qux=1"}}},
	}
	data, err := GeneratePolicyRules(exclusions, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Verify it's valid JSON by unmarshaling.
	var file PolicyRulesFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, string(data))
	}
	if file.Rules[0].Name != "Test \"quotes\" and \\ backslashes" {
		t.Errorf("name not preserved through JSON: %q", file.Rules[0].Name)
	}
}

// ─── GeneratePolicyRules: managed list resolution ─────────────────

func TestGeneratePolicyRulesListResolution(t *testing.T) {
	// Create a managed list store with test data.
	ls := NewManagedListStore(filepath.Join(t.TempDir(), "lists.json"), t.TempDir())
	ls.Create(ManagedList{
		Name:   "bad-ips",
		Kind:   "ip",
		Source: "manual",
		Items:  []string{"10.0.0.1", "192.168.1.0/24"},
	})
	ls.Create(ManagedList{
		Name:   "bad-countries",
		Kind:   "string",
		Source: "manual",
		Items:  []string{"CN", "RU", "KP"},
	})

	exclusions := []RuleExclusion{
		{
			ID:      "1",
			Name:    "block-bad-ips",
			Type:    "block",
			Enabled: true,
			Conditions: []Condition{
				{Field: "ip", Operator: "in_list", Value: "bad-ips"},
			},
		},
		{
			ID:      "2",
			Name:    "block-bad-countries",
			Type:    "block",
			Enabled: true,
			Conditions: []Condition{
				{Field: "country", Operator: "in_list", Value: "bad-countries"},
			},
		},
		{
			ID:      "3",
			Name:    "allow-not-in-bad-ips",
			Type:    "allow",
			Enabled: true,
			Conditions: []Condition{
				{Field: "ip", Operator: "not_in_list", Value: "bad-ips"},
			},
		},
	}

	data, err := GeneratePolicyRules(exclusions, ls)
	if err != nil {
		t.Fatal(err)
	}

	var file PolicyRulesFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(file.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(file.Rules))
	}

	// Rules are sorted by priority: block (200) < allow (300).
	// Find each rule by name.
	byName := map[string]PolicyRule{}
	for _, r := range file.Rules {
		byName[r.Name] = r
	}

	t.Run("IP list resolved", func(t *testing.T) {
		r := byName["block-bad-ips"]
		if len(r.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(r.Conditions))
		}
		c := r.Conditions[0]
		if c.Operator != "in_list" {
			t.Errorf("expected operator=in_list, got %q", c.Operator)
		}
		if c.ListKind != "ip" {
			t.Errorf("expected list_kind=ip, got %q", c.ListKind)
		}
		if len(c.ListItems) != 2 {
			t.Errorf("expected 2 list_items, got %d", len(c.ListItems))
		}
	})

	t.Run("string list resolved", func(t *testing.T) {
		r := byName["block-bad-countries"]
		c := r.Conditions[0]
		if c.ListKind != "string" {
			t.Errorf("expected list_kind=string, got %q", c.ListKind)
		}
		if len(c.ListItems) != 3 {
			t.Errorf("expected 3 list_items, got %d", len(c.ListItems))
		}
	})

	t.Run("not_in_list resolved", func(t *testing.T) {
		r := byName["allow-not-in-bad-ips"]
		c := r.Conditions[0]
		if c.Operator != "not_in_list" {
			t.Errorf("expected operator=not_in_list, got %q", c.Operator)
		}
		if c.ListKind != "ip" {
			t.Errorf("expected list_kind=ip, got %q", c.ListKind)
		}
		if len(c.ListItems) != 2 {
			t.Errorf("expected 2 list_items, got %d", len(c.ListItems))
		}
	})
}

func TestGeneratePolicyRulesListNotFound(t *testing.T) {
	// When a list is not found, condition gets empty ListItems (no match).
	ls := NewManagedListStore(filepath.Join(t.TempDir(), "lists.json"), t.TempDir())

	exclusions := []RuleExclusion{
		{
			ID:      "1",
			Name:    "block-missing-list",
			Type:    "block",
			Enabled: true,
			Conditions: []Condition{
				{Field: "ip", Operator: "in_list", Value: "nonexistent-list"},
			},
		},
	}

	data, err := GeneratePolicyRules(exclusions, ls)
	if err != nil {
		t.Fatal(err)
	}

	var file PolicyRulesFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	c := file.Rules[0].Conditions[0]
	if len(c.ListItems) != 0 {
		t.Errorf("expected empty list_items for missing list, got %d", len(c.ListItems))
	}
	if c.ListKind != "" {
		t.Errorf("expected empty list_kind for missing list, got %q", c.ListKind)
	}
}

func TestGeneratePolicyRulesNilListStore(t *testing.T) {
	// When listStore is nil, in_list conditions pass through unresolved.
	exclusions := []RuleExclusion{
		{
			ID:      "1",
			Name:    "block-with-list",
			Type:    "block",
			Enabled: true,
			Conditions: []Condition{
				{Field: "ip", Operator: "in_list", Value: "some-list"},
			},
		},
	}

	data, err := GeneratePolicyRules(exclusions, nil)
	if err != nil {
		t.Fatal(err)
	}

	var file PolicyRulesFile
	json.Unmarshal(data, &file)

	c := file.Rules[0].Conditions[0]
	if c.Operator != "in_list" {
		t.Errorf("expected operator preserved as in_list, got %q", c.Operator)
	}
	if len(c.ListItems) != 0 {
		t.Errorf("expected no list_items when store is nil, got %d", len(c.ListItems))
	}
}
