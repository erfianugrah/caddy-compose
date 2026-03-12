package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
		{"honeypot", false},
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
			{ID: "5", Name: "Raw", Type: "raw", Enabled: true},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatal(err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		// Only allow, block should be included.
		if len(file.Rules) != 2 {
			t.Fatalf("expected 2 rules, got %d", len(file.Rules))
		}
		types := map[string]bool{}
		for _, r := range file.Rules {
			types[r.Type] = true
		}
		for _, want := range []string{"allow", "block"} {
			if !types[want] {
				t.Errorf("missing type %q in output", want)
			}
		}
	})

	t.Run("priority ordering: block < allow", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "a1", Name: "Allow Office", Type: "allow", Enabled: true},
			{ID: "b1", Name: "Block Scanners", Type: "block", Enabled: true},
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
		// Order should be: block (100+), allow (200+)
		if file.Rules[0].Type != "block" {
			t.Errorf("rules[0].Type = %q, want block", file.Rules[0].Type)
		}
		if file.Rules[1].Type != "allow" {
			t.Errorf("rules[1].Type = %q, want allow", file.Rules[1].Type)
		}
		// Verify priority values.
		if file.Rules[0].Priority < 100 || file.Rules[0].Priority >= 200 {
			t.Errorf("block priority = %d, want [100,200)", file.Rules[0].Priority)
		}
		if file.Rules[1].Priority < 200 || file.Rules[1].Priority >= 300 {
			t.Errorf("allow priority = %d, want [200,300)", file.Rules[1].Priority)
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
		// Priorities should be 100, 101, 102.
		if file.Rules[0].Priority != 100 {
			t.Errorf("b1 priority = %d, want 100", file.Rules[0].Priority)
		}
		if file.Rules[1].Priority != 101 {
			t.Errorf("b2 priority = %d, want 101", file.Rules[1].Priority)
		}
		if file.Rules[2].Priority != 102 {
			t.Errorf("b3 priority = %d, want 102", file.Rules[2].Priority)
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
		// The last two rules (index 99 and 100) should both have priority 199
		// (100 + capped 99).
		last := file.Rules[len(file.Rules)-1]
		secondLast := file.Rules[len(file.Rules)-2]
		if last.Priority != 199 {
			t.Errorf("last rule priority = %d, want 199", last.Priority)
		}
		if secondLast.Priority != 199 {
			t.Errorf("second-to-last rule priority = %d, want 199", secondLast.Priority)
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
			{ID: "b1", Name: "Block", Type: "block", Enabled: true,
				Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "192.168.0.0/16"}}},
			{ID: "b2", Name: "Block Path", Type: "block", Enabled: true,
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/wp-admin"}}},
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
			{ID: "b2", Name: "Block Paths", Type: "block", Enabled: true,
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
		// Verify ordering: block (b1, b2), allow (a1).
		if file.Rules[0].ID != "b1" {
			t.Errorf("first rule ID = %q, want b1", file.Rules[0].ID)
		}
		if file.Rules[1].ID != "b2" {
			t.Errorf("second rule ID = %q, want b2", file.Rules[1].ID)
		}
		if file.Rules[2].ID != "a1" {
			t.Errorf("third rule ID = %q, want a1", file.Rules[2].ID)
		}
		// Verify block path conditions.
		bp := file.Rules[1]
		if len(bp.Conditions) != 1 {
			t.Fatalf("block path conditions = %d, want 1", len(bp.Conditions))
		}
		if bp.Conditions[0].Operator != "in" {
			t.Errorf("block path operator = %q, want in", bp.Conditions[0].Operator)
		}
	})
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

// ─── Tag Passthrough Tests ──────────────────────────────────────────

func TestGeneratePolicyRules_TagsPassthrough(t *testing.T) {
	t.Run("tags flow from exclusion to policy rule", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{
				ID: "1", Name: "Scanner Block", Type: "block",
				Conditions: []Condition{{Field: "user_agent", Operator: "contains", Value: "sqlmap"}},
				Tags:       []string{"scanner", "bot-detection"},
				Enabled:    true,
			},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(file.Rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(file.Rules))
		}
		r := file.Rules[0]
		if len(r.Tags) != 2 || r.Tags[0] != "scanner" || r.Tags[1] != "bot-detection" {
			t.Errorf("tags = %v, want [scanner bot-detection]", r.Tags)
		}
	})

	t.Run("no tags produces empty omitempty", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{
				ID: "2", Name: "Simple Block", Type: "block",
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/bad"}},
				Enabled:    true,
			},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Tags should be omitted entirely from JSON output.
		if strings.Contains(string(data), `"tags"`) {
			t.Errorf("expected tags to be omitted, got:\n%s", data)
		}
	})

	t.Run("block with honeypot tags pass through", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{
				ID: "3", Name: "Trap", Type: "block",
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/wp-login.php"}},
				Tags:       []string{"honeypot", "trap"},
				Enabled:    true,
			},
		}
		data, err := GeneratePolicyRules(exclusions, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)
		if len(file.Rules[0].Tags) != 2 {
			t.Errorf("tags = %v, want [honeypot trap]", file.Rules[0].Tags)
		}
	})
}

// ─── GeneratePolicyRulesWithRL ─────────────────────────────────────

func TestGeneratePolicyRulesWithRL(t *testing.T) {
	t.Run("RL rules only", func(t *testing.T) {
		rlRules := []RateLimitRule{
			{
				ID:      "rl-1",
				Name:    "api-limit",
				Service: "api.erfi.io",
				Key:     "client_ip",
				Events:  100,
				Window:  "1m",
				Action:  "deny",
				Tags:    []string{"api", "protection"},
				Enabled: true,
			},
		}
		data, err := GeneratePolicyRulesWithRL(nil, rlRules, RateLimitGlobalConfig{Jitter: 0.1, SweepInterval: "30s"}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if len(file.Rules) != 1 {
			t.Fatalf("want 1 rule, got %d", len(file.Rules))
		}
		r := file.Rules[0]
		if r.ID != "rl-1" {
			t.Errorf("ID = %q, want rl-1", r.ID)
		}
		if r.Type != "rate_limit" {
			t.Errorf("Type = %q, want rate_limit", r.Type)
		}
		if r.Service != "api.erfi.io" {
			t.Errorf("Service = %q, want api.erfi.io", r.Service)
		}
		if r.RateLimit == nil {
			t.Fatal("RateLimit should not be nil")
		}
		if r.RateLimit.Key != "client_ip" {
			t.Errorf("Key = %q, want client_ip", r.RateLimit.Key)
		}
		if r.RateLimit.Events != 100 {
			t.Errorf("Events = %d, want 100", r.RateLimit.Events)
		}
		if r.RateLimit.Window != "1m" {
			t.Errorf("Window = %q, want 1m", r.RateLimit.Window)
		}
		if r.RateLimit.Action != "deny" {
			t.Errorf("Action = %q, want deny", r.RateLimit.Action)
		}
		if len(r.Tags) != 2 || r.Tags[0] != "api" {
			t.Errorf("Tags = %v, want [api protection]", r.Tags)
		}
		// Priority should be in RL band (300+).
		if r.Priority < 300 {
			t.Errorf("Priority = %d, want >= 300", r.Priority)
		}
		// Global config should be present.
		if file.RateLimitConfig == nil {
			t.Fatal("RateLimitConfig should not be nil")
		}
		if file.RateLimitConfig.Jitter != 0.1 {
			t.Errorf("Jitter = %f, want 0.1", file.RateLimitConfig.Jitter)
		}
		if file.RateLimitConfig.SweepInterval != "30s" {
			t.Errorf("SweepInterval = %q, want 30s", file.RateLimitConfig.SweepInterval)
		}
	})

	t.Run("mixed WAF + RL rules sorted by priority", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "e-1", Name: "allow-office", Type: "allow", Enabled: true,
				Conditions: []Condition{{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"}}},
			{ID: "e-2", Name: "block-scanner", Type: "block", Enabled: true,
				Conditions: []Condition{{Field: "user_agent", Operator: "contains", Value: "Nikto"}}},
		}
		rlRules := []RateLimitRule{
			{ID: "rl-1", Name: "global-limit", Key: "client_ip", Events: 50, Window: "1m", Action: "deny", Enabled: true},
		}
		data, err := GeneratePolicyRulesWithRL(exclusions, rlRules, RateLimitGlobalConfig{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)

		if len(file.Rules) != 3 {
			t.Fatalf("want 3 rules, got %d", len(file.Rules))
		}
		// Order: block (100) < allow (200) < rate_limit (300).
		if file.Rules[0].Type != "block" {
			t.Errorf("rules[0].Type = %q, want block", file.Rules[0].Type)
		}
		if file.Rules[1].Type != "allow" {
			t.Errorf("rules[1].Type = %q, want allow", file.Rules[1].Type)
		}
		if file.Rules[2].Type != "rate_limit" {
			t.Errorf("rules[2].Type = %q, want rate_limit", file.Rules[2].Type)
		}
		// RL rule should not have WAF-only fields, should have RateLimit.
		if file.Rules[2].RateLimit == nil {
			t.Error("RL rule should have RateLimit config")
		}
		if file.Rules[0].RateLimit != nil {
			t.Error("block rule should not have RateLimit config")
		}
	})

	t.Run("no RL rules — same as GeneratePolicyRules", func(t *testing.T) {
		exclusions := []RuleExclusion{
			{ID: "e-1", Name: "allow-test", Type: "allow", Enabled: true},
		}
		data, err := GeneratePolicyRulesWithRL(exclusions, nil, RateLimitGlobalConfig{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)

		if len(file.Rules) != 1 {
			t.Fatalf("want 1 rule, got %d", len(file.Rules))
		}
		// No RL global config when no RL rules.
		if file.RateLimitConfig != nil {
			t.Error("RateLimitConfig should be nil when no RL rules")
		}
	})

	t.Run("RL rule with explicit priority", func(t *testing.T) {
		rlRules := []RateLimitRule{
			{ID: "rl-1", Name: "high-priority", Key: "client_ip", Events: 10, Window: "1m", Priority: 5, Enabled: true},
			{ID: "rl-2", Name: "low-priority", Key: "client_ip", Events: 100, Window: "1m", Priority: 50, Enabled: true},
		}
		data, err := GeneratePolicyRulesWithRL(nil, rlRules, RateLimitGlobalConfig{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)

		if len(file.Rules) != 2 {
			t.Fatalf("want 2 rules, got %d", len(file.Rules))
		}
		// rl-1 should come first (priority 300+5=305 < 300+50=350).
		if file.Rules[0].ID != "rl-1" {
			t.Errorf("first rule should be rl-1 (higher priority), got %s", file.Rules[0].ID)
		}
		if file.Rules[0].Priority != 305 {
			t.Errorf("rl-1 priority = %d, want 305", file.Rules[0].Priority)
		}
		if file.Rules[1].Priority != 350 {
			t.Errorf("rl-2 priority = %d, want 350", file.Rules[1].Priority)
		}
	})

	t.Run("RL default action is deny", func(t *testing.T) {
		rlRules := []RateLimitRule{
			{ID: "rl-1", Name: "no-action", Key: "client_ip", Events: 10, Window: "1m", Enabled: true},
		}
		data, err := GeneratePolicyRulesWithRL(nil, rlRules, RateLimitGlobalConfig{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)
		if file.Rules[0].RateLimit.Action != "deny" {
			t.Errorf("default action = %q, want deny", file.Rules[0].RateLimit.Action)
		}
	})

	t.Run("RL conditions converted correctly", func(t *testing.T) {
		rlRules := []RateLimitRule{
			{
				ID: "rl-1", Name: "api-limit", Key: "client_ip", Events: 10, Window: "1m", Enabled: true,
				Conditions: []Condition{
					{Field: "path", Operator: "begins_with", Value: "/api"},
					{Field: "method", Operator: "in", Value: "POST|PUT"},
				},
			},
		}
		data, err := GeneratePolicyRulesWithRL(nil, rlRules, RateLimitGlobalConfig{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)
		if len(file.Rules[0].Conditions) != 2 {
			t.Fatalf("want 2 conditions, got %d", len(file.Rules[0].Conditions))
		}
		if file.Rules[0].Conditions[0].Field != "path" || file.Rules[0].Conditions[0].Operator != "begins_with" {
			t.Errorf("condition[0] = %+v, want path/begins_with", file.Rules[0].Conditions[0])
		}
	})

	t.Run("RL with managed list conditions", func(t *testing.T) {
		tmpDir := t.TempDir()
		ls := NewManagedListStore(filepath.Join(tmpDir, "lists.json"), filepath.Join(tmpDir, "lists"))
		ls.Create(ManagedList{Name: "blocked-ips", Kind: "ip", Items: []string{"1.2.3.4", "5.6.7.8"}})

		rlRules := []RateLimitRule{
			{
				ID: "rl-1", Name: "list-limit", Key: "client_ip", Events: 10, Window: "1m", Enabled: true,
				Conditions: []Condition{{Field: "ip", Operator: "in_list", Value: "blocked-ips"}},
			},
		}
		data, err := GeneratePolicyRulesWithRL(nil, rlRules, RateLimitGlobalConfig{}, ls, nil, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)
		cond := file.Rules[0].Conditions[0]
		if len(cond.ListItems) != 2 {
			t.Errorf("ListItems = %v, want 2 items", cond.ListItems)
		}
		if cond.ListKind != "ip" {
			t.Errorf("ListKind = %q, want ip", cond.ListKind)
		}
	})

	t.Run("RL group_op defaults to and", func(t *testing.T) {
		rlRules := []RateLimitRule{
			{ID: "rl-1", Name: "test", Key: "client_ip", Events: 10, Window: "1m", Enabled: true},
		}
		data, err := GeneratePolicyRulesWithRL(nil, rlRules, RateLimitGlobalConfig{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)
		if file.Rules[0].GroupOp != "and" {
			t.Errorf("GroupOp = %q, want and", file.Rules[0].GroupOp)
		}
	})

	t.Run("RL log_only action preserved", func(t *testing.T) {
		rlRules := []RateLimitRule{
			{ID: "rl-1", Name: "monitor", Key: "client_ip", Events: 10, Window: "1m", Action: "log_only", Enabled: true},
		}
		data, err := GeneratePolicyRulesWithRL(nil, rlRules, RateLimitGlobalConfig{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)
		if file.Rules[0].RateLimit.Action != "log_only" {
			t.Errorf("Action = %q, want log_only", file.Rules[0].RateLimit.Action)
		}
	})

	t.Run("RL service name resolved via serviceMap", func(t *testing.T) {
		rlRules := []RateLimitRule{
			{ID: "rl-1", Name: "httpbun-limit", Service: "httpbun", Key: "client_ip", Events: 100, Window: "1m", Enabled: true},
			{ID: "rl-2", Name: "caddy-limit", Service: "caddy", Key: "client_ip", Events: 200, Window: "1m", Enabled: true},
			{ID: "rl-3", Name: "already-fqdn", Service: "sonarr.erfi.io", Key: "client_ip", Events: 300, Window: "1m", Enabled: true},
			{ID: "rl-4", Name: "wildcard", Service: "*", Key: "client_ip", Events: 400, Window: "1m", Enabled: true},
			{ID: "rl-5", Name: "empty-service", Service: "", Key: "client_ip", Events: 500, Window: "1m", Enabled: true},
		}
		svcMap := map[string]string{
			"httpbun": "httpbun.erfi.io",
			"caddy":   "caddy.erfi.io",
			"sonarr":  "sonarr.erfi.io",
		}
		data, err := GeneratePolicyRulesWithRL(nil, rlRules, RateLimitGlobalConfig{}, nil, svcMap, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)

		byID := map[string]PolicyRule{}
		for _, r := range file.Rules {
			byID[r.ID] = r
		}

		if byID["rl-1"].Service != "httpbun.erfi.io" {
			t.Errorf("rl-1 service = %q, want httpbun.erfi.io", byID["rl-1"].Service)
		}
		if byID["rl-2"].Service != "caddy.erfi.io" {
			t.Errorf("rl-2 service = %q, want caddy.erfi.io", byID["rl-2"].Service)
		}
		if byID["rl-3"].Service != "sonarr.erfi.io" {
			t.Errorf("rl-3 service = %q, want sonarr.erfi.io (already FQDN)", byID["rl-3"].Service)
		}
		if byID["rl-4"].Service != "*" {
			t.Errorf("rl-4 service = %q, want * (wildcard unchanged)", byID["rl-4"].Service)
		}
		if byID["rl-5"].Service != "" {
			t.Errorf("rl-5 service = %q, want empty (unchanged)", byID["rl-5"].Service)
		}
	})

	t.Run("RL service name with nil serviceMap passes through", func(t *testing.T) {
		rlRules := []RateLimitRule{
			{ID: "rl-1", Name: "short-name", Service: "httpbun", Key: "client_ip", Events: 100, Window: "1m", Enabled: true},
		}
		data, err := GeneratePolicyRulesWithRL(nil, rlRules, RateLimitGlobalConfig{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var file PolicyRulesFile
		json.Unmarshal(data, &file)
		// With nil serviceMap, short name passes through unchanged.
		if file.Rules[0].Service != "httpbun" {
			t.Errorf("service = %q, want httpbun (no resolution with nil map)", file.Rules[0].Service)
		}
	})
}

// ─── BuildServiceFQDNMap ─────────────────────────────────────────────

func TestBuildServiceFQDNMap(t *testing.T) {
	t.Run("parses production-style Caddyfile", func(t *testing.T) {
		caddyfile := `# Global options
{
	admin 0.0.0.0:2019
}

httpbun.erfi.io {
	reverse_proxy httpbun:80
}

caddy.erfi.io {
	reverse_proxy wafctl:8080
}

sonarr.erfi.io {
	reverse_proxy sonarr:8989
}

caddy-prometheus.erfi.io {
	reverse_proxy prometheus:9090
}
`
		path := filepath.Join(t.TempDir(), "Caddyfile")
		if err := os.WriteFile(path, []byte(caddyfile), 0644); err != nil {
			t.Fatal(err)
		}
		m := BuildServiceFQDNMap(path)
		if m == nil {
			t.Fatal("expected non-nil map")
		}
		tests := map[string]string{
			"httpbun":          "httpbun.erfi.io",
			"caddy":            "caddy.erfi.io",
			"sonarr":           "sonarr.erfi.io",
			"caddy-prometheus": "caddy-prometheus.erfi.io",
		}
		for short, wantFQDN := range tests {
			if got := m[short]; got != wantFQDN {
				t.Errorf("m[%q] = %q, want %q", short, got, wantFQDN)
			}
		}
		if len(m) != 4 {
			t.Errorf("map has %d entries, want 4: %v", len(m), m)
		}
	})

	t.Run("empty path returns nil", func(t *testing.T) {
		if m := BuildServiceFQDNMap(""); m != nil {
			t.Errorf("expected nil, got %v", m)
		}
	})

	t.Run("nonexistent file returns nil", func(t *testing.T) {
		if m := BuildServiceFQDNMap("/nonexistent/Caddyfile"); m != nil {
			t.Errorf("expected nil, got %v", m)
		}
	})

	t.Run("no FQDN blocks returns nil", func(t *testing.T) {
		caddyfile := `{
	admin 0.0.0.0:2019
}
:8080 {
	respond "Hello"
}
`
		path := filepath.Join(t.TempDir(), "Caddyfile")
		os.WriteFile(path, []byte(caddyfile), 0644)
		m := BuildServiceFQDNMap(path)
		if m != nil && len(m) > 0 {
			t.Errorf("expected nil or empty map, got %v", m)
		}
	})

	t.Run("handles duplicate short names (last wins)", func(t *testing.T) {
		caddyfile := `httpbun.erfi.io {
}
httpbun.example.com {
}
`
		path := filepath.Join(t.TempDir(), "Caddyfile")
		os.WriteFile(path, []byte(caddyfile), 0644)
		m := BuildServiceFQDNMap(path)
		// Last occurrence wins.
		if m["httpbun"] != "httpbun.example.com" {
			t.Errorf("m[httpbun] = %q, want httpbun.example.com (last wins)", m["httpbun"])
		}
	})
}

// ─── resolveServiceName ──────────────────────────────────────────────

func TestResolveServiceName(t *testing.T) {
	svcMap := map[string]string{
		"httpbun": "httpbun.erfi.io",
		"caddy":   "caddy.erfi.io",
	}

	tests := []struct {
		name    string
		service string
		svcMap  map[string]string
		want    string
	}{
		{"short name resolved", "httpbun", svcMap, "httpbun.erfi.io"},
		{"another short name", "caddy", svcMap, "caddy.erfi.io"},
		{"already FQDN unchanged", "sonarr.erfi.io", svcMap, "sonarr.erfi.io"},
		{"wildcard unchanged", "*", svcMap, "*"},
		{"empty unchanged", "", svcMap, ""},
		{"unknown short name passes through", "unknown", svcMap, "unknown"},
		{"nil map passes through", "httpbun", nil, "httpbun"},
		{"empty map passes through", "httpbun", map[string]string{}, "httpbun"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveServiceName(tt.service, tt.svcMap)
			if got != tt.want {
				t.Errorf("resolveServiceName(%q) = %q, want %q", tt.service, got, tt.want)
			}
		})
	}
}

// ─── BuildPolicyWafConfig ─────────────────────────────────────────

func TestBuildPolicyWafConfig_Nil(t *testing.T) {
	got := BuildPolicyWafConfig(nil, nil)
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestBuildPolicyWafConfig_Defaults(t *testing.T) {
	cs := newTestConfigStore(t)
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			ParanoiaLevel:     2,
			InboundThreshold:  10,
			OutboundThreshold: 8,
		},
	}
	cs.Update(cfg)
	got := BuildPolicyWafConfig(cs, nil)
	if got == nil {
		t.Fatal("expected non-nil")
	}
	if got.ParanoiaLevel != 2 {
		t.Errorf("paranoia_level = %d, want 2", got.ParanoiaLevel)
	}
	if got.InboundThreshold != 10 {
		t.Errorf("inbound_threshold = %d, want 10", got.InboundThreshold)
	}
	if got.OutboundThreshold != 8 {
		t.Errorf("outbound_threshold = %d, want 8", got.OutboundThreshold)
	}
	if got.PerService != nil {
		t.Errorf("expected nil PerService, got %+v", got.PerService)
	}
}

func TestBuildPolicyWafConfig_PerService(t *testing.T) {
	cs := newTestConfigStore(t)
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			ParanoiaLevel:     2,
			InboundThreshold:  10,
			OutboundThreshold: 10,
		},
		Services: map[string]WAFServiceSettings{
			"httpbun": {
				ParanoiaLevel:    3,
				InboundThreshold: 5,
			},
		},
	}
	cs.Update(cfg)
	svcMap := map[string]string{"httpbun": "httpbun.erfi.io"}
	got := BuildPolicyWafConfig(cs, svcMap)
	if got == nil {
		t.Fatal("expected non-nil")
	}
	// Should have both short name and FQDN entries.
	if len(got.PerService) != 2 {
		t.Fatalf("expected 2 per_service entries, got %d", len(got.PerService))
	}
	fqdnCfg, ok := got.PerService["httpbun.erfi.io"]
	if !ok {
		t.Fatal("missing FQDN entry")
	}
	if fqdnCfg.ParanoiaLevel != 3 {
		t.Errorf("fqdn paranoia_level = %d, want 3", fqdnCfg.ParanoiaLevel)
	}
	if fqdnCfg.InboundThreshold != 5 {
		t.Errorf("fqdn inbound_threshold = %d, want 5", fqdnCfg.InboundThreshold)
	}
	shortCfg, ok := got.PerService["httpbun"]
	if !ok {
		t.Fatal("missing short name entry")
	}
	if shortCfg.ParanoiaLevel != 3 {
		t.Errorf("short paranoia_level = %d, want 3", shortCfg.ParanoiaLevel)
	}
}

func TestBuildPolicyWafConfig_InPolicyRulesJSON(t *testing.T) {
	cs := newTestConfigStore(t)
	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			ParanoiaLevel:     2,
			InboundThreshold:  10,
			OutboundThreshold: 10,
		},
	}
	cs.Update(cfg)
	wafCfg := BuildPolicyWafConfig(cs, nil)
	data, err := GeneratePolicyRulesWithRL(nil, nil, RateLimitGlobalConfig{}, nil, nil, nil, wafCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var file PolicyRulesFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if file.WafConfig == nil {
		t.Fatal("expected waf_config in output")
	}
	if file.WafConfig.ParanoiaLevel != 2 {
		t.Errorf("paranoia_level = %d, want 2", file.WafConfig.ParanoiaLevel)
	}
	if file.WafConfig.InboundThreshold != 10 {
		t.Errorf("inbound_threshold = %d, want 10", file.WafConfig.InboundThreshold)
	}
}

func TestBuildPolicyWafConfig_NilOmitsFromJSON(t *testing.T) {
	data, err := GeneratePolicyRulesWithRL(nil, nil, RateLimitGlobalConfig{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not contain waf_config key at all.
	if strings.Contains(string(data), "waf_config") {
		t.Error("expected no waf_config in output when nil")
	}
}

// ─── Detect Rule Generation ───────────────────────────────────────

func TestGenerateDetectRules(t *testing.T) {
	exclusions := []RuleExclusion{
		{
			ID:                  "d1",
			Name:                "Missing Accept",
			Type:                "detect",
			Severity:            "NOTICE",
			DetectParanoiaLevel: 1,
			Conditions: []Condition{
				{Field: "header", Operator: "eq", Value: "Accept:"},
			},
			Tags:    []string{"heuristic", "bot-signal"},
			Enabled: true,
		},
		{
			ID:      "a1",
			Name:    "Allow Office",
			Type:    "allow",
			Enabled: true,
			Conditions: []Condition{
				{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
			},
		},
	}

	data, err := GeneratePolicyRulesWithRL(exclusions, nil, RateLimitGlobalConfig{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var file PolicyRulesFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(file.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(file.Rules))
	}

	// Rules should be sorted by priority: allow (200) before detect (400).
	if file.Rules[0].Type != "allow" {
		t.Errorf("first rule type = %q, want allow", file.Rules[0].Type)
	}
	if file.Rules[1].Type != "detect" {
		t.Errorf("second rule type = %q, want detect", file.Rules[1].Type)
	}

	// Detect rule should carry severity and paranoia level.
	detectRule := file.Rules[1]
	if detectRule.Severity != "NOTICE" {
		t.Errorf("severity = %q, want NOTICE", detectRule.Severity)
	}
	if detectRule.ParanoiaLevel != 1 {
		t.Errorf("paranoia_level = %d, want 1", detectRule.ParanoiaLevel)
	}
	if detectRule.Name != "Missing Accept" {
		t.Errorf("name = %q, want Missing Accept", detectRule.Name)
	}
	if len(detectRule.Tags) != 2 || detectRule.Tags[0] != "heuristic" {
		t.Errorf("tags = %v, want [heuristic bot-signal]", detectRule.Tags)
	}

	// Allow rule should NOT have severity or PL.
	allowRule := file.Rules[0]
	if allowRule.Severity != "" {
		t.Errorf("allow rule severity = %q, want empty", allowRule.Severity)
	}
	if allowRule.ParanoiaLevel != 0 {
		t.Errorf("allow rule paranoia_level = %d, want 0", allowRule.ParanoiaLevel)
	}
}

func TestGenerateDetectRules_PriorityBand(t *testing.T) {
	exclusions := []RuleExclusion{
		{ID: "b1", Name: "Block", Type: "block", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/bad"}}},
		{ID: "a1", Name: "Allow", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "ip", Operator: "eq", Value: "1.2.3.4"}}},
		{ID: "d1", Name: "Detect", Type: "detect", Severity: "CRITICAL", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/sus"}}},
	}

	data, err := GeneratePolicyRulesWithRL(exclusions, nil, RateLimitGlobalConfig{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var file PolicyRulesFile
	json.Unmarshal(data, &file)

	// Priority order: block(100) < allow(200) < detect(400).
	if len(file.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(file.Rules))
	}
	if file.Rules[0].Type != "block" {
		t.Errorf("rule[0] type = %q, want block", file.Rules[0].Type)
	}
	if file.Rules[1].Type != "allow" {
		t.Errorf("rule[1] type = %q, want allow", file.Rules[1].Type)
	}
	if file.Rules[2].Type != "detect" {
		t.Errorf("rule[2] type = %q, want detect", file.Rules[2].Type)
	}
}
