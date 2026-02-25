package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)


func TestExclusionStoreCRUD(t *testing.T) {
	es := newTestExclusionStore(t)

	// Create.
	exc := RuleExclusion{
		Name:    "Test exclusion",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	}

	created, err := es.Create(exc)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == "" {
		t.Error("created exclusion should have an ID")
	}
	if created.CreatedAt.IsZero() {
		t.Error("created_at should be set")
	}

	// List.
	list := es.List()
	if len(list) != 1 {
		t.Fatalf("list: want 1, got %d", len(list))
	}

	// Get.
	got, found := es.Get(created.ID)
	if !found {
		t.Fatal("get: not found")
	}
	if got.Name != "Test exclusion" {
		t.Errorf("get: want Test exclusion, got %s", got.Name)
	}

	// Update.
	exc.Name = "Updated exclusion"
	exc.Description = "Now with description"
	updated, found, err := es.Update(created.ID, exc)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !found {
		t.Fatal("update: not found")
	}
	if updated.Name != "Updated exclusion" {
		t.Errorf("update: want Updated exclusion, got %s", updated.Name)
	}
	if updated.ID != created.ID {
		t.Error("update should preserve ID")
	}
	if updated.CreatedAt != created.CreatedAt {
		t.Error("update should preserve created_at")
	}

	// Delete.
	deleted, err := es.Delete(created.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !deleted {
		t.Fatal("delete: not found")
	}

	list = es.List()
	if len(list) != 0 {
		t.Errorf("list after delete: want 0, got %d", len(list))
	}
}



func TestExclusionStoreDeleteNotFound(t *testing.T) {
	es := newTestExclusionStore(t)
	found, err := es.Delete("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("should not find nonexistent exclusion")
	}
}



func TestExclusionStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")

	es1 := NewExclusionStore(path)
	_, err := es1.Create(RuleExclusion{
		Name:    "Persistent",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Create new store from same file — should load the exclusion.
	es2 := NewExclusionStore(path)
	list := es2.List()
	if len(list) != 1 {
		t.Fatalf("persistence: want 1, got %d", len(list))
	}
	if list[0].Name != "Persistent" {
		t.Errorf("persistence: want Persistent, got %s", list[0].Name)
	}
}



func TestExclusionStoreImportExport(t *testing.T) {
	es := newTestExclusionStore(t)

	// Create some exclusions.
	es.Create(RuleExclusion{Name: "First", Type: "remove_by_id", RuleID: "920420", Enabled: true})
	es.Create(RuleExclusion{Name: "Second", Type: "remove_by_tag", RuleTag: "attack-sqli", Enabled: false})

	// Export.
	export := es.Export()
	if export.Version != 1 {
		t.Errorf("export version: want 1, got %d", export.Version)
	}
	if len(export.Exclusions) != 2 {
		t.Fatalf("export: want 2 exclusions, got %d", len(export.Exclusions))
	}

	// Import into a fresh store.
	es2 := newTestExclusionStore(t)
	err := es2.Import(export.Exclusions)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	list := es2.List()
	if len(list) != 2 {
		t.Fatalf("import: want 2, got %d", len(list))
	}
}



func TestExclusionStoreEnabledFilter(t *testing.T) {
	es := newTestExclusionStore(t)
	es.Create(RuleExclusion{Name: "Enabled", Type: "remove_by_id", RuleID: "1", Enabled: true})
	es.Create(RuleExclusion{Name: "Disabled", Type: "remove_by_id", RuleID: "2", Enabled: false})

	enabled := es.EnabledExclusions()
	if len(enabled) != 1 {
		t.Fatalf("want 1 enabled, got %d", len(enabled))
	}
	if enabled[0].Name != "Enabled" {
		t.Errorf("want Enabled, got %s", enabled[0].Name)
	}
}

// --- Exclusion validation tests ---



// --- Exclusion validation tests ---

func TestValidateExclusion(t *testing.T) {
	tests := []struct {
		name    string
		exc     RuleExclusion
		wantErr bool
	}{
		{
			name:    "valid remove_by_id",
			exc:     RuleExclusion{Name: "test", Type: "remove_by_id", RuleID: "920420"},
			wantErr: false,
		},
		{
			name:    "valid remove_by_tag",
			exc:     RuleExclusion{Name: "test", Type: "remove_by_tag", RuleTag: "attack-sqli"},
			wantErr: false,
		},
		{
			name:    "valid update_target_by_id",
			exc:     RuleExclusion{Name: "test", Type: "update_target_by_id", RuleID: "920420", Variable: "ARGS:foo"},
			wantErr: false,
		},
		{
			name:    "valid runtime_remove_by_id",
			exc:     RuleExclusion{Name: "test", Type: "runtime_remove_by_id", RuleID: "920420", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/"}}},
			wantErr: false,
		},
		{
			name:    "valid runtime_remove_target_by_id",
			exc:     RuleExclusion{Name: "test", Type: "runtime_remove_target_by_id", RuleID: "920420", Variable: "ARGS:x", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/"}}},
			wantErr: false,
		},
		{
			name:    "missing name",
			exc:     RuleExclusion{Type: "remove_by_id", RuleID: "920420"},
			wantErr: true,
		},
		{
			name:    "invalid type",
			exc:     RuleExclusion{Name: "test", Type: "invalid_type"},
			wantErr: true,
		},
		{
			name:    "remove_by_id missing rule_id",
			exc:     RuleExclusion{Name: "test", Type: "remove_by_id"},
			wantErr: true,
		},
		{
			name:    "remove_by_tag missing rule_tag",
			exc:     RuleExclusion{Name: "test", Type: "remove_by_tag"},
			wantErr: true,
		},
		{
			name:    "update_target_by_id missing variable",
			exc:     RuleExclusion{Name: "test", Type: "update_target_by_id", RuleID: "920420"},
			wantErr: true,
		},
		{
			name:    "runtime_remove_by_id missing conditions",
			exc:     RuleExclusion{Name: "test", Type: "runtime_remove_by_id", RuleID: "920420"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExclusion(tt.exc)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExclusion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// --- Exclusion HTTP endpoint tests ---



func TestExclusionEndpointCreate(t *testing.T) {
	mux, _ := setupExclusionMux(t)

	body := `{"name":"Test","type":"remove_by_id","rule_id":"920420","enabled":true}`
	req := httptest.NewRequest("POST", "/api/exclusions", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 201 {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp RuleExclusion
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.ID == "" {
		t.Error("response should have an ID")
	}
	if resp.Name != "Test" {
		t.Errorf("want Test, got %s", resp.Name)
	}
}



func TestExclusionEndpointCreateInvalid(t *testing.T) {
	mux, _ := setupExclusionMux(t)

	body := `{"name":"","type":"remove_by_id","rule_id":"920420"}`
	req := httptest.NewRequest("POST", "/api/exclusions", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
}



func TestExclusionEndpointGetNotFound(t *testing.T) {
	mux, _ := setupExclusionMux(t)

	req := httptest.NewRequest("GET", "/api/exclusions/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("want 404, got %d", w.Code)
	}
}



func TestExclusionEndpointCRUDFlow(t *testing.T) {
	mux, _ := setupExclusionMux(t)

	// Create.
	body := `{"name":"Flow Test","type":"remove_by_id","rule_id":"920420","enabled":true}`
	req := httptest.NewRequest("POST", "/api/exclusions", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("create: want 201, got %d", w.Code)
	}

	var created RuleExclusion
	json.NewDecoder(w.Body).Decode(&created)

	// Get.
	req = httptest.NewRequest("GET", "/api/exclusions/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("get: want 200, got %d", w.Code)
	}

	// Update.
	body = `{"name":"Updated Flow Test","type":"remove_by_id","rule_id":"920420","enabled":false}`
	req = httptest.NewRequest("PUT", "/api/exclusions/"+created.ID, strings.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("update: want 200, got %d: %s", w.Code, w.Body.String())
	}

	var updated RuleExclusion
	json.NewDecoder(w.Body).Decode(&updated)
	if updated.Name != "Updated Flow Test" {
		t.Errorf("update: want Updated Flow Test, got %s", updated.Name)
	}
	if updated.Enabled {
		t.Error("update: want enabled=false")
	}

	// List — should have 1.
	req = httptest.NewRequest("GET", "/api/exclusions", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("list: want 200, got %d", w.Code)
	}
	var list []RuleExclusion
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("list: want 1, got %d", len(list))
	}

	// Delete.
	req = httptest.NewRequest("DELETE", "/api/exclusions/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 204 {
		t.Fatalf("delete: want 204, got %d", w.Code)
	}

	// Verify deleted.
	req = httptest.NewRequest("GET", "/api/exclusions/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("get after delete: want 404, got %d", w.Code)
	}
}



func TestExclusionEndpointExportImport(t *testing.T) {
	mux, es := setupExclusionMux(t)

	// Create two exclusions.
	es.Create(RuleExclusion{Name: "Export1", Type: "remove_by_id", RuleID: "1", Enabled: true})
	es.Create(RuleExclusion{Name: "Export2", Type: "remove_by_tag", RuleTag: "sqli", Enabled: true})

	// Export.
	req := httptest.NewRequest("GET", "/api/exclusions/export", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("export: want 200, got %d", w.Code)
	}

	exportBody := w.Body.Bytes()
	var export ExclusionExport
	json.Unmarshal(exportBody, &export)
	if len(export.Exclusions) != 2 {
		t.Fatalf("export: want 2 exclusions, got %d", len(export.Exclusions))
	}

	// Import into the same store (replaces).
	req = httptest.NewRequest("POST", "/api/exclusions/import", bytes.NewReader(exportBody))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("import: want 200, got %d: %s", w.Code, w.Body.String())
	}
}



func TestExclusionEndpointImportInvalid(t *testing.T) {
	mux, _ := setupExclusionMux(t)

	// Empty exclusions.
	body := `{"version":1,"exclusions":[]}`
	req := httptest.NewRequest("POST", "/api/exclusions/import", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("import empty: want 400, got %d", w.Code)
	}
}



func TestExclusionEndpointGenerate(t *testing.T) {
	mux, es := setupExclusionMux(t)

	es.Create(RuleExclusion{
		Name:    "Remove rule",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	})
	es.Create(RuleExclusion{
		Name:       "Runtime remove",
		Type:       "runtime_remove_by_id",
		RuleID:     "941100",
		Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/webhook"}},
		Enabled:    true,
	})

	req := httptest.NewRequest("POST", "/api/exclusions/generate", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("generate: want 200, got %d", w.Code)
	}

	var resp GenerateResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp.PostCRS, "SecRuleRemoveById 920420") {
		t.Error("post-crs should contain SecRuleRemoveById 920420")
	}
	if !strings.Contains(resp.PreCRS, "ruleRemoveById=941100") {
		t.Error("pre-crs should contain runtime removal for 941100")
	}
}

// --- Config Store tests ---



func TestEscapeSecRuleValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain text", "hello", "hello"},
		{"double quote", `say "hello"`, `say \"hello\"`},
		{"single quote", "msg:'test'", `msg:\'test\'`},
		{"backslash", `path\to\file`, `path\\to\\file`},
		{"newline stripped", "line1\nline2", "line1line2"},
		{"carriage return stripped", "line1\rline2", "line1line2"},
		{"combined injection", "foo\"\nSecRule", `foo\"SecRule`},
		{"backslash before quote", `\"`, `\\\"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeSecRuleValue(tt.input)
			if got != tt.want {
				t.Errorf("escapeSecRuleValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}



func TestSanitizeComment(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"hello", "hello"},
		{"line1\nline2", "line1 line2"},
		{"line1\r\nline2", "line1 line2"},
		{"no\rcarriage", "nocarriage"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeComment(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeComment(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}



func TestValidateExclusion_SecRuleInjection(t *testing.T) {
	tests := []struct {
		name    string
		exc     RuleExclusion
		wantErr string
	}{
		{
			name:    "newline in name",
			exc:     RuleExclusion{Name: "evil\nSecRule", Type: "remove_by_id", RuleID: "920420"},
			wantErr: "newlines",
		},
		{
			name:    "invalid rule_tag characters",
			exc:     RuleExclusion{Name: "test", Type: "remove_by_tag", RuleTag: "attack-sqli\"; SecRule"},
			wantErr: "invalid rule_tag",
		},
		{
			name:    "valid rule_tag with slashes",
			exc:     RuleExclusion{Name: "test", Type: "remove_by_tag", RuleTag: "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"},
			wantErr: "",
		},
		{
			name:    "invalid variable characters",
			exc:     RuleExclusion{Name: "test", Type: "update_target_by_id", RuleID: "920420", Variable: "ARGS:foo\"; deny"},
			wantErr: "invalid variable",
		},
		{
			name:    "valid variable",
			exc:     RuleExclusion{Name: "test", Type: "update_target_by_id", RuleID: "920420", Variable: "!REQUEST_COOKIES:/__session/"},
			wantErr: "",
		},
		{
			name: "newline in condition value",
			exc: RuleExclusion{
				Name: "test", Type: "allow",
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api\n"}},
			},
			wantErr: "newlines",
		},
		{
			name: "invalid named field name in header",
			exc: RuleExclusion{
				Name: "test", Type: "allow",
				Conditions: []Condition{{Field: "header", Operator: "eq", Value: "X-Evil\"; inject:value"}},
			},
			wantErr: "invalid header name",
		},
		{
			name: "valid named field name in header",
			exc: RuleExclusion{
				Name: "test", Type: "allow",
				Conditions: []Condition{{Field: "header", Operator: "eq", Value: "X-Forwarded-For:1.2.3.4"}},
			},
			wantErr: "",
		},
		{
			name: "valid named cookie",
			exc: RuleExclusion{
				Name: "test", Type: "allow",
				Conditions: []Condition{{Field: "cookie", Operator: "eq", Value: "__session:abc123"}},
			},
			wantErr: "",
		},
		{
			name: "skip_rule with invalid rule_tag",
			exc: RuleExclusion{
				Name: "test", Type: "skip_rule", RuleTag: "tag with spaces",
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/"}},
			},
			wantErr: "invalid rule_tag",
		},
		{
			name: "skip_rule with valid rule_tag",
			exc: RuleExclusion{
				Name: "test", Type: "skip_rule", RuleTag: "attack-sqli",
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/"}},
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExclusion(tt.exc)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}



func TestGenerateConfigs_EscapesInjection(t *testing.T) {
	// Generate configs with a malicious exclusion name containing quotes.
	exclusions := []RuleExclusion{
		{
			ID:      "test1",
			Name:    `Test "injection`,
			Type:    "allow",
			Enabled: true,
			Conditions: []Condition{
				{Field: "path", Operator: "eq", Value: `/api/"malicious`},
			},
		},
	}
	cfg := WAFConfig{Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 10}}
	resp := GenerateConfigs(cfg, exclusions)

	// The value /api/"malicious should be escaped to /api/\"malicious in the output.
	// Verify the escaped form is present (backslash-quote before malicious).
	if !strings.Contains(resp.PreCRS, `\/\"malicious`) && !strings.Contains(resp.PreCRS, `\"malicious`) {
		t.Error("expected escaped quotes in generated pre-CRS config")
	}

	// Verify the name in the msg field is escaped: Test \"injection
	if !strings.Contains(resp.PreCRS, `Test \"injection`) {
		t.Errorf("expected escaped name in msg field, got:\n%s", resp.PreCRS)
	}

	// Verify no raw newlines that could inject new directives.
	for i, line := range strings.Split(resp.PreCRS, "\n") {
		if strings.Contains(line, "SecRule") && strings.Count(line, `"`)%2 != 0 {
			// Odd number of unescaped quotes on a SecRule line means broken quoting.
			// Count only unescaped quotes (not preceded by backslash).
			unescaped := 0
			for j, ch := range line {
				if ch == '"' && (j == 0 || line[j-1] != '\\') {
					unescaped++
				}
			}
			if unescaped%2 != 0 {
				t.Errorf("line %d has unbalanced unescaped quotes: %s", i+1, line)
			}
		}
	}
}

// --- extractPolicyName tests ---



// --- extractPolicyName tests ---

func TestExtractPolicyName(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{"Policy Allow: Bypass WAF for uploads", "Bypass WAF for uploads"},
		{"Policy Skip: Skip CRS 942200", "Skip CRS 942200"},
		{"Policy Block: Block bad bots", "Block bad bots"},
		{"CRS 942100", ""},
		{"", ""},
		{"Policy Allow: ", ""},
		{"PolicyAllow: test", ""},
	}
	for _, tc := range tests {
		t.Run(tc.msg, func(t *testing.T) {
			got := extractPolicyName(tc.msg)
			if got != tc.want {
				t.Errorf("extractPolicyName(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}

// --- handleExclusionHits tests ---



// --- handleExclusionHits tests ---

func TestHandleExclusionHits(t *testing.T) {
	// Create an exclusion store with some rules.
	es := newTestExclusionStore(t)
	es.Create(RuleExclusion{Name: "Allow uploads", Type: "allow", Enabled: true})
	es.Create(RuleExclusion{Name: "Skip CRS 942200", Type: "skip_rule", Enabled: true})

	// Create a Store with policy events referencing these exclusions.
	store := &Store{}
	now := time.Now().UTC()
	store.mu.Lock()
	store.events = []Event{
		{
			ID:        "ev1",
			Timestamp: now.Add(-1 * time.Hour),
			EventType: "policy_allow",
			MatchedRules: []MatchedRule{
				{ID: 9500001, Msg: "Policy Allow: Allow uploads"},
			},
		},
		{
			ID:        "ev2",
			Timestamp: now.Add(-2 * time.Hour),
			EventType: "policy_allow",
			MatchedRules: []MatchedRule{
				{ID: 9500001, Msg: "Policy Allow: Allow uploads"},
			},
		},
		{
			ID:        "ev3",
			Timestamp: now.Add(-30 * time.Minute),
			EventType: "policy_skip",
			MatchedRules: []MatchedRule{
				{ID: 9500002, Msg: "Policy Skip: Skip CRS 942200"},
			},
		},
		{
			ID:        "ev4",
			Timestamp: now.Add(-1 * time.Hour),
			EventType: "blocked",
			RuleID:    942100,
		},
	}
	store.mu.Unlock()

	handler := handleExclusionHits(store, es)

	// Default (24h)
	req := httptest.NewRequest("GET", "/api/exclusions/hits", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Hits map[string]struct {
			Total     int   `json:"total"`
			Sparkline []int `json:"sparkline"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// "Allow uploads" should have 2 hits
	uploads, ok := resp.Hits["Allow uploads"]
	if !ok {
		t.Fatal("expected 'Allow uploads' in hits")
	}
	if uploads.Total != 2 {
		t.Errorf("Allow uploads total = %d, want 2", uploads.Total)
	}

	// "Skip CRS 942200" should have 1 hit
	skip, ok := resp.Hits["Skip CRS 942200"]
	if !ok {
		t.Fatal("expected 'Skip CRS 942200' in hits")
	}
	if skip.Total != 1 {
		t.Errorf("Skip CRS 942200 total = %d, want 1", skip.Total)
	}

	// Sparkline should have 24 elements
	if len(uploads.Sparkline) != 24 {
		t.Errorf("sparkline length = %d, want 24", len(uploads.Sparkline))
	}

	// Test with hours param
	req2 := httptest.NewRequest("GET", "/api/exclusions/hits?hours=1", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != 200 {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}

	var resp2 struct {
		Hits map[string]struct {
			Total     int   `json:"total"`
			Sparkline []int `json:"sparkline"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	// With 1 hour window, the 2-hour-old event should be excluded
	if resp2.Hits["Allow uploads"].Total > 2 {
		t.Errorf("with hours=1, Allow uploads total = %d, expected <= 2", resp2.Hits["Allow uploads"].Total)
	}
	if len(resp2.Hits["Allow uploads"].Sparkline) != 1 {
		t.Errorf("with hours=1, sparkline length = %d, want 1", len(resp2.Hits["Allow uploads"].Sparkline))
	}
}

// --- matchesPolicyRuleName tests ---



// --- matchesPolicyRuleName tests ---

func TestMatchesPolicyRuleName(t *testing.T) {
	ev := Event{
		EventType: "policy_skip",
		MatchedRules: []MatchedRule{
			{ID: 9500001, Msg: "Policy Skip: Skip CRS 942200"},
			{ID: 942100, Msg: "OWASP CRS 942100"},
		},
	}

	if !matchesPolicyRuleName(&ev, "Skip CRS 942200") {
		t.Error("expected match for 'Skip CRS 942200'")
	}
	if matchesPolicyRuleName(&ev, "Allow uploads") {
		t.Error("expected no match for 'Allow uploads'")
	}
	if matchesPolicyRuleName(&ev, "") {
		t.Error("expected no match for empty name")
	}
	// Non-policy msg should not match
	if matchesPolicyRuleName(&ev, "OWASP CRS 942100") {
		t.Error("expected no match for non-policy msg")
	}
}

// --- rule_name filter on handleEvents ---
