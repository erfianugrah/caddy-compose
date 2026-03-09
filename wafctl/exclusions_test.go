package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
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

	// Pre-write versioned empty store to skip seed migrations.
	os.WriteFile(path, []byte(fmt.Sprintf(`{"version":%d,"exclusions":[]}`, currentStoreVersion)), 0644)

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

func TestExclusionStoreReorder(t *testing.T) {
	es := newTestExclusionStore(t)

	a, _ := es.Create(RuleExclusion{Name: "A", Type: "remove_by_id", RuleID: "1", Enabled: true})
	b, _ := es.Create(RuleExclusion{Name: "B", Type: "remove_by_id", RuleID: "2", Enabled: true})
	c, _ := es.Create(RuleExclusion{Name: "C", Type: "remove_by_id", RuleID: "3", Enabled: true})

	// Reorder: C, A, B
	err := es.Reorder([]string{c.ID, a.ID, b.ID})
	if err != nil {
		t.Fatalf("reorder: %v", err)
	}
	list := es.List()
	if len(list) != 3 {
		t.Fatalf("want 3, got %d", len(list))
	}
	if list[0].Name != "C" || list[1].Name != "A" || list[2].Name != "B" {
		t.Errorf("want C,A,B got %s,%s,%s", list[0].Name, list[1].Name, list[2].Name)
	}

	// Verify persistence: reload and check order.
	es2 := NewExclusionStore(es.filePath)
	list2 := es2.List()
	if list2[0].Name != "C" || list2[1].Name != "A" || list2[2].Name != "B" {
		t.Errorf("after reload: want C,A,B got %s,%s,%s", list2[0].Name, list2[1].Name, list2[2].Name)
	}
}

func TestExclusionStoreReorderErrors(t *testing.T) {
	es := newTestExclusionStore(t)
	a, _ := es.Create(RuleExclusion{Name: "A", Type: "remove_by_id", RuleID: "1", Enabled: true})
	es.Create(RuleExclusion{Name: "B", Type: "remove_by_id", RuleID: "2", Enabled: true})

	// Wrong count.
	if err := es.Reorder([]string{a.ID}); err == nil {
		t.Error("expected error for wrong ID count")
	}
	// Unknown ID.
	if err := es.Reorder([]string{a.ID, "bogus"}); err == nil {
		t.Error("expected error for unknown ID")
	}
	// Duplicate ID.
	if err := es.Reorder([]string{a.ID, a.ID}); err == nil {
		t.Error("expected error for duplicate ID")
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
		// Anomaly type validation
		{
			name:    "valid anomaly",
			exc:     RuleExclusion{Name: "test", Type: "anomaly", AnomalyScore: 5, Conditions: []Condition{{Field: "user_agent", Operator: "regex", Value: "BadBot.*"}}},
			wantErr: false,
		},
		{
			name:    "valid anomaly with paranoia level",
			exc:     RuleExclusion{Name: "test", Type: "anomaly", AnomalyScore: 3, AnomalyParanoiaLevel: 2, Conditions: []Condition{{Field: "http_version", Operator: "eq", Value: "HTTP/1.0"}}},
			wantErr: false,
		},
		{
			name:    "anomaly missing conditions",
			exc:     RuleExclusion{Name: "test", Type: "anomaly", AnomalyScore: 5},
			wantErr: true,
		},
		{
			name:    "anomaly score too low",
			exc:     RuleExclusion{Name: "test", Type: "anomaly", AnomalyScore: 0, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}}},
			wantErr: true,
		},
		{
			name:    "anomaly score too high",
			exc:     RuleExclusion{Name: "test", Type: "anomaly", AnomalyScore: 11, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}}},
			wantErr: true,
		},
		{
			name:    "anomaly invalid paranoia level",
			exc:     RuleExclusion{Name: "test", Type: "anomaly", AnomalyScore: 5, AnomalyParanoiaLevel: 5, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}}},
			wantErr: true,
		},
		{
			name:    "anomaly paranoia level zero uses default",
			exc:     RuleExclusion{Name: "test", Type: "anomaly", AnomalyScore: 2, AnomalyParanoiaLevel: 0, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}}},
			wantErr: false,
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

func TestExclusionEndpointReorder(t *testing.T) {
	mux, es := setupExclusionMux(t)

	a, _ := es.Create(RuleExclusion{Name: "A", Type: "remove_by_id", RuleID: "1", Enabled: true})
	b, _ := es.Create(RuleExclusion{Name: "B", Type: "remove_by_id", RuleID: "2", Enabled: true})
	c, _ := es.Create(RuleExclusion{Name: "C", Type: "remove_by_id", RuleID: "3", Enabled: true})

	// Reorder: C, A, B.
	body := `{"ids":["` + c.ID + `","` + a.ID + `","` + b.ID + `"]}`
	req := httptest.NewRequest("PUT", "/api/exclusions/reorder", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("reorder: want 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var result []RuleExclusion
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) != 3 {
		t.Fatalf("want 3, got %d", len(result))
	}
	if result[0].Name != "C" || result[1].Name != "A" || result[2].Name != "B" {
		t.Errorf("want C,A,B got %s,%s,%s", result[0].Name, result[1].Name, result[2].Name)
	}

	// Error: empty ids.
	req2 := httptest.NewRequest("PUT", "/api/exclusions/reorder", strings.NewReader(`{"ids":[]}`))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code != 400 {
		t.Errorf("empty ids: want 400, got %d", w2.Code)
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
	resp := GenerateConfigs(cfg, exclusions, nil)

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

// --- matchesPolicyRuleNameFilter tests ---

func TestMatchesPolicyRuleNameFilter(t *testing.T) {
	ev := Event{
		EventType: "policy_skip",
		MatchedRules: []MatchedRule{
			{ID: 9500001, Msg: "Policy Skip: Skip CRS 942200"},
			{ID: 942100, Msg: "OWASP CRS 942100"},
		},
	}

	tests := []struct {
		name   string
		value  string
		op     string
		expect bool
	}{
		{"eq match", "Skip CRS 942200", "eq", true},
		{"eq no match", "Allow uploads", "eq", false},
		{"contains match", "942200", "contains", true},
		{"contains no match", "zzz", "contains", false},
		{"neq match (name differs)", "Allow uploads", "neq", true},
		{"neq no match (name matches)", "Skip CRS 942200", "neq", false},
		{"in match single", "Skip CRS 942200", "in", true},
		{"in match multi", "Allow uploads,Skip CRS 942200,Block bots", "in", true},
		{"in no match", "Allow uploads,Block bots", "in", false},
		{"regex match", "^Skip CRS.*", "regex", true},
		{"regex no match", "^Allow.*", "regex", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseFieldFilter(tt.value, tt.op)
			got := matchesPolicyRuleNameFilter(&ev, f)
			if got != tt.expect {
				t.Errorf("matchesPolicyRuleNameFilter(value=%q op=%q) = %v, want %v",
					tt.value, tt.op, got, tt.expect)
			}
		})
	}
}

func TestMatchesPolicyRuleNameFilter_NoPolicyRules(t *testing.T) {
	// Event with only CRS rules (no policy rules) should never match
	ev := Event{
		EventType: "blocked",
		MatchedRules: []MatchedRule{
			{ID: 942100, Msg: "OWASP CRS 942100"},
		},
	}
	f := parseFieldFilter("OWASP CRS 942100", "eq")
	if matchesPolicyRuleNameFilter(&ev, f) {
		t.Error("expected no match for non-policy rule msg")
	}
}

func TestMatchesPolicyRuleNameFilter_MultiplePolicy(t *testing.T) {
	// Event with multiple policy rules — match any
	ev := Event{
		EventType: "policy_allow",
		MatchedRules: []MatchedRule{
			{ID: 9500001, Msg: "Policy Allow: Allow API calls"},
			{ID: 9500002, Msg: "Policy Block: Block bad bots"},
		},
	}
	// contains should find "API" in the first rule name
	f := parseFieldFilter("API", "contains")
	if !matchesPolicyRuleNameFilter(&ev, f) {
		t.Error("expected contains match for 'API' in 'Allow API calls'")
	}
	// in should match the second rule name
	f2 := parseFieldFilter("Block bad bots,Other rule", "in")
	if !matchesPolicyRuleNameFilter(&ev, f2) {
		t.Error("expected in match for 'Block bad bots'")
	}
}

// ─── Store Migration Tests ─────────────────────────────────────────

func TestStoreMigrationFromEmptyFile(t *testing.T) {
	// No file on disk → should seed heuristic rules via migration v1.
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")

	es := NewExclusionStore(path)
	rules := es.List()

	// 3 from v1 (heuristic bot rules) + 8 from v3 (ipsum block rules) = 11
	if len(rules) != 11 {
		t.Fatalf("expected 11 seed rules (3 heuristic + 8 ipsum), got %d", len(rules))
	}

	// Verify the seed rules by name.
	names := map[string]bool{}
	for _, r := range rules {
		names[r.Name] = true
	}
	for _, expected := range []string{"Scanner UA Block", "HTTP/1.0 Anomaly", "Generic UA Anomaly"} {
		if !names[expected] {
			t.Errorf("missing seed rule %q", expected)
		}
	}
	for level := 1; level <= 8; level++ {
		name := fmt.Sprintf("IPsum Block (Level %d)", level)
		if !names[name] {
			t.Errorf("missing ipsum seed rule %q", name)
		}
	}

	// Verify Scanner UA Block is a block type with user_agent in condition.
	for _, r := range rules {
		if r.Name == "Scanner UA Block" {
			if r.Type != "block" {
				t.Errorf("Scanner UA Block: want type block, got %s", r.Type)
			}
			if len(r.Conditions) != 1 || r.Conditions[0].Field != "user_agent" || r.Conditions[0].Operator != "in" {
				t.Errorf("Scanner UA Block: unexpected conditions: %+v", r.Conditions)
			}
			if !strings.Contains(r.Conditions[0].Value, "sqlmap") {
				t.Error("Scanner UA Block: condition value should contain sqlmap")
			}
		}
	}

	// Verify file was saved in versioned format.
	data, _ := os.ReadFile(path)
	var sf storeFile
	if err := json.Unmarshal(data, &sf); err != nil {
		t.Fatalf("saved file is not valid versioned format: %v", err)
	}
	if sf.Version != currentStoreVersion {
		t.Errorf("saved version: want %d, got %d", currentStoreVersion, sf.Version)
	}
	if len(sf.Exclusions) != 11 {
		t.Errorf("saved exclusions: want 11, got %d", len(sf.Exclusions))
	}
}

func TestStoreMigrationFromLegacyArray(t *testing.T) {
	// Legacy bare-array format → should migrate to versioned + add seed rules.
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")

	// Write a legacy bare-array with one existing rule.
	legacy := []RuleExclusion{{
		ID:      "existing-1",
		Name:    "Existing rule",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	}}
	data, _ := json.Marshal(legacy)
	os.WriteFile(path, data, 0644)

	es := NewExclusionStore(path)
	rules := es.List()

	// Should have 1 existing + 3 seeded (v1) + 8 ipsum (v3) = 12 rules.
	if len(rules) != 12 {
		t.Fatalf("expected 12 rules (1 existing + 3 seeded + 8 ipsum), got %d", len(rules))
	}

	// Existing rule should be preserved.
	if rules[0].ID != "existing-1" || rules[0].Name != "Existing rule" {
		t.Errorf("existing rule not preserved: got %+v", rules[0])
	}

	// File should now be versioned format.
	saved, _ := os.ReadFile(path)
	var sf storeFile
	json.Unmarshal(saved, &sf)
	if sf.Version != currentStoreVersion {
		t.Errorf("saved version after migration: want %d, got %d", currentStoreVersion, sf.Version)
	}
}

func TestStoreMigrationSkipsWhenCurrent(t *testing.T) {
	// Already at current version → no migration, no seed rules added.
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")

	sf := storeFile{Version: currentStoreVersion, Exclusions: []RuleExclusion{}}
	data, _ := json.MarshalIndent(sf, "", "  ")
	os.WriteFile(path, data, 0644)

	es := NewExclusionStore(path)
	rules := es.List()

	if len(rules) != 0 {
		t.Fatalf("expected 0 rules for current-version empty store, got %d", len(rules))
	}
}

func TestStoreMigrationIdempotent(t *testing.T) {
	// Load twice — second load should not re-add seed rules.
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")

	// First load: seeds rules (3 heuristic + 8 ipsum = 11).
	es1 := NewExclusionStore(path)
	count1 := len(es1.List())
	if count1 != 11 {
		t.Fatalf("first load: expected 11 seed rules, got %d", count1)
	}

	// Second load: reads versioned file, no migration.
	es2 := NewExclusionStore(path)
	count2 := len(es2.List())
	if count2 != 11 {
		t.Fatalf("second load: expected 11 rules (no re-seeding), got %d", count2)
	}
}

func TestMigrateV0toV1SeedRules(t *testing.T) {
	// Unit test the migration function directly.
	existing := []RuleExclusion{
		{ID: "x1", Name: "Existing", Type: "allow", Enabled: true},
	}
	result := migrateV0toV1(existing)

	if len(result) != 4 {
		t.Fatalf("expected 4 rules (1 existing + 3 seeds), got %d", len(result))
	}

	// First rule should be the existing one.
	if result[0].ID != "x1" {
		t.Error("existing rule should be preserved at index 0")
	}

	// Verify seed rule types.
	types := map[string]string{}
	for _, r := range result[1:] {
		types[r.Name] = r.Type
	}
	if types["Scanner UA Block"] != "block" {
		t.Errorf("Scanner UA Block: want type block, got %s", types["Scanner UA Block"])
	}
	if types["HTTP/1.0 Anomaly"] != "anomaly" {
		t.Errorf("HTTP/1.0 Anomaly: want type anomaly, got %s", types["HTTP/1.0 Anomaly"])
	}
	if types["Generic UA Anomaly"] != "anomaly" {
		t.Errorf("Generic UA Anomaly: want type anomaly, got %s", types["Generic UA Anomaly"])
	}

	// Verify anomaly scores.
	for _, r := range result[1:] {
		if r.Name == "HTTP/1.0 Anomaly" && r.AnomalyScore != 2 {
			t.Errorf("HTTP/1.0 Anomaly: want score 2, got %d", r.AnomalyScore)
		}
		if r.Name == "Generic UA Anomaly" && r.AnomalyScore != 5 {
			t.Errorf("Generic UA Anomaly: want score 5, got %d", r.AnomalyScore)
		}
	}
}

func TestValidateExclusionUserAgentIn(t *testing.T) {
	// The "in" operator should now be valid for user_agent field.
	e := RuleExclusion{
		Name: "Scanner UA Block",
		Type: "block",
		Conditions: []Condition{
			{Field: "user_agent", Operator: "in", Value: "sqlmap nikto curl"},
		},
		Enabled: true,
	}
	if err := validateExclusion(e); err != nil {
		t.Errorf("user_agent with in operator should be valid: %v", err)
	}
}

// ─── Tag Validation Tests ───────────────────────────────────────────

func TestTagValidation(t *testing.T) {
	base := RuleExclusion{
		Name: "Test",
		Type: "block",
		Conditions: []Condition{
			{Field: "path", Operator: "eq", Value: "/test"},
		},
		Enabled: true,
	}

	t.Run("valid tags", func(t *testing.T) {
		e := base
		e.Tags = []string{"scanner", "bot-detection", "blocklist-ipsum"}
		if err := validateExclusion(e); err != nil {
			t.Errorf("valid tags should pass: %v", err)
		}
	})

	t.Run("empty tags ok", func(t *testing.T) {
		e := base
		if err := validateExclusion(e); err != nil {
			t.Errorf("no tags should pass: %v", err)
		}
	})

	t.Run("too many tags", func(t *testing.T) {
		e := base
		e.Tags = make([]string, 11)
		for i := range e.Tags {
			e.Tags[i] = "tag"
		}
		if err := validateExclusion(e); err == nil {
			t.Error("11 tags should fail")
		}
	})

	t.Run("tag too long", func(t *testing.T) {
		e := base
		e.Tags = []string{strings.Repeat("a", 51)}
		if err := validateExclusion(e); err == nil {
			t.Error("51-char tag should fail")
		}
	})

	t.Run("uppercase rejected", func(t *testing.T) {
		e := base
		e.Tags = []string{"Scanner"}
		if err := validateExclusion(e); err == nil {
			t.Error("uppercase tag should fail")
		}
	})

	t.Run("spaces rejected", func(t *testing.T) {
		e := base
		e.Tags = []string{"bot detection"}
		if err := validateExclusion(e); err == nil {
			t.Error("tag with spaces should fail")
		}
	})

	t.Run("special chars rejected", func(t *testing.T) {
		e := base
		e.Tags = []string{"bot_detection"}
		if err := validateExclusion(e); err == nil {
			t.Error("underscores should fail (hyphens only)")
		}
	})

	t.Run("max 10 tags ok", func(t *testing.T) {
		e := base
		e.Tags = make([]string, 10)
		for i := range e.Tags {
			e.Tags[i] = "tag" + strings.Repeat("x", i)
		}
		if err := validateExclusion(e); err != nil {
			t.Errorf("10 tags should pass: %v", err)
		}
	})
}

// ─── Tag Migration Tests ────────────────────────────────────────────

func TestMigrateV1toV2_BackfillsSeededRuleTags(t *testing.T) {
	exclusions := []RuleExclusion{
		{ID: "1", Name: "Scanner UA Block", Type: "block", Enabled: true},
		{ID: "2", Name: "HTTP/1.0 Anomaly", Type: "anomaly", Enabled: true},
		{ID: "3", Name: "Generic UA Anomaly", Type: "anomaly", Enabled: true},
	}

	result := migrateV1toV2(exclusions)

	expected := map[string][]string{
		"Scanner UA Block":   {"scanner", "bot-detection"},
		"HTTP/1.0 Anomaly":   {"bot-signal", "protocol"},
		"Generic UA Anomaly": {"bot-signal", "generic-ua"},
	}

	for _, e := range result {
		want, ok := expected[e.Name]
		if !ok {
			continue
		}
		if len(e.Tags) != len(want) {
			t.Errorf("%s: got %d tags, want %d", e.Name, len(e.Tags), len(want))
			continue
		}
		for i, tag := range e.Tags {
			if tag != want[i] {
				t.Errorf("%s tag[%d] = %q, want %q", e.Name, i, tag, want[i])
			}
		}
	}
}

func TestMigrateV1toV2_HoneypotGetsTags(t *testing.T) {
	exclusions := []RuleExclusion{
		{ID: "hp1", Name: "My Honeypot", Type: "honeypot", Enabled: true},
	}

	result := migrateV1toV2(exclusions)

	// honeypot type should be converted to block.
	if result[0].Type != "block" {
		t.Errorf("honeypot type should be migrated to block, got %q", result[0].Type)
	}
	if len(result[0].Tags) != 1 || result[0].Tags[0] != "honeypot" {
		t.Errorf("honeypot should get [honeypot] tag, got %v", result[0].Tags)
	}
}

func TestMigrateV1toV2_SkipsAlreadyTagged(t *testing.T) {
	exclusions := []RuleExclusion{
		{ID: "1", Name: "Scanner UA Block", Type: "block", Tags: []string{"custom"}},
		{ID: "hp1", Name: "Trap", Type: "honeypot", Tags: []string{"my-tag"}},
	}

	result := migrateV1toV2(exclusions)

	// block rule with existing tags keeps them unchanged.
	if len(result[0].Tags) != 1 || result[0].Tags[0] != "custom" {
		t.Errorf("already-tagged rule should keep tags, got %v", result[0].Tags)
	}
	// honeypot type is migrated to block; "honeypot" tag is appended
	// because existing tags don't contain "honeypot".
	if result[1].Type != "block" {
		t.Errorf("honeypot type should be migrated to block, got %q", result[1].Type)
	}
	if len(result[1].Tags) != 2 || result[1].Tags[0] != "my-tag" || result[1].Tags[1] != "honeypot" {
		t.Errorf("honeypot should keep existing tags + append honeypot, got %v", result[1].Tags)
	}
}

func TestMigrateV1toV2_Idempotent(t *testing.T) {
	exclusions := []RuleExclusion{
		{ID: "1", Name: "Scanner UA Block", Type: "block"},
	}

	result := migrateV1toV2(exclusions)
	result2 := migrateV1toV2(result)

	if len(result2[0].Tags) != 2 {
		t.Errorf("second migration should be idempotent, got %v", result2[0].Tags)
	}
}

// ─── Store Migration v2 Integration Test ────────────────────────────

func TestStoreMigrationV2_FromFreshInstall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")

	// Create a fresh store — should seed v1 rules then apply v2 migration.
	es := NewExclusionStore(path)
	exclusions := es.List()

	// Verify seeded rules have tags from v0→v1→v2 migration chain.
	found := 0
	for _, e := range exclusions {
		switch e.Name {
		case "Scanner UA Block":
			found++
			if len(e.Tags) < 2 {
				t.Errorf("Scanner UA Block should have tags, got %v", e.Tags)
			}
		case "HTTP/1.0 Anomaly":
			found++
			if len(e.Tags) < 2 {
				t.Errorf("HTTP/1.0 Anomaly should have tags, got %v", e.Tags)
			}
		case "Generic UA Anomaly":
			found++
			if len(e.Tags) < 2 {
				t.Errorf("Generic UA Anomaly should have tags, got %v", e.Tags)
			}
		}
	}
	if found != 3 {
		t.Errorf("expected 3 seeded rules, found %d", found)
	}

	// Verify store version is persisted as current.
	data, _ := os.ReadFile(path)
	var sf storeFile
	json.Unmarshal(data, &sf)
	if sf.Version != currentStoreVersion {
		t.Errorf("stored version = %d, want %d", sf.Version, currentStoreVersion)
	}
}

func TestStoreMigrationV2_FromV1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")

	// Write a v1 store file with seeded rules but no tags.
	sf := storeFile{
		Version: 1,
		Exclusions: []RuleExclusion{
			{ID: "a", Name: "Scanner UA Block", Type: "block", Enabled: true},
			{ID: "b", Name: "Custom Rule", Type: "allow", Enabled: true,
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api"}}},
		},
	}
	data, _ := json.Marshal(sf)
	os.WriteFile(path, data, 0644)

	es := NewExclusionStore(path)
	exclusions := es.List()

	// 2 original + 8 ipsum seeded by v3 = 10
	if len(exclusions) != 10 {
		t.Fatalf("expected 10 rules (2 original + 8 ipsum), got %d", len(exclusions))
	}

	// Scanner UA Block should have tags backfilled (v2 migration).
	for _, e := range exclusions {
		if e.Name == "Scanner UA Block" {
			if len(e.Tags) == 0 {
				t.Error("Scanner UA Block should have tags after v2 migration")
			}
		}
		if e.Name == "Custom Rule" {
			if len(e.Tags) != 0 {
				t.Error("Custom Rule should not have tags after v2 migration")
			}
		}
	}
}

func TestStoreMigrationV3_FromV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")

	// Write a v2 store with existing rules (no ipsum rules yet).
	sf := storeFile{
		Version: 2,
		Exclusions: []RuleExclusion{
			{ID: "a", Name: "Scanner UA Block", Type: "block", Tags: []string{"scanner", "bot-detection"}, Enabled: true},
			{ID: "b", Name: "Custom Allow", Type: "allow", Enabled: true},
		},
	}
	data, _ := json.Marshal(sf)
	os.WriteFile(path, data, 0644)

	es := NewExclusionStore(path)
	exclusions := es.List()

	// 2 original + 8 ipsum = 10
	if len(exclusions) != 10 {
		t.Fatalf("expected 10 rules (2 original + 8 ipsum), got %d", len(exclusions))
	}

	// Verify ipsum rules were added.
	ipsumCount := 0
	for _, e := range exclusions {
		if containsTag(e.Tags, "ipsum") {
			ipsumCount++
			if e.Type != "block" {
				t.Errorf("ipsum rule %q should be block type, got %s", e.Name, e.Type)
			}
			if len(e.Conditions) != 1 || e.Conditions[0].Operator != "in_list" {
				t.Errorf("ipsum rule %q should have in_list condition", e.Name)
			}
		}
	}
	if ipsumCount != 8 {
		t.Errorf("expected 8 ipsum rules, got %d", ipsumCount)
	}
}

func TestStoreMigrationV3_IdempotentIfIpsumExists(t *testing.T) {
	// If an ipsum block rule already exists (e.g., user created one manually),
	// the v3 migration should not add duplicates.
	existing := []RuleExclusion{
		{ID: "a", Name: "Existing Rule", Type: "block", Tags: []string{"ipsum"}, Enabled: true},
	}
	result := migrateV2toV3(existing)
	// Should not add 8 ipsum rules because an ipsum-tagged rule already exists.
	if len(result) != 1 {
		t.Errorf("expected 1 rule (idempotent), got %d", len(result))
	}
}

// ─── Tags in CRUD ───────────────────────────────────────────────────

func TestExclusionStore_TagsCRUD(t *testing.T) {
	es := newTestExclusionStore(t)

	// Create with tags.
	exc := RuleExclusion{
		Name: "Tagged Rule",
		Type: "block",
		Conditions: []Condition{
			{Field: "path", Operator: "eq", Value: "/admin"},
		},
		Tags:    []string{"scanner", "bot-detection"},
		Enabled: true,
	}

	created, err := es.Create(exc)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(created.Tags) != 2 || created.Tags[0] != "scanner" || created.Tags[1] != "bot-detection" {
		t.Errorf("created tags = %v, want [scanner bot-detection]", created.Tags)
	}

	// Get preserves tags.
	got, ok := es.Get(created.ID)
	if !ok {
		t.Fatal("get: not found")
	}
	if len(got.Tags) != 2 {
		t.Errorf("get tags = %v, want 2 tags", got.Tags)
	}

	// Update tags.
	got.Tags = []string{"new-tag"}
	updated, found, err := es.Update(got.ID, got)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !found {
		t.Fatal("update: not found")
	}
	if len(updated.Tags) != 1 || updated.Tags[0] != "new-tag" {
		t.Errorf("updated tags = %v, want [new-tag]", updated.Tags)
	}
}

// ─── Tags in Export/Import ──────────────────────────────────────────

func TestExclusionStore_TagsExportImport(t *testing.T) {
	es := newTestExclusionStore(t)

	exc := RuleExclusion{
		Name: "Tagged Export",
		Type: "block",
		Conditions: []Condition{
			{Field: "path", Operator: "eq", Value: "/test"},
		},
		Tags:    []string{"export-tag"},
		Enabled: true,
	}
	es.Create(exc)

	exported := es.Export()
	if len(exported.Exclusions) == 0 {
		t.Fatal("export should have exclusions")
	}

	// Import into new store.
	es2 := newTestExclusionStore(t)
	if err := es2.Import(exported.Exclusions); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Find the imported rule.
	for _, e := range es2.List() {
		if e.Name == "Tagged Export" {
			if len(e.Tags) != 1 || e.Tags[0] != "export-tag" {
				t.Errorf("imported tags = %v, want [export-tag]", e.Tags)
			}
			return
		}
	}
	t.Error("imported rule not found")
}
