package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
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
		Name:       "Test exclusion",
		Type:       "allow",
		Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}},
		Enabled:    true,
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
		Name:       "Persistent",
		Type:       "allow",
		Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}},
		Enabled:    true,
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
	es.Create(RuleExclusion{Name: "First", Type: "allow", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}}, Enabled: true})
	es.Create(RuleExclusion{Name: "Second", Type: "block", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/blocked"}}, Enabled: false})

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

	a, _ := es.Create(RuleExclusion{Name: "A", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/a"}}})
	b, _ := es.Create(RuleExclusion{Name: "B", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/b"}}})
	c, _ := es.Create(RuleExclusion{Name: "C", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/c"}}})

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
	a, _ := es.Create(RuleExclusion{Name: "A", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/a"}}})
	es.Create(RuleExclusion{Name: "B", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/b"}}})

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
	es.Create(RuleExclusion{Name: "Enabled", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/1"}}})
	es.Create(RuleExclusion{Name: "Disabled", Type: "allow", Enabled: false, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/2"}}})

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
			name:    "valid allow with condition",
			exc:     RuleExclusion{Name: "test", Type: "allow", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api/"}}},
			wantErr: false,
		},
		{
			name:    "valid block with condition",
			exc:     RuleExclusion{Name: "test", Type: "block", Conditions: []Condition{{Field: "user_agent", Operator: "contains", Value: "BadBot"}}},
			wantErr: false,
		},
		{
			name:    "missing name",
			exc:     RuleExclusion{Type: "allow", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/"}}},
			wantErr: true,
		},
		{
			name:    "invalid type",
			exc:     RuleExclusion{Name: "test", Type: "invalid_type"},
			wantErr: true,
		},
		{
			name:    "allow missing conditions",
			exc:     RuleExclusion{Name: "test", Type: "allow"},
			wantErr: true,
		},
		{
			name:    "block missing conditions",
			exc:     RuleExclusion{Name: "test", Type: "block"},
			wantErr: true,
		},
		// Detect type validation
		{
			name:    "valid detect NOTICE",
			exc:     RuleExclusion{Name: "test", Type: "detect", Severity: "NOTICE", Conditions: []Condition{{Field: "user_agent", Operator: "eq", Value: ""}}},
			wantErr: false,
		},
		{
			name:    "valid detect WARNING with PL",
			exc:     RuleExclusion{Name: "test", Type: "detect", Severity: "WARNING", DetectParanoiaLevel: 2, Conditions: []Condition{{Field: "header", Operator: "eq", Value: "Accept:"}}},
			wantErr: false,
		},
		{
			name:    "valid detect CRITICAL",
			exc:     RuleExclusion{Name: "test", Type: "detect", Severity: "CRITICAL", Conditions: []Condition{{Field: "path", Operator: "regex", Value: "/admin"}}},
			wantErr: false,
		},
		{
			name:    "detect missing severity",
			exc:     RuleExclusion{Name: "test", Type: "detect", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}}},
			wantErr: true,
		},
		{
			name:    "detect invalid severity",
			exc:     RuleExclusion{Name: "test", Type: "detect", Severity: "HIGH", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}}},
			wantErr: true,
		},
		{
			name:    "detect missing conditions",
			exc:     RuleExclusion{Name: "test", Type: "detect", Severity: "WARNING"},
			wantErr: true,
		},
		{
			name:    "detect invalid paranoia level",
			exc:     RuleExclusion{Name: "test", Type: "detect", Severity: "ERROR", DetectParanoiaLevel: 5, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}}},
			wantErr: true,
		},
		{
			name:    "detect paranoia level zero uses all",
			exc:     RuleExclusion{Name: "test", Type: "detect", Severity: "NOTICE", DetectParanoiaLevel: 0, Conditions: []Condition{{Field: "method", Operator: "eq", Value: "GET"}}},
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

	body := `{"name":"Test","type":"allow","enabled":true,"conditions":[{"field":"path","operator":"eq","value":"/health"}]}`
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

	body := `{"name":"","type":"allow","conditions":[{"field":"path","operator":"eq","value":"/"}]}`
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
	body := `{"name":"Flow Test","type":"allow","enabled":true,"conditions":[{"field":"path","operator":"eq","value":"/api"}]}`
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
	body = `{"name":"Updated Flow Test","type":"allow","enabled":false,"conditions":[{"field":"path","operator":"eq","value":"/api"}]}`
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
	es.Create(RuleExclusion{Name: "Export1", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/health"}}})
	es.Create(RuleExclusion{Name: "Export2", Type: "block", Enabled: true, Conditions: []Condition{{Field: "user_agent", Operator: "contains", Value: "BadBot"}}})

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

	a, _ := es.Create(RuleExclusion{Name: "A", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/a"}}})
	b, _ := es.Create(RuleExclusion{Name: "B", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/b"}}})
	c, _ := es.Create(RuleExclusion{Name: "C", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/c"}}})

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

func TestValidateExclusion_SecRuleInjection(t *testing.T) {
	tests := []struct {
		name    string
		exc     RuleExclusion
		wantErr string
	}{
		{
			name:    "newline in name",
			exc:     RuleExclusion{Name: "evil\nSecRule", Type: "allow", Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/"}}},
			wantErr: "newlines",
		},

		{
			name: "newline in condition value",
			exc: RuleExclusion{
				Name: "test", Type: "allow",
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api\n"}},
			},
			wantErr: "control character",
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
	es.Create(RuleExclusion{Name: "Allow uploads", Type: "allow", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/uploads"}}})
	es.Create(RuleExclusion{Name: "Skip CRS 942200", Type: "detect", Severity: "WARNING", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/api"}}})

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
			EventType: "detect_block",
			RuleID:    942100,
		},
	}
	store.mu.Unlock()

	als := emptyAccessLogStore(t)
	handler := handleExclusionHits(store, als, es)

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
		EventType: "detect_block",
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

// --- Transform Validation Tests ---

func TestTransformValidation(t *testing.T) {
	tests := []struct {
		name    string
		conds   []Condition
		wantErr bool
		errMsg  string
	}{
		{
			name: "no transforms",
			conds: []Condition{
				{Field: "path", Operator: "eq", Value: "/test"},
			},
			wantErr: false,
		},
		{
			name: "single valid transform",
			conds: []Condition{
				{Field: "path", Operator: "contains", Value: "admin", Transforms: []string{"lowercase"}},
			},
			wantErr: false,
		},
		{
			name: "multiple valid transforms",
			conds: []Condition{
				{Field: "user_agent", Operator: "regex", Value: "bot", Transforms: []string{"lowercase", "urlDecode", "htmlEntityDecode"}},
			},
			wantErr: false,
		},
		{
			name: "all phase 1 transforms",
			conds: []Condition{
				{Field: "path", Operator: "contains", Value: "test", Transforms: []string{
					"lowercase", "urlDecode", "urlDecodeUni", "htmlEntityDecode",
					"normalizePath", "normalizePathWin", "removeNulls",
					"compressWhitespace", "removeWhitespace",
				}},
			},
			wantErr: false,
		},
		{
			name: "all phase 2 transforms",
			conds: []Condition{
				{Field: "body", Operator: "contains", Value: "test", Transforms: []string{
					"base64Decode", "hexDecode", "jsDecode", "cssDecode",
					"utf8toUnicode", "removeComments", "trim", "length",
				}},
			},
			wantErr: false,
		},
		{
			name: "unknown transform",
			conds: []Condition{
				{Field: "path", Operator: "eq", Value: "/test", Transforms: []string{"noSuchTransform"}},
			},
			wantErr: true,
			errMsg:  `unknown transform "noSuchTransform"`,
		},
		{
			name: "valid then invalid transform",
			conds: []Condition{
				{Field: "path", Operator: "eq", Value: "/test", Transforms: []string{"lowercase", "bogus"}},
			},
			wantErr: true,
			errMsg:  `unknown transform "bogus"`,
		},
		{
			name: "empty string transform",
			conds: []Condition{
				{Field: "path", Operator: "eq", Value: "/test", Transforms: []string{""}},
			},
			wantErr: true,
			errMsg:  `unknown transform ""`,
		},
		{
			name: "case sensitive transform name",
			conds: []Condition{
				{Field: "path", Operator: "eq", Value: "/test", Transforms: []string{"Lowercase"}},
			},
			wantErr: true,
			errMsg:  `unknown transform "Lowercase"`,
		},
		{
			name: "transform on second condition only",
			conds: []Condition{
				{Field: "path", Operator: "eq", Value: "/test"},
				{Field: "user_agent", Operator: "contains", Value: "bot", Transforms: []string{"lowercase"}},
			},
			wantErr: false,
		},
		{
			name: "invalid transform on second condition",
			conds: []Condition{
				{Field: "path", Operator: "eq", Value: "/test", Transforms: []string{"lowercase"}},
				{Field: "user_agent", Operator: "contains", Value: "bot", Transforms: []string{"bad"}},
			},
			wantErr: true,
			errMsg:  `condition[1]: unknown transform "bad"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConditions(tt.conds, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConditions() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestValidateExclusion_WithTransforms(t *testing.T) {
	tests := []struct {
		name    string
		exc     RuleExclusion
		wantErr bool
	}{
		{
			name: "block with transforms",
			exc: RuleExclusion{
				Name: "test", Type: "block",
				Conditions: []Condition{
					{Field: "path", Operator: "contains", Value: "/admin", Transforms: []string{"lowercase", "urlDecode"}},
				},
			},
			wantErr: false,
		},
		{
			name: "allow with transforms",
			exc: RuleExclusion{
				Name: "test", Type: "allow",
				Conditions: []Condition{
					{Field: "user_agent", Operator: "eq", Value: "goodbot", Transforms: []string{"lowercase"}},
				},
			},
			wantErr: false,
		},
		{
			name: "detect with transforms",
			exc: RuleExclusion{
				Name: "test", Type: "detect", Severity: "WARNING",
				Conditions: []Condition{
					{Field: "header", Operator: "eq", Value: "Accept:", Transforms: []string{"trim"}},
				},
			},
			wantErr: false,
		},
		{
			name: "detect with transforms",
			exc: RuleExclusion{
				Name: "test", Type: "detect", Severity: "ERROR",
				Conditions: []Condition{
					{Field: "path", Operator: "regex", Value: "(?i)\\.(php|asp)", Transforms: []string{"urlDecode", "normalizePath"}},
				},
			},
			wantErr: false,
		},
		{
			name: "block with invalid transform rejected",
			exc: RuleExclusion{
				Name: "test", Type: "block",
				Conditions: []Condition{
					{Field: "path", Operator: "eq", Value: "/test", Transforms: []string{"INVALID"}},
				},
			},
			wantErr: true,
		},
		{
			name: "detect with transforms and severity",
			exc: RuleExclusion{
				Name: "test", Type: "detect", Severity: "NOTICE",
				Conditions: []Condition{
					{Field: "path", Operator: "eq", Value: "/api", Transforms: []string{"lowercase"}},
				},
			},
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

func TestTransformPassthroughInPolicyGenerator(t *testing.T) {
	conditions := []Condition{
		{Field: "path", Operator: "contains", Value: "/admin", Transforms: []string{"lowercase", "urlDecode"}},
		{Field: "user_agent", Operator: "regex", Value: "bot", Transforms: []string{"htmlEntityDecode"}},
		{Field: "method", Operator: "eq", Value: "GET"},
	}

	result := convertConditions(conditions, nil)

	if len(result) != 3 {
		t.Fatalf("got %d conditions, want 3", len(result))
	}

	// First condition: 2 transforms
	if len(result[0].Transforms) != 2 {
		t.Errorf("result[0] transforms = %v, want 2 items", result[0].Transforms)
	}
	if result[0].Transforms[0] != "lowercase" || result[0].Transforms[1] != "urlDecode" {
		t.Errorf("result[0] transforms = %v, want [lowercase urlDecode]", result[0].Transforms)
	}

	// Second condition: 1 transform
	if len(result[1].Transforms) != 1 || result[1].Transforms[0] != "htmlEntityDecode" {
		t.Errorf("result[1] transforms = %v, want [htmlEntityDecode]", result[1].Transforms)
	}

	// Third condition: no transforms
	if len(result[2].Transforms) != 0 {
		t.Errorf("result[2] transforms = %v, want empty", result[2].Transforms)
	}
}

// ─── v0.9.0 Validation Tests ──────────────────────────────────────

func TestValidateConditions_AggregateFields(t *testing.T) {
	tests := []struct {
		name    string
		conds   []Condition
		wantErr bool
	}{
		{
			name:  "all_args with contains",
			conds: []Condition{{Field: "all_args", Operator: "contains", Value: "select"}},
		},
		{
			name:  "all_headers_names with regex",
			conds: []Condition{{Field: "all_headers_names", Operator: "regex", Value: "^X-"}},
		},
		{
			name:  "all_cookies with eq",
			conds: []Condition{{Field: "all_cookies", Operator: "eq", Value: "malicious"}},
		},
		{
			name:    "aggregate not in validConditionFields (SecRule)",
			conds:   []Condition{{Field: "all_args", Operator: "contains", Value: "x"}},
			wantErr: true, // all_args is NOT in validConditionFields (SecRule doesn't support it)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test with policy engine fields (should pass for aggregate fields)
			if !tt.wantErr {
				err := validateConditions(tt.conds, validPolicyEngineFields)
				if err != nil {
					t.Errorf("policy engine validation: unexpected error: %v", err)
				}
			}
			// Test with nil (validConditionFields) — aggregate fields are not in SecRule field set
			if tt.wantErr {
				err := validateConditions(tt.conds, nil)
				if err == nil {
					t.Error("expected error for aggregate field with SecRule validation")
				}
			}
		})
	}
}

func TestValidateConditions_PhraseMatch(t *testing.T) {
	tests := []struct {
		name    string
		conds   []Condition
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid phrase_match",
			conds: []Condition{{
				Field: "all_args", Operator: "phrase_match",
				ListItems: []string{"select", "union", "insert"},
			}},
		},
		{
			name: "phrase_match without list_items",
			conds: []Condition{{
				Field: "all_args", Operator: "phrase_match", Value: "",
			}},
			wantErr: true,
			errMsg:  "phrase_match requires list_items",
		},
		{
			name: "phrase_match on single field",
			conds: []Condition{{
				Field: "query", Operator: "phrase_match",
				ListItems: []string{"select", "union"},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConditions(tt.conds, validPolicyEngineFields)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestValidateConditions_NumericOperators(t *testing.T) {
	tests := []struct {
		name    string
		conds   []Condition
		wantErr bool
		errMsg  string
	}{
		{
			name:  "gt with numeric value",
			conds: []Condition{{Field: "header", Operator: "gt", Value: "Content-Length:100"}},
		},
		{
			name:    "gt with non-numeric value",
			conds:   []Condition{{Field: "header", Operator: "gt", Value: "Content-Length:abc"}},
			wantErr: true,
			errMsg:  "numeric operator",
		},
		{
			name:  "le with zero",
			conds: []Condition{{Field: "header", Operator: "le", Value: "X-Count:0"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConditions(tt.conds, validPolicyEngineFields)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestValidateConditions_CountField(t *testing.T) {
	tests := []struct {
		name    string
		conds   []Condition
		wantErr bool
		errMsg  string
	}{
		{
			name:  "valid count:all_args with gt",
			conds: []Condition{{Field: "count:all_args", Operator: "gt", Value: "255"}},
		},
		{
			name:  "valid count:all_headers with le",
			conds: []Condition{{Field: "count:all_headers", Operator: "le", Value: "50"}},
		},
		{
			name:    "count: with non-aggregate field",
			conds:   []Condition{{Field: "count:path", Operator: "gt", Value: "10"}},
			wantErr: true,
			errMsg:  "count: requires an aggregate field",
		},
		{
			name:    "count: with non-numeric operator",
			conds:   []Condition{{Field: "count:all_args", Operator: "contains", Value: "10"}},
			wantErr: true,
			errMsg:  "count: fields require a numeric operator",
		},
		{
			name:    "count: with non-numeric value",
			conds:   []Condition{{Field: "count:all_args", Operator: "gt", Value: "abc"}},
			wantErr: true,
			errMsg:  "numeric operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConditions(tt.conds, validPolicyEngineFields)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestConvertConditions_PhraseMatch(t *testing.T) {
	conds := []Condition{
		{
			Field:     "all_args",
			Operator:  "phrase_match",
			ListItems: []string{"select", "union", "drop"},
		},
	}
	result := convertConditions(conds, nil)
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if len(result[0].ListItems) != 3 {
		t.Errorf("ListItems should be passed through, got %v", result[0].ListItems)
	}
	if result[0].ListItems[0] != "select" {
		t.Errorf("ListItems[0] = %q, want select", result[0].ListItems[0])
	}
}

// ─── Bulk Actions Tests ───────────────────────────────────────────

func TestExclusionBulkUpdate(t *testing.T) {
	es := newTestExclusionStore(t)

	// Create 3 exclusions.
	ids := make([]string, 3)
	for i := 0; i < 3; i++ {
		e, err := es.Create(RuleExclusion{
			Name:       fmt.Sprintf("test-%d", i),
			Type:       "allow",
			Conditions: []Condition{{Field: "path", Operator: "eq", Value: fmt.Sprintf("/test%d", i)}},
			Enabled:    true,
		})
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		ids[i] = e.ID
	}

	t.Run("disable", func(t *testing.T) {
		changed, err := es.BulkUpdate(ids[:2], "disable")
		if err != nil {
			t.Fatalf("BulkUpdate disable: %v", err)
		}
		if changed != 2 {
			t.Errorf("expected 2 changed, got %d", changed)
		}
		for _, id := range ids[:2] {
			e, ok := es.Get(id)
			if !ok {
				t.Fatalf("exclusion %s not found", id)
			}
			if e.Enabled {
				t.Errorf("exclusion %s should be disabled", id)
			}
		}
		// Third should still be enabled.
		e, _ := es.Get(ids[2])
		if !e.Enabled {
			t.Error("third exclusion should still be enabled")
		}
	})

	t.Run("enable", func(t *testing.T) {
		changed, err := es.BulkUpdate(ids[:2], "enable")
		if err != nil {
			t.Fatalf("BulkUpdate enable: %v", err)
		}
		if changed != 2 {
			t.Errorf("expected 2 changed, got %d", changed)
		}
	})

	t.Run("delete", func(t *testing.T) {
		changed, err := es.BulkUpdate(ids[:2], "delete")
		if err != nil {
			t.Fatalf("BulkUpdate delete: %v", err)
		}
		if changed != 2 {
			t.Errorf("expected 2 changed, got %d", changed)
		}
		if len(es.List()) != 1 {
			t.Errorf("expected 1 remaining, got %d", len(es.List()))
		}
	})

	t.Run("invalid_action", func(t *testing.T) {
		_, err := es.BulkUpdate([]string{"x"}, "invalid")
		if err == nil {
			t.Error("expected error for invalid action")
		}
	})
}

func TestHandleBulkExclusions(t *testing.T) {
	es := newTestExclusionStore(t)

	// Create test exclusions.
	ids := make([]string, 2)
	for i := 0; i < 2; i++ {
		e, _ := es.Create(RuleExclusion{
			Name:       fmt.Sprintf("test-%d", i),
			Type:       "allow",
			Conditions: []Condition{{Field: "path", Operator: "eq", Value: fmt.Sprintf("/test%d", i)}},
			Enabled:    true,
		})
		ids[i] = e.ID
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/exclusions/bulk", handleBulkExclusions(es))

	t.Run("disable", func(t *testing.T) {
		body := fmt.Sprintf(`{"ids":[%q,%q],"action":"disable"}`, ids[0], ids[1])
		req := httptest.NewRequest("POST", "/api/exclusions/bulk", strings.NewReader(body))
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

	t.Run("empty_ids", func(t *testing.T) {
		body := `{"ids":[],"action":"disable"}`
		req := httptest.NewRequest("POST", "/api/exclusions/bulk", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("invalid_action", func(t *testing.T) {
		body := `{"ids":["x"],"action":"nuke"}`
		req := httptest.NewRequest("POST", "/api/exclusions/bulk", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})
}
