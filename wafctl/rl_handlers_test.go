package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── Rate Limit Rule Handler Tests ──────────────────────────────────

func setupRLRuleMux(t *testing.T) (*http.ServeMux, *RateLimitRuleStore) {
	t.Helper()
	rs := newTestRLRuleStore(t)
	als := emptyAccessLogStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rate-rules", handleListRLRules(rs))
	mux.HandleFunc("POST /api/rate-rules", handleCreateRLRule(rs))
	mux.HandleFunc("GET /api/rate-rules/export", handleExportRLRules(rs))
	mux.HandleFunc("POST /api/rate-rules/import", handleImportRLRules(rs))
	mux.HandleFunc("GET /api/rate-rules/global", handleGetRLGlobal(rs))
	mux.HandleFunc("PUT /api/rate-rules/global", handleUpdateRLGlobal(rs))
	mux.HandleFunc("GET /api/rate-rules/hits", handleRLRuleHits(als, rs))
	mux.HandleFunc("GET /api/rate-rules/{id}", handleGetRLRule(rs))
	mux.HandleFunc("PUT /api/rate-rules/{id}", handleUpdateRLRule(rs))
	mux.HandleFunc("DELETE /api/rate-rules/{id}", handleDeleteRLRule(rs))
	return mux, rs
}

func TestRLRuleHandlerCRUD(t *testing.T) {
	mux, _ := setupRLRuleMux(t)

	// List — empty.
	req := httptest.NewRequest("GET", "/api/rate-rules", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("list: want 200, got %d", w.Code)
	}
	var list []RateLimitRule
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 0 {
		t.Fatalf("want empty list, got %d", len(list))
	}

	// Create.
	body := `{"name":"api-limit","service":"sonarr.erfi.io","key":"client_ip","events":100,"window":"1m","action":"deny","enabled":true}`
	req = httptest.NewRequest("POST", "/api/rate-rules", strings.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("create: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var created RateLimitRule
	json.NewDecoder(w.Body).Decode(&created)
	if created.ID == "" {
		t.Fatal("created rule should have an ID")
	}
	if created.Name != "api-limit" {
		t.Errorf("name: want %q, got %q", "api-limit", created.Name)
	}

	// Get.
	req = httptest.NewRequest("GET", "/api/rate-rules/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("get: want 200, got %d", w.Code)
	}
	var got RateLimitRule
	json.NewDecoder(w.Body).Decode(&got)
	if got.ID != created.ID {
		t.Errorf("get: want ID %q, got %q", created.ID, got.ID)
	}

	// Get — not found.
	req = httptest.NewRequest("GET", "/api/rate-rules/nonexistent", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("get not found: want 404, got %d", w.Code)
	}

	// Update.
	updateBody := `{"name":"renamed","service":"sonarr.erfi.io","key":"client_ip","events":500,"window":"30s","action":"deny","enabled":true}`
	req = httptest.NewRequest("PUT", "/api/rate-rules/"+created.ID, strings.NewReader(updateBody))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("update: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var updated RateLimitRule
	json.NewDecoder(w.Body).Decode(&updated)
	if updated.Name != "renamed" {
		t.Errorf("update: want name %q, got %q", "renamed", updated.Name)
	}
	if updated.Events != 500 {
		t.Errorf("update: want events 500, got %d", updated.Events)
	}

	// Update — not found.
	req = httptest.NewRequest("PUT", "/api/rate-rules/nonexistent", strings.NewReader(updateBody))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("update not found: want 404, got %d", w.Code)
	}

	// Delete.
	req = httptest.NewRequest("DELETE", "/api/rate-rules/"+created.ID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("delete: want 200, got %d", w.Code)
	}

	// Verify empty.
	req = httptest.NewRequest("GET", "/api/rate-rules", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 0 {
		t.Fatalf("want empty list after delete, got %d", len(list))
	}

	// Delete — not found.
	req = httptest.NewRequest("DELETE", "/api/rate-rules/nonexistent", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("delete not found: want 404, got %d", w.Code)
	}
}

func TestRLRuleHandlerCreateValidation(t *testing.T) {
	mux, _ := setupRLRuleMux(t)

	// Missing required fields.
	body := `{"name":"","service":"","key":"","events":0,"window":""}`
	req := httptest.NewRequest("POST", "/api/rate-rules", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("validation: want 400, got %d: %s", w.Code, w.Body.String())
	}

	// Invalid JSON.
	req = httptest.NewRequest("POST", "/api/rate-rules", strings.NewReader("{bad json"))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("bad json: want 400, got %d", w.Code)
	}
}

func TestRLRuleHandlerGlobalConfig(t *testing.T) {
	mux, _ := setupRLRuleMux(t)

	// Get global — starts as zero value.
	req := httptest.NewRequest("GET", "/api/rate-rules/global", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("get global: want 200, got %d", w.Code)
	}

	// Update global.
	body := `{"jitter":0.5,"sweep_interval":"30s","distributed":true,"read_interval":"5s","write_interval":"10s","purge_age":"1m"}`
	req = httptest.NewRequest("PUT", "/api/rate-rules/global", strings.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("update global: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var got RateLimitGlobalConfig
	json.NewDecoder(w.Body).Decode(&got)
	if got.Jitter != 0.5 {
		t.Errorf("want jitter 0.5, got %f", got.Jitter)
	}
	if !got.Distributed {
		t.Error("want distributed true")
	}

	// Update global — invalid.
	body = `{"jitter":2.0}`
	req = httptest.NewRequest("PUT", "/api/rate-rules/global", strings.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("invalid global: want 400, got %d", w.Code)
	}
}

func TestRLRuleHandlerExportImport(t *testing.T) {
	mux, _ := setupRLRuleMux(t)

	// Create a rule first.
	body := `{"name":"test","service":"sonarr.erfi.io","key":"client_ip","events":100,"window":"1m","action":"deny","enabled":true}`
	req := httptest.NewRequest("POST", "/api/rate-rules", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Export.
	req = httptest.NewRequest("GET", "/api/rate-rules/export", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("export: want 200, got %d", w.Code)
	}
	var exported RateLimitRuleExport
	json.NewDecoder(w.Body).Decode(&exported)
	if exported.Version != 1 {
		t.Errorf("export version: want 1, got %d", exported.Version)
	}
	if len(exported.Rules) != 1 {
		t.Fatalf("export: want 1 rule, got %d", len(exported.Rules))
	}

	// Import (replaces all).
	importBody := `{"version":1,"rules":[{"name":"imported","service":"radarr.erfi.io","key":"client_ip","events":200,"window":"30s","action":"deny","enabled":true}]}`
	req = httptest.NewRequest("POST", "/api/rate-rules/import", strings.NewReader(importBody))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("import: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify import replaced.
	req = httptest.NewRequest("GET", "/api/rate-rules", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var list []RateLimitRule
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("after import: want 1 rule, got %d", len(list))
	}
	if list[0].Name != "imported" {
		t.Errorf("after import: want name %q, got %q", "imported", list[0].Name)
	}
}

func TestRLRuleHandlerImportValidation(t *testing.T) {
	mux, _ := setupRLRuleMux(t)

	// Import with invalid rule.
	body := `{"version":1,"rules":[{"name":"","service":"","key":"","events":0,"window":""}]}`
	req := httptest.NewRequest("POST", "/api/rate-rules/import", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("import validation: want 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRLRuleHandlerHits(t *testing.T) {
	mux, _ := setupRLRuleMux(t)

	// Hits — empty store.
	req := httptest.NewRequest("GET", "/api/rate-rules/hits?hours=24", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("hits: want 200, got %d", w.Code)
	}
}
