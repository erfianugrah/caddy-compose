package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	// Verify a known rule exists.
	found := false
	for _, r := range catalog.Rules {
		if r.ID == "920420" {
			found = true
			if r.Category != "protocol-enforcement" {
				t.Errorf("rule 920420: expected category protocol-enforcement, got %s", r.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected rule 920420 in catalog")
	}
}

// --- Rate Limit Store tests ---
