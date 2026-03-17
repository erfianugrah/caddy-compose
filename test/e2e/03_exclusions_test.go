package e2e_test

import (
	"net/http"
	"testing"
)

// ════════════════════════════════════════════════════════════════════
//  5. Exclusion CRUD
// ════════════════════════════════════════════════════════════════════

func TestExclusionCRUD(t *testing.T) {
	// List
	t.Run("list", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/exclusions")
		assertCode(t, "list", 200, resp)
		n := jsonArrayLen(body)
		t.Logf("existing exclusions: %d", n)
	})

	// Create — must return 201 Created
	var exclID string
	t.Run("create", func(t *testing.T) {
		payload := map[string]any{
			"name":        "e2e-test-allow",
			"type":        "allow",
			"description": "E2E test rule",
			"enabled":     true,
			"conditions":  []map[string]string{{"field": "path", "operator": "eq", "value": "/e2e-test"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "create exclusion", 201, resp)
		exclID = mustGetID(t, body)
		assertField(t, "create", body, "name", "e2e-test-allow")
		assertField(t, "create", body, "type", "allow")
		assertField(t, "create", body, "enabled", "true")
	})

	if exclID == "" {
		t.Fatal("no exclusion id, cannot continue CRUD tests")
	}
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Get
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/exclusions/"+exclID)
		assertCode(t, "get", 200, resp)
		assertField(t, "get", body, "name", "e2e-test-allow")
		assertField(t, "get", body, "id", exclID)
	})

	// Update (partial — toggle enabled)
	t.Run("update", func(t *testing.T) {
		resp, body := httpPut(t, wafctlURL+"/api/exclusions/"+exclID, map[string]any{"enabled": false})
		assertCode(t, "update", 200, resp)
		assertField(t, "update", body, "enabled", "false")
		// Name should be preserved from original
		assertField(t, "update", body, "name", "e2e-test-allow")
	})

	// Delete — must return 204 No Content
	t.Run("delete", func(t *testing.T) {
		resp, _ := httpDelete(t, wafctlURL+"/api/exclusions/"+exclID)
		assertCode(t, "delete exclusion", 204, resp)
		exclID = "" // prevent cleanup from double-deleting
	})
}

// ════════════════════════════════════════════════════════════════════
//  6. CRS Rules Catalog
// ════════════════════════════════════════════════════════════════════

func TestCRSRulesCatalog(t *testing.T) {
	t.Run("rules", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/crs/rules")
		assertCode(t, "rules", 200, resp)
		// Response is {categories: [...], rules: [...], total: N}
		total := jsonInt(body, "total")
		if total <= 0 {
			t.Errorf("expected CRS rules total > 0, got %d", total)
		}
	})

}

// ════════════════════════════════════════════════════════════════════
// 13. Exclusion Operations
// ════════════════════════════════════════════════════════════════════

func TestExclusionOperations(t *testing.T) {
	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/exclusions/export"},
		{"GET", "/api/exclusions/hits"},
	}
	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			var resp *http.Response
			if ep.method == "POST" {
				resp, _ = httpPost(t, wafctlURL+ep.path, struct{}{})
			} else {
				resp, _ = httpGet(t, wafctlURL+ep.path)
			}
			assertCode(t, ep.path, 200, resp)
		})
	}
}

// ════════════════════════════════════════════════════════════════════
// 14. WAF Dashboard UI
// ════════════════════════════════════════════════════════════════════
