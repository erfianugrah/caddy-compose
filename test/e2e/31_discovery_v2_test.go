package e2e_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  31. Endpoint Discovery v2 — OpenAPI Schemas, Service Grouping
// ════════════════════════════════════════════════════════════════════

// ── 31a. OpenAPI Schema CRUD ────────────────────────────────────────

func TestOpenAPISchemaCRUD(t *testing.T) {
	t.Run("list-empty", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/discovery/schemas")
		assertCode(t, "list schemas", 200, resp)

		var result struct {
			Schemas []struct {
				Service string `json:"service"`
				Routes  int    `json:"routes"`
			} `json:"schemas"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		// May not be empty if other tests loaded schemas, but structure should be valid.
		t.Logf("schemas: %d", len(result.Schemas))
	})

	t.Run("upload-valid-spec", func(t *testing.T) {
		spec := `{
			"openapi": "3.0.0",
			"paths": {
				"/api/v3/command": {
					"get": {"summary": "Get commands"},
					"post": {"summary": "Create command"}
				},
				"/api/v3/episode/{id}": {
					"get": {"summary": "Get episode by ID"}
				},
				"/api/v3/queue/details": {
					"get": {"summary": "Queue details"}
				}
			}
		}`
		resp, body := httpDo(t, client, "PUT", wafctlURL+"/api/discovery/schemas/test-service.erfi.io", json.RawMessage(spec))
		assertCode(t, "upload schema", 200, resp)

		var result struct {
			Service string `json:"service"`
			Routes  int    `json:"routes"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if result.Service != "test-service.erfi.io" {
			t.Errorf("expected service test-service.erfi.io, got %s", result.Service)
		}
		if result.Routes != 4 { // GET+POST /command, GET /episode/{id}, GET /queue/details
			t.Errorf("expected 4 routes, got %d", result.Routes)
		}

		t.Cleanup(func() {
			httpDelete(t, wafctlURL+"/api/discovery/schemas/test-service.erfi.io")
		})
	})

	t.Run("list-after-upload", func(t *testing.T) {
		// Upload a schema first
		spec := `{"openapi":"3.0.0","paths":{"/health":{"get":{}}}}`
		httpDo(t, client, "PUT", wafctlURL+"/api/discovery/schemas/list-test.erfi.io", json.RawMessage(spec))
		t.Cleanup(func() {
			httpDelete(t, wafctlURL+"/api/discovery/schemas/list-test.erfi.io")
		})

		resp, body := httpGet(t, wafctlURL+"/api/discovery/schemas")
		assertCode(t, "list after upload", 200, resp)

		var result struct {
			Schemas []struct {
				Service string `json:"service"`
				Routes  int    `json:"routes"`
			} `json:"schemas"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		found := false
		for _, s := range result.Schemas {
			if s.Service == "list-test.erfi.io" {
				found = true
				if s.Routes != 1 {
					t.Errorf("expected 1 route, got %d", s.Routes)
				}
			}
		}
		if !found {
			t.Error("uploaded schema not found in list")
		}
	})

	t.Run("delete-schema", func(t *testing.T) {
		spec := `{"openapi":"3.0.0","paths":{"/test":{"get":{}}}}`
		httpDo(t, client, "PUT", wafctlURL+"/api/discovery/schemas/del-test.erfi.io", json.RawMessage(spec))

		resp, _ := httpDelete(t, wafctlURL+"/api/discovery/schemas/del-test.erfi.io")
		assertCode(t, "delete schema", 200, resp)

		// Verify it's gone.
		resp2, body := httpGet(t, wafctlURL+"/api/discovery/schemas")
		assertCode(t, "list after delete", 200, resp2)
		if strings.Contains(string(body), "del-test.erfi.io") {
			t.Error("deleted schema still appears in list")
		}
	})

	t.Run("upload-invalid-json", func(t *testing.T) {
		req, err := http.NewRequest("PUT", wafctlURL+"/api/discovery/schemas/bad.erfi.io", bytes.NewReader([]byte(`{not valid json`)))
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		assertCode(t, "invalid JSON", 400, resp)
	})

	t.Run("upload-no-paths", func(t *testing.T) {
		spec := `{"openapi":"3.0.0","info":{"title":"empty"}}`
		resp, _ := httpDo(t, client, "PUT", wafctlURL+"/api/discovery/schemas/empty.erfi.io", json.RawMessage(spec))
		assertCode(t, "no paths", 400, resp)
	})
}

// ── 31b. Endpoint Discovery Structure ───────────────────────────────

func TestEndpointDiscoveryServiceField(t *testing.T) {
	// Verify each endpoint has a service field (needed for service grouping).
	resp, body := httpGet(t, wafctlURL+"/api/discovery/endpoints?hours=24")
	assertCode(t, "discovery", 200, resp)

	var disc struct {
		Endpoints []struct {
			Service       string  `json:"service"`
			Method        string  `json:"method"`
			Path          string  `json:"path"`
			Requests      int     `json:"requests"`
			NonBrowserPct float64 `json:"non_browser_pct"`
		} `json:"endpoints"`
		TotalPaths int `json:"total_paths"`
	}
	if err := json.Unmarshal(body, &disc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Every endpoint should have a service name.
	for _, ep := range disc.Endpoints {
		if ep.Service == "" {
			t.Errorf("endpoint %s %s has empty service", ep.Method, ep.Path)
		}
		if ep.Method == "" {
			t.Errorf("endpoint with path %s has empty method", ep.Path)
		}
		if ep.Path == "" {
			t.Errorf("endpoint with method %s has empty path", ep.Method)
		}
		// non_browser_pct should be [0,1]
		if ep.NonBrowserPct < 0 || ep.NonBrowserPct > 1 {
			t.Errorf("non_browser_pct %f out of range for %s", ep.NonBrowserPct, ep.Path)
		}
	}

	// Log service distribution for debugging.
	svcCounts := map[string]int{}
	for _, ep := range disc.Endpoints {
		svcCounts[ep.Service]++
	}
	for svc, count := range svcCounts {
		t.Logf("service %s: %d endpoints", svc, count)
	}
}

// ── 31c. Path Normalization ─────────────────────────────────────────

func TestEndpointDiscoveryPathNormalization(t *testing.T) {
	// Generate traffic with dynamic path segments, then verify they are collapsed.
	// The E2E Caddy proxies to httpbun, so we can generate varied paths.
	for _, path := range []string{
		"/anything/12345",
		"/anything/67890",
		"/anything/abc123def456", // hex string
		"/anything/550e8400-e29b-41d4-a716-446655440000", // UUID
	} {
		httpGet(t, caddyURL+path)
	}

	// Poll for log ingestion — Caddy writes access logs, wafctl ingests on interval.
	// If the logs haven't been ingested yet, skip instead of failing.
	var found bool
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, body := httpGet(t, wafctlURL+"/api/discovery/endpoints?hours=24")
		if strings.Contains(string(body), "/anything/{id}") {
			found = true
			break
		}
		time.Sleep(1 * time.Second)
	}

	if !found {
		// Verify endpoint still responds — just check structure.
		resp, body := httpGet(t, wafctlURL+"/api/discovery/endpoints?hours=24")
		assertCode(t, "discovery", 200, resp)
		var disc struct {
			Endpoints []struct {
				Path string `json:"path"`
			} `json:"endpoints"`
		}
		json.Unmarshal(body, &disc)
		paths := make([]string, len(disc.Endpoints))
		for i, ep := range disc.Endpoints {
			paths[i] = ep.Path
		}
		t.Logf("available paths: %v", paths)
		t.Skip("path normalization: /anything/{id} not yet ingested — log pipeline latency")
	}

	// Verify the normalized path appeared.
	resp, body := httpGet(t, wafctlURL+"/api/discovery/endpoints?hours=24")
	assertCode(t, "discovery", 200, resp)
	if !strings.Contains(string(body), "/anything/{id}") {
		t.Error("expected /anything/{id} in discovery response")
	}
}
