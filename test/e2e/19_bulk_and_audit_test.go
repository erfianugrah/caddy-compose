package e2e_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// ─── Item 4: CRS Default Rules Bulk Actions ────────────────────────

func TestDefaultRulesBulk(t *testing.T) {
	// Get some rule IDs from the catalog.
	resp, body := httpGet(t, wafctlURL+"/api/default-rules")
	assertCode(t, "list default rules", 200, resp)
	var rules []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &rules); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rules) < 3 {
		t.Fatalf("need at least 3 default rules, got %d", len(rules))
	}
	ids := []string{rules[0].ID, rules[1].ID, rules[2].ID}

	t.Run("bulk override", func(t *testing.T) {
		payload := map[string]any{
			"ids":    ids,
			"action": "override",
			"override": map[string]any{
				"enabled": false,
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/default-rules/bulk", payload)
		assertCode(t, "bulk override", 200, resp)
		count := jsonInt(body, "changed")
		if count != 3 {
			t.Errorf("expected 3 changed, got %d", count)
		}

		// Verify one of the overridden rules is now disabled.
		resp2, body2 := httpGet(t, wafctlURL+"/api/default-rules/"+ids[0])
		assertCode(t, "get overridden rule", 200, resp2)
		if enabled, found := jsonFieldBool(body2, "enabled"); found && enabled {
			t.Error("expected rule to be disabled after bulk override")
		}
	})

	t.Run("bulk reset", func(t *testing.T) {
		payload := map[string]any{
			"ids":    ids,
			"action": "reset",
		}
		resp, body := httpPost(t, wafctlURL+"/api/default-rules/bulk", payload)
		assertCode(t, "bulk reset", 200, resp)
		count := jsonInt(body, "removed")
		if count != 3 {
			t.Errorf("expected 3 removed, got %d", count)
		}
	})

	t.Run("invalid action rejected", func(t *testing.T) {
		payload := map[string]any{
			"ids":    ids,
			"action": "destroy",
		}
		code, _ := httpPostRaw(wafctlURL+"/api/default-rules/bulk", mustMarshal(payload))
		if code != 400 {
			t.Errorf("expected 400 for invalid action, got %d", code)
		}
	})

	t.Run("empty ids rejected", func(t *testing.T) {
		payload := map[string]any{
			"ids":    []string{},
			"action": "override",
			"override": map[string]any{
				"enabled": false,
			},
		}
		code, _ := httpPostRaw(wafctlURL+"/api/default-rules/bulk", mustMarshal(payload))
		if code != 400 {
			t.Errorf("expected 400 for empty ids, got %d", code)
		}
	})
}

// ─── Item 5: Exclusion Bulk Actions ────────────────────────────────

func TestExclusionBulk(t *testing.T) {
	// Create 3 test exclusions.
	var ids []string
	for i := 0; i < 3; i++ {
		payload := map[string]any{
			"name":     fmt.Sprintf("e2e-bulk-%d-%d", i, time.Now().UnixNano()),
			"type":     "allow",
			"enabled":  true,
			"priority": 200,
			"conditions": []map[string]any{
				{"field": "path", "operator": "eq", "value": fmt.Sprintf("/e2e-bulk-test-%d", i)},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "create exclusion", 201, resp)
		ids = append(ids, mustGetID(t, body))
	}
	t.Cleanup(func() {
		for _, id := range ids {
			cleanup(t, wafctlURL+"/api/exclusions/"+id)
		}
	})

	t.Run("bulk disable", func(t *testing.T) {
		payload := map[string]any{
			"ids":    ids,
			"action": "disable",
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions/bulk", payload)
		assertCode(t, "bulk disable", 200, resp)
		count := jsonInt(body, "changed")
		if count != 3 {
			t.Errorf("expected 3 changed, got %d", count)
		}

		// Verify disabled.
		resp2, body2 := httpGet(t, wafctlURL+"/api/exclusions/"+ids[0])
		assertCode(t, "get disabled exclusion", 200, resp2)
		if enabled, found := jsonFieldBool(body2, "enabled"); found && enabled {
			t.Error("expected exclusion to be disabled")
		}
	})

	t.Run("bulk enable", func(t *testing.T) {
		payload := map[string]any{
			"ids":    ids,
			"action": "enable",
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions/bulk", payload)
		assertCode(t, "bulk enable", 200, resp)
		count := jsonInt(body, "changed")
		if count != 3 {
			t.Errorf("expected 3 changed, got %d", count)
		}
	})

	t.Run("bulk delete", func(t *testing.T) {
		payload := map[string]any{
			"ids":    ids,
			"action": "delete",
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions/bulk", payload)
		assertCode(t, "bulk delete", 200, resp)
		count := jsonInt(body, "changed")
		if count != 3 {
			t.Errorf("expected 3 changed, got %d", count)
		}

		// Verify deleted — GET should 404.
		code, _ := httpGetCode(wafctlURL + "/api/exclusions/" + ids[0])
		if code != 404 {
			t.Errorf("expected 404 after delete, got %d", code)
		}
		// Clear cleanup since already deleted.
		ids = nil
	})

	t.Run("invalid action rejected", func(t *testing.T) {
		payload := map[string]any{
			"ids":    []string{"fake-id"},
			"action": "nuke",
		}
		code, _ := httpPostRaw(wafctlURL+"/api/exclusions/bulk", mustMarshal(payload))
		if code != 400 {
			t.Errorf("expected 400 for invalid action, got %d", code)
		}
	})
}

// ─── Item 6: RequestID Propagation ─────────────────────────────────

func TestEventRequestID(t *testing.T) {
	// Trigger a WAF event that will have a request_id (from Caddy's UUID).
	sentinel := fmt.Sprintf("e2e-reqid-%d", time.Now().UnixNano())
	req := mustNewRequest(t, "GET", caddyURL+"/get?id=<script>alert(1)</script>")
	setBrowserHeaders(req)
	req.Header.Set("User-Agent", sentinel)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	// Wait for the event to appear.
	evt := waitForEvent(t, sentinel, 15*time.Second)
	if evt == nil {
		t.Fatal("event not found")
	}

	// Check request_id is present (Caddy generates a UUID per request).
	reqID, _ := evt["request_id"].(string)
	if reqID == "" {
		t.Error("expected non-empty request_id on event")
	}
}

// ─── Item 7: UI Served by wafctl ───────────────────────────────────

func TestWafctlServesUI(t *testing.T) {
	// The dashboard is now served by wafctl directly (not Caddy file_server).
	// Test that wafctl serves the UI pages on its own port.
	tests := []struct {
		name string
		path string
		want int
	}{
		{"root index", "/", 200},
		{"events page", "/events", 200},
		{"policy page", "/policy", 200},
		{"rate-limits page", "/rate-limits", 200},
		{"api still works", "/api/health", 200},
		{"404 for unknown", "/nonexistent-page", 404},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := httpGetCode(wafctlURL + tt.path)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			if code != tt.want {
				t.Errorf("GET %s: expected %d, got %d", tt.path, tt.want, code)
			}
		})
	}
}

// TestDashboardViaProxy verifies the dashboard is accessible through Caddy's
// reverse proxy to wafctl (the production path).
func TestDashboardViaProxy(t *testing.T) {
	tests := []struct {
		name string
		path string
		want int
	}{
		{"root", "/", 200},
		{"events", "/events", 200},
		{"rules/crs", "/rules/crs", 200},
		{"404", "/nonexistent", 404},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := httpGetCode(dashURL + tt.path)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			if code != tt.want {
				t.Errorf("GET %s: expected %d, got %d", tt.path, tt.want, code)
			}
		})
	}
}

// ─── Backup / Restore ──────────────────────────────────────────────

func TestBackupRestore(t *testing.T) {
	t.Run("export backup", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/backup")
		assertCode(t, "backup", 200, resp)

		// Should contain top-level keys for all stores.
		var backup map[string]json.RawMessage
		if err := json.Unmarshal(body, &backup); err != nil {
			t.Fatalf("unmarshal backup: %v", err)
		}
		for _, key := range []string{"waf_config", "exclusions", "rate_limits", "csp_config", "security_headers", "lists"} {
			if _, ok := backup[key]; !ok {
				t.Errorf("backup missing key %q", key)
			}
		}
	})

	t.Run("restore accepts backup", func(t *testing.T) {
		// First export.
		_, body := httpGet(t, wafctlURL+"/api/backup")
		// Re-import (idempotent).
		var backup map[string]json.RawMessage
		json.Unmarshal(body, &backup)
		resp2, _ := httpPost(t, wafctlURL+"/api/backup/restore", backup)
		assertCode(t, "restore", 200, resp2)
	})
}

// ─── Security Headers API ──────────────────────────────────────────

func TestSecurityHeadersAPI(t *testing.T) {
	t.Run("GET profiles", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/security-headers/profiles")
		assertCode(t, "profiles", 200, resp)
		if jsonArrayLen(body) == 0 {
			t.Error("expected at least one profile")
		}
	})

	t.Run("GET config", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/security-headers")
		assertCode(t, "get security headers", 200, resp)
	})

	t.Run("GET preview", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/security-headers/preview")
		assertCode(t, "preview", 200, resp)
	})
}

// ─── Helper ────────────────────────────────────────────────────────

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
