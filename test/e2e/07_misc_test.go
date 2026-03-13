package e2e_test

import (
	"strings"
	"testing"
)

// ════════════════════════════════════════════════════════════════════
// 11. Blocklist
// ════════════════════════════════════════════════════════════════════

func TestBlocklist(t *testing.T) {
	t.Parallel()
	t.Run("stats", func(t *testing.T) {
		t.Parallel()
		resp, _ := httpGet(t, wafctlURL+"/api/blocklist/stats")
		assertCode(t, "stats", 200, resp)
	})

	t.Run("check clean IP", func(t *testing.T) {
		t.Parallel()
		resp, body := httpGet(t, wafctlURL+"/api/blocklist/check/8.8.8.8")
		assertCode(t, "check", 200, resp)
		assertField(t, "check", body, "blocked", "false")
	})
}

// ════════════════════════════════════════════════════════════════════
// 12. General Logs
// ════════════════════════════════════════════════════════════════════

func TestGeneralLogs(t *testing.T) {
	t.Parallel()
	t.Run("logs", func(t *testing.T) {
		t.Parallel()
		resp, _ := httpGet(t, wafctlURL+"/api/logs?hours=1")
		assertCode(t, "logs", 200, resp)
	})

	t.Run("summary", func(t *testing.T) {
		t.Parallel()
		resp, _ := httpGet(t, wafctlURL+"/api/logs/summary?hours=1")
		assertCode(t, "summary", 200, resp)
	})
}

// ════════════════════════════════════════════════════════════════════
// 14. WAF Dashboard UI
// ════════════════════════════════════════════════════════════════════

func TestWAFDashboardUI(t *testing.T) {
	t.Parallel()
	t.Run("index", func(t *testing.T) {
		t.Parallel()
		resp, body := httpGet(t, dashURL+"/")
		assertCode(t, "index", 200, resp)
		if !strings.Contains(string(body), "_astro/") {
			t.Error("expected _astro/ asset references in HTML")
		}
	})

	pages := []string{
		"analytics", "csp", "events", "headers", "lists",
		"logs", "policy", "rate-limits", "rules", "rules/crs", "services",
	}
	for _, page := range pages {
		t.Run(page, func(t *testing.T) {
			t.Parallel()
			resp, _ := httpGet(t, dashURL+"/"+page+"/")
			assertCode(t, page, 200, resp)
		})
	}

	t.Run("404", func(t *testing.T) {
		t.Parallel()
		code, err := httpGetCode(dashURL + "/nonexistent-page-xyz")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 404 {
			t.Errorf("expected 404, got %d", code)
		}
	})
}

// ════════════════════════════════════════════════════════════════════
// 15. Error Handling
// ════════════════════════════════════════════════════════════════════

func TestErrorHandling(t *testing.T) {
	t.Parallel()
	t.Run("invalid exclusion type", func(t *testing.T) {
		t.Parallel()
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", map[string]any{"name": "bad", "type": "invalid_type"})
		if resp.StatusCode != 400 {
			t.Errorf("expected 400 for invalid type, got %d", resp.StatusCode)
		}
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error field in response, got: %s", body)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()
		code, err := httpPostRaw(wafctlURL+"/api/exclusions", []byte("{invalid json}"))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 400 {
			t.Errorf("expected 400, got %d", code)
		}
	})

	t.Run("non-existent exclusion", func(t *testing.T) {
		t.Parallel()
		code, err := httpGetCode(wafctlURL + "/api/exclusions/nonexistent-id-12345")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 404 {
			t.Errorf("expected 404, got %d", code)
		}
	})

	t.Run("oversized body rejected", func(t *testing.T) {
		t.Parallel()
		// MaxBytesReader is set to 5MB. Send 6MB.
		largeBody := generateLargeBody(6_000_000)
		code, err := httpPostRaw(wafctlURL+"/api/exclusions", largeBody)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 400 {
			t.Errorf("expected 400 from MaxBytesReader, got %d", code)
		}
	})
}
