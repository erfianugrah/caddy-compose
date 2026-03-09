// Package e2e_test contains end-to-end smoke tests for the full
// caddy-compose stack (Caddy + wafctl + httpbun).
//
// Prerequisites:
//
//	docker compose -f test/docker-compose.e2e.yml up -d --wait
//
// Run:
//
//	cd test/e2e && go test -v -count=1 -timeout 300s ./...
//
// Teardown:
//
//	docker compose -f test/docker-compose.e2e.yml down -v
package e2e_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  Service Readiness
// ════════════════════════════════════════════════════════════════════

func TestServiceReadiness(t *testing.T) {
	waitForService(t, "Caddy admin", caddyAdmin+"/config/", 60*time.Second)
	waitForService(t, "wafctl API", wafctlURL+"/api/health", 60*time.Second)
	waitForService(t, "httpbun upstream", caddyURL+"/get", 60*time.Second)
}

// ════════════════════════════════════════════════════════════════════
//  1. Health & Basics
// ════════════════════════════════════════════════════════════════════

func TestHealthAndBasics(t *testing.T) {
	t.Run("wafctl health", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/health")
		assertCode(t, "health", 200, resp)
		assertField(t, "health", body, "status", "ok")
	})

	t.Run("Caddy admin", func(t *testing.T) {
		resp, _ := httpGet(t, caddyAdmin+"/config/")
		assertCode(t, "caddy admin", 200, resp)
	})

	t.Run("proxy GET", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "proxy GET", 200, resp)
	})

	t.Run("proxy POST", func(t *testing.T) {
		resp, _ := httpPost(t, caddyURL+"/post", map[string]string{"hello": "world"})
		assertCode(t, "proxy POST", 200, resp)
	})

	t.Run("security headers", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		if !headerContains(resp, "X-Content-Type-Options", "nosniff") {
			t.Error("missing X-Content-Type-Options: nosniff")
		}
		if !headerContains(resp, "Strict-Transport-Security", "max-age=") {
			t.Error("missing HSTS header")
		}
	})
}

// ════════════════════════════════════════════════════════════════════
//  2. WAF Blocking
// ════════════════════════════════════════════════════════════════════

func TestWAFBlocking(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want int
	}{
		{"SQL injection", caddyURL + "/get?id=1%20OR%201=1%20--", 403},
		{"XSS", caddyURL + "/get?q=%3Cscript%3Ealert(1)%3C/script%3E", 403},
		{"path traversal", caddyURL + "/get?file=../../../../etc/passwd", 403},
		{"legitimate request", caddyURL + "/get?q=hello", 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := httpGetCode(tt.url)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			if code != tt.want {
				t.Errorf("expected %d, got %d", tt.want, code)
			}
		})
	}
}

// ════════════════════════════════════════════════════════════════════
//  3. WAF Events & Summary
// ════════════════════════════════════════════════════════════════════

func TestWAFEventsAndSummary(t *testing.T) {
	// Give the log tailer time to pick up the blocked requests from TestWAFBlocking.
	time.Sleep(4 * time.Second)

	t.Run("summary has events", func(t *testing.T) {
		_, body := httpGet(t, wafctlURL+"/api/summary?hours=1")
		total := jsonInt(body, "total_events")
		if total <= 0 {
			// Retry once — tailer may not have caught up.
			time.Sleep(5 * time.Second)
			_, body = httpGet(t, wafctlURL+"/api/summary?hours=1")
			total = jsonInt(body, "total_events")
			if total <= 0 {
				t.Errorf("expected total_events > 0, got %d", total)
			}
		}
	})

	t.Run("events endpoint", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/events?hours=1&limit=10")
		assertCode(t, "events", 200, resp)
	})

	t.Run("services endpoint", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/services")
		assertCode(t, "services", 200, resp)
	})
}

// ════════════════════════════════════════════════════════════════════
//  4. Analytics
// ════════════════════════════════════════════════════════════════════

func TestAnalytics(t *testing.T) {
	endpoints := []string{
		"/api/analytics/top-ips?hours=1",
		"/api/analytics/top-uris?hours=1",
		"/api/analytics/top-countries?hours=1",
		"/api/lookup/127.0.0.1",
	}
	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			resp, _ := httpGet(t, wafctlURL+ep)
			assertCode(t, ep, 200, resp)
		})
	}
}

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

	t.Run("autocomplete", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/crs/autocomplete")
		assertCode(t, "autocomplete", 200, resp)
	})
}

// ════════════════════════════════════════════════════════════════════
//  7. WAF Config
// ════════════════════════════════════════════════════════════════════

func TestWAFConfig(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/config")
		assertCode(t, "get config", 200, resp)
		// Response is WAFConfig: {defaults: {...}, services: {...}}
		mode := jsonField(body, "defaults.mode")
		if mode == "" || mode == "null" {
			t.Errorf("expected defaults.mode to be set, got: %.200s", string(body))
		}
	})

	t.Run("update", func(t *testing.T) {
		payload := map[string]any{
			"defaults": map[string]any{
				"mode":               "enabled",
				"paranoia_level":     2,
				"inbound_threshold":  10,
				"outbound_threshold": 10,
			},
		}
		resp, body := httpPut(t, wafctlURL+"/api/config", payload)
		assertCode(t, "update config", 200, resp)
		// Response echoes back the full WAFConfig
		assertField(t, "update", body, "defaults.mode", "enabled")
		pl := jsonInt(body, "defaults.paranoia_level")
		if pl != 2 {
			t.Errorf("expected defaults.paranoia_level=2, got %d", pl)
		}
	})

	t.Run("validate", func(t *testing.T) {
		payload := map[string]any{
			"defaults": map[string]any{
				"mode":               "enabled",
				"paranoia_level":     2,
				"inbound_threshold":  10,
				"outbound_threshold": 10,
			},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/config/validate", payload)
		assertCode(t, "validate config", 200, resp)
	})
}

// ════════════════════════════════════════════════════════════════════
//  8. Deploy Pipeline
// ════════════════════════════════════════════════════════════════════

func TestDeployPipeline(t *testing.T) {
	// Create a test exclusion to include in deploy.
	payload := map[string]any{
		"name":        "e2e-deploy-test",
		"type":        "skip_rule",
		"description": "Deploy test",
		"enabled":     true,
		"rule_id":     "942100",
		"conditions":  []map[string]string{{"field": "path", "operator": "begins_with", "value": "/api/"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create deploy-test exclusion", 201, resp)
	exclID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Deploy — status must be "deployed" (not "partial").
	// "partial" means Caddy reload failed, which is a real e2e failure.
	t.Run("deploy", func(t *testing.T) {
		resp, body := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
		assertCode(t, "deploy", 200, resp)
		assertField(t, "deploy status", body, "status", "deployed")
		assertField(t, "deploy reloaded", body, "reloaded", "true")
	})

	t.Run("Caddy healthy post-deploy", func(t *testing.T) {
		time.Sleep(2 * time.Second)
		resp, _ := httpGet(t, caddyAdmin+"/config/")
		assertCode(t, "admin", 200, resp)
	})

	t.Run("proxy works post-deploy", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "proxy", 200, resp)
	})
}

// ════════════════════════════════════════════════════════════════════
//  9. Rate Limit Rules
// ════════════════════════════════════════════════════════════════════

func TestRateLimitRules(t *testing.T) {
	// List — response is a bare JSON array []RateLimitRule
	t.Run("list", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rate-rules")
		assertCode(t, "list", 200, resp)
		n := jsonArrayLen(body)
		if n < 0 {
			t.Errorf("expected JSON array, got: %.200s", string(body))
		}
	})

	// Create — must return 201 Created
	var rlID string
	t.Run("create", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-rl-test",
			"service": "httpbun",
			"key":     "client_ip",
			"events":  100,
			"window":  "1m",
			"action":  "deny",
			"enabled": true,
		}
		resp, body := httpPost(t, wafctlURL+"/api/rate-rules", payload)
		assertCode(t, "create RL rule", 201, resp)
		rlID = mustGetID(t, body)
		assertField(t, "create", body, "name", "e2e-rl-test")
		assertField(t, "create", body, "action", "deny")
	})

	if rlID == "" {
		t.Fatal("no RL rule id, cannot continue")
	}
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/rate-rules/"+rlID) })

	// Get
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rate-rules/"+rlID)
		assertCode(t, "get", 200, resp)
		assertField(t, "get", body, "name", "e2e-rl-test")
		assertField(t, "get", body, "id", rlID)
	})

	// Update — PUT requires full object
	t.Run("update", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-rl-test",
			"service": "httpbun",
			"key":     "client_ip",
			"events":  200,
			"window":  "1m",
			"action":  "deny",
			"enabled": true,
		}
		resp, body := httpPut(t, wafctlURL+"/api/rate-rules/"+rlID, payload)
		assertCode(t, "update", 200, resp)
		events := jsonInt(body, "events")
		if events != 200 {
			t.Errorf("expected events=200, got %d", events)
		}
		assertField(t, "update", body, "name", "e2e-rl-test")
	})

	// Deploy — must return status "deployed" (not "partial")
	t.Run("deploy", func(t *testing.T) {
		resp, body := httpPostDeploy(t, wafctlURL+"/api/rate-rules/deploy", struct{}{})
		assertCode(t, "deploy", 200, resp)
		assertField(t, "deploy status", body, "status", "deployed")
		assertField(t, "deploy reloaded", body, "reloaded", "true")
	})

	// Read-only endpoints
	readOnly := []string{
		"/api/rate-rules/global",
		"/api/rate-limits/summary?hours=1",
		"/api/rate-limits/events?hours=1",
		"/api/rate-rules/hits",
		"/api/rate-rules/advisor?window=1m",
	}
	for _, ep := range readOnly {
		t.Run("GET "+ep, func(t *testing.T) {
			resp, _ := httpGet(t, wafctlURL+ep)
			assertCode(t, ep, 200, resp)
		})
	}

	// Export — response is RateLimitRuleExport: {version, exported_at, rules: [...], global: {...}}
	t.Run("export", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/rate-rules/export")
		assertCode(t, "export", 200, resp)
		version := jsonInt(body, "version")
		if version != 1 {
			t.Errorf("expected export version=1, got %d", version)
		}
		// rules array should exist inside the export object
		rulesRaw := jsonField(body, "rules")
		if rulesRaw == "" || rulesRaw == "null" {
			t.Errorf("expected rules array in export, got: %.200s", string(body))
		}
	})

	// Delete — must return 200 with {status: "deleted"}
	t.Run("delete", func(t *testing.T) {
		resp, body := httpDelete(t, wafctlURL+"/api/rate-rules/"+rlID)
		assertCode(t, "delete RL rule", 200, resp)
		assertField(t, "delete", body, "status", "deleted")
		rlID = "" // prevent cleanup double-delete
	})
}

// ════════════════════════════════════════════════════════════════════
// 10. CSP Management
// ════════════════════════════════════════════════════════════════════

func TestCSPManagement(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/csp")
		assertCode(t, "get", 200, resp)
	})

	t.Run("update", func(t *testing.T) {
		payload := map[string]any{
			"enabled": true,
			"services": map[string]any{
				"httpbun": map[string]any{
					"mode": "set",
					"policy": map[string]any{
						"default_src": []string{"'self'"},
						"script_src":  []string{"'self'", "'unsafe-inline'"},
						"style_src":   []string{"'self'", "'unsafe-inline'"},
					},
				},
			},
		}
		resp, body := httpPut(t, wafctlURL+"/api/csp", payload)
		assertCode(t, "update", 200, resp)
		mode := jsonField(body, "services.httpbun.mode")
		if mode != "set" {
			t.Errorf("expected services.httpbun.mode=set, got %q", mode)
		}
	})

	// Deploy — CSP deploy always returns status "ok"; check reloaded boolean separately
	t.Run("deploy", func(t *testing.T) {
		resp, body := httpPostDeploy(t, wafctlURL+"/api/csp/deploy", struct{}{})
		assertCode(t, "deploy", 200, resp)
		assertField(t, "deploy status", body, "status", "ok")
		// Check that files were generated
		msg := jsonField(body, "message")
		if !strings.Contains(msg, "CSP files") {
			t.Errorf("expected message about CSP files, got: %q", msg)
		}
	})

	t.Run("preview", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/csp/preview")
		assertCode(t, "preview", 200, resp)
	})

	// After a WAF deploy (which reloads Caddy and picks up CSP files), the header must be present
	t.Run("CSP header on proxied response", func(t *testing.T) {
		// Trigger a Caddy reload so it picks up the CSP file
		deployWAF(t)
		time.Sleep(2 * time.Second)
		resp, _ := httpGet(t, caddyURL+"/get")
		csp := resp.Header.Get("Content-Security-Policy")
		if csp == "" {
			t.Error("expected Content-Security-Policy header after deploy, got none")
		}
		if !strings.Contains(csp, "'self'") {
			t.Errorf("expected CSP to contain 'self', got: %q", csp)
		}
	})
}

// ════════════════════════════════════════════════════════════════════
// 11. Blocklist
// ════════════════════════════════════════════════════════════════════

func TestBlocklist(t *testing.T) {
	t.Run("stats", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/blocklist/stats")
		assertCode(t, "stats", 200, resp)
	})

	t.Run("check clean IP", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/blocklist/check/8.8.8.8")
		assertCode(t, "check", 200, resp)
		assertField(t, "check", body, "blocked", "false")
	})
}

// ════════════════════════════════════════════════════════════════════
// 12. General Logs
// ════════════════════════════════════════════════════════════════════

func TestGeneralLogs(t *testing.T) {
	t.Run("logs", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/logs?hours=1")
		assertCode(t, "logs", 200, resp)
	})

	t.Run("summary", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/logs/summary?hours=1")
		assertCode(t, "summary", 200, resp)
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
		{"POST", "/api/exclusions/generate"},
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

func TestWAFDashboardUI(t *testing.T) {
	t.Run("index", func(t *testing.T) {
		resp, body := httpGet(t, dashURL+"/")
		assertCode(t, "index", 200, resp)
		if !strings.Contains(string(body), "_astro/") {
			t.Error("expected _astro/ asset references in HTML")
		}
	})

	pages := []string{
		"analytics", "blocklist", "csp", "events", "logs",
		"policy", "rate-limits", "services", "settings",
	}
	for _, page := range pages {
		t.Run(page, func(t *testing.T) {
			resp, _ := httpGet(t, dashURL+"/"+page+"/")
			assertCode(t, page, 200, resp)
		})
	}

	t.Run("404", func(t *testing.T) {
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
	t.Run("invalid exclusion type", func(t *testing.T) {
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
		code, err := httpPostRaw(wafctlURL+"/api/exclusions", []byte("{invalid json}"))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 400 {
			t.Errorf("expected 400, got %d", code)
		}
	})

	t.Run("non-existent exclusion", func(t *testing.T) {
		code, err := httpGetCode(wafctlURL + "/api/exclusions/nonexistent-id-12345")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 404 {
			t.Errorf("expected 404, got %d", code)
		}
	})

	t.Run("oversized body rejected", func(t *testing.T) {
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

// ════════════════════════════════════════════════════════════════════
// 16. Policy Engine — Block/Honeypot/Allow via Caddy Plugin
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineBlock(t *testing.T) {
	// Create a block rule for a specific path.
	payload := map[string]any{
		"name":        "e2e-policy-block",
		"type":        "block",
		"description": "Block /e2e-blocked path",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "path", "operator": "begins_with", "value": "/e2e-blocked"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create block rule", 201, resp)
	blockID := mustGetID(t, body)
	// Don't deploy in cleanup — avoids mtime race with next test's deploy.
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+blockID) })

	// Deploy — triggers policy-rules.json generation + Caddy reload.
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")

	// Wait for plugin hot reload (polls every 5s, add buffer).
	time.Sleep(8 * time.Second)

	t.Run("blocked path returns 403 with policy-engine header", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-blocked")
		assertCode(t, "block", 403, resp)
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("unblocked path still works", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "unblocked", 200, resp)
	})
}

func TestPolicyEngineHoneypot(t *testing.T) {
	// Create a honeypot rule with in operator — tests exact matching.
	payload := map[string]any{
		"name":        "e2e-honeypot",
		"type":        "honeypot",
		"description": "Honeypot paths",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "path", "operator": "in", "value": "/e2e-trap|/e2e-honeypot"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create honeypot", 201, resp)
	hpID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+hpID) })

	// Ensure mtime differs from any previous deploy by sleeping briefly.
	time.Sleep(2 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	t.Run("honeypot path blocked", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-trap")
		assertCode(t, "honeypot", 403, resp)
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("in operator exact match — /e2e-trap-extended NOT blocked", func(t *testing.T) {
		// This is the core security fix: @pm /e2e-trap would match /e2e-trap-extended,
		// but the plugin's hash set does NOT. httpbun returns 404 for unknown paths,
		// which proves the request passed through without being blocked.
		code, err := httpGetCode(caddyURL + "/e2e-trap-extended")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 (not blocked), got 403 — in operator has substring match bug")
		}
	})

	t.Run("second honeypot path also blocked", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-honeypot")
		assertCode(t, "honeypot2", 403, resp)
	})
}

func TestPolicyEngineAllow(t *testing.T) {
	// Use /get (valid httpbun endpoint) with SQLi in query string.
	sqliURL := caddyURL + "/get?id=1%27%20OR%20%271%27=%271"

	// Verify the SQLi is blocked before the allow rule.
	t.Run("pre-allow blocked", func(t *testing.T) {
		code, err := httpGetCode(sqliURL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 403 {
			t.Fatalf("expected 403 (WAF block), got %d — WAF not working", code)
		}
	})

	// Create an allow rule that bypasses WAF for /get path.
	payload := map[string]any{
		"name":        "e2e-policy-allow",
		"type":        "allow",
		"description": "Allow /get path via policy engine",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "uri_path", "operator": "eq", "value": "/get"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create allow rule", 201, resp)
	allowID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+allowID)
		// Redeploy to remove the allow rule from policy-rules.json,
		// otherwise subsequent tests see a stale WAF bypass.
		time.Sleep(2 * time.Second)
		resp, body := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
		assertCode(t, "cleanup deploy", 200, resp)
		assertField(t, "cleanup deploy", body, "status", "deployed")
		time.Sleep(8 * time.Second)
	})

	time.Sleep(2 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	t.Run("post-allow SQLi passes through", func(t *testing.T) {
		code, err := httpGetCode(sqliURL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 200 {
			t.Errorf("expected 200 (WAF bypass via policy engine allow), got %d", code)
		}
	})
}

// ════════════════════════════════════════════════════════════════════
// 17. End-to-End: WAF Bypass via Exclusion (legacy SecRule path)
// ════════════════════════════════════════════════════════════════════

func TestE2EWAFBypass(t *testing.T) {
	sqliURL := caddyURL + "/get?id=1%27%20OR%20%271%27=%271"

	// Step 1: Confirm blocked before exclusion.
	t.Run("pre-exclusion blocked", func(t *testing.T) {
		code, err := httpGetCode(sqliURL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 403 {
			t.Fatalf("expected 403 (WAF block), got %d — WAF not working", code)
		}
	})

	// Step 2: Create allow exclusion for /get path.
	payload := map[string]any{
		"name":        "e2e-bypass",
		"type":        "allow",
		"description": "E2E bypass test",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "path", "operator": "begins_with", "value": "/get"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create bypass exclusion", 201, resp)
	bypassID := mustGetID(t, body)

	// Step 3: Deploy — must succeed fully (not "partial").
	resp2, deployBody := httpPostDeploy(t, fmt.Sprintf("%s/api/config/deploy", wafctlURL), struct{}{})
	assertCode(t, "deploy bypass", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")

	// Step 4: Verify bypass works — SQLi should now pass through.
	t.Run("post-exclusion passes", func(t *testing.T) {
		time.Sleep(3 * time.Second)
		code, err := httpGetCode(sqliURL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 200 {
			t.Errorf("expected 200 (WAF bypass), got %d", code)
		}
	})

	// Step 5: Cleanup — delete exclusion and redeploy.
	cleanup(t, fmt.Sprintf("%s/api/exclusions/%s", wafctlURL, bypassID))
	_, redeployBody := httpPostDeploy(t, fmt.Sprintf("%s/api/config/deploy", wafctlURL), struct{}{})
	assertField(t, "redeploy", redeployBody, "status", "deployed")
	time.Sleep(2 * time.Second)

	// Step 6: Verify WAF re-enabled — SQLi must be blocked again.
	t.Run("post-cleanup blocked", func(t *testing.T) {
		code, err := httpGetCode(sqliURL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 403 {
			t.Errorf("expected 403 (WAF re-enabled), got %d", code)
		}
	})
}
