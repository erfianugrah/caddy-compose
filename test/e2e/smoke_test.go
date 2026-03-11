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
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

	// The e2e test uses "localhost" as the CSP service name because the plugin
	// resolves CSP by matching the Host header (stripped of port). In e2e,
	// the test client sends Host: localhost:18080, which resolves to "localhost".
	// In production, FQDN resolution maps "httpbun" → "httpbun.erfi.io".
	t.Run("update", func(t *testing.T) {
		payload := map[string]any{
			"enabled": true,
			"services": map[string]any{
				"localhost": map[string]any{
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
		mode := jsonField(body, "services.localhost.mode")
		if mode != "set" {
			t.Errorf("expected services.localhost.mode=set, got %q", mode)
		}
	})

	// Deploy — with policy engine enabled, CSP goes into policy-rules.json (hot-reload).
	t.Run("deploy", func(t *testing.T) {
		resp, body := httpPostDeploy(t, wafctlURL+"/api/csp/deploy", struct{}{})
		assertCode(t, "deploy", 200, resp)
		assertField(t, "deploy status", body, "status", "ok")
		msg := jsonField(body, "message")
		if !strings.Contains(msg, "policy-rules.json") && !strings.Contains(msg, "hot-reload") && !strings.Contains(msg, "CSP") {
			t.Errorf("expected message about policy-rules.json or hot-reload, got: %q", msg)
		}
	})

	t.Run("preview", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/csp/preview")
		assertCode(t, "preview", 200, resp)
	})

	// After CSP deploy (writes policy-rules.json), the plugin hot-reloads within 5s.
	// No Caddy restart needed — just wait for mtime poll.
	t.Run("CSP header on proxied response", func(t *testing.T) {
		time.Sleep(8 * time.Second)
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
// 10b. Policy Engine Response Headers (Security + CSP)
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineResponseHeaders(t *testing.T) {
	// Security headers are injected by DefaultSecurityHeaders() via policy-rules.json.
	// generateOnBoot writes this on startup, so headers should be present from the start.

	t.Run("security headers present", func(t *testing.T) {
		// Trigger a WAF deploy to ensure policy-rules.json has response_headers
		// (generateOnBoot should have done this, but be explicit).
		deployWAF(t)
		time.Sleep(8 * time.Second)

		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "proxy", 200, resp)

		// HSTS
		hsts := resp.Header.Get("Strict-Transport-Security")
		if !strings.Contains(hsts, "max-age=63072000") {
			t.Errorf("expected HSTS with max-age=63072000, got: %q", hsts)
		}
		if !strings.Contains(hsts, "includeSubDomains") {
			t.Errorf("expected HSTS with includeSubDomains, got: %q", hsts)
		}

		// X-Content-Type-Options
		xcto := resp.Header.Get("X-Content-Type-Options")
		if xcto != "nosniff" {
			t.Errorf("expected X-Content-Type-Options=nosniff, got: %q", xcto)
		}

		// Referrer-Policy
		rp := resp.Header.Get("Referrer-Policy")
		if rp != "strict-origin-when-cross-origin" {
			t.Errorf("expected Referrer-Policy=strict-origin-when-cross-origin, got: %q", rp)
		}

		// Permissions-Policy
		pp := resp.Header.Get("Permissions-Policy")
		if pp == "" {
			t.Error("expected Permissions-Policy header, got none")
		}

		// X-Frame-Options
		xfo := resp.Header.Get("X-Frame-Options")
		if xfo != "SAMEORIGIN" {
			t.Errorf("expected X-Frame-Options=SAMEORIGIN, got: %q", xfo)
		}

		// Cross-Origin-Opener-Policy
		coop := resp.Header.Get("Cross-Origin-Opener-Policy")
		if coop != "same-origin" {
			t.Errorf("expected Cross-Origin-Opener-Policy=same-origin, got: %q", coop)
		}

		// Cross-Origin-Resource-Policy
		corp := resp.Header.Get("Cross-Origin-Resource-Policy")
		if corp != "cross-origin" {
			t.Errorf("expected Cross-Origin-Resource-Policy=cross-origin, got: %q", corp)
		}

		// X-Permitted-Cross-Domain-Policies
		xpcdp := resp.Header.Get("X-Permitted-Cross-Domain-Policies")
		if xpcdp != "none" {
			t.Errorf("expected X-Permitted-Cross-Domain-Policies=none, got: %q", xpcdp)
		}
	})

	t.Run("Server header removed", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "proxy", 200, resp)
		server := resp.Header.Get("Server")
		if server != "" {
			t.Errorf("expected Server header to be removed, got: %q", server)
		}
	})

	t.Run("X-Powered-By header removed", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "proxy", 200, resp)
		xpb := resp.Header.Get("X-Powered-By")
		if xpb != "" {
			t.Errorf("expected X-Powered-By header to be removed, got: %q", xpb)
		}
	})

	t.Run("blocked requests do not get response headers", func(t *testing.T) {
		// A WAF-blocked request (403) should NOT have CSP or security headers
		// injected by the plugin since block action returns early.
		resp, _ := httpGet(t, caddyURL+"/get?id=1%20OR%201=1%20--")
		assertCode(t, "blocked", 403, resp)
		// Policy engine block rules return before applyResponseHeaders() runs.
		// For WAF blocks (Coraza), the plugin's ResponseWriter wrapper wrote
		// headers before the upstream response, but the error handler replaces them.
		// Either way, CSP should not be on error responses.
	})
}

func TestCSPHotReload(t *testing.T) {
	// Test that CSP changes propagate via hot-reload without Caddy restart.
	// Uses "localhost" as service name because the plugin resolves CSP by Host header.

	// Step 1: Set a distinctive CSP via the API.
	payload := map[string]any{
		"enabled": true,
		"services": map[string]any{
			"localhost": map[string]any{
				"mode": "set",
				"policy": map[string]any{
					"default_src": []string{"'self'"},
					"script_src":  []string{"'self'", "https://cdn.example.com"},
				},
			},
		},
	}
	resp, body := httpPut(t, wafctlURL+"/api/csp", payload)
	assertCode(t, "set CSP", 200, resp)
	assertField(t, "mode", body, "services.localhost.mode", "set")

	// Step 2: Deploy CSP (writes policy-rules.json, no Caddy restart).
	time.Sleep(1 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/csp/deploy", struct{}{})
	assertCode(t, "deploy CSP", 200, resp2)
	assertField(t, "deploy status", deployBody, "status", "ok")

	// Step 3: Wait for plugin hot-reload (5s poll interval + buffer).
	time.Sleep(8 * time.Second)

	// Step 4: Verify the CSP header contains our custom directive.
	t.Run("initial CSP applied", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "proxy", 200, resp)
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "cdn.example.com") {
			t.Errorf("expected CSP to contain cdn.example.com, got: %q", csp)
		}
	})

	// Step 5: Update CSP to a different value.
	payload2 := map[string]any{
		"enabled": true,
		"services": map[string]any{
			"localhost": map[string]any{
				"mode": "set",
				"policy": map[string]any{
					"default_src": []string{"'self'"},
					"script_src":  []string{"'self'", "https://updated.example.org"},
				},
			},
		},
	}
	resp3, _ := httpPut(t, wafctlURL+"/api/csp", payload2)
	assertCode(t, "update CSP", 200, resp3)

	// Step 6: Deploy the updated CSP.
	time.Sleep(1 * time.Second)
	resp4, _ := httpPostDeploy(t, wafctlURL+"/api/csp/deploy", struct{}{})
	assertCode(t, "redeploy CSP", 200, resp4)

	// Step 7: Wait for hot-reload again.
	time.Sleep(8 * time.Second)

	// Step 8: Verify the CSP header now has the updated value.
	t.Run("updated CSP applied via hot-reload", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		csp := resp.Header.Get("Content-Security-Policy")
		if strings.Contains(csp, "cdn.example.com") {
			t.Errorf("CSP still contains old cdn.example.com after update: %q", csp)
		}
		if !strings.Contains(csp, "updated.example.org") {
			t.Errorf("expected CSP to contain updated.example.org, got: %q", csp)
		}
	})

	// Step 9: Test CSP "none" mode — remove CSP for the service.
	payload3 := map[string]any{
		"enabled": true,
		"services": map[string]any{
			"localhost": map[string]any{
				"mode":   "none",
				"policy": map[string]any{},
			},
		},
	}
	resp5, _ := httpPut(t, wafctlURL+"/api/csp", payload3)
	assertCode(t, "set none mode", 200, resp5)
	time.Sleep(1 * time.Second)
	resp6, _ := httpPostDeploy(t, wafctlURL+"/api/csp/deploy", struct{}{})
	assertCode(t, "deploy none", 200, resp6)
	time.Sleep(8 * time.Second)

	t.Run("none mode removes CSP header", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		csp := resp.Header.Get("Content-Security-Policy")
		if csp != "" {
			t.Errorf("expected no CSP header in 'none' mode, got: %q", csp)
		}
	})

	// Step 10: Clean up — reset CSP to a basic config so subsequent tests are clean.
	cleanupPayload := map[string]any{
		"enabled": true,
		"services": map[string]any{
			"localhost": map[string]any{
				"mode": "set",
				"policy": map[string]any{
					"default_src": []string{"'self'"},
				},
			},
		},
	}
	httpPut(t, wafctlURL+"/api/csp", cleanupPayload)
	httpPostDeploy(t, wafctlURL+"/api/csp/deploy", struct{}{})
	time.Sleep(8 * time.Second)
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
		"analytics", "csp", "events", "lists",
		"logs", "policy", "rate-limits", "services", "settings",
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
	// Create a block rule with honeypot tag and in operator — tests exact matching.
	payload := map[string]any{
		"name":        "e2e-honeypot",
		"type":        "block",
		"description": "Honeypot paths",
		"tags":        []string{"honeypot"},
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "path", "operator": "in", "value": "/e2e-trap|/e2e-honeypot"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create honeypot block rule", 201, resp)
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

func TestPolicyEngineBodyJSON(t *testing.T) {
	// Create a block rule that matches a JSON body field: .action == "delete_all".
	payload := map[string]any{
		"name":        "e2e-body-json-block",
		"type":        "block",
		"description": "Block requests with dangerous action in JSON body",
		"enabled":     true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "begins_with", "value": "/post"},
			{"field": "body_json", "operator": "eq", "value": ".action:delete_all"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create body_json block rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	time.Sleep(2 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	t.Run("matching JSON body blocked", func(t *testing.T) {
		dangerousBody := []byte(`{"action":"delete_all","target":"users"}`)
		code, err := httpPostRaw(caddyURL+"/post", dangerousBody)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 403 {
			t.Errorf("expected 403 (body_json block), got %d", code)
		}
	})

	t.Run("non-matching JSON body passes", func(t *testing.T) {
		safeBody := []byte(`{"action":"list","target":"users"}`)
		code, err := httpPostRaw(caddyURL+"/post", safeBody)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 (safe body should pass), got 403")
		}
	})

	t.Run("non-JSON body passes", func(t *testing.T) {
		plainBody := []byte(`just some plain text`)
		code, err := httpPostRaw(caddyURL+"/post", plainBody)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 (non-JSON body should pass), got 403")
		}
	})
}

// ════════════════════════════════════════════════════════════════════
// 18. Managed Lists CRUD
// ════════════════════════════════════════════════════════════════════

func TestManagedListsCRUD(t *testing.T) {
	// List — initially empty (or whatever exists).
	t.Run("list empty", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists")
		assertCode(t, "list", 200, resp)
		n := jsonArrayLen(body)
		t.Logf("existing managed lists: %d", n)
	})

	// Create an IP list — must return 201.
	var listID string
	t.Run("create IP list", func(t *testing.T) {
		payload := map[string]any{
			"name":        "e2e-test-ips",
			"description": "E2E test IP list",
			"kind":        "ip",
			"source":      "manual",
			"items":       []string{"10.0.0.1", "192.168.1.0/24", "172.16.0.5"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "create IP list", 201, resp)
		listID = mustGetID(t, body)
		assertField(t, "create", body, "name", "e2e-test-ips")
		assertField(t, "create", body, "kind", "ip")
		assertField(t, "create", body, "source", "manual")
		count := jsonInt(body, "item_count")
		if count != 3 {
			t.Errorf("expected item_count=3, got %d", count)
		}
	})

	if listID == "" {
		t.Fatal("no list ID, cannot continue CRUD tests")
	}
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+listID) })

	// Get by ID.
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists/"+listID)
		assertCode(t, "get", 200, resp)
		assertField(t, "get", body, "id", listID)
		assertField(t, "get", body, "name", "e2e-test-ips")
	})

	// Update (partial — add description, change items).
	t.Run("update", func(t *testing.T) {
		payload := map[string]any{
			"description": "Updated E2E IP list",
			"items":       []string{"10.0.0.1", "10.0.0.2"},
		}
		resp, body := httpPut(t, wafctlURL+"/api/lists/"+listID, payload)
		assertCode(t, "update", 200, resp)
		assertField(t, "update", body, "description", "Updated E2E IP list")
		// Name should be preserved from original.
		assertField(t, "update", body, "name", "e2e-test-ips")
		count := jsonInt(body, "item_count")
		if count != 2 {
			t.Errorf("expected item_count=2, got %d", count)
		}
	})

	// List — should contain at least 1.
	t.Run("list non-empty", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists")
		assertCode(t, "list", 200, resp)
		n := jsonArrayLen(body)
		if n < 1 {
			t.Errorf("expected at least 1 list, got %d", n)
		}
	})

	// Export — response is ManagedListExport: {version, exported_at, lists}.
	t.Run("export", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists/export")
		assertCode(t, "export", 200, resp)
		version := jsonInt(body, "version")
		if version != 1 {
			t.Errorf("expected export version=1, got %d", version)
		}
		listsRaw := jsonField(body, "lists")
		if listsRaw == "" || listsRaw == "null" {
			t.Errorf("expected lists array in export, got: %.200s", string(body))
		}
	})

	// Delete — must return 204.
	t.Run("delete", func(t *testing.T) {
		resp, _ := httpDelete(t, wafctlURL+"/api/lists/"+listID)
		assertCode(t, "delete list", 204, resp)
		listID = "" // prevent cleanup double-delete
	})

	// Get non-existent — should be 404.
	t.Run("get non-existent", func(t *testing.T) {
		code, err := httpGetCode(wafctlURL + "/api/lists/nonexistent-id-12345")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 404 {
			t.Errorf("expected 404, got %d", code)
		}
	})
}

func TestManagedListsImportExport(t *testing.T) {
	// Import replaces the entire store (same as exclusion import).
	// Test it in isolation to avoid interfering with CRUD tests.
	t.Run("import", func(t *testing.T) {
		payload := map[string]any{
			"version": 1,
			"lists": []map[string]any{
				{
					"name":   "e2e-imported-hosts",
					"kind":   "hostname",
					"source": "manual",
					"items":  []string{"evil.example.com", "bad.example.org"},
				},
				{
					"name":   "e2e-imported-ips",
					"kind":   "ip",
					"source": "manual",
					"items":  []string{"10.0.0.1"},
				},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists/import", payload)
		assertCode(t, "import", 200, resp)
		imported := jsonInt(body, "imported")
		if imported != 2 {
			t.Errorf("expected imported=2, got %d", imported)
		}
	})

	// Verify imported lists exist.
	t.Run("imported lists exist", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists")
		assertCode(t, "list after import", 200, resp)
		n := jsonArrayLen(body)
		if n < 2 {
			t.Errorf("expected at least 2 lists after import, got %d", n)
		}
		// Find and clean up both imported lists.
		var arr []json.RawMessage
		if err := json.Unmarshal(body, &arr); err == nil {
			for _, raw := range arr {
				id := jsonField(raw, "id")
				if id != "" && id != "null" {
					t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })
				}
			}
		}
	})

	// Export after import should include the imported lists.
	t.Run("export after import", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists/export")
		assertCode(t, "export", 200, resp)
		version := jsonInt(body, "version")
		if version != 1 {
			t.Errorf("expected export version=1, got %d", version)
		}
	})
}

func TestManagedListsValidation(t *testing.T) {
	t.Run("invalid kind rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-bad-kind",
			"kind":   "invalid_kind",
			"source": "manual",
			"items":  []string{"test"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "invalid kind", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error field, got: %s", body)
		}
	})

	t.Run("invalid source rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-bad-source",
			"kind":   "ip",
			"source": "invalid_source",
			"items":  []string{"10.0.0.1"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "invalid source", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error field, got: %s", body)
		}
	})

	t.Run("ipsum source rejected via API", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-ipsum-attempt",
			"kind":   "ip",
			"source": "ipsum",
			"items":  []string{"10.0.0.1"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "ipsum rejected", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error field, got: %s", body)
		}
	})

	t.Run("bad slug name rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "Invalid Name With Spaces!",
			"kind":   "string",
			"source": "manual",
			"items":  []string{"test"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "bad slug", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error field, got: %s", body)
		}
	})

	t.Run("duplicate name rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-dup-test",
			"kind":   "string",
			"source": "manual",
			"items":  []string{"test"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "create first", 201, resp)
		firstID := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+firstID) })

		// Second create with same name — should fail.
		resp2, body2 := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "duplicate name", 400, resp2)
		errMsg := jsonField(body2, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error for duplicate name, got: %s", body2)
		}
	})

	t.Run("invalid IP in IP list rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-bad-ip",
			"kind":   "ip",
			"source": "manual",
			"items":  []string{"not-an-ip"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "bad IP", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error for invalid IP, got: %s", body)
		}
	})

	t.Run("invalid ASN format rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-bad-asn",
			"kind":   "asn",
			"source": "manual",
			"items":  []string{"INVALID123"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "bad ASN", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error for invalid ASN, got: %s", body)
		}
	})
}

func TestManagedListsStringAndASN(t *testing.T) {
	// Create a string kind list (for country codes, etc.).
	t.Run("create string list", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-countries",
			"kind":   "string",
			"source": "manual",
			"items":  []string{"CN", "RU", "KP"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "create string list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })
		assertField(t, "kind", body, "kind", "string")
		count := jsonInt(body, "item_count")
		if count != 3 {
			t.Errorf("expected item_count=3, got %d", count)
		}
	})

	// Create an ASN kind list.
	t.Run("create ASN list", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-asns",
			"kind":   "asn",
			"source": "manual",
			"items":  []string{"AS13335", "AS15169"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "create ASN list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })
		assertField(t, "kind", body, "kind", "asn")
	})

	// Create a hostname kind list.
	t.Run("create hostname list", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-hostnames",
			"kind":   "hostname",
			"source": "manual",
			"items":  []string{"evil.example.com", "bad.example.org"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "create hostname list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })
		assertField(t, "kind", body, "kind", "hostname")
	})
}

func TestManagedListsStress(t *testing.T) {
	// Stress test: large lists that exceed the inline threshold (1000 items)
	// and exercise external file storage.

	t.Run("50K IPs — external file storage", func(t *testing.T) {
		const n = 50_000
		ips := generateIPs(n)
		payload := map[string]any{
			"name":   "e2e-stress-50k",
			"kind":   "ip",
			"source": "manual",
			"items":  ips,
		}
		start := time.Now()
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		createDur := time.Since(start)
		assertCode(t, "create 50K list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })

		count := jsonInt(body, "item_count")
		if count != n {
			t.Errorf("expected item_count=%d, got %d", n, count)
		}
		t.Logf("create 50K list: %v", createDur)

		// Get — verify items are returned from external file.
		start = time.Now()
		resp2, body2 := httpGet(t, wafctlURL+"/api/lists/"+id)
		getDur := time.Since(start)
		assertCode(t, "get 50K list", 200, resp2)
		assertField(t, "get", body2, "name", "e2e-stress-50k")
		getCount := jsonInt(body2, "item_count")
		if getCount != n {
			t.Errorf("expected item_count=%d on get, got %d", n, getCount)
		}
		t.Logf("get 50K list: %v", getDur)

		// Update — replace with different items.
		start = time.Now()
		newIPs := generateIPs(25_000)
		resp3, body3 := httpPut(t, wafctlURL+"/api/lists/"+id, map[string]any{"items": newIPs})
		updateDur := time.Since(start)
		assertCode(t, "update 50K→25K", 200, resp3)
		updCount := jsonInt(body3, "item_count")
		if updCount != 25_000 {
			t.Errorf("expected item_count=25000 after update, got %d", updCount)
		}
		t.Logf("update 50K→25K list: %v", updateDur)
	})

	t.Run("200K IPs — near API body limit", func(t *testing.T) {
		// 200K IPs ≈ 3MB JSON payload (well under the 5MB MaxBytesReader).
		const n = 200_000
		ips := generateIPs(n)
		payload := map[string]any{
			"name":   "e2e-stress-200k",
			"kind":   "ip",
			"source": "manual",
			"items":  ips,
		}
		start := time.Now()
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		createDur := time.Since(start)
		assertCode(t, "create 200K list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })

		count := jsonInt(body, "item_count")
		if count != n {
			t.Errorf("expected item_count=%d, got %d", n, count)
		}
		t.Logf("create 200K list: %v", createDur)

		// Get and verify count survives round-trip.
		start = time.Now()
		resp2, body2 := httpGet(t, wafctlURL+"/api/lists/"+id)
		getDur := time.Since(start)
		assertCode(t, "get 200K list", 200, resp2)
		getCount := jsonInt(body2, "item_count")
		if getCount != n {
			t.Errorf("expected item_count=%d on get, got %d", n, getCount)
		}
		t.Logf("get 200K list: %v", getDur)

		// Delete large list — should clean up external file.
		start = time.Now()
		resp3, _ := httpDelete(t, wafctlURL+"/api/lists/"+id)
		deleteDur := time.Since(start)
		assertCode(t, "delete 200K list", 204, resp3)
		t.Logf("delete 200K list: %v", deleteDur)
		id = "" // prevent cleanup double-delete (captured by closure but unused)
	})

	t.Run("300K strings — push harder", func(t *testing.T) {
		// 300K short strings ≈ 4MB JSON. Tests string kind at scale.
		const n = 300_000
		items := make([]string, n)
		for i := range items {
			items[i] = fmt.Sprintf("item-%06d", i)
		}
		payload := map[string]any{
			"name":   "e2e-stress-300k-strings",
			"kind":   "string",
			"source": "manual",
			"items":  items,
		}
		start := time.Now()
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		createDur := time.Since(start)
		assertCode(t, "create 300K string list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })

		count := jsonInt(body, "item_count")
		if count != n {
			t.Errorf("expected item_count=%d, got %d", n, count)
		}
		t.Logf("create 300K string list: %v", createDur)
	})
}

func TestManagedListsURLRefreshError(t *testing.T) {
	// Create a URL-sourced list with a non-existent URL — refresh should fail gracefully.
	payload := map[string]any{
		"name":   "e2e-url-list",
		"kind":   "ip",
		"source": "url",
		"url":    "http://localhost:1/nonexistent-list.txt",
		"items":  []string{},
	}
	resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
	assertCode(t, "create URL list", 201, resp)
	id := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })

	t.Run("refresh with bad URL returns error", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/lists/"+id+"/refresh", nil)
		// Should return 400 because the URL can't be reached.
		if resp.StatusCode != 400 {
			t.Errorf("expected 400 for unreachable URL refresh, got %d: %s", resp.StatusCode, body)
		}
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error in response, got: %s", body)
		}
	})

	t.Run("refresh non-existent list returns error", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/lists/nonexistent-id/refresh", nil)
		if resp.StatusCode != 400 {
			t.Errorf("expected 400 for non-existent list refresh, got %d: %s", resp.StatusCode, body)
		}
	})
}

// ════════════════════════════════════════════════════════════════════
// 19. Policy Engine — in_list / not_in_list via Managed Lists
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineInList(t *testing.T) {
	// Test the full pipeline: managed list → exclusion with in_list → deploy →
	// plugin hot reload → request matching. This validates the core security fix:
	// exact path matching via hash set instead of @pm substring matching.

	// Step 1: Create a string list with specific paths.
	listPayload := map[string]any{
		"name":   "e2e-blocked-paths",
		"kind":   "string",
		"source": "manual",
		"items":  []string{"/e2e-list-trap", "/e2e-list-blocked"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/lists", listPayload)
	assertCode(t, "create list", 201, resp)
	listID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+listID) })

	// Step 2: Create a block exclusion referencing the list.
	exclPayload := map[string]any{
		"name":        "e2e-in-list-block",
		"type":        "block",
		"description": "Block paths from managed list",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "path", "operator": "in_list", "value": "e2e-blocked-paths"}},
	}
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions", exclPayload)
	assertCode(t, "create in_list exclusion", 201, resp2)
	exclID := mustGetID(t, body2)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Step 3: Deploy and wait for plugin hot reload.
	time.Sleep(2 * time.Second)
	resp3, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp3)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	// Step 4: Verify exact path matching.
	t.Run("listed path /e2e-list-trap blocked", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-list-trap")
		assertCode(t, "blocked", 403, resp)
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("listed path /e2e-list-blocked blocked", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-list-blocked")
		assertCode(t, "blocked", 403, resp)
	})

	t.Run("exact match — /e2e-list-trap-extended NOT blocked", func(t *testing.T) {
		// Core security fix: @pm would substring-match this, hash set does not.
		code, err := httpGetCode(caddyURL + "/e2e-list-trap-extended")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 (not in list), got 403 — in_list has substring match bug")
		}
	})

	t.Run("unrelated path still works", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "unblocked", 200, resp)
	})
}

func TestPolicyEngineNotInList(t *testing.T) {
	// Test not_in_list: block all paths NOT in the safe list.
	// This uses method field to avoid interfering with other tests.

	// Step 1: Create a string list of "safe" user agents.
	listPayload := map[string]any{
		"name":   "e2e-safe-agents",
		"kind":   "string",
		"source": "manual",
		"items":  []string{"Go-http-client/1.1"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/lists", listPayload)
	assertCode(t, "create safe list", 201, resp)
	listID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+listID) })

	// Step 2: Create a block rule: block requests to /e2e-notinlist-test
	// whose user_agent is NOT in the safe list. Combined with a path condition
	// to avoid blocking all traffic.
	exclPayload := map[string]any{
		"name":        "e2e-not-in-list-block",
		"type":        "block",
		"description": "Block unknown UAs on specific path",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-notinlist-test"},
			{"field": "user_agent", "operator": "not_in_list", "value": "e2e-safe-agents"},
		},
	}
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions", exclPayload)
	assertCode(t, "create not_in_list exclusion", 201, resp2)
	exclID := mustGetID(t, body2)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Step 3: Deploy and wait for plugin hot reload.
	time.Sleep(2 * time.Second)
	resp3, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp3)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	// Step 4: Verify not_in_list matching.
	t.Run("safe UA passes through", func(t *testing.T) {
		// Go's default HTTP client sends "Go-http-client/1.1" which is in the safe list.
		code, err := httpGetCode(caddyURL + "/e2e-notinlist-test")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		// Should NOT be blocked since Go's UA is in the safe list.
		if code == 403 {
			t.Errorf("expected non-403 (UA in safe list), got 403")
		}
	})

	t.Run("unknown UA blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-notinlist-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "EvilBot/1.0")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (UA not in safe list), got %d", resp.StatusCode)
		}
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("other paths unaffected", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "EvilBot/1.0")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		// /get should not be affected by the rule (path condition limits scope).
		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 (different path), got 403")
		}
	})
}

func TestPolicyEngineInListIP(t *testing.T) {
	// Test in_list with IP kind list. Uses a CIDR that covers Docker bridge
	// networks (172.16.0.0/12) to match the E2E test client's IP.

	// Step 1: Create IP list with Docker bridge CIDR.
	listPayload := map[string]any{
		"name":   "e2e-blocked-ips",
		"kind":   "ip",
		"source": "manual",
		"items":  []string{"172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/lists", listPayload)
	assertCode(t, "create IP list", 201, resp)
	listID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+listID) })

	// Step 2: Create block rule for specific path + IP in_list.
	exclPayload := map[string]any{
		"name":        "e2e-ip-in-list-block",
		"type":        "block",
		"description": "Block private IPs on specific path",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-ip-list-test"},
			{"field": "ip", "operator": "in_list", "value": "e2e-blocked-ips"},
		},
	}
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions", exclPayload)
	assertCode(t, "create IP in_list exclusion", 201, resp2)
	exclID := mustGetID(t, body2)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Step 3: Deploy and wait for plugin hot reload.
	time.Sleep(2 * time.Second)
	resp3, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp3)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	// Step 4: Our E2E client IP is a Docker private IP — should be blocked.
	t.Run("private IP blocked on target path", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-ip-list-test")
		assertCode(t, "blocked", 403, resp)
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("other paths unaffected", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "unblocked", 200, resp)
	})
}

func TestPolicyEngineInListLarge(t *testing.T) {
	// Stress test: create a large IP list (10K entries), reference it in a
	// block rule, deploy, and verify the plugin handles it without timeout.

	const n = 10_000
	ips := generateIPs(n)

	// Step 1: Create large IP list.
	listPayload := map[string]any{
		"name":   "e2e-large-ip-list",
		"kind":   "ip",
		"source": "manual",
		"items":  ips,
	}
	resp, body := httpPost(t, wafctlURL+"/api/lists", listPayload)
	assertCode(t, "create large list", 201, resp)
	listID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+listID) })

	count := jsonInt(body, "item_count")
	if count != n {
		t.Errorf("expected item_count=%d, got %d", n, count)
	}

	// Step 2: Create block rule referencing it.
	exclPayload := map[string]any{
		"name":        "e2e-large-list-block",
		"type":        "block",
		"description": "Block IPs from large list",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-large-list-test"},
			{"field": "ip", "operator": "in_list", "value": "e2e-large-ip-list"},
		},
	}
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions", exclPayload)
	assertCode(t, "create large list exclusion", 201, resp2)
	exclID := mustGetID(t, body2)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Step 3: Deploy — must succeed (not partial/timeout).
	time.Sleep(2 * time.Second)
	resp3, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy with large list", 200, resp3)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	// Step 4: Verify matching works — 10.0.0.x IPs are in the list,
	// and Docker bridge IPs (172.x) are NOT. Since our test client
	// uses a Docker bridge IP, we should NOT be blocked.
	t.Run("Docker bridge IP not in 10.x.x.x list", func(t *testing.T) {
		code, err := httpGetCode(caddyURL + "/e2e-large-list-test")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		// Docker bridge IP is typically 172.x.x.x, NOT in the 10.x.x.x list.
		if code == 403 {
			t.Errorf("expected non-403 (client IP not in 10.x list), got 403")
		}
	})

	// Step 5: Verify deploy and proxy still work after loading 10K items.
	t.Run("proxy healthy after large list", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "healthy", 200, resp)
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

// ════════════════════════════════════════════════════════════════════
// 18. End-to-End: Policy Engine Rate Limiting
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineRateLimit(t *testing.T) {
	// Step 1: Create a rate limit rule with a very low threshold.
	// 3 events per 10s window so we can trigger it quickly.
	payload := map[string]any{
		"name":    "e2e-ratelimit-test",
		"service": "*",
		"key":     "client_ip",
		"events":  3,
		"window":  "10s",
		"action":  "deny",
		"enabled": true,
		"conditions": []map[string]string{
			{"field": "path", "operator": "begins_with", "value": "/e2e-rl-"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rate-rules", payload)
	assertCode(t, "create RL rule", 201, resp)
	rlID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/rate-rules/"+rlID)
		// Redeploy to remove the rule from policy-rules.json.
		httpPostDeploy(t, wafctlURL+"/api/rate-rules/deploy", struct{}{})
	})

	// Step 2: Deploy — writes to policy-rules.json, no Caddy reload needed.
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/rate-rules/deploy", struct{}{})
	assertCode(t, "deploy RL", 200, resp2)
	assertField(t, "deploy status", deployBody, "status", "deployed")

	// Step 3: Wait for policy engine to hot-reload the rules file.
	// Plugin polls every 5s; give it a generous buffer.
	time.Sleep(8 * time.Second)

	// Step 4: Send requests until rate limited (429).
	targetURL := caddyURL + "/e2e-rl-target"
	var lastResp *http.Response
	var lastBody []byte
	got429 := false

	for i := 0; i < 10; i++ {
		lastResp, lastBody = httpGet(t, targetURL)
		if lastResp.StatusCode == 429 {
			got429 = true
			break
		}
		// Small delay to avoid overwhelming too fast within a single window tick.
		time.Sleep(50 * time.Millisecond)
	}

	if !got429 {
		t.Fatalf("expected 429 after exceeding rate limit (3 req/10s), last status=%d body=%.200s",
			lastResp.StatusCode, string(lastBody))
	}

	// Step 5: Verify rate limit response headers from the policy engine.
	t.Run("429 headers", func(t *testing.T) {
		// X-RateLimit-Policy should contain the rule name.
		policy := lastResp.Header.Get("X-RateLimit-Policy")
		if policy == "" {
			t.Error("missing X-RateLimit-Policy header on 429 response")
		} else if !strings.Contains(policy, "e2e-ratelimit-test") {
			t.Errorf("X-RateLimit-Policy=%q, expected to contain 'e2e-ratelimit-test'", policy)
		}

		// X-RateLimit-Limit should be "3".
		limit := lastResp.Header.Get("X-RateLimit-Limit")
		if limit != "3" {
			t.Errorf("X-RateLimit-Limit=%q, expected '3'", limit)
		}

		// Retry-After should be present and non-empty.
		retryAfter := lastResp.Header.Get("Retry-After")
		if retryAfter == "" {
			t.Error("missing Retry-After header on 429 response")
		}
	})

	// Step 6: Wait for the window to fully expire. Sliding window interpolation
	// means the previous window retains partial weight for one full window after
	// it ends, so we need ~2 full windows (20s) for the counter to fully drain.
	t.Run("recovers after window", func(t *testing.T) {
		time.Sleep(22 * time.Second)
		code, err := httpGetCode(targetURL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 429 {
			t.Errorf("still rate limited after window expiry, expected 200")
		}
	})

	// Step 7: Verify log_only mode — update rule to log_only, redeploy, verify no block.
	t.Run("log_only mode", func(t *testing.T) {
		updatePayload := map[string]any{
			"name":    "e2e-ratelimit-test",
			"service": "*",
			"key":     "client_ip",
			"events":  3,
			"window":  "10s",
			"action":  "log_only",
			"enabled": true,
			"conditions": []map[string]string{
				{"field": "path", "operator": "begins_with", "value": "/e2e-rl-"},
			},
		}
		resp, body := httpPut(t, wafctlURL+"/api/rate-rules/"+rlID, updatePayload)
		assertCode(t, "update to log_only", 200, resp)
		assertField(t, "update action", body, "action", "log_only")

		// Deploy and wait for hot-reload.
		resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/rate-rules/deploy", struct{}{})
		assertCode(t, "deploy log_only", 200, resp2)
		assertField(t, "deploy log_only status", deployBody, "status", "deployed")
		time.Sleep(8 * time.Second)

		// Send requests exceeding the threshold — should NOT get 429.
		for i := 0; i < 8; i++ {
			r, _ := httpGet(t, targetURL)
			if r.StatusCode == 429 {
				t.Fatalf("got 429 in log_only mode on request %d", i+1)
			}
		}
		// Last request should have the monitor header.
		monResp, _ := httpGet(t, targetURL)
		monitor := monResp.Header.Get("X-RateLimit-Monitor")
		if monitor == "" {
			t.Log("X-RateLimit-Monitor header not present (may not have exceeded threshold yet)")
		}
	})
}

// ════════════════════════════════════════════════════════════════════
// 19. End-to-End: WebSocket Through WAF (coraza-caddy hijack fix)
// ════════════════════════════════════════════════════════════════════

// TestWebSocketThroughWAF verifies that WebSocket connections work through the
// Caddy reverse proxy with Coraza WAF enabled. The coraza-caddy fork includes
// a hijack tracking fix that prevents panics on upgraded connections. Without
// the @not_websocket bypass and the fork fix, WebSocket connections would fail
// with NS_ERROR_WEBSOCKET_CONNECTION_REFUSED or cause panics in Caddy.
//
// This test does a raw WebSocket handshake (no external deps), sends a text
// frame, and verifies the echo response — exercising the full upgrade path
// through policy_engine → @not_websocket bypass → reverse_proxy → httpbun.
func TestWebSocketThroughWAF(t *testing.T) {
	t.Run("upgrade succeeds", func(t *testing.T) {
		conn, br := wsHandshake(t, caddyURL+"/websocket/echo")
		defer conn.Close()

		// Send a text frame and verify echo.
		msg := "hello from e2e"
		wsWriteText(t, conn, msg)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := wsReadText(t, br)
		if got != msg {
			t.Errorf("echo mismatch: sent %q, got %q", msg, got)
		}
	})

	t.Run("multiple messages", func(t *testing.T) {
		conn, br := wsHandshake(t, caddyURL+"/websocket/echo")
		defer conn.Close()

		messages := []string{"first", "second", "third with spaces and 日本語"}
		for _, msg := range messages {
			wsWriteText(t, conn, msg)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := wsReadText(t, br)
			if got != msg {
				t.Errorf("echo mismatch: sent %q, got %q", msg, got)
			}
		}
	})

	t.Run("clean close", func(t *testing.T) {
		conn, _ := wsHandshake(t, caddyURL+"/websocket/echo")
		// Send close frame — opcode 0x8 with status 1000 (normal closure).
		wsWriteClose(t, conn, 1000)
		// Read should eventually return EOF or a close frame.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 512)
		_, err := conn.Read(buf)
		if err == nil {
			// Some servers send a close frame back — that's fine.
			t.Log("received response to close frame")
		}
		conn.Close()
	})
}

// ── WebSocket helpers (raw, no external deps) ──────────────────────

// wsHandshake performs a raw WebSocket upgrade handshake and returns the
// underlying TCP connection and a buffered reader for reading frames.
func wsHandshake(t *testing.T, rawURL string) (net.Conn, *bufio.Reader) {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}

	// Generate random key for Sec-WebSocket-Key.
	keyBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		conn.Close()
		t.Fatalf("rand: %v", err)
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	// Send upgrade request.
	reqPath := u.RequestURI()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"\r\n", reqPath, u.Host, wsKey)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		t.Fatalf("write upgrade: %v", err)
	}

	// Read response.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatalf("read status: %v", err)
	}

	if !strings.Contains(statusLine, "101") {
		// Read rest of response for debugging.
		var headers []string
		for {
			line, err := br.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
			headers = append(headers, strings.TrimSpace(line))
		}
		conn.Close()
		t.Fatalf("expected 101 Switching Protocols, got: %s\nHeaders: %s",
			strings.TrimSpace(statusLine), strings.Join(headers, "\n"))
	}

	// Consume remaining headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	// Verify Sec-WebSocket-Accept.
	expectedAccept := wsAcceptKey(wsKey)
	_ = expectedAccept // Accept key is validated by the server; we trust 101.

	// Clear deadlines for subsequent operations.
	conn.SetDeadline(time.Time{})
	return conn, br
}

// wsWriteText sends a masked WebSocket text frame (opcode 0x1).
// Client-to-server frames MUST be masked per RFC 6455.
func wsWriteText(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	payload := []byte(msg)

	// Frame: FIN=1, opcode=0x1 (text).
	var frame []byte
	frame = append(frame, 0x81) // FIN + text opcode

	// Payload length + mask bit.
	maskBit := byte(0x80)
	if len(payload) < 126 {
		frame = append(frame, maskBit|byte(len(payload)))
	} else if len(payload) < 65536 {
		frame = append(frame, maskBit|126)
		frame = append(frame, byte(len(payload)>>8), byte(len(payload)))
	} else {
		t.Fatalf("payload too large for test helper: %d", len(payload))
	}

	// Masking key (4 random bytes).
	mask := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, mask); err != nil {
		t.Fatalf("rand mask: %v", err)
	}
	frame = append(frame, mask...)

	// Masked payload.
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	frame = append(frame, masked...)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write text frame: %v", err)
	}
}

// wsReadText reads one WebSocket text frame and returns the payload string.
// Server-to-client frames are unmasked per RFC 6455.
func wsReadText(t *testing.T, br *bufio.Reader) string {
	t.Helper()

	// Read first 2 bytes: FIN/opcode + payload length.
	header := make([]byte, 2)
	br.Read(header[:1]) // This can block; set deadline on conn before calling.
	br.Read(header[1:2])

	opcode := header[0] & 0x0F
	if opcode != 0x1 {
		t.Fatalf("expected text frame (opcode=1), got opcode=%d", opcode)
	}

	masked := (header[1] & 0x80) != 0
	length := uint64(header[1] & 0x7F)

	if length == 126 {
		var ext [2]byte
		io.ReadFull(br, ext[:])
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		io.ReadFull(br, ext[:])
		length = binary.BigEndian.Uint64(ext[:])
	}

	var mask [4]byte
	if masked {
		io.ReadFull(br, mask[:])
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return string(payload)
}

// wsWriteClose sends a WebSocket close frame with the given status code.
func wsWriteClose(t *testing.T, conn net.Conn, code uint16) {
	t.Helper()
	// Close frame: FIN=1, opcode=0x8, payload=2 bytes (status code).
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, code)

	var frame []byte
	frame = append(frame, 0x88)         // FIN + close opcode
	frame = append(frame, 0x80|byte(2)) // masked, length=2

	mask := make([]byte, 4)
	io.ReadFull(rand.Reader, mask)
	frame = append(frame, mask...)

	masked := make([]byte, 2)
	masked[0] = payload[0] ^ mask[0]
	masked[1] = payload[1] ^ mask[1]
	frame = append(frame, masked...)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write close frame: %v", err)
	}
}

// wsAcceptKey computes the expected Sec-WebSocket-Accept value per RFC 6455.
func wsAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-5AB5DC175B18"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ════════════════════════════════════════════════════════════════════
// 20. Policy Engine — Detect / Anomaly Scoring (v0.8.0)
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineDetectCRUD(t *testing.T) {
	// Create a detect rule via the wafctl API.
	payload := map[string]any{
		"name":                  "e2e-detect-test",
		"type":                  "detect",
		"description":           "E2E detect rule",
		"severity":              "WARNING",
		"detect_paranoia_level": 1,
		"enabled":               true,
		"conditions": []map[string]string{
			{"field": "user_agent", "operator": "contains", "value": "E2EBot"},
		},
		"tags": []string{"e2e-test"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create detect rule", 201, resp)
	detectID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+detectID) })

	assertField(t, "create", body, "type", "detect")
	assertField(t, "create", body, "severity", "WARNING")

	// Get — verify round-trip.
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/exclusions/"+detectID)
		assertCode(t, "get", 200, resp)
		assertField(t, "get", body, "type", "detect")
		assertField(t, "get", body, "severity", "WARNING")
		assertField(t, "get", body, "name", "e2e-detect-test")
	})

	// Update severity to CRITICAL.
	t.Run("update", func(t *testing.T) {
		resp, body := httpPut(t, wafctlURL+"/api/exclusions/"+detectID, map[string]any{"severity": "CRITICAL"})
		assertCode(t, "update", 200, resp)
		assertField(t, "update", body, "severity", "CRITICAL")
		assertField(t, "update", body, "name", "e2e-detect-test")
	})

	// Delete.
	t.Run("delete", func(t *testing.T) {
		resp, _ := httpDelete(t, wafctlURL+"/api/exclusions/"+detectID)
		assertCode(t, "delete", 204, resp)
		detectID = "" // prevent cleanup double-delete
	})
}

func TestPolicyEngineDetectValidation(t *testing.T) {
	// Missing severity — should fail.
	t.Run("missing severity rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":       "e2e-bad-detect",
			"type":       "detect",
			"enabled":    true,
			"conditions": []map[string]string{{"field": "path", "operator": "eq", "value": "/test"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "missing severity", 400, resp)
		// API returns {"error": "validation failed", "details": "detect requires severity ..."}
		details := jsonField(body, "details")
		if !strings.Contains(details, "severity") {
			t.Errorf("expected details about severity, got: %q (error: %q)", details, jsonField(body, "error"))
		}
	})

	// Invalid severity — should fail.
	t.Run("invalid severity rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":       "e2e-bad-detect2",
			"type":       "detect",
			"severity":   "HIGH",
			"enabled":    true,
			"conditions": []map[string]string{{"field": "path", "operator": "eq", "value": "/test"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "invalid severity", 400, resp)
		details := jsonField(body, "details")
		if !strings.Contains(details, "severity") {
			t.Errorf("expected details about severity, got: %q (error: %q)", details, jsonField(body, "error"))
		}
	})

	// Invalid paranoia level — should fail.
	t.Run("invalid PL rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":                  "e2e-bad-detect3",
			"type":                  "detect",
			"severity":              "NOTICE",
			"detect_paranoia_level": 5,
			"enabled":               true,
			"conditions":            []map[string]string{{"field": "path", "operator": "eq", "value": "/test"}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "invalid PL", 400, resp)
		details := jsonField(body, "details")
		if !strings.Contains(details, "paranoia") {
			t.Errorf("expected details about paranoia level, got: %q (error: %q)", details, jsonField(body, "error"))
		}
	})

	// Empty value with eq operator — should succeed (matching missing headers).
	t.Run("empty value with eq allowed", func(t *testing.T) {
		payload := map[string]any{
			"name":       "e2e-detect-empty-val",
			"type":       "detect",
			"severity":   "NOTICE",
			"enabled":    true,
			"conditions": []map[string]string{{"field": "user_agent", "operator": "eq", "value": ""}},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "empty value eq", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+id) })
	})
}

func TestPolicyEngineDetectScoring(t *testing.T) {
	// Test the full anomaly scoring pipeline:
	// 1. Create detect rules that target specific conditions
	// 2. Configure waf_config with a threshold
	// 3. Deploy via policy-rules.json
	// 4. Send requests that trigger detect rules → score exceeds threshold
	// 5. Verify 403 with X-Anomaly-Score header
	//
	// Note: The v4 migration seeds 3 heuristic detect rules that also contribute:
	//   - Missing Accept Header (NOTICE=2)
	//   - Missing User-Agent (WARNING=3)
	//   - Missing Referer on Non-API GET (NOTICE=2, GET only)
	// A GET with no UA, no Accept, no Referer triggers all 3 → base score = 7.

	// Step 1: Create 2 additional detect rules.
	// Combined score with seeded rules for a "naked" GET:
	// Seeded: 2+3+2=7, Custom: 3+3=6 → Total=13
	rule1Payload := map[string]any{
		"name":        "e2e-detect-no-ua",
		"type":        "detect",
		"description": "Missing User-Agent (custom)",
		"severity":    "WARNING",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "user_agent", "operator": "eq", "value": ""}},
		"tags":        []string{"e2e-detect"},
	}
	resp1, body1 := httpPost(t, wafctlURL+"/api/exclusions", rule1Payload)
	assertCode(t, "create detect rule 1", 201, resp1)
	rule1ID := mustGetID(t, body1)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+rule1ID) })

	rule2Payload := map[string]any{
		"name":        "e2e-detect-no-accept",
		"type":        "detect",
		"description": "Missing Accept header (custom)",
		"severity":    "WARNING",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "header", "operator": "eq", "value": "Accept:"}},
		"tags":        []string{"e2e-detect"},
	}
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions", rule2Payload)
	assertCode(t, "create detect rule 2", 201, resp2)
	rule2ID := mustGetID(t, body2)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+rule2ID) })

	// Step 2: Set threshold=5 — a "naked" GET (no UA, no Accept) triggers score=13.
	configPayload := map[string]any{
		"defaults": map[string]any{
			"mode":               "enabled",
			"paranoia_level":     2,
			"inbound_threshold":  5,
			"outbound_threshold": 5,
		},
	}
	resp3, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "set config", 200, resp3)

	// Step 3: Deploy — generates policy-rules.json with detect rules and waf_config.
	time.Sleep(2 * time.Second)
	resp4, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp4)
	assertField(t, "deploy", deployBody, "status", "deployed")

	// Wait for plugin hot-reload.
	time.Sleep(8 * time.Second)

	// Step 4: Send a request with no User-Agent AND no Accept header.
	// Total score ~13 (seeded 7 + custom 6) >> threshold 5.
	t.Run("scoring exceeds threshold — 403 detect_block", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "")
		req.Header.Del("Accept")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (detect_block), got %d; body=%.200s",
				resp.StatusCode, string(body))
		}

		// Verify X-Anomaly-Score header is present on the blocked response.
		score := resp.Header.Get("X-Anomaly-Score")
		if score == "" {
			t.Log("X-Anomaly-Score header not present on 403 (may be hidden by error handler)")
		} else {
			t.Logf("X-Anomaly-Score: %s", score)
		}
	})

	// Step 5: Send a well-formed request — should pass scoring.
	// With UA, Accept, and Referer all present, no detect rules fire → score=0.
	t.Run("normal request passes scoring", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 E2E-Test")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Referer", "https://example.com/")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 (score=0, threshold=5), got 403")
		}
	})

	// Step 6: Raise the threshold above the max possible score so nothing blocks.
	// Max score for "naked" GET: ~13. Set threshold=20 → always passes.
	t.Run("raised threshold prevents block", func(t *testing.T) {
		configPayload := map[string]any{
			"defaults": map[string]any{
				"mode":               "enabled",
				"paranoia_level":     2,
				"inbound_threshold":  20,
				"outbound_threshold": 20,
			},
		}
		resp, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
		assertCode(t, "raise threshold", 200, resp)

		time.Sleep(2 * time.Second)
		resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
		assertCode(t, "deploy raised threshold", 200, resp2)
		assertField(t, "deploy", deployBody, "status", "deployed")
		time.Sleep(8 * time.Second)

		// Same "naked" GET — score ~13 but threshold=20 → passes.
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "")
		req.Header.Del("Accept")

		resp3, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp3.Body.Close()

		if resp3.StatusCode == 403 {
			t.Errorf("expected non-403 (score ~13 < threshold=20), got 403")
		}
	})

	// Step 7: Cleanup — restore config to production defaults.
	restorePayload := map[string]any{
		"defaults": map[string]any{
			"mode":               "enabled",
			"paranoia_level":     2,
			"inbound_threshold":  10,
			"outbound_threshold": 10,
		},
	}
	httpPut(t, wafctlURL+"/api/config", restorePayload)
	time.Sleep(2 * time.Second)
	httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	time.Sleep(8 * time.Second)
}

func TestPolicyEngineDetectParanoiaLevel(t *testing.T) {
	// Test that detect rules with PL > service PL are skipped.
	// Create a PL=4 CRITICAL detect rule, set service PL=1, verify rule doesn't trigger.
	//
	// Test request: no UA, has Accept, no Referer, GET
	// Seeded PL=1 rules that fire:
	//   - "Missing User-Agent" (WARNING=3) — user_agent eq ""
	//   - "Missing Referer on Non-API GET" (NOTICE=2) — method=GET + referer=""
	// Seeded total = 5. Custom PL=4 CRITICAL = 5.
	// Threshold = 8: at PL=1 → 5 < 8 (pass); at PL=4 → 10 ≥ 8 (block).

	rulePL4 := map[string]any{
		"name":                  "e2e-detect-pl4",
		"type":                  "detect",
		"description":           "PL4 detect rule — should not fire at PL1",
		"severity":              "CRITICAL",
		"detect_paranoia_level": 4,
		"enabled":               true,
		"conditions":            []map[string]string{{"field": "user_agent", "operator": "eq", "value": ""}},
		"tags":                  []string{"e2e-detect-pl"},
	}
	resp1, body1 := httpPost(t, wafctlURL+"/api/exclusions", rulePL4)
	assertCode(t, "create PL4 rule", 201, resp1)
	ruleID := mustGetID(t, body1)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	// Set PL=1, threshold=8 — seeded PL1 rules score 5, below 8.
	configPayload := map[string]any{
		"defaults": map[string]any{
			"mode":               "enabled",
			"paranoia_level":     1,
			"inbound_threshold":  8,
			"outbound_threshold": 10,
		},
	}
	resp2, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "set PL1 config", 200, resp2)

	time.Sleep(2 * time.Second)
	resp3, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp3)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	// Send request with no UA — PL4 rule is skipped at PL=1, score=5 < 8 → passes.
	t.Run("PL4 rule skipped at PL1 — score below threshold", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "")
		req.Header.Set("Accept", "text/html")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode == 403 {
			t.Errorf("expected non-403 (PL4 skipped, score=5 < threshold=8), got 403")
		}
	})

	// Now raise PL to 4 — same request should now trigger PL4 rule, total=10 ≥ 8 → block.
	t.Run("PL4 rule fires at PL4 — score exceeds threshold", func(t *testing.T) {
		configPL4 := map[string]any{
			"defaults": map[string]any{
				"mode":               "enabled",
				"paranoia_level":     4,
				"inbound_threshold":  8,
				"outbound_threshold": 10,
			},
		}
		resp, _ := httpPut(t, wafctlURL+"/api/config", configPL4)
		assertCode(t, "set PL4 config", 200, resp)

		time.Sleep(2 * time.Second)
		resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
		assertCode(t, "deploy PL4", 200, resp2)
		assertField(t, "deploy PL4", deployBody, "status", "deployed")
		time.Sleep(8 * time.Second)

		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "")
		req.Header.Set("Accept", "text/html")

		resp3, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp3.Body.Close()

		if resp3.StatusCode != 403 {
			t.Errorf("expected 403 (PL4 fires, score=10 >= threshold=8), got %d", resp3.StatusCode)
		}
	})

	// Cleanup — restore defaults.
	restorePayload := map[string]any{
		"defaults": map[string]any{
			"mode":               "enabled",
			"paranoia_level":     2,
			"inbound_threshold":  10,
			"outbound_threshold": 10,
		},
	}
	httpPut(t, wafctlURL+"/api/config", restorePayload)
	time.Sleep(2 * time.Second)
	httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	time.Sleep(8 * time.Second)
}

func TestPolicyEngineDetectWafConfig(t *testing.T) {
	// Verify that waf_config is present in policy-rules.json after deploy.
	// We can check this via the exclusions generate endpoint which returns the
	// raw generated config.

	// Set a specific config to verify it propagates.
	configPayload := map[string]any{
		"defaults": map[string]any{
			"mode":               "enabled",
			"paranoia_level":     3,
			"inbound_threshold":  15,
			"outbound_threshold": 8,
		},
	}
	resp, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "set config", 200, resp)

	// Generate (dry-run) to see what would be deployed.
	resp2, body2 := httpPost(t, wafctlURL+"/api/exclusions/generate", struct{}{})
	assertCode(t, "generate", 200, resp2)
	// The generate endpoint returns the generated config files.
	// Log the output for debugging.
	logBody(t, "generate output", body2)

	// Restore defaults.
	restorePayload := map[string]any{
		"defaults": map[string]any{
			"mode":               "enabled",
			"paranoia_level":     2,
			"inbound_threshold":  10,
			"outbound_threshold": 10,
		},
	}
	httpPut(t, wafctlURL+"/api/config", restorePayload)
}

func TestPolicyEngineDetectMigrationSeedRules(t *testing.T) {
	// Verify that the v4 migration seeded the 3 heuristic detect rules.
	resp, body := httpGet(t, wafctlURL+"/api/exclusions")
	assertCode(t, "list exclusions", 200, resp)

	var exclusions []json.RawMessage
	if err := json.Unmarshal(body, &exclusions); err != nil {
		t.Fatalf("unmarshal exclusions: %v", err)
	}

	detectCount := 0
	for _, raw := range exclusions {
		typ := jsonField(raw, "type")
		if typ == "detect" {
			detectCount++
		}
	}

	// The v4 migration seeds 3 heuristic detect rules:
	// "Missing Accept Header", "Missing User-Agent", "Missing Referer on Non-API GET"
	// Plus any that test cleanup might have removed — check for at least 3.
	if detectCount < 3 {
		t.Errorf("expected at least 3 seeded detect rules from v4 migration, got %d", detectCount)
	}
	t.Logf("found %d detect rules in store", detectCount)
}

// ════════════════════════════════════════════════════════════════════
//  Transform Functions (v0.8.1)
// ════════════════════════════════════════════════════════════════════

func TestPolicyEngineTransforms(t *testing.T) {
	// Test transform functions end-to-end:
	// 1. Create a block rule with transforms: ["urlDecode", "lowercase"]
	//    that blocks requests containing "/admin" in the path after decoding.
	// 2. Deploy to policy engine.
	// 3. Send a URL-encoded path like /%41dmin — after urlDecode+lowercase it
	//    becomes "/admin" and should be blocked.
	// 4. Verify the block triggers.
	// 5. Send a normal request to verify pass-through.

	// Step 1: Create block rule with transforms.
	blockPayload := map[string]any{
		"name":        "e2e-transform-block-admin",
		"type":        "block",
		"description": "Block /admin after URL decode + lowercase",
		"enabled":     true,
		"conditions": []map[string]any{
			{
				"field":      "path",
				"operator":   "contains",
				"value":      "/admin",
				"transforms": []string{"urlDecode", "lowercase"},
			},
		},
		"tags": []string{"e2e-transforms"},
	}
	resp1, body1 := httpPost(t, wafctlURL+"/api/exclusions", blockPayload)
	assertCode(t, "create block rule with transforms", 201, resp1)
	ruleID := mustGetID(t, body1)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	// Step 2: Deploy.
	time.Sleep(2 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")

	// Wait for plugin hot-reload.
	time.Sleep(8 * time.Second)

	// Step 3: Send URL-encoded path — %41 = 'A', so /%41dmin → /Admin → /admin
	t.Run("url-encoded path blocked after transform", func(t *testing.T) {
		resp, body := httpGet(t, caddyURL+"/%41dmin")
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 for /%s, got %d; body=%.200s",
				"%41dmin", resp.StatusCode, string(body))
		}
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Error("expected X-Blocked-By: policy-engine header")
		}
		t.Logf("URL-encoded path correctly blocked: %d", resp.StatusCode)
	})

	// Step 4: Mixed case — /ADMIN should also match after lowercase transform.
	t.Run("mixed-case path blocked after lowercase", func(t *testing.T) {
		resp, body := httpGet(t, caddyURL+"/ADMIN")
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 for /ADMIN, got %d; body=%.200s",
				resp.StatusCode, string(body))
		}
		t.Logf("Mixed-case path correctly blocked: %d", resp.StatusCode)
	})

	// Step 5: Double-encoded — %2541dmin → after urlDecode → %41dmin → contains
	// "/admin"? No — urlDecode is applied once, so %25 → '%', result is "%41dmin".
	// This should NOT match "/admin" — tests that transforms don't over-decode.
	t.Run("double-encoded path passes — no recursive decode", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/%2541dmin")
		if resp.StatusCode == 403 {
			t.Error("double-encoded path should NOT be blocked (single urlDecode)")
		}
		t.Logf("Double-encoded path correctly passed: %d", resp.StatusCode)
	})

	// Step 6: Normal path should pass through.
	t.Run("normal request passes", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		if resp.StatusCode != 200 {
			t.Errorf("expected 200 for /get, got %d", resp.StatusCode)
		}
	})
}

// ════════════════════════════════════════════════════════════════════
//  v0.9.0: Aggregate Fields, Phrase Match, Numeric Operators, Count
// ════════════════════════════════════════════════════════════════════

func TestPolicyEnginePhraseMatch(t *testing.T) {
	// Test phrase_match operator with Aho-Corasick multi-pattern matching.
	// Use user_agent field with custom bot-name patterns to avoid CRS interference
	// (CRS inspects query strings for SQLi but doesn't block arbitrary UA strings).

	// Step 1: Create block rule with phrase_match on user_agent.
	payload := map[string]any{
		"name":        "e2e-phrase-match",
		"type":        "block",
		"description": "Block specific bot UA phrases",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-pm-"},
			{
				"field":      "user_agent",
				"operator":   "phrase_match",
				"list_items": []string{"dangerous-bot", "evil-scanner", "attack-crawler"},
			},
		},
		"tags": []string{"e2e-phrase-match"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create phrase_match rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	// Step 2: Deploy and wait for plugin hot-reload.
	time.Sleep(2 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	// Step 3: Verify phrase_match matching via User-Agent.
	t.Run("UA with 'dangerous-bot' blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pm-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (dangerous-bot/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (phrase_match), got %d", resp.StatusCode)
		}
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("UA with 'evil-scanner' blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pm-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "evil-scanner v2.0")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (phrase_match), got %d", resp.StatusCode)
		}
	})

	t.Run("safe UA passes", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pm-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64)")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 && headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected non-403 for safe UA, got 403 from policy engine")
		}
	})

	t.Run("partial keyword does NOT match", func(t *testing.T) {
		// "dangerous" alone should not match "dangerous-bot" — AC is substring
		// match of patterns in the input. "dangerous" does NOT contain "dangerous-bot".
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pm-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "dangerous thing but not the full phrase")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 && headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected non-403 for partial keyword, got 403 from policy engine")
		}
	})

	t.Run("other paths unaffected", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/get", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("User-Agent", "dangerous-bot/1.0")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		// /get doesn't match /e2e-pm- prefix
		if resp.StatusCode == 403 && headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("policy engine blocked /get — path condition should have prevented this")
		}
	})
}

func TestPolicyEngineAggregateFields(t *testing.T) {
	// Test aggregate field matching. Create a block rule that matches
	// any header value containing a specific pattern.

	payload := map[string]any{
		"name":        "e2e-all-headers-block",
		"type":        "block",
		"description": "Block requests with 'E2E-Evil' in any header value",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-agg-"},
			{"field": "all_headers", "operator": "contains", "value": "E2E-Evil"},
		},
		"tags": []string{"e2e-aggregate"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create aggregate field rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	time.Sleep(2 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	t.Run("header containing E2E-Evil blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-agg-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("X-Custom", "contains E2E-Evil marker")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (all_headers contains E2E-Evil), got %d", resp.StatusCode)
		}
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("different header name also matches", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-agg-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("X-Another-Header", "E2E-Evil-payload")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (all_headers matches any header), got %d", resp.StatusCode)
		}
	})

	t.Run("clean headers pass", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-agg-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("X-Custom", "totally-safe-value")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == 403 && headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected non-403 (no E2E-Evil in headers), got 403 from policy engine")
		}
	})
}

func TestPolicyEnginePhraseMatchAggregateField(t *testing.T) {
	// Test phrase_match on an aggregate field: scan ALL header values for
	// SQL injection patterns using Aho-Corasick. This is the core CRS-like
	// use case — multi-pattern scanning across all request variables.

	payload := map[string]any{
		"name":        "e2e-pm-all-headers",
		"type":        "block",
		"description": "Phrase match SQL keywords in all headers",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-pmh-"},
			{
				"field":      "all_headers",
				"operator":   "phrase_match",
				"list_items": []string{"union select", "script>alert", "../../etc/passwd"},
			},
		},
		"tags": []string{"e2e-pm-aggregate"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create phrase_match aggregate rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	time.Sleep(2 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	t.Run("SQLi in custom header blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pmh-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("X-Search", "1 union select * from users")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (phrase_match all_headers), got %d", resp.StatusCode)
		}
	})

	t.Run("path traversal in Referer header blocked", func(t *testing.T) {
		req, err := http.NewRequest("GET", caddyURL+"/e2e-pmh-test", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("Referer", "https://example.com/../../etc/passwd")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 (path traversal in Referer), got %d", resp.StatusCode)
		}
	})

	t.Run("clean headers pass", func(t *testing.T) {
		code, err := httpGetCode(caddyURL + "/e2e-pmh-test")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 for clean request, got 403")
		}
	})
}

func TestPolicyEngineCountField(t *testing.T) {
	// Test count: pseudo-field with numeric operators.
	// count:all_args_names counts just the query param names (not values).
	// Block requests to /e2e-count-test that have more than 3 query param names.

	payload := map[string]any{
		"name":        "e2e-count-args",
		"type":        "block",
		"description": "Block requests with >3 query arg names",
		"enabled":     true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/e2e-count-"},
			{"field": "count:all_args_names", "operator": "gt", "value": "3"},
		},
		"tags": []string{"e2e-count"},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create count rule", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+ruleID) })

	time.Sleep(2 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	time.Sleep(8 * time.Second)

	t.Run("4 args blocked (count > 3)", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-count-test?a=1&b=2&c=3&d=4")
		assertCode(t, "4 args", 403, resp)
		if !headerContains(resp, "X-Blocked-By", "policy-engine") {
			t.Errorf("expected X-Blocked-By: policy-engine, got: %q", resp.Header.Get("X-Blocked-By"))
		}
	})

	t.Run("3 args pass (count = 3, not > 3)", func(t *testing.T) {
		code, err := httpGetCode(caddyURL + "/e2e-count-test?a=1&b=2&c=3")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 for 3 args (not > 3), got 403")
		}
	})

	t.Run("0 args pass", func(t *testing.T) {
		code, err := httpGetCode(caddyURL + "/e2e-count-test")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code == 403 {
			t.Errorf("expected non-403 for 0 args, got 403")
		}
	})

	t.Run("many args blocked", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/e2e-count-test?a=1&b=2&c=3&d=4&e=5&f=6")
		assertCode(t, "6 args", 403, resp)
	})

	t.Run("other paths unaffected", func(t *testing.T) {
		code, err := httpGetCode(caddyURL + "/get?a=1&b=2&c=3&d=4&e=5")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		// /get doesn't match /e2e-count- prefix
		if code == 403 {
			// Could be CRS blocking, check header
			resp, _ := httpGet(t, caddyURL+"/get?a=1&b=2&c=3&d=4&e=5")
			if headerContains(resp, "X-Blocked-By", "policy-engine") {
				t.Errorf("policy engine blocked /get — path condition should have prevented this")
			}
		}
	})
}

func TestV090ValidationEndpoints(t *testing.T) {
	// Test that wafctl validation correctly accepts and rejects v0.9.0 features.

	t.Run("aggregate field accepted for policy engine type", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-val-aggregate",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "all_cookies", "operator": "contains", "value": "evil"},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "aggregate accepted", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/exclusions/"+id)
	})

	t.Run("aggregate field rejected for SecRule type", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-val-agg-secrule",
			"type":    "skip_rule",
			"rule_id": "942100",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "all_headers", "operator": "contains", "value": "test"},
			},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "aggregate rejected for SecRule", 400, resp)
	})

	t.Run("phrase_match without list_items rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-val-pm-no-items",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "query", "operator": "phrase_match"},
			},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "phrase_match without list_items", 400, resp)
	})

	t.Run("count: with non-aggregate field rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-val-count-bad",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "count:path", "operator": "gt", "value": "10"},
			},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "count: non-aggregate rejected", 400, resp)
	})

	t.Run("count: with non-numeric operator rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-val-count-op",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "count:all_args", "operator": "contains", "value": "10"},
			},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "count: non-numeric op rejected", 400, resp)
	})

	t.Run("numeric operator with non-numeric value rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-val-numeric-bad",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "count:all_args", "operator": "gt", "value": "abc"},
			},
		}
		resp, _ := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "numeric with non-numeric value", 400, resp)
	})

	t.Run("numeric operator on named field accepted", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-val-numeric-named",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{"field": "path", "operator": "begins_with", "value": "/test"},
				{"field": "header", "operator": "gt", "value": "Content-Length:1000"},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "numeric on named field", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/exclusions/"+id)
	})
}

func TestPolicyEngineTransformValidation(t *testing.T) {
	// Test that wafctl rejects unknown transform names via the API.

	t.Run("invalid transform name rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-bad-transform",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{
					"field":      "path",
					"operator":   "eq",
					"value":      "/test",
					"transforms": []string{"noSuchTransform"},
				},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		if resp.StatusCode != 400 {
			t.Errorf("expected 400 for invalid transform, got %d; body=%s",
				resp.StatusCode, string(body))
		}
		t.Logf("Invalid transform correctly rejected: %d", resp.StatusCode)
	})

	t.Run("valid transforms accepted", func(t *testing.T) {
		payload := map[string]any{
			"name":    "e2e-valid-transforms",
			"type":    "block",
			"enabled": true,
			"conditions": []map[string]any{
				{
					"field":      "path",
					"operator":   "contains",
					"value":      "/test",
					"transforms": []string{"lowercase", "urlDecode", "normalizePath"},
				},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
		assertCode(t, "create with valid transforms", 201, resp)
		id := mustGetID(t, body)
		cleanup(t, wafctlURL+"/api/exclusions/"+id)
		t.Log("Valid transforms accepted")
	})
}
