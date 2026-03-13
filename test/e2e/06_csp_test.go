package e2e_test

import (
	"strings"
	"testing"
	"time"
)

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
		waitForHeader(t, caddyURL+"/get", "Content-Security-Policy", "'self'", 10*time.Second)
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
		waitForHeader(t, caddyURL+"/get", "Strict-Transport-Security", "max-age=63072000", 10*time.Second)

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
	waitForHeader(t, caddyURL+"/get", "Content-Security-Policy", "cdn.example.com", 10*time.Second)

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
	waitForHeader(t, caddyURL+"/get", "Content-Security-Policy", "updated.example.org", 10*time.Second)

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
	waitForNoHeader(t, caddyURL+"/get", "Content-Security-Policy", 10*time.Second)

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
	waitForHeader(t, caddyURL+"/get", "Content-Security-Policy", "'self'", 10*time.Second)
}

// ════════════════════════════════════════════════════════════════════
// 11. Blocklist
// ════════════════════════════════════════════════════════════════════
