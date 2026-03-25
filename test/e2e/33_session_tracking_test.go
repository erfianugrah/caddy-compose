package e2e_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// ════════════════════════════════════════════════════════════════════
//  33. Session Tracking — Phase 1 (Foundation)
// ════════════════════════════════════════════════════════════════════

func TestSessionSWJSServed(t *testing.T) {
	// The session service worker JS should be served at the expected path
	// with correct Content-Type, caching headers, and Service-Worker-Allowed.
	resp, body := httpGet(t, caddyURL+"/.well-known/policy-challenge/session-sw.js")
	assertCode(t, "session-sw.js", 200, resp)

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want application/javascript", ct)
	}

	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "public") {
		t.Errorf("Cache-Control = %q, want public", cc)
	}

	// Critical: Service-Worker-Allowed header must be "/" so the SW can be
	// registered with origin-wide scope from /.well-known/policy-challenge/.
	swa := resp.Header.Get("Service-Worker-Allowed")
	if swa != "/" {
		t.Errorf("Service-Worker-Allowed = %q, want /", swa)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "clients.claim") {
		t.Error("session-sw.js missing clients.claim() call")
	}
	if !strings.Contains(bodyStr, "navigate") {
		t.Error("session-sw.js missing navigate mode check")
	}
	if !strings.Contains(bodyStr, "policy-challenge/session") {
		t.Error("session-sw.js missing beacon URL")
	}
}

func TestSessionBeaconEndpointAcceptsPOST(t *testing.T) {
	// The beacon endpoint should accept POST and return 204 No Content.
	payload := []byte(`[{"ts":1711000000000,"path":"/test","type":"pm","vis":5000,"scr":50,"clk":3,"key":1}]`)
	status, err := httpPostRaw(caddyURL+"/.well-known/policy-challenge/session", payload)
	if err != nil {
		t.Fatalf("beacon POST failed: %v", err)
	}
	if status != http.StatusNoContent {
		t.Errorf("beacon POST status = %d, want 204", status)
	}
}

func TestSessionBeaconEndpointRejectsGET(t *testing.T) {
	// GET to the beacon endpoint should return 405 Method Not Allowed.
	resp, _ := httpGet(t, caddyURL+"/.well-known/policy-challenge/session")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("beacon GET status = %d, want 405", resp.StatusCode)
	}
}

func TestChallengeInterstitialContainsSWRegistration(t *testing.T) {
	ensureDefaultConfig(t)

	// Create a challenge rule.
	payload := map[string]any{
		"name":                 "e2e-session-sw-reg",
		"type":                 "challenge",
		"enabled":              true,
		"challenge_difficulty": 1,
		"conditions": []map[string]string{
			{"field": "path", "operator": "begins_with", "value": "/e2e-session-test"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/rules", payload)
	assertCode(t, "create", 201, resp)
	ruleID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/rules/"+ruleID)
		deployWAF(t)
	})

	deployAndWaitForStatus(t, caddyURL+"/e2e-session-test", 200)

	// Fetch the interstitial and verify it contains SW registration code.
	resp, body = httpGet(t, caddyURL+"/e2e-session-test")
	assertCode(t, "interstitial", 200, resp)

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "serviceWorker") {
		t.Error("interstitial missing serviceWorker reference")
	}
	if !strings.Contains(bodyStr, "session-sw.js") {
		t.Error("interstitial missing session-sw.js registration")
	}
}

func TestSessionStatsEndpoint(t *testing.T) {
	// The /api/sessions/stats endpoint should return valid JSON with expected structure.
	resp, body := httpGet(t, wafctlURL+"/api/sessions/stats")
	assertCode(t, "session stats", 200, resp)

	var stats struct {
		ActiveSessions     int `json:"active_sessions"`
		SuspiciousSessions int `json:"suspicious_sessions"`
		TotalNavigations   int `json:"total_navigations"`
	}
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("unmarshal session stats: %v", err)
	}
	if stats.ActiveSessions < 0 {
		t.Errorf("active_sessions = %d, want >= 0", stats.ActiveSessions)
	}
}

func TestChallengeFailReasonPopulated(t *testing.T) {
	// Submit an invalid PoW to the verify endpoint — the fail_reason
	// should be populated (not empty/unknown). We use httpPostRaw
	// (which sends JSON content type) so we can't really send form data,
	// but the verify endpoint will reject due to missing form fields,
	// which should produce a "missing_fields" fail reason.
	payload := []byte(`{}`)
	status, err := httpPostRaw(caddyURL+"/.well-known/policy-challenge/verify", payload)
	if err != nil {
		t.Fatalf("verify POST failed: %v", err)
	}
	// Should return 403 (missing fields).
	if status == 404 {
		t.Error("verify endpoint returned 404 — not registered")
	}
	if status != http.StatusForbidden {
		t.Errorf("verify POST status = %d, want 403", status)
	}
	// We can't easily check the Caddy variable from the E2E test, but we
	// verify the endpoint is reachable and rejects properly. The fail_reason
	// variable is tested via the access log pipeline in later tests.
}
