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

func TestSessionListEndpoint(t *testing.T) {
	resp, body := httpGet(t, wafctlURL+"/api/sessions/list")
	assertCode(t, "session list", 200, resp)

	var list struct {
		Sessions []json.RawMessage `json:"sessions"`
		Total    int               `json:"total"`
		Offset   int               `json:"offset"`
		Limit    int               `json:"limit"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if list.Total < 0 {
		t.Errorf("total = %d, want >= 0", list.Total)
	}
	if list.Limit <= 0 {
		t.Errorf("limit = %d, want > 0", list.Limit)
	}
}

func TestSessionListWithFilters(t *testing.T) {
	t.Run("min_score", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/sessions/list?min_score=0.5")
		assertCode(t, "with min_score", 200, resp)
	})
	t.Run("ip_filter", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/sessions/list?ip=1.2.3.4")
		assertCode(t, "with ip filter", 200, resp)
	})
	t.Run("pagination", func(t *testing.T) {
		resp, _ := httpGet(t, wafctlURL+"/api/sessions/list?offset=0&limit=10")
		assertCode(t, "with pagination", 200, resp)
	})
}

func TestSessionAlertsEndpoint(t *testing.T) {
	resp, body := httpGet(t, wafctlURL+"/api/sessions/alerts")
	assertCode(t, "session alerts", 200, resp)

	var alerts []json.RawMessage
	if err := json.Unmarshal(body, &alerts); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Alerts should be an array (may be empty).
	if alerts == nil {
		t.Error("alerts should be an array, not null")
	}
}

func TestSessionConfigEndpoint(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/sessions/config")
		assertCode(t, "get config", 200, resp)

		var cfg struct {
			DenylistEnabled   bool    `json:"denylist_enabled"`
			DenylistThreshold float64 `json:"denylist_threshold"`
			WeightSinglePage  float64 `json:"weight_single_page"`
		}
		if err := json.Unmarshal(body, &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		// Default: denylist disabled.
		if cfg.DenylistEnabled {
			t.Error("default denylist_enabled should be false")
		}
		if cfg.DenylistThreshold < 0 || cfg.DenylistThreshold > 1 {
			t.Errorf("threshold = %.2f, want [0, 1]", cfg.DenylistThreshold)
		}
	})

	t.Run("update", func(t *testing.T) {
		// Read current config, modify, PUT back.
		_, body := httpGet(t, wafctlURL+"/api/sessions/config")
		var cfg map[string]any
		json.Unmarshal(body, &cfg)
		cfg["denylist_threshold"] = 0.75
		resp, body := httpPut(t, wafctlURL+"/api/sessions/config", cfg)
		assertCode(t, "update config", 200, resp)

		// Verify the updated value.
		var updated struct {
			DenylistThreshold float64 `json:"denylist_threshold"`
		}
		json.Unmarshal(body, &updated)
		if updated.DenylistThreshold != 0.75 {
			t.Errorf("updated threshold = %.2f, want 0.75", updated.DenylistThreshold)
		}

		// Restore default.
		cfg["denylist_threshold"] = 0.6
		httpPut(t, wafctlURL+"/api/sessions/config", cfg)
	})
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
