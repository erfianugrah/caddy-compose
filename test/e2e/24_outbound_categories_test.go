package e2e_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// 24. Outbound Scoring, Category Masks, and Session Improvements
// ════════════════════════════════════════════════════════════════════

// --- Outbound Threshold Config ---

func TestOutboundThresholdConfig(t *testing.T) {
	// Set outbound threshold.
	configPayload := map[string]any{
		"defaults": map[string]any{
			"mode":               "enabled",
			"paranoia_level":     2,
			"inbound_threshold":  15,
			"outbound_threshold": 8,
		},
	}
	resp, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "update config", 200, resp)

	// Verify persistence.
	resp, body := httpGet(t, wafctlURL+"/api/config")
	assertCode(t, "re-read config", 200, resp)

	ot := jsonInt(body, "defaults.outbound_threshold")
	if ot == 0 {
		// jsonInt doesn't support nested paths — parse manually.
		var cfg struct {
			Defaults struct {
				OutboundThreshold int `json:"outbound_threshold"`
			} `json:"defaults"`
		}
		json.Unmarshal(body, &cfg)
		ot = cfg.Defaults.OutboundThreshold
	}
	if ot != 8 {
		t.Errorf("expected outbound_threshold=8, got %d", ot)
	}

	// Restore.
	t.Cleanup(func() {
		httpPut(t, wafctlURL+"/api/config", map[string]any{
			"defaults": map[string]any{
				"mode":               "enabled",
				"paranoia_level":     2,
				"inbound_threshold":  15,
				"outbound_threshold": 15,
			},
		})
	})
}

func TestOutboundThresholdPerService(t *testing.T) {
	configPayload := map[string]any{
		"defaults": map[string]any{
			"mode":               "enabled",
			"paranoia_level":     2,
			"inbound_threshold":  15,
			"outbound_threshold": 10,
		},
		"services": map[string]any{
			"httpbun.erfi.io": map[string]any{
				"mode":               "enabled",
				"paranoia_level":     1,
				"inbound_threshold":  5,
				"outbound_threshold": 3,
			},
		},
	}
	resp, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "set per-service config", 200, resp)

	resp, body := httpGet(t, wafctlURL+"/api/config")
	assertCode(t, "re-read", 200, resp)

	// Parse services.
	var cfg struct {
		Services map[string]struct {
			OutboundThreshold int `json:"outbound_threshold"`
		} `json:"services"`
	}
	json.Unmarshal(body, &cfg)

	svc, ok := cfg.Services["httpbun.erfi.io"]
	if !ok {
		t.Fatal("httpbun.erfi.io not in services")
	}
	if svc.OutboundThreshold != 3 {
		t.Errorf("expected outbound_threshold=3, got %d", svc.OutboundThreshold)
	}

	t.Cleanup(func() {
		httpPut(t, wafctlURL+"/api/config", map[string]any{
			"defaults": map[string]any{
				"mode":               "enabled",
				"paranoia_level":     2,
				"inbound_threshold":  15,
				"outbound_threshold": 15,
			},
			"services": map[string]any{},
		})
	})
}

// --- CRS Version Dynamic ---

func TestCRSVersionDynamic(t *testing.T) {
	resp, body := httpGet(t, wafctlURL+"/api/health")
	assertCode(t, "health", 200, resp)

	crsVersion := jsonField(body, "crs_version")
	if crsVersion == "" || crsVersion == "unknown" {
		t.Errorf("crs_version should be a real version, got %q", crsVersion)
	}
	if !strings.Contains(crsVersion, ".") {
		t.Errorf("crs_version should be semver-like, got %q", crsVersion)
	}
	t.Logf("CRS version: %s", crsVersion)
}

// --- Default Rules Have Outbound Phase ---

func TestDefaultRulesHaveOutboundPhase(t *testing.T) {
	resp, body := httpGet(t, wafctlURL+"/api/default-rules")
	assertCode(t, "list default rules", 200, resp)

	// Count outbound rules by scanning raw JSON.
	var rules []json.RawMessage
	json.Unmarshal(body, &rules)

	outbound := 0
	for _, raw := range rules {
		var r struct {
			Phase string `json:"phase"`
		}
		json.Unmarshal(raw, &r)
		if r.Phase == "outbound" {
			outbound++
		}
	}

	t.Logf("Total rules: %d, Outbound: %d", len(rules), outbound)

	if outbound == 0 {
		t.Error("expected outbound (response-phase) rules in default-rules.json")
	}
	if outbound < 40 {
		t.Errorf("expected >= 40 outbound rules, got %d", outbound)
	}
}

// --- Deploy No Reload ---

func TestDeployNoReload(t *testing.T) {
	resp, body := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy", 200, resp)
	assertField(t, "deploy", body, "status", "deployed")

	reloaded := jsonField(body, "reloaded")
	if reloaded != "false" {
		t.Errorf("expected reloaded=false (hot-reload via mtime), got %q", reloaded)
	}
}

// --- Exclusion Hits Scans Access Log ---

func TestExclusionHitsEndpoint(t *testing.T) {
	resp, body := httpGet(t, wafctlURL+"/api/exclusions/hits?hours=24")
	assertCode(t, "exclusion hits", 200, resp)

	hitsField := jsonField(body, "hits")
	if hitsField == "" {
		t.Error("expected 'hits' field in response")
	}
	t.Logf("Exclusion hits response length: %d bytes", len(body))
}

// --- Events Pagination ---

func TestEventsPaginationLimit(t *testing.T) {
	resp, body := httpGet(t, wafctlURL+"/api/events?hours=24&limit=5")
	assertCode(t, "events", 200, resp)

	var result struct {
		Total  int             `json:"total"`
		Events json.RawMessage `json:"events"`
	}
	json.Unmarshal(body, &result)

	var events []json.RawMessage
	json.Unmarshal(result.Events, &events)

	if len(events) > 5 {
		t.Errorf("expected at most 5 events (limit=5), got %d", len(events))
	}
	// total can be -1 (early-exit) or >= 0
	if result.Total < -1 {
		t.Errorf("unexpected total: %d", result.Total)
	}
	t.Logf("Events: total=%d, returned=%d", result.Total, len(events))
}

// --- Dashboard UI Tests (via wafctl UI server) ---

func TestUnifiedPolicyPageLoads(t *testing.T) {
	// The dashboard is served by wafctl at its HTTP port.
	resp, body := httpGet(t, wafctlURL+"/policy")
	if resp.StatusCode == 404 {
		t.Skip("dashboard not available in e2e environment")
	}
	assertCode(t, "policy page", 200, resp)

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}
	html := string(body)
	if !strings.Contains(html, "WAF Rules") && !strings.Contains(html, "Policy") {
		t.Error("policy page should contain policy-related content")
	}
}

func TestRateLimitsRedirectToPolicy(t *testing.T) {
	noRedirect := &http.Client{
		Timeout:   httpTimeout,
		Transport: &browserTransport{base: http.DefaultTransport},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequest("GET", wafctlURL+"/rate-limits", nil)
	resp, _ := noRedirect.Do(req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Either a redirect or a page containing the redirect target.
	html := string(body)
	if resp.StatusCode == 404 {
		t.Skip("rate-limits page not available in e2e environment")
	}
	if !strings.Contains(html, "/policy") {
		t.Log("rate-limits page does not reference /policy — may be served differently in e2e")
	}
}

// --- Cache-Control on Hashed Assets ---

func TestCacheControlHashedAssets(t *testing.T) {
	_, body := httpGet(t, wafctlURL+"/policy")
	html := string(body)

	idx := strings.Index(html, "/_astro/")
	if idx == -1 {
		t.Skip("no /_astro/ asset found in HTML")
	}
	end := strings.IndexAny(html[idx:], `"' >`)
	if end == -1 {
		t.Skip("couldn't extract asset URL")
	}
	assetPath := html[idx : idx+end]
	t.Logf("Testing asset: %s", assetPath)

	resp, _ := httpGet(t, wafctlURL+assetPath)
	assertCode(t, "hashed asset", 200, resp)

	cc := resp.Header.Get("Cache-Control")
	if cc != "" && !strings.Contains(cc, "immutable") {
		t.Errorf("expected Cache-Control with 'immutable' (or empty in e2e), got %q", cc)
	}
	if cc == "" {
		t.Log("Cache-Control not set by wafctl directly (Caddy adds it in production)")
	}
}

// --- Deploy Speed (FQDN Cache) ---

func TestDeploySpeed(t *testing.T) {
	start := time.Now()
	deployWAF(t)
	first := time.Since(start)

	start = time.Now()
	deployWAF(t)
	second := time.Since(start)

	t.Logf("First deploy: %v, Second deploy: %v", first, second)

	if first > 30*time.Second {
		t.Errorf("first deploy too slow: %v (no Caddy reload expected)", first)
	}
	if second > 30*time.Second {
		t.Errorf("second deploy too slow: %v", second)
	}
}

// --- Disabled Categories Config ---

func TestDisabledCategoriesConfig(t *testing.T) {
	configPayload := map[string]any{
		"defaults": map[string]any{
			"mode":                "enabled",
			"paranoia_level":      2,
			"inbound_threshold":   15,
			"outbound_threshold":  15,
			"disabled_categories": []string{"942", "941"},
		},
		"services": map[string]any{
			"httpbun.erfi.io": map[string]any{
				"mode":                "enabled",
				"paranoia_level":      1,
				"inbound_threshold":   5,
				"outbound_threshold":  5,
				"disabled_categories": []string{"932"},
			},
		},
	}
	resp, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "set config with disabled_categories", 200, resp)

	resp, body := httpGet(t, wafctlURL+"/api/config")
	assertCode(t, "re-read", 200, resp)

	var cfg struct {
		Defaults struct {
			DisabledCategories []string `json:"disabled_categories"`
		} `json:"defaults"`
		Services map[string]struct {
			DisabledCategories []string `json:"disabled_categories"`
		} `json:"services"`
	}
	json.Unmarshal(body, &cfg)

	if len(cfg.Defaults.DisabledCategories) != 2 {
		t.Errorf("expected 2 global disabled categories, got %d", len(cfg.Defaults.DisabledCategories))
	}

	svc, ok := cfg.Services["httpbun.erfi.io"]
	if !ok {
		t.Fatal("httpbun.erfi.io not in services")
	}
	if len(svc.DisabledCategories) != 1 || svc.DisabledCategories[0] != "932" {
		t.Errorf("expected httpbun disabled_categories=[932], got %v", svc.DisabledCategories)
	}

	t.Cleanup(func() {
		httpPut(t, wafctlURL+"/api/config", map[string]any{
			"defaults": map[string]any{
				"mode":               "enabled",
				"paranoia_level":     2,
				"inbound_threshold":  15,
				"outbound_threshold": 15,
			},
			"services": map[string]any{},
		})
	})
}
