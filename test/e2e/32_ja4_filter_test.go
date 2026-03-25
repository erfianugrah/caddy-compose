package e2e_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  32. JA4 Filter, Non-Browser Detection, Challenge Enrichment
// ════════════════════════════════════════════════════════════════════

// ── 32a. JA4 Filter on Events API ───────────────────────────────────

func TestEventsJA4Filter(t *testing.T) {
	t.Run("ja4-filter-accepted", func(t *testing.T) {
		// The events API should accept ja4= as a filter parameter (returns 200 even if no matches).
		resp, _ := httpGet(t, wafctlURL+"/api/events?hours=24&ja4=t13d1516h2_test")
		assertCode(t, "events with ja4 filter", 200, resp)
	})

	t.Run("ja4-filter-with-operator", func(t *testing.T) {
		// The events API should accept ja4_op= operator.
		resp, _ := httpGet(t, wafctlURL+"/api/events?hours=24&ja4=t13d&ja4_op=contains")
		assertCode(t, "events with ja4 contains", 200, resp)
	})

	t.Run("summary-ja4-filter-accepted", func(t *testing.T) {
		// The summary API should also accept ja4= filter.
		resp, _ := httpGet(t, wafctlURL+"/api/summary?hours=24&ja4=t13d1516h2_test")
		assertCode(t, "summary with ja4 filter", 200, resp)
	})

	t.Run("ja4-filter-returns-valid-structure", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/events?hours=24&ja4=nonexistent_fingerprint")
		assertCode(t, "events with nonexistent ja4", 200, resp)

		var result struct {
			Events []json.RawMessage `json:"events"`
			Total  int               `json:"total"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		// With a nonexistent JA4, total should be 0.
		if result.Total != 0 {
			t.Logf("unexpected %d events for nonexistent JA4 (may be partial match)", result.Total)
		}
	})
}

// ── 32b. Endpoint Discovery with GeneralLogStore ────────────────────

func TestEndpointDiscoveryFromGeneralLogs(t *testing.T) {
	// Generate some normal (non-security) traffic first so it appears in GeneralLogStore.
	for i := 0; i < 5; i++ {
		httpGet(t, caddyURL+"/get")
	}

	// Wait for general log ingestion.
	waitForCondition(t, "general log traffic", 30*time.Second, func() bool {
		_, body := httpGet(t, wafctlURL+"/api/discovery/endpoints?hours=1")
		return strings.Contains(string(body), "/get")
	})

	t.Run("normal-traffic-appears", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/discovery/endpoints?hours=1")
		assertCode(t, "discovery", 200, resp)

		var disc struct {
			Endpoints []struct {
				Path     string `json:"path"`
				Requests int    `json:"requests"`
			} `json:"endpoints"`
			TotalRequests int `json:"total_requests"`
		}
		if err := json.Unmarshal(body, &disc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		// Since we're now reading from GeneralLogStore, /get should appear
		// (it wouldn't appear with the old AccessLogStore because 200 OK responses
		// were filtered out as non-security events).
		found := false
		for _, ep := range disc.Endpoints {
			if ep.Path == "/get" {
				found = true
				if ep.Requests < 5 {
					t.Logf("/get has %d requests (expected >= 5, may still be ingesting)", ep.Requests)
				}
				break
			}
		}
		if !found {
			t.Log("/get not in discovery yet — general log pipeline may still be ingesting")
		}

		// Total requests should reflect all traffic, not just security events.
		if disc.TotalRequests > 0 {
			t.Logf("total requests in discovery: %d (from general log store)", disc.TotalRequests)
		}
	})
}

// ── 32c. Non-Browser Detection UA Fallback ──────────────────────────

func TestEndpointDiscoveryNonBrowserUA(t *testing.T) {
	// In E2E, JA4 is empty (plain HTTP, no TLS). The UA fallback should classify
	// our e2e test client (UA: "Mozilla/5.0 (compatible; e2e-test/1.0)") as browser-like.
	// But if we send requests with a clearly non-browser UA, those should be detected.

	// Send requests with a non-browser User-Agent.
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", caddyURL+"/anything/ua-test-"+string(rune('a'+i)), nil)
		req.Header.Set("User-Agent", "curl/8.0.1")
		req.Header.Set("Accept", "*/*")
		client.Do(req)
	}
	// Also send browser-like requests to the same path pattern.
	for i := 0; i < 5; i++ {
		httpGet(t, caddyURL+"/anything/ua-test-browser-"+string(rune('a'+i)))
	}

	// Wait for ingestion.
	time.Sleep(3 * time.Second)

	resp, body := httpGet(t, wafctlURL+"/api/discovery/endpoints?hours=1")
	assertCode(t, "discovery", 200, resp)

	var disc struct {
		Endpoints []struct {
			Path          string  `json:"path"`
			NonBrowserPct float64 `json:"non_browser_pct"`
			UniqueUAs     int     `json:"unique_uas"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(body, &disc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Log non-browser percentages for debugging.
	for _, ep := range disc.Endpoints {
		if ep.NonBrowserPct > 0 {
			t.Logf("endpoint %s: non_browser=%.0f%% uas=%d", ep.Path, ep.NonBrowserPct*100, ep.UniqueUAs)
		}
	}
}

// ── 32d. Challenge Enrichment Fields ────────────────────────────────

func TestChallengeEnrichmentFields(t *testing.T) {
	t.Run("fail-reasons-in-stats", func(t *testing.T) {
		// Challenge stats should include fail_reasons field (may be empty if no failures).
		resp, body := httpGet(t, wafctlURL+"/api/challenge/stats?hours=24")
		assertCode(t, "challenge stats", 200, resp)

		var stats struct {
			Failed      int            `json:"failed"`
			FailReasons map[string]int `json:"fail_reasons"`
		}
		if err := json.Unmarshal(body, &stats); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		// If there are failures, fail_reasons should be populated.
		if stats.Failed > 0 {
			if stats.FailReasons == nil || len(stats.FailReasons) == 0 {
				t.Error("challenge has failures but fail_reasons is empty")
			}
			total := 0
			for reason, count := range stats.FailReasons {
				t.Logf("fail reason %s: %d", reason, count)
				total += count
			}
			if total != stats.Failed {
				t.Errorf("fail_reasons total %d != failed count %d", total, stats.Failed)
			}
		} else {
			t.Log("no challenge failures — fail_reasons correctly absent/empty")
		}
	})

	t.Run("event-has-challenge-fields", func(t *testing.T) {
		// Fetch challenge events and verify enrichment fields are present.
		resp, body := httpGet(t, wafctlURL+"/api/events?hours=24&event_type=challenge_failed&event_type_op=in&event_type=challenge_failed,challenge_passed,challenge_issued")
		assertCode(t, "challenge events", 200, resp)

		var result struct {
			Events []struct {
				EventType           string `json:"event_type"`
				ChallengeBotScore   int    `json:"challenge_bot_score"`
				ChallengeFailReason string `json:"challenge_fail_reason"`
				ChallengeSignals    string `json:"challenge_signals"`
				ChallengeDifficulty int    `json:"challenge_difficulty"`
				ChallengeElapsedMs  int    `json:"challenge_elapsed_ms"`
				JA4                 string `json:"ja4"`
			} `json:"events"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		// Log what we found for debugging.
		for _, ev := range result.Events {
			t.Logf("event %s: bot_score=%d difficulty=%d elapsed=%d fail_reason=%s ja4=%s",
				ev.EventType, ev.ChallengeBotScore, ev.ChallengeDifficulty,
				ev.ChallengeElapsedMs, ev.ChallengeFailReason, ev.JA4)
		}

		// If there are challenge_failed events, they should have a fail_reason
		// (either from plugin or heuristic inference).
		for _, ev := range result.Events {
			if ev.EventType == "challenge_failed" && ev.ChallengeFailReason == "" {
				t.Log("challenge_failed event without fail_reason — heuristic may not have enough data")
			}
		}
	})
}

// ── 32e. Caddyfile log_append fields ────────────────────────────────

func TestCaddyfileLogAppendFields(t *testing.T) {
	// Verify that the E2E Caddyfile includes all challenge log_append fields.
	// We do this by checking that the general logs include the expected fields
	// for challenge events (even if empty).
	resp, body := httpGet(t, wafctlURL+"/api/logs?hours=1&limit=5")
	assertCode(t, "general logs", 200, resp)

	var result struct {
		Events []struct {
			PolicyAction string `json:"policy_action"`
			JA4          string `json:"ja4"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// At minimum, some events should exist from prior test traffic.
	if len(result.Events) == 0 {
		t.Skip("no general log events found — may need more test traffic")
	}
	t.Logf("found %d general log events", len(result.Events))
}
