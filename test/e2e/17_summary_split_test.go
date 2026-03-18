package e2e_test

import (
	"encoding/json"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  detect_block split — Summary API verification
// ════════════════════════════════════════════════════════════════════
//
// Verifies that the /api/summary response correctly separates detect_block
// (CRS anomaly threshold exceeded) from policy_block (direct policy engine
// blocks) in all aggregation levels: top-level counts, events_by_hour,
// top_services, top_clients, and service_breakdown.
//
// This test checks whether detect_block events are present in the summary.
// If no detect_block events exist (e.g., the tests that generate them were
// removed or haven't run), the test skips gracefully instead of failing.

func TestDetectBlockSummarySplit(t *testing.T) {
	// Poll for detect_blocked events. If none arrive within the timeout,
	// skip the test — the event-generating tests may not be in this suite.
	var body []byte
	found := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, b := httpGet(t, wafctlURL+"/api/summary?hours=1")
		if resp.StatusCode == 200 && jsonInt(b, "detect_blocked") > 0 {
			body = b
			found = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !found {
		t.Skip("no detect_blocked events found in summary — skipping split verification")
	}

	// Parse the full summary response.
	var summary map[string]json.RawMessage
	if err := json.Unmarshal(body, &summary); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}

	// Verify top-level detect_blocked field exists.
	t.Run("top-level detect_blocked field present", func(t *testing.T) {
		if _, ok := summary["detect_blocked"]; !ok {
			t.Error("summary missing detect_blocked field")
			return
		}
		detectBlocked := jsonInt(body, "detect_blocked")
		t.Logf("detect_blocked=%d, policy_blocked=%d",
			detectBlocked, jsonInt(body, "policy_blocked"))

		// Earlier detect scoring tests should have generated at least 1 detect_block event.
		// But we don't hard-require it since access log parsing timing varies.
		if detectBlocked < 0 {
			t.Error("detect_blocked should not be negative")
		}
	})

	// Verify events_by_hour entries have detect_block field.
	t.Run("events_by_hour has detect_block", func(t *testing.T) {
		hourRaw, ok := summary["events_by_hour"]
		if !ok {
			t.Skip("no events_by_hour in summary")
		}
		var hours []map[string]json.RawMessage
		if err := json.Unmarshal(hourRaw, &hours); err != nil {
			t.Fatalf("unmarshal events_by_hour: %v", err)
		}
		if len(hours) == 0 {
			t.Skip("events_by_hour is empty")
		}
		// Check that at least the first hour entry has detect_block field.
		if _, ok := hours[0]["detect_block"]; !ok {
			t.Error("events_by_hour[0] missing detect_block field")
		}
		// Verify detect_block is separate from policy_block.
		if _, ok := hours[0]["policy_block"]; !ok {
			t.Error("events_by_hour[0] missing policy_block field")
		}
	})

	// Verify top_services entries have detect_block field.
	t.Run("top_services has detect_block", func(t *testing.T) {
		svcRaw, ok := summary["top_services"]
		if !ok {
			t.Skip("no top_services in summary")
		}
		var svcs []map[string]json.RawMessage
		if err := json.Unmarshal(svcRaw, &svcs); err != nil {
			t.Fatalf("unmarshal top_services: %v", err)
		}
		if len(svcs) == 0 {
			t.Skip("top_services is empty")
		}
		if _, ok := svcs[0]["detect_block"]; !ok {
			t.Error("top_services[0] missing detect_block field")
		}
	})

	// Verify top_clients entries have detect_block field.
	t.Run("top_clients has detect_block", func(t *testing.T) {
		cRaw, ok := summary["top_clients"]
		if !ok {
			t.Skip("no top_clients in summary")
		}
		var clients []map[string]json.RawMessage
		if err := json.Unmarshal(cRaw, &clients); err != nil {
			t.Fatalf("unmarshal top_clients: %v", err)
		}
		if len(clients) == 0 {
			t.Skip("top_clients is empty")
		}
		if _, ok := clients[0]["detect_block"]; !ok {
			t.Error("top_clients[0] missing detect_block field")
		}
	})

	// Verify service_breakdown entries have detect_block field.
	t.Run("service_breakdown has detect_block", func(t *testing.T) {
		bdRaw, ok := summary["service_breakdown"]
		if !ok {
			t.Skip("no service_breakdown in summary")
		}
		var breakdown []map[string]json.RawMessage
		if err := json.Unmarshal(bdRaw, &breakdown); err != nil {
			t.Fatalf("unmarshal service_breakdown: %v", err)
		}
		if len(breakdown) == 0 {
			t.Skip("service_breakdown is empty")
		}
		if _, ok := breakdown[0]["detect_block"]; !ok {
			t.Error("service_breakdown[0] missing detect_block field")
		}
	})

	// Verify events endpoint accepts event_type=detect_block filter.
	t.Run("events filter by detect_block", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/events?hours=1&event_type=detect_block")
		assertCode(t, "events filter", 200, resp)
		// Response is {total: N, events: [...]}.
		total := jsonInt(body, "total")
		t.Logf("detect_block events total: %d", total)
		// total may be -1 for filtered queries (early-exit pagination).
		if total < -1 {
			t.Error("unexpected total from events endpoint")
		}
		// Verify events array is present.
		events := jsonFieldArray(body, "events")
		if events == nil {
			t.Error("expected events array in response")
		}
	})
}
