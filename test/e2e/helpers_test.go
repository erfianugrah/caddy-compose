package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// ── Environment ────────────────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	caddyURL    = envOr("CADDY_URL", "http://localhost:18080")
	wafctlURL   = envOr("WAFCTL_URL", "http://localhost:18082")
	dashURL     = envOr("DASH_URL", "http://localhost:18081")
	caddyAdmin  = envOr("CADDY_ADMIN", "http://localhost:12019")
	httpTimeout = 10 * time.Second
)

// ── HTTP helpers ───────────────────────────────────────────────────

// browserTransport wraps the default transport to inject browser-like headers
// on every request. Without these, the policy engine's default detect rules
// (9100030 Missing Accept, 9100033 Missing User-Agent, 9100034 Missing
// Referer, 920280 Missing Host) accumulate anomaly scores that exceed the
// default threshold of 5, blocking bare Go http.Client requests.
type browserTransport struct {
	base http.RoundTripper
}

func (bt *browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only inject defaults when the header is completely absent.
	// Tests that explicitly set headers (even to "") are left alone.
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; e2e-test/1.0)")
	}
	if _, ok := req.Header["Accept"]; !ok {
		req.Header.Set("Accept", "*/*")
	}
	return bt.base.RoundTrip(req)
}

var client = &http.Client{
	Timeout:   httpTimeout,
	Transport: &browserTransport{base: http.DefaultTransport},
}

// deployClient has a longer timeout for deploy operations (Caddy reload).
var deployClient = &http.Client{
	Timeout:   120 * time.Second,
	Transport: &browserTransport{base: http.DefaultTransport},
}

func httpGet(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("reading body from %s: %v", url, err)
	}
	return resp, body
}

func httpPost(t *testing.T, url string, payload any) (*http.Response, []byte) {
	t.Helper()
	return httpDo(t, client, "POST", url, payload)
}

func httpPostDeploy(t *testing.T, url string, payload any) (*http.Response, []byte) {
	t.Helper()
	return httpDo(t, deployClient, "POST", url, payload)
}

func httpPut(t *testing.T, url string, payload any) (*http.Response, []byte) {
	t.Helper()
	return httpDo(t, client, "PUT", url, payload)
}

func httpDelete(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	return httpDo(t, client, "DELETE", url, nil)
}

func httpDo(t *testing.T, c *http.Client, method, url string, payload any) (*http.Response, []byte) {
	t.Helper()
	var bodyReader io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshalling payload: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("reading body from %s: %v", url, err)
	}
	return resp, body
}

func httpGetCode(url string) (int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func httpPostRaw(url string, body []byte) (int, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Add browser-like headers to avoid CRS protocol enforcement false positives
	// (920310 missing Accept, 9100035 missing UA on POST, etc.).
	req.Header.Set("User-Agent", "E2E-Browser/1.0")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// ── JSON helpers ───────────────────────────────────────────────────

func jsonField(body []byte, field string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	// Support dotted paths like "defaults.mode"
	parts := strings.SplitN(field, ".", 2)
	raw, ok := m[parts[0]]
	if !ok {
		return ""
	}
	if len(parts) == 2 {
		return jsonField(raw, parts[1])
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Try as number or bool
	return strings.Trim(string(raw), `"`)
}

func jsonInt(body []byte, field string) int {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return -1
	}
	parts := strings.SplitN(field, ".", 2)
	raw, ok := m[parts[0]]
	if !ok {
		return -1
	}
	if len(parts) == 2 {
		return jsonInt(raw, parts[1])
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return -1
	}
	return n
}

func jsonArrayLen(body []byte) int {
	var arr []json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		return -1
	}
	return len(arr)
}

// jsonFieldBool returns a bool field from a JSON object.
func jsonFieldBool(body []byte, field string) (bool, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return false, false
	}
	parts := strings.SplitN(field, ".", 2)
	raw, ok := m[parts[0]]
	if !ok {
		return false, false
	}
	if len(parts) == 2 {
		return jsonFieldBool(raw, parts[1])
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, false
	}
	return b, true
}

// jsonFieldArray returns a raw JSON array field.
func jsonFieldArray(body []byte, field string) []json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	parts := strings.SplitN(field, ".", 2)
	raw, ok := m[parts[0]]
	if !ok {
		return nil
	}
	if len(parts) == 2 {
		return jsonFieldArray(raw, parts[1])
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil
	}
	return arr
}

// ── Assertions ─────────────────────────────────────────────────────

func assertCode(t *testing.T, name string, expected int, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != expected {
		t.Errorf("%s: expected HTTP %d, got %d", name, expected, resp.StatusCode)
	}
}

func assertField(t *testing.T, name string, body []byte, field, expected string) {
	t.Helper()
	got := jsonField(body, field)
	if got != expected {
		t.Errorf("%s: expected %s=%q, got %q", name, field, expected, got)
	}
}

// httpGetRetry is like httpGet but retries on transient errors (EOF, connection
// reset) up to maxRetries times with a brief pause between attempts. Use this
// for endpoints hit immediately after a deploy/reload that may briefly drop
// connections. On each retry, idle connections are closed to avoid reusing a
// stale connection from the pool.
func httpGetRetry(t *testing.T, url string, maxRetries int) (*http.Response, []byte) {
	t.Helper()
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			// Purge stale connections — earlier Caddy reloads may have closed
			// the server side of a keep-alive connection, leaving the pool with
			// a dead socket that surfaces as EOF on the next request.
			client.CloseIdleConnections()
			time.Sleep(500 * time.Millisecond)
		}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			t.Logf("GET %s attempt %d/%d: %v", url, i+1, maxRetries+1, err)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			t.Logf("GET %s attempt %d/%d read body: %v", url, i+1, maxRetries+1, err)
			continue
		}
		return resp, body
	}
	t.Fatalf("GET %s: failed after %d attempts, last error: %v", url, maxRetries+1, lastErr)
	return nil, nil // unreachable
}

// ── Wait helpers ───────────────────────────────────────────────────

func waitForService(t *testing.T, name, url string, maxWait time.Duration) {
	t.Helper()
	deadline := time.Now().Add(maxWait)
	c := &http.Client{Timeout: 3 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := c.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s not ready after %v at %s", name, maxWait, url)
}

func mustGetID(t *testing.T, body []byte) string {
	t.Helper()
	id := jsonField(body, "id")
	if id == "" || id == "null" {
		t.Fatalf("expected id in response, got: %s", string(body))
	}
	return id
}

func headerContains(resp *http.Response, key, substr string) bool {
	return strings.Contains(resp.Header.Get(key), substr)
}

func cleanup(t *testing.T, url string) {
	t.Helper()
	req, _ := http.NewRequest("DELETE", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("cleanup DELETE %s: %v", url, err)
		return
	}
	resp.Body.Close()
}

func generateLargeBody(size int) []byte {
	return append(
		[]byte(`{"name":"`),
		append(bytes.Repeat([]byte("x"), size), []byte(`"}`)...)...,
	)
}

// generateIPs produces n unique IP addresses in the 10.x.x.x range.
func generateIPs(n int) []string {
	ips := make([]string, n)
	for i := 0; i < n; i++ {
		// 10.a.b.c covering 10.0.0.1 through 10.255.255.254
		a := (i / 65536) % 256
		b := (i / 256) % 256
		c := (i % 256) + 1
		if c > 254 {
			c = 254
		}
		ips[i] = fmt.Sprintf("10.%d.%d.%d", a, b, c)
	}
	return ips
}

// httpGetCustom sends a GET request with full control over headers. If headers
// is nil, Go's default headers (User-Agent, etc.) are sent. Use this to test
// detect rules that match on missing headers.
func httpGetCustom(t *testing.T, url string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("reading body from %s: %v", url, err)
	}
	return resp, body
}

// httpGetNoUA sends a GET request with an explicitly empty User-Agent header.
// Go's net/http sends "Go-http-client/1.1" by default; this overrides it.
func httpGetNoUA(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("User-Agent", "")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("reading body from %s: %v", url, err)
	}
	return resp, body
}

func logBody(t *testing.T, label string, body []byte) {
	t.Helper()
	if len(body) > 500 {
		t.Logf("%s: %s...", label, body[:500])
	} else {
		t.Logf("%s: %s", label, body)
	}
}

// deploys WAF config and returns status field
func deployWAF(t *testing.T) string {
	t.Helper()
	resp, body := httpPostDeploy(t, fmt.Sprintf("%s/api/config/deploy", wafctlURL), struct{}{})
	if resp.StatusCode != 200 {
		t.Logf("deploy response: %s", body)
	}
	return jsonField(body, "status")
}

// ── Poll-based wait helpers ───────────────────────────────────────

// waitForCondition polls fn every interval until it returns true or timeout
// expires. Much faster than fixed time.Sleep for hot-reload waits.
func waitForCondition(t *testing.T, desc string, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s after %v", desc, timeout)
}

// waitForStatus polls url until the response status matches expected or timeout.
func waitForStatus(t *testing.T, url string, expected int, timeout time.Duration) {
	t.Helper()
	waitForCondition(t, fmt.Sprintf("status %d from %s", expected, url), timeout, func() bool {
		resp, err := client.Do(mustNewRequest(t, "GET", url))
		if err != nil {
			return false
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode == expected
	})
}

// waitForHeader polls url until the response contains the expected header value.
func waitForHeader(t *testing.T, url, header, substr string, timeout time.Duration) {
	t.Helper()
	waitForCondition(t, fmt.Sprintf("header %s containing %q from %s", header, substr, url), timeout, func() bool {
		resp, err := client.Do(mustNewRequest(t, "GET", url))
		if err != nil {
			return false
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return strings.Contains(resp.Header.Get(header), substr)
	})
}

// waitForNoHeader polls url until the named header is absent.
func waitForNoHeader(t *testing.T, url, header string, timeout time.Duration) {
	t.Helper()
	waitForCondition(t, fmt.Sprintf("header %s absent from %s", header, url), timeout, func() bool {
		resp, err := client.Do(mustNewRequest(t, "GET", url))
		if err != nil {
			return false
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.Header.Get(header) == ""
	})
}

// waitForEvent polls the events API until an event matching the sentinel UA appears.
func waitForEvent(t *testing.T, sentinel string, timeout time.Duration) map[string]any {
	t.Helper()
	var found map[string]any
	waitForCondition(t, fmt.Sprintf("event with UA %q", sentinel), timeout, func() bool {
		found = findEventBySentinel(t, sentinel)
		return found != nil
	})
	return found
}

func mustNewRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	return req
}

// deployAndWaitForStatus deploys WAF config, then polls until url returns
// the expected status. Replaces the pattern: deploy + time.Sleep(8s).
func deployAndWaitForStatus(t *testing.T, url string, expected int) {
	t.Helper()
	time.Sleep(1 * time.Second) // mtime boundary
	deployWAF(t)
	waitForStatus(t, url, expected, 10*time.Second)
}

// ── Event helpers ─────────────────────────────────────────────────

// findEventBySentinel queries the events API and returns the first event
// matching the given User-Agent sentinel value.
func findEventBySentinel(t *testing.T, sentinel string) map[string]any {
	t.Helper()
	_, eventsBody := httpGet(t, wafctlURL+"/api/events?hours=1&limit=100")
	events := jsonFieldArray(eventsBody, "events")

	for _, e := range events {
		var evtMap map[string]any
		if err := json.Unmarshal(e, &evtMap); err != nil {
			continue
		}
		if ua, _ := evtMap["user_agent"].(string); ua == sentinel {
			return evtMap
		}
	}
	return nil
}

// verifyDetectBlockEvent asserts that a detect_block event exists for the
// sentinel UA, was triggered by the policy engine (not Coraza), and contains
// the expected rule ID in matched_rules.
func verifyDetectBlockEvent(t *testing.T, sentinel string, expectedRuleID string, expectedMsgSubstr string) {
	t.Helper()

	evt := findEventBySentinel(t, sentinel)
	if evt == nil {
		t.Fatalf("no event found with sentinel UA %q", sentinel)
	}

	// Must be detect_block — not "blocked" (Coraza) or "policy_block" (custom rule).
	eventType, _ := evt["event_type"].(string)
	if eventType != "detect_block" {
		t.Errorf("event_type: want detect_block, got %q (Coraza=%q means isolation failed)", eventType, eventType)
	}

	// Verify blocked_by indicates anomaly scoring.
	blockedBy, _ := evt["blocked_by"].(string)
	t.Logf("event_type=%s blocked_by=%s anomaly_score=%v", eventType, blockedBy, evt["anomaly_score"])

	// Verify matched_rules contains the expected rule with proper detail.
	matchedRulesRaw, _ := json.Marshal(evt["matched_rules"])
	var matchedRules []map[string]any
	json.Unmarshal(matchedRulesRaw, &matchedRules)

	if len(matchedRules) == 0 {
		t.Fatal("expected matched_rules non-empty")
	}

	foundRule := false
	for _, rule := range matchedRules {
		// Rule IDs come as float64 from JSON unmarshalling.
		var ruleIDStr string
		switch v := rule["id"].(type) {
		case float64:
			ruleIDStr = fmt.Sprintf("%d", int(v))
		case string:
			ruleIDStr = v
		}
		if ruleIDStr == expectedRuleID {
			foundRule = true
			// Verify msg is present and contains expected substring.
			msg, _ := rule["msg"].(string)
			if msg == "" {
				t.Errorf("rule %s: msg should not be empty", expectedRuleID)
			}
			if expectedMsgSubstr != "" && !strings.Contains(strings.ToLower(msg), strings.ToLower(expectedMsgSubstr)) {
				t.Errorf("rule %s msg: want substring %q, got %q", expectedRuleID, expectedMsgSubstr, msg)
			}
			// Verify matched_data is present (the operator's match output).
			matches, _ := rule["matches"].([]any)
			if len(matches) > 0 {
				firstMatch, _ := matches[0].(map[string]any)
				matchedData, _ := firstMatch["matched_data"].(string)
				t.Logf("rule %s: msg=%q matched_data=%q", expectedRuleID, msg, matchedData)
			} else {
				// Fall back to top-level matched_data for Coraza-format events.
				md, _ := rule["matched_data"].(string)
				t.Logf("rule %s: msg=%q matched_data=%q", expectedRuleID, msg, md)
			}
			break
		}
	}
	if !foundRule {
		for _, rule := range matchedRules {
			t.Logf("  matched rule: id=%v msg=%v", rule["id"], rule["msg"])
		}
		t.Errorf("expected rule %s in matched_rules", expectedRuleID)
	}
}

// verifyDetectBlockEventFromMap is like verifyDetectBlockEvent but takes a
// pre-fetched event map (from waitForEvent) instead of looking up by sentinel.
func verifyDetectBlockEventFromMap(t *testing.T, evt map[string]any, expectedRuleID string, expectedMsgSubstr string) {
	t.Helper()

	if evt == nil {
		t.Fatal("event map is nil")
	}

	// Must be detect_block — not "blocked" (Coraza) or "policy_block" (custom rule).
	eventType, _ := evt["event_type"].(string)
	if eventType != "detect_block" {
		t.Errorf("event_type: want detect_block, got %q", eventType)
	}

	// Verify blocked_by indicates anomaly scoring.
	blockedBy, _ := evt["blocked_by"].(string)
	t.Logf("event_type=%s blocked_by=%s anomaly_score=%v", eventType, blockedBy, evt["anomaly_score"])

	// Verify matched_rules contains the expected rule with proper detail.
	matchedRulesRaw, _ := json.Marshal(evt["matched_rules"])
	var matchedRules []map[string]any
	json.Unmarshal(matchedRulesRaw, &matchedRules)

	if len(matchedRules) == 0 {
		t.Fatal("expected matched_rules non-empty")
	}

	foundRule := false
	for _, rule := range matchedRules {
		var ruleIDStr string
		switch v := rule["id"].(type) {
		case float64:
			ruleIDStr = fmt.Sprintf("%d", int(v))
		case string:
			ruleIDStr = v
		}
		if ruleIDStr == expectedRuleID {
			foundRule = true
			msg, _ := rule["msg"].(string)
			if msg == "" {
				t.Errorf("rule %s: msg should not be empty", expectedRuleID)
			}
			if expectedMsgSubstr != "" && !strings.Contains(strings.ToLower(msg), strings.ToLower(expectedMsgSubstr)) {
				t.Errorf("rule %s msg: want substring %q, got %q", expectedRuleID, expectedMsgSubstr, msg)
			}
			matches, _ := rule["matches"].([]any)
			if len(matches) > 0 {
				firstMatch, _ := matches[0].(map[string]any)
				matchedData, _ := firstMatch["matched_data"].(string)
				t.Logf("rule %s: msg=%q matched_data=%q", expectedRuleID, msg, matchedData)
			} else {
				md, _ := rule["matched_data"].(string)
				t.Logf("rule %s: msg=%q matched_data=%q", expectedRuleID, msg, md)
			}
			break
		}
	}
	if !foundRule {
		for _, rule := range matchedRules {
			t.Logf("  matched rule: id=%v msg=%v", rule["id"], rule["msg"])
		}
		t.Errorf("expected rule %s in matched_rules", expectedRuleID)
	}
}

// setBrowserHeaders adds standard browser-like headers to a request to avoid
// false positives from CRS protocol enforcement rules (920310 empty Accept,
// 920470 no Content-Type, 9100034 missing browser headers, etc.).
func setBrowserHeaders(req *http.Request) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "E2E-Browser/1.0")
	}
	req.Header.Set("Accept", "text/html,*/*")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Accept-Encoding", "gzip")
}

// cleanupByName finds a resource by name in a list endpoint, then DELETEs it.
// This handles stores that assign fresh UUIDs on import (backup/restore).
func cleanupByName(t *testing.T, listURL, name string) {
	t.Helper()
	resp, err := client.Do(mustNewRequest(t, "GET", listURL))
	if err != nil {
		t.Logf("cleanupByName GET %s: %v", listURL, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Parse as array of objects, find any with matching "name" field.
	var items []map[string]interface{}
	if err := json.Unmarshal(body, &items); err != nil {
		t.Logf("cleanupByName unmarshal %s: %v", listURL, err)
		return
	}
	for _, item := range items {
		if n, ok := item["name"].(string); ok && n == name {
			if id, ok := item["id"].(string); ok {
				cleanup(t, listURL+"/"+id)
			}
		}
	}
}
