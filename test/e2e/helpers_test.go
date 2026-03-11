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
// (PE-9100030 Missing Accept, PE-9100033 Missing User-Agent, PE-9100034
// Missing Referer, PE-920280 Missing Host) accumulate anomaly scores that
// exceed the default threshold of 5, blocking bare Go http.Client requests.
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
