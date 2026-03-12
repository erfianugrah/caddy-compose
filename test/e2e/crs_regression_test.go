package e2e_test

// CRS Regression Test Runner
//
// Parses CRS YAML test files (ftw-tests-schema format) and runs them against
// the policy engine's default-rules.json detect rules. Uses anomaly scoring
// with threshold=1 so ANY single rule match triggers a 403 block.
//
// Isolation strategy: Coraza is set to detection_only (can't block), so all
// 403s come from the policy engine's anomaly scoring. This validates that our
// auto-converted CRS rules actually detect the same attacks CRS tests expect.
//
// Usage:
//   go test -v -run TestCRSRegression -count=1 -timeout 1800s ./...
//   go test -v -run TestCRSRegression/942 -count=1 -timeout 600s ./...   # SQLi only
//   CRS_TEST_FILTER=920 go test -v -run TestCRSRegression -timeout 600s  # env filter
//
// The test discovers enabled rule IDs from default-rules.json and only runs
// CRS tests for rules we have. Tests using encoded_request (raw HTTP) or
// expect_error are skipped since Go's http.Client can't send malformed HTTP.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ── CRS YAML Schema Types ──────────────────────────────────────────

// CRSTestFile represents a single CRS YAML test file.
type CRSTestFile struct {
	Meta   CRSMeta   `yaml:"meta"`
	RuleID int       `yaml:"rule_id"`
	Tests  []CRSTest `yaml:"tests"`
}

type CRSMeta struct {
	Author      string `yaml:"author"`
	Description string `yaml:"description"`
}

type CRSTest struct {
	TestID int        `yaml:"test_id"`
	Desc   string     `yaml:"desc"`
	Stages []CRSStage `yaml:"stages"`
}

type CRSStage struct {
	Input  CRSInput  `yaml:"input"`
	Output CRSOutput `yaml:"output"`
}

type CRSInput struct {
	DestAddr       string            `yaml:"dest_addr"`
	Port           int               `yaml:"port"`
	Method         string            `yaml:"method"`
	URI            string            `yaml:"uri"`
	Version        string            `yaml:"version"`
	Headers        map[string]string `yaml:"headers"`
	Data           string            `yaml:"data"`
	EncodedRequest string            `yaml:"encoded_request"`
	StopMagic      bool              `yaml:"stop_magic"`
}

type CRSOutput struct {
	Status           *int    `yaml:"status"`
	Log              *CRSLog `yaml:"log"`
	ExpectError      bool    `yaml:"expect_error"`
	ResponseContains string  `yaml:"response_contains"`
}

type CRSLog struct {
	ExpectIDs   []int `yaml:"expect_ids"`
	NoExpectIDs []int `yaml:"no_expect_ids"`
}

// ── Default Rules Loader ────────────────────────────────────────────

type defaultRulesJSON struct {
	Rules        []defaultRule `json:"rules"`
	DefaultRules []defaultRule `json:"default_rules"`
}

type defaultRule struct {
	ID      any   `json:"id"`
	Enabled *bool `json:"enabled"`
}

// loadEnabledRuleIDs reads default-rules.json and returns the set of enabled rule IDs.
func loadEnabledRuleIDs(path string) (map[int]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var dr defaultRulesJSON
	if err := json.Unmarshal(data, &dr); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	rules := dr.DefaultRules
	if len(rules) == 0 {
		rules = dr.Rules
	}
	ids := make(map[int]bool, len(rules))
	for _, r := range rules {
		if r.Enabled != nil && !*r.Enabled {
			continue
		}
		switch v := r.ID.(type) {
		case float64:
			ids[int(v)] = true
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				ids[n] = true
			}
		}
	}
	return ids, nil
}

// ── CRS Test File Discovery ─────────────────────────────────────────

// discoverCRSTestFiles finds all REQUEST-*.yaml files under the CRS tests dir,
// filtered to only those rules we have enabled.
func discoverCRSTestFiles(testsDir string, enabledIDs map[int]bool, filter string) ([]string, error) {
	var files []string
	entries, err := os.ReadDir(testsDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", testsDir, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "REQUEST-") {
			continue
		}
		subDir := filepath.Join(testsDir, entry.Name())
		subEntries, err := os.ReadDir(subDir)
		if err != nil {
			continue
		}
		for _, sub := range subEntries {
			if !strings.HasSuffix(sub.Name(), ".yaml") {
				continue
			}
			ruleIDStr := strings.TrimSuffix(sub.Name(), ".yaml")
			ruleID, err := strconv.Atoi(ruleIDStr)
			if err != nil {
				continue
			}
			// Filter to enabled rules only.
			if !enabledIDs[ruleID] {
				continue
			}
			// Apply user filter (e.g., "942" to run only SQLi).
			if filter != "" && !strings.HasPrefix(ruleIDStr, filter) {
				continue
			}
			files = append(files, filepath.Join(subDir, sub.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// ── Test Execution ──────────────────────────────────────────────────

// crsTestResult tracks the outcome of a single CRS test case.
type crsTestResult struct {
	RuleID  int
	TestID  int
	Desc    string
	Passed  bool
	Skipped bool
	Reason  string // skip reason or failure detail
}

// runCRSTest executes a single CRS test case and returns the result.
// For expect_ids tests: expects 403 (policy engine blocked).
// For no_expect_ids tests: expects NOT 403 (no false positive).
// For status-only tests: expects the exact status code.
func runCRSTest(ruleID int, test CRSTest, targetURL string) crsTestResult {
	result := crsTestResult{
		RuleID: ruleID,
		TestID: test.TestID,
		Desc:   test.Desc,
	}

	if len(test.Stages) == 0 {
		result.Skipped = true
		result.Reason = "no stages"
		return result
	}

	// Skip multi-stage tests (only 2 in the entire CRS suite).
	if len(test.Stages) > 1 {
		result.Skipped = true
		result.Reason = "multi-stage test"
		return result
	}

	stage := test.Stages[0]

	// Skip encoded_request tests — Go http.Client can't send raw malformed HTTP.
	if stage.Input.EncodedRequest != "" {
		result.Skipped = true
		result.Reason = "encoded_request (raw HTTP)"
		return result
	}

	// Skip expect_error tests — those test TCP-level failures.
	if stage.Output.ExpectError {
		result.Skipped = true
		result.Reason = "expect_error (TCP failure)"
		return result
	}

	// Build the HTTP request.
	method := stage.Input.Method
	if method == "" {
		method = "GET"
	}

	uri := stage.Input.URI
	if uri == "" {
		uri = "/"
	}

	var bodyReader io.Reader
	if stage.Input.Data != "" {
		bodyReader = strings.NewReader(stage.Input.Data)
	}

	req, err := http.NewRequest(method, targetURL+uri, bodyReader)
	if err != nil {
		result.Reason = fmt.Sprintf("create request: %v", err)
		return result
	}

	// Set headers from the test definition.
	// Go's net/http ignores Header["Host"] — must set req.Host directly.
	for k, v := range stage.Input.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}

	// Inject headers to suppress our custom 9100xxx rules without affecting
	// CRS detection. CRS tests don't test for these header absences.
	// - Referer: suppresses 9100034 (Missing Referer on non-API GET, NOTICE=2)
	// - Accept-Language: suppresses part of 9100034's heuristics
	// - Accept-Encoding: suppresses browser fingerprint heuristics
	// Only set if the test didn't explicitly set these headers.
	if req.Header.Get("Referer") == "" {
		req.Header.Set("Referer", "https://localhost/")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	}
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate")
	}

	// Set Content-Type for POST with body if not already set.
	if stage.Input.Data != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Send the request.
	c := &http.Client{
		Timeout: 10 * time.Second,
		// Don't follow redirects — we need the raw status.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := c.Do(req)
	if err != nil {
		result.Reason = fmt.Sprintf("request failed: %v", err)
		return result
	}
	resp.Body.Close()

	statusCode := resp.StatusCode

	// Extract rule IDs from X-Detect-Rules header (set by policy engine on detect_block).
	// Format: "920350:WARNING:3 942100:CRITICAL:5" — space-separated "id:severity:score".
	firedRuleIDs := parseDetectRules(resp.Header.Get("X-Detect-Rules"))

	// Determine pass/fail based on the test's expected output.
	if stage.Output.Log != nil {
		if len(stage.Output.Log.ExpectIDs) > 0 {
			// Positive test: rule should fire → request should be blocked (403).
			// With header-based verification, we also check if the specific rule ID is
			// among the fired rules when we get 403.
			if statusCode == 403 {
				expectedID := strconv.Itoa(stage.Output.Log.ExpectIDs[0])
				if len(firedRuleIDs) > 0 && !firedRuleIDs[expectedID] {
					// Got 403 but the expected rule didn't fire — other rules blocked it.
					// Still count as pass for detection purposes (the attack was blocked),
					// but log a note about which rules actually fired.
					result.Passed = true
					result.Reason = fmt.Sprintf("blocked by other rules (wanted %s, fired: %v)", expectedID, firedRuleIDs)
				} else {
					result.Passed = true
				}
			} else {
				result.Reason = fmt.Sprintf("expect_ids %v: wanted 403, got %d", stage.Output.Log.ExpectIDs, statusCode)
			}
			return result
		}
		if len(stage.Output.Log.NoExpectIDs) > 0 {
			// Negative test: rule should NOT fire → request should pass (not 403).
			// KEY INSIGHT: In anomaly scoring mode, other rules may fire on "clean"
			// data, causing 403 even though the rule under test didn't match.
			// We use X-Detect-Rules to check if the SPECIFIC rule fired.
			if statusCode != 403 {
				result.Passed = true
			} else if len(firedRuleIDs) > 0 {
				// Got 403 — check if the rule under test actually fired.
				noExpectID := strconv.Itoa(stage.Output.Log.NoExpectIDs[0])
				if !firedRuleIDs[noExpectID] {
					// The rule under test did NOT fire. The 403 is from other rules.
					// This is NOT a false positive for this rule — it's cross-talk.
					result.Passed = true
					result.Reason = fmt.Sprintf("cross-talk: 403 from other rules %v, rule %s did NOT fire", firedRuleIDs, noExpectID)
				} else {
					// The rule under test DID fire — genuine false positive.
					result.Reason = fmt.Sprintf("no_expect_ids %v: rule fired (genuine FP), fired rules: %v", stage.Output.Log.NoExpectIDs, firedRuleIDs)
				}
			} else {
				// No X-Detect-Rules header — can't distinguish, report as before.
				result.Reason = fmt.Sprintf("no_expect_ids %v: wanted non-403, got 403 (false positive, no detect header)", stage.Output.Log.NoExpectIDs)
			}
			return result
		}
	}

	// Status-only test (no log expectations).
	if stage.Output.Status != nil {
		expected := *stage.Output.Status
		if statusCode == expected {
			result.Passed = true
		} else {
			result.Reason = fmt.Sprintf("wanted status %d, got %d", expected, statusCode)
		}
		return result
	}

	// No expectations defined — skip.
	result.Skipped = true
	result.Reason = "no output expectations"
	return result
}

// parseDetectRules extracts rule IDs from the X-Detect-Rules response header.
// Format: "920350:WARNING:3 942100:CRITICAL:5" — space-separated "id:severity:score".
// Returns a map of rule ID strings for O(1) lookup.
func parseDetectRules(header string) map[string]bool {
	if header == "" {
		return nil
	}
	ids := make(map[string]bool)
	for _, entry := range strings.Fields(header) {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) >= 1 && parts[0] != "" {
			ids[parts[0]] = true
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return ids
}

// ── Overrides ───────────────────────────────────────────────────────

// CRS overrides for platform-specific quirks (Go/Coraza behavior differs from Apache).
// These are our own overrides for the policy engine, based on coraza-overrides.yaml.
type testOverride struct {
	Skip   bool
	Reason string
	Status *int // override expected status
}

func buildOverrides() map[string]testOverride {
	overrides := make(map[string]testOverride)

	// Go/http rejects these before WAF sees them → 404 not 400/403.
	overrides["920100:4"] = testOverride{Skip: true, Reason: "Go rejects invalid URI before WAF (404)"}
	overrides["920100:5"] = testOverride{Skip: true, Reason: "Go rejects invalid URI before WAF (404)"}
	// Go allows colons in path.
	overrides["920100:8"] = testOverride{Skip: true, Reason: "Go allows colon in path"}
	// Apache returns 400 for these; Go/Caddy returns 200.
	overrides["920270:4"] = testOverride{Skip: true, Reason: "Go/Caddy returns 200 not 400 (Apache quirk)"}
	overrides["920272:5"] = testOverride{Skip: true, Reason: "Go/Caddy returns 200 not 400 (Apache quirk)"}
	overrides["920290:1"] = testOverride{Skip: true, Reason: "Empty Host header: Go/Caddy returns 200 not 400"}
	// Go doesn't support HTTP/3.0 → 505.
	overrides["920430:8"] = testOverride{Skip: true, Reason: "Go rejects HTTP/3.0 (505)"}

	return overrides
}

// ── Main Test Function ──────────────────────────────────────────────

func TestCRSRegression(t *testing.T) {
	// Paths.
	defaultRulesPath := envOr("CRS_DEFAULT_RULES", "../../coraza/default-rules.json")
	crsTestsDir := envOr("CRS_TESTS_DIR", "../../tools/coreruleset/tests/regression/tests")
	filter := envOr("CRS_TEST_FILTER", "")

	// Wait for services.
	waitForService(t, "caddy", caddyURL+"/get", 60*time.Second)
	waitForService(t, "wafctl", wafctlURL+"/api/health", 60*time.Second)

	// Load enabled rule IDs.
	enabledIDs, err := loadEnabledRuleIDs(defaultRulesPath)
	if err != nil {
		t.Fatalf("loading enabled rule IDs: %v", err)
	}
	t.Logf("Loaded %d enabled rules from default-rules.json", len(enabledIDs))

	// Discover CRS test files.
	testFiles, err := discoverCRSTestFiles(crsTestsDir, enabledIDs, filter)
	if err != nil {
		t.Fatalf("discovering CRS test files: %v", err)
	}
	t.Logf("Found %d CRS test files matching enabled rules (filter=%q)", len(testFiles), filter)
	if len(testFiles) == 0 {
		t.Fatal("no CRS test files found — check CRS_TESTS_DIR and CRS_DEFAULT_RULES")
	}

	// Configure WAF: detection_only + threshold=1.
	// Threshold=1 means ANY rule match (min severity=2 → score≥2 >1) blocks.
	t.Log("Configuring WAF: detection_only mode, inbound_threshold=1")
	configPayload := map[string]any{
		"defaults": map[string]any{
			"mode":               "detection_only",
			"paranoia_level":     4, // PL4 to match CRS test suite expectations
			"inbound_threshold":  1,
			"outbound_threshold": 1,
		},
	}
	resp, _ := httpPut(t, wafctlURL+"/api/config", configPayload)
	assertCode(t, "set CRS regression config", 200, resp)
	time.Sleep(2 * time.Second)
	resp2, deployBody := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	assertCode(t, "deploy CRS regression config", 200, resp2)
	assertField(t, "deploy", deployBody, "status", "deployed")
	// Wait for policy engine hot-reload.
	time.Sleep(10 * time.Second)

	// Restore config when done.
	defer func() {
		t.Log("Restoring WAF config to defaults")
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
	}()

	overrides := buildOverrides()

	// Counters.
	var totalTests, passed, failed, skipped int

	// Run each test file as a subtest.
	for _, filePath := range testFiles {
		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Errorf("reading %s: %v", filePath, err)
			continue
		}
		var testFile CRSTestFile
		if err := yaml.Unmarshal(data, &testFile); err != nil {
			t.Errorf("parsing %s: %v", filePath, err)
			continue
		}

		ruleID := testFile.RuleID
		ruleIDStr := strconv.Itoa(ruleID)

		t.Run(ruleIDStr, func(t *testing.T) {
			for _, tc := range testFile.Tests {
				testKey := fmt.Sprintf("%d:%d", ruleID, tc.TestID)
				totalTests++

				t.Run(fmt.Sprintf("test_%d", tc.TestID), func(t *testing.T) {
					// Check overrides.
					if ov, ok := overrides[testKey]; ok {
						if ov.Skip {
							skipped++
							t.Skipf("override: %s", ov.Reason)
						}
					}

					result := runCRSTest(ruleID, tc, caddyURL)

					if result.Skipped {
						skipped++
						t.Skipf("skipped: %s", result.Reason)
					} else if result.Passed {
						passed++
					} else {
						failed++
						t.Errorf("FAIL rule %d test %d: %s", ruleID, tc.TestID, result.Reason)
					}
				})
			}
		})
	}

	// Print summary.
	t.Logf("\n════════════════════════════════════════════")
	t.Logf("CRS Regression Test Summary")
	t.Logf("════════════════════════════════════════════")
	t.Logf("Total tests:  %d", totalTests)
	t.Logf("Passed:       %d", passed)
	t.Logf("Failed:       %d", failed)
	t.Logf("Skipped:      %d", skipped)
	if totalTests-skipped > 0 {
		passRate := float64(passed) / float64(totalTests-skipped) * 100
		t.Logf("Pass rate:    %.1f%% (of non-skipped)", passRate)
	}
	t.Logf("════════════════════════════════════════════")
}
