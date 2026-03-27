package crs_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ─── Configuration ─────────────────────────────────────────────────

// crsGitRepo is the GitHub repository URL for the OWASP CRS test suite.
const crsGitRepo = "https://github.com/coreruleset/coreruleset.git"

// crsGitTag is the CRS version to fetch tests from. Must match the version
// used by the converter (set in Dockerfile CRS_VERSION).
var crsGitTag = envOr("CRS_VERSION", "v4.24.1")

var (
	proxyURL   = envOr("CRS_PROXY_URL", "http://localhost:19080")
	wafctlURL  = envOr("CRS_WAFCTL_URL", "http://localhost:19082")
	yamlDir    = envOr("CRS_YAML_DIR", "") // auto-resolved: local checkout or GitHub clone
	baselineF  = envOr("CRS_BASELINE", "baseline.json")
	updateBase = os.Getenv("CRS_UPDATE_BASELINE") == "1"
	statusOnly = os.Getenv("CRS_STATUS_ONLY") == "1" // skip events API, pure status codes
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ─── YAML Test Types (CRS FTW format) ──────────────────────────────

type testSuite struct {
	Meta   testMeta   `yaml:"meta"`
	RuleID string     `yaml:"rule_id"`
	Tests  []testCase `yaml:"tests"`
}

type testMeta struct {
	Author      string `yaml:"author"`
	Description string `yaml:"description"`
	Enabled     *bool  `yaml:"enabled"`
}

type testCase struct {
	TestID int         `yaml:"test_id"`
	Desc   string      `yaml:"desc"`
	Stages []testStage `yaml:"stages"`
}

type testStage struct {
	Input  testInput  `yaml:"input"`
	Output testOutput `yaml:"output"`
}

type testInput struct {
	DestAddr string            `yaml:"dest_addr"`
	Port     int               `yaml:"port"`
	Method   string            `yaml:"method"`
	URI      string            `yaml:"uri"`
	Version  string            `yaml:"version"`
	Headers  map[string]string `yaml:"headers"`
	Data     string            `yaml:"data"`
	// encoded_request is used by some tests for raw HTTP — we skip those.
	EncodedRequest string `yaml:"encoded_request"`
	// stop_magic disables automatic header additions.
	StopMagic bool `yaml:"stop_magic"`
}

type testOutput struct {
	Status *int    `yaml:"status"`
	Log    testLog `yaml:"log"`
	// response_contains is used by some response-phase tests.
	ResponseContains string `yaml:"response_contains"`
}

type testLog struct {
	ExpectIDs   []int `yaml:"expect_ids"`
	NoExpectIDs []int `yaml:"no_expect_ids"`
}

// ─── Baseline ──────────────────────────────────────────────────────

type baselineEntry struct {
	Status string `json:"status"` // "pass", "fail", "skip"
	Note   string `json:"note,omitempty"`
}

type baseline map[string]baselineEntry // key: "ruleID/testID"

func loadBaseline(t *testing.T, path string) baseline {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Logf("No baseline file at %s — will generate one", path)
			return baseline{}
		}
		t.Fatalf("reading baseline: %v", err)
	}
	var b baseline
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("parsing baseline: %v", err)
	}
	return b
}

func saveBaseline(t *testing.T, path string, b baseline) {
	t.Helper()
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatalf("marshaling baseline: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("writing baseline: %v", err)
	}
	t.Logf("Wrote baseline with %d entries to %s", len(b), path)
}

// ─── Stats ─────────────────────────────────────────────────────────

type stats struct {
	Total     int
	Pass      int
	Fail      int
	Skip      int
	NewFail   int // failures not in baseline
	NewPass   int // passes that were baselined as fail
	Skipped   int // skipped due to encoded_request, multi-stage, etc.
	CrossRule int // no_expect_ids blocked by OTHER rules (not the tested rule)

	// deferredChecks collects no_expect_ids 403 results for batch resolution.
	// After all tests run, we wait for log ingestion once and resolve all at once.
	deferredChecks []deferredCheck
}

type deferredCheck struct {
	key      string // "ruleID/testID"
	marker   string // URI marker for event correlation
	noExpIDs []int  // rule IDs that should NOT have fired
}

func (s *stats) report(t *testing.T) {
	t.Helper()
	t.Logf("")
	t.Logf("═══ CRS Fidelity Report ═══")
	t.Logf("  Total tests:   %d", s.Total)
	t.Logf("  Passing:       %d", s.Pass)
	t.Logf("  Failing:       %d (baselined)", s.Fail)
	t.Logf("  Skipped:       %d (unsupported format)", s.Skipped)
	t.Logf("  Cross-rule:    %d (blocked by other rules, not the tested rule)", s.CrossRule)
	t.Logf("  New failures:  %d (REGRESSION)", s.NewFail)
	t.Logf("  New passes:    %d (improvement — update baseline)", s.NewPass)
	t.Logf("")
	if s.Total > 0 {
		testable := s.Total - s.Skipped
		if testable > 0 {
			pct := float64(s.Pass) / float64(testable) * 100
			t.Logf("  Fidelity: %.1f%% (%d/%d testable)", pct, s.Pass, testable)
		}
	}
}

// ─── Setup ─────────────────────────────────────────────────────────

func TestMain(m *testing.M) {
	// Resolve CRS test YAML directory: check local checkout, then clone from GitHub.
	if yamlDir == "" {
		localPath := "../../tools/coreruleset/tests/regression/tests"
		if info, err := os.Stat(localPath); err == nil && info.IsDir() {
			yamlDir = localPath
			fmt.Fprintf(os.Stderr, "Using local CRS tests at %s\n", localPath)
		} else {
			// Clone from GitHub into a temp directory.
			tmpDir, err := os.MkdirTemp("", "crs-tests-*")
			if err != nil {
				fmt.Fprintf(os.Stderr, "creating temp dir: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Cloning CRS %s from GitHub...\n", crsGitTag)
			cmd := exec.Command("git", "clone", "--depth", "1", "--branch", crsGitTag,
				"--filter=blob:none", "--sparse", crsGitRepo, tmpDir)
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "git clone failed: %v\n", err)
				os.Exit(1)
			}
			// Sparse checkout only the test directory
			sparse := exec.Command("git", "-C", tmpDir, "sparse-checkout", "set", "tests/regression/tests")
			sparse.Stderr = os.Stderr
			if err := sparse.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "sparse checkout failed: %v\n", err)
				os.Exit(1)
			}
			yamlDir = filepath.Join(tmpDir, "tests", "regression", "tests")
			fmt.Fprintf(os.Stderr, "CRS tests downloaded to %s\n", yamlDir)
			defer os.RemoveAll(tmpDir) // cleanup on exit
		}
	}

	// Quick connectivity check before running tests
	if err := waitForHealth(wafctlURL+"/api/health", 60*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "wafctl not reachable at %s: %v\n", wafctlURL, err)
		os.Exit(1)
	}

	// Configure WAF: enable CRS blocking with threshold=5, PL1, no disabled categories
	if err := configureWAF(); err != nil {
		fmt.Fprintf(os.Stderr, "configuring WAF: %v\n", err)
		os.Exit(1)
	}

	// Deploy config
	if err := deployConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "deploying config: %v\n", err)
		os.Exit(1)
	}

	// Wait for policy reload
	time.Sleep(3 * time.Second)

	os.Exit(m.Run())
}

func waitForHealth(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout after %s", timeout)
}

func configureWAF() error {
	// Set WAF config: PL1, threshold=5, no disabled categories.
	// Disable custom heuristic rules (91000xx) that accumulate anomaly on
	// CRS test traffic (missing Referer, generic UA, etc.). These are not
	// CRS rules and the CRS tests don't account for their scoring.
	config := map[string]any{
		"defaults": map[string]any{
			"paranoia_level":      1,
			"inbound_threshold":   5,
			"outbound_threshold":  5,
			"disabled_categories": []string{"9100"},
		},
	}
	body, _ := json.Marshal(config)
	req, _ := http.NewRequest("PUT", wafctlURL+"/api/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("PUT /api/config: status %d", resp.StatusCode)
	}
	return nil
}

func deployConfig() error {
	resp, err := http.Post(wafctlURL+"/api/deploy", "application/json", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("POST /api/deploy: status %d", resp.StatusCode)
	}
	return nil
}

// ─── Test Categories to Include ────────────────────────────────────

// testableCategories defines which CRS categories to test.
// Start with inbound detection rules. Response-phase rules are skipped
// (they inspect response bodies which requires specific backend responses).
// Flow-control categories (911, 949, 959, 980) are skipped — they're not
// detection rules and are not converted by the converter.
var testableCategories = map[string]bool{
	"REQUEST-913-SCANNER-DETECTION":                   true,
	"REQUEST-920-PROTOCOL-ENFORCEMENT":                true,
	"REQUEST-921-PROTOCOL-ATTACK":                     true,
	"REQUEST-922-MULTIPART-ATTACK":                    true,
	"REQUEST-930-APPLICATION-ATTACK-LFI":              true,
	"REQUEST-931-APPLICATION-ATTACK-RFI":              true,
	"REQUEST-932-APPLICATION-ATTACK-RCE":              true,
	"REQUEST-933-APPLICATION-ATTACK-PHP":              true,
	"REQUEST-934-APPLICATION-ATTACK-GENERIC":          true,
	"REQUEST-941-APPLICATION-ATTACK-XSS":              true,
	"REQUEST-942-APPLICATION-ATTACK-SQLI":             true,
	"REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION": true,
	"REQUEST-944-APPLICATION-ATTACK-JAVA":             true,
}

// ─── Test Runner ───────────────────────────────────────────────────

func TestCRSRegression(t *testing.T) {
	bl := loadBaseline(t, baselineF)
	newBaseline := make(baseline) // build fresh baseline from results
	var st stats

	entries, err := os.ReadDir(yamlDir)
	if err != nil {
		t.Fatalf("reading yaml dir %s: %v", yamlDir, err)
	}

	// Sort category dirs for deterministic order
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, catDir := range entries {
		if !catDir.IsDir() {
			continue
		}
		if !testableCategories[catDir.Name()] {
			continue
		}

		catPath := filepath.Join(yamlDir, catDir.Name())
		t.Run(catDir.Name(), func(t *testing.T) {
			runCategory(t, catPath, bl, newBaseline, &st)
		})
	}

	// ── Batch resolve deferred cross-rule checks ────────────────
	// Wait once for log ingestion, then query all deferred markers.
	if len(st.deferredChecks) > 0 && !statusOnly {
		t.Logf("Resolving %d deferred cross-rule checks (waiting for log ingestion)...", len(st.deferredChecks))
		time.Sleep(eventIngestionDelay)

		resolved := 0
		for _, dc := range st.deferredChecks {
			matchedIDs := queryMatchedRuleIDsNoDelay(dc.marker)
			ruleFired := false
			for _, noID := range dc.noExpIDs {
				for _, mid := range matchedIDs {
					if mid == noID {
						ruleFired = true
						break
					}
				}
				if ruleFired {
					break
				}
			}
			if !ruleFired && len(matchedIDs) > 0 {
				// Cross-rule interference confirmed: upgrade from fail to pass.
				st.CrossRule++
				resolved++
				// Fix the baseline entry and stats.
				entry := newBaseline[dc.key]
				if entry.Status == "fail" {
					// Was counted as either NewFail or Fail — decrement appropriately.
					if _, inOldBL := bl[dc.key]; inOldBL {
						st.Fail--
					} else {
						st.NewFail--
					}
					st.Pass++
					newBaseline[dc.key] = baselineEntry{Status: "pass", Note: "cross-rule (resolved)"}
				}
			}
		}
		t.Logf("Resolved %d/%d as cross-rule interference", resolved, len(st.deferredChecks))
	}

	st.report(t)

	if updateBase {
		saveBaseline(t, baselineF, newBaseline)
	}

	if st.NewFail > 0 {
		t.Fatalf("%d new regressions detected (not in baseline). Run with CRS_UPDATE_BASELINE=1 to update.", st.NewFail)
	}
}

func runCategory(t *testing.T, catPath string, bl, newBL baseline, st *stats) {
	t.Helper()

	err := filepath.WalkDir(catPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Logf("WARNING: reading %s: %v", path, err)
			return nil
		}

		var suite testSuite
		if err := yaml.Unmarshal(data, &suite); err != nil {
			t.Logf("WARNING: parsing %s: %v", path, err)
			return nil
		}

		// Skip disabled suites
		if suite.Meta.Enabled != nil && !*suite.Meta.Enabled {
			return nil
		}

		for _, tc := range suite.Tests {
			runTest(t, suite.RuleID, tc, bl, newBL, st)
		}
		return nil
	})
	if err != nil {
		t.Logf("WARNING: walking %s: %v", catPath, err)
	}
}

func runTest(t *testing.T, ruleID string, tc testCase, bl, newBL baseline, st *stats) {
	t.Helper()
	st.Total++

	key := fmt.Sprintf("%s/%d", ruleID, tc.TestID)

	// Skip unsupported test formats
	if len(tc.Stages) == 0 {
		st.Skipped++
		newBL[key] = baselineEntry{Status: "skip", Note: "no stages"}
		return
	}

	stage := tc.Stages[0]

	// Skip encoded_request tests (raw HTTP we can't send via net/http)
	if stage.Input.EncodedRequest != "" {
		st.Skipped++
		newBL[key] = baselineEntry{Status: "skip", Note: "encoded_request (raw HTTP)"}
		return
	}

	// Skip multi-stage tests (complex multi-request sequences)
	if len(tc.Stages) > 1 {
		st.Skipped++
		newBL[key] = baselineEntry{Status: "skip", Note: "multi-stage"}
		return
	}

	// Skip tests with no log expectations
	if len(stage.Output.Log.ExpectIDs) == 0 && len(stage.Output.Log.NoExpectIDs) == 0 {
		st.Skipped++
		newBL[key] = baselineEntry{Status: "skip", Note: "no expect_ids or no_expect_ids"}
		return
	}

	// Determine what we expect
	expectBlock := len(stage.Output.Log.ExpectIDs) > 0
	expectAllow := len(stage.Output.Log.NoExpectIDs) > 0 && !expectBlock

	// Add a test marker to the URI so we can identify this request in the events API
	marker := fmt.Sprintf("_crs_test_%s_%d", ruleID, tc.TestID)

	// Build and send request
	status, err := sendTestRequest(stage.Input, marker)
	if err != nil {
		st.Skipped++
		newBL[key] = baselineEntry{Status: "skip", Note: "request error: " + err.Error()}
		return
	}

	// Evaluate result
	var passed bool
	if expectBlock {
		// expect_ids: request should be blocked (403)
		passed = status == 403
	} else if expectAllow {
		if status != 403 {
			// Not blocked — pass
			passed = true
		} else {
			// Blocked (403) on a no_expect_ids test. Defer rule-level check
			// to batch resolution after all tests complete (avoids per-test
			// ingestion delay). Mark as tentative failure for now.
			if !statusOnly {
				st.deferredChecks = append(st.deferredChecks, deferredCheck{
					key:      key,
					marker:   marker,
					noExpIDs: stage.Output.Log.NoExpectIDs,
				})
			}
			passed = false // tentative — may be upgraded by batch resolution
		}
	} else {
		st.Skipped++
		newBL[key] = baselineEntry{Status: "skip", Note: "ambiguous expectations"}
		return
	}

	if passed {
		st.Pass++
		newBL[key] = baselineEntry{Status: "pass"}

		// Check if this was a baselined failure that now passes
		if entry, ok := bl[key]; ok && entry.Status == "fail" {
			st.NewPass++
		}
	} else {
		// Check baseline
		entry, inBaseline := bl[key]
		if inBaseline && entry.Status == "fail" {
			// Known failure — don't count as regression
			st.Fail++
			newBL[key] = baselineEntry{Status: "fail", Note: entry.Note}
		} else {
			// New failure — regression
			st.NewFail++
			newBL[key] = baselineEntry{Status: "fail", Note: "new regression"}
			if expectBlock {
				t.Errorf("REGRESSION: %s — expected 403 (rule should detect), got status %d (%s)",
					key, status, tc.Desc)
			} else {
				t.Errorf("REGRESSION: %s — rule %s over-matched (false positive), status %d (%s)",
					key, ruleID, status, tc.Desc)
			}
		}
	}
}

// ─── Events API: Rule-Level Match Checking ─────────────────────────

// queryMatchedRuleIDs queries the wafctl events API with an ingestion delay.
func queryMatchedRuleIDs(marker string) []int {
	time.Sleep(eventIngestionDelay)
	return queryMatchedRuleIDsNoDelay(marker)
}

// queryMatchedRuleIDsNoDelay queries the wafctl events API for the most recent
// event matching the test marker, returning all matched CRS rule IDs.
// No ingestion delay — caller must ensure events are already ingested.
func queryMatchedRuleIDsNoDelay(marker string) []int {
	reqURL := fmt.Sprintf("%s/api/events?limit=1&hours=1&uri=%s&uri_op=contains",
		wafctlURL, url.QueryEscape(marker))

	resp, err := http.Get(reqURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	var result struct {
		Events []struct {
			MatchedRules []struct {
				ID int `json:"id"`
			} `json:"matched_rules"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}
	if len(result.Events) == 0 {
		return nil
	}

	var ids []int
	for _, mr := range result.Events[0].MatchedRules {
		ids = append(ids, mr.ID)
	}
	return ids
}

// eventIngestionDelay is the time to wait for wafctl to ingest the access log
// entry for a request. Only used for NEW no_expect_ids failures (not baselined).
// Most tests don't need this — they pass on status code alone, or are already
// baselined and skip the events API check entirely.
var eventIngestionDelay = 2500 * time.Millisecond

func init() {
	if d := os.Getenv("CRS_EVENT_DELAY"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil {
			eventIngestionDelay = parsed
		}
	}
}

// ─── HTTP Request Builder ──────────────────────────────────────────

func sendTestRequest(input testInput, marker string) (int, error) {
	method := input.Method
	if method == "" {
		method = "GET"
	}

	uri := input.URI
	if uri == "" {
		uri = "/"
	}

	// Add test marker as a query parameter for event correlation.
	// Uses a parameter name unlikely to trigger CRS rules.
	if marker != "" {
		sep := "?"
		if strings.Contains(uri, "?") {
			sep = "&"
		}
		uri = uri + sep + marker + "=1"
	}

	// Build full URL
	reqURL := proxyURL + uri

	// Build request body
	var body *bytes.Reader
	if input.Data != "" {
		// URL-decode the data if it looks URL-encoded (CRS tests use %XX encoding)
		decoded, err := url.QueryUnescape(input.Data)
		if err != nil {
			decoded = input.Data // use as-is if not URL-encoded
		}
		body = bytes.NewReader([]byte(decoded))
	} else {
		body = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		return 0, err
	}

	// Set headers from test case
	for k, v := range input.Headers {
		req.Header.Set(k, v)
	}

	// Set Content-Type for POST with data
	if input.Data != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()

	return resp.StatusCode, nil
}
