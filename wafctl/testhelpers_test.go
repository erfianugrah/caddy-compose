package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// sample log lines matching Coraza's JSON audit format.
// Headers are now map[string][]string format.
// sampleLines uses dynamically generated timestamps so eviction tests don't
// break as calendar time progresses past hardcoded dates.
var sampleLines = func() []string {
	// Anchor to the start of the current hour to guarantee exactly 2 hour
	// buckets regardless of when the test runs. ts1/ts2 land in the
	// previous hour, ts3 in the current hour.
	nowHour := time.Now().Truncate(time.Hour)
	ts1 := nowHour.Add(-50 * time.Minute) // previous hour bucket (e.g., 12:10)
	ts2 := nowHour.Add(-40 * time.Minute) // previous hour bucket (e.g., 12:20)
	ts3 := nowHour.Add(1 * time.Second)   // current hour bucket (e.g., 13:00:01)
	fmtTS := func(t time.Time) string { return t.UTC().Format("2006/01/02 15:04:05") }
	fmtUnix := func(t time.Time) int64 { return t.UnixNano() }
	return []string{
		fmt.Sprintf(`{"transaction":{"timestamp":"%s","unix_timestamp":%d,"id":"AAA111","client_ip":"195.240.81.42","client_port":0,"host_ip":"","host_port":0,"server_id":"dockge-sg.erfi.io","request":{"method":"POST","protocol":"HTTP/2.0","uri":"/socket.io/?EIO=4","http_version":"","headers":{"User-Agent":["Mozilla/5.0"]},"body":"40","files":null,"args":{},"length":0},"response":{"protocol":"","status":0,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":true}}`, fmtTS(ts1), fmtUnix(ts1)),
		fmt.Sprintf(`{"transaction":{"timestamp":"%s","unix_timestamp":%d,"id":"BBB222","client_ip":"10.0.0.1","client_port":0,"host_ip":"","host_port":0,"server_id":"radarr.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/.env","http_version":"","headers":{"User-Agent":["curl/7.68"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":403,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":true}}`, fmtTS(ts2), fmtUnix(ts2)),
		fmt.Sprintf(`{"transaction":{"timestamp":"%s","unix_timestamp":%d,"id":"CCC333","client_ip":"10.0.0.1","client_port":0,"host_ip":"","host_port":0,"server_id":"radarr.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/api/v3/queue","http_version":"","headers":{"User-Agent":["Radarr/5.0"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":200,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":false}}`, fmtTS(ts3), fmtUnix(ts3)),
	}
}()

func writeTempLog(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
	f.Close()
	return path
}

// --- HTTP handler tests ---

// testHealthHandler returns a handleHealth closure with minimal test stores.
func testHealthHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	store := NewStore(filepath.Join(t.TempDir(), "audit.log"))
	als := NewAccessLogStore(filepath.Join(t.TempDir(), "access.log"))
	gls := NewGeneralLogStore(filepath.Join(t.TempDir(), "access.log"))
	geoStore := NewGeoIPStore(filepath.Join(t.TempDir(), "nonexistent.mmdb"), nil)
	exclStore := NewExclusionStore(filepath.Join(t.TempDir(), "excl.json"))
	blStore := NewBlocklistStore()
	cfStore := NewCFProxyStore(filepath.Join(t.TempDir(), "cf.caddy"))
	cspStore := NewCSPStore(filepath.Join(t.TempDir(), "csp.json"))
	return handleHealth(store, als, gls, geoStore, exclStore, blStore, cfStore, cspStore)
}

// emptyAccessLogStore returns an AccessLogStore with no events for tests that
// don't care about 429 merging.
func emptyAccessLogStore(t *testing.T) *AccessLogStore {
	t.Helper()
	return NewAccessLogStore(filepath.Join(t.TempDir(), "empty-access.log"))
}

// emptyRLRuleStore returns a RateLimitRuleStore with no rules for tests that
// don't care about RL tag enrichment.
func emptyRLRuleStore(t *testing.T) *RateLimitRuleStore {
	t.Helper()
	return NewRateLimitRuleStore(filepath.Join(t.TempDir(), "rl-rules.json"))
}

// --- Exclusion Store tests ---

func newTestExclusionStore(t *testing.T) *ExclusionStore {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")
	// Write a current-version empty store to skip seed migrations.
	os.WriteFile(path, []byte(fmt.Sprintf(`{"version":%d,"exclusions":[]}`, currentStoreVersion)), 0644)
	return NewExclusionStore(path)
}

// --- Exclusion HTTP endpoint tests ---

func setupExclusionMux(t *testing.T) (*http.ServeMux, *ExclusionStore) {
	t.Helper()
	es := newTestExclusionStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/exclusions", handleListExclusions(es))
	mux.HandleFunc("POST /api/exclusions", handleCreateExclusion(es))
	mux.HandleFunc("GET /api/exclusions/export", handleExportExclusions(es))
	mux.HandleFunc("POST /api/exclusions/import", handleImportExclusions(es))
	mux.HandleFunc("POST /api/exclusions/generate", handleGenerateExclusions(es))
	mux.HandleFunc("PUT /api/exclusions/reorder", handleReorderExclusions(es))
	mux.HandleFunc("GET /api/exclusions/{id}", handleGetExclusion(es))
	mux.HandleFunc("PUT /api/exclusions/{id}", handleUpdateExclusion(es))
	mux.HandleFunc("DELETE /api/exclusions/{id}", handleDeleteExclusion(es))
	return mux, es
}

// --- Config Store tests ---

func newTestConfigStore(t *testing.T) *ConfigStore {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	return NewConfigStore(path)
}

func writeTempAccessLog(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "combined-access.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
	f.Close()
	return path
}

// ─── Blocklist tests ────────────────────────────────────────────────

var sampleAccessLogLines = func() []string {
	// Anchor to the start of the current hour to guarantee exactly 2 hour
	// buckets for 429 events. First batch in previous hour, last in current.
	nowHour := time.Now().Truncate(time.Hour)
	ts := func(t time.Time) string { return t.UTC().Format("2006/01/02 15:04:05") }
	return []string{
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["Sonarr/4.0"]}},"status":200,"size":1234,"duration":0.05}`, ts(nowHour.Add(-50*time.Minute))),
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`, ts(nowHour.Add(-49*time.Minute))),
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"POST","host":"radarr.erfi.io","uri":"/api/v3/command","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`, ts(nowHour.Add(-48*time.Minute))),
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/1.1","method":"GET","host":"radarr.erfi.io","uri":"/.env","headers":{"User-Agent":["BadBot/1.0"]}},"resp_headers":{},"status":403,"size":0,"duration":0.002}`, ts(nowHour.Add(-47*time.Minute))),
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/series","headers":{"User-Agent":["BadBot/1.0"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`, ts(nowHour.Add(1*time.Second))),
	}
}()

// sampleIpsumAccessLogLines contains mixed 429 (rate limited) and 403 policy engine blocks
// (detected via policy_action log_append field and/or X-Blocked-By header).
var sampleIpsumAccessLogLines = func() []string {
	// Same hour-anchoring pattern for consistent bucket boundaries.
	nowHour := time.Now().Truncate(time.Hour)
	ts := func(t time.Time) string { return t.UTC().Format("2006/01/02 15:04:05") }
	return []string{
		// 200 OK — should be ignored
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["Sonarr/4.0"]}},"resp_headers":{},"status":200,"size":1234,"duration":0.05}`, ts(nowHour.Add(-50*time.Minute))),
		// 429 rate limited
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`, ts(nowHour.Add(-49*time.Minute))),
		// 403 policy engine block — detected via policy_action field (primary)
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/2.0","method":"GET","host":"radarr.erfi.io","uri":"/","headers":{"User-Agent":["BadBot/1.0"]}},"resp_headers":{"x-blocked-by":["policy-engine"],"x-blocked-rule":["IPsum Block (Level 3)"]},"policy_action":"block","policy_rule":"IPsum Block (Level 3)","status":403,"size":0,"duration":0.001}`, ts(nowHour.Add(-48*time.Minute))),
		// 403 without policy headers — should be ignored
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.4","client_ip":"10.0.0.4","proto":"HTTP/1.1","method":"GET","host":"radarr.erfi.io","uri":"/.env","headers":{"User-Agent":["Scanner/1.0"]}},"resp_headers":{},"status":403,"size":0,"duration":0.002}`, ts(nowHour.Add(-47*time.Minute))),
		// Another policy engine block — lowercase headers only (HTTP/2), no policy_action field
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.5","client_ip":"10.0.0.5","proto":"HTTP/2.0","method":"POST","host":"sonarr.erfi.io","uri":"/login","headers":{"User-Agent":["MaliciousBot/2.0"]}},"resp_headers":{"x-blocked-by":["policy-engine"],"x-blocked-rule":["IPsum Block (Level 5)"]},"status":403,"size":0,"duration":0.001}`, ts(nowHour.Add(1*time.Second))),
	}
}()
