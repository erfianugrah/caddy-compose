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
	now := time.Now()
	ts1 := now.Add(-1 * time.Hour)
	ts2 := now.Add(-50 * time.Minute)
	ts3 := now.Add(-10 * time.Minute)
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
	geoStore := NewGeoIPStore(filepath.Join(t.TempDir(), "nonexistent.mmdb"), nil)
	exclStore := NewExclusionStore(filepath.Join(t.TempDir(), "excl.json"))
	blStore := NewBlocklistStore(filepath.Join(t.TempDir(), "ipsum.caddy"))
	cfStore := NewCFProxyStore(filepath.Join(t.TempDir(), "cf.caddy"))
	cspStore := NewCSPStore(filepath.Join(t.TempDir(), "csp.json"))
	return handleHealth(store, als, geoStore, exclStore, blStore, cfStore, cspStore)
}

// emptyAccessLogStore returns an AccessLogStore with no events for tests that
// don't care about 429 merging.
func emptyAccessLogStore(t *testing.T) *AccessLogStore {
	t.Helper()
	return NewAccessLogStore(filepath.Join(t.TempDir(), "empty-access.log"))
}

// --- Exclusion Store tests ---

func newTestExclusionStore(t *testing.T) *ExclusionStore {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "exclusions.json")
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

func writeTempBlocklist(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ipsum_block.caddy")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

var sampleAccessLogLines = func() []string {
	now := time.Now()
	ts := func(offset time.Duration) string { return now.Add(offset).UTC().Format("2006/01/02 15:04:05") }
	return []string{
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["Sonarr/4.0"]}},"status":200,"size":1234,"duration":0.05}`, ts(-1*time.Hour)),
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"status":429,"size":0,"duration":0.001}`, ts(-59*time.Minute)),
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"POST","host":"radarr.erfi.io","uri":"/api/v3/command","headers":{"User-Agent":["curl/7.68"]}},"status":429,"size":0,"duration":0.001}`, ts(-58*time.Minute)),
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/1.1","method":"GET","host":"radarr.erfi.io","uri":"/.env","headers":{"User-Agent":["BadBot/1.0"]}},"status":403,"size":0,"duration":0.002}`, ts(-57*time.Minute)),
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/series","headers":{"User-Agent":["BadBot/1.0"]}},"status":429,"size":0,"duration":0.001}`, ts(-10*time.Minute)),
	}
}()

// sampleIpsumAccessLogLines contains mixed 429 (rate limited) and 403+X-Blocked-By:ipsum lines.
var sampleIpsumAccessLogLines = func() []string {
	now := time.Now()
	ts := func(offset time.Duration) string { return now.Add(offset).UTC().Format("2006/01/02 15:04:05") }
	return []string{
		// 200 OK — should be ignored
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["Sonarr/4.0"]}},"resp_headers":{},"status":200,"size":1234,"duration":0.05}`, ts(-1*time.Hour)),
		// 429 rate limited
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`, ts(-59*time.Minute)),
		// 403 ipsum blocked (has X-Blocked-By: ipsum)
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/2.0","method":"GET","host":"radarr.erfi.io","uri":"/","headers":{"User-Agent":["BadBot/1.0"]}},"resp_headers":{"X-Blocked-By":["ipsum"]},"status":403,"size":0,"duration":0.001}`, ts(-58*time.Minute)),
		// 403 without ipsum header — should be ignored
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.4","client_ip":"10.0.0.4","proto":"HTTP/1.1","method":"GET","host":"radarr.erfi.io","uri":"/.env","headers":{"User-Agent":["Scanner/1.0"]}},"resp_headers":{},"status":403,"size":0,"duration":0.002}`, ts(-57*time.Minute)),
		// Another ipsum blocked
		fmt.Sprintf(`{"level":"info","ts":"%s","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.5","client_ip":"10.0.0.5","proto":"HTTP/2.0","method":"POST","host":"sonarr.erfi.io","uri":"/login","headers":{"User-Agent":["MaliciousBot/2.0"]}},"resp_headers":{"X-Blocked-By":["ipsum"]},"status":403,"size":0,"duration":0.001}`, ts(-10*time.Minute)),
	}
}()
