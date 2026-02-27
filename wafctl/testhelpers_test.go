package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// sample log lines matching Coraza's JSON audit format.
// Headers are now map[string][]string format.
var sampleLines = []string{
	`{"transaction":{"timestamp":"2026/02/22 07:19:01","unix_timestamp":1771744741169677031,"id":"AAA111","client_ip":"195.240.81.42","client_port":0,"host_ip":"","host_port":0,"server_id":"dockge-sg.erfi.io","request":{"method":"POST","protocol":"HTTP/2.0","uri":"/socket.io/?EIO=4","http_version":"","headers":{"User-Agent":["Mozilla/5.0"]},"body":"40","files":null,"args":{},"length":0},"response":{"protocol":"","status":0,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":true}}`,
	`{"transaction":{"timestamp":"2026/02/22 07:20:00","unix_timestamp":1771744800000000000,"id":"BBB222","client_ip":"10.0.0.1","client_port":0,"host_ip":"","host_port":0,"server_id":"radarr.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/.env","http_version":"","headers":{"User-Agent":["curl/7.68"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":403,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":true}}`,
	`{"transaction":{"timestamp":"2026/02/22 08:00:00","unix_timestamp":1771747200000000000,"id":"CCC333","client_ip":"10.0.0.1","client_port":0,"host_ip":"","host_port":0,"server_id":"radarr.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/api/v3/queue","http_version":"","headers":{"User-Agent":["Radarr/5.0"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":200,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":false}}`,
}

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
	return handleHealth(store, als, geoStore, exclStore, blStore)
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

var sampleAccessLogLines = []string{
	`{"level":"info","ts":"2026/02/22 12:00:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["Sonarr/4.0"]}},"status":200,"size":1234,"duration":0.05}`,
	`{"level":"info","ts":"2026/02/22 12:01:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"status":429,"size":0,"duration":0.001}`,
	`{"level":"info","ts":"2026/02/22 12:02:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"POST","host":"radarr.erfi.io","uri":"/api/v3/command","headers":{"User-Agent":["curl/7.68"]}},"status":429,"size":0,"duration":0.001}`,
	`{"level":"info","ts":"2026/02/22 12:03:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/1.1","method":"GET","host":"radarr.erfi.io","uri":"/.env","headers":{"User-Agent":["BadBot/1.0"]}},"status":403,"size":0,"duration":0.002}`,
	`{"level":"info","ts":"2026/02/22 13:00:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/series","headers":{"User-Agent":["BadBot/1.0"]}},"status":429,"size":0,"duration":0.001}`,
}

// sampleIpsumAccessLogLines contains mixed 429 (rate limited) and 403+X-Blocked-By:ipsum lines.
var sampleIpsumAccessLogLines = []string{
	// 200 OK — should be ignored
	`{"level":"info","ts":"2026/02/22 12:00:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.1","client_ip":"10.0.0.1","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["Sonarr/4.0"]}},"resp_headers":{},"status":200,"size":1234,"duration":0.05}`,
	// 429 rate limited
	`{"level":"info","ts":"2026/02/22 12:01:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"10.0.0.2","proto":"HTTP/2.0","method":"GET","host":"sonarr.erfi.io","uri":"/api/v3/queue","headers":{"User-Agent":["curl/7.68"]}},"resp_headers":{},"status":429,"size":0,"duration":0.001}`,
	// 403 ipsum blocked (has X-Blocked-By: ipsum)
	`{"level":"info","ts":"2026/02/22 12:02:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.3","client_ip":"10.0.0.3","proto":"HTTP/2.0","method":"GET","host":"radarr.erfi.io","uri":"/","headers":{"User-Agent":["BadBot/1.0"]}},"resp_headers":{"X-Blocked-By":["ipsum"]},"status":403,"size":0,"duration":0.001}`,
	// 403 without ipsum header — should be ignored
	`{"level":"info","ts":"2026/02/22 12:03:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.4","client_ip":"10.0.0.4","proto":"HTTP/1.1","method":"GET","host":"radarr.erfi.io","uri":"/.env","headers":{"User-Agent":["Scanner/1.0"]}},"resp_headers":{},"status":403,"size":0,"duration":0.002}`,
	// Another ipsum blocked
	`{"level":"info","ts":"2026/02/22 13:00:00","logger":"http.log.access.combined","msg":"handled request","request":{"remote_ip":"10.0.0.5","client_ip":"10.0.0.5","proto":"HTTP/2.0","method":"POST","host":"sonarr.erfi.io","uri":"/login","headers":{"User-Agent":["MaliciousBot/2.0"]}},"resp_headers":{"X-Blocked-By":["ipsum"]},"status":403,"size":0,"duration":0.001}`,
}
