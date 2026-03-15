package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// sampleEvents provides 3 events for summary tests:
// 2 detect_block + 1 logged, across 2 hour buckets.
// ts1/ts2 in previous hour, ts3 in current hour.
var sampleEvents = func() []Event {
	nowHour := time.Now().Truncate(time.Hour)
	ts1 := nowHour.Add(-50 * time.Minute)
	ts2 := nowHour.Add(-40 * time.Minute)
	ts3 := nowHour.Add(1 * time.Second)
	return []Event{
		{
			ID: "AAA111", Timestamp: ts1, ClientIP: "195.240.81.42",
			Service: "dockge-sg.erfi.io", Method: "POST", URI: "/socket.io/?EIO=4",
			Protocol: "HTTP/2.0", UserAgent: "Mozilla/5.0",
			ResponseStatus: 0, IsBlocked: true, EventType: "detect_block",
		},
		{
			ID: "BBB222", Timestamp: ts2, ClientIP: "10.0.0.1",
			Service: "radarr.erfi.io", Method: "GET", URI: "/.env",
			Protocol: "HTTP/1.1", UserAgent: "curl/7.68",
			ResponseStatus: 403, IsBlocked: true, EventType: "detect_block",
		},
		{
			ID: "CCC333", Timestamp: ts3, ClientIP: "10.0.0.1",
			Service: "radarr.erfi.io", Method: "GET", URI: "/api/v3/queue",
			Protocol: "HTTP/1.1", UserAgent: "Radarr/5.0",
			ResponseStatus: 200, IsBlocked: false, EventType: "logged",
		},
	}
}()

// storeWithEvents creates a Store pre-populated with the given events.
func storeWithEvents(t *testing.T, events []Event) *Store {
	t.Helper()
	store := NewStore()
	store.mu.Lock()
	store.events = make([]Event, len(events))
	copy(store.events, events)
	store.mu.Unlock()
	return store
}

// --- HTTP handler tests ---

// testHealthHandler returns a handleHealth closure with minimal test stores.
func testHealthHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	store := NewStore()
	als := NewAccessLogStore(filepath.Join(t.TempDir(), "access.log"))
	gls := NewGeneralLogStore(filepath.Join(t.TempDir(), "access.log"))
	geoStore := NewGeoIPStore(filepath.Join(t.TempDir(), "nonexistent.mmdb"), nil)
	exclStore := NewExclusionStore(filepath.Join(t.TempDir(), "excl.json"))
	blStore := NewBlocklistStore()
	cfStore := NewCFProxyStore(filepath.Join(t.TempDir(), "cf.caddy"))
	cspStore := NewCSPStore(filepath.Join(t.TempDir(), "csp.json"))
	secStore := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))
	ds := NewDefaultRuleStore(filepath.Join(t.TempDir(), "defaults.json"), filepath.Join(t.TempDir(), "overrides.json"))
	return handleHealth(store, als, gls, geoStore, exclStore, blStore, cfStore, cspStore, secStore, ds)
}

// emptyWAFStore returns a Store with no events for tests that only need
// an empty WAF store (policy engine handles detection via the access log).
func emptyWAFStore(t *testing.T) *Store {
	t.Helper()
	return NewStore()
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
