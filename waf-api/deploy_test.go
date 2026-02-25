package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)


// --- Deploy tests ---

func TestEnsureCorazaDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "coraza")
	if err := ensureCorazaDir(dir); err != nil {
		t.Fatalf("ensureCorazaDir failed: %v", err)
	}

	// Check placeholder files exist
	for _, name := range []string{"custom-pre-crs.conf", "custom-post-crs.conf"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
		if !strings.Contains(string(data), "Managed by waf-api") {
			t.Errorf("%s missing header comment", name)
		}
	}

	// Calling again should be idempotent (doesn't overwrite)
	if err := ensureCorazaDir(dir); err != nil {
		t.Fatalf("second ensureCorazaDir failed: %v", err)
	}
}



func TestWriteConfFiles(t *testing.T) {
	dir := t.TempDir()
	pre := "# pre-crs content\nSecRuleRemoveById 920420\n"
	post := "# post-crs content\n"
	settings := "# waf settings\nSecAction \"id:9700001,phase:1,pass,t:none,nolog\"\n"

	if err := writeConfFiles(dir, pre, post, settings); err != nil {
		t.Fatalf("writeConfFiles failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "custom-pre-crs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != pre {
		t.Errorf("pre-crs content mismatch: got %q", string(data))
	}

	data, err = os.ReadFile(filepath.Join(dir, "custom-post-crs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != post {
		t.Errorf("post-crs content mismatch: got %q", string(data))
	}

	data, err = os.ReadFile(filepath.Join(dir, "custom-waf-settings.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != settings {
		t.Errorf("waf-settings content mismatch: got %q", string(data))
	}
}



func TestDeployEndpoint(t *testing.T) {
	corazaDir := t.TempDir()
	caddyfileDir := t.TempDir()
	caddyfilePath := filepath.Join(caddyfileDir, "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80 {\n\trespond \"ok\"\n}\n"), 0644)

	// Mock Caddy admin API
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer adminServer.Close()

	deployCfg := DeployConfig{
		CorazaDir:     corazaDir,
		CaddyfilePath: caddyfilePath,
		CaddyAdminURL: adminServer.URL,
	}

	excDir := t.TempDir()
	cfgDir := t.TempDir()
	es := NewExclusionStore(filepath.Join(excDir, "exclusions.json"))
	cs := NewConfigStore(filepath.Join(cfgDir, "config.json"))

	// Create an exclusion so the generated config isn't empty
	es.Create(RuleExclusion{
		Name:    "test-exclusion",
		Type:    "remove_by_id",
		RuleID:  "920420",
		Enabled: true,
	})

	rs := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(cs, es, rs, deployCfg))

	req := httptest.NewRequest("POST", "/api/config/deploy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp DeployResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "deployed" {
		t.Errorf("expected status=deployed, got %q", resp.Status)
	}
	if !resp.Reloaded {
		t.Error("expected reloaded=true")
	}

	// Verify files were written
	preData, err := os.ReadFile(filepath.Join(corazaDir, "custom-pre-crs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(preData) == 0 {
		t.Error("custom-pre-crs.conf is empty")
	}
}



func TestDeployEndpointReloadFail(t *testing.T) {
	corazaDir := t.TempDir()
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80\n"), 0644)

	// Admin server that always fails
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("reload failed"))
	}))
	defer adminServer.Close()

	deployCfg := DeployConfig{
		CorazaDir:     corazaDir,
		CaddyfilePath: caddyfilePath,
		CaddyAdminURL: adminServer.URL,
	}

	es := NewExclusionStore(filepath.Join(t.TempDir(), "exclusions.json"))
	cs := NewConfigStore(filepath.Join(t.TempDir(), "config.json"))
	rs := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(cs, es, rs, deployCfg))

	req := httptest.NewRequest("POST", "/api/config/deploy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200 (partial success), got %d", rec.Code)
	}

	var resp DeployResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Status != "partial" {
		t.Errorf("expected status=partial, got %q", resp.Status)
	}
	if resp.Reloaded {
		t.Error("expected reloaded=false")
	}
}

// --- Analytics endpoint tests ---



// --- Atomic write tests ---

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	data := []byte(`{"key": "value"}`)

	if err := atomicWriteFile(path, data, 0644); err != nil {
		t.Fatalf("atomicWriteFile failed: %v", err)
	}

	// Verify content.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content mismatch: want %q, got %q", string(data), string(got))
	}

	// Verify permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("permissions: want 0644, got %o", info.Mode().Perm())
	}

	// Verify no temp files left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected 1 file in dir, got %d", len(entries))
	}
}



func TestAtomicWriteFileOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	// Write initial content.
	atomicWriteFile(path, []byte("initial"), 0644)

	// Overwrite.
	atomicWriteFile(path, []byte("updated"), 0644)

	got, _ := os.ReadFile(path)
	if string(got) != "updated" {
		t.Errorf("overwrite: want 'updated', got %q", string(got))
	}
}

// --- Deploy fingerprint tests ---



// --- Deploy fingerprint tests ---

func TestDeployFingerprint(t *testing.T) {
	dir := t.TempDir()

	// Create two files with known content.
	f1 := filepath.Join(dir, "a.conf")
	f2 := filepath.Join(dir, "b.conf")
	os.WriteFile(f1, []byte("content-a"), 0644)
	os.WriteFile(f2, []byte("content-b"), 0644)

	fp1 := deployFingerprint([]string{f1, f2})
	if len(fp1) != 16 {
		t.Errorf("fingerprint should be 16 hex chars, got %d: %s", len(fp1), fp1)
	}

	// Same files, same content → same fingerprint.
	fp2 := deployFingerprint([]string{f1, f2})
	if fp1 != fp2 {
		t.Errorf("same content should produce same fingerprint: %s vs %s", fp1, fp2)
	}

	// Change one file → different fingerprint.
	os.WriteFile(f2, []byte("content-b-changed"), 0644)
	fp3 := deployFingerprint([]string{f1, f2})
	if fp1 == fp3 {
		t.Error("different content should produce different fingerprint")
	}

	// Missing file → still produces a fingerprint (hashes path instead).
	fp4 := deployFingerprint([]string{f1, filepath.Join(dir, "nonexistent.conf")})
	if fp4 == fp1 {
		t.Error("missing file should produce different fingerprint than two real files")
	}

	// No files → produces a fingerprint (empty hash).
	fp5 := deployFingerprint(nil)
	if len(fp5) != 16 {
		t.Errorf("empty fingerprint should be 16 hex chars, got %d", len(fp5))
	}
}



func TestReloadCaddyInjectsFingerprint(t *testing.T) {
	caddyfileDir := t.TempDir()
	caddyfilePath := filepath.Join(caddyfileDir, "Caddyfile")
	caddyfileContent := "{\n\tadmin localhost:2019\n}\nlocalhost:80 {\n\trespond \"ok\"\n}\n"
	os.WriteFile(caddyfilePath, []byte(caddyfileContent), 0644)

	// Create config files to fingerprint.
	confDir := t.TempDir()
	confFile := filepath.Join(confDir, "custom-waf-settings.conf")
	os.WriteFile(confFile, []byte("SecAction \"id:9700001\""), 0644)

	// Mock Caddy admin API that captures the POST body.
	var receivedBody []byte
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" && r.Method == "POST" {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer adminServer.Close()

	err := reloadCaddy(caddyfilePath, adminServer.URL, confFile)
	if err != nil {
		t.Fatalf("reloadCaddy failed: %v", err)
	}

	bodyStr := string(receivedBody)

	// Should start with a fingerprint comment.
	if !strings.HasPrefix(bodyStr, "# waf-api deploy ") {
		t.Error("POST body should start with fingerprint comment")
	}
	if !strings.Contains(bodyStr, "fingerprint:") {
		t.Error("POST body should contain 'fingerprint:'")
	}

	// Original Caddyfile content should follow the comment.
	if !strings.Contains(bodyStr, caddyfileContent) {
		t.Error("POST body should contain the original Caddyfile content")
	}

	// Verify the on-disk Caddyfile was NOT modified.
	diskContent, _ := os.ReadFile(caddyfilePath)
	if string(diskContent) != caddyfileContent {
		t.Error("Caddyfile on disk should not be modified")
	}
}



func TestReloadCaddyFingerprintChangesWithContent(t *testing.T) {
	caddyfileDir := t.TempDir()
	caddyfilePath := filepath.Join(caddyfileDir, "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80 { respond ok }"), 0644)

	confDir := t.TempDir()
	confFile := filepath.Join(confDir, "settings.conf")
	os.WriteFile(confFile, []byte("version-1"), 0644)

	var bodies []string
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer adminServer.Close()

	// First reload.
	reloadCaddy(caddyfilePath, adminServer.URL, confFile)

	// Change config file content.
	os.WriteFile(confFile, []byte("version-2"), 0644)

	// Second reload.
	reloadCaddy(caddyfilePath, adminServer.URL, confFile)

	if len(bodies) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(bodies))
	}
	// The two POST bodies should differ (different fingerprints).
	if bodies[0] == bodies[1] {
		t.Error("POST bodies should differ when config file content changes")
	}
}



// ─── End-to-End Deploy Pipeline Tests ───────────────────────────────

// TestDeployEndToEnd_ExclusionAndSettings simulates the full user flow:
// 1. Create an exclusion via POST /api/exclusions
// 2. Update WAF settings via PUT /api/config
// 3. Deploy via POST /api/config/deploy
// 4. Verify all three generated files contain correct content
// 5. Verify exclusions are NOT lost when settings deploy, and vice versa
func TestDeployEndToEnd_ExclusionAndSettings(t *testing.T) {
	// Set up temp dirs and files.
	corazaDir := t.TempDir()
	rlDir := t.TempDir()
	caddyfileDir := t.TempDir()
	caddyfilePath := filepath.Join(caddyfileDir, "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80 { respond ok }"), 0644)

	// Ensure placeholder files exist (like startup does).
	if err := ensureCorazaDir(corazaDir); err != nil {
		t.Fatalf("ensureCorazaDir: %v", err)
	}

	// Mock Caddy admin API.
	var reloadCount int
	var lastPostedBody string
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" && r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			lastPostedBody = string(body)
			reloadCount++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer adminServer.Close()

	deployCfg := DeployConfig{
		CorazaDir:     corazaDir,
		RateLimitDir:  rlDir,
		CaddyfilePath: caddyfilePath,
		CaddyAdminURL: adminServer.URL,
	}

	// Create stores.
	exclusionStore := newTestExclusionStore(t)
	configStore := newTestConfigStore(t)
	rateLimitStore := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))

	// Register all handlers on a mux (same as main()).
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/exclusions", handleCreateExclusion(exclusionStore))
	mux.HandleFunc("GET /api/exclusions", handleListExclusions(exclusionStore))
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(configStore))
	mux.HandleFunc("GET /api/config", handleGetConfig(configStore))
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(configStore, exclusionStore, rateLimitStore, deployCfg))

	// Step 1: Create a "block bad IP" exclusion.
	exclusionJSON := `{
		"name": "Block bad actor",
		"type": "block",
		"conditions": [{"field": "ip", "operator": "ip_match", "value": "192.168.1.100"}],
		"enabled": true
	}`
	req := httptest.NewRequest("POST", "/api/exclusions", strings.NewReader(exclusionJSON))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create exclusion: want 201, got %d: %s", w.Code, w.Body.String())
	}

	// Step 2: Update WAF settings (paranoia=2, thresholds=10).
	configJSON := `{
		"defaults": {
			"mode": "enabled",
			"paranoia_level": 2,
			"inbound_threshold": 10,
			"outbound_threshold": 10
		},
		"services": {}
	}`
	req = httptest.NewRequest("PUT", "/api/config", strings.NewReader(configJSON))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update config: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Step 3: Deploy.
	req = httptest.NewRequest("POST", "/api/config/deploy", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("deploy: want 200, got %d: %s", w.Code, w.Body.String())
	}

	var deployResp DeployResponse
	json.NewDecoder(w.Body).Decode(&deployResp)
	if deployResp.Status != "deployed" {
		t.Errorf("deploy status: want 'deployed', got %q", deployResp.Status)
	}
	if !deployResp.Reloaded {
		t.Error("deploy should report reloaded=true")
	}
	if reloadCount != 1 {
		t.Errorf("Caddy should be reloaded once, got %d", reloadCount)
	}

	// Step 4: Verify generated files on disk.

	// 4a: custom-pre-crs.conf should contain the block exclusion.
	preCRS, err := os.ReadFile(filepath.Join(corazaDir, "custom-pre-crs.conf"))
	if err != nil {
		t.Fatalf("reading pre-crs: %v", err)
	}
	preCRSStr := string(preCRS)
	if !strings.Contains(preCRSStr, "192.168.1.100") {
		t.Error("pre-crs.conf should contain the blocked IP 192.168.1.100")
	}
	if !strings.Contains(preCRSStr, "deny") {
		t.Error("pre-crs.conf should contain deny action for block exclusion")
	}
	if !strings.Contains(preCRSStr, "@ipMatch") {
		t.Error("pre-crs.conf should contain @ipMatch operator")
	}

	// 4b: custom-waf-settings.conf should contain paranoia=2, thresholds=10.
	wafSettings, err := os.ReadFile(filepath.Join(corazaDir, "custom-waf-settings.conf"))
	if err != nil {
		t.Fatalf("reading waf-settings: %v", err)
	}
	wafStr := string(wafSettings)
	if !strings.Contains(wafStr, "paranoia_level=2") {
		t.Errorf("waf-settings should contain paranoia_level=2, got:\n%s", wafStr)
	}
	if !strings.Contains(wafStr, "inbound_anomaly_score_threshold=10") {
		t.Errorf("waf-settings should contain inbound threshold=10, got:\n%s", wafStr)
	}
	if !strings.Contains(wafStr, "SecRuleEngine On") {
		t.Errorf("waf-settings should contain SecRuleEngine On, got:\n%s", wafStr)
	}

	// 4c: custom-post-crs.conf should exist (even if empty of exclusions).
	postCRS, err := os.ReadFile(filepath.Join(corazaDir, "custom-post-crs.conf"))
	if err != nil {
		t.Fatalf("reading post-crs: %v", err)
	}
	if len(postCRS) == 0 {
		t.Error("post-crs.conf should not be empty (at least a header)")
	}

	// Step 5: Deploy again — verify exclusions are still present.
	// (This catches the bug where deploying from Settings would overwrite exclusions.)
	req = httptest.NewRequest("POST", "/api/config/deploy", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("second deploy: want 200, got %d", w.Code)
	}

	preCRS2, _ := os.ReadFile(filepath.Join(corazaDir, "custom-pre-crs.conf"))
	if !strings.Contains(string(preCRS2), "192.168.1.100") {
		t.Error("second deploy: exclusion should still be in pre-crs.conf")
	}
	wafSettings2, _ := os.ReadFile(filepath.Join(corazaDir, "custom-waf-settings.conf"))
	if !strings.Contains(string(wafSettings2), "paranoia_level=2") {
		t.Error("second deploy: settings should still be in waf-settings.conf")
	}

	// Step 6: Verify the Caddy reload received the Caddyfile with fingerprint.
	if !strings.Contains(lastPostedBody, "# waf-api deploy") {
		t.Error("Caddy reload POST should contain fingerprint comment")
	}
	if !strings.Contains(lastPostedBody, "localhost:80") {
		t.Error("Caddy reload POST should contain original Caddyfile content")
	}
}

// TestDeployEndToEnd_SettingsOnlyNoExclusions verifies that deploying
// with settings but zero exclusions still produces valid files.


// TestDeployEndToEnd_SettingsOnlyNoExclusions verifies that deploying
// with settings but zero exclusions still produces valid files.
func TestDeployEndToEnd_SettingsOnlyNoExclusions(t *testing.T) {
	corazaDir := t.TempDir()
	rlDir := t.TempDir()
	caddyfileDir := t.TempDir()
	caddyfilePath := filepath.Join(caddyfileDir, "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80 { respond ok }"), 0644)
	ensureCorazaDir(corazaDir)

	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer adminServer.Close()

	deployCfg := DeployConfig{
		CorazaDir:     corazaDir,
		RateLimitDir:  rlDir,
		CaddyfilePath: caddyfilePath,
		CaddyAdminURL: adminServer.URL,
	}

	exclusionStore := newTestExclusionStore(t)
	configStore := newTestConfigStore(t)
	rateLimitStore := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))

	// Change settings to detection_only with paranoia 3.
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(configStore))
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(configStore, exclusionStore, rateLimitStore, deployCfg))

	configJSON := `{
		"defaults": {
			"mode": "detection_only",
			"paranoia_level": 3,
			"inbound_threshold": 5,
			"outbound_threshold": 4
		},
		"services": {}
	}`
	req := httptest.NewRequest("PUT", "/api/config", strings.NewReader(configJSON))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("update config: want 200, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("POST", "/api/config/deploy", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("deploy: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify settings.
	wafSettings, _ := os.ReadFile(filepath.Join(corazaDir, "custom-waf-settings.conf"))
	wafStr := string(wafSettings)
	if !strings.Contains(wafStr, "paranoia_level=3") {
		t.Errorf("want paranoia_level=3, got:\n%s", wafStr)
	}
	if !strings.Contains(wafStr, "SecRuleEngine DetectionOnly") {
		t.Errorf("want SecRuleEngine DetectionOnly, got:\n%s", wafStr)
	}
	// Detection only should set thresholds to 10000.
	if !strings.Contains(wafStr, "inbound_anomaly_score_threshold=10000") {
		t.Errorf("detection_only should set inbound threshold to 10000, got:\n%s", wafStr)
	}

	// Pre-CRS should just have the header (no exclusions).
	preCRS, _ := os.ReadFile(filepath.Join(corazaDir, "custom-pre-crs.conf"))
	if !strings.Contains(string(preCRS), "Pre-CRS Configuration") {
		t.Error("pre-crs should have a header")
	}
	// Should NOT contain any SecRule (no exclusions).
	if strings.Contains(string(preCRS), "SecRule") {
		t.Error("pre-crs should not contain SecRule when no exclusions exist")
	}
}

// TestDeployEndToEnd_CaddyReloadFails verifies partial deploy when Caddy is unreachable.


// TestDeployEndToEnd_CaddyReloadFails verifies partial deploy when Caddy is unreachable.
func TestDeployEndToEnd_CaddyReloadFails(t *testing.T) {
	corazaDir := t.TempDir()
	rlDir := t.TempDir()
	caddyfileDir := t.TempDir()
	caddyfilePath := filepath.Join(caddyfileDir, "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80 { respond ok }"), 0644)
	ensureCorazaDir(corazaDir)

	// Admin server that rejects reloads.
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Caddy error: invalid config"))
	}))
	defer adminServer.Close()

	deployCfg := DeployConfig{
		CorazaDir:     corazaDir,
		RateLimitDir:  rlDir,
		CaddyfilePath: caddyfilePath,
		CaddyAdminURL: adminServer.URL,
	}

	exclusionStore := newTestExclusionStore(t)
	configStore := newTestConfigStore(t)
	rateLimitStore := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))

	req := httptest.NewRequest("POST", "/api/config/deploy",
		nil)
	w := httptest.NewRecorder()
	handleDeploy(configStore, exclusionStore, rateLimitStore, deployCfg)(w, req)

	if w.Code != 200 {
		t.Fatalf("deploy should return 200 even when reload fails, got %d", w.Code)
	}

	var resp DeployResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != "partial" {
		t.Errorf("want status 'partial', got %q", resp.Status)
	}
	if resp.Reloaded {
		t.Error("reloaded should be false when Caddy reload fails")
	}

	// Files should still be written to disk.
	wafSettings, err := os.ReadFile(filepath.Join(corazaDir, "custom-waf-settings.conf"))
	if err != nil {
		t.Fatalf("waf-settings should exist even when reload fails: %v", err)
	}
	if !strings.Contains(string(wafSettings), "SecRuleEngine On") {
		t.Error("waf-settings should contain default SecRuleEngine On")
	}
}

// ─── Multi-rule-ID skip_rule bug tests ──────────────────────────────
