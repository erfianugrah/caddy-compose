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

// TestDeployEndpointNoReload verifies that the deploy endpoint writes
// policy-rules.json and returns success without triggering a Caddy reload.
// The policy engine plugin detects the file change via mtime polling.
func TestDeployEndpointNoReload(t *testing.T) {
	wafDir := t.TempDir()
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost:80\n"), 0644)

	deployCfg := DeployConfig{
		WafDir:          wafDir,
		CaddyfilePath:   caddyfilePath,
		CaddyAdminURL:   "http://127.0.0.1:0", // unused — no reload
		PolicyRulesFile: filepath.Join(wafDir, "policy-rules.json"),
	}

	tmpDir := t.TempDir()
	es := NewExclusionStore(filepath.Join(t.TempDir(), "exclusions.json"))
	cs := NewConfigStore(filepath.Join(t.TempDir(), "config.json"))
	rs := NewRateLimitRuleStore(filepath.Join(t.TempDir(), "rl.json"))
	ls := NewManagedListStore(filepath.Join(t.TempDir(), "lists.json"), tmpDir)
	cspStore := NewCSPStore(filepath.Join(t.TempDir(), "csp.json"))
	secStore := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))
	ds := NewDefaultRuleStore(filepath.Join(t.TempDir(), "defaults.json"), filepath.Join(t.TempDir(), "overrides.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(cs, es, rs, ls, cspStore, secStore, ds, deployCfg))

	req := httptest.NewRequest("POST", "/api/config/deploy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp DeployResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Status != "deployed" {
		t.Errorf("expected status=deployed, got %q", resp.Status)
	}
	if resp.Reloaded {
		t.Error("expected reloaded=false (hot-reload via mtime)")
	}

	// Verify policy-rules.json was written.
	if _, err := os.Stat(deployCfg.PolicyRulesFile); err != nil {
		t.Errorf("policy-rules.json should exist: %v", err)
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

	// Mock Caddy admin API that captures the POST body and headers.
	var receivedBody []byte
	var receivedHeaders http.Header
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" && r.Method == "POST" {
			receivedBody, _ = io.ReadAll(r.Body)
			receivedHeaders = r.Header.Clone()
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
	if !strings.HasPrefix(bodyStr, "# wafctl deploy ") {
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

	// Verify Cache-Control: must-revalidate header is sent to force Caddy
	// to reload even when the adapted JSON is byte-identical.
	if cc := receivedHeaders.Get("Cache-Control"); cc != "must-revalidate" {
		t.Errorf("expected Cache-Control: must-revalidate, got %q", cc)
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
