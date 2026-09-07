package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		PolicyRulesFile: filepath.Join(wafDir, "policy-rules.json"),
	}

	tmpDir := t.TempDir()
	es := NewExclusionStore(filepath.Join(t.TempDir(), "exclusions.json"))
	cs := NewConfigStore(filepath.Join(t.TempDir(), "config.json"))
	ls := NewManagedListStore(filepath.Join(t.TempDir(), "lists.json"), tmpDir)
	cspStore := NewCSPStore(filepath.Join(t.TempDir(), "csp.json"))
	secStore := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))
	ds := NewDefaultRuleStore(filepath.Join(t.TempDir(), "defaults.json"), filepath.Join(t.TempDir(), "overrides.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(cs, es, ls, cspStore, secStore, nil, ds, deployCfg))

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
