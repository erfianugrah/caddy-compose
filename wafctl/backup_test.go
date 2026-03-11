package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── Test Helpers ───────────────────────────────────────────────────────────
//
// newTestCSPStore and newTestManagedListStore live in csp_test.go and
// managed_lists_test.go respectively — reused here via package main.

func newTestSecurityHeaderStore(t *testing.T) *SecurityHeaderStore {
	t.Helper()
	return NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec-headers.json"))
}

func setupBackupMux(t *testing.T) (*http.ServeMux, *ConfigStore, *CSPStore, *SecurityHeaderStore, *ExclusionStore, *RateLimitRuleStore, *ManagedListStore) {
	t.Helper()
	cs := newTestConfigStore(t)
	cspS := newTestCSPStore(t)
	secS := newTestSecurityHeaderStore(t)
	es := newTestExclusionStore(t)
	rs := emptyRLRuleStore(t)
	ls := newTestManagedListStore(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/backup", handleBackup(cs, cspS, secS, es, rs, ls))
	mux.HandleFunc("POST /api/backup/restore", handleRestore(cs, cspS, secS, es, rs, ls))
	return mux, cs, cspS, secS, es, rs, ls
}

// testAllowExclusion returns a valid allow exclusion with a condition.
func testAllowExclusion(name string) RuleExclusion {
	return RuleExclusion{
		Name:    name,
		Type:    "allow",
		Enabled: true,
		Conditions: []Condition{
			{Field: "path", Operator: "eq", Value: "/health"},
		},
	}
}

// testSkipRuleExclusion returns a valid skip_rule exclusion.
func testSkipRuleExclusion(name, ruleID string) RuleExclusion {
	return RuleExclusion{
		Name:    name,
		Type:    "skip_rule",
		Enabled: true,
		RuleID:  ruleID,
		Conditions: []Condition{
			{Field: "path", Operator: "eq", Value: "/api"},
		},
	}
}

// testBlockExclusion returns a valid block exclusion with conditions and tags.
func testBlockExclusion(name string, tags []string) RuleExclusion {
	return RuleExclusion{
		Name:    name,
		Type:    "block",
		Enabled: true,
		Tags:    tags,
		Conditions: []Condition{
			{Field: "path", Operator: "eq", Value: "/evil"},
		},
	}
}

// testRLRule returns a valid rate limit rule.
func testRLRule(name, service string) RateLimitRule {
	return RateLimitRule{
		Name:    name,
		Service: service,
		Key:     "client_ip",
		Events:  100,
		Window:  "1m",
		Action:  "deny",
		Enabled: true,
	}
}

// ─── Backup: Empty Stores ───────────────────────────────────────────────────

func TestBackup_EmptyStores(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	req := httptest.NewRequest("GET", "/api/backup", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var backup FullBackup
	if err := json.Unmarshal(rec.Body.Bytes(), &backup); err != nil {
		t.Fatalf("failed to decode backup: %v", err)
	}

	if backup.Version != 1 {
		t.Errorf("expected version 1, got %d", backup.Version)
	}
	if backup.ExportedAt.IsZero() {
		t.Error("expected non-zero exported_at")
	}
	if backup.WAFConfig.Defaults.Mode != "enabled" {
		t.Errorf("expected default mode 'enabled', got %q", backup.WAFConfig.Defaults.Mode)
	}
	if backup.WAFConfig.Defaults.ParanoiaLevel != 1 {
		t.Errorf("expected default paranoia 1, got %d", backup.WAFConfig.Defaults.ParanoiaLevel)
	}
	// Empty stores should produce empty/nil slices, not absent fields.
	if backup.Exclusions == nil {
		// nil is acceptable — it means no exclusions.
	}
	if backup.RateLimits.Rules == nil {
		// nil is acceptable — it means no rules.
	}
	if backup.Lists == nil {
		// nil is acceptable — it means no lists.
	}
	// CSP should have defaults.
	if !cspEnabled(backup.CSPConfig) {
		t.Error("CSP should be enabled by default")
	}
}

// ─── Backup: Content-Disposition Header ─────────────────────────────────────

func TestBackup_ContentDisposition(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	req := httptest.NewRequest("GET", "/api/backup", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	cd := rec.Header().Get("Content-Disposition")
	if cd == "" {
		t.Fatal("expected Content-Disposition header")
	}
	if !strings.Contains(cd, "wafctl-backup-") {
		t.Errorf("Content-Disposition should contain 'wafctl-backup-', got %q", cd)
	}
	if !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition should be attachment, got %q", cd)
	}
	if !strings.HasSuffix(cd, `.json"`) {
		t.Errorf("Content-Disposition should end with .json, got %q", cd)
	}
}

// ─── Backup: Content-Type ───────────────────────────────────────────────────

func TestBackup_ContentType(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	req := httptest.NewRequest("GET", "/api/backup", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected application/json, got %q", ct)
	}
}

// ─── Backup: With Seeded Data ───────────────────────────────────────────────

func TestBackup_WithData(t *testing.T) {
	mux, cs, _, _, es, rs, ls := setupBackupMux(t)

	// Seed WAF config.
	cs.Update(WAFConfig{
		Defaults: WAFServiceSettings{
			Mode:              "detection_only",
			ParanoiaLevel:     3,
			InboundThreshold:  10,
			OutboundThreshold: 8,
		},
		Services: map[string]WAFServiceSettings{
			"httpbun": {
				Mode:              "enabled",
				ParanoiaLevel:     2,
				InboundThreshold:  5,
				OutboundThreshold: 4,
			},
		},
	})
	// Seed exclusions.
	es.Create(testAllowExclusion("test-allow"))
	es.Create(testBlockExclusion("test-block", []string{"honeypot"}))
	// Seed RL rule.
	rs.Create(testRLRule("test-rl", "httpbun"))
	// Seed managed list.
	ls.Create(ManagedList{
		Name:   "my-ips",
		Kind:   "ip",
		Source: "manual",
		Items:  []string{"10.0.0.1", "10.0.0.2"},
	})

	req := httptest.NewRequest("GET", "/api/backup", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var backup FullBackup
	json.Unmarshal(rec.Body.Bytes(), &backup)

	if backup.WAFConfig.Defaults.Mode != "detection_only" {
		t.Errorf("expected WAF mode 'detection_only', got %q", backup.WAFConfig.Defaults.Mode)
	}
	if _, ok := backup.WAFConfig.Services["httpbun"]; !ok {
		t.Error("expected httpbun service override in backup")
	}
	if len(backup.Exclusions) != 2 {
		t.Errorf("expected 2 exclusions, got %d", len(backup.Exclusions))
	}
	if len(backup.RateLimits.Rules) != 1 {
		t.Errorf("expected 1 RL rule, got %d", len(backup.RateLimits.Rules))
	}
	if len(backup.Lists) != 1 {
		t.Errorf("expected 1 list, got %d", len(backup.Lists))
	}
}

// ─── Backup: JSON Is Valid ──────────────────────────────────────────────────

func TestBackup_ValidJSON(t *testing.T) {
	mux, cs, _, _, es, rs, _ := setupBackupMux(t)

	// Seed data to make the JSON non-trivial.
	cs.Update(WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "enabled", ParanoiaLevel: 2,
			InboundThreshold: 5, OutboundThreshold: 4,
		},
		Services: map[string]WAFServiceSettings{},
	})
	es.Create(testAllowExclusion("json-test"))
	rs.Create(testRLRule("json-rl", "svc"))

	req := httptest.NewRequest("GET", "/api/backup", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Verify it's valid JSON by round-tripping.
	var raw json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("backup is not valid JSON: %v", err)
	}
	// And that it re-marshals to the same structure.
	var backup FullBackup
	if err := json.Unmarshal(rec.Body.Bytes(), &backup); err != nil {
		t.Fatalf("backup does not match FullBackup schema: %v", err)
	}
}

// ─── Backup: Ipsum Lists Excluded ───────────────────────────────────────────

func TestBackup_IpsumListsExcluded(t *testing.T) {
	dir := t.TempDir()
	listsPath := filepath.Join(dir, "lists-ipsum.json")
	ipsumList := ManagedList{
		ID:     "ipsum-level-3",
		Name:   "IPsum Level 3",
		Kind:   "ip",
		Source: "ipsum",
		Items:  []string{"1.2.3.4"},
	}
	normalList := ManagedList{
		ID:     "custom-ips",
		Name:   "Custom IPs",
		Kind:   "ip",
		Source: "manual",
		Items:  []string{"10.0.0.1"},
	}
	data, _ := json.Marshal([]ManagedList{ipsumList, normalList})
	os.WriteFile(listsPath, data, 0644)
	ipsumStore := NewManagedListStore(listsPath, filepath.Join(dir, "lists-dir"))

	mux := http.NewServeMux()
	cs := newTestConfigStore(t)
	csp := newTestCSPStore(t)
	es := newTestExclusionStore(t)
	rs := emptyRLRuleStore(t)
	sec := newTestSecurityHeaderStore(t)
	mux.HandleFunc("GET /api/backup", handleBackup(cs, csp, sec, es, rs, ipsumStore))

	req := httptest.NewRequest("GET", "/api/backup", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var backup FullBackup
	json.Unmarshal(rec.Body.Bytes(), &backup)

	for _, l := range backup.Lists {
		if l.Source == "ipsum" {
			t.Errorf("ipsum list should not be in backup: %s", l.Name)
		}
	}
}

// ─── Restore: Valid Full Backup ─────────────────────────────────────────────

func TestRestore_ValidBackup(t *testing.T) {
	mux, cs, cspS, _, es, rs, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode:              "detection_only",
				ParanoiaLevel:     2,
				InboundThreshold:  8,
				OutboundThreshold: 6,
			},
			Services: map[string]WAFServiceSettings{},
		},
		CSPConfig: CSPConfig{
			Enabled:        boolPtr(false),
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
			Services:       map[string]CSPServiceConfig{},
		},
		Exclusions: []RuleExclusion{
			testAllowExclusion("restored-rule"),
		},
		RateLimits: RateLimitBackup{
			Rules: []RateLimitRule{
				testRLRule("restored-rl", "test"),
			},
		},
		Lists: []ManagedList{},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "restored" {
		t.Errorf("expected status 'restored', got %v", resp["status"])
	}

	// Verify each store was updated.
	cfg := cs.Get()
	if cfg.Defaults.Mode != "detection_only" {
		t.Errorf("WAF config not restored: mode=%q", cfg.Defaults.Mode)
	}
	if cfg.Defaults.ParanoiaLevel != 2 {
		t.Errorf("WAF config not restored: paranoia=%d", cfg.Defaults.ParanoiaLevel)
	}

	cspCfg := cspS.Get()
	if cspEnabled(cspCfg) {
		t.Error("CSP config not restored: expected disabled")
	}

	exclusions := es.List()
	if len(exclusions) != 1 {
		t.Fatalf("expected 1 exclusion, got %d", len(exclusions))
	}
	if exclusions[0].Name != "restored-rule" {
		t.Errorf("exclusion name not preserved: got %q", exclusions[0].Name)
	}
	// IDs should be reassigned (not empty or matching input).
	if exclusions[0].ID == "" {
		t.Error("restored exclusion should have a new ID assigned")
	}

	rules := rs.List()
	if len(rules) != 1 {
		t.Fatalf("expected 1 RL rule, got %d", len(rules))
	}
	if rules[0].Name != "restored-rl" {
		t.Errorf("RL rule name not preserved: got %q", rules[0].Name)
	}
}

// ─── Restore: Missing Version ───────────────────────────────────────────────

func TestRestore_MissingVersion(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	body := []byte(`{"waf_config":{"defaults":{"mode":"enabled","paranoia_level":1,"inbound_threshold":5,"outbound_threshold":4}}}`)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Error, "version") {
		t.Errorf("expected error about version, got %q", resp.Error)
	}
}

// ─── Restore: Invalid JSON Body ─────────────────────────────────────────────

func TestRestore_InvalidJSON(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader([]byte(`{not json}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ─── Restore: Empty Body ────────────────────────────────────────────────────

func TestRestore_EmptyBody(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader([]byte{}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ─── Restore: Invalid WAF Config (partial) ──────────────────────────────────

func TestRestore_InvalidWAFConfig(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode:              "bogus_mode",
				ParanoiaLevel:     2,
				InboundThreshold:  5,
				OutboundThreshold: 4,
			},
		},
		CSPConfig: defaultCSPConfig(),
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200 (partial restore), got %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["status"] != "partial" {
		t.Errorf("expected status 'partial', got %v", resp["status"])
	}

	results := resp["results"].(map[string]interface{})
	wafResult := results["waf_config"].(string)
	if !strings.HasPrefix(wafResult, "failed") {
		t.Errorf("expected waf_config to fail, got %q", wafResult)
	}
	// Other stores should still restore or skip.
	cspResult := results["csp_config"].(string)
	if cspResult != "restored" {
		t.Errorf("expected csp_config restored, got %q", cspResult)
	}
}

// ─── Restore: Invalid CSP Config (partial) ──────────────────────────────────

func TestRestore_InvalidCSPConfig(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "enabled", ParanoiaLevel: 1,
				InboundThreshold: 5, OutboundThreshold: 4,
			},
			Services: map[string]WAFServiceSettings{},
		},
		CSPConfig: CSPConfig{
			Services: map[string]CSPServiceConfig{
				"svc": {Mode: "bogus_mode"}, // invalid mode
			},
		},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["status"] != "partial" {
		t.Errorf("expected partial, got %v", resp["status"])
	}
	results := resp["results"].(map[string]interface{})
	cspResult := results["csp_config"].(string)
	if !strings.HasPrefix(cspResult, "failed") {
		t.Errorf("expected csp_config failure, got %q", cspResult)
	}
	// WAF config should still succeed.
	if results["waf_config"] != "restored" {
		t.Errorf("expected waf_config restored, got %v", results["waf_config"])
	}
}

// ─── Restore: Invalid Exclusion (partial) ───────────────────────────────────

func TestRestore_InvalidExclusion(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "enabled", ParanoiaLevel: 1,
				InboundThreshold: 5, OutboundThreshold: 4,
			},
			Services: map[string]WAFServiceSettings{},
		},
		CSPConfig: defaultCSPConfig(),
		Exclusions: []RuleExclusion{
			{Name: "bad-rule", Type: "invalid_type", Enabled: true},
		},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200 (partial), got %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["status"] != "partial" {
		t.Errorf("expected partial, got %v", resp["status"])
	}
	results := resp["results"].(map[string]interface{})
	exclResult := results["exclusions"].(string)
	if !strings.HasPrefix(exclResult, "failed") {
		t.Errorf("expected exclusions failure, got %q", exclResult)
	}
}

// ─── Restore: Invalid RL Rule (partial) ─────────────────────────────────────

func TestRestore_InvalidRLRule(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "enabled", ParanoiaLevel: 1,
				InboundThreshold: 5, OutboundThreshold: 4,
			},
			Services: map[string]WAFServiceSettings{},
		},
		CSPConfig: defaultCSPConfig(),
		RateLimits: RateLimitBackup{
			Rules: []RateLimitRule{
				{Name: "bad-rl", Key: "invalid_key", Events: 0, Window: "nope", Action: "deny"},
			},
		},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["status"] != "partial" {
		t.Errorf("expected partial, got %v", resp["status"])
	}
	results := resp["results"].(map[string]interface{})
	rlResult := results["rate_limits"].(string)
	if !strings.HasPrefix(rlResult, "failed") {
		t.Errorf("expected rate_limits failure, got %q", rlResult)
	}
}

// ─── Restore: Empty Sections Skipped ────────────────────────────────────────

func TestRestore_EmptyExclusions(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "enabled", ParanoiaLevel: 1,
				InboundThreshold: 5, OutboundThreshold: 4,
			},
			Services: map[string]WAFServiceSettings{},
		},
		CSPConfig:  defaultCSPConfig(),
		Exclusions: []RuleExclusion{},
		RateLimits: RateLimitBackup{},
		Lists:      []ManagedList{},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	results := resp["results"].(map[string]interface{})
	if results["exclusions"] != "skipped: no exclusions in backup" {
		t.Errorf("unexpected exclusions result: %v", results["exclusions"])
	}
	if results["rate_limits"] != "skipped: no rules in backup" {
		t.Errorf("unexpected rate_limits result: %v", results["rate_limits"])
	}
	if results["lists"] != "skipped: no lists in backup" {
		t.Errorf("unexpected lists result: %v", results["lists"])
	}
}

// ─── Restore: Full Round-Trip ───────────────────────────────────────────────

func TestRestore_RoundTrip(t *testing.T) {
	mux, cs, cspS, _, es, rs, ls := setupBackupMux(t)

	// Seed all stores with non-trivial data.
	cs.Update(WAFConfig{
		Defaults: WAFServiceSettings{
			Mode:              "detection_only",
			ParanoiaLevel:     3,
			InboundThreshold:  15,
			OutboundThreshold: 10,
		},
		Services: map[string]WAFServiceSettings{
			"api-svc": {
				Mode: "enabled", ParanoiaLevel: 4,
				InboundThreshold: 5, OutboundThreshold: 3,
			},
		},
	})
	cspS.Update(CSPConfig{
		Enabled: boolPtr(true),
		GlobalDefaults: CSPPolicy{
			DefaultSrc: []string{"'self'"},
			ScriptSrc:  []string{"'self'", "'unsafe-inline'"},
		},
		Services: map[string]CSPServiceConfig{
			"web": {Mode: "set", Inherit: true, Policy: CSPPolicy{
				ImgSrc: []string{"'self'", "data:", "https:"},
			}},
		},
	})
	es.Create(testSkipRuleExclusion("roundtrip-skip", "920270"))
	es.Create(testBlockExclusion("roundtrip-block", []string{"honeypot"}))
	rs.Create(testRLRule("roundtrip-rl", "test"))
	rs.Create(RateLimitRule{
		Name: "roundtrip-rl2", Service: "api",
		Key: "client_ip+path", Events: 50, Window: "5m",
		Action: "log_only", Enabled: true,
	})
	ls.Create(ManagedList{
		Name:   "test-list",
		Kind:   "ip",
		Source: "manual",
		Items:  []string{"10.0.0.1", "10.0.0.2"},
	})

	// Export.
	req := httptest.NewRequest("GET", "/api/backup", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("backup failed: %d", rec.Code)
	}
	backupJSON := rec.Body.Bytes()

	// Parse to verify export contents.
	var exported FullBackup
	json.Unmarshal(backupJSON, &exported)
	if len(exported.Exclusions) != 2 {
		t.Fatalf("expected 2 exclusions in export, got %d", len(exported.Exclusions))
	}
	if len(exported.RateLimits.Rules) != 2 {
		t.Fatalf("expected 2 RL rules in export, got %d", len(exported.RateLimits.Rules))
	}
	if len(exported.Lists) != 1 {
		t.Fatalf("expected 1 list in export, got %d", len(exported.Lists))
	}
	if len(exported.WAFConfig.Services) != 1 {
		t.Fatalf("expected 1 service override in export, got %d", len(exported.WAFConfig.Services))
	}
	if len(exported.CSPConfig.Services) != 1 {
		t.Fatalf("expected 1 CSP service in export, got %d", len(exported.CSPConfig.Services))
	}

	// Set up a fresh set of stores.
	mux2, cs2, csp2, _, es2, rs2, ls2 := setupBackupMux(t)

	// Restore into fresh stores.
	req2 := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(backupJSON))
	rec2 := httptest.NewRecorder()
	mux2.ServeHTTP(rec2, req2)

	if rec2.Code != 200 {
		t.Fatalf("restore failed: %d: %s", rec2.Code, rec2.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec2.Body.Bytes(), &resp)
	if resp["status"] != "restored" {
		t.Fatalf("expected fully restored, got %v — results: %v", resp["status"], resp["results"])
	}

	// Verify WAF config.
	cfg2 := cs2.Get()
	if cfg2.Defaults.ParanoiaLevel != 3 {
		t.Errorf("expected paranoia 3, got %d", cfg2.Defaults.ParanoiaLevel)
	}
	if cfg2.Defaults.Mode != "detection_only" {
		t.Errorf("expected mode detection_only, got %q", cfg2.Defaults.Mode)
	}
	if _, ok := cfg2.Services["api-svc"]; !ok {
		t.Error("expected api-svc service override after restore")
	}

	// Verify CSP config.
	cspCfg2 := csp2.Get()
	if !cspEnabled(cspCfg2) {
		t.Error("CSP should be enabled")
	}
	if _, ok := cspCfg2.Services["web"]; !ok {
		t.Error("expected web service in CSP after restore")
	}
	if len(cspCfg2.GlobalDefaults.ScriptSrc) != 2 {
		t.Errorf("expected 2 script_src values, got %d", len(cspCfg2.GlobalDefaults.ScriptSrc))
	}

	// Verify exclusions.
	excl2 := es2.List()
	if len(excl2) != 2 {
		t.Fatalf("expected 2 exclusions, got %d", len(excl2))
	}
	names := map[string]bool{}
	for _, e := range excl2 {
		names[e.Name] = true
		// Verify IDs are freshly assigned.
		if e.ID == "" {
			t.Errorf("exclusion %q has empty ID", e.Name)
		}
		if e.UpdatedAt.IsZero() {
			t.Errorf("exclusion %q has zero UpdatedAt", e.Name)
		}
	}
	if !names["roundtrip-skip"] || !names["roundtrip-block"] {
		t.Errorf("expected both exclusions by name, got %v", names)
	}

	// Verify skip_rule details preserved.
	for _, e := range excl2 {
		if e.Name == "roundtrip-skip" {
			if e.RuleID != "920270" {
				t.Errorf("rule ID not preserved: got %q", e.RuleID)
			}
			if e.Type != "skip_rule" {
				t.Errorf("type not preserved: got %q", e.Type)
			}
		}
		if e.Name == "roundtrip-block" {
			if len(e.Tags) != 1 || e.Tags[0] != "honeypot" {
				t.Errorf("tags not preserved: got %v", e.Tags)
			}
		}
	}

	// Verify RL rules.
	rules2 := rs2.List()
	if len(rules2) != 2 {
		t.Fatalf("expected 2 RL rules, got %d", len(rules2))
	}
	rlNames := map[string]bool{}
	for _, r := range rules2 {
		rlNames[r.Name] = true
	}
	if !rlNames["roundtrip-rl"] || !rlNames["roundtrip-rl2"] {
		t.Errorf("expected both RL rules by name, got %v", rlNames)
	}

	// Verify managed lists.
	lists2 := ls2.List()
	foundTestList := false
	for _, l := range lists2 {
		if l.Name == "test-list" {
			foundTestList = true
			if len(l.Items) != 2 {
				t.Errorf("expected 2 items in list, got %d", len(l.Items))
			}
			if l.Kind != "ip" {
				t.Errorf("expected kind 'ip', got %q", l.Kind)
			}
		}
	}
	if !foundTestList {
		t.Error("test-list not found after round-trip")
	}
}

// ─── Restore: Multiple Failures ─────────────────────────────────────────────

func TestRestore_MultipleFailures(t *testing.T) {
	mux, _, _, _, _, _, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "bogus", ParanoiaLevel: 99, // invalid
				InboundThreshold: 5, OutboundThreshold: 4,
			},
		},
		CSPConfig: CSPConfig{
			Services: map[string]CSPServiceConfig{
				"../evil": {Mode: "set"}, // invalid service name
			},
		},
		Exclusions: []RuleExclusion{
			{Name: "bad", Type: "nonexistent"},
		},
		RateLimits: RateLimitBackup{
			Rules: []RateLimitRule{
				{Name: "", Key: "bad", Events: -1, Window: "nope", Action: "deny"},
			},
		},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["status"] != "partial" {
		t.Errorf("expected partial, got %v", resp["status"])
	}

	results := resp["results"].(map[string]interface{})
	// All stores except lists (empty=skipped) should fail.
	for _, key := range []string{"waf_config", "csp_config", "exclusions", "rate_limits"} {
		result := results[key].(string)
		if !strings.HasPrefix(result, "failed") {
			t.Errorf("%s: expected failure, got %q", key, result)
		}
	}
}

// ─── Restore: Preserves Existing Data on Partial Failure ────────────────────

func TestRestore_PreservesExistingOnPartialFailure(t *testing.T) {
	mux, cs, _, _, es, _, _ := setupBackupMux(t)

	// Pre-seed some data.
	cs.Update(WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "enabled", ParanoiaLevel: 2,
			InboundThreshold: 10, OutboundThreshold: 8,
		},
		Services: map[string]WAFServiceSettings{},
	})
	es.Create(testAllowExclusion("existing-rule"))

	// Try to restore with a valid WAF config but invalid exclusions.
	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "detection_only", ParanoiaLevel: 3,
				InboundThreshold: 15, OutboundThreshold: 12,
			},
			Services: map[string]WAFServiceSettings{},
		},
		CSPConfig: defaultCSPConfig(),
		Exclusions: []RuleExclusion{
			{Name: "bad", Type: "completely_invalid"},
		},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// WAF config should be updated (it was valid).
	cfg := cs.Get()
	if cfg.Defaults.ParanoiaLevel != 3 {
		t.Errorf("WAF config should have been updated to paranoia 3, got %d", cfg.Defaults.ParanoiaLevel)
	}

	// Exclusions should NOT have been replaced (validation failed).
	excls := es.List()
	if len(excls) != 1 || excls[0].Name != "existing-rule" {
		t.Errorf("exclusions should be preserved after failed restore: got %d exclusions", len(excls))
	}
}

// ─── Restore: WAF Config With Service Overrides ─────────────────────────────

func TestRestore_WAFConfigServiceOverrides(t *testing.T) {
	mux, cs, _, _, _, _, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "enabled", ParanoiaLevel: 2,
				InboundThreshold: 10, OutboundThreshold: 8,
			},
			Services: map[string]WAFServiceSettings{
				"api": {
					Mode: "detection_only", ParanoiaLevel: 4,
					InboundThreshold: 20, OutboundThreshold: 15,
				},
				"web": {
					Mode: "disabled", ParanoiaLevel: 1,
					InboundThreshold: 5, OutboundThreshold: 4,
				},
			},
		},
		CSPConfig: defaultCSPConfig(),
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	cfg := cs.Get()
	if len(cfg.Services) != 2 {
		t.Fatalf("expected 2 service overrides, got %d", len(cfg.Services))
	}
	apiCfg := cfg.Services["api"]
	if apiCfg.Mode != "detection_only" || apiCfg.ParanoiaLevel != 4 {
		t.Errorf("api service not restored correctly: mode=%q pl=%d", apiCfg.Mode, apiCfg.ParanoiaLevel)
	}
	webCfg := cfg.Services["web"]
	if webCfg.Mode != "disabled" {
		t.Errorf("web service not restored correctly: mode=%q", webCfg.Mode)
	}
}

// ─── Restore: CSP With Service Overrides ────────────────────────────────────

func TestRestore_CSPServiceOverrides(t *testing.T) {
	mux, _, cspS, _, _, _, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "enabled", ParanoiaLevel: 1,
				InboundThreshold: 5, OutboundThreshold: 4,
			},
			Services: map[string]WAFServiceSettings{},
		},
		CSPConfig: CSPConfig{
			Enabled: boolPtr(true),
			GlobalDefaults: CSPPolicy{
				DefaultSrc: []string{"'self'"},
				ScriptSrc:  []string{"'self'", "'unsafe-inline'"},
			},
			Services: map[string]CSPServiceConfig{
				"strict-svc": {
					Mode:    "set",
					Inherit: false,
					Policy: CSPPolicy{
						DefaultSrc: []string{"'none'"},
						ScriptSrc:  []string{"'self'"},
					},
				},
				"relaxed-svc": {
					Mode:       "default",
					Inherit:    true,
					ReportOnly: true,
				},
			},
		},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	cspCfg := cspS.Get()
	if len(cspCfg.Services) != 2 {
		t.Fatalf("expected 2 CSP service overrides, got %d", len(cspCfg.Services))
	}
	strict := cspCfg.Services["strict-svc"]
	if strict.Mode != "set" || strict.Inherit {
		t.Errorf("strict-svc not restored: mode=%q inherit=%v", strict.Mode, strict.Inherit)
	}
	relaxed := cspCfg.Services["relaxed-svc"]
	if relaxed.Mode != "default" || !relaxed.ReportOnly || !relaxed.Inherit {
		t.Errorf("relaxed-svc not restored: mode=%q ro=%v inherit=%v", relaxed.Mode, relaxed.ReportOnly, relaxed.Inherit)
	}
}

// ─── Restore: Exclusion Conditions Preserved ────────────────────────────────

func TestRestore_ExclusionConditionsPreserved(t *testing.T) {
	mux, _, _, _, es, _, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "enabled", ParanoiaLevel: 1,
				InboundThreshold: 5, OutboundThreshold: 4,
			},
			Services: map[string]WAFServiceSettings{},
		},
		CSPConfig: defaultCSPConfig(),
		Exclusions: []RuleExclusion{
			{
				Name:    "multi-cond",
				Type:    "allow",
				Enabled: true,
				GroupOp: "or",
				Conditions: []Condition{
					{Field: "path", Operator: "begins_with", Value: "/api/"},
					{Field: "ip", Operator: "eq", Value: "10.0.0.1"},
					{Field: "method", Operator: "in", Value: "GET|POST"},
				},
			},
		},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	excls := es.List()
	if len(excls) != 1 {
		t.Fatalf("expected 1 exclusion, got %d", len(excls))
	}
	e := excls[0]
	if e.GroupOp != "or" {
		t.Errorf("group_operator not preserved: got %q", e.GroupOp)
	}
	if len(e.Conditions) != 3 {
		t.Fatalf("expected 3 conditions, got %d", len(e.Conditions))
	}
	if e.Conditions[0].Field != "path" || e.Conditions[0].Operator != "begins_with" {
		t.Errorf("condition[0] not preserved: %+v", e.Conditions[0])
	}
	if e.Conditions[2].Operator != "in" || e.Conditions[2].Value != "GET|POST" {
		t.Errorf("condition[2] not preserved: %+v", e.Conditions[2])
	}
}

// ─── Restore: RL Rule Details Preserved ─────────────────────────────────────

func TestRestore_RLRuleDetailsPreserved(t *testing.T) {
	mux, _, _, _, _, rs, _ := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "enabled", ParanoiaLevel: 1,
				InboundThreshold: 5, OutboundThreshold: 4,
			},
			Services: map[string]WAFServiceSettings{},
		},
		CSPConfig: defaultCSPConfig(),
		RateLimits: RateLimitBackup{
			Rules: []RateLimitRule{
				{
					Name:        "detailed-rl",
					Description: "Rate limit for API",
					Service:     "api-svc",
					Key:         "client_ip+path",
					Events:      500,
					Window:      "10m",
					Action:      "log_only",
					Priority:    50,
					Tags:        []string{"api", "monitoring"},
					Enabled:     true,
					Conditions: []Condition{
						{Field: "path", Operator: "begins_with", Value: "/api/v3"},
						{Field: "method", Operator: "in", Value: "POST|PUT|DELETE"},
					},
					GroupOp: "and",
				},
			},
		},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	rules := rs.List()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Name != "detailed-rl" {
		t.Errorf("name: got %q", r.Name)
	}
	if r.Key != "client_ip+path" {
		t.Errorf("key: got %q", r.Key)
	}
	if r.Events != 500 {
		t.Errorf("events: got %d", r.Events)
	}
	if r.Window != "10m" {
		t.Errorf("window: got %q", r.Window)
	}
	if r.Action != "log_only" {
		t.Errorf("action: got %q", r.Action)
	}
	if len(r.Tags) != 2 || r.Tags[0] != "api" {
		t.Errorf("tags: got %v", r.Tags)
	}
	if len(r.Conditions) != 2 {
		t.Errorf("conditions: got %d", len(r.Conditions))
	}
}

// ─── Restore: Managed List Details Preserved ────────────────────────────────

func TestRestore_ManagedListDetailsPreserved(t *testing.T) {
	mux, _, _, _, _, _, ls := setupBackupMux(t)

	backup := FullBackup{
		Version: 1,
		WAFConfig: WAFConfig{
			Defaults: WAFServiceSettings{
				Mode: "enabled", ParanoiaLevel: 1,
				InboundThreshold: 5, OutboundThreshold: 4,
			},
			Services: map[string]WAFServiceSettings{},
		},
		CSPConfig: defaultCSPConfig(),
		Lists: []ManagedList{
			{
				Name:        "scanner-uas",
				Description: "Known scanner user agents",
				Kind:        "string",
				Source:      "manual",
				Items:       []string{"curl/7.68", "BadBot/1.0", "Nmap/7.92"},
			},
			{
				Name:   "trusted-ips",
				Kind:   "ip",
				Source: "manual",
				Items:  []string{"10.0.0.0/8", "172.16.0.0/12"},
			},
		},
	}

	body, _ := json.Marshal(backup)
	req := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	lists := ls.List()
	if len(lists) < 2 {
		t.Fatalf("expected at least 2 lists, got %d", len(lists))
	}
	nameMap := map[string]ManagedList{}
	for _, l := range lists {
		nameMap[l.Name] = l
	}
	if ua, ok := nameMap["scanner-uas"]; !ok {
		t.Error("scanner-uas not found")
	} else {
		if ua.Kind != "string" {
			t.Errorf("kind: got %q", ua.Kind)
		}
		if len(ua.Items) != 3 {
			t.Errorf("items: got %d", len(ua.Items))
		}
	}
	if ips, ok := nameMap["trusted-ips"]; !ok {
		t.Error("trusted-ips not found")
	} else {
		if ips.Kind != "ip" {
			t.Errorf("kind: got %q", ips.Kind)
		}
	}
}

// ─── itoa ───────────────────────────────────────────────────────────────────

func TestItoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{-5, "-5"},
		{999999, "999999"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("itoa(%d)", tt.input), func(t *testing.T) {
			got := itoa(tt.input)
			if got != tt.want {
				t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
