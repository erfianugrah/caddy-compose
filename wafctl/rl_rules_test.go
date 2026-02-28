package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ─── Test Helpers ───────────────────────────────────────────────────

func newTestRLRuleStore(t *testing.T) *RateLimitRuleStore {
	t.Helper()
	return NewRateLimitRuleStore(filepath.Join(t.TempDir(), "rl-rules.json"))
}

func sampleRLRule() RateLimitRule {
	return RateLimitRule{
		Name:    "api-limit",
		Service: "sonarr.erfi.io",
		Key:     "client_ip",
		Events:  100,
		Window:  "1m",
		Action:  "deny",
		Enabled: true,
	}
}

// ─── Store Lifecycle ────────────────────────────────────────────────

func TestRLRuleStoreStartsEmpty(t *testing.T) {
	s := newTestRLRuleStore(t)
	rules := s.List()
	if len(rules) != 0 {
		t.Fatalf("want 0 rules, got %d", len(rules))
	}
}

func TestRLRuleStorePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rl-rules.json")
	s := NewRateLimitRuleStore(path)

	rule := sampleRLRule()
	created, err := s.Create(rule)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Reload from disk.
	s2 := NewRateLimitRuleStore(path)
	rules := s2.List()
	if len(rules) != 1 {
		t.Fatalf("want 1 rule after reload, got %d", len(rules))
	}
	if rules[0].ID != created.ID {
		t.Errorf("want ID %q, got %q", created.ID, rules[0].ID)
	}
	if rules[0].Name != "api-limit" {
		t.Errorf("want name %q, got %q", "api-limit", rules[0].Name)
	}
}

// ─── CRUD Operations ────────────────────────────────────────────────

func TestRLRuleStoreCreate(t *testing.T) {
	s := newTestRLRuleStore(t)
	rule := sampleRLRule()

	created, err := s.Create(rule)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("created rule should have an ID")
	}
	if created.CreatedAt.IsZero() {
		t.Error("created_at should be set")
	}
	if created.UpdatedAt.IsZero() {
		t.Error("updated_at should be set")
	}
	if len(s.List()) != 1 {
		t.Fatalf("want 1 rule, got %d", len(s.List()))
	}
}

func TestRLRuleStoreGet(t *testing.T) {
	s := newTestRLRuleStore(t)
	created, _ := s.Create(sampleRLRule())

	got := s.Get(created.ID)
	if got == nil {
		t.Fatal("Get should find the rule")
	}
	if got.Name != "api-limit" {
		t.Errorf("want name %q, got %q", "api-limit", got.Name)
	}

	// Not found.
	if s.Get("nonexistent") != nil {
		t.Error("Get with bad ID should return nil")
	}
}

func TestRLRuleStoreUpdate(t *testing.T) {
	s := newTestRLRuleStore(t)
	created, _ := s.Create(sampleRLRule())

	updated := created
	updated.Name = "renamed"
	updated.Events = 500
	result, found, err := s.Update(created.ID, updated)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !found {
		t.Fatal("Update should find the rule")
	}
	if result.Name != "renamed" {
		t.Errorf("want name %q, got %q", "renamed", result.Name)
	}
	if result.Events != 500 {
		t.Errorf("want events 500, got %d", result.Events)
	}
	// ID and CreatedAt should be preserved.
	if result.ID != created.ID {
		t.Errorf("ID should be preserved: want %q, got %q", created.ID, result.ID)
	}
	if result.CreatedAt != created.CreatedAt {
		t.Error("created_at should be preserved")
	}
	if !result.UpdatedAt.After(created.UpdatedAt) {
		t.Error("updated_at should advance")
	}

	// Update nonexistent.
	_, found, err = s.Update("nonexistent", updated)
	if err != nil {
		t.Fatalf("Update nonexistent: %v", err)
	}
	if found {
		t.Error("Update should not find nonexistent ID")
	}
}

func TestRLRuleStoreDelete(t *testing.T) {
	s := newTestRLRuleStore(t)
	created, _ := s.Create(sampleRLRule())

	found, err := s.Delete(created.ID)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !found {
		t.Fatal("Delete should find the rule")
	}
	if len(s.List()) != 0 {
		t.Fatalf("want 0 rules after delete, got %d", len(s.List()))
	}

	// Delete nonexistent.
	found, err = s.Delete("nonexistent")
	if err != nil {
		t.Fatalf("Delete nonexistent: %v", err)
	}
	if found {
		t.Error("Delete should not find nonexistent ID")
	}
}

// ─── Queries ────────────────────────────────────────────────────────

func TestRLRuleStoreEnabledRules(t *testing.T) {
	s := newTestRLRuleStore(t)

	r1 := sampleRLRule()
	r1.Enabled = true
	r1.Priority = 10
	s.Create(r1)

	r2 := sampleRLRule()
	r2.Name = "disabled-rule"
	r2.Enabled = false
	s.Create(r2)

	r3 := sampleRLRule()
	r3.Name = "high-priority"
	r3.Enabled = true
	r3.Priority = 1
	s.Create(r3)

	enabled := s.EnabledRules()
	if len(enabled) != 2 {
		t.Fatalf("want 2 enabled rules, got %d", len(enabled))
	}
	// Should be sorted by priority: 1 before 10.
	if enabled[0].Name != "high-priority" {
		t.Errorf("want first rule %q, got %q", "high-priority", enabled[0].Name)
	}
	if enabled[1].Name != "api-limit" {
		t.Errorf("want second rule %q, got %q", "api-limit", enabled[1].Name)
	}
}

func TestRLRuleStoreListByService(t *testing.T) {
	s := newTestRLRuleStore(t)

	r1 := sampleRLRule()
	r1.Service = "sonarr.erfi.io"
	s.Create(r1)

	r2 := sampleRLRule()
	r2.Name = "radarr-limit"
	r2.Service = "radarr.erfi.io"
	s.Create(r2)

	r3 := sampleRLRule()
	r3.Name = "global-limit"
	r3.Service = "*"
	s.Create(r3)

	sonarr := s.ListByService("sonarr.erfi.io")
	if len(sonarr) != 2 { // sonarr + wildcard
		t.Fatalf("want 2 rules for sonarr, got %d", len(sonarr))
	}

	radarr := s.ListByService("radarr.erfi.io")
	if len(radarr) != 2 { // radarr + wildcard
		t.Fatalf("want 2 rules for radarr, got %d", len(radarr))
	}

	unknown := s.ListByService("unknown.io")
	if len(unknown) != 1 { // wildcard only
		t.Fatalf("want 1 rule for unknown service, got %d", len(unknown))
	}
}

// ─── Global Config ──────────────────────────────────────────────────

func TestRLRuleStoreGlobalConfig(t *testing.T) {
	s := newTestRLRuleStore(t)

	// Starts with zero-value global config.
	g := s.GetGlobal()
	if g.Distributed {
		t.Error("distributed should default to false")
	}

	// Update.
	newGlobal := RateLimitGlobalConfig{
		Jitter:        0.5,
		SweepInterval: "30s",
		Distributed:   true,
		ReadInterval:  "5s",
		WriteInterval: "5s",
		PurgeAge:      "1m",
	}
	if err := s.UpdateGlobal(newGlobal); err != nil {
		t.Fatalf("UpdateGlobal: %v", err)
	}

	got := s.GetGlobal()
	if got.Jitter != 0.5 {
		t.Errorf("want jitter 0.5, got %f", got.Jitter)
	}
	if !got.Distributed {
		t.Error("want distributed true")
	}
	if got.ReadInterval != "5s" {
		t.Errorf("want read_interval 5s, got %q", got.ReadInterval)
	}
}

func TestRLRuleStoreGlobalPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rl-rules.json")
	s := NewRateLimitRuleStore(path)
	s.UpdateGlobal(RateLimitGlobalConfig{Jitter: 0.8, Distributed: true})

	s2 := NewRateLimitRuleStore(path)
	g := s2.GetGlobal()
	if g.Jitter != 0.8 {
		t.Errorf("want jitter 0.8 after reload, got %f", g.Jitter)
	}
	if !g.Distributed {
		t.Error("want distributed true after reload")
	}
}

// ─── Import / Export ────────────────────────────────────────────────

func TestRLRuleStoreExport(t *testing.T) {
	s := newTestRLRuleStore(t)
	s.Create(sampleRLRule())

	exp := s.Export()
	if exp.Version != 1 {
		t.Errorf("want version 1, got %d", exp.Version)
	}
	if len(exp.Rules) != 1 {
		t.Fatalf("want 1 rule in export, got %d", len(exp.Rules))
	}
	if exp.ExportedAt.IsZero() {
		t.Error("exported_at should be set")
	}
}

func TestRLRuleStoreImport(t *testing.T) {
	s := newTestRLRuleStore(t)
	s.Create(sampleRLRule())
	s.Create(sampleRLRule())

	// Import replaces all rules.
	imported := []RateLimitRule{
		{Name: "new-rule", Service: "test.io", Key: "client_ip", Events: 50, Window: "30s", Enabled: true},
	}
	if err := s.Import(imported); err != nil {
		t.Fatalf("Import: %v", err)
	}

	rules := s.List()
	if len(rules) != 1 {
		t.Fatalf("want 1 rule after import, got %d", len(rules))
	}
	if rules[0].Name != "new-rule" {
		t.Errorf("want name %q, got %q", "new-rule", rules[0].Name)
	}
	// IDs should be reassigned.
	if rules[0].ID == "" {
		t.Error("imported rule should have a new ID")
	}
}

func TestRLRuleStoreReorder(t *testing.T) {
	s := newTestRLRuleStore(t)
	a, _ := s.Create(RateLimitRule{Name: "A", Service: "s.io", Key: "client_ip", Events: 10, Window: "1m", Enabled: true, Priority: 99})
	b, _ := s.Create(RateLimitRule{Name: "B", Service: "s.io", Key: "client_ip", Events: 20, Window: "1m", Enabled: true, Priority: 50})
	c, _ := s.Create(RateLimitRule{Name: "C", Service: "s.io", Key: "client_ip", Events: 30, Window: "1m", Enabled: true, Priority: 10})

	// Reorder: C, A, B — priorities should become 0, 1, 2.
	if err := s.Reorder([]string{c.ID, a.ID, b.ID}); err != nil {
		t.Fatalf("reorder: %v", err)
	}
	rules := s.List()
	if rules[0].Name != "C" || rules[1].Name != "A" || rules[2].Name != "B" {
		t.Errorf("want C,A,B got %s,%s,%s", rules[0].Name, rules[1].Name, rules[2].Name)
	}
	if rules[0].Priority != 0 || rules[1].Priority != 1 || rules[2].Priority != 2 {
		t.Errorf("priorities: want 0,1,2 got %d,%d,%d", rules[0].Priority, rules[1].Priority, rules[2].Priority)
	}

	// Verify persistence.
	s2 := NewRateLimitRuleStore(s.filePath)
	list2 := s2.List()
	if list2[0].Name != "C" || list2[1].Name != "A" || list2[2].Name != "B" {
		t.Errorf("after reload: want C,A,B got %s,%s,%s", list2[0].Name, list2[1].Name, list2[2].Name)
	}
}

func TestRLRuleStoreReorderErrors(t *testing.T) {
	s := newTestRLRuleStore(t)
	a, _ := s.Create(sampleRLRule())
	s.Create(sampleRLRule())

	if err := s.Reorder([]string{a.ID}); err == nil {
		t.Error("expected error for wrong ID count")
	}
	if err := s.Reorder([]string{a.ID, "bogus"}); err == nil {
		t.Error("expected error for unknown ID")
	}
	if err := s.Reorder([]string{a.ID, a.ID}); err == nil {
		t.Error("expected error for duplicate ID")
	}
}

// ─── V1 Migration ───────────────────────────────────────────────────

func TestRLRuleStoreMigrateFromV1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rl.json")

	// Write legacy format.
	legacy := map[string]any{
		"zones": []map[string]any{
			{"name": "sonarr", "events": 300, "window": "1m", "enabled": true},
			{"name": "radarr", "events": 200, "window": "30s", "enabled": false},
		},
	}
	data, _ := json.Marshal(legacy)
	os.WriteFile(path, data, 0644)

	// Load triggers migration.
	s := NewRateLimitRuleStore(path)
	rules := s.List()
	if len(rules) != 2 {
		t.Fatalf("want 2 migrated rules, got %d", len(rules))
	}

	// Check first rule.
	if rules[0].Name != "sonarr" {
		t.Errorf("want name %q, got %q", "sonarr", rules[0].Name)
	}
	if rules[0].Service != "sonarr" {
		t.Errorf("want service %q, got %q", "sonarr", rules[0].Service)
	}
	if rules[0].Key != "client_ip" {
		t.Errorf("want key %q, got %q", "client_ip", rules[0].Key)
	}
	if rules[0].Events != 300 {
		t.Errorf("want events 300, got %d", rules[0].Events)
	}
	if rules[0].Enabled != true {
		t.Error("want first rule enabled")
	}

	// Check second rule.
	if rules[1].Enabled != false {
		t.Error("want second rule disabled (preserved from legacy)")
	}

	// Backup file should exist.
	backupPath := path + ".v1.bak"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("backup file should exist after migration")
	}
}

func TestRLRuleStoreMigrateFromV1Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rl.json")

	// Write legacy format with empty zones.
	data := []byte(`{"zones":[]}`)
	os.WriteFile(path, data, 0644)

	s := NewRateLimitRuleStore(path)
	rules := s.List()
	if len(rules) != 0 {
		t.Fatalf("want 0 rules from empty legacy, got %d", len(rules))
	}
}

// ─── Caddyfile Auto-Discovery ───────────────────────────────────────

func TestScanCaddyfileServices(t *testing.T) {
	dir := t.TempDir()
	caddyfile := filepath.Join(dir, "Caddyfile")

	content := `sonarr.erfi.io {
	import /data/caddy/rl/sonarr_rl*.caddy
}

radarr.erfi.io {
	import /data/caddy/rl/radarr_rl*.caddy
}

prowlarr.erfi.io {
	# no rate limit import
}`
	os.WriteFile(caddyfile, []byte(content), 0644)

	services := scanCaddyfileServices(caddyfile)
	if len(services) != 2 {
		t.Fatalf("want 2 services, got %d: %v", len(services), services)
	}

	// Check both are present (order may vary).
	found := make(map[string]bool)
	for _, s := range services {
		found[s] = true
	}
	if !found["sonarr"] {
		t.Error("want sonarr in discovered services")
	}
	if !found["radarr"] {
		t.Error("want radarr in discovered services")
	}
}

func TestScanCaddyfileServicesNonexistent(t *testing.T) {
	services := scanCaddyfileServices("/nonexistent/Caddyfile")
	if len(services) != 0 {
		t.Fatalf("want 0 services from nonexistent file, got %d", len(services))
	}
}

func TestScanCaddyfileServicesNoGlobs(t *testing.T) {
	dir := t.TempDir()
	caddyfile := filepath.Join(dir, "Caddyfile")
	os.WriteFile(caddyfile, []byte("sonarr.erfi.io {\n}\n"), 0644)

	services := scanCaddyfileServices(caddyfile)
	if len(services) != 0 {
		t.Fatalf("want 0 services from Caddyfile without RL globs, got %d", len(services))
	}
}

func TestMergeCaddyfileServices(t *testing.T) {
	dir := t.TempDir()
	caddyfile := filepath.Join(dir, "Caddyfile")
	content := "sonarr.erfi.io {\n\timport /data/caddy/rl/sonarr_rl*.caddy\n}\n" +
		"radarr.erfi.io {\n\timport /data/caddy/rl/radarr_rl*.caddy\n}\n"
	os.WriteFile(caddyfile, []byte(content), 0644)

	s := newTestRLRuleStore(t)

	// Pre-add sonarr — only radarr should be added.
	s.Create(RateLimitRule{
		Name: "existing", Service: "sonarr", Key: "client_ip",
		Events: 100, Window: "1m", Enabled: true,
	})

	added := s.MergeCaddyfileServices(caddyfile)
	if added != 1 {
		t.Fatalf("want 1 added, got %d", added)
	}

	rules := s.List()
	if len(rules) != 2 {
		t.Fatalf("want 2 total rules, got %d", len(rules))
	}

	// The new one should be radarr with defaults.
	var radarrRule *RateLimitRule
	for _, r := range rules {
		if r.Service == "radarr" {
			cp := r
			radarrRule = &cp
		}
	}
	if radarrRule == nil {
		t.Fatal("radarr rule should have been created")
	}
	if radarrRule.Events != defaultRLEvents {
		t.Errorf("want default events %d, got %d", defaultRLEvents, radarrRule.Events)
	}
	if radarrRule.Window != defaultRLWindow {
		t.Errorf("want default window %q, got %q", defaultRLWindow, radarrRule.Window)
	}
}

func TestMergeCaddyfileServicesIdempotent(t *testing.T) {
	dir := t.TempDir()
	caddyfile := filepath.Join(dir, "Caddyfile")
	content := "sonarr.erfi.io {\n\timport /data/caddy/rl/sonarr_rl*.caddy\n}\n"
	os.WriteFile(caddyfile, []byte(content), 0644)

	s := newTestRLRuleStore(t)

	added1 := s.MergeCaddyfileServices(caddyfile)
	if added1 != 1 {
		t.Fatalf("first merge: want 1, got %d", added1)
	}

	added2 := s.MergeCaddyfileServices(caddyfile)
	if added2 != 0 {
		t.Fatalf("second merge should be 0, got %d", added2)
	}
}

func TestMergeCaddyfileServicesEmptyPath(t *testing.T) {
	s := newTestRLRuleStore(t)
	added := s.MergeCaddyfileServices("")
	if added != 0 {
		t.Fatalf("want 0 from empty path, got %d", added)
	}
}

// ─── Validation ─────────────────────────────────────────────────────

func TestValidateRateLimitRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    RateLimitRule
		wantErr bool
	}{
		{
			name:    "valid basic rule",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip", Events: 100, Window: "1m"},
			wantErr: false,
		},
		{
			name:    "valid with header key",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "header:X-API-Key", Events: 100, Window: "1m"},
			wantErr: false,
		},
		{
			name:    "valid with cookie key",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "cookie:session", Events: 100, Window: "1m"},
			wantErr: false,
		},
		{
			name:    "valid with composite key",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip+path", Events: 100, Window: "1m"},
			wantErr: false,
		},
		{
			name:    "valid with body_json key",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "body_json:.user.api_key", Events: 100, Window: "1m"},
			wantErr: false,
		},
		{
			name:    "valid with body_json key no leading dot",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "body_json:user.role", Events: 100, Window: "1m"},
			wantErr: false,
		},
		{
			name:    "valid with body_form key",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "body_form:action", Events: 100, Window: "1m"},
			wantErr: false,
		},
		{
			name:    "valid log_only action",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip", Events: 100, Window: "1m", Action: "log_only"},
			wantErr: false,
		},
		{
			name:    "empty name",
			rule:    RateLimitRule{Service: "s", Key: "client_ip", Events: 100, Window: "1m"},
			wantErr: true,
		},
		{
			name:    "newline in name",
			rule:    RateLimitRule{Name: "test\n", Service: "s", Key: "client_ip", Events: 100, Window: "1m"},
			wantErr: true,
		},
		{
			name:    "empty service",
			rule:    RateLimitRule{Name: "test", Key: "client_ip", Events: 100, Window: "1m"},
			wantErr: true,
		},
		{
			name:    "empty key",
			rule:    RateLimitRule{Name: "test", Service: "s", Events: 100, Window: "1m"},
			wantErr: true,
		},
		{
			name:    "invalid key",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "bad_key", Events: 100, Window: "1m"},
			wantErr: true,
		},
		{
			name:    "zero events",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip", Events: 0, Window: "1m"},
			wantErr: true,
		},
		{
			name:    "events too high",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip", Events: 100001, Window: "1m"},
			wantErr: true,
		},
		{
			name:    "empty window",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip", Events: 100},
			wantErr: true,
		},
		{
			name:    "invalid window format",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip", Events: 100, Window: "5min"},
			wantErr: true,
		},
		{
			name:    "invalid action",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip", Events: 100, Window: "1m", Action: "drop"},
			wantErr: true,
		},
		{
			name:    "priority too high",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip", Events: 100, Window: "1m", Priority: 1000},
			wantErr: true,
		},
		{
			name:    "negative priority",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip", Events: 100, Window: "1m", Priority: -1},
			wantErr: true,
		},
		{
			name:    "invalid group operator",
			rule:    RateLimitRule{Name: "test", Service: "s", Key: "client_ip", Events: 100, Window: "1m", GroupOp: "xor"},
			wantErr: true,
		},
		{
			name: "valid with conditions",
			rule: RateLimitRule{
				Name: "test", Service: "s", Key: "client_ip", Events: 100, Window: "1m",
				Conditions: []Condition{{Field: "path", Operator: "begins_with", Value: "/api"}},
			},
			wantErr: false,
		},
		{
			name: "invalid condition field (response_header not allowed for RL)",
			rule: RateLimitRule{
				Name: "test", Service: "s", Key: "client_ip", Events: 100, Window: "1m",
				Conditions: []Condition{{Field: "response_header", Operator: "eq", Value: "X-Test:val"}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRateLimitRule(tt.rule)
			if tt.wantErr && err == nil {
				t.Error("want error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("want no error, got: %v", err)
			}
		})
	}
}

func TestValidateRateLimitGlobal(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RateLimitGlobalConfig
		wantErr bool
	}{
		{
			name:    "zero value (valid)",
			cfg:     RateLimitGlobalConfig{},
			wantErr: false,
		},
		{
			name:    "valid full config",
			cfg:     RateLimitGlobalConfig{Jitter: 0.5, SweepInterval: "1m", Distributed: true, ReadInterval: "5s", WriteInterval: "5s", PurgeAge: "1m"},
			wantErr: false,
		},
		{
			name:    "jitter too high",
			cfg:     RateLimitGlobalConfig{Jitter: 1.5},
			wantErr: true,
		},
		{
			name:    "negative jitter",
			cfg:     RateLimitGlobalConfig{Jitter: -0.1},
			wantErr: true,
		},
		{
			name:    "invalid sweep_interval",
			cfg:     RateLimitGlobalConfig{SweepInterval: "5min"},
			wantErr: true,
		},
		{
			name:    "invalid read_interval",
			cfg:     RateLimitGlobalConfig{ReadInterval: "fast"},
			wantErr: true,
		},
		{
			name:    "invalid write_interval",
			cfg:     RateLimitGlobalConfig{WriteInterval: "xyz"},
			wantErr: true,
		},
		{
			name:    "invalid purge_age",
			cfg:     RateLimitGlobalConfig{PurgeAge: "tomorrow"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRateLimitGlobal(tt.cfg)
			if tt.wantErr && err == nil {
				t.Error("want error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("want no error, got: %v", err)
			}
		})
	}
}

// ─── Deep Copy Guarantee ────────────────────────────────────────────

func TestRLRuleStoreListDeepCopy(t *testing.T) {
	s := newTestRLRuleStore(t)
	s.Create(sampleRLRule())

	list := s.List()
	list[0].Name = "mutated"

	// Original should be unchanged.
	if s.List()[0].Name == "mutated" {
		t.Error("List should return deep copies; mutation leaked through")
	}
}

func TestRLRuleStoreGetDeepCopy(t *testing.T) {
	s := newTestRLRuleStore(t)
	created, _ := s.Create(sampleRLRule())

	got := s.Get(created.ID)
	got.Name = "mutated"

	// Original should be unchanged.
	if s.Get(created.ID).Name == "mutated" {
		t.Error("Get should return deep copies; mutation leaked through")
	}
}

// ─── generateOnBoot Integration ─────────────────────────────────────

func TestGenerateOnBootMergesCaddyfileServices(t *testing.T) {
	// Set up a Caddyfile with an RL import.
	dir := t.TempDir()
	caddyfile := filepath.Join(dir, "Caddyfile")
	os.WriteFile(caddyfile, []byte("sonarr.erfi.io {\n\timport /data/caddy/rl/sonarr_rl*.caddy\n}\n"), 0644)

	corazaDir := filepath.Join(dir, "coraza")
	os.MkdirAll(corazaDir, 0755)
	rlDir := filepath.Join(dir, "rl")
	os.MkdirAll(rlDir, 0755)
	cspDir := filepath.Join(dir, "csp")
	os.MkdirAll(cspDir, 0755)

	cs := NewConfigStore(filepath.Join(dir, "config.json"))
	es := NewExclusionStore(filepath.Join(dir, "excl.json"))
	rs := NewRateLimitRuleStore(filepath.Join(dir, "rl.json"))
	cspS := NewCSPStore(filepath.Join(dir, "csp.json"))

	deployCfg := DeployConfig{
		CorazaDir:     corazaDir,
		RateLimitDir:  rlDir,
		CSPDir:        cspDir,
		CaddyfilePath: caddyfile,
	}

	generateOnBoot(cs, es, rs, cspS, deployCfg)

	// The sonarr service should be auto-discovered.
	rules := rs.List()
	if len(rules) != 1 {
		t.Fatalf("want 1 rule from Caddyfile discovery, got %d", len(rules))
	}
	if rules[0].Service != "sonarr" {
		t.Errorf("want service %q, got %q", "sonarr", rules[0].Service)
	}

	// RL file should exist.
	entries, _ := os.ReadDir(rlDir)
	if len(entries) == 0 {
		t.Error("want at least one RL file in the RL dir")
	}
}

// ─── ensureRateLimitDir ─────────────────────────────────────────────

func TestEnsureRateLimitDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "rl")
	if err := ensureRateLimitDir(dir); err != nil {
		t.Fatalf("ensureRateLimitDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("dir should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("should be a directory")
	}
}
