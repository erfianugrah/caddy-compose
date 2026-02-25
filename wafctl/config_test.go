package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func TestConfigStoreDefaults(t *testing.T) {
	cs := newTestConfigStore(t)
	cfg := cs.Get()
	expected := defaultConfig()

	if cfg.Defaults.ParanoiaLevel != expected.Defaults.ParanoiaLevel {
		t.Errorf("default paranoia: want %d, got %d", expected.Defaults.ParanoiaLevel, cfg.Defaults.ParanoiaLevel)
	}
	if cfg.Defaults.InboundThreshold != expected.Defaults.InboundThreshold {
		t.Errorf("default inbound: want %d, got %d", expected.Defaults.InboundThreshold, cfg.Defaults.InboundThreshold)
	}
	if cfg.Defaults.OutboundThreshold != expected.Defaults.OutboundThreshold {
		t.Errorf("default outbound: want %d, got %d", expected.Defaults.OutboundThreshold, cfg.Defaults.OutboundThreshold)
	}
	if cfg.Defaults.Mode != expected.Defaults.Mode {
		t.Errorf("default mode: want %s, got %s", expected.Defaults.Mode, cfg.Defaults.Mode)
	}
}



func TestDefaultServiceSettingsMatchesDefaultConfig(t *testing.T) {
	ss := defaultServiceSettings()
	dc := defaultConfig().Defaults

	if ss.Mode != dc.Mode {
		t.Errorf("Mode: defaultServiceSettings()=%s, defaultConfig().Defaults=%s", ss.Mode, dc.Mode)
	}
	if ss.ParanoiaLevel != dc.ParanoiaLevel {
		t.Errorf("ParanoiaLevel: defaultServiceSettings()=%d, defaultConfig().Defaults=%d", ss.ParanoiaLevel, dc.ParanoiaLevel)
	}
	if ss.InboundThreshold != dc.InboundThreshold {
		t.Errorf("InboundThreshold: defaultServiceSettings()=%d, defaultConfig().Defaults=%d", ss.InboundThreshold, dc.InboundThreshold)
	}
	if ss.OutboundThreshold != dc.OutboundThreshold {
		t.Errorf("OutboundThreshold: defaultServiceSettings()=%d, defaultConfig().Defaults=%d", ss.OutboundThreshold, dc.OutboundThreshold)
	}
}



func TestConfigStoreUpdate(t *testing.T) {
	cs := newTestConfigStore(t)

	cfg := WAFConfig{
		Defaults: WAFServiceSettings{
			Mode: "detection_only", ParanoiaLevel: 2, InboundThreshold: 10, OutboundThreshold: 8,
		},
		Services: map[string]WAFServiceSettings{
			"test.erfi.io": {Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}

	updated, err := cs.Update(cfg)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Defaults.ParanoiaLevel != 2 {
		t.Errorf("want paranoia 2, got %d", updated.Defaults.ParanoiaLevel)
	}
}



func TestConfigStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cs1 := NewConfigStore(path)
	cs1.Update(WAFConfig{
		Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 3, InboundThreshold: 7, OutboundThreshold: 6},
		Services: make(map[string]WAFServiceSettings),
	})

	cs2 := NewConfigStore(path)
	cfg := cs2.Get()
	if cfg.Defaults.ParanoiaLevel != 3 {
		t.Errorf("persistence: want paranoia 3, got %d", cfg.Defaults.ParanoiaLevel)
	}
}



func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     WAFConfig
		wantErr bool
	}{
		{
			name: "valid",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: false,
		},
		{
			name: "paranoia too low",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 0, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: true,
		},
		{
			name: "paranoia too high",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 5, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: true,
		},
		{
			name: "invalid mode",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "maybe", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: true,
		},
		{
			name: "invalid rule group tag",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, DisabledGroups: []string{"not-a-real-tag"}},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: true,
		},
		{
			name: "valid with disabled groups",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, DisabledGroups: []string{"attack-sqli", "attack-xss"}},
				Services: map[string]WAFServiceSettings{},
			},
			wantErr: false,
		},
		{
			name: "valid per-service override",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{
					"test.erfi.io": {Mode: "disabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid per-service paranoia",
			cfg: WAFConfig{
				Defaults: WAFServiceSettings{Mode: "enabled", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
				Services: map[string]WAFServiceSettings{
					"test.erfi.io": {Mode: "enabled", ParanoiaLevel: 0, InboundThreshold: 5, OutboundThreshold: 4},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// --- Config HTTP endpoint tests ---



// --- Config HTTP endpoint tests ---

func TestConfigEndpoints(t *testing.T) {
	cs := newTestConfigStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/config", handleGetConfig(cs))
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(cs))

	// GET defaults.
	req := httptest.NewRequest("GET", "/api/config", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("get: want 200, got %d", w.Code)
	}

	var cfg WAFConfig
	json.NewDecoder(w.Body).Decode(&cfg)
	if cfg.Defaults.ParanoiaLevel != 1 {
		t.Errorf("default paranoia: want 1, got %d", cfg.Defaults.ParanoiaLevel)
	}

	// PUT update.
	body := `{"defaults":{"mode":"enabled","paranoia_level":2,"inbound_threshold":10,"outbound_threshold":8},"services":{}}`
	req = httptest.NewRequest("PUT", "/api/config", strings.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("put: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify.
	req = httptest.NewRequest("GET", "/api/config", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	json.NewDecoder(w.Body).Decode(&cfg)
	if cfg.Defaults.ParanoiaLevel != 2 {
		t.Errorf("updated paranoia: want 2, got %d", cfg.Defaults.ParanoiaLevel)
	}
}



func TestConfigEndpointInvalid(t *testing.T) {
	cs := newTestConfigStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(cs))

	body := `{"defaults":{"mode":"enabled","paranoia_level":0,"inbound_threshold":5,"outbound_threshold":4},"services":{}}`
	req := httptest.NewRequest("PUT", "/api/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// --- Generator tests ---



func TestConfigMigrationFromOldFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Write old format config.
	oldConfig := `{"paranoia_level":2,"inbound_threshold":15,"outbound_threshold":15,"rule_engine":"DetectionOnly","services":{"test.erfi.io":{"profile":"strict"},"qbit.erfi.io":{"profile":"off"}}}`
	os.WriteFile(path, []byte(oldConfig), 0644)

	cs := NewConfigStore(path)
	cfg := cs.Get()

	// Check migrated defaults.
	if cfg.Defaults.Mode != "detection_only" {
		t.Errorf("migrated mode: want detection_only, got %s", cfg.Defaults.Mode)
	}
	if cfg.Defaults.ParanoiaLevel != 2 {
		t.Errorf("migrated paranoia: want 2, got %d", cfg.Defaults.ParanoiaLevel)
	}
	if cfg.Defaults.InboundThreshold != 15 {
		t.Errorf("migrated inbound: want 15, got %d", cfg.Defaults.InboundThreshold)
	}

	// Check migrated services.
	if ss, ok := cfg.Services["test.erfi.io"]; !ok {
		t.Error("migrated service test.erfi.io not found")
	} else if ss.Mode != "enabled" {
		t.Errorf("migrated test.erfi.io mode: want enabled, got %s", ss.Mode)
	}
	if ss, ok := cfg.Services["qbit.erfi.io"]; !ok {
		t.Error("migrated service qbit.erfi.io not found")
	} else if ss.Mode != "disabled" {
		t.Errorf("migrated qbit.erfi.io mode: want disabled, got %s", ss.Mode)
	}
}



func TestConfigMigrationFallbacksForInvalidValues(t *testing.T) {
	// Old format is detected by presence of "rule_engine" field in JSON.
	// migrateOldConfig falls back to defaultConfig().Defaults for invalid values.
	defaults := defaultConfig().Defaults

	tests := []struct {
		name    string
		oldJSON string
		wantPL  int
		wantIn  int
		wantOut int
	}{
		{
			name:    "zero paranoia falls back to default",
			oldJSON: `{"paranoia_level":0,"inbound_threshold":10,"outbound_threshold":8,"rule_engine":"On"}`,
			wantPL:  defaults.ParanoiaLevel,
			wantIn:  10,
			wantOut: 8,
		},
		{
			name:    "paranoia too high falls back to default",
			oldJSON: `{"paranoia_level":5,"inbound_threshold":10,"outbound_threshold":8,"rule_engine":"On"}`,
			wantPL:  defaults.ParanoiaLevel,
			wantIn:  10,
			wantOut: 8,
		},
		{
			name:    "zero thresholds fall back to defaults",
			oldJSON: `{"paranoia_level":2,"inbound_threshold":0,"outbound_threshold":0,"rule_engine":"On"}`,
			wantPL:  2,
			wantIn:  defaults.InboundThreshold,
			wantOut: defaults.OutboundThreshold,
		},
		{
			name:    "all invalid falls back to all defaults",
			oldJSON: `{"paranoia_level":0,"inbound_threshold":0,"outbound_threshold":0,"rule_engine":"On"}`,
			wantPL:  defaults.ParanoiaLevel,
			wantIn:  defaults.InboundThreshold,
			wantOut: defaults.OutboundThreshold,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			os.WriteFile(path, []byte(tt.oldJSON), 0644)

			cs := NewConfigStore(path)
			cfg := cs.Get()

			if cfg.Defaults.ParanoiaLevel != tt.wantPL {
				t.Errorf("paranoia: want %d, got %d", tt.wantPL, cfg.Defaults.ParanoiaLevel)
			}
			if cfg.Defaults.InboundThreshold != tt.wantIn {
				t.Errorf("inbound: want %d, got %d", tt.wantIn, cfg.Defaults.InboundThreshold)
			}
			if cfg.Defaults.OutboundThreshold != tt.wantOut {
				t.Errorf("outbound: want %d, got %d", tt.wantOut, cfg.Defaults.OutboundThreshold)
			}
		})
	}
}

// --- Generate config endpoint test ---
