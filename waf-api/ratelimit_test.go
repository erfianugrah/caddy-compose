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

// --- Rate Limit Store tests ---

func TestRateLimitStoreStartsEmpty(t *testing.T) {
	s := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))
	cfg := s.Get()

	if len(cfg.Zones) != 0 {
		t.Fatalf("expected 0 zones for fresh store, got %d", len(cfg.Zones))
	}

	// Non-existent zone
	if s.GetZone("nonexistent") != nil {
		t.Error("expected nil for nonexistent zone")
	}
}

func TestRateLimitStoreUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rl.json")
	s := NewRateLimitStore(path)

	newCfg := RateLimitConfig{
		Zones: []RateLimitZone{
			{Name: "test", Events: 500, Window: "5m", Enabled: true},
		},
	}
	updated, err := s.Update(newCfg)
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if len(updated.Zones) != 1 || updated.Zones[0].Name != "test" {
		t.Fatalf("unexpected update result: %+v", updated)
	}

	// Reload from disk
	s2 := NewRateLimitStore(path)
	cfg := s2.Get()
	if len(cfg.Zones) != 1 || cfg.Zones[0].Events != 500 {
		t.Errorf("persisted data mismatch: %+v", cfg)
	}
}

func TestRateLimitValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RateLimitConfig
		wantErr bool
	}{
		{
			name:    "valid",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test", Events: 100, Window: "1m", Enabled: true}}},
			wantErr: false,
		},
		{
			name:    "empty zones",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{}},
			wantErr: false,
		},
		{
			name:    "empty name",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "", Events: 100, Window: "1m"}}},
			wantErr: true,
		},
		{
			name:    "invalid name chars",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test zone", Events: 100, Window: "1m"}}},
			wantErr: true,
		},
		{
			name:    "duplicate names",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "a", Events: 100, Window: "1m"}, {Name: "a", Events: 200, Window: "1m"}}},
			wantErr: true,
		},
		{
			name:    "zero events",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test", Events: 0, Window: "1m"}}},
			wantErr: true,
		},
		{
			name:    "events too high",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test", Events: 200000, Window: "1m"}}},
			wantErr: true,
		},
		{
			name:    "empty window",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test", Events: 100, Window: ""}}},
			wantErr: true,
		},
		{
			name:    "invalid window",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "test", Events: 100, Window: "abc"}}},
			wantErr: true,
		},
		{
			name:    "valid windows",
			cfg:     RateLimitConfig{Zones: []RateLimitZone{{Name: "a", Events: 100, Window: "30s"}, {Name: "b", Events: 100, Window: "5m"}, {Name: "c", Events: 100, Window: "1h"}}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRateLimitConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRateLimitConfig() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateZoneFile(t *testing.T) {
	t.Run("enabled zone", func(t *testing.T) {
		zone := RateLimitZone{Name: "sonarr", Events: 300, Window: "1m", Enabled: true}
		content := generateZoneFile(zone)

		if !strings.Contains(content, "zone sonarr") {
			t.Error("expected zone name in output")
		}
		if !strings.Contains(content, "events 300") {
			t.Error("expected events 300")
		}
		if !strings.Contains(content, "window 1m") {
			t.Error("expected window 1m")
		}
		if !strings.Contains(content, "rate_limit {") {
			t.Error("expected rate_limit directive")
		}
		if !strings.Contains(content, "not header Connection *Upgrade*") {
			t.Error("expected WebSocket exclusion")
		}
		if !strings.Contains(content, `X-RateLimit-Limit "300"`) {
			t.Error("expected X-RateLimit-Limit header")
		}
	})

	t.Run("disabled zone", func(t *testing.T) {
		zone := RateLimitZone{Name: "test", Events: 100, Window: "1m", Enabled: false}
		content := generateZoneFile(zone)

		if strings.Contains(content, "rate_limit {") {
			t.Error("disabled zone should not contain rate_limit directive")
		}
		if !strings.Contains(content, "Rate limiting disabled") {
			t.Error("expected disabled comment")
		}
	})
}

func TestWriteZoneFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rl")

	zones := []RateLimitZone{
		{Name: "test1", Events: 100, Window: "1m", Enabled: true},
		{Name: "test2", Events: 500, Window: "5m", Enabled: false},
	}

	written, err := writeZoneFiles(dir, zones)
	if err != nil {
		t.Fatalf("writeZoneFiles failed: %v", err)
	}
	if len(written) != 2 {
		t.Fatalf("expected 2 files written, got %d", len(written))
	}

	// Check file 1 exists and has content (uses _rl suffix)
	data1, err := os.ReadFile(filepath.Join(dir, "test1_rl.caddy"))
	if err != nil {
		t.Fatalf("reading test1_rl.caddy: %v", err)
	}
	if !strings.Contains(string(data1), "events 100") {
		t.Error("test1_rl.caddy missing events")
	}

	// Check file 2 is disabled
	data2, err := os.ReadFile(filepath.Join(dir, "test2_rl.caddy"))
	if err != nil {
		t.Fatalf("reading test2_rl.caddy: %v", err)
	}
	if strings.Contains(string(data2), "rate_limit") {
		t.Error("test2_rl.caddy should be disabled (no rate_limit)")
	}
}

func TestScanCaddyfileZones(t *testing.T) {
	t.Run("extracts zone prefixes from import globs", func(t *testing.T) {
		caddyfile := filepath.Join(t.TempDir(), "Caddyfile")
		content := `
example.com {
	import /data/caddy/rl/sonarr_rl*.caddy
	import /data/caddy/rl/caddy_rl*.caddy
	import /data/caddy/rl/caddy-prometheus_rl*.caddy
	reverse_proxy localhost:8080
}
`
		os.WriteFile(caddyfile, []byte(content), 0644)

		prefixes := scanCaddyfileZones(caddyfile)
		if len(prefixes) != 3 {
			t.Fatalf("expected 3 prefixes, got %d: %v", len(prefixes), prefixes)
		}

		expected := map[string]bool{"sonarr_rl": true, "caddy_rl": true, "caddy-prometheus_rl": true}
		for _, p := range prefixes {
			if !expected[p] {
				t.Errorf("unexpected prefix: %q", p)
			}
		}
	})

	t.Run("deduplicates repeated zones", func(t *testing.T) {
		caddyfile := filepath.Join(t.TempDir(), "Caddyfile")
		content := `
site1.com { import /data/caddy/rl/test_rl*.caddy }
site2.com { import /data/caddy/rl/test_rl*.caddy }
`
		os.WriteFile(caddyfile, []byte(content), 0644)

		prefixes := scanCaddyfileZones(caddyfile)
		if len(prefixes) != 1 {
			t.Fatalf("expected 1 prefix after dedup, got %d: %v", len(prefixes), prefixes)
		}
	})

	t.Run("returns nil for missing caddyfile", func(t *testing.T) {
		prefixes := scanCaddyfileZones("/nonexistent/Caddyfile")
		if prefixes != nil {
			t.Errorf("expected nil for missing file, got %v", prefixes)
		}
	})

	t.Run("returns empty for caddyfile without rl imports", func(t *testing.T) {
		caddyfile := filepath.Join(t.TempDir(), "Caddyfile")
		os.WriteFile(caddyfile, []byte("localhost:80 { respond ok }"), 0644)

		prefixes := scanCaddyfileZones(caddyfile)
		if len(prefixes) != 0 {
			t.Errorf("expected 0 prefixes, got %d: %v", len(prefixes), prefixes)
		}
	})
}

func TestMergeCaddyfileZones(t *testing.T) {
	t.Run("discovers zones from Caddyfile", func(t *testing.T) {
		caddyfile := filepath.Join(t.TempDir(), "Caddyfile")
		content := `
sonarr.example.com {
	import /data/caddy/rl/sonarr_rl*.caddy
}
tracearr.example.com {
	import /data/caddy/rl/tracearr_rl*.caddy
}
radarr.example.com {
	import /data/caddy/rl/radarr_rl*.caddy
}
`
		os.WriteFile(caddyfile, []byte(content), 0644)

		s := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))
		added := s.MergeCaddyfileZones(caddyfile)
		if added != 3 {
			t.Fatalf("expected 3 added, got %d", added)
		}

		cfg := s.Get()
		if len(cfg.Zones) != 3 {
			t.Fatalf("expected 3 zones, got %d", len(cfg.Zones))
		}

		for _, name := range []string{"sonarr", "tracearr", "radarr"} {
			z := s.GetZone(name)
			if z == nil {
				t.Fatalf("zone %q not found", name)
			}
			if z.Events != defaultZoneEvents || z.Window != defaultZoneWindow || !z.Enabled {
				t.Errorf("zone %q: unexpected defaults events=%d window=%s enabled=%v", name, z.Events, z.Window, z.Enabled)
			}
		}
	})

	t.Run("skips zones already in store", func(t *testing.T) {
		caddyfile := filepath.Join(t.TempDir(), "Caddyfile")
		content := `
sonarr.example.com { import /data/caddy/rl/sonarr_rl*.caddy }
tracearr.example.com { import /data/caddy/rl/tracearr_rl*.caddy }
`
		os.WriteFile(caddyfile, []byte(content), 0644)

		path := filepath.Join(t.TempDir(), "rl.json")
		s := NewRateLimitStore(path)
		// Pre-configure sonarr with custom settings.
		s.Update(RateLimitConfig{
			Zones: []RateLimitZone{
				{Name: "sonarr", Events: 1000, Window: "5m", Enabled: false},
			},
		})

		added := s.MergeCaddyfileZones(caddyfile)
		if added != 1 {
			t.Fatalf("expected 1 added (tracearr only), got %d", added)
		}

		// sonarr should retain its custom settings.
		z := s.GetZone("sonarr")
		if z.Events != 1000 || z.Window != "5m" || z.Enabled {
			t.Errorf("sonarr was overwritten: events=%d window=%s enabled=%v", z.Events, z.Window, z.Enabled)
		}

		// tracearr should have defaults.
		z = s.GetZone("tracearr")
		if z == nil {
			t.Fatal("tracearr not added")
		}
		if z.Events != defaultZoneEvents {
			t.Errorf("tracearr events: got %d, want %d", z.Events, defaultZoneEvents)
		}
	})

	t.Run("persists merged zones to disk", func(t *testing.T) {
		caddyfile := filepath.Join(t.TempDir(), "Caddyfile")
		os.WriteFile(caddyfile, []byte(`site.com { import /data/caddy/rl/newzone_rl*.caddy }`), 0644)

		rlPath := filepath.Join(t.TempDir(), "rl.json")
		s := NewRateLimitStore(rlPath)
		s.MergeCaddyfileZones(caddyfile)

		// Reload from disk and verify.
		s2 := NewRateLimitStore(rlPath)
		z := s2.GetZone("newzone")
		if z == nil {
			t.Fatal("merged zone not persisted to disk")
		}
	})

	t.Run("no-op for empty caddyfile path", func(t *testing.T) {
		s := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))
		added := s.MergeCaddyfileZones("")
		if added != 0 {
			t.Errorf("expected 0 added for empty path, got %d", added)
		}
	})
}

func TestZoneFileName(t *testing.T) {
	tests := []struct {
		zone string
		want string
	}{
		{"sonarr", "sonarr_rl.caddy"},
		{"caddy", "caddy_rl.caddy"},
		{"caddy-prometheus", "caddy-prometheus_rl.caddy"},
	}
	for _, tt := range tests {
		got := zoneFileName(tt.zone)
		if got != tt.want {
			t.Errorf("zoneFileName(%q) = %q, want %q", tt.zone, got, tt.want)
		}
	}
}

func TestGenerateOnBootMergesCaddyfileZones(t *testing.T) {
	// Set up directories and a Caddyfile with zone imports that aren't in the
	// rate limit config. generateOnBoot should discover them via MergeCaddyfileZones
	// and write proper zone files for all of them.
	corazaDir := t.TempDir()
	rlDir := filepath.Join(t.TempDir(), "rl")
	caddyfileDir := t.TempDir()
	caddyfilePath := filepath.Join(caddyfileDir, "Caddyfile")

	// Caddyfile references 3 zones: "sonarr", "tracearr", and "newzone".
	// The rate limit store will only have "sonarr" pre-configured.
	caddyfileContent := `
sonarr.example.com {
	import /data/caddy/rl/sonarr_rl*.caddy
}
tracearr.example.com {
	import /data/caddy/rl/tracearr_rl*.caddy
}
newzone.example.com {
	import /data/caddy/rl/newzone_rl*.caddy
}
`
	os.WriteFile(caddyfilePath, []byte(caddyfileContent), 0644)
	ensureCorazaDir(corazaDir)

	deployCfg := DeployConfig{
		CorazaDir:     corazaDir,
		RateLimitDir:  rlDir,
		CaddyfilePath: caddyfilePath,
		CaddyAdminURL: "http://localhost:1", // not used (no reload on boot)
	}

	es := newTestExclusionStore(t)
	cs := newTestConfigStore(t)
	rs := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))
	// Only "sonarr" zone configured with custom settings.
	rs.Update(RateLimitConfig{
		Zones: []RateLimitZone{
			{Name: "sonarr", Events: 500, Window: "1m", Enabled: true},
		},
	})

	generateOnBoot(cs, es, rs, deployCfg)

	// All 3 zones should now have proper rate_limit zone files.
	for _, zone := range []string{"sonarr", "tracearr", "newzone"} {
		data, err := os.ReadFile(filepath.Join(rlDir, zone+"_rl.caddy"))
		if err != nil {
			t.Fatalf("%s_rl.caddy not created: %v", zone, err)
		}
		if !strings.Contains(string(data), "rate_limit") {
			t.Errorf("%s_rl.caddy should contain rate_limit directive", zone)
		}
	}

	// sonarr should retain its custom events value, not be overwritten.
	z := rs.GetZone("sonarr")
	if z == nil || z.Events != 500 {
		t.Errorf("sonarr should retain custom events=500, got %v", z)
	}

	// tracearr and newzone should have default values.
	for _, name := range []string{"tracearr", "newzone"} {
		z := rs.GetZone(name)
		if z == nil {
			t.Fatalf("zone %q not in store after boot", name)
		}
		if z.Events != defaultZoneEvents {
			t.Errorf("zone %q: expected default events=%d, got %d", name, defaultZoneEvents, z.Events)
		}
	}
}

func TestRateLimitAPIEndpoints(t *testing.T) {
	rs := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rate-limits", handleGetRateLimits(rs))
	mux.HandleFunc("PUT /api/rate-limits", handleUpdateRateLimits(rs))

	// GET — should return defaults
	req := httptest.NewRequest("GET", "/api/rate-limits", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("GET expected 200, got %d", rec.Code)
	}

	var cfg RateLimitConfig
	json.NewDecoder(rec.Body).Decode(&cfg)
	if len(cfg.Zones) != 0 {
		t.Fatalf("expected 0 zones for fresh store, got %d", len(cfg.Zones))
	}

	// PUT — update to single zone
	body := `{"zones":[{"name":"test","events":500,"window":"5m","enabled":true}]}`
	req = httptest.NewRequest("PUT", "/api/rate-limits", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("PUT expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var updated RateLimitConfig
	json.NewDecoder(rec.Body).Decode(&updated)
	if len(updated.Zones) != 1 || updated.Zones[0].Events != 500 {
		t.Errorf("unexpected PUT result: %+v", updated)
	}

	// PUT — validation error (duplicate names)
	body = `{"zones":[{"name":"a","events":100,"window":"1m"},{"name":"a","events":200,"window":"1m"}]}`
	req = httptest.NewRequest("PUT", "/api/rate-limits", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400 for duplicate names, got %d", rec.Code)
	}

	// PUT — validation error (bad window)
	body = `{"zones":[{"name":"x","events":100,"window":"bad"}]}`
	req = httptest.NewRequest("PUT", "/api/rate-limits", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400 for bad window, got %d", rec.Code)
	}
}

func TestRateLimitDeployEndpoint(t *testing.T) {
	rlDir := filepath.Join(t.TempDir(), "rl")
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	os.WriteFile(caddyfilePath, []byte("localhost { respond 200 }"), 0644)

	// Mock Caddy admin API
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer adminServer.Close()

	deployCfg := DeployConfig{
		CorazaDir:     filepath.Join(t.TempDir(), "coraza"),
		RateLimitDir:  rlDir,
		CaddyfilePath: caddyfilePath,
		CaddyAdminURL: adminServer.URL,
	}

	rs := NewRateLimitStore(filepath.Join(t.TempDir(), "rl.json"))
	// Set a small config for testing
	rs.Update(RateLimitConfig{
		Zones: []RateLimitZone{
			{Name: "test", Events: 100, Window: "1m", Enabled: true},
			{Name: "disabled", Events: 50, Window: "30s", Enabled: false},
		},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/rate-limits/deploy", handleDeployRateLimits(rs, deployCfg))

	req := httptest.NewRequest("POST", "/api/rate-limits/deploy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RateLimitDeployResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Status != "deployed" {
		t.Errorf("expected status=deployed, got %q", resp.Status)
	}
	if !resp.Reloaded {
		t.Error("expected reloaded=true")
	}
	if len(resp.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(resp.Files))
	}

	// Verify files exist on disk (uses _rl suffix)
	data, err := os.ReadFile(filepath.Join(rlDir, "test_rl.caddy"))
	if err != nil {
		t.Fatalf("reading test_rl.caddy: %v", err)
	}
	if !strings.Contains(string(data), "events 100") {
		t.Error("test_rl.caddy missing events")
	}

	data, err = os.ReadFile(filepath.Join(rlDir, "disabled_rl.caddy"))
	if err != nil {
		t.Fatalf("reading disabled_rl.caddy: %v", err)
	}
	if strings.Contains(string(data), "rate_limit") {
		t.Error("disabled_rl.caddy should not have rate_limit directive")
	}
}
