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

// ─── buildCSPHeader Tests ───────────────────────────────────────────────────

func TestBuildCSPHeader(t *testing.T) {
	tests := []struct {
		name   string
		policy CSPPolicy
		want   string
	}{
		{
			name:   "empty policy",
			policy: CSPPolicy{},
			want:   "",
		},
		{
			name: "default-src only",
			policy: CSPPolicy{
				DefaultSrc: []string{"'self'"},
			},
			want: "default-src 'self'",
		},
		{
			name: "multiple directives",
			policy: CSPPolicy{
				DefaultSrc: []string{"'self'"},
				ScriptSrc:  []string{"'self'", "'unsafe-inline'"},
				StyleSrc:   []string{"'self'", "'unsafe-inline'"},
				ImgSrc:     []string{"'self'", "data:"},
			},
			want: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
		},
		{
			name: "upgrade-insecure-requests",
			policy: CSPPolicy{
				DefaultSrc:              []string{"'self'"},
				UpgradeInsecureRequests: true,
			},
			want: "default-src 'self'; upgrade-insecure-requests",
		},
		{
			name: "raw directives appended",
			policy: CSPPolicy{
				DefaultSrc:    []string{"'self'"},
				RawDirectives: "report-uri /csp-report",
			},
			want: "default-src 'self'; report-uri /csp-report",
		},
		{
			name: "all directives",
			policy: CSPPolicy{
				DefaultSrc:  []string{"'self'"},
				ScriptSrc:   []string{"'self'"},
				StyleSrc:    []string{"'self'"},
				ImgSrc:      []string{"'self'"},
				FontSrc:     []string{"'self'"},
				ConnectSrc:  []string{"'self'"},
				MediaSrc:    []string{"'self'"},
				FrameSrc:    []string{"'self'"},
				WorkerSrc:   []string{"'self'"},
				ObjectSrc:   []string{"'none'"},
				ChildSrc:    []string{"'self'"},
				ManifestSrc: []string{"'self'"},
				BaseURI:     []string{"'self'"},
				FormAction:  []string{"'self'"},
				FrameAnc:    []string{"'self'"},
			},
			want: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; media-src 'self'; frame-src 'self'; worker-src 'self'; object-src 'none'; child-src 'self'; manifest-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
		},
		{
			name: "only upgrade-insecure-requests",
			policy: CSPPolicy{
				UpgradeInsecureRequests: true,
			},
			want: "upgrade-insecure-requests",
		},
		{
			name: "only raw directives",
			policy: CSPPolicy{
				RawDirectives: "plugin-types application/pdf",
			},
			want: "plugin-types application/pdf",
		},
		{
			name: "raw directives trimmed",
			policy: CSPPolicy{
				DefaultSrc:    []string{"'self'"},
				RawDirectives: "  report-uri /csp-report  ",
			},
			want: "default-src 'self'; report-uri /csp-report",
		},
		{
			name: "multiple values per directive",
			policy: CSPPolicy{
				ConnectSrc: []string{"'self'", "wss:", "https://api.example.com"},
			},
			want: "connect-src 'self' wss: https://api.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCSPHeader(tt.policy)
			if got != tt.want {
				t.Errorf("buildCSPHeader() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ─── mergeCSPPolicy Tests ───────────────────────────────────────────────────

func TestMergeCSPPolicy(t *testing.T) {
	t.Run("override replaces base", func(t *testing.T) {
		base := CSPPolicy{
			DefaultSrc: []string{"'self'"},
			ScriptSrc:  []string{"'self'", "'unsafe-inline'"},
			ImgSrc:     []string{"'self'", "data:"},
		}
		override := CSPPolicy{
			ScriptSrc: []string{"'self'", "'strict-dynamic'"},
		}
		got := mergeCSPPolicy(base, override)

		// ScriptSrc should be replaced.
		if strings.Join(got.ScriptSrc, " ") != "'self' 'strict-dynamic'" {
			t.Errorf("ScriptSrc = %v, want ['self' 'strict-dynamic']", got.ScriptSrc)
		}
		// DefaultSrc should remain from base.
		if strings.Join(got.DefaultSrc, " ") != "'self'" {
			t.Errorf("DefaultSrc = %v, want ['self']", got.DefaultSrc)
		}
		// ImgSrc should remain from base.
		if strings.Join(got.ImgSrc, " ") != "'self' data:" {
			t.Errorf("ImgSrc = %v, want ['self' data:]", got.ImgSrc)
		}
	})

	t.Run("empty override keeps base", func(t *testing.T) {
		base := CSPPolicy{
			DefaultSrc: []string{"'self'"},
			ScriptSrc:  []string{"'self'"},
		}
		override := CSPPolicy{}
		got := mergeCSPPolicy(base, override)

		if strings.Join(got.DefaultSrc, " ") != "'self'" {
			t.Errorf("DefaultSrc = %v, want ['self']", got.DefaultSrc)
		}
		if strings.Join(got.ScriptSrc, " ") != "'self'" {
			t.Errorf("ScriptSrc = %v, want ['self']", got.ScriptSrc)
		}
	})

	t.Run("upgrade-insecure-requests is sticky", func(t *testing.T) {
		base := CSPPolicy{UpgradeInsecureRequests: true}
		override := CSPPolicy{}
		got := mergeCSPPolicy(base, override)
		if !got.UpgradeInsecureRequests {
			t.Error("UpgradeInsecureRequests should be true from base")
		}

		// Override can set it true, but can't turn it off once base has it.
		base2 := CSPPolicy{UpgradeInsecureRequests: false}
		override2 := CSPPolicy{UpgradeInsecureRequests: true}
		got2 := mergeCSPPolicy(base2, override2)
		if !got2.UpgradeInsecureRequests {
			t.Error("UpgradeInsecureRequests should be true from override")
		}
	})

	t.Run("raw directives override", func(t *testing.T) {
		base := CSPPolicy{RawDirectives: "report-uri /old"}
		override := CSPPolicy{RawDirectives: "report-uri /new"}
		got := mergeCSPPolicy(base, override)
		if got.RawDirectives != "report-uri /new" {
			t.Errorf("RawDirectives = %q, want %q", got.RawDirectives, "report-uri /new")
		}
	})

	t.Run("all directives can be overridden", func(t *testing.T) {
		base := CSPPolicy{
			DefaultSrc:  []string{"'self'"},
			ScriptSrc:   []string{"'self'"},
			StyleSrc:    []string{"'self'"},
			ImgSrc:      []string{"'self'"},
			FontSrc:     []string{"'self'"},
			ConnectSrc:  []string{"'self'"},
			MediaSrc:    []string{"'self'"},
			FrameSrc:    []string{"'self'"},
			WorkerSrc:   []string{"'self'"},
			ObjectSrc:   []string{"'none'"},
			ChildSrc:    []string{"'self'"},
			ManifestSrc: []string{"'self'"},
			BaseURI:     []string{"'self'"},
			FormAction:  []string{"'self'"},
			FrameAnc:    []string{"'self'"},
		}
		override := CSPPolicy{
			DefaultSrc:  []string{"'none'"},
			ScriptSrc:   []string{"'none'"},
			StyleSrc:    []string{"'none'"},
			ImgSrc:      []string{"'none'"},
			FontSrc:     []string{"'none'"},
			ConnectSrc:  []string{"'none'"},
			MediaSrc:    []string{"'none'"},
			FrameSrc:    []string{"'none'"},
			WorkerSrc:   []string{"'none'"},
			ObjectSrc:   []string{"'self'"},
			ChildSrc:    []string{"'none'"},
			ManifestSrc: []string{"'none'"},
			BaseURI:     []string{"'none'"},
			FormAction:  []string{"'none'"},
			FrameAnc:    []string{"'none'"},
		}
		got := mergeCSPPolicy(base, override)
		// Every directive should be overridden.
		if strings.Join(got.DefaultSrc, " ") != "'none'" {
			t.Errorf("DefaultSrc not overridden: %v", got.DefaultSrc)
		}
		if strings.Join(got.ObjectSrc, " ") != "'self'" {
			t.Errorf("ObjectSrc not overridden: %v", got.ObjectSrc)
		}
	})
}

// ─── Validation Tests ───────────────────────────────────────────────────────

func TestValidateCSPConfig(t *testing.T) {
	t.Run("valid config passes", func(t *testing.T) {
		cfg := defaultCSPConfig()
		cfg.Services["jellyfin"] = CSPServiceConfig{
			Mode:    "set",
			Inherit: true,
			Policy: CSPPolicy{
				ScriptSrc: []string{"'self'", "'unsafe-inline'", "https://cdn.example.com"},
			},
		}
		if err := validateCSPConfig(cfg); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid mode rejected", func(t *testing.T) {
		cfg := defaultCSPConfig()
		cfg.Services["test"] = CSPServiceConfig{Mode: "invalid"}
		err := validateCSPConfig(cfg)
		if err == nil {
			t.Fatal("expected error for invalid mode")
		}
		if !strings.Contains(err.Error(), "invalid mode") {
			t.Errorf("error should mention 'invalid mode', got: %v", err)
		}
	})

	t.Run("newline in source value rejected", func(t *testing.T) {
		cfg := defaultCSPConfig()
		cfg.GlobalDefaults.ScriptSrc = []string{"'self'\ninjection"}
		err := validateCSPConfig(cfg)
		if err == nil {
			t.Fatal("expected error for newline in source value")
		}
		if !strings.Contains(err.Error(), "invalid characters") {
			t.Errorf("error should mention 'invalid characters', got: %v", err)
		}
	})

	t.Run("semicolon in source value rejected", func(t *testing.T) {
		cfg := defaultCSPConfig()
		cfg.GlobalDefaults.ImgSrc = []string{"'self'; script-src 'unsafe-eval'"}
		err := validateCSPConfig(cfg)
		if err == nil {
			t.Fatal("expected error for semicolon in source value")
		}
	})

	t.Run("newline in raw directives rejected", func(t *testing.T) {
		cfg := defaultCSPConfig()
		cfg.GlobalDefaults.RawDirectives = "report-uri /csp\nscript-src 'unsafe-eval'"
		err := validateCSPConfig(cfg)
		if err == nil {
			t.Fatal("expected error for newline in raw_directives")
		}
	})

	t.Run("service policy validation", func(t *testing.T) {
		cfg := defaultCSPConfig()
		cfg.Services["test"] = CSPServiceConfig{
			Mode: "set",
			Policy: CSPPolicy{
				FontSrc: []string{"data:\rinjection"},
			},
		}
		err := validateCSPConfig(cfg)
		if err == nil {
			t.Fatal("expected error for carriage return in service policy")
		}
		if !strings.Contains(err.Error(), "service \"test\"") {
			t.Errorf("error should name the service, got: %v", err)
		}
	})
}

// ─── CSP Store Tests ────────────────────────────────────────────────────────

func newTestCSPStore(t *testing.T) *CSPStore {
	t.Helper()
	dir := t.TempDir()
	return NewCSPStore(filepath.Join(dir, "csp.json"))
}

func TestCSPStoreDefaults(t *testing.T) {
	store := newTestCSPStore(t)
	cfg := store.Get()

	if len(cfg.GlobalDefaults.DefaultSrc) == 0 {
		t.Error("GlobalDefaults.DefaultSrc should have default values")
	}
	if cfg.GlobalDefaults.DefaultSrc[0] != "'self'" {
		t.Errorf("DefaultSrc[0] = %q, want \"'self'\"", cfg.GlobalDefaults.DefaultSrc[0])
	}
	if len(cfg.Services) != 0 {
		t.Errorf("Services should be empty by default, got %d", len(cfg.Services))
	}
}

func TestCSPStoreUpdate(t *testing.T) {
	store := newTestCSPStore(t)

	cfg := store.Get()
	cfg.Services["jellyfin"] = CSPServiceConfig{
		Mode:    "set",
		Inherit: true,
		Policy: CSPPolicy{
			ConnectSrc: []string{"'self'", "wss:", "https://api.jellyfin.org"},
		},
	}

	updated, err := store.Update(cfg)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if len(updated.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(updated.Services))
	}
	jf := updated.Services["jellyfin"]
	if jf.Mode != "set" {
		t.Errorf("mode = %q, want %q", jf.Mode, "set")
	}
}

func TestCSPStoreUpdateValidation(t *testing.T) {
	store := newTestCSPStore(t)

	cfg := store.Get()
	cfg.Services["test"] = CSPServiceConfig{Mode: "bogus"}

	_, err := store.Update(cfg)
	if err == nil {
		t.Fatal("expected validation error for bogus mode")
	}

	// Store should retain old state on failure.
	current := store.Get()
	if len(current.Services) != 0 {
		t.Error("store should retain old state after failed update")
	}
}

func TestCSPStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csp.json")

	// Write config.
	store1 := NewCSPStore(path)
	cfg := store1.Get()
	cfg.Services["sonarr"] = CSPServiceConfig{
		Mode:    "default",
		Inherit: true,
	}
	store1.Update(cfg)

	// Reload from same file.
	store2 := NewCSPStore(path)
	cfg2 := store2.Get()
	if len(cfg2.Services) != 1 {
		t.Fatalf("expected 1 service after reload, got %d", len(cfg2.Services))
	}
	if cfg2.Services["sonarr"].Mode != "default" {
		t.Errorf("mode = %q, want %q", cfg2.Services["sonarr"].Mode, "default")
	}
}

func TestCSPStoreServiceNames(t *testing.T) {
	store := newTestCSPStore(t)
	cfg := store.Get()
	cfg.Services["zebra"] = CSPServiceConfig{Mode: "set"}
	cfg.Services["alpha"] = CSPServiceConfig{Mode: "none"}
	cfg.Services["middle"] = CSPServiceConfig{Mode: "default"}
	store.Update(cfg)

	names := store.ServiceNames()
	if len(names) != 3 {
		t.Fatalf("expected 3 names, got %d", len(names))
	}
	// Should be sorted.
	if names[0] != "alpha" || names[1] != "middle" || names[2] != "zebra" {
		t.Errorf("names not sorted: %v", names)
	}
}

func TestCSPStoreResolvePolicy(t *testing.T) {
	store := newTestCSPStore(t)
	cfg := store.Get()
	cfg.Services["jellyfin"] = CSPServiceConfig{
		Mode:    "set",
		Inherit: true,
		Policy: CSPPolicy{
			ConnectSrc: []string{"'self'", "wss:", "https://api.jellyfin.org"},
		},
	}
	cfg.Services["authelia"] = CSPServiceConfig{
		Mode:    "default",
		Inherit: false,
		Policy: CSPPolicy{
			DefaultSrc: []string{"'self'"},
			ScriptSrc:  []string{"'self'"},
		},
	}
	cfg.Services["qbittorrent"] = CSPServiceConfig{
		Mode: "none",
	}
	store.Update(cfg)

	t.Run("inherit merges with global", func(t *testing.T) {
		policy, sc := store.ResolvePolicy("jellyfin")
		if sc.Mode != "set" {
			t.Errorf("mode = %q, want %q", sc.Mode, "set")
		}
		// ConnectSrc should be from override, DefaultSrc from global.
		if strings.Join(policy.ConnectSrc, " ") != "'self' wss: https://api.jellyfin.org" {
			t.Errorf("ConnectSrc = %v", policy.ConnectSrc)
		}
		if strings.Join(policy.DefaultSrc, " ") != "'self'" {
			t.Errorf("DefaultSrc should come from global: %v", policy.DefaultSrc)
		}
	})

	t.Run("no inherit uses only service policy", func(t *testing.T) {
		policy, sc := store.ResolvePolicy("authelia")
		if sc.Mode != "default" {
			t.Errorf("mode = %q, want %q", sc.Mode, "default")
		}
		if strings.Join(policy.DefaultSrc, " ") != "'self'" {
			t.Errorf("DefaultSrc = %v", policy.DefaultSrc)
		}
		// ObjectSrc should be empty (not inherited from global).
		if len(policy.ObjectSrc) != 0 {
			t.Errorf("ObjectSrc should be empty without inherit: %v", policy.ObjectSrc)
		}
	})

	t.Run("mode none returns empty policy", func(t *testing.T) {
		policy, sc := store.ResolvePolicy("qbittorrent")
		if sc.Mode != "none" {
			t.Errorf("mode = %q, want %q", sc.Mode, "none")
		}
		if len(policy.DefaultSrc) != 0 {
			t.Errorf("DefaultSrc should be empty for none mode: %v", policy.DefaultSrc)
		}
	})

	t.Run("unconfigured service uses global defaults", func(t *testing.T) {
		policy, sc := store.ResolvePolicy("unknown_service")
		if sc.Mode != "set" {
			t.Errorf("mode = %q, want %q for unconfigured service", sc.Mode, "set")
		}
		if strings.Join(policy.DefaultSrc, " ") != "'self'" {
			t.Errorf("DefaultSrc should be global defaults: %v", policy.DefaultSrc)
		}
	})
}

func TestCSPStoreDeepCopy(t *testing.T) {
	store := newTestCSPStore(t)
	cfg1 := store.Get()
	cfg1.GlobalDefaults.ScriptSrc = append(cfg1.GlobalDefaults.ScriptSrc, "INJECTED")

	// Fetching again should not see the mutation.
	cfg2 := store.Get()
	for _, v := range cfg2.GlobalDefaults.ScriptSrc {
		if v == "INJECTED" {
			t.Error("deep copy failed: mutation leaked to store")
		}
	}
}

func TestCSPStoreNilServices(t *testing.T) {
	// Update with nil Services map should be normalized to empty map.
	store := newTestCSPStore(t)
	cfg := CSPConfig{
		GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		Services:       nil,
	}
	updated, err := store.Update(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Services == nil {
		t.Error("Services should be normalized to non-nil map")
	}
}

// ─── Generator Tests ────────────────────────────────────────────────────────

// ─── HTTP Handler Tests ─────────────────────────────────────────────────────

func setupCSPMux(t *testing.T) (*http.ServeMux, *CSPStore) {
	t.Helper()
	store := newTestCSPStore(t)
	dir := t.TempDir()
	deployCfg := DeployConfig{
		CSPDir:        dir,
		CaddyfilePath: filepath.Join(dir, "Caddyfile"),
	}
	// Write an empty Caddyfile for the deploy handler.
	os.WriteFile(deployCfg.CaddyfilePath, []byte(""), 0644)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/csp", handleGetCSP(store))
	mux.HandleFunc("PUT /api/csp", handleUpdateCSP(store))
	mux.HandleFunc("POST /api/csp/deploy", handleDeployCSP(store, nil, nil, nil, nil, nil, nil, deployCfg))
	mux.HandleFunc("GET /api/csp/preview", handlePreviewCSP(store, deployCfg))
	return mux, store
}

func TestHandleGetCSP(t *testing.T) {
	mux, _ := setupCSPMux(t)

	req := httptest.NewRequest("GET", "/api/csp", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var cfg CSPConfig
	json.NewDecoder(w.Body).Decode(&cfg)
	if len(cfg.GlobalDefaults.DefaultSrc) == 0 {
		t.Error("should return default CSP config")
	}
}

func TestHandleUpdateCSP(t *testing.T) {
	mux, _ := setupCSPMux(t)

	cfg := defaultCSPConfig()
	cfg.Services["test"] = CSPServiceConfig{
		Mode:    "set",
		Inherit: true,
		Policy: CSPPolicy{
			ScriptSrc: []string{"'self'", "'strict-dynamic'"},
		},
	}

	body, _ := json.Marshal(cfg)
	req := httptest.NewRequest("PUT", "/api/csp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	var updated CSPConfig
	json.NewDecoder(w.Body).Decode(&updated)
	if len(updated.Services) != 1 {
		t.Errorf("expected 1 service, got %d", len(updated.Services))
	}
}

func TestHandleUpdateCSPValidationError(t *testing.T) {
	mux, _ := setupCSPMux(t)

	cfg := defaultCSPConfig()
	cfg.Services["test"] = CSPServiceConfig{Mode: "badmode"}

	body, _ := json.Marshal(cfg)
	req := httptest.NewRequest("PUT", "/api/csp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	var errResp ErrorResponse
	json.NewDecoder(w.Body).Decode(&errResp)
	if errResp.Error != "validation failed" {
		t.Errorf("error = %q, want %q", errResp.Error, "validation failed")
	}
}

func TestHandlePreviewCSP(t *testing.T) {
	mux, store := setupCSPMux(t)

	cfg := store.Get()
	cfg.Services["jellyfin"] = CSPServiceConfig{
		Mode:    "set",
		Inherit: true,
		Policy: CSPPolicy{
			ConnectSrc: []string{"'self'", "wss:"},
		},
	}
	cfg.Services["authelia"] = CSPServiceConfig{
		Mode: "none",
	}
	store.Update(cfg)

	req := httptest.NewRequest("GET", "/api/csp/preview", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var preview CSPPreviewResponse
	json.NewDecoder(w.Body).Decode(&preview)

	// Jellyfin should have a rendered header.
	jf, ok := preview.Services["jellyfin"]
	if !ok {
		t.Fatal("missing jellyfin in preview")
	}
	if jf.Mode != "set" {
		t.Errorf("jellyfin mode = %q, want %q", jf.Mode, "set")
	}
	if jf.Header == "" {
		t.Error("jellyfin should have rendered CSP header")
	}
	if !strings.Contains(jf.Header, "connect-src 'self' wss:") {
		t.Errorf("jellyfin header should contain connect-src, got: %q", jf.Header)
	}

	// Authelia should be mode none with empty header.
	auth, ok := preview.Services["authelia"]
	if !ok {
		t.Fatal("missing authelia in preview")
	}
	if auth.Mode != "none" {
		t.Errorf("authelia mode = %q, want %q", auth.Mode, "none")
	}
	if auth.Header != "" {
		t.Error("authelia should have empty header for mode none")
	}
}

func TestHandlePreviewCSPDiscoveredServices(t *testing.T) {
	store := newTestCSPStore(t)
	dir := t.TempDir()
	caddyfilePath := filepath.Join(dir, "Caddyfile")

	// Write a Caddyfile with site blocks for sonarr and radarr.
	caddyfileContent := `sonarr.example.com {
	reverse_proxy sonarr:8989
}
radarr.example.com {
	reverse_proxy radarr:7878
}
`
	os.WriteFile(caddyfilePath, []byte(caddyfileContent), 0644)

	deployCfg := DeployConfig{
		CSPDir:        dir,
		CaddyfilePath: caddyfilePath,
	}

	// Set global defaults so discovered services have something to show.
	cfg := store.Get()
	cfg.GlobalDefaults = CSPPolicy{
		DefaultSrc: []string{"'self'"},
		ScriptSrc:  []string{"'self'", "'unsafe-inline'"},
	}
	// Only configure sonarr explicitly — radarr should come from discovery.
	cfg.Services["sonarr"] = CSPServiceConfig{
		Mode:    "set",
		Inherit: false,
		Policy: CSPPolicy{
			DefaultSrc: []string{"'none'"},
		},
	}
	store.Update(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/csp/preview", handlePreviewCSP(store, deployCfg))

	req := httptest.NewRequest("GET", "/api/csp/preview", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var preview CSPPreviewResponse
	json.NewDecoder(w.Body).Decode(&preview)

	// sonarr is explicitly configured — should appear.
	sonarr, ok := preview.Services["sonarr"]
	if !ok {
		t.Fatal("missing sonarr in preview")
	}
	if !strings.Contains(sonarr.Header, "default-src 'none'") {
		t.Errorf("sonarr header = %q, want default-src 'none'", sonarr.Header)
	}

	// radarr is NOT configured but discovered in Caddyfile — should appear
	// with global defaults.
	radarr, ok := preview.Services["radarr"]
	if !ok {
		t.Fatal("missing radarr in preview — discovered services should appear")
	}
	if radarr.Mode != "set" {
		t.Errorf("radarr mode = %q, want %q (inherited from global)", radarr.Mode, "set")
	}
	if !strings.Contains(radarr.Header, "default-src 'self'") {
		t.Errorf("radarr header should contain global default-src, got: %q", radarr.Header)
	}
	if !strings.Contains(radarr.Header, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("radarr header should contain global script-src, got: %q", radarr.Header)
	}
}

func TestHandlePreviewCSPEmptyGlobals(t *testing.T) {
	store := newTestCSPStore(t)
	dir := t.TempDir()
	caddyfilePath := filepath.Join(dir, "Caddyfile")

	// Caddyfile with a discovered service.
	os.WriteFile(caddyfilePath, []byte(`s.example.com {
	import /data/caddy/csp/myapp_csp*.caddy
}
`), 0644)

	deployCfg := DeployConfig{
		CSPDir:        dir,
		CaddyfilePath: caddyfilePath,
	}

	// Clear global defaults so discovered services produce an empty header.
	cfg := store.Get()
	cfg.GlobalDefaults = CSPPolicy{}
	store.Update(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/csp/preview", handlePreviewCSP(store, deployCfg))

	req := httptest.NewRequest("GET", "/api/csp/preview", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var preview CSPPreviewResponse
	json.NewDecoder(w.Body).Decode(&preview)

	if _, ok := preview.Services["myapp"]; ok {
		t.Error("myapp should not appear when global defaults are empty")
	}
}

func TestHandleDeployCSPRequiresPolicyEngine(t *testing.T) {
	mux, store := setupCSPMux(t)

	cfg := store.Get()
	cfg.Services["test"] = CSPServiceConfig{
		Mode:    "set",
		Inherit: false,
		Policy: CSPPolicy{
			DefaultSrc: []string{"'none'"},
		},
	}
	store.Update(cfg)

	req := httptest.NewRequest("POST", "/api/csp/deploy", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Without policy engine enabled, deploy should return 400.
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body: %s", w.Code, w.Body.String())
	}

	var resp ErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp.Error, "policy engine") {
		t.Errorf("error should mention policy engine, got %q", resp.Error)
	}
}

// ─── Default Config Tests ───────────────────────────────────────────────────

func TestDefaultCSPConfig(t *testing.T) {
	cfg := defaultCSPConfig()

	// Verify the pragmatic baseline.
	header := buildCSPHeader(cfg.GlobalDefaults)
	expectedParts := []string{
		"default-src 'self'",
		"script-src 'self' 'unsafe-inline'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"font-src 'self' data:",
		"connect-src 'self' wss:",
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'self'",
		"upgrade-insecure-requests",
	}
	for _, part := range expectedParts {
		if !strings.Contains(header, part) {
			t.Errorf("default CSP header missing %q.\nFull header: %s", part, header)
		}
	}
}

// ─── StoreInfo Tests ────────────────────────────────────────────────────────

func TestCSPStoreInfo(t *testing.T) {
	store := newTestCSPStore(t)
	info := store.StoreInfo()
	if info["services"] != 0 {
		t.Errorf("services = %v, want 0", info["services"])
	}

	cfg := store.Get()
	cfg.Services["a"] = CSPServiceConfig{Mode: "set"}
	cfg.Services["b"] = CSPServiceConfig{Mode: "none"}
	store.Update(cfg)

	info = store.StoreInfo()
	if info["services"] != 2 {
		t.Errorf("services = %v, want 2", info["services"])
	}
}

// ─── Enabled/Disabled Tests ─────────────────────────────────────────────────

func TestCSPEnabled(t *testing.T) {
	t.Run("nil defaults to true", func(t *testing.T) {
		cfg := CSPConfig{}
		if !cspEnabled(cfg) {
			t.Error("nil Enabled should default to true")
		}
	})

	t.Run("explicit true", func(t *testing.T) {
		cfg := CSPConfig{Enabled: boolPtr(true)}
		if !cspEnabled(cfg) {
			t.Error("explicit true should be enabled")
		}
	})

	t.Run("explicit false", func(t *testing.T) {
		cfg := CSPConfig{Enabled: boolPtr(false)}
		if cspEnabled(cfg) {
			t.Error("explicit false should be disabled")
		}
	})
}

func TestPreviewCSPDisabled(t *testing.T) {
	store := newTestCSPStore(t)
	cfg := store.Get()
	cfg.Enabled = boolPtr(false)
	cfg.Services["test"] = CSPServiceConfig{
		Mode:    "set",
		Inherit: true,
		Policy:  CSPPolicy{DefaultSrc: []string{"'self'"}},
	}
	store.Update(cfg)

	dir := t.TempDir()
	deployCfg := DeployConfig{CSPDir: dir, CaddyfilePath: filepath.Join(dir, "Caddyfile")}
	os.WriteFile(deployCfg.CaddyfilePath, []byte(""), 0644)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/csp/preview", handlePreviewCSP(store, deployCfg))

	req := httptest.NewRequest("GET", "/api/csp/preview", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var preview CSPPreviewResponse
	json.NewDecoder(w.Body).Decode(&preview)

	if len(preview.Services) != 0 {
		t.Errorf("preview should be empty when disabled, got %d services", len(preview.Services))
	}
}

func TestCSPStoreEnabledPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csp.json")

	store1 := NewCSPStore(path)
	cfg := store1.Get()
	cfg.Enabled = boolPtr(false)
	store1.Update(cfg)

	// Reload and verify.
	store2 := NewCSPStore(path)
	cfg2 := store2.Get()
	if cspEnabled(cfg2) {
		t.Error("disabled state should persist across reload")
	}
}

func TestCSPStoreBackwardCompatNoEnabledField(t *testing.T) {
	// Simulate loading a JSON file that doesn't have the "enabled" field.
	dir := t.TempDir()
	path := filepath.Join(dir, "csp.json")
	os.WriteFile(path, []byte(`{"global_defaults":{"default_src":["'self'"]},"services":{}}`), 0644)

	store := NewCSPStore(path)
	cfg := store.Get()
	// Should default to enabled when field is missing.
	if !cspEnabled(cfg) {
		t.Error("missing enabled field should default to true (enabled)")
	}
}

// ─── FQDN Propagation Tests ────────────────────────────────────────────────

func TestFindParentServiceConfig(t *testing.T) {
	services := map[string]CSPServiceConfig{
		"httpbun": {Mode: "set", Inherit: false, Policy: CSPPolicy{DefaultSrc: []string{"'none'"}}},
		"sonarr":  {Mode: "none"},
	}

	t.Run("FQDN finds parent", func(t *testing.T) {
		sc, ok := findParentServiceConfig("httpbun.erfi.io", services)
		if !ok {
			t.Fatal("should find parent config for httpbun.erfi.io")
		}
		if sc.Mode != "set" {
			t.Errorf("mode = %q, want %q", sc.Mode, "set")
		}
	})

	t.Run("short name has no parent", func(t *testing.T) {
		_, ok := findParentServiceConfig("httpbun", services)
		if ok {
			t.Error("short name should not match as FQDN")
		}
	})

	t.Run("unknown FQDN", func(t *testing.T) {
		_, ok := findParentServiceConfig("unknown.erfi.io", services)
		if ok {
			t.Error("unknown FQDN should not find parent")
		}
	})
}

func TestPreviewCSPFQDNPropagation(t *testing.T) {
	store := newTestCSPStore(t)
	dir := t.TempDir()
	caddyfilePath := filepath.Join(dir, "Caddyfile")

	os.WriteFile(caddyfilePath, []byte(`httpbun.erfi.io {
	reverse_proxy httpbun:8080
}
`), 0644)

	cfg := store.Get()
	cfg.Services["httpbun"] = CSPServiceConfig{
		Mode:       "set",
		ReportOnly: true,
		Inherit:    false,
		Policy: CSPPolicy{
			DefaultSrc: []string{"'self'"},
			ScriptSrc:  []string{"'self'", "'unsafe-eval'"},
		},
	}
	store.Update(cfg)

	deployCfg := DeployConfig{CSPDir: dir, CaddyfilePath: caddyfilePath}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/csp/preview", handlePreviewCSP(store, deployCfg))

	req := httptest.NewRequest("GET", "/api/csp/preview", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var preview CSPPreviewResponse
	json.NewDecoder(w.Body).Decode(&preview)

	fqdn, ok := preview.Services["httpbun.erfi.io"]
	if !ok {
		t.Fatal("FQDN should appear in preview")
	}
	if !strings.Contains(fqdn.Header, "'unsafe-eval'") {
		t.Errorf("FQDN preview should propagate override, got: %q", fqdn.Header)
	}
	if fqdn.Mode != "set" {
		t.Errorf("FQDN mode = %q, want %q", fqdn.Mode, "set")
	}
	if !fqdn.ReportOnly {
		t.Error("FQDN should propagate report_only from parent")
	}
}

// ─── ensureCSPDir Tests ─────────────────────────────────────────────────────

func TestEnsureCSPDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "csp")
	if err := ensureCSPDir(dir); err != nil {
		t.Fatalf("ensureCSPDir failed: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("dir should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("should be a directory")
	}
}
