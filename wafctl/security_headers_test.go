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

// ─── Store Tests ────────────────────────────────────────────────────

func TestSecurityHeaderStore_DefaultConfig(t *testing.T) {
	store := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))
	cfg := store.Get()

	if cfg.Profile != "default" {
		t.Errorf("expected profile 'default', got %q", cfg.Profile)
	}
	if cfg.Enabled != nil && !*cfg.Enabled {
		t.Error("expected enabled to be true/nil")
	}
	if cfg.Headers == nil || cfg.Headers["X-Content-Type-Options"] != "nosniff" {
		t.Error("expected default headers to include X-Content-Type-Options: nosniff")
	}
	if len(cfg.Remove) != 2 {
		t.Errorf("expected 2 remove headers, got %d", len(cfg.Remove))
	}
}

func TestSecurityHeaderStore_PersistAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sec.json")
	store := NewSecurityHeaderStore(path)

	cfg := store.Get()
	cfg.Profile = "strict"
	cfg.Headers["X-Frame-Options"] = "DENY"
	updated, err := store.Update(cfg)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Profile != "strict" {
		t.Errorf("expected profile 'strict', got %q", updated.Profile)
	}

	// Reload from disk.
	store2 := NewSecurityHeaderStore(path)
	cfg2 := store2.Get()
	if cfg2.Profile != "strict" {
		t.Errorf("reloaded profile: expected 'strict', got %q", cfg2.Profile)
	}
	if cfg2.Headers["X-Frame-Options"] != "DENY" {
		t.Errorf("reloaded X-Frame-Options: expected 'DENY', got %q", cfg2.Headers["X-Frame-Options"])
	}
}

func TestSecurityHeaderStore_Validation(t *testing.T) {
	store := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))

	tests := []struct {
		name    string
		cfg     SecurityHeaderConfig
		wantErr string
	}{
		{
			name:    "invalid profile",
			cfg:     SecurityHeaderConfig{Profile: "invalid", Services: map[string]SecurityServiceConfig{}},
			wantErr: "invalid profile",
		},
		{
			name: "header name with spaces",
			cfg: SecurityHeaderConfig{
				Profile:  "custom",
				Headers:  map[string]string{"Bad Name": "value"},
				Services: map[string]SecurityServiceConfig{},
			},
			wantErr: "invalid header name",
		},
		{
			name: "header value with newline",
			cfg: SecurityHeaderConfig{
				Profile:  "custom",
				Headers:  map[string]string{"X-Test": "val\nue"},
				Services: map[string]SecurityServiceConfig{},
			},
			wantErr: "contains newline",
		},
		{
			name: "invalid service name",
			cfg: SecurityHeaderConfig{
				Profile: "custom",
				Services: map[string]SecurityServiceConfig{
					"../etc": {},
				},
			},
			wantErr: "invalid service name",
		},
		{
			name: "valid custom config",
			cfg: SecurityHeaderConfig{
				Profile:  "custom",
				Headers:  map[string]string{"X-Custom": "test"},
				Remove:   []string{"Server"},
				Services: map[string]SecurityServiceConfig{},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.Update(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}

func TestSecurityHeaderStore_PerServiceOverrides(t *testing.T) {
	store := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))

	cfg := store.Get()
	cfg.Services["immich"] = SecurityServiceConfig{
		Profile: "relaxed",
		Headers: map[string]string{
			"Cross-Origin-Opener-Policy": "same-origin-allow-popups",
		},
	}
	_, err := store.Update(cfg)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	resolved := store.Resolve("immich")
	if resolved.Headers["Cross-Origin-Opener-Policy"] != "same-origin-allow-popups" {
		t.Errorf("expected COOP override, got %q", resolved.Headers["Cross-Origin-Opener-Policy"])
	}

	// Unknown service should get global.
	resolvedDefault := store.Resolve("unknown-service")
	if resolvedDefault.Headers["X-Content-Type-Options"] != "nosniff" {
		t.Error("expected default headers for unknown service")
	}
}

func TestResolveSecurityHeaders(t *testing.T) {
	cfg := SecurityHeaderConfig{
		Profile: "default",
		Headers: map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "SAMEORIGIN",
		},
		Remove: []string{"Server"},
		Services: map[string]SecurityServiceConfig{
			"jellyfin": {
				Headers: map[string]string{
					"X-Frame-Options": "", // Remove this header for jellyfin
				},
			},
			"immich": {
				Profile: "relaxed",
			},
		},
	}

	// Global (no service override).
	global := resolveSecurityHeaders(cfg, "caddy")
	if global.Headers["X-Frame-Options"] != "SAMEORIGIN" {
		t.Errorf("expected SAMEORIGIN, got %q", global.Headers["X-Frame-Options"])
	}

	// Jellyfin: X-Frame-Options removed.
	jf := resolveSecurityHeaders(cfg, "jellyfin")
	if _, ok := jf.Headers["X-Frame-Options"]; ok {
		t.Error("expected X-Frame-Options to be removed for jellyfin")
	}
	if jf.Headers["X-Content-Type-Options"] != "nosniff" {
		t.Error("expected inherited X-Content-Type-Options")
	}

	// Immich: relaxed profile replaces all headers.
	im := resolveSecurityHeaders(cfg, "immich")
	if im.Headers["Cross-Origin-Opener-Policy"] != "same-origin-allow-popups" {
		t.Errorf("expected relaxed COOP, got %q", im.Headers["Cross-Origin-Opener-Policy"])
	}
}

func TestSecurityProfiles(t *testing.T) {
	for name, prof := range securityProfiles {
		if prof.Name != name {
			t.Errorf("profile %q: Name field mismatch %q", name, prof.Name)
		}
		if len(prof.Headers) == 0 {
			t.Errorf("profile %q: no headers defined", name)
		}
		if prof.Description == "" {
			t.Errorf("profile %q: no description", name)
		}
	}

	// Strict should have X-Frame-Options: DENY
	strict := securityProfiles["strict"]
	if strict.Headers["X-Frame-Options"] != "DENY" {
		t.Errorf("strict profile X-Frame-Options: expected DENY, got %q", strict.Headers["X-Frame-Options"])
	}

	// Default should have SAMEORIGIN
	def := securityProfiles["default"]
	if def.Headers["X-Frame-Options"] != "SAMEORIGIN" {
		t.Errorf("default profile X-Frame-Options: expected SAMEORIGIN, got %q", def.Headers["X-Frame-Options"])
	}

	// API should not have X-Frame-Options
	api := securityProfiles["api"]
	if _, ok := api.Headers["X-Frame-Options"]; ok {
		t.Error("api profile should not have X-Frame-Options")
	}
}

// ─── Handler Tests ──────────────────────────────────────────────────

func TestHandleGetSecurityHeaders(t *testing.T) {
	store := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))
	handler := handleGetSecurityHeaders(store)

	req := httptest.NewRequest("GET", "/api/security-headers", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var cfg SecurityHeaderConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if cfg.Profile != "default" {
		t.Errorf("expected profile 'default', got %q", cfg.Profile)
	}
}

func TestHandleUpdateSecurityHeaders(t *testing.T) {
	store := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))
	handler := handleUpdateSecurityHeaders(store)

	body := `{"profile":"strict","headers":{"X-Frame-Options":"DENY"},"remove":["Server"]}`
	req := httptest.NewRequest("PUT", "/api/security-headers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var cfg SecurityHeaderConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if cfg.Profile != "strict" {
		t.Errorf("expected profile 'strict', got %q", cfg.Profile)
	}
}

func TestHandleUpdateSecurityHeaders_ValidationError(t *testing.T) {
	store := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))
	handler := handleUpdateSecurityHeaders(store)

	body := `{"profile":"invalid_profile"}`
	req := httptest.NewRequest("PUT", "/api/security-headers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleListSecurityProfiles(t *testing.T) {
	handler := handleListSecurityProfiles()

	req := httptest.NewRequest("GET", "/api/security-headers/profiles", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var profiles []SecurityProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &profiles); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(profiles) != 4 {
		t.Errorf("expected 4 profiles, got %d", len(profiles))
	}

	// Verify sorted order.
	for i := 1; i < len(profiles); i++ {
		if profiles[i].Name < profiles[i-1].Name {
			t.Errorf("profiles not sorted: %q before %q", profiles[i-1].Name, profiles[i].Name)
		}
	}
}

func TestHandlePreviewSecurityHeaders(t *testing.T) {
	store := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))
	cfg := store.Get()
	cfg.Services["immich"] = SecurityServiceConfig{
		Headers: map[string]string{"Cross-Origin-Opener-Policy": "same-origin-allow-popups"},
	}
	store.Update(cfg)

	handler := handlePreviewSecurityHeaders(store, DeployConfig{})

	req := httptest.NewRequest("GET", "/api/security-headers/preview", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var preview SecurityHeaderPreviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if preview.Global.Headers["X-Content-Type-Options"] != "nosniff" {
		t.Error("expected global X-Content-Type-Options: nosniff")
	}
	if imm, ok := preview.Services["immich"]; ok {
		if imm.Headers["Cross-Origin-Opener-Policy"] != "same-origin-allow-popups" {
			t.Error("expected immich COOP override in preview")
		}
	} else {
		t.Error("expected immich in preview services")
	}
}

func TestBuildPolicyResponseHeaders_WithSecStore(t *testing.T) {
	secPath := filepath.Join(t.TempDir(), "sec.json")
	secStore := NewSecurityHeaderStore(secPath)
	cfg := secStore.Get()
	cfg.Services["httpbun"] = SecurityServiceConfig{
		Headers: map[string]string{"Cross-Origin-Opener-Policy": "same-origin-allow-popups"},
	}
	secStore.Update(cfg)

	svcMap := map[string]string{
		"httpbun": "httpbun.erfi.io",
	}

	resp := BuildPolicyResponseHeaders(nil, secStore, svcMap)

	if resp.Security == nil {
		t.Fatal("expected security config")
	}
	if resp.Security.Headers["X-Content-Type-Options"] != "nosniff" {
		t.Error("expected global nosniff")
	}
	if resp.Security.PerService == nil {
		t.Fatal("expected per-service overrides")
	}
	// FQDN should be resolved.
	if ps, ok := resp.Security.PerService["httpbun.erfi.io"]; ok {
		if ps.Headers["Cross-Origin-Opener-Policy"] != "same-origin-allow-popups" {
			t.Error("expected COOP override for httpbun.erfi.io")
		}
	} else {
		t.Error("expected httpbun.erfi.io in per-service")
	}
}

func TestBuildPolicyResponseHeaders_NilSecStore(t *testing.T) {
	resp := BuildPolicyResponseHeaders(nil, nil, nil)
	if resp.Security == nil {
		t.Fatal("expected fallback security config")
	}
	if resp.Security.Headers["X-Content-Type-Options"] != "nosniff" {
		t.Error("expected default nosniff from DefaultSecurityHeaders()")
	}
}

func TestSecurityHeaderStore_StoreInfo(t *testing.T) {
	store := NewSecurityHeaderStore(filepath.Join(t.TempDir(), "sec.json"))
	info := store.StoreInfo()
	if info["profile"] != "default" {
		t.Errorf("expected profile 'default', got %v", info["profile"])
	}
	if info["enabled"] != true {
		t.Error("expected enabled=true")
	}
	if info["services"] != 0 {
		t.Errorf("expected 0 services, got %v", info["services"])
	}
}

func TestSecurityHeaderStore_BackfillFromProfile(t *testing.T) {
	// Simulate loading a file that has profile set but no headers.
	path := filepath.Join(t.TempDir(), "sec.json")
	data := []byte(`{"profile":"strict","services":{}}`)
	os.WriteFile(path, data, 0644)

	store := NewSecurityHeaderStore(path)
	cfg := store.Get()
	if cfg.Headers["X-Frame-Options"] != "DENY" {
		t.Errorf("expected backfilled X-Frame-Options DENY from strict profile, got %q", cfg.Headers["X-Frame-Options"])
	}
}
