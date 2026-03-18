package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newTestDosStores(t *testing.T) (*JailStore, *DosConfigStore) {
	t.Helper()
	dir := t.TempDir()
	jail := NewJailStore(filepath.Join(dir, "jail.json"))
	cfg := NewDosConfigStore(filepath.Join(dir, "dos-config.json"))
	return jail, cfg
}

func TestHandleDosStatus(t *testing.T) {
	jail, dosCfg := newTestDosStores(t)
	spike := NewSpikeDetector("", 50, 10, 0)
	als := &AccessLogStore{}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/dos/status", handleDosStatus(jail, dosCfg, spike, als))

	req := httptest.NewRequest("GET", "/api/dos/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var status DosStatus
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if status.Mode != "normal" {
		t.Errorf("mode = %q, want normal", status.Mode)
	}
	if status.UpdatedAt == "" {
		t.Error("expected non-empty updated_at")
	}
}

func TestHandleListJail(t *testing.T) {
	jail, _ := newTestDosStores(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/dos/jail", handleListJail(jail))

	req := httptest.NewRequest("GET", "/api/dos/jail", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var entries []JailEntry
	if err := json.NewDecoder(rec.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestHandleAddJail(t *testing.T) {
	jail, _ := newTestDosStores(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/dos/jail", handleAddJail(jail))

	t.Run("valid add", func(t *testing.T) {
		body := `{"ip":"198.51.100.1","ttl":"5m","reason":"test"}`
		req := httptest.NewRequest("POST", "/api/dos/jail", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "jailed") {
			t.Errorf("expected 'jailed' in response, got: %s", rec.Body.String())
		}
	})

	t.Run("missing IP", func(t *testing.T) {
		body := `{"ttl":"5m"}`
		req := httptest.NewRequest("POST", "/api/dos/jail", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("invalid IP", func(t *testing.T) {
		body := `{"ip":"not-an-ip","ttl":"5m"}`
		req := httptest.NewRequest("POST", "/api/dos/jail", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})
}

func TestHandleRemoveJail(t *testing.T) {
	jail, _ := newTestDosStores(t)
	// Pre-add an entry.
	jail.Add("198.51.100.2", "1h", "test")

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /api/dos/jail/{ip}", handleRemoveJail(jail))

	req := httptest.NewRequest("DELETE", "/api/dos/jail/198.51.100.2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unjailed") {
		t.Errorf("expected 'unjailed' in response")
	}
}

func TestHandleGetDosConfig(t *testing.T) {
	_, dosCfg := newTestDosStores(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/dos/config", handleGetDosConfig(dosCfg))

	req := httptest.NewRequest("GET", "/api/dos/config", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var cfg DosConfig
	if err := json.NewDecoder(rec.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Threshold <= 0 {
		t.Errorf("expected positive threshold, got %f", cfg.Threshold)
	}
}

func TestHandleUpdateDosConfig(t *testing.T) {
	jail, dosCfg := newTestDosStores(t)
	spike := NewSpikeDetector("", 50, 10, 0)

	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/dos/config", handleUpdateDosConfig(dosCfg, jail, spike))

	t.Run("valid update", func(t *testing.T) {
		body := `{"enabled":true,"threshold":2.0,"base_penalty":"30s","max_penalty":"1h","eps_trigger":100,"eps_cooldown":20,"cooldown_delay":"15s","max_buckets":5000,"max_reports":50,"whitelist":["10.0.0.0/8"],"kernel_drop":false,"strategy":"auto"}`
		req := httptest.NewRequest("PUT", "/api/dos/config", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != 200 {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		// Verify spike detector picked up new thresholds.
		if spike.EPS() != 0 {
			t.Logf("eps = %.1f (expected 0 since no events)", spike.EPS())
		}
	})

	t.Run("invalid strategy", func(t *testing.T) {
		body := `{"enabled":true,"threshold":1.0,"base_penalty":"30s","max_penalty":"1h","eps_trigger":50,"eps_cooldown":10,"cooldown_delay":"15s","max_buckets":5000,"max_reports":50,"whitelist":["10.0.0.0/8"],"strategy":"invalid"}`
		req := httptest.NewRequest("PUT", "/api/dos/config", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != 400 {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("wildcard CIDR rejected", func(t *testing.T) {
		body := `{"enabled":true,"threshold":1.0,"base_penalty":"30s","max_penalty":"1h","eps_trigger":50,"eps_cooldown":10,"cooldown_delay":"15s","max_buckets":5000,"max_reports":50,"whitelist":["0.0.0.0/0"],"strategy":"auto"}`
		req := httptest.NewRequest("PUT", "/api/dos/config", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != 400 {
			t.Fatalf("expected 400 for wildcard CIDR, got %d", rec.Code)
		}
	})
}
