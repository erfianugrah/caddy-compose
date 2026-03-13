package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupUIDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Create Astro MPA structure:
	// /index.html (home page)
	// /events/index.html (events page)
	// /rules/crs/index.html (nested page)
	// /_astro/style.abc123.css (hashed asset)
	// /404.html (custom 404)
	for _, sub := range []string{"events", "rules/crs", "_astro"} {
		os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	write := func(rel, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", "<html>home</html>")
	write("events/index.html", "<html>events</html>")
	write("rules/crs/index.html", "<html>crs</html>")
	write("_astro/style.abc123.css", "body{color:red}")
	write("404.html", "<html>not found</html>")

	return dir
}

func TestUIFileServer_ExactFile(t *testing.T) {
	dir := setupUIDir(t)
	handler := uiFileServer(dir)

	req := httptest.NewRequest("GET", "/_astro/style.abc123.css", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "body{color:red}") {
		t.Errorf("expected CSS content, got %q", rec.Body.String())
	}
}

func TestUIFileServer_RootIndex(t *testing.T) {
	dir := setupUIDir(t)
	handler := uiFileServer(dir)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "home") {
		t.Errorf("expected home page, got %q", rec.Body.String())
	}
}

func TestUIFileServer_DirectoryRoute(t *testing.T) {
	dir := setupUIDir(t)
	handler := uiFileServer(dir)

	for _, path := range []string{"/events", "/events/", "/rules/crs", "/rules/crs/"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected 200 for %s, got %d", path, rec.Code)
			}
		})
	}
}

func TestUIFileServer_NotFound(t *testing.T) {
	dir := setupUIDir(t)
	handler := uiFileServer(dir)

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not found") {
		t.Errorf("expected 404 page content, got %q", rec.Body.String())
	}
}

func TestUIFileServer_PathTraversal(t *testing.T) {
	dir := setupUIDir(t)
	handler := uiFileServer(dir)

	req := httptest.NewRequest("GET", "/../etc/passwd", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for path traversal, got %d", rec.Code)
	}
}

func TestUIFileServer_NoCatchAllFallback(t *testing.T) {
	// Verify that unknown paths do NOT serve index.html (would be SPA pattern / Web Cache Deception)
	dir := setupUIDir(t)
	handler := uiFileServer(dir)

	req := httptest.NewRequest("GET", "/blocklist;test.png", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown path, got %d (Web Cache Deception risk)", rec.Code)
	}
}
