package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// uiFileServer returns an http.Handler that serves the Astro MPA dashboard
// from dir with try_files semantics:
//
//  1. Serve the exact file if it exists (e.g. /_astro/foo.js)
//  2. Try path/index.html for directory-style routes (e.g. /events → events/index.html)
//  3. Return 404.html with a 404 status for anything else
//
// No catch-all /index.html fallback — that would be an SPA pattern and would
// create Web Cache Deception vulnerabilities.
func uiFileServer(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sanitize: strip leading slash, reject path traversal.
		p := strings.TrimPrefix(r.URL.Path, "/")
		if strings.Contains(p, "..") {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}

		// 1. Exact file match (static assets, e.g. /_astro/index.DxN2a.css)
		full := filepath.Join(dir, p)
		if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
			http.ServeFile(w, r, full)
			return
		}

		// 2. Directory index (MPA route, e.g. /events → events/index.html)
		idx := filepath.Join(full, "index.html")
		if fi, err := os.Stat(idx); err == nil && !fi.IsDir() {
			http.ServeFile(w, r, idx)
			return
		}

		// 3. 404 — serve the custom 404 page with proper status code.
		serve404(w, r, dir)
	})
}

// serve404 writes the custom 404.html page with a 404 status code.
// Falls back to a plain text response if the file doesn't exist.
func serve404(w http.ResponseWriter, _ *http.Request, dir string) {
	notFoundPath := filepath.Join(dir, "404.html")
	f, err := os.Open(notFoundPath)
	if err != nil {
		http.Error(w, "404 not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	io.Copy(w, f)
}
