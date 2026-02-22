package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DeployConfig holds paths and settings for the deploy pipeline.
type DeployConfig struct {
	// CorazaDir is the directory for custom Coraza config files.
	// These files are volume-mounted into the Caddy container.
	CorazaDir string

	// RateLimitDir is the directory for per-zone rate limit .caddy files.
	// These files are volume-mounted into the Caddy container and imported
	// by each site block via glob patterns.
	RateLimitDir string

	// CaddyfilePath is the path to the Caddyfile (read-only mount from Caddy).
	// Used to POST to Caddy's admin API for reload.
	CaddyfilePath string

	// CaddyAdminURL is the base URL for Caddy's admin API.
	CaddyAdminURL string
}

// DeployResponse is returned by the deploy endpoint.
type DeployResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	PreCRS      string `json:"pre_crs_file"`
	PostCRS     string `json:"post_crs_file"`
	WAFSettings string `json:"waf_settings_file"`
	Reloaded    bool   `json:"reloaded"`
	Timestamp   string `json:"timestamp"`
}

// ensureCorazaDir creates the coraza config directory and empty placeholder
// files if they don't exist. Called at startup.
func ensureCorazaDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating coraza dir %s: %w", dir, err)
	}

	placeholders := map[string]string{
		"custom-pre-crs.conf":  "",
		"custom-post-crs.conf": "",
		// The WAF settings placeholder includes SecRuleEngine On as the safe
		// default. The Caddyfile intentionally does NOT set SecRuleEngine —
		// this file is the single source of truth, managed by the generator.
		"custom-waf-settings.conf": "SecRuleEngine On\n",
	}
	for name, extra := range placeholders {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			header := fmt.Sprintf("# Managed by waf-api\n# Created: %s\n# This file is empty until settings are deployed.\n%s",
				time.Now().UTC().Format(time.RFC3339), extra)
			if err := atomicWriteFile(path, []byte(header), 0644); err != nil {
				return fmt.Errorf("creating placeholder %s: %w", path, err)
			}
			log.Printf("created placeholder: %s", path)
		}
	}
	return nil
}

// writeConfFiles writes the generated pre-CRS, post-CRS, and WAF settings configs to disk atomically.
func writeConfFiles(dir, preCRS, postCRS, wafSettings string) error {
	files := map[string]string{
		"custom-pre-crs.conf":      preCRS,
		"custom-post-crs.conf":     postCRS,
		"custom-waf-settings.conf": wafSettings,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := atomicWriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
		log.Printf("wrote %s (%d bytes)", path, len(content))
	}
	return nil
}

// reloadCaddy sends the Caddyfile to Caddy's admin API to trigger a reload.
// This reads the Caddyfile from disk and POSTs it to /load with the caddyfile adapter.
//
// IMPORTANT: Caddy compares the incoming config to its current config and may
// skip reprocessing if the Caddyfile text is identical — even when included files
// (e.g. custom-waf-settings.conf) have changed on disk. To force a full reparse
// on every deploy, we inject a unique comment with a SHA-256 fingerprint of the
// Coraza config files and a timestamp. This comment is only in the POST body;
// the Caddyfile on disk is not modified.
func reloadCaddy(caddyfilePath, adminURL string, configFiles ...string) error {
	content, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return fmt.Errorf("reading Caddyfile at %s: %w", caddyfilePath, err)
	}

	// Build a fingerprint from all config file contents to force Caddy to
	// see a "new" Caddyfile on every deploy. The timestamp alone would suffice,
	// but including the hash lets us log exactly what changed.
	fingerprint := deployFingerprint(configFiles)
	header := fmt.Sprintf("# waf-api deploy %s fingerprint:%s\n",
		time.Now().UTC().Format(time.RFC3339), fingerprint)
	payload := append([]byte(header), content...)

	url := adminURL + "/load"
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating reload request: %w", err)
	}
	req.Header.Set("Content-Type", "text/caddyfile")

	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Caddy admin API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Caddy reload failed (status %d): %s", resp.StatusCode, string(body))
	}

	log.Printf("Caddy reload successful via %s (fingerprint: %s)", url, fingerprint)
	return nil
}

// deployFingerprint computes a short SHA-256 hash of the concatenated contents
// of the given file paths. If a file can't be read, its path is hashed instead
// (so the fingerprint still changes when files are added/removed).
func deployFingerprint(paths []string) string {
	h := sha256.New()
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			// File missing or unreadable — hash the path itself as a marker.
			h.Write([]byte(p))
		} else {
			h.Write(data)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}
