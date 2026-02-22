package main

import (
	"bytes"
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

	// CaddyfilePath is the path to the Caddyfile (read-only mount from Caddy).
	// Used to POST to Caddy's admin API for reload.
	CaddyfilePath string

	// CaddyAdminURL is the base URL for Caddy's admin API.
	CaddyAdminURL string
}

// DeployResponse is returned by the deploy endpoint.
type DeployResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	PreCRS    string `json:"pre_crs_file"`
	PostCRS   string `json:"post_crs_file"`
	Reloaded  bool   `json:"reloaded"`
	Timestamp string `json:"timestamp"`
}

// ensureCorazaDir creates the coraza config directory and empty placeholder
// files if they don't exist. Called at startup.
func ensureCorazaDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating coraza dir %s: %w", dir, err)
	}

	files := []string{"custom-pre-crs.conf", "custom-post-crs.conf"}
	for _, name := range files {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			header := fmt.Sprintf("# Managed by waf-api Policy Engine\n# Created: %s\n# This file is empty until exclusions are deployed.\n",
				time.Now().UTC().Format(time.RFC3339))
			if err := os.WriteFile(path, []byte(header), 0644); err != nil {
				return fmt.Errorf("creating placeholder %s: %w", path, err)
			}
			log.Printf("created placeholder: %s", path)
		}
	}
	return nil
}

// writeConfFiles writes the generated pre-CRS and post-CRS configs to disk.
func writeConfFiles(dir, preCRS, postCRS string) error {
	prePath := filepath.Join(dir, "custom-pre-crs.conf")
	postPath := filepath.Join(dir, "custom-post-crs.conf")

	if err := os.WriteFile(prePath, []byte(preCRS), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", prePath, err)
	}
	log.Printf("wrote %s (%d bytes)", prePath, len(preCRS))

	if err := os.WriteFile(postPath, []byte(postCRS), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", postPath, err)
	}
	log.Printf("wrote %s (%d bytes)", postPath, len(postCRS))

	return nil
}

// reloadCaddy sends the Caddyfile to Caddy's admin API to trigger a reload.
// This reads the Caddyfile from disk and POSTs it to /load with the caddyfile adapter.
func reloadCaddy(caddyfilePath, adminURL string) error {
	content, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return fmt.Errorf("reading Caddyfile at %s: %w", caddyfilePath, err)
	}

	url := adminURL + "/load"
	req, err := http.NewRequest("POST", url, bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("creating reload request: %w", err)
	}
	req.Header.Set("Content-Type", "text/caddyfile")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Caddy admin API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Caddy reload failed (status %d): %s", resp.StatusCode, string(body))
	}

	log.Printf("Caddy reload successful via %s", url)
	return nil
}
