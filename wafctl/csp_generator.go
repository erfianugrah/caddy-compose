package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ─── CSP Caddy Config Generator ─────────────────────────────────────────────

// cspFileName returns the Caddy snippet filename for a service.
func cspFileName(service string) string {
	return service + "_csp.caddy"
}

// GenerateCSPConfigs produces a map of filename → Caddy snippet content
// for each service that has CSP configured.
// Services discovered in the Caddyfile but not configured get placeholder files.
// When CSP is globally disabled, all files are comment-only placeholders.
func GenerateCSPConfigs(store *CSPStore, caddyfilePath string) map[string]string {
	cfg := store.Get()
	files := make(map[string]string)
	disabled := !cspEnabled(cfg)

	// Generate files for explicitly configured services.
	for service, sc := range cfg.Services {
		filename := cspFileName(service)
		if disabled {
			files[filename] = fmt.Sprintf("# CSP disabled globally for %s\n", service)
		} else {
			files[filename] = generateServiceCSP(service, sc, cfg.GlobalDefaults)
		}
	}

	// Discover services from the Caddyfile. For each discovered service,
	// check if the short name (before the first ".") has an explicit config —
	// this handles the FQDN variant (e.g. "httpbun.erfi.io" inherits from
	// an explicit "httpbun" override). Otherwise use global defaults.
	discovered := scanCaddyfileCSPServices(caddyfilePath)
	globalHeader := buildCSPHeader(cfg.GlobalDefaults)
	for _, svc := range discovered {
		filename := cspFileName(svc)
		if _, exists := files[filename]; exists {
			continue
		}

		if disabled {
			files[filename] = fmt.Sprintf("# CSP disabled globally for %s\n", svc)
			continue
		}

		// Check if this is a FQDN whose short name has an explicit override.
		if sc, ok := findParentServiceConfig(svc, cfg.Services); ok {
			files[filename] = generateServiceCSP(svc, sc, cfg.GlobalDefaults)
			continue
		}

		if globalHeader != "" {
			// Synthesize a "set + inherit" config so discovered services
			// get the global defaults applied.
			sc := CSPServiceConfig{Mode: "set", Inherit: true}
			files[filename] = generateServiceCSP(svc, sc, cfg.GlobalDefaults)
		} else {
			files[filename] = fmt.Sprintf("# CSP: no config for %s (global defaults empty)\n", svc)
		}
	}

	return files
}

// findParentServiceConfig checks if a FQDN service (e.g. "httpbun.erfi.io")
// has a parent short-name service (e.g. "httpbun") with an explicit config.
// Returns the config and true if found.
func findParentServiceConfig(fqdn string, services map[string]CSPServiceConfig) (CSPServiceConfig, bool) {
	dotIdx := strings.IndexByte(fqdn, '.')
	if dotIdx <= 0 {
		return CSPServiceConfig{}, false
	}
	shortName := fqdn[:dotIdx]
	sc, ok := services[shortName]
	return sc, ok
}

// generateServiceCSP builds the Caddy config snippet for a single service.
func generateServiceCSP(service string, sc CSPServiceConfig, globalDefaults CSPPolicy) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# CSP config for %s\n", service))
	sb.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))

	if sc.Mode == "none" {
		sb.WriteString("# Mode: none — no CSP header\n")
		return sb.String()
	}

	// Resolve the effective policy.
	var policy CSPPolicy
	if sc.Inherit {
		policy = mergeCSPPolicy(globalDefaults, sc.Policy)
	} else {
		policy = sc.Policy
	}

	header := buildCSPHeader(policy)
	if header == "" {
		sb.WriteString("# Empty policy — no CSP header emitted\n")
		return sb.String()
	}

	// Escape double quotes in the header value for Caddy.
	escapedHeader := strings.ReplaceAll(header, `"`, `\"`)

	// Choose header name based on report-only flag.
	headerName := "Content-Security-Policy"
	if sc.ReportOnly {
		headerName = "Content-Security-Policy-Report-Only"
	}

	// Choose Caddy prefix based on mode.
	prefix := ""
	if sc.Mode == "default" {
		prefix = "?"
	}

	sb.WriteString(fmt.Sprintf("header %s%s \"%s\"\n", prefix, headerName, escapedHeader))
	return sb.String()
}

// writeCSPFiles writes generated CSP config files to the output directory.
// Returns the list of written filenames. Cleans up stale *_csp.caddy files.
func writeCSPFiles(dir string, files map[string]string) ([]string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating CSP dir %s: %w", dir, err)
	}

	written := make([]string, 0, len(files))
	for filename, content := range files {
		path := filepath.Join(dir, filename)
		if err := atomicWriteFile(path, []byte(content), 0644); err != nil {
			return written, fmt.Errorf("writing %s: %w", path, err)
		}
		written = append(written, filename)
	}

	// Clean up stale CSP files not in the generated set.
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("warning: could not read CSP dir for cleanup: %v", err)
		return written, nil
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, "_csp.caddy") {
			continue
		}
		if _, exists := files[name]; !exists {
			path := filepath.Join(dir, name)
			if err := os.Remove(path); err != nil {
				log.Printf("warning: could not remove stale CSP file %s: %v", path, err)
			} else {
				log.Printf("removed stale CSP file: %s", name)
			}
		}
	}

	return written, nil
}

// scanCaddyfileCSPServices extracts service short names from CSP import lines
// in the Caddyfile. Returns unique service names (without the _csp suffix).
func scanCaddyfileCSPServices(caddyfilePath string) []string {
	if caddyfilePath == "" {
		return nil
	}
	data, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return nil
	}

	// Match patterns like: import /data/caddy/csp/sonarr_csp*.caddy
	var services []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "_csp") {
			continue
		}
		// Extract service name from the import path.
		// Pattern: import /path/to/<service>_csp*.caddy
		idx := strings.LastIndex(line, "/")
		if idx < 0 {
			continue
		}
		rest := line[idx+1:]
		cspIdx := strings.Index(rest, "_csp")
		if cspIdx <= 0 {
			continue
		}
		svc := rest[:cspIdx]
		if !seen[svc] {
			seen[svc] = true
			services = append(services, svc)
		}
	}
	return services
}

// ensureCSPDir creates the CSP output directory if it doesn't exist.
func ensureCSPDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}
