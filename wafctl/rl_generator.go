package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// GenerateRateLimitConfigs produces per-service .caddy file content from the rule set.
// Returns a map of filename → content (e.g. "sonarr_rl.caddy" → "rate_limit { ... }").
// Also includes a cleanup list of filenames that SHOULD exist; writeRLFiles uses this
// to remove stale files for deleted services.
func GenerateRateLimitConfigs(rules []RateLimitRule, global RateLimitGlobalConfig, caddyfilePath string) map[string]string {
	// Group enabled rules by service.
	byService := make(map[string][]RateLimitRule)
	for _, r := range rules {
		if r.Enabled {
			byService[r.Service] = append(byService[r.Service], r)
		}
	}

	// Also discover all services from the Caddyfile to produce placeholder
	// files for services with no enabled rules (prevents Caddy import errors
	// if a glob expects a file to exist).
	if caddyfilePath != "" {
		for _, svc := range scanCaddyfileServices(caddyfilePath) {
			if _, ok := byService[svc]; !ok {
				byService[svc] = nil // nil = no enabled rules, produce comment-only file
			}
		}
	}

	files := make(map[string]string, len(byService))
	for service, svcRules := range byService {
		filename := rlFileName(service)
		files[filename] = generateServiceRL(service, svcRules, global)
	}
	return files
}

// rlFileName returns the rate limit file name for a service.
// Uses _rl suffix to prevent glob collisions (e.g. "caddy" vs "caddy-prometheus").
func rlFileName(service string) string {
	return service + "_rl.caddy"
}

// generateServiceRL generates the complete Caddyfile snippet for a single service.
func generateServiceRL(service string, rules []RateLimitRule, global RateLimitGlobalConfig) string {
	var b strings.Builder

	b.WriteString("# Managed by wafctl Rate Limit Policy Engine\n")
	b.WriteString(fmt.Sprintf("# Service: %s | Rules: %d | Updated: %s\n",
		service, len(rules), time.Now().UTC().Format(time.RFC3339)))

	if len(rules) == 0 {
		b.WriteString("# No enabled rate limit rules for this service\n")
		return b.String()
	}

	// Sort by priority (lower = first).
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	// Separate deny rules from log_only rules.
	var denyRules, logOnlyRules []RateLimitRule
	for _, r := range rules {
		if r.Action == "log_only" {
			logOnlyRules = append(logOnlyRules, r)
		} else {
			denyRules = append(denyRules, r)
		}
	}

	// Emit body_vars directive if any rules use body-based keys.
	// This must come before rate_limit so the placeholders are populated.
	writeBodyVarsBlock(&b, rules)

	// Generate the rate_limit block for deny rules.
	if len(denyRules) > 0 {
		b.WriteString("rate_limit {\n")
		for _, r := range denyRules {
			writeRLZone(&b, r)
		}
		// Global settings.
		if global.Jitter > 0 {
			b.WriteString(fmt.Sprintf("\tjitter %.2f\n", global.Jitter))
		}
		if global.SweepInterval != "" {
			b.WriteString(fmt.Sprintf("\tsweep_interval %s\n", global.SweepInterval))
		}
		if global.Distributed {
			b.WriteString("\tdistributed {\n")
			if global.ReadInterval != "" {
				b.WriteString(fmt.Sprintf("\t\tread_interval %s\n", global.ReadInterval))
			}
			if global.WriteInterval != "" {
				b.WriteString(fmt.Sprintf("\t\twrite_interval %s\n", global.WriteInterval))
			}
			if global.PurgeAge != "" {
				b.WriteString(fmt.Sprintf("\t\tpurge_age %s\n", global.PurgeAge))
			}
			b.WriteString("\t}\n")
		}
		b.WriteString("}\n")
	}

	// Generate log_only monitoring blocks.
	// These use named matchers and log directives instead of rate_limit.
	for _, r := range logOnlyRules {
		writeRLMonitorBlock(&b, r)
	}

	// Response headers: show the policy name for the service.
	// Use the last deny rule's rate for the X-RateLimit-Limit header.
	if len(denyRules) > 0 {
		last := denyRules[len(denyRules)-1]
		b.WriteString(fmt.Sprintf("header X-RateLimit-Limit \"%d\"\n", last.Events))
		b.WriteString(fmt.Sprintf("header X-RateLimit-Policy \"%d;w=%s;name=\\\"%s\\\"\"\n",
			last.Events, last.Window, rlZoneName(service, last.ID)))
	}

	return b.String()
}

// writeRLZone writes a single zone block inside a rate_limit directive.
func writeRLZone(b *strings.Builder, r RateLimitRule) {
	zoneName := rlZoneName(r.Service, r.ID)
	b.WriteString(fmt.Sprintf("\t# Rule: %q (%s)\n", r.Name, shortID(r.ID)))
	b.WriteString(fmt.Sprintf("\tzone %s {\n", zoneName))

	// Matchers.
	b.WriteString("\t\tmatch {\n")
	// Always exclude WebSocket upgrades.
	b.WriteString("\t\t\tnot header Connection *Upgrade*\n")
	// Condition-based matchers.
	writeConditionMatchers(b, r.Conditions, r.GroupOp)
	b.WriteString("\t\t}\n")

	// Key.
	b.WriteString(fmt.Sprintf("\t\tkey %s\n", rlKeyToPlaceholder(r.Key)))
	b.WriteString(fmt.Sprintf("\t\tevents %d\n", r.Events))
	b.WriteString(fmt.Sprintf("\t\twindow %s\n", r.Window))
	b.WriteString("\t}\n")
}

// writeRLMonitorBlock writes a log_only monitoring block using a named matcher.
// Instead of rate_limit (which would return 429), this logs matching requests
// with an X-RateLimit-Monitor header for analytics tracking.
func writeRLMonitorBlock(b *strings.Builder, r RateLimitRule) {
	matcherName := fmt.Sprintf("rl_monitor_%s", shortID(r.ID))
	b.WriteString(fmt.Sprintf("\n# Monitor rule: %q (log_only)\n", r.Name))
	b.WriteString(fmt.Sprintf("@%s {\n", matcherName))
	if len(r.Conditions) > 0 {
		writeConditionMatchers(b, r.Conditions, r.GroupOp)
	}
	b.WriteString("}\n")
	b.WriteString(fmt.Sprintf("header @%s X-RateLimit-Monitor \"%s\"\n", matcherName, r.Name))
}

// ─── Key Translation ────────────────────────────────────────────────

// rlKeyToPlaceholder translates a key descriptor to a Caddy placeholder string.
func rlKeyToPlaceholder(key string) string {
	switch key {
	case "client_ip", "":
		return "{http.request.remote.host}"
	case "path":
		return "{http.request.uri.path}"
	case "static":
		return "static"
	case "client_ip+path":
		return "{http.request.remote.host}_{http.request.uri.path}"
	case "client_ip+method":
		return "{http.request.remote.host}_{http.request.method}"
	}
	// header:X-API-Key → {http.request.header.X-API-Key}
	if strings.HasPrefix(key, "header:") {
		name := strings.TrimPrefix(key, "header:")
		return fmt.Sprintf("{http.request.header.%s}", name)
	}
	// cookie:session → {http.request.cookie.session}
	if strings.HasPrefix(key, "cookie:") {
		name := strings.TrimPrefix(key, "cookie:")
		return fmt.Sprintf("{http.request.cookie.%s}", name)
	}
	// body_json:.user.api_key → {http.vars.body_json.user.api_key}
	if strings.HasPrefix(key, "body_json:") {
		dotPath := strings.TrimPrefix(key, "body_json:")
		dotPath = strings.TrimPrefix(dotPath, ".") // normalize: strip leading dot
		return fmt.Sprintf("{http.vars.body_json.%s}", dotPath)
	}
	// body_form:action → {http.vars.body_form.action}
	if strings.HasPrefix(key, "body_form:") {
		field := strings.TrimPrefix(key, "body_form:")
		return fmt.Sprintf("{http.vars.body_form.%s}", field)
	}
	return "{http.request.remote.host}" // fallback
}

// ─── Body Vars Handler ──────────────────────────────────────────────

// writeBodyVarsBlock emits a body_vars { ... } directive if any rules
// use body_json: or body_form: keys. This handler must run before
// rate_limit so that placeholders like {http.vars.body_json.user.api_key}
// are available as rate limit bucket keys.
func writeBodyVarsBlock(b *strings.Builder, rules []RateLimitRule) {
	jsonPaths := make(map[string]bool)
	formFields := make(map[string]bool)

	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if strings.HasPrefix(r.Key, "body_json:") {
			dotPath := strings.TrimPrefix(r.Key, "body_json:")
			jsonPaths[dotPath] = true
		}
		if strings.HasPrefix(r.Key, "body_form:") {
			field := strings.TrimPrefix(r.Key, "body_form:")
			formFields[field] = true
		}
	}

	if len(jsonPaths) == 0 && len(formFields) == 0 {
		return
	}

	b.WriteString("body_vars {\n")

	// Sort for deterministic output.
	sortedJSON := make([]string, 0, len(jsonPaths))
	for p := range jsonPaths {
		sortedJSON = append(sortedJSON, p)
	}
	sort.Strings(sortedJSON)
	for _, p := range sortedJSON {
		b.WriteString(fmt.Sprintf("\tjson %s\n", p))
	}

	sortedForm := make([]string, 0, len(formFields))
	for f := range formFields {
		sortedForm = append(sortedForm, f)
	}
	sort.Strings(sortedForm)
	for _, f := range sortedForm {
		b.WriteString(fmt.Sprintf("\tform %s\n", f))
	}

	b.WriteString("}\n")
}

// ─── Helpers ────────────────────────────────────────────────────────

// rlZoneName generates a unique Caddy zone name from service + rule ID.
func rlZoneName(service, ruleID string) string {
	id := shortID(ruleID)
	return fmt.Sprintf("%s_%s", service, id)
}

// shortID returns the first 8 chars of an ID for use in zone names.
func shortID(id string) string {
	clean := strings.ReplaceAll(id, "-", "")
	if len(clean) > 8 {
		return clean[:8]
	}
	return clean
}

// splitNamedField splits a "Name:value" string into name and value parts.
func splitNamedField(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// ─── File Writer ────────────────────────────────────────────────────

// writeRLFiles writes all generated .caddy files to the rate limit directory
// and removes stale files that are no longer in the generated set.
// Returns the list of files written.
func writeRLFiles(dir string, files map[string]string) ([]string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating rate limit dir %s: %w", dir, err)
	}

	var written []string
	for filename, content := range files {
		path := filepath.Join(dir, filename)
		if err := atomicWriteFile(path, []byte(content), 0644); err != nil {
			return written, fmt.Errorf("writing RL file %s: %w", path, err)
		}
		written = append(written, path)
	}

	// Clean up stale files: remove any *_rl.caddy files not in the generated set.
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasSuffix(name, "_rl.caddy") {
				if _, ok := files[name]; !ok {
					stalePath := filepath.Join(dir, name)
					if err := os.Remove(stalePath); err != nil {
						log.Printf("warning: could not remove stale RL file %s: %v", stalePath, err)
					} else {
						log.Printf("removed stale RL file: %s", stalePath)
					}
				}
			}
		}
	}

	return written, nil
}
