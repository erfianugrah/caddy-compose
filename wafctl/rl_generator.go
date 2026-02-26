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

// writeConditionMatchers writes Caddy matcher directives for conditions.
func writeConditionMatchers(b *strings.Builder, conditions []Condition, groupOp string) {
	if len(conditions) == 0 {
		return
	}

	// For AND logic (default): all matchers in one match block.
	// For OR logic: Caddy evaluates multiple match blocks as OR,
	// but since we're already inside a single match block, we use
	// expression matchers for OR. For simplicity in v1, we emit
	// all conditions in one block (AND behavior) — OR support
	// requires named matcher composition which is more complex.
	// TODO: OR grouping via multiple named matchers in future version.
	for _, c := range conditions {
		line := rlConditionToMatcher(c)
		if line != "" {
			b.WriteString("\t\t\t" + line + "\n")
		}
	}
}

// rlConditionToMatcher translates a Condition to a Caddy matcher line.
func rlConditionToMatcher(c Condition) string {
	switch c.Field {
	case "path":
		return rlPathMatcher(c)
	case "method":
		return rlMethodMatcher(c)
	case "ip":
		return rlIPMatcher(c)
	case "header":
		return rlHeaderMatcher(c)
	case "user_agent":
		return rlUserAgentMatcher(c)
	case "query":
		return rlQueryMatcher(c)
	case "uri_path":
		return rlURIPathMatcher(c)
	case "host":
		// Host matching is implicit in Caddy site blocks; skip.
		return ""
	case "country":
		// Country matching via Cf-Ipcountry header.
		return rlCountryMatcher(c)
	case "cookie":
		return rlCookieMatcher(c)
	case "referer":
		return rlRefererMatcher(c)
	case "http_version":
		return rlHTTPVersionMatcher(c)
	}
	return ""
}

func rlPathMatcher(c Condition) string {
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("path %s", c.Value)
	case "begins_with":
		v := c.Value
		if !strings.HasSuffix(v, "*") {
			v += "*"
		}
		return fmt.Sprintf("path %s", v)
	case "ends_with":
		return fmt.Sprintf("path *%s", c.Value)
	case "contains":
		return fmt.Sprintf("path *%s*", c.Value)
	case "regex":
		return fmt.Sprintf("path_regexp %s", c.Value)
	case "in":
		paths := strings.Join(splitPipe(c.Value), " ")
		return fmt.Sprintf("path %s", paths)
	case "neq":
		return fmt.Sprintf("not path %s", c.Value)
	}
	return ""
}

func rlMethodMatcher(c Condition) string {
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("method %s", c.Value)
	case "in":
		methods := strings.Join(splitPipe(c.Value), " ")
		return fmt.Sprintf("method %s", methods)
	case "neq":
		return fmt.Sprintf("not method %s", c.Value)
	}
	return ""
}

func rlIPMatcher(c Condition) string {
	switch c.Operator {
	case "eq", "ip_match":
		return fmt.Sprintf("remote_ip %s", c.Value)
	case "neq", "not_ip_match":
		return fmt.Sprintf("not remote_ip %s", c.Value)
	}
	return ""
}

func rlHeaderMatcher(c Condition) string {
	name, value := splitNamedField(c.Value)
	if name == "" {
		return ""
	}
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("header %s %s", name, value)
	case "contains":
		return fmt.Sprintf("header %s *%s*", name, value)
	case "regex":
		return fmt.Sprintf("header_regexp %s %s", name, value)
	}
	return ""
}

func rlUserAgentMatcher(c Condition) string {
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("header User-Agent %s", c.Value)
	case "contains":
		return fmt.Sprintf("header User-Agent *%s*", c.Value)
	case "regex":
		return fmt.Sprintf("header_regexp User-Agent %s", c.Value)
	}
	return ""
}

func rlQueryMatcher(c Condition) string {
	switch c.Operator {
	case "contains":
		// Caddy's query matcher does key=value matching. For substring matching,
		// use a wildcard pattern. This matches if any query param value contains the string.
		return fmt.Sprintf("query *%s*", c.Value)
	case "regex":
		// Caddy's query matcher doesn't support regex. Use an expression matcher instead.
		return fmt.Sprintf("expression {http.request.uri.query}.matches(%q)", c.Value)
	}
	return ""
}

func rlURIPathMatcher(c Condition) string {
	// uri_path is the same as path for Caddy matchers.
	return rlPathMatcher(Condition{Field: "path", Operator: c.Operator, Value: c.Value})
}

func rlCountryMatcher(c Condition) string {
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("header Cf-Ipcountry %s", c.Value)
	case "neq":
		return fmt.Sprintf("not header Cf-Ipcountry %s", c.Value)
	case "in":
		// Multiple countries as separate header matchers won't work with AND;
		// use expression matcher for OR across country values.
		countries := splitPipe(c.Value)
		if len(countries) == 1 {
			return fmt.Sprintf("header Cf-Ipcountry %s", countries[0])
		}
		// For multiple countries, use a Caddy expression.
		var parts []string
		for _, cc := range countries {
			parts = append(parts, fmt.Sprintf("{http.request.header.Cf-Ipcountry} == %q", cc))
		}
		return fmt.Sprintf("expression (%s)", strings.Join(parts, " || "))
	}
	return ""
}

func rlCookieMatcher(c Condition) string {
	name, value := splitNamedField(c.Value)
	if name == "" {
		return ""
	}
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("header Cookie *%s=%s*", name, value)
	case "neq":
		return fmt.Sprintf("not header Cookie *%s=%s*", name, value)
	case "contains":
		return fmt.Sprintf("header Cookie *%s=*%s*", name, value)
	case "regex":
		// Caddy header matcher doesn't support regex. Use expression.
		return fmt.Sprintf("expression {http.request.cookie.%s}.matches(%q)", name, value)
	}
	return ""
}

func rlRefererMatcher(c Condition) string {
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("header Referer %s", c.Value)
	case "neq":
		return fmt.Sprintf("not header Referer %s", c.Value)
	case "contains":
		return fmt.Sprintf("header Referer *%s*", c.Value)
	case "regex":
		return fmt.Sprintf("header_regexp Referer %s", c.Value)
	}
	return ""
}

func rlHTTPVersionMatcher(c Condition) string {
	// Caddy's `protocol` matcher matches HTTP version.
	// Valid values: "http/1.0", "http/1.1", "http/2", "h2c", "http/3"
	// CRS uses "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0" format.
	// Caddy uses lowercase: "http/1.0", "http/1.1", "http/2", "http/3"
	val := strings.ToLower(c.Value)
	// Normalize "http/2.0" → "http/2" (Caddy uses "http/2", not "http/2.0")
	if val == "http/2.0" {
		val = "http/2"
	}
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("protocol %s", val)
	case "neq":
		return fmt.Sprintf("not protocol %s", val)
	}
	return ""
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
		return "{http.request.remote.host}{http.request.uri.path}"
	case "client_ip+method":
		return "{http.request.remote.host}{http.request.method}"
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
	return "{http.request.remote.host}" // fallback
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
