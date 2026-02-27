package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── Key Translation ────────────────────────────────────────────────

func TestRLKeyToPlaceholder(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"client_ip", "{http.request.remote.host}"},
		{"", "{http.request.remote.host}"},
		{"path", "{http.request.uri.path}"},
		{"static", "static"},
		{"client_ip+path", "{http.request.remote.host}{http.request.uri.path}"},
		{"client_ip+method", "{http.request.remote.host}{http.request.method}"},
		{"header:X-API-Key", "{http.request.header.X-API-Key}"},
		{"cookie:session", "{http.request.cookie.session}"},
		{"body_json:.user.api_key", "{http.vars.body_json.user.api_key}"},
		{"body_json:user.role", "{http.vars.body_json.user.role}"},
		{"body_json:.tenant.id", "{http.vars.body_json.tenant.id}"},
		{"body_form:action", "{http.vars.body_form.action}"},
		{"body_form:token", "{http.vars.body_form.token}"},
		{"unknown", "{http.request.remote.host}"}, // fallback
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := rlKeyToPlaceholder(tt.key)
			if got != tt.want {
				t.Errorf("rlKeyToPlaceholder(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

// ─── Zone Name ──────────────────────────────────────────────────────

func TestRLZoneName(t *testing.T) {
	// Zone names use first 8 chars of ID (dashes removed).
	got := rlZoneName("sonarr", "abcd1234-ef56-7890-abcd-ef1234567890")
	if !strings.HasPrefix(got, "sonarr_") {
		t.Errorf("zone name should start with sonarr_, got %q", got)
	}
	if len(got) > 20 {
		t.Errorf("zone name too long: %q", got)
	}
}

func TestShortID(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"abcd1234-ef56-7890-abcd-ef1234567890", "abcd1234"},
		{"12345678", "12345678"},
		{"short", "short"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := shortID(tt.id)
			if got != tt.want {
				t.Errorf("shortID(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

// ─── File Name ──────────────────────────────────────────────────────

func TestRLFileName(t *testing.T) {
	if got := rlFileName("sonarr"); got != "sonarr_rl.caddy" {
		t.Errorf("want %q, got %q", "sonarr_rl.caddy", got)
	}
}

// ─── splitNamedField ────────────────────────────────────────────────

func TestSplitNamedField(t *testing.T) {
	tests := []struct {
		input     string
		wantName  string
		wantValue string
	}{
		{"X-API-Key:abc123", "X-API-Key", "abc123"},
		{"User-Agent", "User-Agent", ""},
		{"Cookie:session=xyz", "Cookie", "session=xyz"}, // only first colon splits
		{"", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, value := splitNamedField(tt.input)
			if name != tt.wantName || value != tt.wantValue {
				t.Errorf("splitNamedField(%q) = (%q, %q), want (%q, %q)",
					tt.input, name, value, tt.wantName, tt.wantValue)
			}
		})
	}
}

// ─── Condition → Matcher ────────────────────────────────────────────

func TestRLConditionToMatcher(t *testing.T) {
	tests := []struct {
		name string
		cond Condition
		want string
	}{
		{
			name: "path eq",
			cond: Condition{Field: "path", Operator: "eq", Value: "/api/v3"},
			want: "path /api/v3",
		},
		{
			name: "path begins_with",
			cond: Condition{Field: "path", Operator: "begins_with", Value: "/api"},
			want: "path /api*",
		},
		{
			name: "path begins_with already has wildcard",
			cond: Condition{Field: "path", Operator: "begins_with", Value: "/api*"},
			want: "path /api*",
		},
		{
			name: "path ends_with",
			cond: Condition{Field: "path", Operator: "ends_with", Value: ".json"},
			want: "path *.json",
		},
		{
			name: "path contains",
			cond: Condition{Field: "path", Operator: "contains", Value: "admin"},
			want: "path *admin*",
		},
		{
			name: "path regex",
			cond: Condition{Field: "path", Operator: "regex", Value: "^/api/v[0-9]+"},
			want: "path_regexp ^/api/v[0-9]+",
		},
		{
			name: "path in (pipe-separated)",
			cond: Condition{Field: "path", Operator: "in", Value: "/api|/admin"},
			want: "path /api /admin",
		},
		{
			name: "path neq",
			cond: Condition{Field: "path", Operator: "neq", Value: "/health"},
			want: "not path /health",
		},
		{
			name: "method eq",
			cond: Condition{Field: "method", Operator: "eq", Value: "POST"},
			want: "method POST",
		},
		{
			name: "method in",
			cond: Condition{Field: "method", Operator: "in", Value: "POST|PUT|DELETE"},
			want: "method POST PUT DELETE",
		},
		{
			name: "method neq",
			cond: Condition{Field: "method", Operator: "neq", Value: "GET"},
			want: "not method GET",
		},
		{
			name: "ip eq",
			cond: Condition{Field: "ip", Operator: "eq", Value: "10.0.0.1"},
			want: "remote_ip 10.0.0.1",
		},
		{
			name: "ip ip_match",
			cond: Condition{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
			want: "remote_ip 10.0.0.0/8",
		},
		{
			name: "ip neq",
			cond: Condition{Field: "ip", Operator: "neq", Value: "10.0.0.1"},
			want: "not remote_ip 10.0.0.1",
		},
		{
			name: "header eq",
			cond: Condition{Field: "header", Operator: "eq", Value: "X-API-Key:abc123"},
			want: "header X-API-Key abc123",
		},
		{
			name: "header contains",
			cond: Condition{Field: "header", Operator: "contains", Value: "X-Test:partial"},
			want: "header X-Test *partial*",
		},
		{
			name: "header regex",
			cond: Condition{Field: "header", Operator: "regex", Value: "Authorization:^Bearer "},
			want: "header_regexp Authorization ^Bearer ",
		},
		{
			name: "header empty name",
			cond: Condition{Field: "header", Operator: "eq", Value: ""},
			want: "",
		},
		{
			name: "user_agent eq",
			cond: Condition{Field: "user_agent", Operator: "eq", Value: "curl/7.68"},
			want: "header User-Agent curl/7.68",
		},
		{
			name: "user_agent contains",
			cond: Condition{Field: "user_agent", Operator: "contains", Value: "Bot"},
			want: "header User-Agent *Bot*",
		},
		{
			name: "user_agent regex",
			cond: Condition{Field: "user_agent", Operator: "regex", Value: "(?i)bot"},
			want: "header_regexp User-Agent (?i)bot",
		},
		{
			name: "query contains",
			cond: Condition{Field: "query", Operator: "contains", Value: "debug=true"},
			want: "query *debug=true*",
		},
		{
			name: "query regex uses expression",
			cond: Condition{Field: "query", Operator: "regex", Value: "token=[a-f0-9]+"},
			want: `expression {http.request.uri.query}.matches("token=[a-f0-9]+")`,
		},
		{
			name: "uri_path delegates to path",
			cond: Condition{Field: "uri_path", Operator: "eq", Value: "/test"},
			want: "path /test",
		},
		{
			name: "country eq",
			cond: Condition{Field: "country", Operator: "eq", Value: "CN"},
			want: "header Cf-Ipcountry CN",
		},
		{
			name: "country neq",
			cond: Condition{Field: "country", Operator: "neq", Value: "US"},
			want: "not header Cf-Ipcountry US",
		},
		{
			name: "country in single",
			cond: Condition{Field: "country", Operator: "in", Value: "CN"},
			want: "header Cf-Ipcountry CN",
		},
		{
			name: "country in multi",
			cond: Condition{Field: "country", Operator: "in", Value: "CN|RU|KP"},
			want: `expression ({http.request.header.Cf-Ipcountry} == "CN" || {http.request.header.Cf-Ipcountry} == "RU" || {http.request.header.Cf-Ipcountry} == "KP")`,
		},
		{
			name: "cookie eq",
			cond: Condition{Field: "cookie", Operator: "eq", Value: "session:abc"},
			want: "header Cookie *session=abc*",
		},
		{
			name: "cookie neq",
			cond: Condition{Field: "cookie", Operator: "neq", Value: "session:abc"},
			want: "not header Cookie *session=abc*",
		},
		{
			name: "cookie contains",
			cond: Condition{Field: "cookie", Operator: "contains", Value: "token:xyz"},
			want: "header Cookie *token=*xyz*",
		},
		{
			name: "cookie regex uses expression",
			cond: Condition{Field: "cookie", Operator: "regex", Value: "authelia_session:^[a-f0-9]+$"},
			want: `expression {http.request.cookie.authelia_session}.matches("^[a-f0-9]+$")`,
		},
		{
			name: "referer eq",
			cond: Condition{Field: "referer", Operator: "eq", Value: "https://evil.com"},
			want: "header Referer https://evil.com",
		},
		{
			name: "referer neq",
			cond: Condition{Field: "referer", Operator: "neq", Value: "https://good.com"},
			want: "not header Referer https://good.com",
		},
		{
			name: "referer contains",
			cond: Condition{Field: "referer", Operator: "contains", Value: "evil"},
			want: "header Referer *evil*",
		},
		{
			name: "referer regex",
			cond: Condition{Field: "referer", Operator: "regex", Value: "https?://evil"},
			want: "header_regexp Referer https?://evil",
		},
		{
			name: "http_version eq",
			cond: Condition{Field: "http_version", Operator: "eq", Value: "HTTP/1.1"},
			want: "protocol http/1.1",
		},
		{
			name: "http_version neq",
			cond: Condition{Field: "http_version", Operator: "neq", Value: "HTTP/1.0"},
			want: "not protocol http/1.0",
		},
		{
			name: "http_version normalizes 2.0 to 2",
			cond: Condition{Field: "http_version", Operator: "eq", Value: "HTTP/2.0"},
			want: "protocol http/2",
		},
		{
			name: "host is skipped",
			cond: Condition{Field: "host", Operator: "eq", Value: "example.com"},
			want: "",
		},
		{
			name: "unknown field",
			cond: Condition{Field: "nonexistent", Operator: "eq", Value: "test"},
			want: "",
		},
		// --- Body matchers (caddy-body-matcher plugin) ---
		{
			name: "body contains",
			cond: Condition{Field: "body", Operator: "contains", Value: "password"},
			want: `body contains "password"`,
		},
		{
			name: "body eq",
			cond: Condition{Field: "body", Operator: "eq", Value: "exact"},
			want: `body eq "exact"`,
		},
		{
			name: "body begins_with",
			cond: Condition{Field: "body", Operator: "begins_with", Value: "{\"type\":"},
			want: `body starts_with "{\"type\":"`,
		},
		{
			name: "body ends_with",
			cond: Condition{Field: "body", Operator: "ends_with", Value: "</html>"},
			want: `body ends_with "</html>"`,
		},
		{
			name: "body regex",
			cond: Condition{Field: "body", Operator: "regex", Value: "password=.*"},
			want: `body regex "password=.*"`,
		},
		{
			name: "body_json eq",
			cond: Condition{Field: "body_json", Operator: "eq", Value: ".user.role:admin"},
			want: `body json .user.role "admin"`,
		},
		{
			name: "body_json contains",
			cond: Condition{Field: "body_json", Operator: "contains", Value: ".name:test"},
			want: `body json_contains .name "test"`,
		},
		{
			name: "body_json regex",
			cond: Condition{Field: "body_json", Operator: "regex", Value: ".email:^[a-z]+@"},
			want: `body json_regex .email "^[a-z]+@"`,
		},
		{
			name: "body_json exists",
			cond: Condition{Field: "body_json", Operator: "exists", Value: ".token:"},
			want: "body json_exists .token",
		},
		{
			name: "body_json without leading dot",
			cond: Condition{Field: "body_json", Operator: "eq", Value: "user.role:admin"},
			want: `body json .user.role "admin"`,
		},
		{
			name: "body_json empty name",
			cond: Condition{Field: "body_json", Operator: "eq", Value: ""},
			want: "",
		},
		{
			name: "body_form eq",
			cond: Condition{Field: "body_form", Operator: "eq", Value: "action:delete"},
			want: `body form action "delete"`,
		},
		{
			name: "body_form contains",
			cond: Condition{Field: "body_form", Operator: "contains", Value: "query:SELECT"},
			want: `body form_contains query "SELECT"`,
		},
		{
			name: "body_form regex",
			cond: Condition{Field: "body_form", Operator: "regex", Value: "cmd:^ls\\s"},
			want: `body form_regex cmd "^ls\\s"`,
		},
		{
			name: "body_form empty name",
			cond: Condition{Field: "body_form", Operator: "eq", Value: ""},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rlConditionToMatcher(tt.cond)
			if got != tt.want {
				t.Errorf("rlConditionToMatcher(%+v) = %q, want %q", tt.cond, got, tt.want)
			}
		})
	}
}

// ─── Full Generator ─────────────────────────────────────────────────

func TestGenerateRateLimitConfigsEmpty(t *testing.T) {
	files := GenerateRateLimitConfigs(nil, RateLimitGlobalConfig{}, "")
	if len(files) != 0 {
		t.Fatalf("want 0 files for nil rules, got %d", len(files))
	}
}

func TestGenerateRateLimitConfigsBasicDeny(t *testing.T) {
	rules := []RateLimitRule{
		{
			ID: "test-id-1234", Name: "api-limit", Service: "sonarr",
			Key: "client_ip", Events: 100, Window: "1m",
			Action: "deny", Enabled: true,
		},
	}

	files := GenerateRateLimitConfigs(rules, RateLimitGlobalConfig{}, "")
	content, ok := files["sonarr_rl.caddy"]
	if !ok {
		t.Fatal("want sonarr_rl.caddy in output")
	}

	// Should contain rate_limit block.
	if !strings.Contains(content, "rate_limit {") {
		t.Error("want rate_limit block in output")
	}
	// Should contain zone.
	if !strings.Contains(content, "zone sonarr_") {
		t.Error("want zone declaration")
	}
	// Should contain events and window.
	if !strings.Contains(content, "events 100") {
		t.Error("want events 100")
	}
	if !strings.Contains(content, "window 1m") {
		t.Error("want window 1m")
	}
	// Should contain key placeholder.
	if !strings.Contains(content, "key {http.request.remote.host}") {
		t.Error("want client_ip key placeholder")
	}
	// Should exclude WebSocket.
	if !strings.Contains(content, "not header Connection *Upgrade*") {
		t.Error("want WebSocket exclusion matcher")
	}
	// Should have response headers.
	if !strings.Contains(content, "header X-RateLimit-Limit") {
		t.Error("want X-RateLimit-Limit header")
	}
}

func TestGenerateRateLimitConfigsLogOnly(t *testing.T) {
	rules := []RateLimitRule{
		{
			ID: "monitor-id-5678", Name: "api-monitor", Service: "sonarr",
			Key: "client_ip", Events: 100, Window: "1m",
			Action: "log_only", Enabled: true,
		},
	}

	files := GenerateRateLimitConfigs(rules, RateLimitGlobalConfig{}, "")
	content := files["sonarr_rl.caddy"]

	// log_only should NOT produce a rate_limit block.
	if strings.Contains(content, "rate_limit {") {
		t.Error("log_only should not produce rate_limit block")
	}
	// Should produce a named matcher + header.
	if !strings.Contains(content, "@rl_monitor_") {
		t.Error("want named matcher for monitor block")
	}
	if !strings.Contains(content, "X-RateLimit-Monitor") {
		t.Error("want X-RateLimit-Monitor header")
	}
}

func TestGenerateRateLimitConfigsMixed(t *testing.T) {
	rules := []RateLimitRule{
		{
			ID: "deny-id", Name: "deny-rule", Service: "sonarr",
			Key: "client_ip", Events: 100, Window: "1m",
			Action: "deny", Enabled: true, Priority: 0,
		},
		{
			ID: "monitor-id", Name: "monitor-rule", Service: "sonarr",
			Key: "client_ip", Events: 50, Window: "30s",
			Action: "log_only", Enabled: true, Priority: 1,
		},
	}

	files := GenerateRateLimitConfigs(rules, RateLimitGlobalConfig{}, "")
	content := files["sonarr_rl.caddy"]

	// Should have both rate_limit block and monitor block.
	if !strings.Contains(content, "rate_limit {") {
		t.Error("want rate_limit block for deny rule")
	}
	if !strings.Contains(content, "X-RateLimit-Monitor") {
		t.Error("want monitor block for log_only rule")
	}
}

func TestGenerateRateLimitConfigsDisabledSkipped(t *testing.T) {
	rules := []RateLimitRule{
		{
			ID: "disabled-id", Name: "disabled", Service: "sonarr",
			Key: "client_ip", Events: 100, Window: "1m",
			Action: "deny", Enabled: false,
		},
	}

	files := GenerateRateLimitConfigs(rules, RateLimitGlobalConfig{}, "")
	if len(files) != 0 {
		t.Fatalf("want 0 files for disabled-only rules, got %d", len(files))
	}
}

func TestGenerateRateLimitConfigsGlobalSettings(t *testing.T) {
	rules := []RateLimitRule{
		{
			ID: "test-id", Name: "test", Service: "sonarr",
			Key: "client_ip", Events: 100, Window: "1m",
			Action: "deny", Enabled: true,
		},
	}
	global := RateLimitGlobalConfig{
		Jitter:        0.5,
		SweepInterval: "30s",
		Distributed:   true,
		ReadInterval:  "5s",
		WriteInterval: "10s",
		PurgeAge:      "1m",
	}

	files := GenerateRateLimitConfigs(rules, global, "")
	content := files["sonarr_rl.caddy"]

	if !strings.Contains(content, "jitter 0.50") {
		t.Errorf("want jitter in output:\n%s", content)
	}
	if !strings.Contains(content, "sweep_interval 30s") {
		t.Error("want sweep_interval")
	}
	if !strings.Contains(content, "distributed {") {
		t.Error("want distributed block")
	}
	if !strings.Contains(content, "read_interval 5s") {
		t.Error("want read_interval")
	}
	if !strings.Contains(content, "write_interval 10s") {
		t.Error("want write_interval")
	}
	if !strings.Contains(content, "purge_age 1m") {
		t.Error("want purge_age")
	}
}

func TestGenerateRateLimitConfigsWithConditions(t *testing.T) {
	rules := []RateLimitRule{
		{
			ID: "cond-id", Name: "api-only", Service: "sonarr",
			Key: "client_ip", Events: 100, Window: "1m",
			Action: "deny", Enabled: true,
			Conditions: []Condition{
				{Field: "path", Operator: "begins_with", Value: "/api"},
				{Field: "method", Operator: "in", Value: "POST|PUT"},
			},
		},
	}

	files := GenerateRateLimitConfigs(rules, RateLimitGlobalConfig{}, "")
	content := files["sonarr_rl.caddy"]

	if !strings.Contains(content, "path /api*") {
		t.Errorf("want path matcher in output:\n%s", content)
	}
	if !strings.Contains(content, "method POST PUT") {
		t.Errorf("want method matcher in output:\n%s", content)
	}
}

func TestGenerateRateLimitConfigsMultiService(t *testing.T) {
	rules := []RateLimitRule{
		{
			ID: "id1", Name: "sonarr-limit", Service: "sonarr",
			Key: "client_ip", Events: 100, Window: "1m",
			Action: "deny", Enabled: true,
		},
		{
			ID: "id2", Name: "radarr-limit", Service: "radarr",
			Key: "client_ip", Events: 200, Window: "30s",
			Action: "deny", Enabled: true,
		},
	}

	files := GenerateRateLimitConfigs(rules, RateLimitGlobalConfig{}, "")
	if len(files) != 2 {
		t.Fatalf("want 2 files, got %d", len(files))
	}
	if _, ok := files["sonarr_rl.caddy"]; !ok {
		t.Error("want sonarr_rl.caddy")
	}
	if _, ok := files["radarr_rl.caddy"]; !ok {
		t.Error("want radarr_rl.caddy")
	}
}

func TestGenerateRateLimitConfigsCaddyfileDiscovery(t *testing.T) {
	dir := t.TempDir()
	caddyfile := filepath.Join(dir, "Caddyfile")
	content := "prowlarr.erfi.io {\n\timport /data/caddy/rl/prowlarr_rl*.caddy\n}\n"
	os.WriteFile(caddyfile, []byte(content), 0644)

	// No rules for prowlarr — should still produce a placeholder file.
	files := GenerateRateLimitConfigs(nil, RateLimitGlobalConfig{}, caddyfile)
	fc, ok := files["prowlarr_rl.caddy"]
	if !ok {
		t.Fatal("want prowlarr_rl.caddy from Caddyfile discovery")
	}
	if !strings.Contains(fc, "No enabled rate limit rules") {
		t.Error("want comment-only placeholder content")
	}
}

// ─── Priority Sorting ───────────────────────────────────────────────

func TestGenerateRateLimitConfigsPrioritySorted(t *testing.T) {
	rules := []RateLimitRule{
		{
			ID: "low-prio", Name: "low", Service: "sonarr",
			Key: "client_ip", Events: 100, Window: "1m",
			Action: "deny", Enabled: true, Priority: 10,
		},
		{
			ID: "high-prio", Name: "high", Service: "sonarr",
			Key: "client_ip", Events: 50, Window: "30s",
			Action: "deny", Enabled: true, Priority: 1,
		},
	}

	files := GenerateRateLimitConfigs(rules, RateLimitGlobalConfig{}, "")
	content := files["sonarr_rl.caddy"]

	// "high" should appear before "low" in the output.
	highIdx := strings.Index(content, `"high"`)
	lowIdx := strings.Index(content, `"low"`)
	if highIdx < 0 || lowIdx < 0 {
		t.Fatalf("both rules should be in output:\n%s", content)
	}
	if highIdx >= lowIdx {
		t.Errorf("high priority rule should appear first (highIdx=%d, lowIdx=%d)", highIdx, lowIdx)
	}
}

// ─── writeRLFiles ───────────────────────────────────────────────────

func TestWriteRLFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rl")

	files := map[string]string{
		"sonarr_rl.caddy": "# sonarr config\n",
		"radarr_rl.caddy": "# radarr config\n",
	}

	written, err := writeRLFiles(dir, files)
	if err != nil {
		t.Fatalf("writeRLFiles: %v", err)
	}
	if len(written) != 2 {
		t.Fatalf("want 2 written, got %d", len(written))
	}

	// Verify file contents.
	for filename, want := range files {
		data, err := os.ReadFile(filepath.Join(dir, filename))
		if err != nil {
			t.Fatalf("reading %s: %v", filename, err)
		}
		if string(data) != want {
			t.Errorf("%s: want %q, got %q", filename, want, string(data))
		}
	}
}

func TestWriteRLFilesCleanupStale(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rl")
	os.MkdirAll(dir, 0755)

	// Pre-create a stale file.
	stalePath := filepath.Join(dir, "old_service_rl.caddy")
	os.WriteFile(stalePath, []byte("stale"), 0644)

	// Write only sonarr — old_service should be cleaned up.
	files := map[string]string{
		"sonarr_rl.caddy": "# sonarr\n",
	}
	writeRLFiles(dir, files)

	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Error("stale file should have been removed")
	}

	// Non-RL files should be left alone.
	otherPath := filepath.Join(dir, "other.conf")
	os.WriteFile(otherPath, []byte("keep"), 0644)
	writeRLFiles(dir, files)
	if _, err := os.Stat(otherPath); os.IsNotExist(err) {
		t.Error("non-RL files should not be removed")
	}
}

func TestWriteRLFilesCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "rl")
	files := map[string]string{
		"test_rl.caddy": "# test\n",
	}
	_, err := writeRLFiles(dir, files)
	if err != nil {
		t.Fatalf("writeRLFiles should create directory: %v", err)
	}
}

// ─── Analytics: matchRLCondition ────────────────────────────────────

func TestMatchRLCondition(t *testing.T) {
	evt := RateLimitEvent{
		ClientIP:  "10.0.0.1",
		Service:   "sonarr.erfi.io",
		URI:       "/api/v3/queue",
		Method:    "GET",
		UserAgent: "curl/7.68",
		Country:   "US",
	}

	tests := []struct {
		name string
		cond Condition
		want bool
	}{
		{"path eq match", Condition{Field: "path", Operator: "eq", Value: "/api/v3/queue"}, true},
		{"path eq no match", Condition{Field: "path", Operator: "eq", Value: "/other"}, false},
		{"path begins_with match", Condition{Field: "path", Operator: "begins_with", Value: "/api"}, true},
		{"path ends_with match", Condition{Field: "path", Operator: "ends_with", Value: "/queue"}, true},
		{"path contains match", Condition{Field: "path", Operator: "contains", Value: "v3"}, true},
		{"path regex match", Condition{Field: "path", Operator: "regex", Value: "^/api/v[0-9]+"}, true},
		{"path in match", Condition{Field: "path", Operator: "in", Value: "/api/v3/queue|/other"}, true},
		{"path in no match", Condition{Field: "path", Operator: "in", Value: "/a|/b"}, false},
		{"path neq match", Condition{Field: "path", Operator: "neq", Value: "/other"}, true},
		{"path neq no match", Condition{Field: "path", Operator: "neq", Value: "/api/v3/queue"}, false},
		{"method eq match", Condition{Field: "method", Operator: "eq", Value: "GET"}, true},
		{"method eq no match", Condition{Field: "method", Operator: "eq", Value: "POST"}, false},
		{"ip eq match", Condition{Field: "ip", Operator: "eq", Value: "10.0.0.1"}, true},
		{"ip neq match", Condition{Field: "ip", Operator: "neq", Value: "192.168.1.1"}, true},
		{"ip ip_match", Condition{Field: "ip", Operator: "ip_match", Value: "10.0.0.1"}, true},
		{"ip not_ip_match", Condition{Field: "ip", Operator: "not_ip_match", Value: "10.0.0.1"}, false},
		{"host eq match", Condition{Field: "host", Operator: "eq", Value: "sonarr.erfi.io"}, true},
		{"user_agent contains match", Condition{Field: "user_agent", Operator: "contains", Value: "curl"}, true},
		{"country eq match", Condition{Field: "country", Operator: "eq", Value: "US"}, true},
		{"country in match", Condition{Field: "country", Operator: "in", Value: "US|CA"}, true},
		{"country in no match", Condition{Field: "country", Operator: "in", Value: "CN|RU"}, false},
		{"uri_path delegates to path", Condition{Field: "uri_path", Operator: "eq", Value: "/api/v3/queue"}, true},
		{"unknown field", Condition{Field: "nonexistent", Operator: "contains", Value: "test"}, false},
		{"regex invalid", Condition{Field: "path", Operator: "regex", Value: "[invalid"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchRLCondition(evt, tt.cond)
			if got != tt.want {
				t.Errorf("matchRLCondition(%+v) = %v, want %v", tt.cond, got, tt.want)
			}
		})
	}
}

func TestMatchRLConditionsAND(t *testing.T) {
	evt := RateLimitEvent{
		ClientIP: "10.0.0.1",
		URI:      "/api/v3/queue",
		Method:   "GET",
		Service:  "sonarr.erfi.io",
	}

	// Both match → true.
	conditions := []Condition{
		{Field: "path", Operator: "begins_with", Value: "/api"},
		{Field: "method", Operator: "eq", Value: "GET"},
	}
	if !matchRLConditions(evt, conditions, "and") {
		t.Error("AND: both conditions match, want true")
	}

	// One doesn't match → false.
	conditions[1].Value = "POST"
	if matchRLConditions(evt, conditions, "and") {
		t.Error("AND: one condition fails, want false")
	}
}

func TestMatchRLConditionsOR(t *testing.T) {
	evt := RateLimitEvent{
		ClientIP: "10.0.0.1",
		URI:      "/api/v3/queue",
		Method:   "GET",
		Service:  "sonarr.erfi.io",
	}

	// One matches → true.
	conditions := []Condition{
		{Field: "method", Operator: "eq", Value: "POST"},        // no match
		{Field: "path", Operator: "begins_with", Value: "/api"}, // match
	}
	if !matchRLConditions(evt, conditions, "or") {
		t.Error("OR: one condition matches, want true")
	}

	// None match → false.
	conditions = []Condition{
		{Field: "method", Operator: "eq", Value: "POST"},
		{Field: "path", Operator: "eq", Value: "/other"},
	}
	if matchRLConditions(evt, conditions, "or") {
		t.Error("OR: no conditions match, want false")
	}
}

func TestMatchRLConditionsDefaultIsAND(t *testing.T) {
	evt := RateLimitEvent{
		URI:    "/api",
		Method: "GET",
	}
	conditions := []Condition{
		{Field: "path", Operator: "eq", Value: "/api"},
		{Field: "method", Operator: "eq", Value: "POST"}, // no match
	}
	// Default (empty string) should be AND.
	if matchRLConditions(evt, conditions, "") {
		t.Error("default group_op should be AND, one fails → want false")
	}
}

// ─── matchEventToRule ───────────────────────────────────────────────

func TestMatchEventToRule(t *testing.T) {
	rules := []RateLimitRule{
		{
			Name: "api-limit", Service: "sonarr.erfi.io", Enabled: true, Priority: 0,
			Conditions: []Condition{
				{Field: "path", Operator: "begins_with", Value: "/api"},
			},
		},
		{
			Name: "catchall", Service: "sonarr.erfi.io", Enabled: true, Priority: 10,
		},
	}

	t.Run("matches first rule", func(t *testing.T) {
		evt := RateLimitEvent{Service: "sonarr.erfi.io", URI: "/api/v3/queue"}
		got := matchEventToRule(evt, rules)
		if got != "api-limit" {
			t.Errorf("want %q, got %q", "api-limit", got)
		}
	})

	t.Run("falls through to catchall", func(t *testing.T) {
		evt := RateLimitEvent{Service: "sonarr.erfi.io", URI: "/login"}
		got := matchEventToRule(evt, rules)
		if got != "catchall" {
			t.Errorf("want %q, got %q", "catchall", got)
		}
	})

	t.Run("service mismatch", func(t *testing.T) {
		evt := RateLimitEvent{Service: "radarr.erfi.io", URI: "/api/v3"}
		got := matchEventToRule(evt, rules)
		if got != "" {
			t.Errorf("want empty, got %q", got)
		}
	})

	t.Run("wildcard service", func(t *testing.T) {
		wildcardRules := []RateLimitRule{
			{Name: "global", Service: "*", Enabled: true},
		}
		evt := RateLimitEvent{Service: "anything.io", URI: "/test"}
		got := matchEventToRule(evt, wildcardRules)
		if got != "global" {
			t.Errorf("want %q, got %q", "global", got)
		}
	})

	t.Run("disabled rule skipped", func(t *testing.T) {
		disabledRules := []RateLimitRule{
			{Name: "disabled", Service: "sonarr.erfi.io", Enabled: false},
		}
		evt := RateLimitEvent{Service: "sonarr.erfi.io"}
		got := matchEventToRule(evt, disabledRules)
		if got != "" {
			t.Errorf("want empty for disabled rule, got %q", got)
		}
	})
}

// ─── Body Vars Block Generation ─────────────────────────────────────

func TestWriteBodyVarsBlock(t *testing.T) {
	t.Run("no body keys", func(t *testing.T) {
		rules := []RateLimitRule{
			{Key: "client_ip", Enabled: true},
			{Key: "header:X-API-Key", Enabled: true},
		}
		var b strings.Builder
		writeBodyVarsBlock(&b, rules)
		if b.String() != "" {
			t.Errorf("expected empty output for non-body keys, got %q", b.String())
		}
	})

	t.Run("json key only", func(t *testing.T) {
		rules := []RateLimitRule{
			{Key: "body_json:.user.api_key", Enabled: true},
		}
		var b strings.Builder
		writeBodyVarsBlock(&b, rules)
		got := b.String()
		if !strings.Contains(got, "body_vars {") {
			t.Errorf("expected body_vars block, got %q", got)
		}
		if !strings.Contains(got, "json .user.api_key") {
			t.Errorf("expected json .user.api_key, got %q", got)
		}
		if strings.Contains(got, "form ") {
			t.Errorf("expected no form directive, got %q", got)
		}
	})

	t.Run("form key only", func(t *testing.T) {
		rules := []RateLimitRule{
			{Key: "body_form:action", Enabled: true},
		}
		var b strings.Builder
		writeBodyVarsBlock(&b, rules)
		got := b.String()
		if !strings.Contains(got, "body_vars {") {
			t.Errorf("expected body_vars block, got %q", got)
		}
		if !strings.Contains(got, "form action") {
			t.Errorf("expected form action, got %q", got)
		}
		if strings.Contains(got, "json ") {
			t.Errorf("expected no json directive, got %q", got)
		}
	})

	t.Run("mixed json and form keys", func(t *testing.T) {
		rules := []RateLimitRule{
			{Key: "body_json:.user.api_key", Enabled: true},
			{Key: "body_form:token", Enabled: true},
			{Key: "body_json:.tenant.id", Enabled: true},
		}
		var b strings.Builder
		writeBodyVarsBlock(&b, rules)
		got := b.String()
		if !strings.Contains(got, "json .tenant.id") {
			t.Errorf("expected json .tenant.id, got %q", got)
		}
		if !strings.Contains(got, "json .user.api_key") {
			t.Errorf("expected json .user.api_key, got %q", got)
		}
		if !strings.Contains(got, "form token") {
			t.Errorf("expected form token, got %q", got)
		}
	})

	t.Run("disabled rules ignored", func(t *testing.T) {
		rules := []RateLimitRule{
			{Key: "body_json:.user.api_key", Enabled: false},
		}
		var b strings.Builder
		writeBodyVarsBlock(&b, rules)
		if b.String() != "" {
			t.Errorf("expected empty output for disabled rules, got %q", b.String())
		}
	})

	t.Run("deduplicated keys", func(t *testing.T) {
		rules := []RateLimitRule{
			{Key: "body_json:.user.api_key", Enabled: true},
			{Key: "body_json:.user.api_key", Enabled: true},
		}
		var b strings.Builder
		writeBodyVarsBlock(&b, rules)
		got := b.String()
		count := strings.Count(got, "json .user.api_key")
		if count != 1 {
			t.Errorf("expected 1 occurrence of json path, got %d in %q", count, got)
		}
	})

	t.Run("integrated in generateServiceRL", func(t *testing.T) {
		rules := []RateLimitRule{
			{
				ID:      "test-001",
				Name:    "body-key-rule",
				Service: "api",
				Key:     "body_json:.user.api_key",
				Events:  100,
				Window:  "1m",
				Action:  "deny",
				Enabled: true,
			},
		}
		got := generateServiceRL("api", rules, RateLimitGlobalConfig{})
		if !strings.Contains(got, "body_vars {") {
			t.Errorf("expected body_vars block in generated output, got:\n%s", got)
		}
		if !strings.Contains(got, "json .user.api_key") {
			t.Errorf("expected json .user.api_key in body_vars block, got:\n%s", got)
		}
		if !strings.Contains(got, "{http.vars.body_json.user.api_key}") {
			t.Errorf("expected placeholder in rate_limit zone key, got:\n%s", got)
		}
		// Verify body_vars comes before rate_limit
		bvIdx := strings.Index(got, "body_vars {")
		rlIdx := strings.Index(got, "rate_limit {")
		if bvIdx >= rlIdx {
			t.Errorf("body_vars must come before rate_limit in output:\n%s", got)
		}
	})
}
