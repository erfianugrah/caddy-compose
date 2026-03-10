package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestParseCLIFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCmd  []string
		wantJSON bool
		wantFile string
	}{
		{"empty", nil, nil, false, ""},
		{"serve", []string{"serve"}, []string{"serve"}, false, ""},
		{"version", []string{"version"}, []string{"version"}, false, ""},
		{"help flag", []string{"--help"}, []string{"help"}, false, ""},
		{"help short", []string{"-h"}, []string{"help"}, false, ""},
		{"json flag", []string{"health", "--json"}, []string{"health"}, true, ""},
		{"addr flag", []string{"health", "--addr", "http://remote:9090"}, []string{"health"}, false, ""},
		{"addr equals", []string{"health", "--addr=http://remote:9090"}, []string{"health"}, false, ""},
		{"file flag", []string{"rules", "create", "--file", "rule.json"}, []string{"rules", "create"}, false, "rule.json"},
		{"file short", []string{"rules", "create", "-f", "rule.json"}, []string{"rules", "create"}, false, "rule.json"},
		{"events with filters", []string{"events", "--hours", "6", "--service", "cdn.erfi.io"}, []string{"events", "--hours", "6", "--service", "cdn.erfi.io"}, false, ""},
		{"rules subcommand", []string{"rules", "list"}, []string{"rules", "list"}, false, ""},
		{"rules delete id", []string{"rules", "delete", "abc-123"}, []string{"rules", "delete", "abc-123"}, false, ""},
		{"blocklist check", []string{"blocklist", "check", "1.2.3.4"}, []string{"blocklist", "check", "1.2.3.4"}, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, flags := parseCLIFlags(tt.args)
			if len(cmd) != len(tt.wantCmd) {
				t.Errorf("command = %v, want %v", cmd, tt.wantCmd)
			} else {
				for i := range cmd {
					if cmd[i] != tt.wantCmd[i] {
						t.Errorf("command[%d] = %q, want %q", i, cmd[i], tt.wantCmd[i])
					}
				}
			}
			if flags.asJSON != tt.wantJSON {
				t.Errorf("asJSON = %v, want %v", flags.asJSON, tt.wantJSON)
			}
			if flags.file != tt.wantFile {
				t.Errorf("file = %q, want %q", flags.file, tt.wantFile)
			}
		})
	}
}

func TestParseCLIFlagsAddr(t *testing.T) {
	// --addr should override the default
	_, flags := parseCLIFlags([]string{"health", "--addr", "http://remote:9090"})
	if flags.addr != "http://remote:9090" {
		t.Errorf("addr = %q, want http://remote:9090", flags.addr)
	}

	// --addr= syntax
	_, flags2 := parseCLIFlags([]string{"--addr=http://custom:1234", "config", "get"})
	if flags2.addr != "http://custom:1234" {
		t.Errorf("addr = %q, want http://custom:1234", flags2.addr)
	}
}

func TestCLIVersion(t *testing.T) {
	code := cliVersion()
	if code != 0 {
		t.Errorf("cliVersion returned %d, want 0", code)
	}
}

func TestRunCLIHelp(t *testing.T) {
	code := runCLI([]string{"help"})
	if code != 0 {
		t.Errorf("runCLI help returned %d, want 0", code)
	}
}

func TestRunCLIVersion(t *testing.T) {
	code := runCLI([]string{"version"})
	if code != 0 {
		t.Errorf("runCLI version returned %d, want 0", code)
	}
}

func TestRunCLIUnknown(t *testing.T) {
	code := runCLI([]string{"nonexistent"})
	if code != 1 {
		t.Errorf("runCLI unknown returned %d, want 1", code)
	}
}

// TestCLIHealthParsesStores verifies that the CLI health struct correctly
// unmarshals the nested stores structure from the health API response.
func TestCLIHealthParsesStores(t *testing.T) {
	handler := testHealthHandler(t)
	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}

	// Parse the response using the same struct shape as cliHealth.
	var health struct {
		Status     string `json:"status"`
		Version    string `json:"version"`
		CRSVersion string `json:"crs_version"`
		Uptime     string `json:"uptime"`
		Stores     struct {
			WAFEvents struct {
				Events int `json:"events"`
			} `json:"waf_events"`
			AccessEvents struct {
				Events int `json:"events"`
			} `json:"access_events"`
			GeneralLogs struct {
				Events int `json:"events"`
			} `json:"general_logs"`
			GeoIP struct {
				MMDBLoaded bool `json:"mmdb_loaded"`
				APIEnabled bool `json:"api_enabled"`
			} `json:"geoip"`
			Exclusions struct {
				Count int `json:"count"`
			} `json:"exclusions"`
			Blocklist BlocklistStatsResponse `json:"blocklist"`
		} `json:"stores"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if health.Status != "ok" {
		t.Errorf("status = %q, want ok", health.Status)
	}
	if health.Version != version {
		t.Errorf("version = %q, want %q", health.Version, version)
	}
	if health.Uptime == "" {
		t.Error("uptime should not be empty")
	}
	// Blocklist source should be set even with 0 IPs.
	if health.Stores.Blocklist.Source != "IPsum" {
		t.Errorf("blocklist source = %q, want IPsum", health.Stores.Blocklist.Source)
	}
}

func TestRunCLIMissingSubcommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"config no sub", []string{"config"}},
		{"rules no sub", []string{"rules"}},
		{"blocklist no sub", []string{"blocklist"}},
		{"rules get no id", []string{"rules", "get"}},
		{"rules delete no id", []string{"rules", "delete"}},
		{"blocklist check no ip", []string{"blocklist", "check"}},
		{"ratelimit no sub", []string{"ratelimit"}},
		{"rl no sub", []string{"rl"}},
		{"ratelimit get no id", []string{"ratelimit", "get"}},
		{"ratelimit delete no id", []string{"ratelimit", "delete"}},
		{"ratelimit unknown sub", []string{"ratelimit", "xyz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := runCLI(tt.args)
			if code != 1 {
				t.Errorf("runCLI(%v) returned %d, want 1", tt.args, code)
			}
		})
	}
}
