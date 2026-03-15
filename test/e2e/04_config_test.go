package e2e_test

import (
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
//  7. WAF Config
// ════════════════════════════════════════════════════════════════════

func TestWAFConfig(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/config")
		assertCode(t, "get config", 200, resp)
		// Response is WAFConfig: {defaults: {...}, services: {...}}
		mode := jsonField(body, "defaults.mode")
		if mode == "" || mode == "null" {
			t.Errorf("expected defaults.mode to be set, got: %.200s", string(body))
		}
	})

	t.Run("update", func(t *testing.T) {
		payload := map[string]any{
			"defaults": map[string]any{
				"mode":               "enabled",
				"paranoia_level":     2,
				"inbound_threshold":  10,
				"outbound_threshold": 10,
			},
		}
		resp, body := httpPut(t, wafctlURL+"/api/config", payload)
		assertCode(t, "update config", 200, resp)
		// Response echoes back the full WAFConfig
		assertField(t, "update", body, "defaults.mode", "enabled")
		pl := jsonInt(body, "defaults.paranoia_level")
		if pl != 2 {
			t.Errorf("expected defaults.paranoia_level=2, got %d", pl)
		}
	})

}

// ════════════════════════════════════════════════════════════════════
//  8. Deploy Pipeline
// ════════════════════════════════════════════════════════════════════

func TestDeployPipeline(t *testing.T) {
	// Create a test exclusion to include in deploy.
	payload := map[string]any{
		"name":        "e2e-deploy-test",
		"type":        "allow",
		"description": "Deploy test",
		"enabled":     true,
		"conditions":  []map[string]string{{"field": "path", "operator": "begins_with", "value": "/api/"}},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", payload)
	assertCode(t, "create deploy-test exclusion", 201, resp)
	exclID := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/exclusions/"+exclID) })

	// Deploy — status must be "deployed" (not "partial").
	// "partial" means Caddy reload failed, which is a real e2e failure.
	t.Run("deploy", func(t *testing.T) {
		resp, body := httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
		assertCode(t, "deploy", 200, resp)
		assertField(t, "deploy status", body, "status", "deployed")
		// Hot-reload via mtime polling — deploy writes the file,
		// plugin detects mtime change asynchronously. reloaded=false is expected.
		reloaded := jsonField(body, "reloaded")
		if reloaded != "true" && reloaded != "false" {
			t.Errorf("deploy reloaded: expected boolean string, got %q", reloaded)
		}
	})

	t.Run("Caddy healthy post-deploy", func(t *testing.T) {
		time.Sleep(1 * time.Second)
		resp, _ := httpGet(t, caddyAdmin+"/config/")
		assertCode(t, "admin", 200, resp)
	})

	t.Run("proxy works post-deploy", func(t *testing.T) {
		resp, _ := httpGet(t, caddyURL+"/get")
		assertCode(t, "proxy", 200, resp)
	})
}
