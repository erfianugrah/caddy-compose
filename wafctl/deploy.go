package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// deployMu serializes all deploy operations (WAF, RL, CSP) to prevent
// interleaved file writes and Caddy reloads from concurrent requests.
var deployMu sync.Mutex

// DeployConfig holds paths and settings for the deploy pipeline.
type DeployConfig struct {
	// WafDir is the directory for WAF config files (policy rules, trusted proxies, etc.).
	// These files are volume-mounted into the Caddy container.
	WafDir string

	// CaddyfilePath is the path to the Caddyfile (read-only mount from Caddy).
	// Used to POST to Caddy's admin API for reload.
	CaddyfilePath string

	// CaddyAdminURL is the base URL for Caddy's admin API.
	CaddyAdminURL string

	// PolicyRulesFile is the path to the policy-rules.json file consumed by
	// the caddy-policy-engine plugin. The plugin hot-reloads this file via
	// mtime polling.
	PolicyRulesFile string
}

// DeployResponse is returned by the deploy endpoint.
type DeployResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	Reloaded  bool   `json:"reloaded"`
	Timestamp string `json:"timestamp"`
}

// ensureWafDir creates the WAF config directory if it doesn't exist.
// The policy engine plugin reads policy-rules.json from this directory.
func ensureWafDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating waf dir %s: %w", dir, err)
	}
	return nil
}

// generateOnBoot regenerates the policy engine rules file from stored state
// at startup. This ensures a stack restart always picks up the latest rules
// without requiring a manual POST /api/config/deploy.
// No Caddy reload is performed — Caddy reads the files fresh on its own start.
func generateOnBoot(cs *ConfigStore, es *ExclusionStore, rs *RateLimitRuleStore, cspStore *CSPStore, secStore *SecurityHeaderStore, ls *ManagedListStore, ds *DefaultRuleStore, deployCfg DeployConfig) {
	allExclusions := es.EnabledExclusions()

	// Policy engine: generate JSON rules file for the Caddy plugin.
	// Includes WAF exclusions (allow/block/skip/detect) and rate limit rules.
	rlRules := rs.EnabledRules()
	rlGlobal := rs.GetGlobal()
	svcMap := BuildServiceFQDNMap(deployCfg.CaddyfilePath)
	respHeaders := BuildPolicyResponseHeaders(cspStore, secStore, svcMap)
	wafCfg := BuildPolicyWafConfig(cs, svcMap)
	policyData, err := GeneratePolicyRulesWithRL(allExclusions, rlRules, rlGlobal, ls, svcMap, respHeaders, wafCfg)
	if err != nil {
		log.Printf("[boot] warning: failed to generate policy rules: %v", err)
	} else {
		policyData, err = ApplyDefaultRuleOverrides(policyData, ds)
		if err != nil {
			log.Printf("[boot] warning: failed to apply default rule overrides: %v", err)
		} else if err := atomicWriteFile(deployCfg.PolicyRulesFile, policyData, 0644); err != nil {
			log.Printf("[boot] warning: failed to write policy rules file: %v", err)
		} else {
			policyCount := 0
			for _, e := range allExclusions {
				if IsPolicyEngineType(e.Type) {
					policyCount++
				}
			}
			log.Printf("[boot] regenerated policy rules (%d WAF + %d RL rules) → %s",
				policyCount, len(rlRules), deployCfg.PolicyRulesFile)
		}
	}

}

// deployAll regenerates the policy engine rules file and reloads Caddy.
// This is the programmatic equivalent of POST /api/config/deploy, used by
// background processes (e.g. blocklist refresh) that need to trigger a full
// regeneration + reload cycle after updating managed lists.
func deployAll(cs *ConfigStore, es *ExclusionStore, rs *RateLimitRuleStore, ls *ManagedListStore, cspStore *CSPStore, secStore *SecurityHeaderStore, ds *DefaultRuleStore, deployCfg DeployConfig) error {
	deployMu.Lock()
	defer deployMu.Unlock()

	allExclusions := es.EnabledExclusions()

	// Generate policy engine rules file (WAF exclusions + RL rules).
	rlRules := rs.EnabledRules()
	rlGlobal := rs.GetGlobal()
	svcMap := BuildServiceFQDNMap(deployCfg.CaddyfilePath)
	respHeaders := BuildPolicyResponseHeaders(cspStore, secStore, svcMap)
	wafCfg := BuildPolicyWafConfig(cs, svcMap)
	policyData, err := GeneratePolicyRulesWithRL(allExclusions, rlRules, rlGlobal, ls, svcMap, respHeaders, wafCfg)
	if err != nil {
		return fmt.Errorf("generating policy rules: %w", err)
	}
	policyData, err = ApplyDefaultRuleOverrides(policyData, ds)
	if err != nil {
		return fmt.Errorf("applying default rule overrides: %w", err)
	}
	if err := atomicWriteFile(deployCfg.PolicyRulesFile, policyData, 0644); err != nil {
		return fmt.Errorf("writing policy rules file: %w", err)
	}
	policyCount := 0
	for _, e := range allExclusions {
		if IsPolicyEngineType(e.Type) {
			policyCount++
		}
	}
	log.Printf("[deploy] wrote policy rules (%d WAF + %d RL rules) → %s",
		policyCount, len(rlRules), deployCfg.PolicyRulesFile)

	// Reload Caddy to pick up the new policy rules.
	if err := reloadCaddy(deployCfg.CaddyfilePath, deployCfg.CaddyAdminURL); err != nil {
		return fmt.Errorf("Caddy reload: %w", err)
	}

	return nil
}

// reloadCaddy sends the Caddyfile to Caddy's admin API to trigger a reload.
// This reads the Caddyfile from disk and POSTs it to /load with the caddyfile adapter.
//
// The Caddyfile adapter strips comments during conversion to JSON, so even when
// included files (e.g. custom-waf-settings.conf, custom-pre-crs.conf) change on
// disk, the adapted JSON is byte-identical to the running config. Caddy's
// changeConfig() compares via bytes.Equal() and silently skips reload on match.
//
// We solve this with Cache-Control: must-revalidate, which sets forceReload=true
// in Caddy's admin handler, bypassing the bytes.Equal() gate entirely. This
// forces a full re-provision of all modules (including the policy engine,
// which re-reads its rules files at provision time).
//
// The fingerprint comment is still prepended for logging/diagnostics but is NOT
// relied upon for forcing the reload.
func reloadCaddy(caddyfilePath, adminURL string, configFiles ...string) error {
	content, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return fmt.Errorf("reading Caddyfile at %s: %w", caddyfilePath, err)
	}

	// Build a fingerprint from all config file contents for logging/diagnostics.
	// This does NOT force the reload (Cache-Control header does that) but lets
	// us track what changed across deploys in the log output.
	fingerprint := deployFingerprint(configFiles)
	header := fmt.Sprintf("# wafctl deploy %s fingerprint:%s\n",
		time.Now().UTC().Format(time.RFC3339), fingerprint)
	payload := append([]byte(header), content...)

	url := adminURL + "/load"
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating reload request: %w", err)
	}
	req.Header.Set("Content-Type", "text/caddyfile")
	// Force Caddy to reload even when the adapted JSON is byte-identical to
	// the running config. Without this, Caddy's changeConfig() compares the
	// adapted JSON via bytes.Equal() and silently skips the reload when it
	// matches — which it always does because our fingerprint comment is
	// stripped during Caddyfile-to-JSON adaptation. The "must-revalidate"
	// value sets forceReload=true in Caddy's admin handler, bypassing the
	// bytes.Equal() gate entirely and forcing a full re-provision of all
	// modules (including the policy engine, which re-reads its rules files).
	// See: caddy.go changeConfig() and admin.go handleLoadConfig().
	req.Header.Set("Cache-Control", "must-revalidate")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Caddy admin API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
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
