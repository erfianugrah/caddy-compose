package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
)

// deployMu serializes all deploy operations (WAF, RL, CSP) to prevent
// interleaved file writes.
var deployMu sync.Mutex

// DeployConfig holds paths and settings for the deploy pipeline.
type DeployConfig struct {
	// WafDir is the directory for WAF config files (policy rules, jail state, etc.).
	// These files are volume-mounted into the Caddy container.
	WafDir string

	// CaddyfilePath is the path to the Caddyfile (read-only mount from Caddy).
	// Feeds Caddyfile service discovery for CSP / security-header deploy previews.
	CaddyfilePath string

	// PolicyRulesFile is the path to the policy-rules.json file consumed by
	// the caddy-policy-engine plugin. The plugin hot-reloads this file via
	// mtime polling.
	PolicyRulesFile string

	// ChallengeHMACKey is the hex-encoded 32-byte HMAC key for challenge cookie
	// signing. Read from CHALLENGE_HMAC_KEY env or auto-generated on first boot.
	ChallengeHMACKey string
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

// generatePolicyData runs the full policy generation pipeline: collect enabled
// exclusions, build service FQDN map, generate response headers + WAF config,
// generate policy rules, and apply default rule overrides. Returns the JSON
// policy data and the number of policy-engine rules, or an error.
//
// This is the single source of truth for config generation — used by
// generateOnBoot, deployAll, handleDeploy, and handleGenerateConfig.
func generatePolicyData(cs *ConfigStore, es *ExclusionStore, ls *ManagedListStore, cspStore *CSPStore, secStore *SecurityHeaderStore, corsStore *CORSStore, ds *DefaultRuleStore, deployCfg DeployConfig) ([]byte, int, error) {
	allExclusions := es.EnabledExclusions()
	rlGlobal := cs.Get().RateLimitGlobal
	svcMap := BuildServiceFQDNMap(deployCfg.CaddyfilePath)
	respHeaders := BuildPolicyResponseHeaders(cspStore, secStore, corsStore, svcMap)
	wafCfg := BuildPolicyWafConfig(cs, svcMap)
	policyData, err := GeneratePolicyRulesWithRL(allExclusions, rlGlobal, ls, svcMap, respHeaders, wafCfg)
	if err != nil {
		return nil, 0, fmt.Errorf("generating policy rules: %w", err)
	}
	policyData, err = ApplyDefaultRuleOverrides(policyData, ds)
	if err != nil {
		return nil, 0, fmt.Errorf("applying default rule overrides: %w", err)
	}

	// Inject challenge HMAC key when challenge rules exist.
	// Uses a single unmarshal/marshal pass rather than a second round-trip.
	if deployCfg.ChallengeHMACKey != "" {
		hasChallengeRules := false
		for _, e := range allExclusions {
			if e.Type == "challenge" {
				hasChallengeRules = true
				break
			}
		}
		if hasChallengeRules {
			var file PolicyRulesFile
			if err := json.Unmarshal(policyData, &file); err != nil {
				return nil, 0, fmt.Errorf("injecting challenge config: unmarshal: %w", err)
			}
			file.ChallengeConfig = &PolicyChallengeGlobalConfig{
				HMACKey: deployCfg.ChallengeHMACKey,
			}
			policyData, err = json.MarshalIndent(file, "", "  ")
			if err != nil {
				return nil, 0, fmt.Errorf("injecting challenge config: marshal: %w", err)
			}
		}
	}

	policyCount := 0
	for _, e := range allExclusions {
		if IsPolicyEngineType(e.Type) {
			policyCount++
		}
	}
	return policyData, policyCount, nil
}

// generateOnBoot regenerates the policy engine rules file from stored state
// at startup. This ensures a stack restart always picks up the latest rules
// without requiring a manual POST /api/config/deploy.
// No Caddy reload is performed — Caddy reads the files fresh on its own start.
func generateOnBoot(cs *ConfigStore, es *ExclusionStore, cspStore *CSPStore, secStore *SecurityHeaderStore, corsStore *CORSStore, ls *ManagedListStore, ds *DefaultRuleStore, deployCfg DeployConfig) {
	policyData, policyCount, err := generatePolicyData(cs, es, ls, cspStore, secStore, corsStore, ds, deployCfg)
	if err != nil {
		log.Printf("[boot] warning: %v", err)
		return
	}
	if err := atomicWriteFile(deployCfg.PolicyRulesFile, policyData, 0644); err != nil {
		log.Printf("[boot] warning: failed to write policy rules file: %v", err)
		return
	}
	log.Printf("[boot] regenerated policy rules (%d rules) → %s",
		policyCount, deployCfg.PolicyRulesFile)
}

// deployAll regenerates the policy engine rules file from all stores.
// Used by background processes (e.g. blocklist refresh) that need to trigger
// a full regeneration after updating managed lists. The policy engine plugin
// detects the file change via mtime polling and hot-reloads within seconds.
func deployAll(cs *ConfigStore, es *ExclusionStore, ls *ManagedListStore, cspStore *CSPStore, secStore *SecurityHeaderStore, corsStore *CORSStore, ds *DefaultRuleStore, deployCfg DeployConfig) error {
	deployMu.Lock()
	defer deployMu.Unlock()

	policyData, policyCount, err := generatePolicyData(cs, es, ls, cspStore, secStore, corsStore, ds, deployCfg)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(deployCfg.PolicyRulesFile, policyData, 0644); err != nil {
		return fmt.Errorf("writing policy rules file: %w", err)
	}
	log.Printf("[deploy] wrote policy rules (%d rules) → %s",
		policyCount, deployCfg.PolicyRulesFile)

	// No Caddy reload — policy engine plugin hot-reloads via mtime polling.
	return nil
}
