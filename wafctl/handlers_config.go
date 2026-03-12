package main

import (
	"encoding/json"
	"log"
	"net/http"
	"path/filepath"
	"time"
)

// --- Handlers: CRS Catalog ---

func handleCRSRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, GetCRSCatalog())
}

func handleCRSAutocomplete(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, GetCRSAutocomplete())
}

// --- Handlers: WAF Config ---

func handleGetConfig(cs *ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, cs.Get())
	}
}

func handleUpdateConfig(cs *ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg WAFConfig
		if _, failed := decodeJSON(w, r, &cfg); failed {
			return
		}
		if err := validateConfig(cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		updated, err := cs.Update(cfg)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update config", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

// --- Handler: Generate Config ---

func handleGenerateConfig(cs *ConfigStore, es *ExclusionStore, rs *RateLimitRuleStore, ls *ManagedListStore, cspStore *CSPStore, secStore *SecurityHeaderStore, ds *DefaultRuleStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		cfg := cs.Get()
		allExclusions := es.EnabledExclusions()
		// Filter out policy engine types when enabled.
		exclusions := FilterSecRuleExclusions(allExclusions, deployCfg.PolicyEngineEnabled)
		result := GenerateConfigs(cfg, exclusions, ls)
		// Include WAF settings in the response.
		wafSettings := GenerateWAFSettings(cfg)
		resp := map[string]interface{}{
			"pre_crs_conf":          result.PreCRS,
			"post_crs_conf":         result.PostCRS,
			"waf_settings":          wafSettings,
			"policy_engine_enabled": deployCfg.PolicyEngineEnabled,
		}
		// Include policy rules preview when enabled (with RL rules).
		if deployCfg.PolicyEngineEnabled {
			rlRules := rs.EnabledRules()
			rlGlobal := rs.GetGlobal()
			svcMap := BuildServiceFQDNMap(deployCfg.CaddyfilePath)
			respHeaders := BuildPolicyResponseHeaders(cspStore, secStore, svcMap)
			wafCfg := BuildPolicyWafConfig(cs, svcMap)
			policyData, err := GeneratePolicyRulesWithRL(allExclusions, rlRules, rlGlobal, ls, svcMap, respHeaders, wafCfg)
			if err == nil {
				policyData, err = ApplyDefaultRuleOverrides(policyData, ds)
				if err == nil {
					resp["policy_rules"] = json.RawMessage(policyData)
				}
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// --- Handler: Validate ---

func handleValidateConfig(cs *ConfigStore, es *ExclusionStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := cs.Get()
		allExclusions := es.EnabledExclusions()
		exclusions := FilterSecRuleExclusions(allExclusions, deployCfg.PolicyEngineEnabled)
		result := GenerateConfigs(cfg, exclusions, nil)
		wafSettings := GenerateWAFSettings(cfg)

		vr := ValidateGeneratedConfig(result.PreCRS, result.PostCRS, wafSettings)

		// Also check for self-referencing rule IDs.
		selfRefWarnings := validateGeneratedRuleIDs(exclusions)
		vr.Warnings = append(vr.Warnings, selfRefWarnings...)
		for _, warn := range selfRefWarnings {
			if warn.Level == "error" {
				vr.Valid = false
			}
		}

		// Include generated configs if ?include_configs=true.
		if r.URL.Query().Get("include_configs") == "true" {
			vr.PreCRSConf = result.PreCRS
			vr.PostCRSConf = result.PostCRS
			vr.WAFSettings = wafSettings
		}

		logValidationResult(vr)
		writeJSON(w, http.StatusOK, vr)
	}
}

// --- Handler: Deploy ---

func handleDeploy(cs *ConfigStore, es *ExclusionStore, rs *RateLimitRuleStore, ls *ManagedListStore, cspStore *CSPStore, secStore *SecurityHeaderStore, ds *DefaultRuleStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		deployMu.Lock()
		defer deployMu.Unlock()
		cfg := cs.Get()
		allExclusions := es.EnabledExclusions()

		// When policy engine is enabled, allow/block/honeypot go to the plugin's
		// JSON file instead of SecRules. Filter them out before generation.
		exclusions := FilterSecRuleExclusions(allExclusions, deployCfg.PolicyEngineEnabled)
		result := GenerateConfigs(cfg, exclusions, ls)
		wafSettings := GenerateWAFSettings(cfg)

		// Validate generated config before writing.
		vr := ValidateGeneratedConfig(result.PreCRS, result.PostCRS, wafSettings)
		selfRefWarnings := validateGeneratedRuleIDs(exclusions)
		vr.Warnings = append(vr.Warnings, selfRefWarnings...)
		for _, sw := range selfRefWarnings {
			if sw.Level == "error" {
				vr.Valid = false
			}
		}
		logValidationResult(vr)

		// Abort deploy if validation found errors.
		if !vr.Valid {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":    "validation failed — deploy aborted",
				"warnings": vr.Warnings,
				"valid":    false,
			})
			return
		}

		// Write config files to the shared volume.
		if err := writeConfFiles(deployCfg.WafDir, result.PreCRS, result.PostCRS, wafSettings); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error:   "failed to write config files",
				Details: err.Error(),
			})
			return
		}

		// Policy engine: generate JSON rules file (WAF exclusions + RL rules).
		if deployCfg.PolicyEngineEnabled && deployCfg.PolicyRulesFile != "" {
			rlRules := rs.EnabledRules()
			rlGlobal := rs.GetGlobal()
			svcMap := BuildServiceFQDNMap(deployCfg.CaddyfilePath)
			respHeaders := BuildPolicyResponseHeaders(cspStore, secStore, svcMap)
			wafCfg := BuildPolicyWafConfig(cs, svcMap)
			policyData, err := GeneratePolicyRulesWithRL(allExclusions, rlRules, rlGlobal, ls, svcMap, respHeaders, wafCfg)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{
					Error:   "failed to generate policy rules",
					Details: err.Error(),
				})
				return
			}
			policyData, err = ApplyDefaultRuleOverrides(policyData, ds)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{
					Error:   "failed to apply default rule overrides",
					Details: err.Error(),
				})
				return
			}
			if err := atomicWriteFile(deployCfg.PolicyRulesFile, policyData, 0644); err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{
					Error:   "failed to write policy rules file",
					Details: err.Error(),
				})
				return
			}
			policyCount := 0
			for _, e := range allExclusions {
				if IsPolicyEngineType(e.Type) {
					policyCount++
				}
			}
			log.Printf("[deploy] wrote policy rules (%d WAF + %d RL rules) → %s",
				policyCount, len(rlRules), deployCfg.PolicyRulesFile)
		}

		// Sync RL Caddyfile snippets (legacy mode only).
		if !deployCfg.PolicyEngineEnabled {
			syncCaddyfileServices(rs, ls, deployCfg)
		}

		// Reload Caddy via admin API.
		// Pass the config file paths so reloadCaddy can fingerprint them and
		// inject a unique comment, forcing Caddy to reparse all includes.
		confFiles := []string{
			filepath.Join(deployCfg.WafDir, "custom-pre-crs.conf"),
			filepath.Join(deployCfg.WafDir, "custom-post-crs.conf"),
			filepath.Join(deployCfg.WafDir, "custom-waf-settings.conf"),
		}
		reloaded := true
		if err := reloadCaddy(deployCfg.CaddyfilePath, deployCfg.CaddyAdminURL, confFiles...); err != nil {
			log.Printf("warning: Caddy reload failed: %v", err)
			reloaded = false
			// Don't fail the request — files were written successfully.
			// The user can manually reload or investigate.
		}

		status := "deployed"
		msg := "Config files written and Caddy reloaded successfully"
		if !reloaded {
			status = "partial"
			msg = "Config files written but Caddy reload failed — manual reload may be needed"
		}

		writeJSON(w, http.StatusOK, DeployResponse{
			Status:      status,
			Message:     msg,
			PreCRS:      confFiles[0],
			PostCRS:     confFiles[1],
			WAFSettings: confFiles[2],
			Reloaded:    reloaded,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		})
	}
}
