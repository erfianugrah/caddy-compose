package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// --- Handlers: CRS Catalog ---

func handleCRSRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, GetCRSCatalog())
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

// --- Handler: Generate Config (preview) ---

func handleGenerateConfig(cs *ConfigStore, es *ExclusionStore, rs *RateLimitRuleStore, ls *ManagedListStore, cspStore *CSPStore, secStore *SecurityHeaderStore, ds *DefaultRuleStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		allExclusions := es.EnabledExclusions()
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
		resp := map[string]interface{}{
			"policy_rules": json.RawMessage(policyData),
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// --- Handler: Deploy ---

func handleDeploy(cs *ConfigStore, es *ExclusionStore, rs *RateLimitRuleStore, ls *ManagedListStore, cspStore *CSPStore, secStore *SecurityHeaderStore, ds *DefaultRuleStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		deployMu.Lock()
		defer deployMu.Unlock()

		allExclusions := es.EnabledExclusions()

		// Generate policy engine rules file (WAF exclusions + RL rules).
		if deployCfg.PolicyRulesFile != "" {
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

		// Reload Caddy via admin API to pick up the new policy rules.
		reloaded := true
		if err := reloadCaddy(deployCfg.CaddyfilePath, deployCfg.CaddyAdminURL); err != nil {
			log.Printf("warning: Caddy reload failed: %v", err)
			reloaded = false
		}

		status := "deployed"
		msg := "Policy rules written and Caddy reloaded successfully"
		if !reloaded {
			status = "partial"
			msg = "Policy rules written but Caddy reload failed — manual reload may be needed"
		}

		writeJSON(w, http.StatusOK, DeployResponse{
			Status:    status,
			Message:   msg,
			Reloaded:  reloaded,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
}
