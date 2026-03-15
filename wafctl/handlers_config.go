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

func handleGenerateConfig(cs *ConfigStore, es *ExclusionStore, ls *ManagedListStore, cspStore *CSPStore, secStore *SecurityHeaderStore, corsStore *CORSStore, ds *DefaultRuleStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		allExclusions := es.EnabledExclusions()
		rlGlobal := cs.Get().RateLimitGlobal
		svcMap := BuildServiceFQDNMap(deployCfg.CaddyfilePath)
		respHeaders := BuildPolicyResponseHeaders(cspStore, secStore, corsStore, svcMap)
		wafCfg := BuildPolicyWafConfig(cs, svcMap)
		policyData, err := GeneratePolicyRulesWithRL(allExclusions, rlGlobal, ls, svcMap, respHeaders, wafCfg)
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

func handleDeploy(cs *ConfigStore, es *ExclusionStore, ls *ManagedListStore, cspStore *CSPStore, secStore *SecurityHeaderStore, corsStore *CORSStore, ds *DefaultRuleStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		deployMu.Lock()
		defer deployMu.Unlock()

		allExclusions := es.EnabledExclusions()

		// Generate policy engine rules file (all rule types from unified ExclusionStore).
		rlGlobal := cs.Get().RateLimitGlobal
		svcMap := BuildServiceFQDNMap(deployCfg.CaddyfilePath)
		respHeaders := BuildPolicyResponseHeaders(cspStore, secStore, corsStore, svcMap)
		wafCfg := BuildPolicyWafConfig(cs, svcMap)
		policyData, err := GeneratePolicyRulesWithRL(allExclusions, rlGlobal, ls, svcMap, respHeaders, wafCfg)
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
		log.Printf("[deploy] wrote policy rules (%d rules) → %s",
			policyCount, deployCfg.PolicyRulesFile)

		// No Caddy reload needed — the policy engine plugin hot-reloads
		// policy-rules.json via mtime polling (default 5s interval).
		writeJSON(w, http.StatusOK, DeployResponse{
			Status:    "deployed",
			Message:   "Policy rules written — plugin will hot-reload within seconds",
			Reloaded:  false,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
}
