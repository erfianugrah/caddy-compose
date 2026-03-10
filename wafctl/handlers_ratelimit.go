package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// ─── Handlers: Rate Limit Rules (Policy Engine) ────────────────────

func handleListRLRules(rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, rs.List())
	}
}

func handleGetRLRule(rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		rule := rs.Get(id)
		if rule == nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "rule not found"})
			return
		}
		writeJSON(w, http.StatusOK, rule)
	}
}

func handleCreateRLRule(rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule RateLimitRule
		if _, failed := decodeJSON(w, r, &rule); failed {
			return
		}
		if err := validateRateLimitRule(rule); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		created, err := rs.Create(rule)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to create rule", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func handleUpdateRLRule(rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var rule RateLimitRule
		if _, failed := decodeJSON(w, r, &rule); failed {
			return
		}
		if err := validateRateLimitRule(rule); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		updated, found, err := rs.Update(id, rule)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update rule", Details: err.Error()})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "rule not found"})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func handleDeleteRLRule(rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		found, err := rs.Delete(id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to delete rule", Details: err.Error()})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "rule not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

func handleDeployRLRules(rs *RateLimitRuleStore, es *ExclusionStore, ls *ManagedListStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		deployMu.Lock()
		defer deployMu.Unlock()
		// Discover any new services from the Caddyfile.
		rs.MergeCaddyfileServices(deployCfg.CaddyfilePath)

		rules := rs.EnabledRules()
		global := rs.GetGlobal()

		// When policy engine is enabled, RL rules go into policy-rules.json
		// alongside WAF exclusions. The plugin hot-reloads via mtime polling
		// — no Caddy restart needed.
		if deployCfg.PolicyEngineEnabled && deployCfg.PolicyRulesFile != "" {
			allExclusions := es.EnabledExclusions()
			svcMap := BuildServiceFQDNMap(deployCfg.CaddyfilePath)
			policyData, err := GeneratePolicyRulesWithRL(allExclusions, rules, global, ls, svcMap)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{
					Error:   "failed to generate policy rules",
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
			log.Printf("[deploy] wrote policy rules with %d RL rules → %s", len(rules), deployCfg.PolicyRulesFile)

			writeJSON(w, http.StatusOK, RateLimitDeployResponse{
				Status:    "deployed",
				Message:   fmt.Sprintf("Deployed %d RL rules via policy engine (hot-reload, no Caddy restart)", len(rules)),
				Files:     []string{deployCfg.PolicyRulesFile},
				Reloaded:  true, // Plugin hot-reloads automatically
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			return
		}

		// Legacy mode: generate .caddy files and reload Caddy.
		files := GenerateRateLimitConfigs(rules, global, deployCfg.CaddyfilePath, ls)

		written, err := writeRLFiles(deployCfg.RateLimitDir, files)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error:   "failed to write RL files",
				Details: err.Error(),
			})
			return
		}

		reloaded := true
		if err := reloadCaddy(deployCfg.CaddyfilePath, deployCfg.CaddyAdminURL, written...); err != nil {
			log.Printf("warning: Caddy reload failed after RL deploy: %v", err)
			reloaded = false
		}

		status := "deployed"
		msg := fmt.Sprintf("Wrote %d RL files and Caddy reloaded successfully", len(written))
		if !reloaded {
			status = "partial"
			msg = fmt.Sprintf("Wrote %d RL files but Caddy reload failed — manual reload may be needed", len(written))
		}

		writeJSON(w, http.StatusOK, RateLimitDeployResponse{
			Status:    status,
			Message:   msg,
			Files:     written,
			Reloaded:  reloaded,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
}

func handleGetRLGlobal(rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, rs.GetGlobal())
	}
}

func handleUpdateRLGlobal(rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg RateLimitGlobalConfig
		if _, failed := decodeJSON(w, r, &cfg); failed {
			return
		}
		if err := validateRateLimitGlobal(cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		if err := rs.UpdateGlobal(cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update global config", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, rs.GetGlobal())
	}
}

func handleExportRLRules(rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, rs.Export())
	}
}

func handleImportRLRules(rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var export RateLimitRuleExport
		if _, failed := decodeJSON(w, r, &export); failed {
			return
		}
		// Validate all imported rules.
		for i, rule := range export.Rules {
			if err := validateRateLimitRule(rule); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{
					Error:   fmt.Sprintf("rule[%d] validation failed", i),
					Details: err.Error(),
				})
				return
			}
		}
		if err := rs.Import(export.Rules); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "import failed", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "imported",
			"imported": len(export.Rules),
		})
	}
}

func handleReorderRLRules(rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IDs []string `json:"ids"`
		}
		if _, failed := decodeJSON(w, r, &req); failed {
			return
		}
		if len(req.IDs) == 0 {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "ids array is required"})
			return
		}
		if err := rs.Reorder(req.IDs); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "reorder failed", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, rs.List())
	}
}

func handleRLRuleHits(als *AccessLogStore, rs *RateLimitRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := parseHours(r)
		rules := rs.List()
		hits := als.RuleHits(rules, hours)
		writeJSON(w, http.StatusOK, hits)
	}
}

// --- Rate Limit Advisor handler ---

func handleRLAdvisor(als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := queryInt(q.Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		req := RateAdvisorRequest{
			Window:  q.Get("window"),
			Service: q.Get("service"),
			Path:    q.Get("path"),
			Method:  q.Get("method"),
			Limit:   limit,
		}
		writeJSON(w, http.StatusOK, als.ScanRates(req))
	}
}

// --- Rate Limit Analytics handlers ---

func handleRLSummary(als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := parseHours(r)
		writeJSON(w, http.StatusOK, als.Summary(hours))
	}
}

func handleRLEvents(als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		service := q.Get("service")
		client := q.Get("client")
		method := q.Get("method")
		limit := queryInt(q.Get("limit"), 50)
		if limit <= 0 || limit > 1000 {
			limit = 50
		}
		offset := queryInt(q.Get("offset"), 0)
		if offset < 0 {
			offset = 0
		}
		hours := parseHours(r)
		writeJSON(w, http.StatusOK, als.FilteredEvents(service, client, method, limit, offset, hours))
	}
}
