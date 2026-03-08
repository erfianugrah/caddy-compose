package main

import (
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

func handleGenerateConfig(cs *ConfigStore, es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		cfg := cs.Get()
		exclusions := es.EnabledExclusions()
		ResetRuleIDCounter()
		result := GenerateConfigs(cfg, exclusions)
		// Include WAF settings in the response.
		wafSettings := GenerateWAFSettings(cfg)
		writeJSON(w, http.StatusOK, map[string]string{
			"pre_crs_conf":  result.PreCRS,
			"post_crs_conf": result.PostCRS,
			"waf_settings":  wafSettings,
		})
	}
}

// --- Handler: Validate ---

func handleValidateConfig(cs *ConfigStore, es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := cs.Get()
		exclusions := es.EnabledExclusions()
		ResetRuleIDCounter()
		result := GenerateConfigs(cfg, exclusions)
		wafSettings := GenerateWAFSettings(cfg)

		vr := ValidateGeneratedConfig(result.PreCRS, result.PostCRS, wafSettings)

		// Also check for self-referencing rule IDs.
		selfRefWarnings := validateGeneratedRuleIDs(exclusions)
		vr.Warnings = append(vr.Warnings, selfRefWarnings...)
		for _, w := range selfRefWarnings {
			if w.Level == "error" {
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

func handleDeploy(cs *ConfigStore, es *ExclusionStore, rs *RateLimitRuleStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		deployMu.Lock()
		defer deployMu.Unlock()
		cfg := cs.Get()
		exclusions := es.EnabledExclusions()
		ResetRuleIDCounter()
		result := GenerateConfigs(cfg, exclusions)
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
		if err := writeConfFiles(deployCfg.CorazaDir, result.PreCRS, result.PostCRS, wafSettings); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error:   "failed to write config files",
				Details: err.Error(),
			})
			return
		}

		// Ensure any new Caddyfile services have rate limit files before reload.
		syncCaddyfileServices(rs, deployCfg)

		// Reload Caddy via admin API.
		// Pass the config file paths so reloadCaddy can fingerprint them and
		// inject a unique comment, forcing Caddy to reparse all includes.
		confFiles := []string{
			filepath.Join(deployCfg.CorazaDir, "custom-pre-crs.conf"),
			filepath.Join(deployCfg.CorazaDir, "custom-post-crs.conf"),
			filepath.Join(deployCfg.CorazaDir, "custom-waf-settings.conf"),
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
