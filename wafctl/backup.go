package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ─── Backup / Restore ───────────────────────────────────────────────────────
//
// Unified backup bundles all six configuration stores into a single JSON
// envelope for download. Restore replaces all stores atomically (per-store),
// preserving ipsum managed lists and assigning fresh UUIDs.

// FullBackup is the top-level envelope for a complete config backup.
type FullBackup struct {
	Version              int                        `json:"version"`
	ExportedAt           time.Time                  `json:"exported_at"`
	WAFConfig            WAFConfig                  `json:"waf_config"`
	CSPConfig            CSPConfig                  `json:"csp_config"`
	SecurityHeaders      SecurityHeaderConfig       `json:"security_headers"`
	Exclusions           []RuleExclusion            `json:"exclusions"`
	RateLimits           RateLimitBackup            `json:"rate_limits"`
	Lists                []ManagedList              `json:"lists"`
	DefaultRuleOverrides map[string]json.RawMessage `json:"default_rule_overrides,omitempty"`
}

// RateLimitBackup holds both rules and global config for rate limits.
type RateLimitBackup struct {
	Rules  []RateLimitRule       `json:"rules"`
	Global RateLimitGlobalConfig `json:"global"`
}

// handleBackup returns a unified backup of all configuration stores.
func handleBackup(
	cs *ConfigStore,
	cspS *CSPStore,
	secS *SecurityHeaderStore,
	es *ExclusionStore,
	ls *ManagedListStore,
	ds *DefaultRuleStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Collect from all stores. Each getter returns a deep copy.
		exclusionExport := es.Export()
		listExport := ls.Export() // already excludes ipsum lists

		backup := FullBackup{
			Version:              1,
			ExportedAt:           time.Now().UTC(),
			WAFConfig:            cs.Get(),
			CSPConfig:            cspS.Get(),
			SecurityHeaders:      secS.Get(),
			Exclusions:           exclusionExport.Exclusions,
			RateLimits:           RateLimitBackup{}, // empty — rate_limit rules are now in Exclusions
			Lists:                listExport.Lists,
			DefaultRuleOverrides: ds.GetOverrides(),
		}

		// Set Content-Disposition so browsers offer a file download.
		w.Header().Set("Content-Disposition",
			`attachment; filename="wafctl-backup-`+backup.ExportedAt.Format("2006-01-02T150405Z")+`.json"`)
		writeJSON(w, http.StatusOK, backup)
	}
}

// handleRestore replaces all configuration stores from a unified backup.
// Uses a two-pass approach: first validate ALL stores, then apply changes.
// If any validation fails, no stores are modified (prevents partial restores
// that could weaken security).
func handleRestore(
	cs *ConfigStore,
	cspS *CSPStore,
	secS *SecurityHeaderStore,
	es *ExclusionStore,
	ls *ManagedListStore,
	ds *DefaultRuleStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var backup FullBackup
		if _, failed := decodeJSON(w, r, &backup); failed {
			return
		}

		if backup.Version == 0 {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "invalid backup: missing or zero version field",
			})
			return
		}

		// ── Pass 1: Validate everything before modifying any store ──
		var validationErrors []string

		// 1. WAF Config
		if err := validateConfig(backup.WAFConfig); err != nil {
			validationErrors = append(validationErrors, "waf_config: "+err.Error())
		}

		// 2. CSP Config — CSPStore.Update handles validation internally;
		// no separate validation function exists. Validated during apply.

		// 3. Security Headers — same as CSP: validated during apply.

		// 4. Exclusions
		if len(backup.Exclusions) > 0 {
			for i, exc := range backup.Exclusions {
				if err := validateExclusion(exc); err != nil {
					validationErrors = append(validationErrors,
						"exclusion "+strconv.Itoa(i)+": "+err.Error())
					break
				}
			}
		}

		// 5. Managed Lists
		if len(backup.Lists) > 0 {
			for i, list := range backup.Lists {
				if list.Source == "ipsum" {
					continue // skip validation for ipsum (ignored on import)
				}
				if err := validateManagedList(list); err != nil {
					validationErrors = append(validationErrors,
						"list "+strconv.Itoa(i)+": "+err.Error())
					break
				}
			}
		}

		// If any pre-apply validation failed, reject the entire restore.
		if len(validationErrors) > 0 {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error:   "backup validation failed — no stores were modified",
				Details: "validation errors: " + strings.Join(validationErrors, "; "),
			})
			return
		}

		// ── Pass 2: Apply all changes ──────────────────────────────
		results := make(map[string]string)

		// 1. WAF Config
		if _, err := cs.Update(backup.WAFConfig); err != nil {
			results["waf_config"] = "failed: " + err.Error()
		} else {
			results["waf_config"] = "restored"
		}

		// 2. CSP Config
		if _, err := cspS.Update(backup.CSPConfig); err != nil {
			results["csp_config"] = "failed: " + err.Error()
		} else {
			results["csp_config"] = "restored"
		}

		// 3. Security Headers
		if _, err := secS.Update(backup.SecurityHeaders); err != nil {
			results["security_headers"] = "failed: " + err.Error()
		} else {
			results["security_headers"] = "restored"
		}

		// 4. Exclusions
		if len(backup.Exclusions) == 0 {
			results["exclusions"] = "skipped: no exclusions in backup"
		} else {
			if err := es.Import(backup.Exclusions); err != nil {
				results["exclusions"] = "failed: " + err.Error()
			} else {
				results["exclusions"] = "restored " + strconv.Itoa(len(backup.Exclusions)) + " exclusions"
			}
		}

		// 5. Rate Limit Rules — skipped (rate_limit rules are now managed via the unified ExclusionStore).
		// Old backups may contain rate_limits; we gracefully ignore them.
		if len(backup.RateLimits.Rules) > 0 {
			results["rate_limits"] = "skipped: legacy rate_limit rules ignored (use exclusions with type=rate_limit)"
		} else {
			results["rate_limits"] = "skipped: no rules in backup"
		}

		// 6. Managed Lists (ipsum lists are preserved by the store's Import method)
		if len(backup.Lists) == 0 {
			results["lists"] = "skipped: no lists in backup"
		} else {
			if err := ls.Import(backup.Lists); err != nil {
				results["lists"] = "failed: " + err.Error()
			} else {
				results["lists"] = "restored " + strconv.Itoa(len(backup.Lists)) + " lists"
			}
		}

		// 7. Default Rule Overrides
		if len(backup.DefaultRuleOverrides) == 0 {
			results["default_rules"] = "skipped: no overrides in backup"
		} else {
			if err := ds.ReplaceOverrides(backup.DefaultRuleOverrides); err != nil {
				results["default_rules"] = "failed: " + err.Error()
			} else {
				results["default_rules"] = "restored " + strconv.Itoa(len(backup.DefaultRuleOverrides)) + " overrides"
			}
		}

		// Determine overall status.
		status := "restored"
		for _, v := range results {
			if len(v) > 6 && v[:6] == "failed" {
				status = "partial"
				break
			}
		}

		resp := map[string]interface{}{
			"status":  status,
			"results": results,
		}
		if status == "partial" {
			resp["warning"] = "Some store updates failed during apply. " +
				"Re-run the restore or manually fix the failed stores. " +
				"A deploy is recommended to sync the live Caddy config."
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
