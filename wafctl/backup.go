package main

import (
	"net/http"
	"time"
)

// ─── Backup / Restore ───────────────────────────────────────────────────────
//
// Unified backup bundles all five configuration stores into a single JSON
// envelope for download. Restore replaces all stores atomically (per-store),
// preserving ipsum managed lists and assigning fresh UUIDs.

// FullBackup is the top-level envelope for a complete config backup.
type FullBackup struct {
	Version    int             `json:"version"`
	ExportedAt time.Time       `json:"exported_at"`
	WAFConfig  WAFConfig       `json:"waf_config"`
	CSPConfig  CSPConfig       `json:"csp_config"`
	Exclusions []RuleExclusion `json:"exclusions"`
	RateLimits RateLimitBackup `json:"rate_limits"`
	Lists      []ManagedList   `json:"lists"`
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
	es *ExclusionStore,
	rs *RateLimitRuleStore,
	ls *ManagedListStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Collect from all stores. Each getter returns a deep copy.
		exclusionExport := es.Export()
		rlExport := rs.Export()
		listExport := ls.Export() // already excludes ipsum lists

		backup := FullBackup{
			Version:    1,
			ExportedAt: time.Now().UTC(),
			WAFConfig:  cs.Get(),
			CSPConfig:  cspS.Get(),
			Exclusions: exclusionExport.Exclusions,
			RateLimits: RateLimitBackup{
				Rules:  rlExport.Rules,
				Global: rlExport.Global,
			},
			Lists: listExport.Lists,
		}

		// Set Content-Disposition so browsers offer a file download.
		w.Header().Set("Content-Disposition",
			`attachment; filename="wafctl-backup-`+backup.ExportedAt.Format("2006-01-02T150405Z")+`.json"`)
		writeJSON(w, http.StatusOK, backup)
	}
}

// handleRestore replaces all configuration stores from a unified backup.
// Each store is restored independently — a failure in one store does not
// roll back previously restored stores (partial restore is better than
// no restore). The response reports per-store success/failure.
func handleRestore(
	cs *ConfigStore,
	cspS *CSPStore,
	es *ExclusionStore,
	rs *RateLimitRuleStore,
	ls *ManagedListStore,
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

		results := make(map[string]string)

		// 1. WAF Config
		if err := validateConfig(backup.WAFConfig); err != nil {
			results["waf_config"] = "failed: " + err.Error()
		} else if _, err := cs.Update(backup.WAFConfig); err != nil {
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

		// 3. Exclusions
		if len(backup.Exclusions) == 0 {
			results["exclusions"] = "skipped: no exclusions in backup"
		} else {
			for i, exc := range backup.Exclusions {
				if err := validateExclusion(exc); err != nil {
					results["exclusions"] = "failed: exclusion " + itoa(i) + ": " + err.Error()
					break
				}
			}
			if _, ok := results["exclusions"]; !ok {
				if err := es.Import(backup.Exclusions); err != nil {
					results["exclusions"] = "failed: " + err.Error()
				} else {
					results["exclusions"] = "restored " + itoa(len(backup.Exclusions)) + " exclusions"
				}
			}
		}

		// 4. Rate Limit Rules
		if len(backup.RateLimits.Rules) == 0 {
			results["rate_limits"] = "skipped: no rules in backup"
		} else {
			for i, rule := range backup.RateLimits.Rules {
				if err := validateRateLimitRule(rule); err != nil {
					results["rate_limits"] = "failed: rule " + itoa(i) + ": " + err.Error()
					break
				}
			}
			if _, ok := results["rate_limits"]; !ok {
				if err := rs.Import(backup.RateLimits.Rules); err != nil {
					results["rate_limits"] = "failed: " + err.Error()
				} else {
					results["rate_limits"] = "restored " + itoa(len(backup.RateLimits.Rules)) + " rules"
				}
			}
		}

		// 5. Managed Lists (ipsum lists are preserved by the store's Import method)
		if len(backup.Lists) == 0 {
			results["lists"] = "skipped: no lists in backup"
		} else {
			for i, list := range backup.Lists {
				if list.Source == "ipsum" {
					continue // skip validation for ipsum (they're ignored on import anyway)
				}
				if err := validateManagedList(list); err != nil {
					results["lists"] = "failed: list " + itoa(i) + ": " + err.Error()
					break
				}
			}
			if _, ok := results["lists"]; !ok {
				if err := ls.Import(backup.Lists); err != nil {
					results["lists"] = "failed: " + err.Error()
				} else {
					results["lists"] = "restored " + itoa(len(backup.Lists)) + " lists"
				}
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

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  status,
			"results": results,
		})
	}
}

// itoa is a tiny int-to-string helper (avoids importing strconv just for this).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
