package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// detectionOnlyThreshold is the anomaly score threshold used in detection_only
// mode. Set high enough that no request will be blocked, so everything is
// logged but nothing is denied.
const detectionOnlyThreshold = 10000

// GenerateWAFSettings produces custom-waf-settings.conf content.
// This file is positioned between @crs-setup.conf.example and @owasp_crs/*.conf
// in the Caddyfile, so it overrides CRS defaults before CRS rules evaluate them.
//
// It generates:
//   - Default SecAction for paranoia level and anomaly thresholds
//   - Per-service SecRule SERVER_NAME overrides for custom settings
//   - Per-service ctl:ruleRemoveByTag for disabled rule groups
//   - Per-service ctl:ruleEngine=Off for disabled services
func GenerateWAFSettings(cfg WAFConfig) string {
	var b strings.Builder
	idGen := newSettingsIDGen()

	b.WriteString("# ============================================================\n")
	b.WriteString("# WAF Dynamic Settings\n")
	b.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("# Loaded AFTER @crs-setup.conf.example, BEFORE @owasp_crs/*.conf\n")
	b.WriteString("# ============================================================\n\n")

	// --- Defaults ---
	b.WriteString("# --- Global Defaults ---\n")
	b.WriteString("# Override CRS setup defaults. Applied to all services.\n")
	b.WriteString("# Per-service overrides below can further modify these values.\n\n")

	d := cfg.Defaults
	// For detection_only mode, thresholds are set high (log everything, block nothing).
	inT, outT := d.InboundThreshold, d.OutboundThreshold
	if d.Mode == "detection_only" {
		inT, outT = detectionOnlyThreshold, detectionOnlyThreshold
	}

	// Resolve blocking/detection paranoia levels: if explicitly set, use them;
	// otherwise default to the main paranoia level (legacy behavior).
	bpl := d.BlockingParanoiaLevel
	if bpl == 0 {
		bpl = d.ParanoiaLevel
	}
	dpl := d.DetectionParanoiaLevel
	if dpl == 0 {
		dpl = d.ParanoiaLevel
	}

	b.WriteString(fmt.Sprintf("SecAction \"id:%s,phase:1,pass,t:none,nolog,"+
		"setvar:tx.paranoia_level=%d,"+
		"setvar:tx.blocking_paranoia_level=%d,"+
		"setvar:tx.detection_paranoia_level=%d\"\n",
		idGen.next(), d.ParanoiaLevel, bpl, dpl))
	b.WriteString(fmt.Sprintf("SecAction \"id:%s,phase:1,pass,t:none,nolog,"+
		"setvar:tx.inbound_anomaly_score_threshold=%d,"+
		"setvar:tx.outbound_anomaly_score_threshold=%d\"\n",
		idGen.next(), inT, outT))

	// Emit extended CRS v4 settings (only non-zero/non-default values).
	extVars := collectExtendedSetvars(d)
	if len(extVars) > 0 {
		b.WriteString(fmt.Sprintf("SecAction \"id:%s,phase:1,pass,t:none,nolog,%s\"\n",
			idGen.next(), strings.Join(extVars, ",")))
	}
	b.WriteString("\n")

	// Emit SecRuleEngine directive based on the global mode.
	// This is a config-time directive (not per-request ctl), making the
	// generator the single source of truth for the WAF engine state.
	// The Caddyfile must NOT contain its own SecRuleEngine directive.
	switch d.Mode {
	case "disabled":
		b.WriteString("SecRuleEngine Off\n\n")
	case "detection_only":
		b.WriteString("SecRuleEngine DetectionOnly\n\n")
	default: // "enabled"
		b.WriteString("SecRuleEngine On\n\n")
	}

	// Default disabled groups.
	for _, tag := range d.DisabledGroups {
		b.WriteString(fmt.Sprintf("SecAction \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleRemoveByTag=%s\"\n",
			idGen.next(), tag))
	}
	if len(d.DisabledGroups) > 0 {
		b.WriteString("\n")
	}

	// --- Per-service overrides ---
	if len(cfg.Services) > 0 {
		b.WriteString("# --- Per-Service Overrides ---\n")
		b.WriteString("# Each rule matches SERVER_NAME for the specific service hostname.\n")
		b.WriteString("# Only fires within that service's coraza_waf instance.\n\n")

		// Sort for deterministic output.
		hosts := sortedKeys(cfg.Services)
		for _, host := range hosts {
			ss := cfg.Services[host]
			writeServiceOverride(&b, host, ss, d, idGen)
		}
	}

	return b.String()
}

// collectExtendedSetvars collects setvar directives for CRS v4 extended settings.
// Only emits setvars for non-zero/non-default values.
func collectExtendedSetvars(ss WAFServiceSettings) []string {
	var vars []string
	if ss.EarlyBlocking != nil && *ss.EarlyBlocking {
		vars = append(vars, "setvar:tx.early_blocking=1")
	}
	if ss.SamplingPercentage > 0 && ss.SamplingPercentage != 100 {
		vars = append(vars, fmt.Sprintf("setvar:tx.sampling_percentage=%d", ss.SamplingPercentage))
	}
	if ss.ReportingLevel > 0 {
		vars = append(vars, fmt.Sprintf("setvar:tx.reporting_level=%d", ss.ReportingLevel))
	}
	if ss.EnforceBodyprocURLEncoded != nil && *ss.EnforceBodyprocURLEncoded {
		vars = append(vars, "setvar:tx.enforce_bodyproc_urlencoded=1")
	}
	if ss.AllowedMethods != "" {
		vars = append(vars, fmt.Sprintf("setvar:'tx.allowed_methods=%s'", escapeSecRuleValue(ss.AllowedMethods)))
	}
	if ss.AllowedRequestContentType != "" {
		vars = append(vars, fmt.Sprintf("setvar:'tx.allowed_request_content_type=%s'", escapeSecRuleValue(ss.AllowedRequestContentType)))
	}
	if ss.AllowedHTTPVersions != "" {
		vars = append(vars, fmt.Sprintf("setvar:'tx.allowed_http_versions=%s'", escapeSecRuleValue(ss.AllowedHTTPVersions)))
	}
	if ss.RestrictedExtensions != "" {
		vars = append(vars, fmt.Sprintf("setvar:'tx.restricted_extensions=%s'", escapeSecRuleValue(ss.RestrictedExtensions)))
	}
	if ss.RestrictedHeaders != "" {
		vars = append(vars, fmt.Sprintf("setvar:'tx.restricted_headers=%s'", escapeSecRuleValue(ss.RestrictedHeaders)))
	}
	if ss.MaxNumArgs > 0 {
		vars = append(vars, fmt.Sprintf("setvar:tx.max_num_args=%d", ss.MaxNumArgs))
	}
	if ss.ArgNameLength > 0 {
		vars = append(vars, fmt.Sprintf("setvar:tx.arg_name_length=%d", ss.ArgNameLength))
	}
	if ss.ArgLength > 0 {
		vars = append(vars, fmt.Sprintf("setvar:tx.arg_length=%d", ss.ArgLength))
	}
	if ss.TotalArgLength > 0 {
		vars = append(vars, fmt.Sprintf("setvar:tx.total_arg_length=%d", ss.TotalArgLength))
	}
	if ss.MaxFileSize > 0 {
		vars = append(vars, fmt.Sprintf("setvar:tx.max_file_size=%d", ss.MaxFileSize))
	}
	if ss.CombinedFileSizes > 0 {
		vars = append(vars, fmt.Sprintf("setvar:tx.combined_file_sizes=%d", ss.CombinedFileSizes))
	}
	// CRS exclusion profiles: each profile sets tx.crs_exclusions_<name>=1
	for _, excl := range ss.CRSExclusions {
		vars = append(vars, fmt.Sprintf("setvar:tx.crs_exclusions_%s=1", excl))
	}
	return vars
}

// writeServiceOverride generates SecRule(s) for a single service override.
func writeServiceOverride(b *strings.Builder, host string, ss, defaults WAFServiceSettings, idGen *settingsIDGen) {
	escapedHost := escapeSecRuleValue(host)

	// If disabled, generate ctl:ruleEngine=Off (only if default is not already disabled).
	if ss.Mode == "disabled" && defaults.Mode != "disabled" {
		b.WriteString(fmt.Sprintf("# %s\n", host))
		b.WriteString(fmt.Sprintf("SecRule SERVER_NAME \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleEngine=Off\"\n\n",
			escapedHost, idGen.next()))
		return // No further overrides needed for disabled services.
	}

	// Determine if we need to change the rule engine mode for this service.
	// Possible transitions:
	//   default=disabled      + service=blocking       → ctl:ruleEngine=On
	//   default=disabled      + service=detection_only → ctl:ruleEngine=DetectionOnly
	//   default=detection_only + service=blocking      → ctl:ruleEngine=On
	//   default=blocking      + service=detection_only → ctl:ruleEngine=DetectionOnly
	var engineOverride string
	if ss.Mode != defaults.Mode {
		switch {
		case ss.Mode == "detection_only":
			engineOverride = "DetectionOnly"
		case defaults.Mode == "disabled" || defaults.Mode == "detection_only":
			// Service is "blocking" (the default/empty mode) but global is
			// disabled or detection_only — re-enable full blocking.
			engineOverride = "On"
		}
	}

	// For detection_only, override thresholds to log everything.
	inT, outT := ss.InboundThreshold, ss.OutboundThreshold
	if ss.Mode == "detection_only" {
		inT, outT = detectionOnlyThreshold, detectionOnlyThreshold
	}

	// Check if paranoia or thresholds differ from defaults.
	defInT, defOutT := defaults.InboundThreshold, defaults.OutboundThreshold
	if defaults.Mode == "detection_only" {
		defInT, defOutT = detectionOnlyThreshold, detectionOnlyThreshold
	}

	needsParanoiaOverride := ss.ParanoiaLevel != defaults.ParanoiaLevel
	needsThresholdOverride := inT != defInT || outT != defOutT

	// Resolve per-service blocking/detection paranoia levels.
	svcBPL := ss.BlockingParanoiaLevel
	if svcBPL == 0 {
		svcBPL = ss.ParanoiaLevel
	}
	svcDPL := ss.DetectionParanoiaLevel
	if svcDPL == 0 {
		svcDPL = ss.ParanoiaLevel
	}
	defBPL := defaults.BlockingParanoiaLevel
	if defBPL == 0 {
		defBPL = defaults.ParanoiaLevel
	}
	defDPL := defaults.DetectionParanoiaLevel
	if defDPL == 0 {
		defDPL = defaults.ParanoiaLevel
	}
	needsBPLOverride := svcBPL != defBPL
	needsDPLOverride := svcDPL != defDPL

	// Extended CRS v4 settings: compare against defaults to emit only differences.
	svcExtVars := collectExtendedSetvars(ss)
	defExtVars := collectExtendedSetvars(defaults)
	needsExtOverride := !stringSliceEqual(svcExtVars, defExtVars)

	// Disabled rule groups (unique to this service, not already in defaults).
	defaultDisabled := make(map[string]bool, len(defaults.DisabledGroups))
	for _, tag := range defaults.DisabledGroups {
		defaultDisabled[tag] = true
	}
	var extraGroups []string
	for _, tag := range ss.DisabledGroups {
		if !defaultDisabled[tag] {
			extraGroups = append(extraGroups, tag)
		}
	}

	// Skip this service entirely if it produces no output (identical to defaults).
	if engineOverride == "" && !needsParanoiaOverride && !needsBPLOverride && !needsDPLOverride && !needsThresholdOverride && !needsExtOverride && len(extraGroups) == 0 {
		return
	}

	b.WriteString(fmt.Sprintf("# %s\n", host))

	// Emit engine override when the service mode differs from the global default.
	if engineOverride != "" {
		b.WriteString(fmt.Sprintf("SecRule SERVER_NAME \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleEngine=%s\"\n",
			escapedHost, idGen.next(), engineOverride))
	}

	if needsParanoiaOverride || needsBPLOverride || needsDPLOverride || needsThresholdOverride {
		var setvars []string
		if needsParanoiaOverride {
			setvars = append(setvars,
				fmt.Sprintf("setvar:tx.paranoia_level=%d", ss.ParanoiaLevel),
			)
		}
		if needsParanoiaOverride || needsBPLOverride {
			setvars = append(setvars,
				fmt.Sprintf("setvar:tx.blocking_paranoia_level=%d", svcBPL),
			)
		}
		if needsParanoiaOverride || needsDPLOverride {
			setvars = append(setvars,
				fmt.Sprintf("setvar:tx.detection_paranoia_level=%d", svcDPL),
			)
		}
		if needsThresholdOverride {
			setvars = append(setvars,
				fmt.Sprintf("setvar:tx.inbound_anomaly_score_threshold=%d", inT),
				fmt.Sprintf("setvar:tx.outbound_anomaly_score_threshold=%d", outT),
			)
		}
		b.WriteString(fmt.Sprintf("SecRule SERVER_NAME \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,%s\"\n",
			escapedHost, idGen.next(), strings.Join(setvars, ",")))
	}

	// Extended CRS v4 settings override.
	if needsExtOverride && len(svcExtVars) > 0 {
		b.WriteString(fmt.Sprintf("SecRule SERVER_NAME \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,%s\"\n",
			escapedHost, idGen.next(), strings.Join(svcExtVars, ",")))
	}

	for _, tag := range extraGroups {
		b.WriteString(fmt.Sprintf("SecRule SERVER_NAME \"@streq %s\" \"id:%s,phase:1,pass,t:none,nolog,ctl:ruleRemoveByTag=%s\"\n",
			escapedHost, idGen.next(), tag))
	}

	b.WriteString("\n")
}

// stringSliceEqual compares two string slices for equality.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sortedKeys returns map keys sorted alphabetically.
func sortedKeys(m map[string]WAFServiceSettings) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// settingsIDGen generates unique rule IDs in the 97xxxxx range
// for WAF settings overrides (separate from exclusion IDs in 95xxxxx).
type settingsIDGen struct {
	counter int
}

func newSettingsIDGen() *settingsIDGen {
	return &settingsIDGen{}
}

func (g *settingsIDGen) next() string {
	g.counter++
	return fmt.Sprintf("97%05d", g.counter)
}
