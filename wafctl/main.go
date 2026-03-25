package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// version is the wafctl release version, shown in /api/health.
// Set at build time via: -ldflags="-X main.version=2.64.0"
var version = "dev"

// startTime records when the process started, used for uptime calculation.
var startTime = time.Now()

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

// runServe starts the HTTP API server. This is the default command.
func runServe() int {
	port := envOr("WAFCTL_PORT", "8080")
	exclusionsFile := envOr("WAF_EXCLUSIONS_FILE", "/data/exclusions.json")
	configFile := envOr("WAF_CONFIG_FILE", "/data/waf-config.json")
	combinedAccessLog := envOr("WAF_COMBINED_ACCESS_LOG", "/var/log/combined-access.log")

	cspFile := envOr("WAF_CSP_FILE", "/data/csp-config.json")
	secHeadersFile := envOr("WAF_SECURITY_HEADERS_FILE", "/data/security-headers.json")
	corsFile := envOr("WAF_CORS_FILE", "/data/cors.json")
	managedListsFile := envOr("WAF_MANAGED_LISTS_FILE", "/data/lists.json")
	managedListsDir := envOr("WAF_MANAGED_LISTS_DIR", "/data/lists")

	policyRulesFile := envOr("WAF_POLICY_RULES_FILE", "/data/waf/policy-rules.json")

	defaultRulesFile := envOr("WAF_DEFAULT_RULES_FILE", "/etc/caddy/waf/default-rules.json")
	defaultRulesOverridesFile := envOr("WAF_DEFAULT_RULES_OVERRIDES_FILE", "/data/default-rule-overrides.json")

	// Challenge HMAC key: read from env or auto-generate and persist.
	challengeHMACKey := envOr("CHALLENGE_HMAC_KEY", "")
	if challengeHMACKey == "" {
		challengeHMACKey = loadOrGenerateChallengeKey(envOr("WAF_DATA_DIR", "/data"))
	}

	deployCfg := DeployConfig{
		WafDir:           envOr("WAF_DIR", "/data/waf"),
		CaddyfilePath:    envOr("WAF_CADDYFILE_PATH", "/data/Caddyfile"),
		CaddyAdminURL:    envOr("WAF_CADDY_ADMIN_URL", "http://caddy:2020"),
		PolicyRulesFile:  policyRulesFile,
		ChallengeHMACKey: challengeHMACKey,
	}

	// Ensure WAF config directory and placeholder files exist.
	if err := ensureWafDir(deployCfg.WafDir); err != nil {
		log.Printf("[boot] warning: could not initialize waf dir: %v", err)
	}

	// Event retention: maximum age for in-memory events (default 2160h = 90 days).
	maxAgeStr := envOr("WAF_EVENT_MAX_AGE", "2160h")
	maxAge, err := time.ParseDuration(maxAgeStr)
	if err != nil {
		log.Printf("[boot] warning: invalid WAF_EVENT_MAX_AGE %q, using 2160h", maxAgeStr)
		maxAge = 2160 * time.Hour
	}

	// General log retention (shorter due to higher volume, default 168h = 7 days).
	generalMaxAgeStr := envOr("WAF_GENERAL_LOG_MAX_AGE", "168h")
	generalMaxAge, err := time.ParseDuration(generalMaxAgeStr)
	if err != nil {
		log.Printf("[boot] warning: invalid WAF_GENERAL_LOG_MAX_AGE %q, using 168h", generalMaxAgeStr)
		generalMaxAge = 168 * time.Hour
	}

	// Tailing interval (default 5s).
	tailIntervalStr := envOr("WAF_TAIL_INTERVAL", "5s")
	tailInterval, err := time.ParseDuration(tailIntervalStr)
	if err != nil {
		log.Printf("[boot] warning: invalid WAF_TAIL_INTERVAL %q, using 5s", tailIntervalStr)
		tailInterval = 5 * time.Second
	}

	geoDBPath := envOr("WAF_GEOIP_DB", "/data/geoip/country.mmdb")
	geoAPIURL := envOr("WAF_GEOIP_API_URL", "")
	geoAPIKey := envOr("WAF_GEOIP_API_KEY", "")

	log.Printf("wafctl starting: combined=%s port=%s exclusions=%s config=%s lists=%s waf_dir=%s max_age=%s tail_interval=%s geoip_db=%s geoip_api=%s default_rules=%s",
		combinedAccessLog, port, exclusionsFile, configFile, managedListsFile, deployCfg.WafDir, maxAge, tailInterval, geoDBPath, geoAPIURL, defaultRulesFile)

	var geoAPICfg *GeoIPAPIConfig
	if geoAPIURL != "" {
		geoAPICfg = &GeoIPAPIConfig{URL: geoAPIURL, Key: geoAPIKey}
	}
	geoStore := NewGeoIPStore(geoDBPath, geoAPICfg)

	// Create shutdown context early so background goroutines can be cancelled.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// ── Create stores (lightweight — no JSONL loading yet) ──
	// Hard caps prevent OOM under bombardment. Defaults are generous for normal
	// traffic but bounded: 100K security events (~200MB), 100K access events
	// (~100MB), 50K general log events (~25MB). Under sustained attack, oldest
	// events are silently evicted — summary counters preserve aggregate stats.
	wafMaxItems := queryIntEnv("WAF_EVENT_MAX_ITEMS", 100000)
	accessMaxItems := queryIntEnv("WAF_ACCESS_MAX_ITEMS", 100000)
	generalMaxItems := queryIntEnv("WAF_GENERAL_LOG_MAX_ITEMS", 50000)

	store := NewStore()
	store.SetMaxAge(maxAge)
	store.SetMaxItems(wafMaxItems)
	store.SetGeoIP(geoStore)

	accessLogStore := NewAccessLogStore(combinedAccessLog)
	accessLogStore.SetOffsetFile(envOr("WAF_ACCESS_OFFSET_FILE", "/data/.access-log-offset"))
	accessLogStore.SetMaxAge(maxAge)
	accessLogStore.SetMaxItems(accessMaxItems)
	accessLogStore.SetGeoIP(geoStore)

	generalLogStore := NewGeneralLogStore(combinedAccessLog)
	generalLogStore.SetOffsetFile(envOr("WAF_GENERAL_LOG_OFFSET_FILE", "/data/.general-log-offset"))
	generalLogStore.SetMaxAge(generalMaxAge)
	generalLogStore.SetMaxItems(generalMaxItems)
	generalLogStore.SetGeoIP(geoStore)

	// General log sampling: store only a fraction of normal 2xx traffic.
	// Non-2xx responses (errors, WAF blocks, rate limits) are always kept.
	// Default: 10% sampling. Set WAF_GENERAL_LOG_SAMPLE_RATE=1.0 to keep all.
	if rateStr := envOr("WAF_GENERAL_LOG_SAMPLE_RATE", "0.1"); rateStr != "" {
		if rate, err := strconv.ParseFloat(rateStr, 64); err == nil {
			generalLogStore.SetSampleRate(rate)
			if rate < 1.0 {
				log.Printf("general log sampling: keeping %.0f%% of 2xx responses", rate*100)
			}
		}
	}

	// Config stores load instantly (small JSON files).
	exclusionStore := NewExclusionStore(exclusionsFile)
	accessLogStore.SetExclusionStore(exclusionStore)
	configStore := NewConfigStore(configFile)
	cspStore := NewCSPStore(cspFile)
	secHeaderStore := NewSecurityHeaderStore(secHeadersFile)
	corsStore := NewCORSStore(corsFile)
	managedListStore := NewManagedListStore(managedListsFile, managedListsDir)
	defaultRuleStore := NewDefaultRuleStore(defaultRulesFile, defaultRulesOverridesFile)

	// Load CRS metadata (category taxonomy, valid prefixes, severity levels).
	// Generated by crs-converter at Docker build time from actual CRS .conf files.
	// Required — no hardcoded fallback. The converter must run at build time.
	crsMetadataFile := envOr("WAF_CRS_METADATA_FILE", "/etc/caddy/waf/crs-metadata.json")
	meta, err := LoadCRSMetadata(crsMetadataFile)
	if err != nil {
		log.Fatalf("[crs] fatal: loading metadata from %s: %v", crsMetadataFile, err)
	}
	SetCRSMetadata(meta)

	// Set up the CRS catalog backed by the default rule store. All catalog
	// data comes from default-rules.json + crs-metadata.json (both built by
	// crs-converter at Docker build time).
	SetCRSCatalog(NewCRSCatalog(defaultRuleStore))

	// Generate-on-boot: regenerate policy-rules.json from stored config so
	// Caddy's policy engine has fresh rules on startup. This only reads small
	// config files (exclusions, config, CSP, etc.) — not event stores.
	generateOnBoot(configStore, exclusionStore, cspStore, secHeaderStore, corsStore, managedListStore, defaultRuleStore, deployCfg)

	blocklistStore := NewBlocklistStore()
	blocklistStore.SetOnRefresh(func(ipsByScore map[int][]string) {
		managedListStore.SyncIPsum(ipsByScore)
	})
	blocklistStore.SetOnDeploy(func() error {
		return deployAll(configStore, exclusionStore, managedListStore, cspStore, secHeaderStore, corsStore, defaultRuleStore, deployCfg)
	})

	// Schedule daily blocklist refresh at the configured UTC hour (default 06:00).
	refreshHour := 6
	if h := envOr("WAF_BLOCKLIST_REFRESH_HOUR", ""); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n >= 0 && n <= 23 {
			refreshHour = n
		} else {
			log.Printf("[blocklist] warning: invalid WAF_BLOCKLIST_REFRESH_HOUR %q, using 6", h)
		}
	}
	blocklistStore.StartScheduledRefresh(ctx, refreshHour)

	// ── Background loading of heavy event stores ──
	// Load JSONL event files and blocklist IPs in parallel goroutines so
	// the HTTP server starts immediately. Handlers return empty results
	// until loading completes (stores are mutex-protected).
	go func() {
		store.SetEventFile(envOr("WAF_EVENT_FILE", "/data/events.jsonl"))
		store.StartEviction(ctx, tailInterval)
	}()
	go func() {
		accessLogStore.SetEventFile(envOr("WAF_ACCESS_EVENT_FILE", "/data/access-events.jsonl"))
		accessLogStore.StartTailing(ctx, tailInterval)
	}()
	go func() {
		generalLogStore.SetEventFile(envOr("WAF_GENERAL_LOG_FILE", "/data/general-events.jsonl"))
		generalLogStore.StartTailing(ctx, tailInterval)
	}()
	go func() {
		blocklistStore.loadFromLists(managedListStore)
	}()

	// DDoS mitigation stores — jail management + config + spike detection.
	dosJailFile := envOr("WAF_DOS_JAIL_FILE", filepath.Join(deployCfg.WafDir, "jail.json"))
	dosConfigFile := envOr("WAF_DOS_CONFIG_FILE", "/data/dos-config.json")
	jailStore := NewJailStore(dosJailFile)
	dosConfigStore := NewDosConfigStore(dosConfigFile)
	// Seed whitelist in jail.json from current DDoS config so the plugin
	// picks it up on its next sync cycle.
	jailStore.SetWhitelist(dosConfigStore.Get().Whitelist)

	// Spike detector — tails access log for ddos_action fields, computes EPS.
	dosCfg := dosConfigStore.Get()
	spikeDetector := NewSpikeDetector(
		combinedAccessLog,
		dosCfg.EPSTrigger,
		dosCfg.EPSCooldown,
		parseDurationOr(dosCfg.CooldownDelay, 30*time.Second),
	)

	// Spike reports — forensic snapshots on spike → normal transition.
	spikeReportsDir := envOr("WAF_DOS_SPIKE_REPORTS_DIR", "/data/spike-reports")
	spikeMaxReports := 100
	if dosCfg.MaxReports > 0 {
		spikeMaxReports = dosCfg.MaxReports
	}
	spikeReporter := NewSpikeReporter(spikeReportsDir, spikeMaxReports, jailStore)
	spikeDetector.SetOnSpikeEnd(func(start, end time.Time, peakEPS float64, totalEvents int64) {
		spikeReporter.Generate(start, end, peakEPS, totalEvents)
	})

	spikeDetector.StartTailing(ctx, tailInterval)

	// Periodic jail file reload (picks up entries added by the plugin).
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				jailStore.Reload()
			}
		}
	}()

	// IP intelligence store — aggregates Team Cymru, RIPE, GreyNoise, Shodan.
	intelStore := NewIPIntelStore(blocklistStore)

	// Cloudflare trusted proxy store — refreshes CF IP ranges at runtime.
	cfProxyPath := filepath.Join(deployCfg.WafDir, "cf_trusted_proxies.caddy")
	cfProxyStore := NewCFProxyStore(cfProxyPath)

	// Schedule weekly CF IP refresh (Monday at the same hour as blocklist).
	cfProxyStore.StartScheduledRefresh(ctx, refreshHour, deployCfg)

	mux := http.NewServeMux()

	// Existing endpoints (with hours filter support) — merged WAF + 429 events
	mux.HandleFunc("GET /api/health", handleHealth(store, accessLogStore, generalLogStore, geoStore, exclusionStore, blocklistStore, cfProxyStore, cspStore, secHeaderStore, defaultRuleStore, jailStore, spikeDetector, spikeReporter))
	mux.HandleFunc("GET /api/summary", handleSummary(store, accessLogStore))
	mux.HandleFunc("GET /api/events", handleEvents(store, accessLogStore))
	mux.HandleFunc("GET /api/services", handleServices(store, accessLogStore))

	// Analytics
	mux.HandleFunc("GET /api/analytics/top-ips", handleTopBlockedIPs(store, accessLogStore))
	mux.HandleFunc("GET /api/analytics/top-uris", handleTopTargetedURIs(store, accessLogStore))
	mux.HandleFunc("GET /api/analytics/top-countries", handleTopCountries(store, accessLogStore))

	// IP Lookup
	mux.HandleFunc("GET /api/lookup/{ip}", handleIPLookup(store, accessLogStore, geoStore, intelStore))

	// Exclusion CRUD
	mux.HandleFunc("GET /api/exclusions", handleListExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions", handleCreateExclusion(exclusionStore))
	mux.HandleFunc("GET /api/exclusions/export", handleExportExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions/import", handleImportExclusions(exclusionStore))
	mux.HandleFunc("PUT /api/exclusions/reorder", handleReorderExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions/bulk", handleBulkExclusions(exclusionStore))
	mux.HandleFunc("GET /api/exclusions/hits", handleExclusionHits(store, accessLogStore, exclusionStore))
	mux.HandleFunc("GET /api/exclusions/{id}", handleGetExclusion(exclusionStore))
	mux.HandleFunc("PUT /api/exclusions/{id}", handleUpdateExclusion(exclusionStore))
	mux.HandleFunc("DELETE /api/exclusions/{id}", handleDeleteExclusion(exclusionStore))

	// CRS Catalog
	mux.HandleFunc("GET /api/crs/rules", handleCRSRules)

	// ── Unified Rules API ─────────────────────────────────────────────
	// /api/rules is the canonical endpoint for all rule types (allow, block,
	// skip, detect, rate_limit). Backed by ExclusionStore (now the unified store).
	mux.HandleFunc("GET /api/rules", handleListExclusions(exclusionStore))
	mux.HandleFunc("POST /api/rules", handleCreateExclusion(exclusionStore))
	mux.HandleFunc("GET /api/rules/export", handleExportExclusions(exclusionStore))
	mux.HandleFunc("POST /api/rules/import", handleImportExclusions(exclusionStore))
	mux.HandleFunc("POST /api/rules/bulk", handleBulkExclusions(exclusionStore))
	mux.HandleFunc("PUT /api/rules/reorder", handleReorderExclusions(exclusionStore))
	mux.HandleFunc("GET /api/rules/hits", handleExclusionHits(store, accessLogStore, exclusionStore))
	mux.HandleFunc("GET /api/rules/{id}", handleGetExclusion(exclusionStore))
	mux.HandleFunc("PUT /api/rules/{id}", handleUpdateExclusion(exclusionStore))
	mux.HandleFunc("DELETE /api/rules/{id}", handleDeleteExclusion(exclusionStore))

	// ── Unified Deploy ────────────────────────────────────────────────
	// Single deploy endpoint for all config (replaces /api/config/deploy,
	// /api/rate-rules/deploy, /api/csp/deploy, /api/security-headers/deploy).
	mux.HandleFunc("POST /api/deploy", handleDeploy(configStore, exclusionStore, managedListStore, cspStore, secHeaderStore, corsStore, defaultRuleStore, deployCfg))

	// WAF Config
	mux.HandleFunc("GET /api/config", handleGetConfig(configStore))
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(configStore))
	mux.HandleFunc("POST /api/config/generate", handleGenerateConfig(configStore, exclusionStore, managedListStore, cspStore, secHeaderStore, corsStore, defaultRuleStore, deployCfg))
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(configStore, exclusionStore, managedListStore, cspStore, secHeaderStore, corsStore, defaultRuleStore, deployCfg))

	// Rate Limit Analytics (kept — reads from accessLogStore, not RateLimitRuleStore)
	mux.HandleFunc("GET /api/rate-rules/hits", handleRLRuleHits(accessLogStore, exclusionStore))
	mux.HandleFunc("GET /api/rate-rules/advisor", handleRLAdvisor(accessLogStore))

	// Rate Limit Analytics (access log based)
	mux.HandleFunc("GET /api/rate-limits/summary", handleRLSummary(accessLogStore))
	mux.HandleFunc("GET /api/rate-limits/events", handleRLEvents(accessLogStore))

	// Blocklist (IPsum)
	mux.HandleFunc("GET /api/blocklist/stats", handleBlocklistStats(blocklistStore))
	mux.HandleFunc("GET /api/blocklist/check/{ip}", handleBlocklistCheck(blocklistStore))
	mux.HandleFunc("POST /api/blocklist/refresh", handleBlocklistRefresh(blocklistStore))

	// CSP (Content Security Policy)
	mux.HandleFunc("GET /api/csp", handleGetCSP(cspStore))
	mux.HandleFunc("PUT /api/csp", handleUpdateCSP(cspStore))
	mux.HandleFunc("POST /api/csp/deploy", handleDeployCSP(cspStore, secHeaderStore, corsStore, configStore, exclusionStore, managedListStore, defaultRuleStore, deployCfg))
	mux.HandleFunc("GET /api/csp/preview", handlePreviewCSP(cspStore, deployCfg))

	// Security Headers
	mux.HandleFunc("GET /api/security-headers", handleGetSecurityHeaders(secHeaderStore))
	mux.HandleFunc("PUT /api/security-headers", handleUpdateSecurityHeaders(secHeaderStore))
	mux.HandleFunc("GET /api/security-headers/profiles", handleListSecurityProfiles())
	mux.HandleFunc("POST /api/security-headers/deploy", handleDeploySecurityHeaders(secHeaderStore, cspStore, corsStore, configStore, exclusionStore, managedListStore, defaultRuleStore, deployCfg))
	mux.HandleFunc("GET /api/security-headers/preview", handlePreviewSecurityHeaders(secHeaderStore, deployCfg))

	// CORS
	mux.HandleFunc("GET /api/cors", handleGetCORS(corsStore))
	mux.HandleFunc("PUT /api/cors", handleUpdateCORS(corsStore))

	// Cloudflare trusted proxies
	mux.HandleFunc("GET /api/cfproxy/stats", handleCFProxyStats(cfProxyStore))
	mux.HandleFunc("POST /api/cfproxy/refresh", handleCFProxyRefresh(cfProxyStore, deployCfg))

	// Managed Lists
	mux.HandleFunc("GET /api/lists", handleListManagedLists(managedListStore))
	mux.HandleFunc("POST /api/lists", handleCreateManagedList(managedListStore))
	mux.HandleFunc("GET /api/lists/export", handleExportManagedLists(managedListStore))
	mux.HandleFunc("POST /api/lists/import", handleImportManagedLists(managedListStore))
	mux.HandleFunc("GET /api/lists/{id}", handleGetManagedList(managedListStore))
	mux.HandleFunc("PUT /api/lists/{id}", handleUpdateManagedList(managedListStore))
	mux.HandleFunc("DELETE /api/lists/{id}", handleDeleteManagedList(managedListStore))
	mux.HandleFunc("POST /api/lists/{id}/refresh", handleRefreshManagedList(managedListStore))

	// Default Rules (baked-in rules with user overrides)
	mux.HandleFunc("GET /api/default-rules", handleListDefaultRules(defaultRuleStore))
	mux.HandleFunc("GET /api/default-rules/{id}", handleGetDefaultRule(defaultRuleStore))
	mux.HandleFunc("PUT /api/default-rules/{id}", handleOverrideDefaultRule(defaultRuleStore))
	mux.HandleFunc("DELETE /api/default-rules/{id}/override", handleResetDefaultRule(defaultRuleStore))
	mux.HandleFunc("POST /api/default-rules/bulk", handleBulkDefaultRules(defaultRuleStore))

	// Rule Templates
	mux.HandleFunc("GET /api/rules/templates", handleListTemplates())
	mux.HandleFunc("POST /api/rules/templates/{id}/apply", handleApplyTemplate(exclusionStore))

	// General Logs (all access log entries)
	mux.HandleFunc("GET /api/logs", handleGeneralLogs(generalLogStore))
	mux.HandleFunc("GET /api/logs/summary", handleGeneralLogsSummary(generalLogStore))

	// Challenge Analytics + Reputation
	mux.HandleFunc("GET /api/challenge/stats", handleChallengeStats(accessLogStore))
	mux.HandleFunc("GET /api/challenge/reputation", handleChallengeReputation(accessLogStore))

	// Endpoint Discovery
	mux.HandleFunc("GET /api/discovery/endpoints", handleEndpointDiscovery(generalLogStore, exclusionStore))
	mux.HandleFunc("GET /api/discovery/schemas", handleListOpenAPISchemas())
	mux.HandleFunc("PUT /api/discovery/schemas/{service}", handleUploadOpenAPISchema())
	mux.HandleFunc("DELETE /api/discovery/schemas/{service}", handleDeleteOpenAPISchema())

	// DDoS Mitigation
	mux.HandleFunc("GET /api/dos/status", handleDosStatus(jailStore, dosConfigStore, spikeDetector, accessLogStore))
	mux.HandleFunc("GET /api/dos/jail", handleListJail(jailStore))
	mux.HandleFunc("POST /api/dos/jail", handleAddJail(jailStore))
	mux.HandleFunc("DELETE /api/dos/jail/{ip}", handleRemoveJail(jailStore))
	mux.HandleFunc("GET /api/dos/config", handleGetDosConfig(dosConfigStore))
	mux.HandleFunc("PUT /api/dos/config", handleUpdateDosConfig(dosConfigStore, jailStore, spikeDetector))
	mux.HandleFunc("GET /api/dos/reports", handleListSpikeReports(spikeReporter))
	mux.HandleFunc("GET /api/dos/reports/{id}", handleGetSpikeReport(spikeReporter))

	// Backup / Restore (unified export of all config stores)
	mux.HandleFunc("GET /api/backup", handleBackup(configStore, cspStore, secHeaderStore, exclusionStore, managedListStore, defaultRuleStore))
	mux.HandleFunc("POST /api/backup/restore", handleRestore(configStore, cspStore, secHeaderStore, exclusionStore, managedListStore, defaultRuleStore))

	// Dashboard UI: serve static files from the embedded waf-dashboard build.
	// The UI dir is configurable so it can be disabled or relocated.
	uiDir := envOr("WAF_UI_DIR", "/app/waf-ui")
	if fi, err := os.Stat(uiDir); err == nil && fi.IsDir() {
		mux.Handle("/", uiFileServer(uiDir))
		log.Printf("serving dashboard UI from %s", uiDir)
	} else {
		log.Printf("dashboard UI dir %s not found, API-only mode", uiDir)
	}

	// Bearer token auth: protect /api/ routes (except /api/health).
	authToken := envOr("WAF_AUTH_TOKEN", "")
	if authToken == "" {
		log.Printf("[boot] warning: WAF_AUTH_TOKEN not set — API endpoints are unauthenticated")
	}

	// CORS: configure allowed origins (comma-separated).
	// When auth is enabled, default to empty (require explicit config);
	// when auth is disabled, default to "*" for backward compat.
	corsDefault := "*"
	if authToken != "" {
		corsDefault = ""
	}
	corsOrigins := envOr("WAF_CORS_ORIGINS", corsDefault)
	allowedOrigins := strings.Split(corsOrigins, ",")
	handler := newCORSMiddleware(allowedOrigins)(authMiddleware(authToken)(mux))

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 150 * time.Second, // Must exceed Caddy reload client timeout (120s)
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutdown signal received, draining connections...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
		return 1
	}
	log.Printf("server stopped gracefully")
	return 0
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseExtendedDuration parses a duration string supporting Go's standard units
// (ns, us, ms, s, m, h) plus extended units: "d" (24h) and "w" (168h).
// This matches Caddy's duration parser behavior for user-facing config.
func parseExtendedDuration(s string) (time.Duration, error) {
	// Try Go stdlib first (handles ns, us, ms, s, m, h)
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Handle extended units: "7d" → "168h", "2w" → "336h"
	if len(s) > 1 {
		suffix := s[len(s)-1]
		numStr := s[:len(s)-1]
		var multiplier time.Duration
		switch suffix {
		case 'd':
			multiplier = 24 * time.Hour
		case 'w':
			multiplier = 7 * 24 * time.Hour
		default:
			return 0, fmt.Errorf("time: unknown unit %q in duration %q", string(suffix), s)
		}

		var n float64
		if _, err := fmt.Sscanf(numStr, "%f", &n); err != nil {
			return 0, fmt.Errorf("time: invalid number %q in duration %q", numStr, s)
		}
		return time.Duration(n * float64(multiplier)), nil
	}

	return 0, fmt.Errorf("time: invalid duration %q", s)
}

func parseDurationOr(s string, fallback time.Duration) time.Duration {
	d, err := parseExtendedDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// --- Auth middleware ---

// authMiddleware enforces Bearer token authentication on /api/ routes.
// /api/health and non-API routes are exempt. If token is empty, all
// requests are allowed (backward compat).
func authMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health check.
			if r.URL.Path == "/api/health" {
				next.ServeHTTP(w, r)
				return
			}
			// Skip auth for non-API routes (dashboard UI).
			if !strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}
			// If no token configured, allow (backward compat).
			if token == "" {
				next.ServeHTTP(w, r)
				return
			}
			// Check bearer token.
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != token {
				writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized: invalid or missing bearer token"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- CORS middleware ---

// corsMiddleware validates the Origin header against a set of allowed origins.
// If allowedOrigins is empty or contains "*", all origins are allowed (backward compat).
func newCORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	// Build a set for O(1) lookup.
	allowAll := false
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		if o == "*" || o == "" {
			allowAll = true
		}
		originSet[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if allowAll {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "86400")
			} else if origin != "" && originSet[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "86400")
			} else if origin != "" {
				// Origin not allowed — reject preflight, still serve GET/POST
				// (browser will block the response due to missing CORS header).
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
