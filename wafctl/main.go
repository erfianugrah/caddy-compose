package main

import (
	"context"
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
// Set at build time via: -ldflags="-X main.version=2.20.0"
var version = "dev"

// crsVersion is the OWASP CRS version used by the policy engine's default rules.
const crsVersion = "4.24.1"

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
	rateLimitFile := envOr("WAF_RATELIMIT_FILE", "/data/rate-limits.json")
	combinedAccessLog := envOr("WAF_COMBINED_ACCESS_LOG", "/var/log/combined-access.log")

	cspFile := envOr("WAF_CSP_FILE", "/data/csp-config.json")
	secHeadersFile := envOr("WAF_SECURITY_HEADERS_FILE", "/data/security-headers.json")

	managedListsFile := envOr("WAF_MANAGED_LISTS_FILE", "/data/lists.json")
	managedListsDir := envOr("WAF_MANAGED_LISTS_DIR", "/data/lists")

	policyRulesFile := envOr("WAF_POLICY_RULES_FILE", "/data/waf/policy-rules.json")

	defaultRulesFile := envOr("WAF_DEFAULT_RULES_FILE", "/etc/caddy/waf/default-rules.json")
	defaultRulesOverridesFile := envOr("WAF_DEFAULT_RULES_OVERRIDES_FILE", "/data/default-rule-overrides.json")

	deployCfg := DeployConfig{
		WafDir:          envOr("WAF_DIR", "/data/waf"),
		CaddyfilePath:   envOr("WAF_CADDYFILE_PATH", "/data/Caddyfile"),
		CaddyAdminURL:   envOr("WAF_CADDY_ADMIN_URL", "http://caddy:2019"),
		PolicyRulesFile: policyRulesFile,
	}

	// Ensure WAF config directory and placeholder files exist.
	if err := ensureWafDir(deployCfg.WafDir); err != nil {
		log.Printf("warning: could not initialize waf dir: %v", err)
	}

	// Event retention: maximum age for in-memory events (default 2160h = 90 days).
	maxAgeStr := envOr("WAF_EVENT_MAX_AGE", "2160h")
	maxAge, err := time.ParseDuration(maxAgeStr)
	if err != nil {
		log.Printf("warning: invalid WAF_EVENT_MAX_AGE %q, using 2160h", maxAgeStr)
		maxAge = 2160 * time.Hour
	}

	// General log retention (shorter due to higher volume, default 168h = 7 days).
	generalMaxAgeStr := envOr("WAF_GENERAL_LOG_MAX_AGE", "168h")
	generalMaxAge, err := time.ParseDuration(generalMaxAgeStr)
	if err != nil {
		log.Printf("warning: invalid WAF_GENERAL_LOG_MAX_AGE %q, using 168h", generalMaxAgeStr)
		generalMaxAge = 168 * time.Hour
	}

	// Tailing interval (default 5s).
	tailIntervalStr := envOr("WAF_TAIL_INTERVAL", "5s")
	tailInterval, err := time.ParseDuration(tailIntervalStr)
	if err != nil {
		log.Printf("warning: invalid WAF_TAIL_INTERVAL %q, using 5s", tailIntervalStr)
		tailInterval = 5 * time.Second
	}

	geoDBPath := envOr("WAF_GEOIP_DB", "/data/geoip/country.mmdb")
	geoAPIURL := envOr("WAF_GEOIP_API_URL", "")
	geoAPIKey := envOr("WAF_GEOIP_API_KEY", "")

	log.Printf("wafctl starting: combined=%s port=%s exclusions=%s config=%s ratelimits=%s lists=%s waf_dir=%s max_age=%s tail_interval=%s geoip_db=%s geoip_api=%s default_rules=%s",
		combinedAccessLog, port, exclusionsFile, configFile, rateLimitFile, managedListsFile, deployCfg.WafDir, maxAge, tailInterval, geoDBPath, geoAPIURL, defaultRulesFile)

	var geoAPICfg *GeoIPAPIConfig
	if geoAPIURL != "" {
		geoAPICfg = &GeoIPAPIConfig{URL: geoAPIURL, Key: geoAPIKey}
	}
	geoStore := NewGeoIPStore(geoDBPath, geoAPICfg)

	// Create shutdown context early so background goroutines can be cancelled.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	store := NewStore()
	store.SetEventFile(envOr("WAF_EVENT_FILE", "/data/events.jsonl"))
	store.SetMaxAge(maxAge)
	store.SetGeoIP(geoStore)
	store.StartEviction(ctx, tailInterval)

	accessLogStore := NewAccessLogStore(combinedAccessLog)
	accessLogStore.SetOffsetFile(envOr("WAF_ACCESS_OFFSET_FILE", "/data/.access-log-offset"))
	accessLogStore.SetEventFile(envOr("WAF_ACCESS_EVENT_FILE", "/data/access-events.jsonl"))
	accessLogStore.SetMaxAge(maxAge)
	accessLogStore.SetGeoIP(geoStore)
	// ExclusionStore wired up below after it's created (line order dependency).

	generalLogStore := NewGeneralLogStore(combinedAccessLog)
	generalLogStore.SetOffsetFile(envOr("WAF_GENERAL_LOG_OFFSET_FILE", "/data/.general-log-offset"))
	generalLogStore.SetEventFile(envOr("WAF_GENERAL_LOG_FILE", "/data/general-events.jsonl"))
	generalLogStore.SetMaxAge(generalMaxAge)
	generalLogStore.SetGeoIP(geoStore)
	generalLogStore.StartTailing(ctx, tailInterval)

	exclusionStore := NewExclusionStore(exclusionsFile)
	accessLogStore.SetExclusionStore(exclusionStore)
	accessLogStore.StartTailing(ctx, tailInterval)

	configStore := NewConfigStore(configFile)
	rlRuleStore := NewRateLimitRuleStore(rateLimitFile)
	cspStore := NewCSPStore(cspFile)
	secHeaderStore := NewSecurityHeaderStore(secHeadersFile)
	managedListStore := NewManagedListStore(managedListsFile, managedListsDir)
	defaultRuleStore := NewDefaultRuleStore(defaultRulesFile, defaultRulesOverridesFile)

	// Generate-on-boot: regenerate WAF, rate limit, and CSP config files from
	// stored state so a stack restart always picks up the latest generator output.
	// No Caddy reload is needed because Caddy reads fresh on its own startup.
	generateOnBoot(configStore, exclusionStore, rlRuleStore, cspStore, secHeaderStore, managedListStore, defaultRuleStore, deployCfg)

	blocklistStore := NewBlocklistStore()

	// Sync IPsum IPs to per-level managed lists after each blocklist refresh.
	blocklistStore.SetOnRefresh(func(ipsByScore map[int][]string) {
		managedListStore.SyncIPsum(ipsByScore)
	})

	// After managed list sync, regenerate policy-rules.json so the plugin
	// picks up updated IP lists, then reload Caddy.
	blocklistStore.SetOnDeploy(func() error {
		return deployAll(configStore, exclusionStore, rlRuleStore, managedListStore, cspStore, secHeaderStore, defaultRuleStore, deployCfg)
	})

	// Populate in-memory IP set from existing managed lists (for Check API).
	blocklistStore.loadFromLists(managedListStore)

	// Schedule daily blocklist refresh at the configured UTC hour (default 06:00).
	// Replaces the old cron + shell script approach that ran in the caddy container.
	refreshHour := 6
	if h := envOr("WAF_BLOCKLIST_REFRESH_HOUR", ""); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n >= 0 && n <= 23 {
			refreshHour = n
		} else {
			log.Printf("warning: invalid WAF_BLOCKLIST_REFRESH_HOUR %q, using 6", h)
		}
	}
	blocklistStore.StartScheduledRefresh(ctx, refreshHour)

	// IP intelligence store — aggregates Team Cymru, RIPE, GreyNoise, Shodan.
	intelStore := NewIPIntelStore(blocklistStore)

	// Cloudflare trusted proxy store — refreshes CF IP ranges at runtime.
	cfProxyPath := filepath.Join(deployCfg.WafDir, "cf_trusted_proxies.caddy")
	cfProxyStore := NewCFProxyStore(cfProxyPath)

	// Schedule weekly CF IP refresh (Monday at the same hour as blocklist).
	cfProxyStore.StartScheduledRefresh(ctx, refreshHour, deployCfg)

	mux := http.NewServeMux()

	// Existing endpoints (with hours filter support) — merged WAF + 429 events
	mux.HandleFunc("GET /api/health", handleHealth(store, accessLogStore, generalLogStore, geoStore, exclusionStore, blocklistStore, cfProxyStore, cspStore, secHeaderStore))
	mux.HandleFunc("GET /api/summary", handleSummary(store, accessLogStore, rlRuleStore))
	mux.HandleFunc("GET /api/events", handleEvents(store, accessLogStore, rlRuleStore))
	mux.HandleFunc("GET /api/services", handleServices(store, accessLogStore, rlRuleStore))

	// Analytics
	mux.HandleFunc("GET /api/analytics/top-ips", handleTopBlockedIPs(store, accessLogStore, rlRuleStore))
	mux.HandleFunc("GET /api/analytics/top-uris", handleTopTargetedURIs(store, accessLogStore, rlRuleStore))
	mux.HandleFunc("GET /api/analytics/top-countries", handleTopCountries(store, accessLogStore, rlRuleStore))

	// IP Lookup
	mux.HandleFunc("GET /api/lookup/{ip}", handleIPLookup(store, accessLogStore, rlRuleStore, geoStore, intelStore))

	// Exclusion CRUD
	mux.HandleFunc("GET /api/exclusions", handleListExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions", handleCreateExclusion(exclusionStore))
	mux.HandleFunc("GET /api/exclusions/export", handleExportExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions/import", handleImportExclusions(exclusionStore))
	mux.HandleFunc("PUT /api/exclusions/reorder", handleReorderExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions/bulk", handleBulkExclusions(exclusionStore))
	mux.HandleFunc("GET /api/exclusions/hits", handleExclusionHits(store, accessLogStore, rlRuleStore, exclusionStore))
	mux.HandleFunc("GET /api/exclusions/{id}", handleGetExclusion(exclusionStore))
	mux.HandleFunc("PUT /api/exclusions/{id}", handleUpdateExclusion(exclusionStore))
	mux.HandleFunc("DELETE /api/exclusions/{id}", handleDeleteExclusion(exclusionStore))

	// CRS Catalog
	mux.HandleFunc("GET /api/crs/rules", handleCRSRules)

	// WAF Config
	mux.HandleFunc("GET /api/config", handleGetConfig(configStore))
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(configStore))
	mux.HandleFunc("POST /api/config/generate", handleGenerateConfig(configStore, exclusionStore, rlRuleStore, managedListStore, cspStore, secHeaderStore, defaultRuleStore, deployCfg))
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(configStore, exclusionStore, rlRuleStore, managedListStore, cspStore, secHeaderStore, defaultRuleStore, deployCfg))

	// Rate Limit Rules (policy engine)
	mux.HandleFunc("GET /api/rate-rules", handleListRLRules(rlRuleStore))
	mux.HandleFunc("POST /api/rate-rules", handleCreateRLRule(rlRuleStore))
	mux.HandleFunc("GET /api/rate-rules/export", handleExportRLRules(rlRuleStore))
	mux.HandleFunc("POST /api/rate-rules/import", handleImportRLRules(rlRuleStore))
	mux.HandleFunc("POST /api/rate-rules/deploy", handleDeployRLRules(rlRuleStore, exclusionStore, configStore, managedListStore, cspStore, secHeaderStore, defaultRuleStore, deployCfg))
	mux.HandleFunc("PUT /api/rate-rules/reorder", handleReorderRLRules(rlRuleStore))
	mux.HandleFunc("GET /api/rate-rules/global", handleGetRLGlobal(rlRuleStore))
	mux.HandleFunc("PUT /api/rate-rules/global", handleUpdateRLGlobal(rlRuleStore))
	mux.HandleFunc("GET /api/rate-rules/hits", handleRLRuleHits(accessLogStore, rlRuleStore))
	mux.HandleFunc("GET /api/rate-rules/advisor", handleRLAdvisor(accessLogStore))
	mux.HandleFunc("GET /api/rate-rules/{id}", handleGetRLRule(rlRuleStore))
	mux.HandleFunc("PUT /api/rate-rules/{id}", handleUpdateRLRule(rlRuleStore))
	mux.HandleFunc("DELETE /api/rate-rules/{id}", handleDeleteRLRule(rlRuleStore))

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
	mux.HandleFunc("POST /api/csp/deploy", handleDeployCSP(cspStore, secHeaderStore, configStore, exclusionStore, rlRuleStore, managedListStore, defaultRuleStore, deployCfg))
	mux.HandleFunc("GET /api/csp/preview", handlePreviewCSP(cspStore, deployCfg))

	// Security Headers
	mux.HandleFunc("GET /api/security-headers", handleGetSecurityHeaders(secHeaderStore))
	mux.HandleFunc("PUT /api/security-headers", handleUpdateSecurityHeaders(secHeaderStore))
	mux.HandleFunc("GET /api/security-headers/profiles", handleListSecurityProfiles())
	mux.HandleFunc("POST /api/security-headers/deploy", handleDeploySecurityHeaders(secHeaderStore, cspStore, configStore, exclusionStore, rlRuleStore, managedListStore, defaultRuleStore, deployCfg))
	mux.HandleFunc("GET /api/security-headers/preview", handlePreviewSecurityHeaders(secHeaderStore, deployCfg))

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

	// General Logs (all access log entries)
	mux.HandleFunc("GET /api/logs", handleGeneralLogs(generalLogStore))
	mux.HandleFunc("GET /api/logs/summary", handleGeneralLogsSummary(generalLogStore))

	// Backup / Restore (unified export of all config stores)
	mux.HandleFunc("GET /api/backup", handleBackup(configStore, cspStore, secHeaderStore, exclusionStore, rlRuleStore, managedListStore))
	mux.HandleFunc("POST /api/backup/restore", handleRestore(configStore, cspStore, secHeaderStore, exclusionStore, rlRuleStore, managedListStore))

	// Dashboard UI: serve static files from the embedded waf-dashboard build.
	// The UI dir is configurable so it can be disabled or relocated.
	uiDir := envOr("WAF_UI_DIR", "/app/waf-ui")
	if fi, err := os.Stat(uiDir); err == nil && fi.IsDir() {
		mux.Handle("/", uiFileServer(uiDir))
		log.Printf("serving dashboard UI from %s", uiDir)
	} else {
		log.Printf("dashboard UI dir %s not found, API-only mode", uiDir)
	}

	// CORS: configure allowed origins (comma-separated). Default "*" for backward compat.
	corsOrigins := envOr("WAF_CORS_ORIGINS", "*")
	allowedOrigins := strings.Split(corsOrigins, ",")
	handler := newCORSMiddleware(allowedOrigins)(mux)

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
