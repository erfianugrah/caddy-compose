package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// version is the wafctl release version, shown in /api/health.
// Set at build time via: -ldflags="-X main.version=0.21.0"
var version = "dev"

// crsVersion is the OWASP CRS version bundled via coraza-caddy.
// Derived from the coraza-coreruleset module version in the plugin's go.mod.
const crsVersion = "4.23.0"

// startTime records when the process started, used for uptime calculation.
var startTime = time.Now()

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

// runServe starts the HTTP API server. This is the default command.
func runServe() int {
	logPath := envOr("WAF_AUDIT_LOG", "/var/log/coraza-audit.log")
	port := envOr("WAFCTL_PORT", "8080")
	exclusionsFile := envOr("WAF_EXCLUSIONS_FILE", "/data/exclusions.json")
	configFile := envOr("WAF_CONFIG_FILE", "/data/waf-config.json")
	rateLimitFile := envOr("WAF_RATELIMIT_FILE", "/data/rate-limits.json")
	combinedAccessLog := envOr("WAF_COMBINED_ACCESS_LOG", "/var/log/combined-access.log")

	cspFile := envOr("WAF_CSP_FILE", "/data/csp-config.json")

	deployCfg := DeployConfig{
		CorazaDir:     envOr("WAF_CORAZA_DIR", "/data/coraza"),
		RateLimitDir:  envOr("WAF_RATELIMIT_DIR", "/data/rl"),
		CSPDir:        envOr("WAF_CSP_DIR", "/data/csp"),
		CaddyfilePath: envOr("WAF_CADDYFILE_PATH", "/data/Caddyfile"),
		CaddyAdminURL: envOr("WAF_CADDY_ADMIN_URL", "http://caddy:2019"),
	}

	// Ensure custom coraza config directory and placeholder files exist.
	if err := ensureCorazaDir(deployCfg.CorazaDir); err != nil {
		log.Printf("warning: could not initialize coraza dir: %v", err)
	}

	// Ensure rate limit directory exists.
	if err := ensureRateLimitDir(deployCfg.RateLimitDir); err != nil {
		log.Printf("warning: could not initialize rate limit dir: %v", err)
	}

	// Ensure CSP directory exists.
	if err := ensureCSPDir(deployCfg.CSPDir); err != nil {
		log.Printf("warning: could not initialize CSP dir: %v", err)
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

	log.Printf("wafctl starting: log=%s combined=%s port=%s exclusions=%s config=%s ratelimits=%s coraza_dir=%s rl_dir=%s max_age=%s tail_interval=%s geoip_db=%s geoip_api=%s",
		logPath, combinedAccessLog, port, exclusionsFile, configFile, rateLimitFile, deployCfg.CorazaDir, deployCfg.RateLimitDir, maxAge, tailInterval, geoDBPath, geoAPIURL)

	var geoAPICfg *GeoIPAPIConfig
	if geoAPIURL != "" {
		geoAPICfg = &GeoIPAPIConfig{URL: geoAPIURL, Key: geoAPIKey}
	}
	geoStore := NewGeoIPStore(geoDBPath, geoAPICfg)

	store := NewStore(logPath)
	store.SetOffsetFile(envOr("WAF_AUDIT_OFFSET_FILE", "/data/.audit-log-offset"))
	store.SetEventFile(envOr("WAF_EVENT_FILE", "/data/events.jsonl"))
	store.SetMaxAge(maxAge)
	store.SetGeoIP(geoStore)
	store.StartTailing(tailInterval)

	accessLogStore := NewAccessLogStore(combinedAccessLog)
	accessLogStore.SetOffsetFile(envOr("WAF_ACCESS_OFFSET_FILE", "/data/.access-log-offset"))
	accessLogStore.SetEventFile(envOr("WAF_ACCESS_EVENT_FILE", "/data/access-events.jsonl"))
	accessLogStore.SetMaxAge(maxAge)
	accessLogStore.SetGeoIP(geoStore)
	accessLogStore.StartTailing(tailInterval)

	generalLogStore := NewGeneralLogStore(combinedAccessLog)
	generalLogStore.SetOffsetFile(envOr("WAF_GENERAL_LOG_OFFSET_FILE", "/data/.general-log-offset"))
	generalLogStore.SetEventFile(envOr("WAF_GENERAL_LOG_FILE", "/data/general-events.jsonl"))
	generalLogStore.SetMaxAge(generalMaxAge)
	generalLogStore.SetGeoIP(geoStore)
	generalLogStore.StartTailing(tailInterval)

	exclusionStore := NewExclusionStore(exclusionsFile)
	configStore := NewConfigStore(configFile)
	rlRuleStore := NewRateLimitRuleStore(rateLimitFile)
	cspStore := NewCSPStore(cspFile)

	// Generate-on-boot: regenerate WAF, rate limit, and CSP config files from
	// stored state so a stack restart always picks up the latest generator output.
	// No Caddy reload is needed because Caddy reads fresh on its own startup.
	generateOnBoot(configStore, exclusionStore, rlRuleStore, cspStore, deployCfg)

	blocklistPath := filepath.Join(deployCfg.CorazaDir, "ipsum_block.caddy")
	blocklistStore := NewBlocklistStore(blocklistPath)

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
	blocklistStore.StartScheduledRefresh(refreshHour, deployCfg, rlRuleStore)

	// Cloudflare trusted proxy store — refreshes CF IP ranges at runtime.
	cfProxyPath := filepath.Join(deployCfg.CorazaDir, "cf_trusted_proxies.caddy")
	cfProxyStore := NewCFProxyStore(cfProxyPath)

	// Schedule weekly CF IP refresh (Monday at the same hour as blocklist).
	cfProxyStore.StartScheduledRefresh(refreshHour, deployCfg)

	mux := http.NewServeMux()

	// Existing endpoints (with hours filter support) — merged WAF + 429 events
	mux.HandleFunc("GET /api/health", handleHealth(store, accessLogStore, generalLogStore, geoStore, exclusionStore, blocklistStore, cfProxyStore, cspStore))
	mux.HandleFunc("GET /api/summary", handleSummary(store, accessLogStore))
	mux.HandleFunc("GET /api/events", handleEvents(store, accessLogStore))
	mux.HandleFunc("GET /api/services", handleServices(store, accessLogStore))

	// Analytics
	mux.HandleFunc("GET /api/analytics/top-ips", handleTopBlockedIPs(store, accessLogStore))
	mux.HandleFunc("GET /api/analytics/top-uris", handleTopTargetedURIs(store, accessLogStore))
	mux.HandleFunc("GET /api/analytics/top-countries", handleTopCountries(store, accessLogStore))

	// IP Lookup
	mux.HandleFunc("GET /api/lookup/{ip}", handleIPLookup(store, accessLogStore, geoStore))

	// Exclusion CRUD
	mux.HandleFunc("GET /api/exclusions", handleListExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions", handleCreateExclusion(exclusionStore))
	mux.HandleFunc("GET /api/exclusions/export", handleExportExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions/import", handleImportExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions/generate", handleGenerateExclusions(exclusionStore))
	mux.HandleFunc("PUT /api/exclusions/reorder", handleReorderExclusions(exclusionStore))
	mux.HandleFunc("GET /api/exclusions/hits", handleExclusionHits(store, exclusionStore))
	mux.HandleFunc("GET /api/exclusions/{id}", handleGetExclusion(exclusionStore))
	mux.HandleFunc("PUT /api/exclusions/{id}", handleUpdateExclusion(exclusionStore))
	mux.HandleFunc("DELETE /api/exclusions/{id}", handleDeleteExclusion(exclusionStore))

	// CRS Catalog
	mux.HandleFunc("GET /api/crs/rules", handleCRSRules)
	mux.HandleFunc("GET /api/crs/autocomplete", handleCRSAutocomplete)

	// WAF Config
	mux.HandleFunc("GET /api/config", handleGetConfig(configStore))
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(configStore))
	mux.HandleFunc("POST /api/config/generate", handleGenerateConfig(configStore, exclusionStore))
	mux.HandleFunc("POST /api/config/validate", handleValidateConfig(configStore, exclusionStore))
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(configStore, exclusionStore, rlRuleStore, deployCfg))

	// Rate Limit Rules (policy engine)
	mux.HandleFunc("GET /api/rate-rules", handleListRLRules(rlRuleStore))
	mux.HandleFunc("POST /api/rate-rules", handleCreateRLRule(rlRuleStore))
	mux.HandleFunc("GET /api/rate-rules/export", handleExportRLRules(rlRuleStore))
	mux.HandleFunc("POST /api/rate-rules/import", handleImportRLRules(rlRuleStore))
	mux.HandleFunc("POST /api/rate-rules/deploy", handleDeployRLRules(rlRuleStore, deployCfg))
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
	mux.HandleFunc("POST /api/blocklist/refresh", handleBlocklistRefresh(blocklistStore, rlRuleStore, deployCfg))

	// CSP (Content Security Policy)
	mux.HandleFunc("GET /api/csp", handleGetCSP(cspStore))
	mux.HandleFunc("PUT /api/csp", handleUpdateCSP(cspStore))
	mux.HandleFunc("POST /api/csp/deploy", handleDeployCSP(cspStore, deployCfg))
	mux.HandleFunc("GET /api/csp/preview", handlePreviewCSP(cspStore, deployCfg))

	// Cloudflare trusted proxies
	mux.HandleFunc("GET /api/cfproxy/stats", handleCFProxyStats(cfProxyStore))
	mux.HandleFunc("POST /api/cfproxy/refresh", handleCFProxyRefresh(cfProxyStore, deployCfg))

	// General Logs (all access log entries)
	mux.HandleFunc("GET /api/logs", handleGeneralLogs(generalLogStore))
	mux.HandleFunc("GET /api/logs/summary", handleGeneralLogsSummary(generalLogStore))

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

	log.Printf("listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("server error: %v", err)
		return 1
	}
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
			} else if origin != "" && originSet[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			} else if origin != "" {
				// Origin not allowed — reject preflight, still serve GET/POST
				// (browser will block the response due to missing CORS header).
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
