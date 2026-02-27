package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

	deployCfg := DeployConfig{
		CorazaDir:     envOr("WAF_CORAZA_DIR", "/data/coraza"),
		RateLimitDir:  envOr("WAF_RATELIMIT_DIR", "/data/rl"),
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

	// Event retention: maximum age for in-memory events (default 2160h = 90 days).
	maxAgeStr := envOr("WAF_EVENT_MAX_AGE", "2160h")
	maxAge, err := time.ParseDuration(maxAgeStr)
	if err != nil {
		log.Printf("warning: invalid WAF_EVENT_MAX_AGE %q, using 2160h", maxAgeStr)
		maxAge = 2160 * time.Hour
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

	exclusionStore := NewExclusionStore(exclusionsFile)
	configStore := NewConfigStore(configFile)
	rlRuleStore := NewRateLimitRuleStore(rateLimitFile)

	// Generate-on-boot: regenerate WAF and rate limit config files from stored
	// state so a stack restart always picks up the latest generator output.
	// No Caddy reload is needed because Caddy reads fresh on its own startup.
	generateOnBoot(configStore, exclusionStore, rlRuleStore, deployCfg)

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

	mux := http.NewServeMux()

	// Existing endpoints (with hours filter support) — merged WAF + 429 events
	mux.HandleFunc("GET /api/health", handleHealth(store, accessLogStore, geoStore, exclusionStore, blocklistStore))
	mux.HandleFunc("GET /api/summary", handleSummary(store, accessLogStore))
	mux.HandleFunc("GET /api/events", handleEvents(store, accessLogStore))
	mux.HandleFunc("GET /api/services", handleServices(store, accessLogStore))

	// Analytics
	mux.HandleFunc("GET /api/analytics/top-ips", handleTopBlockedIPs(store))
	mux.HandleFunc("GET /api/analytics/top-uris", handleTopTargetedURIs(store))
	mux.HandleFunc("GET /api/analytics/top-countries", handleTopCountries(store, accessLogStore))

	// IP Lookup
	mux.HandleFunc("GET /api/lookup/{ip}", handleIPLookup(store))

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

// --- Query parameter helpers ---

// parseHours extracts and validates the ?hours= query parameter.
// Returns 0 (meaning "all time") if not provided or invalid.
func parseHours(r *http.Request) int {
	s := r.URL.Query().Get("hours")
	if s == "" {
		return 0
	}
	h, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	if !validHours[h] {
		return 0
	}
	return h
}

// timeRange holds an optional absolute time range from ?start= and ?end= query params.
type timeRange struct {
	Start time.Time
	End   time.Time
	Valid bool // true if both start and end were successfully parsed
}

// parseTimeRange extracts ?start= and ?end= ISO 8601 query parameters.
// Returns a valid timeRange only if both are present and parseable.
// When valid, this takes precedence over ?hours=.
func parseTimeRange(r *http.Request) timeRange {
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")
	if startStr == "" || endStr == "" {
		return timeRange{}
	}

	// Try multiple common formats.
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
	}

	var start, end time.Time
	var err error
	for _, f := range formats {
		start, err = time.Parse(f, startStr)
		if err == nil {
			break
		}
	}
	if err != nil {
		return timeRange{}
	}

	for _, f := range formats {
		end, err = time.Parse(f, endStr)
		if err == nil {
			break
		}
	}
	if err != nil {
		return timeRange{}
	}

	return timeRange{Start: start.UTC(), End: end.UTC(), Valid: true}
}

// getWAFEvents returns WAF events filtered by either time range or hours.
func getWAFEvents(store *Store, tr timeRange, hours int) []Event {
	if tr.Valid {
		return store.SnapshotRange(tr.Start, tr.End)
	}
	return store.SnapshotSince(hours)
}

// getRLEvents returns rate-limited events filtered by either time range or hours.
func getRLEvents(als *AccessLogStore, tr timeRange, hours int) []Event {
	if tr.Valid {
		return als.SnapshotAsEventsRange(tr.Start, tr.End)
	}
	return als.SnapshotAsEvents(hours)
}

// --- Handlers: Event endpoints ---

func handleHealth(store *Store, als *AccessLogStore, geoStore *GeoIPStore, exclusionStore *ExclusionStore, blocklistStore *BlocklistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		uptime := time.Since(startTime).Truncate(time.Second)

		stores := map[string]any{
			"waf_events":    store.Stats(),
			"access_events": als.Stats(),
			"geoip": map[string]any{
				"mmdb_loaded": geoStore.HasDB(),
				"api_enabled": geoStore.HasAPI(),
			},
			"exclusions": map[string]any{
				"count": len(exclusionStore.List()),
			},
			"blocklist": blocklistStore.Stats(),
		}

		writeJSON(w, http.StatusOK, HealthResponse{
			Status:     "ok",
			Version:    version,
			CRSVersion: crsVersion,
			Uptime:     uptime.String(),
			Stores:     stores,
		})
	}
}

func handleSummary(store *Store, als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tr := parseTimeRange(r)
		hours := parseHours(r)
		q := r.URL.Query()

		// Read filter params with operator support (e.g. service_op=in&service=a,b).
		serviceF := parseFieldFilter(q.Get("service"), q.Get("service_op"))
		clientF := parseFieldFilter(q.Get("client"), q.Get("client_op"))
		methodF := parseFieldFilter(q.Get("method"), q.Get("method_op"))
		eventTypeF := parseFieldFilter(q.Get("event_type"), q.Get("event_type_op"))
		ruleNameF := parseFieldFilter(q.Get("rule_name"), q.Get("rule_name_op"))
		uriF := parseFieldFilter(q.Get("uri"), q.Get("uri_op"))
		statusCodeF := parseFieldFilter(q.Get("status_code"), q.Get("status_code_op"))
		countryF := parseFieldFilter(q.Get("country"), q.Get("country_op"))

		hasFilter := serviceF != nil || clientF != nil || methodF != nil || eventTypeF != nil || ruleNameF != nil ||
			uriF != nil || statusCodeF != nil || countryF != nil

		// When any filter is active, collect all events, apply filters, then
		// summarize — this is the general-purpose filtered path.
		if hasFilter {
			var allEvents []Event
			// Optimization: skip event sources that can't match the event_type filter.
			wafTypes := map[string]bool{
				"blocked": true, "logged": true,
				"policy_skip": true, "policy_allow": true, "policy_block": true,
				"honeypot": true, "scanner": true,
			}
			rlTypes := map[string]bool{"rate_limited": true, "ipsum_blocked": true}
			needWAF, needRL := true, true
			if eventTypeF != nil {
				switch eventTypeF.op {
				case "eq":
					needWAF = wafTypes[eventTypeF.value]
					needRL = rlTypes[eventTypeF.value]
				case "in":
					needWAF, needRL = false, false
					for _, v := range strings.Split(eventTypeF.value, ",") {
						if wafTypes[strings.TrimSpace(v)] {
							needWAF = true
						}
						if rlTypes[strings.TrimSpace(v)] {
							needRL = true
						}
					}
				default:
					// neq, contains, regex — can't prune safely, fetch both
				}
			}
			if needWAF {
				allEvents = append(allEvents, getWAFEvents(store, tr, hours)...)
			}
			if needRL {
				allEvents = append(allEvents, getRLEvents(als, tr, hours)...)
			}

			var filtered []Event
			for i := range allEvents {
				ev := &allEvents[i]
				if !serviceF.matchField(ev.Service) {
					continue
				}
				if !clientF.matchField(ev.ClientIP) {
					continue
				}
				if !methodF.matchField(ev.Method) {
					continue
				}
				if !eventTypeF.matchField(ev.EventType) {
					continue
				}
				if ruleNameF != nil && !matchesPolicyRuleNameFilter(ev, ruleNameF) {
					continue
				}
				if !uriF.matchField(ev.URI) {
					continue
				}
				if !statusCodeF.matchField(strconv.Itoa(ev.ResponseStatus)) {
					continue
				}
				if !countryF.matchField(ev.Country) {
					continue
				}
				filtered = append(filtered, *ev)
			}

			summary := summarizeEvents(filtered)
			allClients := make(map[string]struct{})
			allServices := make(map[string]struct{})
			for i := range filtered {
				allClients[filtered[i].ClientIP] = struct{}{}
				allServices[filtered[i].Service] = struct{}{}
			}
			summary.UniqueClients = len(allClients)
			summary.UniqueServices = len(allServices)
			writeJSON(w, http.StatusOK, summary)
			return
		}

		var summary SummaryResponse
		if tr.Valid {
			summary = store.SummaryRange(tr.Start, tr.End)
		} else {
			summary = store.Summary(hours)
		}

		// Merge access-log events (429 rate-limited + ipsum-blocked) into the summary.
		rlEvents := getRLEvents(als, tr, hours)

		// Split into rate_limited vs ipsum_blocked.
		var rlOnlyCount, ipsumCount int
		rlHourMap := make(map[string]int)
		ipsumHourMap := make(map[string]int)
		rlSvcMap := make(map[string]int)
		ipsumSvcMap := make(map[string]int)
		rlClients := make(map[string]struct{})
		rlServices := make(map[string]struct{})

		for i := range rlEvents {
			ev := &rlEvents[i]
			hourKey := ev.Timestamp.Truncate(time.Hour).Format(time.RFC3339)
			rlClients[ev.ClientIP] = struct{}{}
			rlServices[ev.Service] = struct{}{}
			if ev.EventType == "ipsum_blocked" {
				ipsumCount++
				ipsumHourMap[hourKey]++
				ipsumSvcMap[ev.Service]++
			} else {
				rlOnlyCount++
				rlHourMap[hourKey]++
				rlSvcMap[ev.Service]++
			}
		}

		summary.RateLimited = rlOnlyCount
		summary.IpsumBlocked = ipsumCount
		summary.TotalEvents += rlOnlyCount + ipsumCount

		// Merge into existing hourly buckets.
		existingHours := make(map[string]int) // index into summary.EventsByHour
		for i, hc := range summary.EventsByHour {
			existingHours[hc.Hour] = i
		}
		// Helper to merge a per-hour map into EventsByHour.
		mergeHourMap := func(hourMap map[string]int, isIpsum bool) {
			for hour, count := range hourMap {
				if idx, ok := existingHours[hour]; ok {
					if isIpsum {
						summary.EventsByHour[idx].IpsumBlocked += count
					} else {
						summary.EventsByHour[idx].RateLimited += count
					}
					summary.EventsByHour[idx].Count += count
				} else {
					hc := HourCount{Hour: hour, Count: count}
					if isIpsum {
						hc.IpsumBlocked = count
					} else {
						hc.RateLimited = count
					}
					existingHours[hour] = len(summary.EventsByHour)
					summary.EventsByHour = append(summary.EventsByHour, hc)
				}
			}
		}
		mergeHourMap(rlHourMap, false)
		mergeHourMap(ipsumHourMap, true)

		// Re-sort hourly buckets.
		sort.Slice(summary.EventsByHour, func(i, j int) bool {
			return summary.EventsByHour[i].Hour < summary.EventsByHour[j].Hour
		})

		// Helper to merge a per-service map into ServiceBreakdown.
		mergeSvcBreakdown := func(svcMap map[string]int, isIpsum bool) {
			existingSvcs := make(map[string]int)
			for i, sd := range summary.ServiceBreakdown {
				existingSvcs[sd.Service] = i
			}
			for svc, count := range svcMap {
				if idx, ok := existingSvcs[svc]; ok {
					if isIpsum {
						summary.ServiceBreakdown[idx].IpsumBlocked += count
					} else {
						summary.ServiceBreakdown[idx].RateLimited += count
					}
					summary.ServiceBreakdown[idx].Total += count
				} else {
					sd := ServiceDetail{Service: svc, Total: count}
					if isIpsum {
						sd.IpsumBlocked = count
					} else {
						sd.RateLimited = count
					}
					existingSvcs[svc] = len(summary.ServiceBreakdown)
					summary.ServiceBreakdown = append(summary.ServiceBreakdown, sd)
				}
			}
		}
		mergeSvcBreakdown(rlSvcMap, false)
		mergeSvcBreakdown(ipsumSvcMap, true)

		// Helper to merge a per-service map into TopServices.
		mergeTopSvcs := func(svcMap map[string]int, isIpsum bool) {
			existingTopSvcs := make(map[string]int)
			for i, sc := range summary.TopServices {
				existingTopSvcs[sc.Service] = i
			}
			for svc, count := range svcMap {
				if idx, ok := existingTopSvcs[svc]; ok {
					if isIpsum {
						summary.TopServices[idx].IpsumBlocked += count
					} else {
						summary.TopServices[idx].RateLimited += count
					}
					summary.TopServices[idx].Count += count
				} else {
					sc := ServiceCount{Service: svc, Count: count}
					if isIpsum {
						sc.IpsumBlocked = count
					} else {
						sc.RateLimited = count
					}
					existingTopSvcs[svc] = len(summary.TopServices)
					summary.TopServices = append(summary.TopServices, sc)
				}
			}
		}
		mergeTopSvcs(rlSvcMap, false)
		mergeTopSvcs(ipsumSvcMap, true)

		// Merge RL/ipsum client counts into TopClients.
		rlClientMap := make(map[string]int)
		ipsumClientMap := make(map[string]int)
		for i := range rlEvents {
			if rlEvents[i].EventType == "ipsum_blocked" {
				ipsumClientMap[rlEvents[i].ClientIP]++
			} else {
				rlClientMap[rlEvents[i].ClientIP]++
			}
		}

		existingTopClients := make(map[string]int) // index into summary.TopClients
		for i, cc := range summary.TopClients {
			existingTopClients[cc.Client] = i
		}
		for client, count := range rlClientMap {
			if idx, ok := existingTopClients[client]; ok {
				summary.TopClients[idx].RateLimited += count
				summary.TopClients[idx].Count += count
			} else {
				cc := ClientCount{Client: client, Count: count, RateLimited: count}
				existingTopClients[client] = len(summary.TopClients)
				summary.TopClients = append(summary.TopClients, cc)
			}
		}
		for client, count := range ipsumClientMap {
			if idx, ok := existingTopClients[client]; ok {
				summary.TopClients[idx].IpsumBlocked += count
				summary.TopClients[idx].Count += count
			} else {
				cc := ClientCount{Client: client, Count: count, IpsumBlocked: count}
				existingTopClients[client] = len(summary.TopClients)
				summary.TopClients = append(summary.TopClients, cc)
			}
		}
		// Re-sort TopClients by count desc, cap at 10.
		sort.Slice(summary.TopClients, func(i, j int) bool {
			return summary.TopClients[i].Count > summary.TopClients[j].Count
		})
		if len(summary.TopClients) > topNSummary {
			summary.TopClients = summary.TopClients[:topNSummary]
		}

		// Merge unique clients/services (union of WAF + RL).
		// Only re-fetch WAF events when RL events introduce new clients/services;
		// otherwise keep the WAF-only counts already in summary.
		if len(rlClients) > 0 || len(rlServices) > 0 {
			wafSnapshot := getWAFEvents(store, tr, hours)
			allClients := make(map[string]struct{}, len(wafSnapshot)+len(rlClients))
			allServices := make(map[string]struct{}, len(wafSnapshot)+len(rlServices))
			for i := range wafSnapshot {
				allClients[wafSnapshot[i].ClientIP] = struct{}{}
				allServices[wafSnapshot[i].Service] = struct{}{}
			}
			for c := range rlClients {
				allClients[c] = struct{}{}
			}
			for s := range rlServices {
				allServices[s] = struct{}{}
			}
			summary.UniqueClients = len(allClients)
			summary.UniqueServices = len(allServices)
		}

		// Merge RL events into recent_events, re-sort newest-first.
		summary.RecentEvents = append(summary.RecentEvents, rlEvents...)
		sort.Slice(summary.RecentEvents, func(i, j int) bool {
			return summary.RecentEvents[i].Timestamp.After(summary.RecentEvents[j].Timestamp)
		})
		if len(summary.RecentEvents) > topNSummary {
			summary.RecentEvents = summary.RecentEvents[:topNSummary]
		}

		writeJSON(w, http.StatusOK, summary)
	}
}

func handleEvents(store *Store, als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// Read filter params with operator support.
		serviceF := parseFieldFilter(q.Get("service"), q.Get("service_op"))
		clientF := parseFieldFilter(q.Get("client"), q.Get("client_op"))
		methodF := parseFieldFilter(q.Get("method"), q.Get("method_op"))
		eventTypeF := parseFieldFilter(q.Get("event_type"), q.Get("event_type_op"))
		ruleNameF := parseFieldFilter(q.Get("rule_name"), q.Get("rule_name_op"))
		uriF := parseFieldFilter(q.Get("uri"), q.Get("uri_op"))
		statusCodeF := parseFieldFilter(q.Get("status_code"), q.Get("status_code_op"))
		countryF := parseFieldFilter(q.Get("country"), q.Get("country_op"))

		var blocked *bool
		if b := q.Get("blocked"); b != "" {
			val := strings.EqualFold(b, "true") || b == "1"
			blocked = &val
		}

		exportAll := strings.EqualFold(q.Get("export"), "true")
		limit := queryInt(q.Get("limit"), 50)
		if exportAll {
			limit = 100000 // export mode: return all matching events
		} else if limit <= 0 || limit > 1000 {
			limit = 50
		}
		offset := queryInt(q.Get("offset"), 0)
		if offset < 0 {
			offset = 0
		}

		tr := parseTimeRange(r)
		hours := parseHours(r)

		// Collect WAF events (unless filtering to only rate_limited or ipsum_blocked).
		wafTypes := map[string]bool{
			"blocked": true, "logged": true,
			"policy_skip": true, "policy_allow": true, "policy_block": true,
			"honeypot": true, "scanner": true,
		}
		rlTypes := map[string]bool{"rate_limited": true, "ipsum_blocked": true}
		needWAF, needRL := true, true
		if eventTypeF != nil {
			switch eventTypeF.op {
			case "eq":
				needWAF = wafTypes[eventTypeF.value]
				needRL = rlTypes[eventTypeF.value]
			case "in":
				needWAF, needRL = false, false
				for _, v := range strings.Split(eventTypeF.value, ",") {
					if wafTypes[strings.TrimSpace(v)] {
						needWAF = true
					}
					if rlTypes[strings.TrimSpace(v)] {
						needRL = true
					}
				}
			default:
				// neq, contains, regex — can't prune safely, fetch both
			}
		}
		var allEvents []Event
		if needWAF {
			allEvents = append(allEvents, getWAFEvents(store, tr, hours)...)
		}

		// Collect access-log events (429 + ipsum) unless filtering to WAF-only types.
		if needRL {
			rlEvents := getRLEvents(als, tr, hours)
			allEvents = append(allEvents, rlEvents...)
		}

		// Sort newest-first.
		sort.Slice(allEvents, func(i, j int) bool {
			return allEvents[i].Timestamp.After(allEvents[j].Timestamp)
		})

		// Apply filters.
		var filtered []Event
		for i := range allEvents {
			ev := &allEvents[i]
			if !serviceF.matchField(ev.Service) {
				continue
			}
			if !clientF.matchField(ev.ClientIP) {
				continue
			}
			if !methodF.matchField(ev.Method) {
				continue
			}
			if blocked != nil && ev.IsBlocked != *blocked {
				continue
			}
			if !eventTypeF.matchField(ev.EventType) {
				continue
			}
			if ruleNameF != nil && !matchesPolicyRuleNameFilter(ev, ruleNameF) {
				continue
			}
			if !uriF.matchField(ev.URI) {
				continue
			}
			if !statusCodeF.matchField(strconv.Itoa(ev.ResponseStatus)) {
				continue
			}
			if !countryF.matchField(ev.Country) {
				continue
			}
			filtered = append(filtered, *ev)
		}

		total := len(filtered)

		// Apply pagination.
		if offset > total {
			offset = total
		}
		end := offset + limit
		if end > total {
			end = total
		}
		page := filtered[offset:end]

		writeJSON(w, http.StatusOK, EventsResponse{
			Total:  total,
			Events: page,
		})
	}
}

func handleServices(store *Store, als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tr := parseTimeRange(r)
		hours := parseHours(r)

		var resp ServicesResponse
		if tr.Valid {
			resp = store.ServicesRange(tr.Start, tr.End)
		} else {
			resp = store.Services(hours)
		}

		// Merge access-log events (429 rate-limited + ipsum-blocked) into service breakdown.
		rlEvents := getRLEvents(als, tr, hours)
		rlSvcMap := make(map[string]int)
		ipsumSvcMap := make(map[string]int)
		for i := range rlEvents {
			if rlEvents[i].EventType == "ipsum_blocked" {
				ipsumSvcMap[rlEvents[i].Service]++
			} else {
				rlSvcMap[rlEvents[i].Service]++
			}
		}

		existingSvcs := make(map[string]int) // index into resp.Services
		for i, sd := range resp.Services {
			existingSvcs[sd.Service] = i
		}

		// Merge rate-limited.
		for svc, count := range rlSvcMap {
			if idx, ok := existingSvcs[svc]; ok {
				resp.Services[idx].RateLimited += count
				resp.Services[idx].Total += count
			} else {
				resp.Services = append(resp.Services, ServiceDetail{
					Service:     svc,
					Total:       count,
					RateLimited: count,
				})
				existingSvcs[svc] = len(resp.Services) - 1
			}
		}

		// Merge ipsum-blocked.
		for svc, count := range ipsumSvcMap {
			if idx, ok := existingSvcs[svc]; ok {
				resp.Services[idx].IpsumBlocked += count
				resp.Services[idx].Total += count
			} else {
				resp.Services = append(resp.Services, ServiceDetail{
					Service:      svc,
					Total:        count,
					IpsumBlocked: count,
				})
				existingSvcs[svc] = len(resp.Services) - 1
			}
		}

		// Re-sort by total desc.
		sort.Slice(resp.Services, func(i, j int) bool {
			return resp.Services[i].Total > resp.Services[j].Total
		})

		writeJSON(w, http.StatusOK, resp)
	}
}

// --- Handlers: Analytics ---

func handleTopBlockedIPs(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tr := parseTimeRange(r)
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		events := getWAFEvents(store, tr, hours)
		writeJSON(w, http.StatusOK, topBlockedIPs(events, limit))
	}
}

func handleTopTargetedURIs(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tr := parseTimeRange(r)
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		events := getWAFEvents(store, tr, hours)
		writeJSON(w, http.StatusOK, topTargetedURIs(events, limit))
	}
}

func handleTopCountries(store *Store, als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tr := parseTimeRange(r)
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		// Merge WAF events + rate-limit/ipsum events
		wafEvents := getWAFEvents(store, tr, hours)
		rlEvents := getRLEvents(als, tr, hours)
		all := make([]Event, 0, len(wafEvents)+len(rlEvents))
		all = append(all, wafEvents...)
		all = append(all, rlEvents...)
		writeJSON(w, http.StatusOK, TopCountries(all, limit))
	}
}

// --- Handler: IP Lookup ---

func handleIPLookup(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.PathValue("ip")
		if ip == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "IP address is required"})
			return
		}
		// Basic IP validation.
		if net.ParseIP(ip) == nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid IP address"})
			return
		}
		q := r.URL.Query()
		hours := parseHours(r)
		limit := queryInt(q.Get("limit"), 50)
		if limit <= 0 || limit > 1000 {
			limit = 50
		}
		offset := queryInt(q.Get("offset"), 0)
		if offset < 0 {
			offset = 0
		}
		result := store.IPLookup(ip, hours, limit, offset)
		writeJSON(w, http.StatusOK, result)
	}
}

// --- Handlers: Exclusion CRUD ---

// handleExclusionHits returns per-exclusion hit counts derived from policy events.
// It scans events for policy_* event types, matches the msg field in matched_rules
// back to exclusion names, and returns both total hit counts and an hourly sparkline.
//
// Response: { "hits": { "<exclusion_name>": { "total": N, "sparkline": [n, n, ...] } } }
// The sparkline is a 24-element array (one per hour, oldest first).
func handleExclusionHits(store *Store, es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hoursStr := r.URL.Query().Get("hours")
		hours := 24
		if hoursStr != "" {
			if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 && h <= 720 {
				hours = h
			}
		}

		events := store.SnapshotSince(hours)
		exclusions := es.List()

		// Build a set of known exclusion names for fast lookup.
		nameSet := make(map[string]bool, len(exclusions))
		for _, exc := range exclusions {
			nameSet[exc.Name] = true
		}

		// Determine the sparkline bucket boundaries.
		now := time.Now().UTC()
		bucketCount := hours
		if bucketCount > 168 { // cap at 168 buckets (1 week hourly)
			bucketCount = 168
		}
		bucketStart := now.Truncate(time.Hour).Add(-time.Duration(bucketCount-1) * time.Hour)

		type hitData struct {
			Total     int   `json:"total"`
			Sparkline []int `json:"sparkline"`
		}
		hits := make(map[string]*hitData)

		// Initialize entries for all exclusions (so the frontend doesn't need to handle missing keys).
		for _, exc := range exclusions {
			hits[exc.Name] = &hitData{Sparkline: make([]int, bucketCount)}
		}

		for i := range events {
			ev := &events[i]
			if !strings.HasPrefix(ev.EventType, "policy_") {
				continue
			}
			for _, mr := range ev.MatchedRules {
				// msg format: "Policy Allow: <name>", "Policy Skip: <name>", "Policy Block: <name>"
				name := extractPolicyName(mr.Msg)
				if name == "" || !nameSet[name] {
					continue
				}
				hd, ok := hits[name]
				if !ok {
					hd = &hitData{Sparkline: make([]int, bucketCount)}
					hits[name] = hd
				}
				hd.Total++
				// Assign to sparkline bucket.
				bucket := int(ev.Timestamp.Sub(bucketStart).Hours())
				if bucket >= 0 && bucket < bucketCount {
					hd.Sparkline[bucket]++
				}
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{"hits": hits})
	}
}

// matchesPolicyRuleName checks whether an event was triggered by a policy
// exclusion with the given name.  It scans the matched_rules for a msg
// containing "Policy Allow/Skip/Block: <name>".
func matchesPolicyRuleName(ev *Event, name string) bool {
	if name == "" {
		return false
	}
	for _, mr := range ev.MatchedRules {
		if extractPolicyName(mr.Msg) == name {
			return true
		}
	}
	return false
}

// matchesPolicyRuleNameFilter checks whether an event's policy rule name
// matches the given fieldFilter (supporting eq, neq, contains, regex, in).
func matchesPolicyRuleNameFilter(ev *Event, f *fieldFilter) bool {
	for _, mr := range ev.MatchedRules {
		name := extractPolicyName(mr.Msg)
		if name != "" && f.matchField(name) {
			return true
		}
	}
	return false
}

// extractPolicyName extracts the exclusion name from a policy rule msg string.
// Expected formats: "Policy Allow: <name>", "Policy Skip: <name>", "Policy Block: <name>"
func extractPolicyName(msg string) string {
	prefixes := []string{"Policy Allow: ", "Policy Skip: ", "Policy Block: "}
	for _, p := range prefixes {
		if strings.HasPrefix(msg, p) {
			return msg[len(p):]
		}
	}
	return ""
}

func handleListExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, es.List())
	}
}

func handleGetExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		exc, found := es.Get(id)
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}
		writeJSON(w, http.StatusOK, exc)
	}
}

func handleCreateExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var exc RuleExclusion
		if _, failed := decodeJSON(w, r, &exc); failed {
			return
		}
		if err := validateExclusion(exc); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		created, err := es.Create(exc)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to create exclusion", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func handleUpdateExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		// Decode into a map first to detect which fields were sent.
		var raw map[string]json.RawMessage
		if _, failed := decodeJSON(w, r, &raw); failed {
			return
		}

		// Fetch the existing exclusion to use as base for merge.
		existing, found := es.Get(id)
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}

		// Marshal existing to JSON, then overlay the incoming fields.
		base, _ := json.Marshal(existing)
		var merged RuleExclusion
		_ = json.Unmarshal(base, &merged)
		overlay, _ := json.Marshal(raw)
		_ = json.Unmarshal(overlay, &merged)

		if err := validateExclusion(merged); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		updated, found, err := es.Update(id, merged)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update exclusion", Details: err.Error()})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func handleDeleteExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		found, err := es.Delete(id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to delete exclusion", Details: err.Error()})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleGenerateExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		exclusions := es.EnabledExclusions()
		// Generate with a default config — this endpoint is exclusion-only.
		result := GenerateConfigs(defaultConfig(), exclusions)
		writeJSON(w, http.StatusOK, result)
	}
}

func handleExportExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, es.Export())
	}
}

func handleImportExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var export ExclusionExport
		if _, failed := decodeJSON(w, r, &export); failed {
			return
		}
		if len(export.Exclusions) == 0 {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "no exclusions in import data"})
			return
		}
		// Validate all exclusions before importing.
		for i, exc := range export.Exclusions {
			if err := validateExclusion(exc); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{
					Error:   "validation failed",
					Details: "exclusion " + strconv.Itoa(i) + ": " + err.Error(),
				})
				return
			}
		}
		if err := es.Import(export.Exclusions); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to import exclusions", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"imported": len(export.Exclusions)})
	}
}

func handleReorderExclusions(es *ExclusionStore) http.HandlerFunc {
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
		if err := es.Reorder(req.IDs); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "reorder failed", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, es.List())
	}
}

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
		cfg := cs.Get()
		exclusions := es.EnabledExclusions()
		ResetRuleIDCounter()
		result := GenerateConfigs(cfg, exclusions)
		wafSettings := GenerateWAFSettings(cfg)

		// Validate generated config before writing.
		vr := ValidateGeneratedConfig(result.PreCRS, result.PostCRS, wafSettings)
		selfRefWarnings := validateGeneratedRuleIDs(exclusions)
		vr.Warnings = append(vr.Warnings, selfRefWarnings...)
		logValidationResult(vr)

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

func handleDeployRLRules(rs *RateLimitRuleStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Discover any new services from the Caddyfile.
		rs.MergeCaddyfileServices(deployCfg.CaddyfilePath)

		rules := rs.EnabledRules()
		global := rs.GetGlobal()
		files := GenerateRateLimitConfigs(rules, global, deployCfg.CaddyfilePath)

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

// maxJSONBody is the maximum request body size for JSON endpoints (5 MB).
// Generous for bulk imports (~500+ exclusions) while preventing OOM from
// unbounded payloads. The dashboard only sends small payloads; this is a
// safety net, not a functional limit.
const maxJSONBody = 5 << 20

// decodeJSON limits the request body to maxJSONBody and decodes JSON into dst.
// Returns a user-facing error string and true on failure; empty string and false on success.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) (string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		msg := "invalid JSON body"
		if err.Error() == "http: request body too large" {
			msg = "request body too large (max 5 MB)"
		}
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: msg, Details: err.Error()})
		return msg, true
	}
	return "", false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Printf("error encoding JSON response: %v", err)
	}
}

func queryInt(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}

// --- Field filter with operator support ---

// fieldFilter represents a single filter condition with an operator.
// Supported operators: eq (default), neq, contains, in, regex.
type fieldFilter struct {
	value string
	op    string         // "eq", "neq", "contains", "in", "regex"
	re    *regexp.Regexp // compiled only when op == "regex"
	ins   []string       // split values only when op == "in"
}

// validFilterOps is the set of recognized filter operators.
var validFilterOps = map[string]bool{
	"eq": true, "neq": true, "contains": true, "in": true, "regex": true,
}

// parseFieldFilter reads a filter value and its companion _op param from query.
// Returns nil when the field is empty (no filter).
func parseFieldFilter(value, op string) *fieldFilter {
	if value == "" {
		return nil
	}
	if !validFilterOps[op] {
		op = "eq"
	}
	f := &fieldFilter{value: value, op: op}
	switch op {
	case "regex":
		re, err := regexp.Compile(value)
		if err != nil {
			// Fall back to literal contains on bad regex.
			f.op = "contains"
		} else {
			f.re = re
		}
	case "in":
		parts := strings.Split(value, ",")
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				f.ins = append(f.ins, t)
			}
		}
	}
	return f
}

// matchField tests whether target matches the filter condition.
// Case-insensitive for eq/neq/contains/in; regex uses the compiled pattern as-is.
func (f *fieldFilter) matchField(target string) bool {
	if f == nil {
		return true // no filter = always match
	}
	switch f.op {
	case "eq":
		return strings.EqualFold(target, f.value)
	case "neq":
		return !strings.EqualFold(target, f.value)
	case "contains":
		return strings.Contains(strings.ToLower(target), strings.ToLower(f.value))
	case "in":
		for _, v := range f.ins {
			if strings.EqualFold(target, v) {
				return true
			}
		}
		return false
	case "regex":
		if f.re != nil {
			return f.re.MatchString(target)
		}
		return strings.Contains(strings.ToLower(target), strings.ToLower(f.value))
	}
	return true
}
