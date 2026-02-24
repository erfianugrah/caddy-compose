package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	logPath := envOr("WAF_AUDIT_LOG", "/var/log/coraza-audit.log")
	port := envOr("WAF_API_PORT", "8080")
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

	// Event retention: maximum age for in-memory events (default 168h = 7 days).
	maxAgeStr := envOr("WAF_EVENT_MAX_AGE", "168h")
	maxAge, err := time.ParseDuration(maxAgeStr)
	if err != nil {
		log.Printf("warning: invalid WAF_EVENT_MAX_AGE %q, using 168h", maxAgeStr)
		maxAge = 168 * time.Hour
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

	log.Printf("waf-api starting: log=%s combined=%s port=%s exclusions=%s config=%s ratelimits=%s coraza_dir=%s rl_dir=%s max_age=%s tail_interval=%s geoip_db=%s geoip_api=%s",
		logPath, combinedAccessLog, port, exclusionsFile, configFile, rateLimitFile, deployCfg.CorazaDir, deployCfg.RateLimitDir, maxAge, tailInterval, geoDBPath, geoAPIURL)

	var geoAPICfg *GeoIPAPIConfig
	if geoAPIURL != "" {
		geoAPICfg = &GeoIPAPIConfig{URL: geoAPIURL, Key: geoAPIKey}
	}
	geoStore := NewGeoIPStore(geoDBPath, geoAPICfg)

	store := NewStore(logPath)
	store.SetOffsetFile(envOr("WAF_AUDIT_OFFSET_FILE", "/data/.audit-log-offset"))
	store.SetMaxAge(maxAge)
	store.SetGeoIP(geoStore)
	store.StartTailing(tailInterval)

	accessLogStore := NewAccessLogStore(combinedAccessLog)
	accessLogStore.SetMaxAge(maxAge)
	accessLogStore.SetGeoIP(geoStore)
	accessLogStore.StartTailing(tailInterval)

	exclusionStore := NewExclusionStore(exclusionsFile)
	configStore := NewConfigStore(configFile)
	rateLimitStore := NewRateLimitStore(rateLimitFile)

	// Generate-on-boot: regenerate WAF and rate limit config files from stored
	// state so a stack restart always picks up the latest generator output.
	// No Caddy reload is needed because Caddy reads fresh on its own startup.
	generateOnBoot(configStore, exclusionStore, rateLimitStore, deployCfg)

	blocklistPath := filepath.Join(deployCfg.CorazaDir, "ipsum_block.caddy")
	blocklistStore := NewBlocklistStore(blocklistPath)

	mux := http.NewServeMux()

	// Existing endpoints (with hours filter support) — merged WAF + 429 events
	mux.HandleFunc("GET /api/health", handleHealth)
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
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(configStore, exclusionStore, rateLimitStore, deployCfg))

	// Rate Limits
	mux.HandleFunc("GET /api/rate-limits", handleGetRateLimits(rateLimitStore))
	mux.HandleFunc("PUT /api/rate-limits", handleUpdateRateLimits(rateLimitStore))
	mux.HandleFunc("POST /api/rate-limits/deploy", handleDeployRateLimits(rateLimitStore, deployCfg))

	// Rate Limit Analytics (429 events from combined access log)
	mux.HandleFunc("GET /api/rate-limits/summary", handleRLSummary(accessLogStore))
	mux.HandleFunc("GET /api/rate-limits/events", handleRLEvents(accessLogStore))

	// Blocklist (IPsum)
	mux.HandleFunc("GET /api/blocklist/stats", handleBlocklistStats(blocklistStore))
	mux.HandleFunc("GET /api/blocklist/check/{ip}", handleBlocklistCheck(blocklistStore))
	mux.HandleFunc("POST /api/blocklist/refresh", handleBlocklistRefresh(blocklistStore, rateLimitStore, deployCfg))

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
		log.Fatalf("server error: %v", err)
	}
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

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{Status: "ok"})
}

func handleSummary(store *Store, als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tr := parseTimeRange(r)
		hours := parseHours(r)

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

		// Merge unique clients/services (union).
		wafSnapshot := getWAFEvents(store, tr, hours)
		allClients := make(map[string]struct{})
		allServices := make(map[string]struct{})
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

		service := q.Get("service")
		client := q.Get("client")
		method := q.Get("method")
		eventType := q.Get("event_type") // "blocked", "logged", "rate_limited", "ipsum_blocked", "policy_skip", "policy_allow", "policy_block", "honeypot", "scanner", or ""

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
		var allEvents []Event
		if eventType != "rate_limited" && eventType != "ipsum_blocked" {
			wafEvents := getWAFEvents(store, tr, hours)
			allEvents = append(allEvents, wafEvents...)
		}

		// Collect access-log events (429 + ipsum) unless filtering to WAF-only types.
		if eventType != "blocked" && eventType != "logged" {
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
			if service != "" && !strings.EqualFold(ev.Service, service) {
				continue
			}
			if client != "" && ev.ClientIP != client {
				continue
			}
			if method != "" && !strings.EqualFold(ev.Method, method) {
				continue
			}
			if blocked != nil && ev.IsBlocked != *blocked {
				continue
			}
			if eventType != "" && ev.EventType != eventType {
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
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		writeJSON(w, http.StatusOK, store.TopBlockedIPs(hours, limit))
	}
}

func handleTopTargetedURIs(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		writeJSON(w, http.StatusOK, store.TopTargetedURIs(hours, limit))
	}
}

func handleTopCountries(store *Store, als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		// Merge WAF events + rate-limit/ipsum events
		wafEvents := store.SnapshotSince(hours)
		rlEvents := als.SnapshotAsEvents(hours)
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
		hours := parseHours(r)
		result := store.IPLookup(ip, hours)
		writeJSON(w, http.StatusOK, result)
	}
}

// --- Handlers: Exclusion CRUD ---

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
		if err := json.NewDecoder(r.Body).Decode(&exc); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON body", Details: err.Error()})
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
		var exc RuleExclusion
		if err := json.NewDecoder(r.Body).Decode(&exc); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON body", Details: err.Error()})
			return
		}
		if err := validateExclusion(exc); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		updated, found, err := es.Update(id, exc)
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
		if err := json.NewDecoder(r.Body).Decode(&export); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON body", Details: err.Error()})
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
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON body", Details: err.Error()})
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

// --- Handler: Deploy ---

func handleDeploy(cs *ConfigStore, es *ExclusionStore, rs *RateLimitStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		cfg := cs.Get()
		exclusions := es.EnabledExclusions()
		ResetRuleIDCounter()
		result := GenerateConfigs(cfg, exclusions)
		wafSettings := GenerateWAFSettings(cfg)

		// Write config files to the shared volume.
		if err := writeConfFiles(deployCfg.CorazaDir, result.PreCRS, result.PostCRS, wafSettings); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error:   "failed to write config files",
				Details: err.Error(),
			})
			return
		}

		// Ensure any new Caddyfile zones have rate limit files before reload.
		syncCaddyfileZones(rs, deployCfg)

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

// --- Handlers: Rate Limits ---

func handleGetRateLimits(rs *RateLimitStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, rs.Get())
	}
}

func handleUpdateRateLimits(rs *RateLimitStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg RateLimitConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON body", Details: err.Error()})
			return
		}
		if err := validateRateLimitConfig(cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		updated, err := rs.Update(cfg)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update rate limits", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func handleDeployRateLimits(rs *RateLimitStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Discover any new zones from the Caddyfile before writing files.
		// Use MergeCaddyfileZones directly (not syncCaddyfileZones) because
		// writeZoneFiles below already writes all zones in one pass.
		rs.MergeCaddyfileZones(deployCfg.CaddyfilePath)

		cfg := rs.Get()

		// Write zone files to the shared volume.
		written, err := writeZoneFiles(deployCfg.RateLimitDir, cfg.Zones)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error:   "failed to write zone files",
				Details: err.Error(),
			})
			return
		}

		// Reload Caddy via admin API.
		// Pass the written zone files so reloadCaddy can fingerprint them.
		reloaded := true
		if err := reloadCaddy(deployCfg.CaddyfilePath, deployCfg.CaddyAdminURL, written...); err != nil {
			log.Printf("warning: Caddy reload failed after rate limit deploy: %v", err)
			reloaded = false
		}

		status := "deployed"
		msg := fmt.Sprintf("Wrote %d zone files and Caddy reloaded successfully", len(written))
		if !reloaded {
			status = "partial"
			msg = fmt.Sprintf("Wrote %d zone files but Caddy reload failed — manual reload may be needed", len(written))
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

// ─── Rate Limit Analytics handlers ──────────────────────────────────

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
