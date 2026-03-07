package main

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ─── Aggregation ────────────────────────────────────────────────────

// getGeneralEvents returns events filtered by either time range or hours.
func getGeneralEvents(s *GeneralLogStore, tr timeRange, hours int) []GeneralLogEvent {
	if tr.Valid {
		return s.snapshotRange(tr.Start, tr.End)
	}
	return s.snapshotSince(hours)
}

// summarizeGeneralLogs builds a GeneralLogsSummary from a slice of events.
func summarizeGeneralLogs(events []GeneralLogEvent) GeneralLogsSummary {
	summary := GeneralLogsSummary{
		TotalRequests:      len(events),
		StatusDistribution: make(map[string]int),
	}

	if len(events) == 0 {
		return summary
	}

	// Accumulators
	var totalDuration float64
	durations := make([]float64, 0, len(events))
	serviceMap := make(map[string]*generalServiceAcc)
	uriMap := make(map[string]*generalURIAcc)
	clientMap := make(map[string]*generalClientAcc)
	var recentErrors []GeneralLogEvent

	for i := range events {
		e := &events[i]

		// Status distribution
		bucket := statusBucket(e.Status)
		summary.StatusDistribution[bucket]++

		if e.Status >= 500 {
			summary.ErrorCount++
		} else if e.Status >= 400 {
			summary.ClientErrorCount++
		}

		// Duration
		totalDuration += e.Duration
		durations = append(durations, e.Duration)

		// Per-service
		sa, ok := serviceMap[e.Service]
		if !ok {
			sa = &generalServiceAcc{}
			serviceMap[e.Service] = sa
		}
		sa.count++
		sa.totalDuration += e.Duration
		if e.Status >= 500 {
			sa.errorCount++
		}
		// Header compliance tracking
		if e.SecurityHeaders.HasCSP {
			sa.cspCount++
		}
		if e.SecurityHeaders.HasHSTS {
			sa.hstsCount++
		}
		if e.SecurityHeaders.HasXContentTypeOptions {
			sa.xctoCount++
		}
		if e.SecurityHeaders.HasXFrameOptions {
			sa.xfoCount++
		}
		if e.SecurityHeaders.HasReferrerPolicy {
			sa.rpCount++
		}
		if e.SecurityHeaders.HasCORSOrigin {
			sa.corsCount++
		}
		if e.SecurityHeaders.HasPermissionsPolicy {
			sa.ppCount++
		}

		// Per-URI (only track top N by accumulation, cap map size)
		if len(uriMap) < 5000 {
			ua, ok := uriMap[e.URI]
			if !ok {
				ua = &generalURIAcc{}
				uriMap[e.URI] = ua
			}
			ua.count++
			ua.totalDuration += e.Duration
			if e.Status >= 500 {
				ua.errorCount++
			}
		} else if ua, ok := uriMap[e.URI]; ok {
			ua.count++
			ua.totalDuration += e.Duration
			if e.Status >= 500 {
				ua.errorCount++
			}
		}

		// Per-client
		if len(clientMap) < 5000 {
			ca, ok := clientMap[e.ClientIP]
			if !ok {
				ca = &generalClientAcc{country: e.Country}
				clientMap[e.ClientIP] = ca
			}
			ca.count++
			if e.Status >= 500 {
				ca.errorCount++
			}
		} else if ca, ok := clientMap[e.ClientIP]; ok {
			ca.count++
			if e.Status >= 500 {
				ca.errorCount++
			}
		}

		// Recent errors (keep last 20)
		if e.Status >= 400 {
			recentErrors = append(recentErrors, *e)
		}
	}

	// Average duration
	if len(events) > 0 {
		summary.AvgDuration = totalDuration / float64(len(events))
	}

	// Latency percentiles
	sort.Float64s(durations)
	summary.P50Duration = percentile(durations, 0.50)
	summary.P95Duration = percentile(durations, 0.95)
	summary.P99Duration = percentile(durations, 0.99)

	// Top services
	summary.TopServices = topGeneralServices(serviceMap, topNSummary)

	// Header compliance
	summary.HeaderCompliance = buildHeaderCompliance(serviceMap, topNAnalytics)

	// Top URIs
	summary.TopURIs = topGeneralURIs(uriMap, topNSummary)

	// Top clients
	summary.TopClients = topGeneralClients(clientMap, topNSummary)

	// Recent errors (newest first, limit 20)
	if len(recentErrors) > 20 {
		recentErrors = recentErrors[len(recentErrors)-20:]
	}
	// Reverse to newest first
	for i, j := 0, len(recentErrors)-1; i < j; i, j = i+1, j-1 {
		recentErrors[i], recentErrors[j] = recentErrors[j], recentErrors[i]
	}
	summary.RecentErrors = recentErrors

	return summary
}

// --- Aggregation accumulators ---

type generalServiceAcc struct {
	count         int
	errorCount    int
	totalDuration float64
	cspCount      int
	hstsCount     int
	xctoCount     int
	xfoCount      int
	rpCount       int
	corsCount     int
	ppCount       int
}

type generalURIAcc struct {
	count         int
	errorCount    int
	totalDuration float64
}

type generalClientAcc struct {
	country    string
	count      int
	errorCount int
}

func statusBucket(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "other"
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := p * float64(len(sorted)-1)
	lower := int(math.Floor(idx))
	upper := int(math.Ceil(idx))
	if lower == upper || upper >= len(sorted) {
		return sorted[lower]
	}
	frac := idx - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

func topGeneralServices(m map[string]*generalServiceAcc, n int) []GeneralServiceCount {
	type kv struct {
		key string
		acc *generalServiceAcc
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].acc.count > items[j].acc.count })
	if len(items) > n {
		items = items[:n]
	}
	result := make([]GeneralServiceCount, len(items))
	for i, item := range items {
		avgDur := 0.0
		if item.acc.count > 0 {
			avgDur = item.acc.totalDuration / float64(item.acc.count)
		}
		errRate := 0.0
		if item.acc.count > 0 {
			errRate = float64(item.acc.errorCount) / float64(item.acc.count)
		}
		result[i] = GeneralServiceCount{
			Service:     item.key,
			Count:       item.acc.count,
			ErrorCount:  item.acc.errorCount,
			ErrorRate:   errRate,
			AvgDuration: avgDur,
		}
	}
	return result
}

func buildHeaderCompliance(m map[string]*generalServiceAcc, n int) []HeaderCompliance {
	type kv struct {
		key string
		acc *generalServiceAcc
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].acc.count > items[j].acc.count })
	if len(items) > n {
		items = items[:n]
	}
	result := make([]HeaderCompliance, len(items))
	for i, item := range items {
		c := float64(item.acc.count)
		result[i] = HeaderCompliance{
			Service:                 item.key,
			Total:                   item.acc.count,
			CSPRate:                 float64(item.acc.cspCount) / c,
			HSTSRate:                float64(item.acc.hstsCount) / c,
			XContentTypeOptionsRate: float64(item.acc.xctoCount) / c,
			XFrameOptionsRate:       float64(item.acc.xfoCount) / c,
			ReferrerPolicyRate:      float64(item.acc.rpCount) / c,
			CORSOriginRate:          float64(item.acc.corsCount) / c,
			PermissionsPolicyRate:   float64(item.acc.ppCount) / c,
		}
	}
	return result
}

func topGeneralURIs(m map[string]*generalURIAcc, n int) []GeneralURICount {
	type kv struct {
		key string
		acc *generalURIAcc
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].acc.count > items[j].acc.count })
	if len(items) > n {
		items = items[:n]
	}
	result := make([]GeneralURICount, len(items))
	for i, item := range items {
		avgDur := 0.0
		if item.acc.count > 0 {
			avgDur = item.acc.totalDuration / float64(item.acc.count)
		}
		result[i] = GeneralURICount{
			URI:         item.key,
			Count:       item.acc.count,
			ErrorCount:  item.acc.errorCount,
			AvgDuration: avgDur,
		}
	}
	return result
}

func topGeneralClients(m map[string]*generalClientAcc, n int) []GeneralClientCount {
	type kv struct {
		key string
		acc *generalClientAcc
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].acc.count > items[j].acc.count })
	if len(items) > n {
		items = items[:n]
	}
	result := make([]GeneralClientCount, len(items))
	for i, item := range items {
		result[i] = GeneralClientCount{
			ClientIP:   item.key,
			Country:    item.acc.country,
			Count:      item.acc.count,
			ErrorCount: item.acc.errorCount,
		}
	}
	return result
}

// ─── HTTP Handlers ──────────────────────────────────────────────────

// handleGeneralLogs returns paginated, filtered general log events.
// GET /api/logs?hours=&start=&end=&service=&method=&status=&status_op=&client=&uri=&level=&limit=&offset=
func handleGeneralLogs(gls *GeneralLogStore) http.HandlerFunc {
	cache := newResponseCache(50)
	return func(w http.ResponseWriter, r *http.Request) {
		tr := parseTimeRange(r)
		hours := parseHours(r)
		q := r.URL.Query()

		cacheKey := r.URL.RawQuery
		gen := gls.generation.Load()
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		events := getGeneralEvents(gls, tr, hours)

		// Parse filters
		serviceF := parseFieldFilter(q.Get("service"), q.Get("service_op"))
		methodF := parseFieldFilter(q.Get("method"), q.Get("method_op"))
		clientF := parseFieldFilter(q.Get("client"), q.Get("client_op"))
		uriF := parseFieldFilter(q.Get("uri"), q.Get("uri_op"))
		levelF := parseFieldFilter(q.Get("level"), q.Get("level_op"))
		countryF := parseFieldFilter(q.Get("country"), q.Get("country_op"))
		uaF := parseFieldFilter(q.Get("user_agent"), q.Get("user_agent_op"))

		// Status filter: support "4xx", "5xx" buckets as well as exact codes
		statusStr := q.Get("status")
		statusOp := q.Get("status_op")
		var statusFilter *fieldFilter
		var statusBucketFilter string
		if statusStr != "" {
			lower := strings.ToLower(statusStr)
			if lower == "2xx" || lower == "3xx" || lower == "4xx" || lower == "5xx" {
				statusBucketFilter = lower
			} else {
				statusFilter = parseFieldFilter(statusStr, statusOp)
			}
		}

		// Header presence filter (e.g., ?missing_header=csp)
		missingHeader := strings.ToLower(q.Get("missing_header"))

		limit := queryInt(q.Get("limit"), 50)
		if limit > 1000 {
			limit = 1000
		}
		offsetVal := queryInt(q.Get("offset"), 0)

		// Filter (newest first)
		matched := 0
		var filtered []GeneralLogEvent
		for i := len(events) - 1; i >= 0; i-- {
			e := &events[i]

			if serviceF != nil && !serviceF.matchField(e.Service) {
				continue
			}
			if methodF != nil && !methodF.matchField(e.Method) {
				continue
			}
			if clientF != nil && !clientF.matchField(e.ClientIP) {
				continue
			}
			if uriF != nil && !uriF.matchField(e.URI) {
				continue
			}
			if levelF != nil && !levelF.matchField(e.Level) {
				continue
			}
			if countryF != nil && !countryF.matchField(e.Country) {
				continue
			}
			if uaF != nil && !uaF.matchField(e.UserAgent) {
				continue
			}

			// Status filter
			if statusBucketFilter != "" {
				if statusBucket(e.Status) != statusBucketFilter {
					continue
				}
			}
			if statusFilter != nil && !statusFilter.matchField(strconv.Itoa(e.Status)) {
				continue
			}

			// Missing header filter
			if missingHeader != "" && !isMissingHeader(e, missingHeader) {
				continue
			}

			matched++
			if matched > offsetVal && len(filtered) < limit {
				filtered = append(filtered, *e)
			}
		}

		resp := GeneralLogsResponse{
			Total:  matched,
			Events: filtered,
		}
		if resp.Events == nil {
			resp.Events = []GeneralLogEvent{}
		}
		cache.set(cacheKey, resp, gen, 3*time.Second)
		writeJSON(w, http.StatusOK, resp)
	}
}

// handleGeneralLogsSummary returns aggregated stats for the general log viewer.
// GET /api/logs/summary?hours=&start=&end=&service=
func handleGeneralLogsSummary(gls *GeneralLogStore) http.HandlerFunc {
	cache := newResponseCache(50)
	return func(w http.ResponseWriter, r *http.Request) {
		tr := parseTimeRange(r)
		hours := parseHours(r)
		q := r.URL.Query()

		cacheKey := r.URL.RawQuery
		gen := gls.generation.Load()
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		events := getGeneralEvents(gls, tr, hours)

		// Optional service filter
		serviceF := parseFieldFilter(q.Get("service"), q.Get("service_op"))
		if serviceF != nil {
			var filtered []GeneralLogEvent
			for i := range events {
				if serviceF.matchField(events[i].Service) {
					filtered = append(filtered, events[i])
				}
			}
			events = filtered
		}

		summary := summarizeGeneralLogs(events)
		cache.set(cacheKey, summary, gen, 3*time.Second)
		writeJSON(w, http.StatusOK, summary)
	}
}

// isMissingHeader checks if a specific security header is absent from the event.
func isMissingHeader(e *GeneralLogEvent, header string) bool {
	switch header {
	case "csp":
		return !e.SecurityHeaders.HasCSP
	case "hsts":
		return !e.SecurityHeaders.HasHSTS
	case "x-content-type-options", "xcto":
		return !e.SecurityHeaders.HasXContentTypeOptions
	case "x-frame-options", "xfo":
		return !e.SecurityHeaders.HasXFrameOptions
	case "referrer-policy":
		return !e.SecurityHeaders.HasReferrerPolicy
	case "cors":
		return !e.SecurityHeaders.HasCORSOrigin
	case "permissions-policy":
		return !e.SecurityHeaders.HasPermissionsPolicy
	}
	return false
}
