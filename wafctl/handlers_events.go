package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// eventQueryTimeout is the maximum time allowed for event search iteration.
// Prevents unbounded CPU usage from complex filter queries over large event stores.
const eventQueryTimeout = 60 * time.Second

// --- Handlers: Health, Summary, Events, Services ---

func handleHealth(store *Store, als *AccessLogStore, gls *GeneralLogStore, geoStore *GeoIPStore, exclusionStore *ExclusionStore, blocklistStore *BlocklistStore, cfProxyStore *CFProxyStore, cspStore *CSPStore, secStore *SecurityHeaderStore, ds *DefaultRuleStore, jailStore *JailStore, spike *SpikeDetector, reporter *SpikeReporter) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		uptime := time.Since(startTime).Truncate(time.Second)

		// Use TryRLock for event stores — if they're busy loading/compacting,
		// return a minimal health response instead of blocking for minutes.
		spikeStatus := spike.Status()
		stores := map[string]any{
			"geoip": map[string]any{
				"mmdb_loaded": geoStore.HasDB(),
				"api_enabled": geoStore.HasAPI(),
			},
			"exclusions": map[string]any{
				"count": exclusionStore.Count(),
			},
			"blocklist":        blocklistStore.Stats(),
			"cfproxy":          cfProxyStore.Stats(),
			"csp":              cspStore.StoreInfo(),
			"security_headers": secStore.StoreInfo(),
			"dos": map[string]any{
				"mode":          spikeStatus.Mode,
				"eps":           spikeStatus.EPS,
				"jail_count":    jailStore.Count(),
				"spike_reports": reporter.Count(),
			},
		}

		// Non-blocking stats for event stores — return "loading" if locked.
		if store.mu.TryRLock() {
			stores["waf_events"] = store.statsLocked()
			store.mu.RUnlock()
		} else {
			stores["waf_events"] = map[string]any{"status": "loading"}
		}
		if als.mu.TryRLock() {
			stores["access_events"] = als.statsLocked()
			als.mu.RUnlock()
		} else {
			stores["access_events"] = map[string]any{"status": "loading"}
		}
		if gls.mu.TryRLock() {
			stores["general_logs"] = gls.statsLocked()
			gls.mu.RUnlock()
		} else {
			stores["general_logs"] = map[string]any{"status": "loading"}
		}

		crsVer := ds.CRSVersion()
		if crsVer == "" {
			crsVer = "unknown"
		}

		writeJSON(w, http.StatusOK, HealthResponse{
			Status:     "ok",
			Version:    version,
			CRSVersion: crsVer,
			Uptime:     uptime.String(),
			Stores:     stores,
		})
	}
}

func handleSummary(store *Store, als *AccessLogStore) http.HandlerFunc {
	cache := newResponseCache(50)
	return func(w http.ResponseWriter, r *http.Request) {
		tr := parseTimeRange(r)
		hours := parseHours(r)
		q := r.URL.Query()

		// Check response cache — keyed on normalized query string, invalidated by
		// data generation changes (new events or evictions in either store).
		cacheKey := normalizeCacheKey(r.URL.RawQuery)
		gen := combinedGeneration(&store.generation, &als.generation)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		// Read filter params with operator support (e.g. service_op=in&service=a,b).
		serviceF := parseFieldFilter(q.Get("service"), q.Get("service_op"))
		clientF := parseFieldFilter(q.Get("client"), q.Get("client_op"))
		methodF := parseFieldFilter(q.Get("method"), q.Get("method_op"))
		eventTypeF := parseFieldFilter(q.Get("event_type"), q.Get("event_type_op"))
		ruleNameF := parseFieldFilter(q.Get("rule_name"), q.Get("rule_name_op"))
		uriF := parseFieldFilter(q.Get("uri"), q.Get("uri_op"))
		statusCodeF := parseFieldFilter(q.Get("status_code"), q.Get("status_code_op"))
		countryF := parseFieldFilter(q.Get("country"), q.Get("country_op"))
		requestIDF := parseFieldFilter(q.Get("request_id"), q.Get("request_id_op"))
		tagF := parseFieldFilter(q.Get("tag"), q.Get("tag_op"))
		blockedByF := parseFieldFilter(q.Get("blocked_by"), q.Get("blocked_by_op"))

		hasFilter := serviceF != nil || clientF != nil || methodF != nil || eventTypeF != nil || ruleNameF != nil ||
			uriF != nil || statusCodeF != nil || countryF != nil || requestIDF != nil || tagF != nil || blockedByF != nil

		// When any filter is active, collect matching events from both stores
		// and summarize. Uses raw RLE for ALS to avoid O(N) enrichment.
		if hasFilter {
			needWAF, needRL := eventSourcesNeeded(eventTypeF)

			// WAF events: filter inline (small store, typically <50K).
			var filtered []Event
			if needWAF {
				wafEvents := getWAFEvents(store, tr, hours)
				for i := range wafEvents {
					ev := &wafEvents[i]
					if !serviceF.matchField(ev.Service) || !clientF.matchField(ev.ClientIP) ||
						!methodF.matchField(ev.Method) || !eventTypeF.matchField(ev.EventType) ||
						!uriF.matchField(ev.URI) || !statusCodeF.matchIntField(ev.ResponseStatus) ||
						!countryF.matchField(ev.Country) || !requestIDF.matchField(ev.RequestID) ||
						!tagF.matchTags(ev.Tags) || !blockedByF.matchField(ev.BlockedBy) {
						continue
					}
					if ruleNameF != nil && !matchesPolicyRuleNameFilter(ev, ruleNameF) {
						continue
					}
					filtered = append(filtered, *ev)
				}
			}

			// ALS events: filter on raw RLE fields to avoid O(N) enrichment of 579K events.
			// Only matching events are enriched for summarization.
			if needRL {
				rlRaw := getRawRLSnapshot(als, tr, hours)
				lookup := buildEnrichmentLookup(als)
				for i := range rlRaw {
					rle := &rlRaw[i]
					if !serviceF.matchField(rle.Service) || !clientF.matchField(rle.ClientIP) ||
						!methodF.matchField(rle.Method) || !eventTypeF.matchField(rleEventType(rle.Source)) ||
						!uriF.matchField(rle.URI) || !statusCodeF.matchIntField(rleResponseStatus(rle)) ||
						!countryF.matchField(rle.Country) || !requestIDF.matchField(rle.RequestID) ||
						!blockedByF.matchField(rleBlockedBy(rle)) {
						continue
					}
					if ruleNameF != nil && !ruleNameF.matchField(rle.RuleName) {
						continue
					}
					if tagF != nil && !tagF.matchTags(rleTags(rle, &lookup)) {
						continue
					}
					blocked := rleIsBlocked(rle.Source)
					if blocked != (blockedByF != nil) || true {
						// Always enrich matching events for summary.
						filtered = append(filtered, enrichSingleRLE(rle, &lookup))
					}
				}
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
			cache.set(cacheKey, summary, gen, 30*time.Second)
			writeJSON(w, http.StatusOK, summary)
			return
		}

		// Fast path: use incremental per-hour counters from both stores
		// and merge their summaries. O(buckets) instead of O(events).
		// The time-range path falls back to the full-scan approach since
		// counters only support hour-granularity filtering.
		if tr.Valid {
			// Absolute time range: fall back to full-scan merge.
			// WAF store: small, use snapshot directly.
			sr := summarizeEventsWithSets(store.SnapshotRange(tr.Start, tr.End))
			summary := sr.SummaryResponse
			// ALS store: use raw RLE snapshot + lightweight enrichment for summary.
			// Only convert matching events instead of enriching all 579K.
			rlRaw := getRawRLSnapshot(als, tr, hours)
			lookup := buildEnrichmentLookup(als)
			rlEvents := make([]Event, len(rlRaw))
			for i := range rlRaw {
				rlEvents[i] = enrichSingleRLE(&rlRaw[i], &lookup)
			}
			alsSummary := summarizeEvents(rlEvents)
			summary = mergeSummaryResponses(summary, alsSummary)
			cache.set(cacheKey, summary, gen, 30*time.Second)
			writeJSON(w, http.StatusOK, summary)
			return
		}

		wafSummary := store.FastSummary(hours)
		alsSummary := als.FastSummary(hours)
		summary := mergeSummaryResponses(wafSummary, alsSummary)

		// Post-Coraza: all blocks now come through the ALS (access log store).
		// The merged TotalBlocked from both stores is the correct value.
		// (Legacy code previously overrode with wafSummary.TotalBlocked only.)

		cache.set(cacheKey, summary, gen, 30*time.Second)
		writeJSON(w, http.StatusOK, summary)
	}
}

func handleEvents(store *Store, als *AccessLogStore) http.HandlerFunc {
	cache := newResponseCache(100)
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// Fast path: lookup a single event by ID (Caddy request UUID).
		// Events without a request UUID have empty IDs and won't match.
		if id := q.Get("id"); id != "" {
			if ev := store.EventByID(id); ev != nil {
				writeJSON(w, http.StatusOK, EventsResponse{Total: 1, Events: []Event{*ev}})
				return
			}
			// Not found — fall through to normal filter path so RL/ipsum events
			// can still be located via service+type+ip+time window.
		}

		// Check response cache — keyed on normalized query string, invalidated by
		// data generation changes (new events or evictions in either store).
		cacheKey := normalizeCacheKey(r.URL.RawQuery)
		gen := combinedGeneration(&store.generation, &als.generation)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		// Read filter params with operator support.
		serviceF := parseFieldFilter(q.Get("service"), q.Get("service_op"))
		clientF := parseFieldFilter(q.Get("client"), q.Get("client_op"))
		methodF := parseFieldFilter(q.Get("method"), q.Get("method_op"))
		eventTypeF := parseFieldFilter(q.Get("event_type"), q.Get("event_type_op"))
		ruleNameF := parseFieldFilter(q.Get("rule_name"), q.Get("rule_name_op"))
		uriF := parseFieldFilter(q.Get("uri"), q.Get("uri_op"))
		statusCodeF := parseFieldFilter(q.Get("status_code"), q.Get("status_code_op"))
		countryF := parseFieldFilter(q.Get("country"), q.Get("country_op"))
		requestIDF := parseFieldFilter(q.Get("request_id"), q.Get("request_id_op"))
		tagF := parseFieldFilter(q.Get("tag"), q.Get("tag_op"))
		blockedByF := parseFieldFilter(q.Get("blocked_by"), q.Get("blocked_by_op"))

		var blocked *bool
		if b := q.Get("blocked"); b != "" {
			val := strings.EqualFold(b, "true") || b == "1"
			blocked = &val
		}

		exportAll := strings.EqualFold(q.Get("export"), "true")
		limit := queryInt(q.Get("limit"), 50)
		if exportAll {
			if limit <= 0 || limit > 10000 {
				limit = 10000 // export mode: capped to prevent OOM on small containers
			}
		} else if limit <= 0 || limit > 1000 {
			limit = 50
		}
		offset := queryInt(q.Get("offset"), 0)
		if offset < 0 {
			offset = 0
		}

		tr := parseTimeRange(r)
		hours := parseHours(r)

		// Collect events from both sources, optimizing by event_type filter.
		needWAF, needRL := eventSourcesNeeded(eventTypeF)

		// WAF events: snapshot copy (typically smaller set — logged/detect events).
		var wafEvents []Event
		if needWAF {
			wafEvents = getWAFEvents(store, tr, hours)
		}

		// ALS events: raw snapshot WITHOUT enrichment. At 100K+ events this
		// avoids allocating a second []Event of equal size and running tag
		// lookups on every event. Only events that land in the result page
		// are enriched via enrichSingleRLE (deferred enrichment).
		//
		// When single-value "eq" filters are present for event_type, client_ip,
		// or service, use the secondary index to pre-filter at the store level.
		// This reduces the scan set from O(N) to O(matching events).
		var rlRaw []RateLimitEvent
		if needRL {
			idxEventType := eqFilterValue(eventTypeF)
			idxClient := eqFilterValue(clientF)
			idxService := eqFilterValue(serviceF)
			if !tr.Valid && (idxEventType != "" || idxClient != "" || idxService != "") {
				rlRaw = als.indexedRLSnapshot(idxEventType, idxClient, idxService, hours)
			} else {
				rlRaw = getRawRLSnapshot(als, tr, hours)
			}
		}

		// Build enrichment lookup tables once (cheap map builds from exclusion store).
		lookup := buildEnrichmentLookup(als)

		// matchesWAFFilters checks if a WAF Event passes all active filters.
		matchesWAFFilters := func(ev *Event) bool {
			if !serviceF.matchField(ev.Service) {
				return false
			}
			if !clientF.matchField(ev.ClientIP) {
				return false
			}
			if !methodF.matchField(ev.Method) {
				return false
			}
			if blocked != nil && ev.IsBlocked != *blocked {
				return false
			}
			if !eventTypeF.matchField(ev.EventType) {
				return false
			}
			if ruleNameF != nil && !matchesPolicyRuleNameFilter(ev, ruleNameF) {
				return false
			}
			if !uriF.matchField(ev.URI) {
				return false
			}
			if !statusCodeF.matchIntField(ev.ResponseStatus) {
				return false
			}
			if !countryF.matchField(ev.Country) {
				return false
			}
			if !requestIDF.matchField(ev.RequestID) {
				return false
			}
			if !tagF.matchTags(ev.Tags) {
				return false
			}
			if !blockedByF.matchField(ev.BlockedBy) {
				return false
			}
			return true
		}

		// matchesRLFilters checks if a raw RateLimitEvent passes all active
		// filters WITHOUT converting to Event first. This avoids the per-event
		// allocation cost of RateLimitEventToEvent for non-matching events.
		matchesRLFilters := func(rle *RateLimitEvent) bool {
			if !serviceF.matchField(rle.Service) {
				return false
			}
			if !clientF.matchField(rle.ClientIP) {
				return false
			}
			if !methodF.matchField(rle.Method) {
				return false
			}
			isBlocked := rleIsBlocked(rle.Source)
			if blocked != nil && isBlocked != *blocked {
				return false
			}
			if !eventTypeF.matchField(rleEventType(rle.Source)) {
				return false
			}
			// ruleNameF: check RuleName directly (before enrichment adds "Policy Block: " prefix).
			if ruleNameF != nil && !ruleNameF.matchField(rle.RuleName) {
				return false
			}
			if !uriF.matchField(rle.URI) {
				return false
			}
			if !statusCodeF.matchIntField(rleResponseStatus(rle)) {
				return false
			}
			if !countryF.matchField(rle.Country) {
				return false
			}
			if !requestIDF.matchField(rle.RequestID) {
				return false
			}
			if tagF != nil && !tagF.matchTags(rleTags(rle, &lookup)) {
				return false
			}
			if !blockedByF.matchField(rleBlockedBy(rle)) {
				return false
			}
			return true
		}

		// --- Streaming JSON export path ---
		// For export=true, stream events directly to the response writer to
		// avoid buffering 10K+ events in memory. The total is written as -1
		// (unknown) since we stream incrementally.
		if exportAll {
			ctx, cancel := context.WithTimeout(context.Background(), eventQueryTimeout)
			defer cancel()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"total":-1,"events":[`))

			enc := json.NewEncoder(w)
			enc.SetEscapeHTML(false)
			first := true
			emitted := 0
			wi, ri := len(wafEvents)-1, len(rlRaw)-1
			iterations := 0

			for (wi >= 0 || ri >= 0) && emitted < limit {
				iterations++
				if iterations%2000 == 0 {
					if ctx.Err() != nil {
						break
					}
				}
				useWAF := wi >= 0 && (ri < 0 || !wafEvents[wi].Timestamp.Before(rlRaw[ri].Timestamp))
				if useWAF {
					ev := &wafEvents[wi]
					wi--
					if !matchesWAFFilters(ev) {
						continue
					}
					if !first {
						w.Write([]byte(","))
					}
					enc.Encode(*ev)
					first = false
					emitted++
				} else {
					rle := &rlRaw[ri]
					ri--
					if !matchesRLFilters(rle) {
						continue
					}
					if !first {
						w.Write([]byte(","))
					}
					enc.Encode(enrichSingleRLE(rle, &lookup))
					first = false
					emitted++
				}
			}

			w.Write([]byte(`],"total_emitted":` + strconv.Itoa(emitted) + `}`))
			return
		}

		// --- Normal paginated path ---
		// Reverse-merge WAF events ([]Event) and ALS events ([]RateLimitEvent)
		// sorted by timestamp (newest first) with inline filtering and pagination.
		// Only events that land in the result page are enriched/converted.
		// Bounded by eventQueryTimeout to prevent runaway iteration on huge stores.
		ctx, cancel := context.WithTimeout(context.Background(), eventQueryTimeout)
		defer cancel()

		wi, ri := len(wafEvents)-1, len(rlRaw)-1
		filtered := make([]Event, 0, limit)
		matched := 0
		iterations := 0
		timedOut := false

		for wi >= 0 || ri >= 0 {
			iterations++
			// Check timeout every 2000 iterations to avoid syscall overhead.
			if iterations%2000 == 0 {
				if ctx.Err() != nil {
					timedOut = true
					break
				}
			}
			// Early exit: if we have a full page AND passed the offset window,
			// do a fast count-only pass to get the real total instead of returning -1.
			if len(filtered) >= limit && matched >= offset+limit {
				for wi >= 0 || ri >= 0 {
					iterations++
					if iterations%5000 == 0 {
						if ctx.Err() != nil {
							timedOut = true
							break
						}
					}
					useWAF := wi >= 0 && (ri < 0 || !wafEvents[wi].Timestamp.Before(rlRaw[ri].Timestamp))
					if useWAF {
						ev := &wafEvents[wi]
						wi--
						if matchesWAFFilters(ev) {
							matched++
						}
					} else {
						rle := &rlRaw[ri]
						ri--
						if matchesRLFilters(rle) {
							matched++
						}
					}
				}
				break
			}
			// Pick the newest event from either source.
			useWAF := wi >= 0 && (ri < 0 || !wafEvents[wi].Timestamp.Before(rlRaw[ri].Timestamp))

			if useWAF {
				ev := &wafEvents[wi]
				wi--
				if !matchesWAFFilters(ev) {
					continue
				}
				matched++
				if matched > offset && len(filtered) < limit {
					filtered = append(filtered, *ev)
				}
			} else {
				rle := &rlRaw[ri]
				ri--
				if !matchesRLFilters(rle) {
					continue
				}
				matched++
				if matched > offset && len(filtered) < limit {
					// Deferred enrichment: only convert events that land in the page.
					filtered = append(filtered, enrichSingleRLE(rle, &lookup))
				}
			}

		}

		resp := EventsResponse{Total: matched, Events: filtered}
		if timedOut {
			resp.Total = -1 // signal: results are partial due to timeout
		}
		cache.set(cacheKey, resp, gen, 5*time.Second)
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleServices(store *Store, als *AccessLogStore) http.HandlerFunc {
	cache := newResponseCache(20)
	return func(w http.ResponseWriter, r *http.Request) {
		gen := combinedGeneration(&store.generation, &als.generation)
		cacheKey := normalizeCacheKey(r.URL.RawQuery)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
		hours := parseHours(r)

		// Use FastSummary from both stores (O(buckets)) to build per-service counts.
		// This avoids the slow O(events) snapshot+enrich path for aggregate counters.
		wafSummary := store.FastSummary(hours)
		alsSummary := als.FastSummary(hours)
		merged := mergeSummaryResponses(wafSummary, alsSummary)

		// Compute per-service TopURIs/TopRules from WAF events (requires event-level data).
		wafServices := store.Services(hours)
		wafDetailMap := make(map[string]*ServiceDetail, len(wafServices.Services))
		for i := range wafServices.Services {
			wafDetailMap[wafServices.Services[i].Service] = &wafServices.Services[i]
		}

		// Build ServicesResponse from merged summary TopServices,
		// enriching with TopURIs/TopRules from WAF event data.
		// Fall back to AccessLogStore when the legacy WAF store has no data.
		const topN = 10
		var resp ServicesResponse
		for _, sd := range merged.TopServices {
			detail := ServiceDetail{
				Service:      sd.Service,
				Total:        sd.Count,
				TotalBlocked: sd.TotalBlocked,
				Logged:       sd.Logged,
				RateLimited:  sd.RateLimited,
				PolicyBlock:  sd.PolicyBlock,
				DetectBlock:  sd.DetectBlock,
				DDoSBlocked:  sd.DDoSBlocked,
				PolicyAllow:  sd.PolicyAllow,
				PolicySkip:   sd.PolicySkip,
			}
			if wd, ok := wafDetailMap[sd.Service]; ok && len(wd.TopURIs) > 0 {
				detail.TopURIs = wd.TopURIs
			}
			if wd, ok := wafDetailMap[sd.Service]; ok && len(wd.TopRules) > 0 {
				detail.TopRules = wd.TopRules
			}
			// Fall back to AccessLogStore for TopURIs/TopRules when
			// the legacy WAF store has no data (most events now flow
			// through the access log store).
			if len(detail.TopURIs) == 0 {
				detail.TopURIs = als.ServiceTopURIs(sd.Service, hours, topN)
			}
			if len(detail.TopRules) == 0 {
				detail.TopRules = als.ServiceTopRules(sd.Service, hours, topN)
			}
			resp.Services = append(resp.Services, detail)
		}

		cache.set(cacheKey, resp, gen, 30*time.Second)
		writeJSON(w, http.StatusOK, resp)
	}
}
