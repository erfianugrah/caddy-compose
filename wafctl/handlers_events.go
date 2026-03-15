package main

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

// --- Handlers: Health, Summary, Events, Services ---

func handleHealth(store *Store, als *AccessLogStore, gls *GeneralLogStore, geoStore *GeoIPStore, exclusionStore *ExclusionStore, blocklistStore *BlocklistStore, cfProxyStore *CFProxyStore, cspStore *CSPStore, secStore *SecurityHeaderStore, ds *DefaultRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		uptime := time.Since(startTime).Truncate(time.Second)

		stores := map[string]any{
			"waf_events":    store.Stats(),
			"access_events": als.Stats(),
			"general_logs":  gls.Stats(),
			"geoip": map[string]any{
				"mmdb_loaded": geoStore.HasDB(),
				"api_enabled": geoStore.HasAPI(),
			},
			"exclusions": map[string]any{
				"count": len(exclusionStore.List()),
			},
			"blocklist":        blocklistStore.Stats(),
			"cfproxy":          cfProxyStore.Stats(),
			"csp":              cspStore.StoreInfo(),
			"security_headers": secStore.StoreInfo(),
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

		// When any filter is active, collect all events, apply filters, then
		// summarize — this is the general-purpose filtered path.
		if hasFilter {
			var allEvents []Event
			// Optimization: skip event sources that can't match the event_type filter.
			needWAF, needRL := eventSourcesNeeded(eventTypeF)
			if needWAF {
				allEvents = append(allEvents, getWAFEvents(store, tr, hours)...)
			}
			if needRL {
				allEvents = append(allEvents, getRLEvents(als, tr, hours, nil)...)
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
				if !statusCodeF.matchIntField(ev.ResponseStatus) {
					continue
				}
				if !countryF.matchField(ev.Country) {
					continue
				}
				if !requestIDF.matchField(ev.RequestID) {
					continue
				}
				if !tagF.matchTags(ev.Tags) {
					continue
				}
				if !blockedByF.matchField(ev.BlockedBy) {
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
			cache.set(cacheKey, summary, gen, 10*time.Second)
			writeJSON(w, http.StatusOK, summary)
			return
		}

		// Fast path: use incremental per-hour counters from both stores
		// and merge their summaries. O(buckets) instead of O(events).
		// The time-range path falls back to the full-scan approach since
		// counters only support hour-granularity filtering.
		if tr.Valid {
			// Absolute time range: fall back to full-scan merge.
			sr := summarizeEventsWithSets(store.SnapshotRange(tr.Start, tr.End))
			summary := sr.SummaryResponse
			alsEvents := getRLEvents(als, tr, hours, nil)
			alsSummary := summarizeEvents(alsEvents)
			summary = mergeSummaryResponses(summary, alsSummary)
			cache.set(cacheKey, summary, gen, 10*time.Second)
			writeJSON(w, http.StatusOK, summary)
			return
		}

		wafSummary := store.FastSummary(hours)
		alsSummary := als.FastSummary(hours)
		summary := mergeSummaryResponses(wafSummary, alsSummary)

		// Preserve backward compatibility: TotalBlocked counts only WAF-store
		// blocked events. ALS policy blocks are tracked separately in
		// PolicyBlocked/DetectBlocked. The old merge path did not add ALS
		// blocked counts to TotalBlocked.
		summary.TotalBlocked = wafSummary.TotalBlocked

		cache.set(cacheKey, summary, gen, 30*time.Second)
		writeJSON(w, http.StatusOK, summary)
	}
}

func handleEvents(store *Store, als *AccessLogStore) http.HandlerFunc {
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
		// Collect events from both sources (already in chronological order).
		var wafEvents, rlEvts []Event
		if needWAF {
			wafEvents = getWAFEvents(store, tr, hours)
		}
		if needRL {
			rlEvts = getRLEvents(als, tr, hours, nil)
		}

		// eventMatchesFilters checks if an event passes all active filters.
		matchesFilters := func(ev *Event) bool {
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

		// Reverse-merge two chronologically sorted slices (newest first)
		// with inline filtering and pagination.
		wi, ri := len(wafEvents)-1, len(rlEvts)-1
		filtered := make([]Event, 0, limit)
		matched := 0

		for wi >= 0 || ri >= 0 {
			var ev *Event
			if wi >= 0 && (ri < 0 || !wafEvents[wi].Timestamp.Before(rlEvts[ri].Timestamp)) {
				ev = &wafEvents[wi]
				wi--
			} else {
				ev = &rlEvts[ri]
				ri--
			}

			if !matchesFilters(ev) {
				continue
			}

			matched++
			if matched > offset && len(filtered) < limit {
				filtered = append(filtered, *ev)
			}
			// Early-exit for non-export: once we have a full page and are past
			// the offset window, stop scanning. Return total=-1 to signal
			// that more results exist but the exact count is unknown.
			if !exportAll && len(filtered) >= limit && matched >= offset+limit {
				// Check if there are more events to determine hasMore.
				hasMore := wi >= 0 || ri >= 0
				total := matched
				if hasMore {
					total = -1 // signal: more results exist
				}
				writeJSON(w, http.StatusOK, EventsResponse{
					Total:  total,
					Events: filtered,
				})
				return
			}
		}

		writeJSON(w, http.StatusOK, EventsResponse{
			Total:  matched,
			Events: filtered,
		})
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
		tr := parseTimeRange(r)
		hours := parseHours(r)

		var resp ServicesResponse
		if tr.Valid {
			resp = store.ServicesRange(tr.Start, tr.End)
		} else {
			resp = store.Services(hours)
		}

		// Merge access-log events (rate-limited and policy blocks) into service breakdown.
		rlEvents := getRLEvents(als, tr, hours, nil)
		type svcCounts struct {
			rl, policyBlock, detectBlock int
		}
		alsSvcMap := make(map[string]*svcCounts)
		for i := range rlEvents {
			ev := &rlEvents[i]
			sc, ok := alsSvcMap[ev.Service]
			if !ok {
				sc = &svcCounts{}
				alsSvcMap[ev.Service] = sc
			}
			switch ev.EventType {
			case "policy_block":
				sc.policyBlock++
			case "detect_block":
				sc.detectBlock++
			default:
				sc.rl++
			}
		}

		existingSvcs := make(map[string]int)
		for i, sd := range resp.Services {
			existingSvcs[sd.Service] = i
		}
		for svc, sc := range alsSvcMap {
			total := sc.rl + sc.policyBlock + sc.detectBlock
			if idx, ok := existingSvcs[svc]; ok {
				resp.Services[idx].RateLimited += sc.rl
				resp.Services[idx].PolicyBlock += sc.policyBlock
				resp.Services[idx].DetectBlock += sc.detectBlock
				resp.Services[idx].Total += total
			} else {
				resp.Services = append(resp.Services, ServiceDetail{
					Service:     svc,
					Total:       total,
					RateLimited: sc.rl,
					PolicyBlock: sc.policyBlock,
					DetectBlock: sc.detectBlock,
				})
				existingSvcs[svc] = len(resp.Services) - 1
			}
		}

		// Re-sort by total desc.
		sort.Slice(resp.Services, func(i, j int) bool {
			return resp.Services[i].Total > resp.Services[j].Total
		})

		cache.set(cacheKey, resp, gen, 10*time.Second)
		writeJSON(w, http.StatusOK, resp)
	}
}
