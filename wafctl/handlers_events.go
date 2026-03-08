package main

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// --- Handlers: Health, Summary, Events, Services ---

func handleHealth(store *Store, als *AccessLogStore, gls *GeneralLogStore, geoStore *GeoIPStore, exclusionStore *ExclusionStore, blocklistStore *BlocklistStore, cfProxyStore *CFProxyStore, cspStore *CSPStore) http.HandlerFunc {
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
			"blocklist": blocklistStore.Stats(),
			"cfproxy":   cfProxyStore.Stats(),
			"csp":       cspStore.StoreInfo(),
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
	cache := newResponseCache(50)
	return func(w http.ResponseWriter, r *http.Request) {
		tr := parseTimeRange(r)
		hours := parseHours(r)
		q := r.URL.Query()

		// Check response cache — keyed on the raw query string, invalidated by
		// data generation changes (new events or evictions in either store).
		cacheKey := r.URL.RawQuery
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

		hasFilter := serviceF != nil || clientF != nil || methodF != nil || eventTypeF != nil || ruleNameF != nil ||
			uriF != nil || statusCodeF != nil || countryF != nil || requestIDF != nil

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
				if !requestIDF.matchField(ev.RequestID) {
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
			cache.set(cacheKey, summary, gen, 3*time.Second)
			writeJSON(w, http.StatusOK, summary)
			return
		}

		var sr summaryResult
		if tr.Valid {
			sr = summarizeEventsWithSets(store.SnapshotRange(tr.Start, tr.End))
		} else {
			sr = summarizeEventsWithSets(store.SnapshotSince(hours))
		}
		summary := sr.SummaryResponse

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

		// Merge unique clients/services (union of WAF + RL) using the sets
		// already computed by summarizeEventsWithSets — no re-fetch needed.
		if len(rlClients) > 0 || len(rlServices) > 0 {
			for c := range rlClients {
				sr.clientSet[c] = struct{}{}
			}
			for svc := range rlServices {
				sr.serviceSet[svc] = struct{}{}
			}
			summary.UniqueClients = len(sr.clientSet)
			summary.UniqueServices = len(sr.serviceSet)
		}

		// Merge RL events into recent_events, re-sort newest-first.
		summary.RecentEvents = append(summary.RecentEvents, rlEvents...)
		sort.Slice(summary.RecentEvents, func(i, j int) bool {
			return summary.RecentEvents[i].Timestamp.After(summary.RecentEvents[j].Timestamp)
		})
		if len(summary.RecentEvents) > topNSummary {
			summary.RecentEvents = summary.RecentEvents[:topNSummary]
		}

		cache.set(cacheKey, summary, gen, 3*time.Second)
		writeJSON(w, http.StatusOK, summary)
	}
}

func handleEvents(store *Store, als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// Fast path: lookup a single event by ID (WAF events have persistent UUIDs;
		// access log events use ephemeral IDs so they won't match here — the caller
		// should also pass filters as fallback).
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
		// Collect events from both sources (already in chronological order).
		var wafEvents, rlEvts []Event
		if needWAF {
			wafEvents = getWAFEvents(store, tr, hours)
		}
		if needRL {
			rlEvts = getRLEvents(als, tr, hours)
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
			if !statusCodeF.matchField(strconv.Itoa(ev.ResponseStatus)) {
				return false
			}
			if !countryF.matchField(ev.Country) {
				return false
			}
			if !requestIDF.matchField(ev.RequestID) {
				return false
			}
			return true
		}

		// Reverse-merge two chronologically sorted slices (newest first)
		// with inline filtering and early-exit pagination.
		// For export mode we need the total count, so we can't early-exit.
		wi, ri := len(wafEvents)-1, len(rlEvts)-1
		filtered := make([]Event, 0)
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
			// For non-export: once we have a full page AND enough to know
			// the total would require scanning everything anyway for total count.
			// We must continue to get accurate total, so no early-exit here.
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
		cacheKey := r.URL.RawQuery
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

		cache.set(cacheKey, resp, gen, 3*time.Second)
		writeJSON(w, http.StatusOK, resp)
	}
}
