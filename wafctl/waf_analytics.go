package main

import (
	"sort"
	"time"
)

// --- Service Breakdown ---

// Services returns per-service breakdown.
func (s *Store) Services(hours int) ServicesResponse {
	return computeServices(s.SnapshotSince(hours))
}

func (s *Store) ServicesRange(start, end time.Time) ServicesResponse {
	return computeServices(s.SnapshotRange(start, end))
}

func computeServices(events []Event) ServicesResponse {
	type uriStats struct {
		count, totalBlocked int
	}
	type ruleKey struct {
		id  int
		msg string
	}
	type svcData struct {
		total, totalBlocked                               int
		policyBlock, detectBlock, policyAllow, policySkip int
		uris                                              map[string]*uriStats
		rules                                             map[ruleKey]int
	}
	m := make(map[string]*svcData)

	for i := range events {
		ev := &events[i]
		d, ok := m[ev.Service]
		if !ok {
			d = &svcData{
				uris:  make(map[string]*uriStats),
				rules: make(map[ruleKey]int),
			}
			m[ev.Service] = d
		}
		d.total++
		if ev.IsBlocked {
			d.totalBlocked++
		}
		switch ev.EventType {
		case "policy_block":
			d.policyBlock++
		case "detect_block":
			d.detectBlock++
		case "policy_allow":
			d.policyAllow++
		case "policy_skip":
			d.policySkip++
		}

		// Track per-service URI counts.
		if ev.URI != "" {
			us, ok := d.uris[ev.URI]
			if !ok {
				us = &uriStats{}
				d.uris[ev.URI] = us
			}
			us.count++
			if ev.IsBlocked {
				us.totalBlocked++
			}
		}

		// Track per-service rule counts from all matched rules.
		for _, mr := range ev.MatchedRules {
			if mr.ID > 0 {
				d.rules[ruleKey{id: mr.ID, msg: mr.Msg}]++
			}
		}
		// Fall back to primary rule if no matched rules.
		if len(ev.MatchedRules) == 0 && ev.RuleID > 0 {
			d.rules[ruleKey{id: ev.RuleID, msg: ev.RuleMsg}]++
		}
	}

	result := make([]ServiceDetail, 0, len(m))
	for svc, d := range m {
		sd := ServiceDetail{
			Service:      svc,
			Total:        d.total,
			TotalBlocked: d.totalBlocked,
			Logged:       d.total - d.totalBlocked,
			PolicyBlock:  d.policyBlock,
			DetectBlock:  d.detectBlock,
			PolicyAllow:  d.policyAllow,
			PolicySkip:   d.policySkip,
		}

		// Build top URIs.
		uriList := make([]ServiceURI, 0, len(d.uris))
		for uri, us := range d.uris {
			uriList = append(uriList, ServiceURI{URI: uri, Count: us.count, TotalBlocked: us.totalBlocked})
		}
		sort.Slice(uriList, func(i, j int) bool { return uriList[i].Count > uriList[j].Count })
		if len(uriList) > topNSummary {
			uriList = uriList[:topNSummary]
		}
		sd.TopURIs = uriList

		// Build top rules.
		ruleList := make([]ServiceRule, 0, len(d.rules))
		for rk, count := range d.rules {
			ruleList = append(ruleList, ServiceRule{RuleID: rk.id, RuleMsg: rk.msg, Count: count})
		}
		sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].Count > ruleList[j].Count })
		if len(ruleList) > topNSummary {
			ruleList = ruleList[:topNSummary]
		}
		sd.TopRules = ruleList

		result = append(result, sd)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Total > result[j].Total
	})

	return ServicesResponse{Services: result}
}

// --- IP Lookup ---

// IPLookup returns all events and stats for a specific IP address.
// IPLookupRange is a time-range-aware wrapper around IPLookup.
// When tr is valid, WAF events are filtered by absolute range; otherwise by hours.
func (s *Store) IPLookupRange(ip string, tr timeRange, hours, limit, offset int, extraEvents []Event) IPLookupResponse {
	var events []Event
	if tr.Valid {
		events = s.SnapshotRange(tr.Start, tr.End)
	} else {
		events = s.SnapshotSince(hours)
	}
	return s.ipLookupFromEvents(ip, events, limit, offset, extraEvents)
}

// IPLookupRangeRaw is like IPLookupRange but accepts raw []RateLimitEvent
// instead of pre-enriched []Event. Only matching events (for the target IP)
// are enriched, avoiding the O(N) enrichment cost of converting all 148K+
// ALS events. The lookup parameter provides tag resolution for enrichment.
func (s *Store) IPLookupRangeRaw(ip string, tr timeRange, hours, limit, offset int, rlRaw []RateLimitEvent, lookup *enrichmentLookup) IPLookupResponse {
	var events []Event
	if tr.Valid {
		events = s.SnapshotRange(tr.Start, tr.End)
	} else {
		events = s.SnapshotSince(hours)
	}
	return s.ipLookupFromEventsRaw(ip, events, limit, offset, rlRaw, lookup)
}

// IPLookup returns an IP lookup response using events from the last N hours.
// Retained for backward compatibility (CLI, tests).
func (s *Store) IPLookup(ip string, hours, limit, offset int, extraEvents []Event) IPLookupResponse {
	events := s.SnapshotSince(hours)
	return s.ipLookupFromEvents(ip, events, limit, offset, extraEvents)
}

func (s *Store) ipLookupFromEvents(ip string, events []Event, limit, offset int, extraEvents []Event) IPLookupResponse {

	// Collect WAF events matching this IP (newest-first).
	var matched []Event
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].ClientIP == ip {
			matched = append(matched, events[i])
		}
	}

	// Collect access log events (rate_limited, ipsum_blocked) matching this IP.
	var rlMatched []Event
	for i := len(extraEvents) - 1; i >= 0; i-- {
		if extraEvents[i].ClientIP == ip {
			rlMatched = append(rlMatched, extraEvents[i])
		}
	}

	return s.buildIPLookupResponse(ip, matched, rlMatched, limit, offset)
}

// ipLookupFromEventsRaw is like ipLookupFromEvents but filters raw
// RateLimitEvents by IP first, then enriches only the matches.
func (s *Store) ipLookupFromEventsRaw(ip string, events []Event, limit, offset int, rlRaw []RateLimitEvent, lookup *enrichmentLookup) IPLookupResponse {
	// Collect WAF events matching this IP (newest-first).
	var matched []Event
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].ClientIP == ip {
			matched = append(matched, events[i])
		}
	}

	// Filter raw RLE by IP first, then enrich only matching events.
	// This avoids enriching all 148K+ events when only a handful match.
	var rlMatched []Event
	for i := len(rlRaw) - 1; i >= 0; i-- {
		if rlRaw[i].ClientIP == ip {
			rlMatched = append(rlMatched, enrichSingleRLE(&rlRaw[i], lookup))
		}
	}

	return s.buildIPLookupResponse(ip, matched, rlMatched, limit, offset)
}

// buildIPLookupResponse constructs the response from pre-filtered WAF and RL
// event slices (both already newest-first, already filtered to the target IP).
func (s *Store) buildIPLookupResponse(ip string, matched, rlMatched []Event, limit, offset int) IPLookupResponse {
	// Reverse-merge into newest-first combined list.
	combined := make([]Event, 0, len(matched)+len(rlMatched))
	wi, ri := 0, 0
	for wi < len(matched) || ri < len(rlMatched) {
		if wi < len(matched) && (ri >= len(rlMatched) || !matched[wi].Timestamp.Before(rlMatched[ri].Timestamp)) {
			combined = append(combined, matched[wi])
			wi++
		} else {
			combined = append(combined, rlMatched[ri])
			ri++
		}
	}

	resp := IPLookupResponse{
		IP:          ip,
		Total:       len(combined),
		EventsTotal: len(combined),
	}

	// Compute per-service breakdown, hourly timeline, first/last seen, total blocked count.
	type counts struct {
		total, totalBlocked, logged, rateLimited          int
		policyBlock, detectBlock, policyAllow, policySkip int
	}
	svcMap := make(map[string]*counts)
	hourMap := make(map[string]*counts)

	for i := range combined {
		ev := &combined[i]
		if ev.IsBlocked {
			resp.TotalBlocked++
		}

		// First/last seen (combined is newest-first).
		if resp.LastSeen == nil {
			ts := ev.Timestamp
			resp.LastSeen = &ts
		}
		ts := ev.Timestamp
		resp.FirstSeen = &ts

		c, ok := svcMap[ev.Service]
		if !ok {
			c = &counts{}
			svcMap[ev.Service] = c
		}
		c.total++
		if ev.IsBlocked {
			c.totalBlocked++
		}

		// Per-hour bucketing for timeline.
		hk := ev.Timestamp.Truncate(time.Hour).Format(time.RFC3339)
		hc, ok := hourMap[hk]
		if !ok {
			hc = &counts{}
			hourMap[hk] = hc
		}
		hc.total++
		if ev.IsBlocked {
			hc.totalBlocked++
		}

		switch {
		case ev.EventType == "rate_limited":
			c.rateLimited++
			hc.rateLimited++
		case ev.EventType == "policy_block":
			c.policyBlock++
			hc.policyBlock++
		case ev.EventType == "detect_block":
			c.detectBlock++
			hc.detectBlock++
		case ev.EventType == "policy_allow":
			c.policyAllow++
			hc.policyAllow++
		case ev.EventType == "policy_skip":
			c.policySkip++
			hc.policySkip++
		case ev.EventType == "logged":
			c.logged++
			hc.logged++
		}
	}

	// Apply limit/offset pagination to the combined events slice.
	if offset >= len(combined) {
		resp.Events = []Event{}
	} else {
		end := offset + limit
		if end > len(combined) {
			end = len(combined)
		}
		resp.Events = combined[offset:end]
	}

	svcList := make([]ServiceDetail, 0, len(svcMap))
	for svc, c := range svcMap {
		svcList = append(svcList, ServiceDetail{
			Service:      svc,
			Total:        c.total,
			TotalBlocked: c.totalBlocked,
			Logged:       c.logged,
			PolicyBlock:  c.policyBlock,
			DetectBlock:  c.detectBlock,
			PolicyAllow:  c.policyAllow,
			PolicySkip:   c.policySkip,
			RateLimited:  c.rateLimited,
		})
	}
	sort.Slice(svcList, func(i, j int) bool {
		return svcList[i].Total > svcList[j].Total
	})
	resp.Services = svcList

	// Build sorted hourly timeline.
	hourCounts := make([]HourCount, 0, len(hourMap))
	for k, v := range hourMap {
		logged := v.total - v.totalBlocked - v.rateLimited - v.policyAllow - v.policySkip
		if logged < 0 {
			logged = 0
		}
		hourCounts = append(hourCounts, HourCount{
			Hour:         k,
			Count:        v.total,
			TotalBlocked: v.totalBlocked,
			Logged:       logged,
			RateLimited:  v.rateLimited,
			PolicyBlock:  v.policyBlock,
			DetectBlock:  v.detectBlock,
			PolicyAllow:  v.policyAllow,
			PolicySkip:   v.policySkip,
		})
	}
	sort.Slice(hourCounts, func(i, j int) bool {
		return hourCounts[i].Hour < hourCounts[j].Hour
	})
	resp.EventsByHour = hourCounts

	return resp
}

// --- Top Blocked IPs ---

// TopBlockedIPs returns the top N IPs by blocked count.
func (s *Store) TopBlockedIPs(hours, n int) []TopBlockedIP {
	return topBlockedIPs(s.SnapshotSince(hours), n)
}

// TopTargetedURIs returns the top N URIs by total event count.
func (s *Store) TopTargetedURIs(hours, n int) []TopTargetedURI {
	return topTargetedURIs(s.SnapshotSince(hours), n)
}

// topBlockedIPs aggregates the top N IPs by blocked count from a pre-filtered event slice.
func topBlockedIPs(events []Event, n int) []TopBlockedIP {
	type ipStats struct {
		total, totalBlocked int
		first, last         time.Time
		country             string
	}
	m := make(map[string]*ipStats)

	for i := range events {
		ev := &events[i]
		st, ok := m[ev.ClientIP]
		if !ok {
			st = &ipStats{first: ev.Timestamp, last: ev.Timestamp}
			m[ev.ClientIP] = st
		}
		st.total++
		if ev.IsBlocked {
			st.totalBlocked++
		}
		if ev.Timestamp.Before(st.first) {
			st.first = ev.Timestamp
		}
		if ev.Timestamp.After(st.last) {
			st.last = ev.Timestamp
		}
		if st.country == "" && ev.Country != "" {
			st.country = ev.Country
		}
	}

	result := make([]TopBlockedIP, 0, len(m))
	for ip, st := range m {
		if st.totalBlocked == 0 {
			continue // only include IPs that have at least one block
		}
		rate := 0.0
		if st.total > 0 {
			rate = float64(st.totalBlocked) / float64(st.total) * 100
		}
		result = append(result, TopBlockedIP{
			ClientIP:     ip,
			Country:      st.country,
			Total:        st.total,
			TotalBlocked: st.totalBlocked,
			BlockRate:    rate,
			FirstSeen:    st.first.Format(time.RFC3339),
			LastSeen:     st.last.Format(time.RFC3339),
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalBlocked > result[j].TotalBlocked
	})
	if len(result) > n {
		result = result[:n]
	}
	return result
}

// topTargetedURIs aggregates the top N URIs by total event count from a pre-filtered event slice.
func topTargetedURIs(events []Event, n int) []TopTargetedURI {
	type uriStats struct {
		total, totalBlocked int
		services            map[string]bool
	}
	m := make(map[string]*uriStats)

	for i := range events {
		ev := &events[i]
		st, ok := m[ev.URI]
		if !ok {
			st = &uriStats{services: make(map[string]bool)}
			m[ev.URI] = st
		}
		st.total++
		if ev.IsBlocked {
			st.totalBlocked++
		}
		if ev.Service != "" {
			st.services[ev.Service] = true
		}
	}

	result := make([]TopTargetedURI, 0, len(m))
	for uri, st := range m {
		svcs := make([]string, 0, len(st.services))
		for svc := range st.services {
			svcs = append(svcs, svc)
		}
		sort.Strings(svcs)
		result = append(result, TopTargetedURI{
			URI:          uri,
			Total:        st.total,
			TotalBlocked: st.totalBlocked,
			Services:     svcs,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Total > result[j].Total
	})
	if len(result) > n {
		result = result[:n]
	}
	return result
}

// ─── Mixed-type analytics (deferred enrichment) ────────────────────
//
// These variants operate on WAF []Event + raw []RateLimitEvent to avoid
// the O(N) enrichment cost of converting all ALS events to Events.

// topBlockedIPsMixed computes top blocked IPs from WAF events and raw ALS events.
func topBlockedIPsMixed(wafEvents []Event, rlRaw []RateLimitEvent, n int) []TopBlockedIP {
	type ipStats struct {
		total, totalBlocked int
		first, last         time.Time
		country             string
	}
	m := make(map[string]*ipStats)

	recordIP := func(ip, country string, blocked bool, ts time.Time) {
		st, ok := m[ip]
		if !ok {
			st = &ipStats{first: ts, last: ts}
			m[ip] = st
		}
		st.total++
		if blocked {
			st.totalBlocked++
		}
		if ts.Before(st.first) {
			st.first = ts
		}
		if ts.After(st.last) {
			st.last = ts
		}
		if st.country == "" && country != "" {
			st.country = country
		}
	}

	for i := range wafEvents {
		ev := &wafEvents[i]
		recordIP(ev.ClientIP, ev.Country, ev.IsBlocked, ev.Timestamp)
	}
	for i := range rlRaw {
		rle := &rlRaw[i]
		recordIP(rle.ClientIP, rle.Country, rleIsBlocked(rle.Source), rle.Timestamp)
	}

	result := make([]TopBlockedIP, 0, len(m))
	for ip, st := range m {
		if st.totalBlocked == 0 {
			continue
		}
		rate := 0.0
		if st.total > 0 {
			rate = float64(st.totalBlocked) / float64(st.total) * 100
		}
		result = append(result, TopBlockedIP{
			ClientIP:     ip,
			Country:      st.country,
			Total:        st.total,
			TotalBlocked: st.totalBlocked,
			BlockRate:    rate,
			FirstSeen:    st.first.Format(time.RFC3339),
			LastSeen:     st.last.Format(time.RFC3339),
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalBlocked > result[j].TotalBlocked
	})
	if len(result) > n {
		result = result[:n]
	}
	return result
}

// topTargetedURIsMixed computes top targeted URIs from WAF events and raw ALS events.
func topTargetedURIsMixed(wafEvents []Event, rlRaw []RateLimitEvent, n int) []TopTargetedURI {
	type uriStats struct {
		total, totalBlocked int
		services            map[string]bool
	}
	m := make(map[string]*uriStats)

	recordURI := func(uri, service string, blocked bool) {
		st, ok := m[uri]
		if !ok {
			st = &uriStats{services: make(map[string]bool)}
			m[uri] = st
		}
		st.total++
		if blocked {
			st.totalBlocked++
		}
		if service != "" {
			st.services[service] = true
		}
	}

	for i := range wafEvents {
		ev := &wafEvents[i]
		recordURI(ev.URI, ev.Service, ev.IsBlocked)
	}
	for i := range rlRaw {
		rle := &rlRaw[i]
		recordURI(rle.URI, rle.Service, rleIsBlocked(rle.Source))
	}

	result := make([]TopTargetedURI, 0, len(m))
	for uri, st := range m {
		svcs := make([]string, 0, len(st.services))
		for svc := range st.services {
			svcs = append(svcs, svc)
		}
		sort.Strings(svcs)
		result = append(result, TopTargetedURI{
			URI:          uri,
			Total:        st.total,
			TotalBlocked: st.totalBlocked,
			Services:     svcs,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Total > result[j].Total
	})
	if len(result) > n {
		result = result[:n]
	}
	return result
}

// topCountriesMixed computes top countries from WAF events and raw ALS events.
// Used as fallback for absolute time range queries where FastSummary isn't available.
func topCountriesMixed(wafEvents []Event, rlRaw []RateLimitEvent, n int) []CountryCount {
	counts := make(map[string]*CountryCount)

	recordCountry := func(cc string, blocked bool) {
		if cc == "" {
			cc = "XX"
		}
		entry, ok := counts[cc]
		if !ok {
			entry = &CountryCount{Country: cc}
			counts[cc] = entry
		}
		entry.Count++
		if blocked {
			entry.TotalBlocked++
		}
	}

	for i := range wafEvents {
		recordCountry(wafEvents[i].Country, wafEvents[i].IsBlocked)
	}
	for i := range rlRaw {
		recordCountry(rlRaw[i].Country, rleIsBlocked(rlRaw[i].Source))
	}

	result := make([]CountryCount, 0, len(counts))
	for _, v := range counts {
		result = append(result, *v)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	if n > 0 && len(result) > n {
		result = result[:n]
	}
	return result
}
