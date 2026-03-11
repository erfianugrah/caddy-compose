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
		count, blocked int
	}
	type ruleKey struct {
		id  int
		msg string
	}
	type svcData struct {
		total, blocked                       int
		policyBlock, policyAllow, policySkip int
		uris                                 map[string]*uriStats
		rules                                map[ruleKey]int
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
			d.blocked++
		}
		switch ev.EventType {
		case "policy_block", "detect_block":
			d.policyBlock++
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
				us.blocked++
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
			Service:     svc,
			Total:       d.total,
			Blocked:     d.blocked,
			Logged:      d.total - d.blocked,
			PolicyBlock: d.policyBlock,
			PolicyAllow: d.policyAllow,
			PolicySkip:  d.policySkip,
		}

		// Build top URIs.
		uriList := make([]ServiceURI, 0, len(d.uris))
		for uri, us := range d.uris {
			uriList = append(uriList, ServiceURI{URI: uri, Count: us.count, Blocked: us.blocked})
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

	// Compute per-service breakdown, hourly timeline, first/last seen, blocked count.
	type counts struct {
		total, blocked, logged, rateLimited  int
		policyBlock, policyAllow, policySkip int
	}
	svcMap := make(map[string]*counts)
	hourMap := make(map[string]*counts)

	for i := range combined {
		ev := &combined[i]
		if ev.IsBlocked {
			resp.Blocked++
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
			c.blocked++
		}

		// Per-hour bucketing for timeline.
		hourKey := ev.Timestamp.Truncate(time.Hour).Format(time.RFC3339)
		hc, ok := hourMap[hourKey]
		if !ok {
			hc = &counts{}
			hourMap[hourKey] = hc
		}
		hc.total++
		if ev.IsBlocked {
			hc.blocked++
		}

		switch {
		case ev.EventType == "rate_limited":
			c.rateLimited++
			hc.rateLimited++
		case ev.EventType == "policy_block" || ev.EventType == "detect_block":
			c.policyBlock++
			hc.policyBlock++
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
			Service:     svc,
			Total:       c.total,
			Blocked:     c.blocked,
			Logged:      c.logged,
			PolicyBlock: c.policyBlock,
			PolicyAllow: c.policyAllow,
			PolicySkip:  c.policySkip,
			RateLimited: c.rateLimited,
		})
	}
	sort.Slice(svcList, func(i, j int) bool {
		return svcList[i].Total > svcList[j].Total
	})
	resp.Services = svcList

	// Build sorted hourly timeline.
	hourCounts := make([]HourCount, 0, len(hourMap))
	for k, v := range hourMap {
		logged := v.total - v.blocked - v.rateLimited - v.policyBlock - v.policyAllow - v.policySkip
		if logged < 0 {
			logged = 0
		}
		hourCounts = append(hourCounts, HourCount{
			Hour:        k,
			Count:       v.total,
			Blocked:     v.blocked,
			Logged:      logged,
			RateLimited: v.rateLimited,
			PolicyBlock: v.policyBlock,
			PolicyAllow: v.policyAllow,
			PolicySkip:  v.policySkip,
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
		total, blocked int
		first, last    time.Time
		country        string
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
			st.blocked++
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
		if st.blocked == 0 {
			continue // only include IPs that have at least one block
		}
		rate := 0.0
		if st.total > 0 {
			rate = float64(st.blocked) / float64(st.total) * 100
		}
		result = append(result, TopBlockedIP{
			ClientIP:  ip,
			Country:   st.country,
			Total:     st.total,
			Blocked:   st.blocked,
			BlockRate: rate,
			FirstSeen: st.first.Format(time.RFC3339),
			LastSeen:  st.last.Format(time.RFC3339),
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Blocked > result[j].Blocked
	})
	if len(result) > n {
		result = result[:n]
	}
	return result
}

// topTargetedURIs aggregates the top N URIs by total event count from a pre-filtered event slice.
func topTargetedURIs(events []Event, n int) []TopTargetedURI {
	type uriStats struct {
		total, blocked int
		services       map[string]bool
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
			st.blocked++
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
			URI:      uri,
			Total:    st.total,
			Blocked:  st.blocked,
			Services: svcs,
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
