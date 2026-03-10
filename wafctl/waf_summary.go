package main

import (
	"sort"
	"strings"
	"time"
)

// summaryResult bundles the SummaryResponse with internal sets needed for
// efficient merging (avoids re-fetching WAF events just for unique counts).
type summaryResult struct {
	SummaryResponse
	clientSet  map[string]struct{}
	serviceSet map[string]struct{}
}

// summarizeEvents computes aggregate stats from a slice of events.
func summarizeEvents(events []Event) SummaryResponse {
	return summarizeEventsWithSets(events).SummaryResponse
}

// summarizeEventsWithSets computes aggregate stats and also returns the
// unique client/service sets for efficient merging with RL events.
func summarizeEventsWithSets(events []Event) summaryResult {
	var totalBlocked, totalLogged, totalRateLimited int
	var totalPolicyBlock, totalPolicyAllow, totalPolicySkip int

	// Per-hour breakdown with action type counters.
	type hourStats struct {
		total, blocked, rateLimited          int
		policyBlock, policyAllow, policySkip int
	}
	hourMap := make(map[string]*hourStats)

	// Per-service breakdown with action type counters.
	type svcStats struct {
		total, blocked, rateLimited          int
		policyBlock, policyAllow, policySkip int
	}
	svcMap := make(map[string]*svcStats)

	// Per-client breakdown with action type counters.
	type clientStats struct {
		total, blocked, rateLimited          int
		policyBlock, policyAllow, policySkip int
		country                              string
	}
	clientMap := make(map[string]*clientStats)

	uris := make(map[string]int)

	// Per-tag breakdown — counts how many events carry each tag.
	tagMap := make(map[string]int)

	// Per-country breakdown (folded into main loop to avoid second full scan).
	countryMap := make(map[string]*CountryCount)

	// Collect recent events of all types (newest first, up to 10).
	var recentEvents []Event

	for i := len(events) - 1; i >= 0; i-- {
		ev := &events[i]
		switch {
		case ev.EventType == "rate_limited":
			totalRateLimited++
		case ev.EventType == "policy_block":
			totalPolicyBlock++
			// policy_block events are also blocked
			if ev.IsBlocked {
				totalBlocked++
			}
		case ev.EventType == "policy_allow":
			totalPolicyAllow++
		case ev.EventType == "policy_skip":
			totalPolicySkip++
		case ev.IsBlocked:
			totalBlocked++
		default:
			totalLogged++
		}
		if len(recentEvents) < 10 {
			recentEvents = append(recentEvents, *ev)
		}

		// Per-hour.
		hourKey := ev.Timestamp.Truncate(time.Hour).Format(time.RFC3339)
		hs, ok := hourMap[hourKey]
		if !ok {
			hs = &hourStats{}
			hourMap[hourKey] = hs
		}
		hs.total++
		switch {
		case ev.EventType == "rate_limited":
			hs.rateLimited++
		case ev.EventType == "policy_block":
			hs.policyBlock++
		case ev.EventType == "policy_allow":
			hs.policyAllow++
		case ev.EventType == "policy_skip":
			hs.policySkip++
		case ev.IsBlocked:
			hs.blocked++
		}

		// Per-service.
		ss, ok := svcMap[ev.Service]
		if !ok {
			ss = &svcStats{}
			svcMap[ev.Service] = ss
		}
		ss.total++
		switch {
		case ev.EventType == "rate_limited":
			ss.rateLimited++
		case ev.EventType == "policy_block":
			ss.policyBlock++
		case ev.EventType == "policy_allow":
			ss.policyAllow++
		case ev.EventType == "policy_skip":
			ss.policySkip++
		case ev.IsBlocked:
			ss.blocked++
		}

		// Per-client.
		cs, ok := clientMap[ev.ClientIP]
		if !ok {
			cs = &clientStats{}
			clientMap[ev.ClientIP] = cs
		}
		cs.total++
		switch {
		case ev.EventType == "rate_limited":
			cs.rateLimited++
		case ev.EventType == "policy_block":
			cs.policyBlock++
		case ev.EventType == "policy_allow":
			cs.policyAllow++
		case ev.EventType == "policy_skip":
			cs.policySkip++
		case ev.IsBlocked:
			cs.blocked++
		}
		if cs.country == "" && ev.Country != "" {
			cs.country = ev.Country
		}

		uris[ev.URI]++

		// Per-tag.
		for _, tag := range ev.Tags {
			tagMap[tag]++
		}

		// Per-country (avoids second full scan via TopCountries).
		cc := ev.Country
		if cc == "" {
			cc = "XX"
		}
		entry, ok := countryMap[cc]
		if !ok {
			entry = &CountryCount{Country: cc}
			countryMap[cc] = entry
		}
		entry.Count++
		if ev.IsBlocked {
			entry.Blocked++
		}
	}

	// Build sorted country counts from the inline map.
	countryCounts := make([]CountryCount, 0, len(countryMap))
	for _, v := range countryMap {
		countryCounts = append(countryCounts, *v)
	}
	sort.Slice(countryCounts, func(i, j int) bool {
		return countryCounts[i].Count > countryCounts[j].Count
	})
	if len(countryCounts) > topNAnalytics {
		countryCounts = countryCounts[:topNAnalytics]
	}

	// Build sorted hour buckets.
	// logged = total - blocked - rateLimited - policyBlock - policyAllow - policySkip
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

	// Build service counts (for top_services).
	svcCounts := make([]ServiceCount, 0, len(svcMap))
	for k, v := range svcMap {
		policyTotal := v.policyBlock + v.policyAllow + v.policySkip
		logged := v.total - v.blocked - v.rateLimited - policyTotal
		if logged < 0 {
			logged = 0
		}
		svcCounts = append(svcCounts, ServiceCount{
			Service:     k,
			Count:       v.total,
			Blocked:     v.blocked,
			Logged:      logged,
			RateLimited: v.rateLimited,
			PolicyBlock: v.policyBlock,
			PolicyAllow: v.policyAllow,
			PolicySkip:  v.policySkip,
		})
	}
	sort.Slice(svcCounts, func(i, j int) bool {
		return svcCounts[i].Count > svcCounts[j].Count
	})
	if len(svcCounts) > topNAnalytics {
		svcCounts = svcCounts[:topNAnalytics]
	}

	// Build service breakdown (same data, different type for convenience).
	svcBreakdown := make([]ServiceDetail, 0, len(svcMap))
	for k, v := range svcMap {
		policyTotal := v.policyBlock + v.policyAllow + v.policySkip
		svcLogged := v.total - v.blocked - v.rateLimited - policyTotal
		if svcLogged < 0 {
			svcLogged = 0
		}
		svcBreakdown = append(svcBreakdown, ServiceDetail{
			Service:     k,
			Total:       v.total,
			Blocked:     v.blocked,
			Logged:      svcLogged,
			RateLimited: v.rateLimited,
			PolicyBlock: v.policyBlock,
			PolicyAllow: v.policyAllow,
			PolicySkip:  v.policySkip,
		})
	}
	sort.Slice(svcBreakdown, func(i, j int) bool {
		return svcBreakdown[i].Total > svcBreakdown[j].Total
	})

	// Build client counts.
	clientCounts := make([]ClientCount, 0, len(clientMap))
	for k, v := range clientMap {
		clientCounts = append(clientCounts, ClientCount{
			Client:      k,
			Country:     v.country,
			Count:       v.total,
			Blocked:     v.blocked,
			RateLimited: v.rateLimited,
			PolicyBlock: v.policyBlock,
			PolicyAllow: v.policyAllow,
			PolicySkip:  v.policySkip,
		})
	}
	sort.Slice(clientCounts, func(i, j int) bool {
		return clientCounts[i].Count > clientCounts[j].Count
	})
	if len(clientCounts) > topNAnalytics {
		clientCounts = clientCounts[:topNAnalytics]
	}

	// Build unique sets for efficient merging with RL events.
	cSet := make(map[string]struct{}, len(clientMap))
	for k := range clientMap {
		cSet[k] = struct{}{}
	}
	sSet := make(map[string]struct{}, len(svcMap))
	for k := range svcMap {
		sSet[k] = struct{}{}
	}

	// Build sorted tag counts.
	tagCounts := make([]TagCount, 0, len(tagMap))
	for tag, count := range tagMap {
		tagCounts = append(tagCounts, TagCount{Tag: tag, Count: count})
	}
	sort.Slice(tagCounts, func(i, j int) bool {
		if tagCounts[i].Count != tagCounts[j].Count {
			return tagCounts[i].Count > tagCounts[j].Count
		}
		return tagCounts[i].Tag < tagCounts[j].Tag
	})

	totalPolicy := totalPolicyBlock + totalPolicyAllow + totalPolicySkip
	return summaryResult{
		SummaryResponse: SummaryResponse{
			TotalEvents:      len(events),
			BlockedEvents:    totalBlocked,
			LoggedEvents:     totalLogged,
			RateLimited:      totalRateLimited,
			PolicyEvents:     totalPolicy,
			PolicyBlocked:    totalPolicyBlock,
			PolicyAllowed:    totalPolicyAllow,
			PolicySkipped:    totalPolicySkip,
			UniqueClients:    len(clientMap),
			UniqueServices:   len(svcMap),
			TagCounts:        tagCounts,
			EventsByHour:     hourCounts,
			TopServices:      svcCounts,
			TopClients:       clientCounts,
			TopCountries:     countryCounts,
			TopURIs:          topN(uris, topNAnalytics, func(k string, c int) URICount { return URICount{k, c} }),
			ServiceBreakdown: svcBreakdown,
			RecentEvents:     recentEvents,
		},
		clientSet:  cSet,
		serviceSet: sSet,
	}
}

// FilteredEvents returns events matching the given filters, with pagination.
func (s *Store) FilteredEvents(service, client, method string, blocked *bool, limit, offset, hours int) EventsResponse {
	events := s.SnapshotSince(hours)

	// Iterate in reverse chronological order (newest first).
	// Events are appended chronologically, so reverse.
	var filtered []Event
	for i := len(events) - 1; i >= 0; i-- {
		ev := &events[i]
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

	return EventsResponse{
		Total:  total,
		Events: page,
	}
}
