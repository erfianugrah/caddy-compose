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
	var totalBlocked, totalLogged, totalPolicy, totalHoneypot, totalScanner int
	var totalRateLimited, totalIpsumBlocked int

	// Per-hour breakdown with action type counters.
	type hourStats struct {
		total, blocked, honeypot, scanner, policy, rateLimited, ipsumBlocked int
	}
	hourMap := make(map[string]*hourStats)

	// Per-service breakdown with action type counters.
	type svcStats struct {
		total, blocked, honeypot, scanner, policy, rateLimited, ipsumBlocked int
	}
	svcMap := make(map[string]*svcStats)

	// Per-client breakdown with action type counters.
	type clientStats struct {
		total, blocked, honeypot, scanner, policy, rateLimited, ipsumBlocked int
		country                                                              string
	}
	clientMap := make(map[string]*clientStats)

	uris := make(map[string]int)

	// Per-country breakdown (folded into main loop to avoid second full scan).
	countryMap := make(map[string]*CountryCount)

	// Collect recent events of all types (newest first, up to 10).
	var recentEvents []Event

	for i := len(events) - 1; i >= 0; i-- {
		ev := &events[i]
		switch {
		case ev.EventType == "rate_limited":
			totalRateLimited++
		case ev.EventType == "ipsum_blocked":
			totalIpsumBlocked++
		case strings.HasPrefix(ev.EventType, "policy_"):
			totalPolicy++
			// policy_block events are also blocked
			if ev.IsBlocked {
				totalBlocked++
			}
		case ev.EventType == "honeypot":
			totalHoneypot++
			totalBlocked++ // honeypot hits are always denied
		case ev.EventType == "scanner":
			totalScanner++
			totalBlocked++ // scanner drops are always blocked
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
		switch ev.EventType {
		case "honeypot":
			hs.honeypot++
		case "scanner":
			hs.scanner++
		case "policy_skip", "policy_allow", "policy_block":
			hs.policy++
		case "rate_limited":
			hs.rateLimited++
		case "ipsum_blocked":
			hs.ipsumBlocked++
		default:
			if ev.IsBlocked {
				hs.blocked++
			}
		}

		// Per-service.
		ss, ok := svcMap[ev.Service]
		if !ok {
			ss = &svcStats{}
			svcMap[ev.Service] = ss
		}
		ss.total++
		switch ev.EventType {
		case "honeypot":
			ss.honeypot++
		case "scanner":
			ss.scanner++
		case "policy_skip", "policy_allow", "policy_block":
			ss.policy++
		case "rate_limited":
			ss.rateLimited++
		case "ipsum_blocked":
			ss.ipsumBlocked++
		default:
			if ev.IsBlocked {
				ss.blocked++
			}
		}

		// Per-client.
		cs, ok := clientMap[ev.ClientIP]
		if !ok {
			cs = &clientStats{}
			clientMap[ev.ClientIP] = cs
		}
		cs.total++
		switch ev.EventType {
		case "honeypot":
			cs.honeypot++
		case "scanner":
			cs.scanner++
		case "policy_skip", "policy_allow", "policy_block":
			cs.policy++
		case "rate_limited":
			cs.rateLimited++
		case "ipsum_blocked":
			cs.ipsumBlocked++
		default:
			if ev.IsBlocked {
				cs.blocked++
			}
		}
		if cs.country == "" && ev.Country != "" {
			cs.country = ev.Country
		}

		uris[ev.URI]++

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
	hourCounts := make([]HourCount, 0, len(hourMap))
	for k, v := range hourMap {
		logged := v.total - v.blocked - v.rateLimited - v.ipsumBlocked - v.honeypot - v.scanner - v.policy
		if logged < 0 {
			logged = 0
		}
		hourCounts = append(hourCounts, HourCount{
			Hour:         k,
			Count:        v.total,
			Blocked:      v.blocked,
			Logged:       logged,
			RateLimited:  v.rateLimited,
			IpsumBlocked: v.ipsumBlocked,
			Honeypot:     v.honeypot,
			Scanner:      v.scanner,
			Policy:       v.policy,
		})
	}
	sort.Slice(hourCounts, func(i, j int) bool {
		return hourCounts[i].Hour < hourCounts[j].Hour
	})

	// Build service counts (for top_services).
	svcCounts := make([]ServiceCount, 0, len(svcMap))
	for k, v := range svcMap {
		svcCounts = append(svcCounts, ServiceCount{
			Service:      k,
			Count:        v.total,
			Blocked:      v.blocked,
			Logged:       v.total - v.blocked - v.rateLimited - v.ipsumBlocked - v.honeypot - v.scanner - v.policy,
			RateLimited:  v.rateLimited,
			IpsumBlocked: v.ipsumBlocked,
			Honeypot:     v.honeypot,
			Scanner:      v.scanner,
			Policy:       v.policy,
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
		svcBreakdown = append(svcBreakdown, ServiceDetail{
			Service:      k,
			Total:        v.total,
			Blocked:      v.blocked,
			Logged:       v.total - v.blocked - v.rateLimited - v.ipsumBlocked - v.honeypot - v.scanner - v.policy,
			RateLimited:  v.rateLimited,
			IpsumBlocked: v.ipsumBlocked,
			Honeypot:     v.honeypot,
			Scanner:      v.scanner,
			Policy:       v.policy,
		})
	}
	sort.Slice(svcBreakdown, func(i, j int) bool {
		return svcBreakdown[i].Total > svcBreakdown[j].Total
	})

	// Build client counts.
	clientCounts := make([]ClientCount, 0, len(clientMap))
	for k, v := range clientMap {
		clientCounts = append(clientCounts, ClientCount{
			Client:       k,
			Country:      v.country,
			Count:        v.total,
			Blocked:      v.blocked,
			RateLimited:  v.rateLimited,
			IpsumBlocked: v.ipsumBlocked,
			Honeypot:     v.honeypot,
			Scanner:      v.scanner,
			Policy:       v.policy,
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

	return summaryResult{
		SummaryResponse: SummaryResponse{
			TotalEvents:      len(events),
			BlockedEvents:    totalBlocked,
			LoggedEvents:     totalLogged,
			RateLimited:      totalRateLimited,
			IpsumBlocked:     totalIpsumBlocked,
			PolicyEvents:     totalPolicy,
			HoneypotEvents:   totalHoneypot,
			ScannerEvents:    totalScanner,
			UniqueClients:    len(clientMap),
			UniqueServices:   len(svcMap),
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
