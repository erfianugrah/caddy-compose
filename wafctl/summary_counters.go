package main

import (
	"sort"
	"sync"
	"time"
)

// ─── Incremental Summary Counters ───────────────────────────────────
//
// hourBucket holds aggregated counters for a single hour window.
// These are maintained incrementally on event ingestion and eviction
// so that summary computation is O(buckets) instead of O(events).

type hourBucket struct {
	Total       int
	Blocked     int
	Logged      int
	RateLimited int
	PolicyBlock int
	DetectBlock int
	PolicyAllow int
	PolicySkip  int
	// Per-service, per-client, per-country, per-URI, per-tag counts.
	Services  map[string]int
	Clients   map[string]int
	Countries map[string]int
	URIs      map[string]int
	Tags      map[string]int
	// Per-client country mapping (first seen country per client in this bucket).
	ClientCountry map[string]string
	// Per-service action breakdown for ServiceDetail/ServiceCount.
	ServiceRL          map[string]int
	ServicePolicyBlock map[string]int
	ServiceDetectBlock map[string]int
	ServicePolicyAllow map[string]int
	ServicePolicySkip  map[string]int
	ServiceLogged      map[string]int
	ServiceBlocked     map[string]int
	// Per-client action breakdown for ClientCount.
	ClientRL          map[string]int
	ClientPolicyBlock map[string]int
	ClientDetectBlock map[string]int
	ClientPolicyAllow map[string]int
	ClientPolicySkip  map[string]int
	ClientBlocked     map[string]int
	// Per-country blocked count.
	CountryBlocked map[string]int
	// Recent events (newest first, up to recentCap).
	RecentEvents []Event
}

const recentCap = 10

func newHourBucket() *hourBucket {
	return &hourBucket{
		Services:           make(map[string]int),
		Clients:            make(map[string]int),
		Countries:          make(map[string]int),
		URIs:               make(map[string]int),
		Tags:               make(map[string]int),
		ClientCountry:      make(map[string]string),
		ServiceRL:          make(map[string]int),
		ServicePolicyBlock: make(map[string]int),
		ServiceDetectBlock: make(map[string]int),
		ServicePolicyAllow: make(map[string]int),
		ServicePolicySkip:  make(map[string]int),
		ServiceLogged:      make(map[string]int),
		ServiceBlocked:     make(map[string]int),
		ClientRL:           make(map[string]int),
		ClientPolicyBlock:  make(map[string]int),
		ClientDetectBlock:  make(map[string]int),
		ClientPolicyAllow:  make(map[string]int),
		ClientPolicySkip:   make(map[string]int),
		ClientBlocked:      make(map[string]int),
		CountryBlocked:     make(map[string]int),
	}
}

// summaryCounters holds incrementally-maintained summary state.
// Keyed by hour-truncated timestamp string for O(1) bucket lookup.
type summaryCounters struct {
	mu    sync.RWMutex
	hours map[string]*hourBucket // keyed by "2006-01-02T15"
}

func newSummaryCounters() *summaryCounters {
	return &summaryCounters{
		hours: make(map[string]*hourBucket),
	}
}

// totalEvents returns the total number of events across all hour buckets.
func (sc *summaryCounters) totalEvents() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	total := 0
	for _, b := range sc.hours {
		total += b.Total
	}
	return total
}

// hourKey returns the bucket key for a timestamp.
func hourKey(ts time.Time) string {
	return ts.Truncate(time.Hour).Format("2006-01-02T15")
}

// hourKeyToRFC3339 converts our compact hour key to the RFC3339 format
// used in SummaryResponse.EventsByHour (e.g. "2026-02-22T07:00:00Z").
func hourKeyToRFC3339(key string) string {
	t, err := time.Parse("2006-01-02T15", key)
	if err != nil {
		return key
	}
	return t.UTC().Format(time.RFC3339)
}

// incrementEvent updates the bucket for a single event.
func (sc *summaryCounters) incrementEvent(ev *Event) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	key := hourKey(ev.Timestamp)
	b, ok := sc.hours[key]
	if !ok {
		b = newHourBucket()
		sc.hours[key] = b
	}

	b.Total++
	classifyEventIntoBucket(b, ev, 1)

	b.Services[ev.Service]++
	b.Clients[ev.ClientIP]++
	b.URIs[ev.URI]++

	cc := ev.Country
	if cc == "" {
		cc = "XX"
	}
	b.Countries[cc]++
	if ev.IsBlocked {
		b.CountryBlocked[cc]++
	}

	// Service action breakdown.
	switch ev.EventType {
	case "rate_limited":
		b.ServiceRL[ev.Service]++
	case "policy_block":
		b.ServicePolicyBlock[ev.Service]++
	case "detect_block":
		b.ServiceDetectBlock[ev.Service]++
	case "policy_allow":
		b.ServicePolicyAllow[ev.Service]++
	case "policy_skip":
		b.ServicePolicySkip[ev.Service]++
	default:
		b.ServiceLogged[ev.Service]++
	}
	if ev.IsBlocked {
		b.ServiceBlocked[ev.Service]++
	}

	// Client action breakdown.
	switch ev.EventType {
	case "rate_limited":
		b.ClientRL[ev.ClientIP]++
	case "policy_block":
		b.ClientPolicyBlock[ev.ClientIP]++
	case "detect_block":
		b.ClientDetectBlock[ev.ClientIP]++
	case "policy_allow":
		b.ClientPolicyAllow[ev.ClientIP]++
	case "policy_skip":
		b.ClientPolicySkip[ev.ClientIP]++
	}
	if ev.IsBlocked {
		b.ClientBlocked[ev.ClientIP]++
	}

	if b.ClientCountry[ev.ClientIP] == "" && ev.Country != "" {
		b.ClientCountry[ev.ClientIP] = ev.Country
	}

	for _, tag := range ev.Tags {
		b.Tags[tag]++
	}

	// Maintain recent events (append to tail, trim front — avoids prepend garbage).
	b.RecentEvents = append(b.RecentEvents, *ev)
	if len(b.RecentEvents) > recentCap {
		b.RecentEvents = b.RecentEvents[len(b.RecentEvents)-recentCap:]
	}
}

// decrementEvent removes a single event's contribution from the counters.
func (sc *summaryCounters) decrementEvent(ev *Event) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	key := hourKey(ev.Timestamp)
	b, ok := sc.hours[key]
	if !ok {
		return
	}

	b.Total--
	classifyEventIntoBucket(b, ev, -1)

	decrMap(b.Services, ev.Service)
	decrMap(b.Clients, ev.ClientIP)
	decrMap(b.URIs, ev.URI)

	cc := ev.Country
	if cc == "" {
		cc = "XX"
	}
	decrMap(b.Countries, cc)
	if ev.IsBlocked {
		decrMap(b.CountryBlocked, cc)
	}

	// Service action breakdown.
	switch ev.EventType {
	case "rate_limited":
		decrMap(b.ServiceRL, ev.Service)
	case "policy_block":
		decrMap(b.ServicePolicyBlock, ev.Service)
	case "detect_block":
		decrMap(b.ServiceDetectBlock, ev.Service)
	case "policy_allow":
		decrMap(b.ServicePolicyAllow, ev.Service)
	case "policy_skip":
		decrMap(b.ServicePolicySkip, ev.Service)
	default:
		decrMap(b.ServiceLogged, ev.Service)
	}
	if ev.IsBlocked {
		decrMap(b.ServiceBlocked, ev.Service)
	}

	// Client action breakdown.
	switch ev.EventType {
	case "rate_limited":
		decrMap(b.ClientRL, ev.ClientIP)
	case "policy_block":
		decrMap(b.ClientPolicyBlock, ev.ClientIP)
	case "detect_block":
		decrMap(b.ClientDetectBlock, ev.ClientIP)
	case "policy_allow":
		decrMap(b.ClientPolicyAllow, ev.ClientIP)
	case "policy_skip":
		decrMap(b.ClientPolicySkip, ev.ClientIP)
	}
	if ev.IsBlocked {
		decrMap(b.ClientBlocked, ev.ClientIP)
	}

	for _, tag := range ev.Tags {
		decrMap(b.Tags, tag)
	}

	// Remove empty bucket.
	if b.Total <= 0 {
		delete(sc.hours, key)
	}

	// Note: we don't try to maintain recent events on decrement —
	// they are rebuilt from scratch during FastSummary across buckets.
}

// classifyEventIntoBucket increments or decrements the action counters
// based on event type. delta is +1 for increment, -1 for decrement.
func classifyEventIntoBucket(b *hourBucket, ev *Event, delta int) {
	switch {
	case ev.EventType == "rate_limited":
		b.RateLimited += delta
	case ev.EventType == "policy_block":
		b.PolicyBlock += delta
		if ev.IsBlocked {
			b.Blocked += delta
		}
	case ev.EventType == "detect_block":
		b.DetectBlock += delta
		if ev.IsBlocked {
			b.Blocked += delta
		}
	case ev.EventType == "policy_allow":
		b.PolicyAllow += delta
	case ev.EventType == "policy_skip":
		b.PolicySkip += delta
	case ev.IsBlocked:
		b.Blocked += delta
	default:
		b.Logged += delta
	}
}

// decrMap decrements a map counter and removes the key if it reaches zero.
func decrMap(m map[string]int, key string) {
	if v, ok := m[key]; ok {
		if v <= 1 {
			delete(m, key)
		} else {
			m[key] = v - 1
		}
	}
}

// buildSummary aggregates the relevant hourly buckets into a SummaryResponse.
// If hours <= 0, all buckets are included.
func (sc *summaryCounters) buildSummary(hours int) SummaryResponse {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	var cutoffKey string
	if hours > 0 {
		cutoff := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
		cutoffKey = hourKey(cutoff)
	}

	var totalEvents, totalBlocked, totalLogged, totalRateLimited int
	var totalPolicyBlock, totalDetectBlock, totalPolicyAllow, totalPolicySkip int

	hourCounts := make([]HourCount, 0, len(sc.hours))
	svcMap := make(map[string]*[8]int)    // [total, blocked, logged, rl, policyBlock, detectBlock, policyAllow, policySkip]
	clientMap := make(map[string]*[7]int) // [total, rl, policyBlock, detectBlock, policyAllow, policySkip, blocked]
	clientCountry := make(map[string]string)
	uriMap := make(map[string]int)
	tagMap := make(map[string]int)
	countryMap := make(map[string]*CountryCount)

	var allRecent []Event

	for key, b := range sc.hours {
		if cutoffKey != "" && key < cutoffKey {
			continue
		}

		totalEvents += b.Total
		totalBlocked += b.Blocked
		totalLogged += b.Logged
		totalRateLimited += b.RateLimited
		totalPolicyBlock += b.PolicyBlock
		totalDetectBlock += b.DetectBlock
		totalPolicyAllow += b.PolicyAllow
		totalPolicySkip += b.PolicySkip

		// Build HourCount.
		logged := b.Total - b.Blocked - b.RateLimited - b.PolicyAllow - b.PolicySkip
		if logged < 0 {
			logged = 0
		}
		hourCounts = append(hourCounts, HourCount{
			Hour:         hourKeyToRFC3339(key),
			Count:        b.Total,
			TotalBlocked: b.Blocked,
			Logged:       logged,
			RateLimited:  b.RateLimited,
			PolicyBlock:  b.PolicyBlock,
			DetectBlock:  b.DetectBlock,
			PolicyAllow:  b.PolicyAllow,
			PolicySkip:   b.PolicySkip,
		})

		// Aggregate per-service.
		for svc, count := range b.Services {
			s, ok := svcMap[svc]
			if !ok {
				s = &[8]int{}
				svcMap[svc] = s
			}
			s[0] += count
			s[1] += b.ServiceBlocked[svc]
			// logged computed later
			s[3] += b.ServiceRL[svc]
			s[4] += b.ServicePolicyBlock[svc]
			s[5] += b.ServiceDetectBlock[svc]
			s[6] += b.ServicePolicyAllow[svc]
			s[7] += b.ServicePolicySkip[svc]
		}

		// Aggregate per-client.
		for client, count := range b.Clients {
			c, ok := clientMap[client]
			if !ok {
				c = &[7]int{}
				clientMap[client] = c
			}
			c[0] += count
			c[1] += b.ClientRL[client]
			c[2] += b.ClientPolicyBlock[client]
			c[3] += b.ClientDetectBlock[client]
			c[4] += b.ClientPolicyAllow[client]
			c[5] += b.ClientPolicySkip[client]
			c[6] += b.ClientBlocked[client]
			if clientCountry[client] == "" {
				clientCountry[client] = b.ClientCountry[client]
			}
		}

		// Aggregate URIs.
		for uri, count := range b.URIs {
			uriMap[uri] += count
		}

		// Aggregate tags.
		for tag, count := range b.Tags {
			tagMap[tag] += count
		}

		// Aggregate countries.
		for cc, count := range b.Countries {
			entry, ok := countryMap[cc]
			if !ok {
				entry = &CountryCount{Country: cc}
				countryMap[cc] = entry
			}
			entry.Count += count
			entry.TotalBlocked += b.CountryBlocked[cc]
		}

		// Collect recent events from each bucket.
		allRecent = append(allRecent, b.RecentEvents...)
	}

	sort.Slice(hourCounts, func(i, j int) bool {
		return hourCounts[i].Hour < hourCounts[j].Hour
	})

	// Build TopServices and ServiceBreakdown.
	svcCounts := make([]ServiceCount, 0, len(svcMap))
	svcBreakdown := make([]ServiceDetail, 0, len(svcMap))
	for svc, s := range svcMap {
		svcLogged := s[0] - s[1] - s[3] - s[6] - s[7]
		if svcLogged < 0 {
			svcLogged = 0
		}
		sc := ServiceCount{
			Service:      svc,
			Count:        s[0],
			TotalBlocked: s[1],
			Logged:       svcLogged,
			RateLimited:  s[3],
			PolicyBlock:  s[4],
			DetectBlock:  s[5],
			PolicyAllow:  s[6],
			PolicySkip:   s[7],
		}
		svcCounts = append(svcCounts, sc)
		svcBreakdown = append(svcBreakdown, ServiceDetail{
			Service:      svc,
			Total:        s[0],
			TotalBlocked: s[1],
			Logged:       svcLogged,
			RateLimited:  s[3],
			PolicyBlock:  s[4],
			DetectBlock:  s[5],
			PolicyAllow:  s[6],
			PolicySkip:   s[7],
		})
	}
	sort.Slice(svcCounts, func(i, j int) bool {
		return svcCounts[i].Count > svcCounts[j].Count
	})
	if len(svcCounts) > topNAnalytics {
		svcCounts = svcCounts[:topNAnalytics]
	}
	sort.Slice(svcBreakdown, func(i, j int) bool {
		return svcBreakdown[i].Total > svcBreakdown[j].Total
	})

	// Build TopClients.
	clientCounts := make([]ClientCount, 0, len(clientMap))
	for client, c := range clientMap {
		clientCounts = append(clientCounts, ClientCount{
			Client:       client,
			Country:      clientCountry[client],
			Count:        c[0],
			TotalBlocked: c[6],
			RateLimited:  c[1],
			PolicyBlock:  c[2],
			DetectBlock:  c[3],
			PolicyAllow:  c[4],
			PolicySkip:   c[5],
		})
	}
	sort.Slice(clientCounts, func(i, j int) bool {
		return clientCounts[i].Count > clientCounts[j].Count
	})
	if len(clientCounts) > topNAnalytics {
		clientCounts = clientCounts[:topNAnalytics]
	}

	// Build TopCountries.
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

	// Build TopURIs.
	topURIs := topN(uriMap, topNAnalytics, func(k string, c int) URICount {
		return URICount{URI: k, Count: c}
	})

	// Build TagCounts.
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

	// Build RecentEvents (newest first, across all buckets).
	sort.Slice(allRecent, func(i, j int) bool {
		return allRecent[i].Timestamp.After(allRecent[j].Timestamp)
	})
	if len(allRecent) > topNSummary {
		allRecent = allRecent[:topNSummary]
	}

	totalPolicy := totalPolicyBlock + totalDetectBlock + totalPolicyAllow + totalPolicySkip
	return SummaryResponse{
		TotalEvents:      totalEvents,
		TotalBlocked:     totalBlocked,
		LoggedEvents:     totalLogged,
		RateLimited:      totalRateLimited,
		PolicyEvents:     totalPolicy,
		PolicyBlocked:    totalPolicyBlock,
		DetectBlocked:    totalDetectBlock,
		PolicyAllowed:    totalPolicyAllow,
		PolicySkipped:    totalPolicySkip,
		UniqueClients:    len(clientMap),
		UniqueServices:   len(svcMap),
		TagCounts:        tagCounts,
		EventsByHour:     hourCounts,
		TopServices:      svcCounts,
		TopClients:       clientCounts,
		TopCountries:     countryCounts,
		TopURIs:          topURIs,
		ServiceBreakdown: svcBreakdown,
		RecentEvents:     allRecent,
	}
}

// mergeSummaryResponses merges two SummaryResponse values into one.
// Used to combine WAF store and access log store incremental summaries.
func mergeSummaryResponses(a, b SummaryResponse) SummaryResponse {
	merged := a

	// Merge scalar counters.
	merged.TotalEvents += b.TotalEvents
	merged.TotalBlocked += b.TotalBlocked
	merged.LoggedEvents += b.LoggedEvents
	merged.RateLimited += b.RateLimited
	merged.PolicyEvents += b.PolicyEvents
	merged.PolicyBlocked += b.PolicyBlocked
	merged.DetectBlocked += b.DetectBlocked
	merged.PolicyAllowed += b.PolicyAllowed
	merged.PolicySkipped += b.PolicySkipped

	// Merge EventsByHour.
	hourIdx := make(map[string]int, len(merged.EventsByHour))
	for i, hc := range merged.EventsByHour {
		hourIdx[hc.Hour] = i
	}
	for _, hc := range b.EventsByHour {
		if idx, ok := hourIdx[hc.Hour]; ok {
			merged.EventsByHour[idx].Count += hc.Count
			merged.EventsByHour[idx].TotalBlocked += hc.TotalBlocked
			merged.EventsByHour[idx].Logged += hc.Logged
			merged.EventsByHour[idx].RateLimited += hc.RateLimited
			merged.EventsByHour[idx].PolicyBlock += hc.PolicyBlock
			merged.EventsByHour[idx].DetectBlock += hc.DetectBlock
			merged.EventsByHour[idx].PolicyAllow += hc.PolicyAllow
			merged.EventsByHour[idx].PolicySkip += hc.PolicySkip
		} else {
			hourIdx[hc.Hour] = len(merged.EventsByHour)
			merged.EventsByHour = append(merged.EventsByHour, hc)
		}
	}
	sort.Slice(merged.EventsByHour, func(i, j int) bool {
		return merged.EventsByHour[i].Hour < merged.EventsByHour[j].Hour
	})

	// Merge ServiceBreakdown.
	svcIdx := make(map[string]int, len(merged.ServiceBreakdown))
	for i, sd := range merged.ServiceBreakdown {
		svcIdx[sd.Service] = i
	}
	for _, sd := range b.ServiceBreakdown {
		if idx, ok := svcIdx[sd.Service]; ok {
			merged.ServiceBreakdown[idx].Total += sd.Total
			merged.ServiceBreakdown[idx].TotalBlocked += sd.TotalBlocked
			merged.ServiceBreakdown[idx].Logged += sd.Logged
			merged.ServiceBreakdown[idx].RateLimited += sd.RateLimited
			merged.ServiceBreakdown[idx].PolicyBlock += sd.PolicyBlock
			merged.ServiceBreakdown[idx].DetectBlock += sd.DetectBlock
			merged.ServiceBreakdown[idx].PolicyAllow += sd.PolicyAllow
			merged.ServiceBreakdown[idx].PolicySkip += sd.PolicySkip
		} else {
			svcIdx[sd.Service] = len(merged.ServiceBreakdown)
			merged.ServiceBreakdown = append(merged.ServiceBreakdown, sd)
		}
	}
	sort.Slice(merged.ServiceBreakdown, func(i, j int) bool {
		return merged.ServiceBreakdown[i].Total > merged.ServiceBreakdown[j].Total
	})

	// Merge TopServices.
	topSvcIdx := make(map[string]int, len(merged.TopServices))
	for i, sc := range merged.TopServices {
		topSvcIdx[sc.Service] = i
	}
	for _, sc := range b.TopServices {
		if idx, ok := topSvcIdx[sc.Service]; ok {
			merged.TopServices[idx].Count += sc.Count
			merged.TopServices[idx].TotalBlocked += sc.TotalBlocked
			merged.TopServices[idx].Logged += sc.Logged
			merged.TopServices[idx].RateLimited += sc.RateLimited
			merged.TopServices[idx].PolicyBlock += sc.PolicyBlock
			merged.TopServices[idx].DetectBlock += sc.DetectBlock
			merged.TopServices[idx].PolicyAllow += sc.PolicyAllow
			merged.TopServices[idx].PolicySkip += sc.PolicySkip
		} else {
			topSvcIdx[sc.Service] = len(merged.TopServices)
			merged.TopServices = append(merged.TopServices, sc)
		}
	}
	sort.Slice(merged.TopServices, func(i, j int) bool {
		return merged.TopServices[i].Count > merged.TopServices[j].Count
	})
	if len(merged.TopServices) > topNAnalytics {
		merged.TopServices = merged.TopServices[:topNAnalytics]
	}

	// Merge TopClients.
	clientIdx := make(map[string]int, len(merged.TopClients))
	for i, cc := range merged.TopClients {
		clientIdx[cc.Client] = i
	}
	for _, cc := range b.TopClients {
		if idx, ok := clientIdx[cc.Client]; ok {
			merged.TopClients[idx].Count += cc.Count
			merged.TopClients[idx].TotalBlocked += cc.TotalBlocked
			merged.TopClients[idx].RateLimited += cc.RateLimited
			merged.TopClients[idx].PolicyBlock += cc.PolicyBlock
			merged.TopClients[idx].DetectBlock += cc.DetectBlock
			merged.TopClients[idx].PolicyAllow += cc.PolicyAllow
			merged.TopClients[idx].PolicySkip += cc.PolicySkip
			if merged.TopClients[idx].Country == "" && cc.Country != "" {
				merged.TopClients[idx].Country = cc.Country
			}
		} else {
			clientIdx[cc.Client] = len(merged.TopClients)
			merged.TopClients = append(merged.TopClients, cc)
		}
	}
	sort.Slice(merged.TopClients, func(i, j int) bool {
		return merged.TopClients[i].Count > merged.TopClients[j].Count
	})
	if len(merged.TopClients) > topNSummary {
		merged.TopClients = merged.TopClients[:topNSummary]
	}

	// Merge TopCountries.
	countryIdx := make(map[string]int, len(merged.TopCountries))
	for i, cc := range merged.TopCountries {
		countryIdx[cc.Country] = i
	}
	for _, cc := range b.TopCountries {
		if idx, ok := countryIdx[cc.Country]; ok {
			merged.TopCountries[idx].Count += cc.Count
			merged.TopCountries[idx].TotalBlocked += cc.TotalBlocked
		} else {
			countryIdx[cc.Country] = len(merged.TopCountries)
			merged.TopCountries = append(merged.TopCountries, cc)
		}
	}
	sort.Slice(merged.TopCountries, func(i, j int) bool {
		return merged.TopCountries[i].Count > merged.TopCountries[j].Count
	})
	if len(merged.TopCountries) > topNAnalytics {
		merged.TopCountries = merged.TopCountries[:topNAnalytics]
	}

	// Merge TopURIs.
	uriIdx := make(map[string]int, len(merged.TopURIs))
	for i, u := range merged.TopURIs {
		uriIdx[u.URI] = i
	}
	for _, u := range b.TopURIs {
		if idx, ok := uriIdx[u.URI]; ok {
			merged.TopURIs[idx].Count += u.Count
		} else {
			uriIdx[u.URI] = len(merged.TopURIs)
			merged.TopURIs = append(merged.TopURIs, u)
		}
	}
	sort.Slice(merged.TopURIs, func(i, j int) bool {
		return merged.TopURIs[i].Count > merged.TopURIs[j].Count
	})
	if len(merged.TopURIs) > topNAnalytics {
		merged.TopURIs = merged.TopURIs[:topNAnalytics]
	}

	// Merge TagCounts.
	tagIdx := make(map[string]int, len(merged.TagCounts))
	for i, tc := range merged.TagCounts {
		tagIdx[tc.Tag] = i
	}
	for _, tc := range b.TagCounts {
		if idx, ok := tagIdx[tc.Tag]; ok {
			merged.TagCounts[idx].Count += tc.Count
		} else {
			tagIdx[tc.Tag] = len(merged.TagCounts)
			merged.TagCounts = append(merged.TagCounts, tc)
		}
	}
	sort.Slice(merged.TagCounts, func(i, j int) bool {
		if merged.TagCounts[i].Count != merged.TagCounts[j].Count {
			return merged.TagCounts[i].Count > merged.TagCounts[j].Count
		}
		return merged.TagCounts[i].Tag < merged.TagCounts[j].Tag
	})

	// Merge RecentEvents (newest first).
	merged.RecentEvents = append(merged.RecentEvents, b.RecentEvents...)
	sort.Slice(merged.RecentEvents, func(i, j int) bool {
		return merged.RecentEvents[i].Timestamp.After(merged.RecentEvents[j].Timestamp)
	})
	if len(merged.RecentEvents) > topNSummary {
		merged.RecentEvents = merged.RecentEvents[:topNSummary]
	}

	// UniqueClients/UniqueServices: sum is an upper-bound approximation.
	// For exact counts we'd need to union the client/service sets across
	// both stores, but the counters don't track full sets for efficiency.
	// The two stores rarely overlap, so this is acceptable.
	merged.UniqueClients = a.UniqueClients + b.UniqueClients
	merged.UniqueServices = a.UniqueServices + b.UniqueServices

	return merged
}

// initFromEvents bulk-loads events into the counters. Used at startup
// to initialize counters from persisted events.
func (sc *summaryCounters) initFromEvents(events []Event) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Clear existing state.
	sc.hours = make(map[string]*hourBucket)

	// Process events (assumed chronological order).
	for i := range events {
		ev := &events[i]
		key := hourKey(ev.Timestamp)
		b, ok := sc.hours[key]
		if !ok {
			b = newHourBucket()
			sc.hours[key] = b
		}

		b.Total++
		classifyEventIntoBucket(b, ev, 1)

		b.Services[ev.Service]++
		b.Clients[ev.ClientIP]++
		b.URIs[ev.URI]++

		cc := ev.Country
		if cc == "" {
			cc = "XX"
		}
		b.Countries[cc]++
		if ev.IsBlocked {
			b.CountryBlocked[cc]++
		}

		switch ev.EventType {
		case "rate_limited":
			b.ServiceRL[ev.Service]++
		case "policy_block":
			b.ServicePolicyBlock[ev.Service]++
		case "detect_block":
			b.ServiceDetectBlock[ev.Service]++
		case "policy_allow":
			b.ServicePolicyAllow[ev.Service]++
		case "policy_skip":
			b.ServicePolicySkip[ev.Service]++
		default:
			b.ServiceLogged[ev.Service]++
		}
		if ev.IsBlocked {
			b.ServiceBlocked[ev.Service]++
		}

		switch ev.EventType {
		case "rate_limited":
			b.ClientRL[ev.ClientIP]++
		case "policy_block":
			b.ClientPolicyBlock[ev.ClientIP]++
		case "detect_block":
			b.ClientDetectBlock[ev.ClientIP]++
		case "policy_allow":
			b.ClientPolicyAllow[ev.ClientIP]++
		case "policy_skip":
			b.ClientPolicySkip[ev.ClientIP]++
		}
		if ev.IsBlocked {
			b.ClientBlocked[ev.ClientIP]++
		}

		if b.ClientCountry[ev.ClientIP] == "" && ev.Country != "" {
			b.ClientCountry[ev.ClientIP] = ev.Country
		}

		for _, tag := range ev.Tags {
			b.Tags[tag]++
		}

		// Recent events: append to tail, trim front (avoids prepend garbage).
		b.RecentEvents = append(b.RecentEvents, *ev)
		if len(b.RecentEvents) > recentCap {
			b.RecentEvents = b.RecentEvents[len(b.RecentEvents)-recentCap:]
		}
	}
}

// ─── RateLimitEvent counter methods ─────────────────────────────────
//
// These operate directly on RateLimitEvent fields, avoiding the O(N)
// allocation of converting every RateLimitEvent to Event just for
// counter ingestion/eviction. The field mapping uses rleEventType and
// rleIsBlocked from query_helpers.go.

// incrementRLEvent updates the bucket for a single RateLimitEvent.
func (sc *summaryCounters) incrementRLEvent(rle *RateLimitEvent) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	eventType := rleEventType(rle.Source)
	isBlocked := rleIsBlocked(rle.Source)
	key := hourKey(rle.Timestamp)
	b, ok := sc.hours[key]
	if !ok {
		b = newHourBucket()
		sc.hours[key] = b
	}

	b.Total++
	classifyRLIntoBucket(b, eventType, isBlocked, 1)

	b.Services[rle.Service]++
	b.Clients[rle.ClientIP]++
	b.URIs[rle.URI]++

	cc := rle.Country
	if cc == "" {
		cc = "XX"
	}
	b.Countries[cc]++
	if isBlocked {
		b.CountryBlocked[cc]++
	}

	// Service action breakdown.
	switch eventType {
	case "rate_limited":
		b.ServiceRL[rle.Service]++
	case "policy_block":
		b.ServicePolicyBlock[rle.Service]++
	case "detect_block":
		b.ServiceDetectBlock[rle.Service]++
	case "policy_allow":
		b.ServicePolicyAllow[rle.Service]++
	case "policy_skip":
		b.ServicePolicySkip[rle.Service]++
	default:
		b.ServiceLogged[rle.Service]++
	}
	if isBlocked {
		b.ServiceBlocked[rle.Service]++
	}

	// Client action breakdown.
	switch eventType {
	case "rate_limited":
		b.ClientRL[rle.ClientIP]++
	case "policy_block":
		b.ClientPolicyBlock[rle.ClientIP]++
	case "detect_block":
		b.ClientDetectBlock[rle.ClientIP]++
	case "policy_allow":
		b.ClientPolicyAllow[rle.ClientIP]++
	case "policy_skip":
		b.ClientPolicySkip[rle.ClientIP]++
	}
	if isBlocked {
		b.ClientBlocked[rle.ClientIP]++
	}

	if b.ClientCountry[rle.ClientIP] == "" && rle.Country != "" {
		b.ClientCountry[rle.ClientIP] = rle.Country
	}

	for _, tag := range rle.InlineTags {
		b.Tags[tag]++
	}

	// Recent events: convert only the few that end up in the cap.
	ev := RateLimitEventToEvent(*rle, rle.InlineTags)
	b.RecentEvents = append(b.RecentEvents, ev)
	if len(b.RecentEvents) > recentCap {
		b.RecentEvents = b.RecentEvents[len(b.RecentEvents)-recentCap:]
	}
}

// decrementRLEvent removes a single RateLimitEvent's contribution from the counters.
func (sc *summaryCounters) decrementRLEvent(rle *RateLimitEvent) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	eventType := rleEventType(rle.Source)
	isBlocked := rleIsBlocked(rle.Source)
	key := hourKey(rle.Timestamp)
	b, ok := sc.hours[key]
	if !ok {
		return
	}

	b.Total--
	classifyRLIntoBucket(b, eventType, isBlocked, -1)

	decrMap(b.Services, rle.Service)
	decrMap(b.Clients, rle.ClientIP)
	decrMap(b.URIs, rle.URI)

	cc := rle.Country
	if cc == "" {
		cc = "XX"
	}
	decrMap(b.Countries, cc)
	if isBlocked {
		decrMap(b.CountryBlocked, cc)
	}

	switch eventType {
	case "rate_limited":
		decrMap(b.ServiceRL, rle.Service)
	case "policy_block":
		decrMap(b.ServicePolicyBlock, rle.Service)
	case "detect_block":
		decrMap(b.ServiceDetectBlock, rle.Service)
	case "policy_allow":
		decrMap(b.ServicePolicyAllow, rle.Service)
	case "policy_skip":
		decrMap(b.ServicePolicySkip, rle.Service)
	default:
		decrMap(b.ServiceLogged, rle.Service)
	}
	if isBlocked {
		decrMap(b.ServiceBlocked, rle.Service)
	}

	switch eventType {
	case "rate_limited":
		decrMap(b.ClientRL, rle.ClientIP)
	case "policy_block":
		decrMap(b.ClientPolicyBlock, rle.ClientIP)
	case "detect_block":
		decrMap(b.ClientDetectBlock, rle.ClientIP)
	case "policy_allow":
		decrMap(b.ClientPolicyAllow, rle.ClientIP)
	case "policy_skip":
		decrMap(b.ClientPolicySkip, rle.ClientIP)
	}
	if isBlocked {
		decrMap(b.ClientBlocked, rle.ClientIP)
	}

	for _, tag := range rle.InlineTags {
		decrMap(b.Tags, tag)
	}

	if b.Total <= 0 {
		delete(sc.hours, key)
	}
}

// initFromRLEvents initializes counters directly from RateLimitEvents,
// avoiding the O(N) allocation of converting to []Event.
func (sc *summaryCounters) initFromRLEvents(events []RateLimitEvent) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.hours = make(map[string]*hourBucket)

	for i := range events {
		rle := &events[i]
		eventType := rleEventType(rle.Source)
		isBlocked := rleIsBlocked(rle.Source)
		key := hourKey(rle.Timestamp)
		b, ok := sc.hours[key]
		if !ok {
			b = newHourBucket()
			sc.hours[key] = b
		}

		b.Total++
		classifyRLIntoBucket(b, eventType, isBlocked, 1)

		b.Services[rle.Service]++
		b.Clients[rle.ClientIP]++
		b.URIs[rle.URI]++

		cc := rle.Country
		if cc == "" {
			cc = "XX"
		}
		b.Countries[cc]++
		if isBlocked {
			b.CountryBlocked[cc]++
		}

		switch eventType {
		case "rate_limited":
			b.ServiceRL[rle.Service]++
		case "policy_block":
			b.ServicePolicyBlock[rle.Service]++
		case "detect_block":
			b.ServiceDetectBlock[rle.Service]++
		case "policy_allow":
			b.ServicePolicyAllow[rle.Service]++
		case "policy_skip":
			b.ServicePolicySkip[rle.Service]++
		default:
			b.ServiceLogged[rle.Service]++
		}
		if isBlocked {
			b.ServiceBlocked[rle.Service]++
		}

		switch eventType {
		case "rate_limited":
			b.ClientRL[rle.ClientIP]++
		case "policy_block":
			b.ClientPolicyBlock[rle.ClientIP]++
		case "detect_block":
			b.ClientDetectBlock[rle.ClientIP]++
		case "policy_allow":
			b.ClientPolicyAllow[rle.ClientIP]++
		case "policy_skip":
			b.ClientPolicySkip[rle.ClientIP]++
		}
		if isBlocked {
			b.ClientBlocked[rle.ClientIP]++
		}

		if b.ClientCountry[rle.ClientIP] == "" && rle.Country != "" {
			b.ClientCountry[rle.ClientIP] = rle.Country
		}

		for _, tag := range rle.InlineTags {
			b.Tags[tag]++
		}

		// Recent events: convert only the last recentCap per bucket.
		ev := RateLimitEventToEvent(*rle, rle.InlineTags)
		b.RecentEvents = append(b.RecentEvents, ev)
		if len(b.RecentEvents) > recentCap {
			b.RecentEvents = b.RecentEvents[len(b.RecentEvents)-recentCap:]
		}
	}
}

// classifyRLIntoBucket increments or decrements action counters for an
// RLE-derived event type. delta is +1 for increment, -1 for decrement.
func classifyRLIntoBucket(b *hourBucket, eventType string, isBlocked bool, delta int) {
	switch {
	case eventType == "rate_limited":
		b.RateLimited += delta
	case eventType == "policy_block":
		b.PolicyBlock += delta
		if isBlocked {
			b.Blocked += delta
		}
	case eventType == "detect_block":
		b.DetectBlock += delta
		if isBlocked {
			b.Blocked += delta
		}
	case eventType == "policy_allow":
		b.PolicyAllow += delta
	case eventType == "policy_skip":
		b.PolicySkip += delta
	case isBlocked:
		b.Blocked += delta
	default:
		b.Logged += delta
	}
}
