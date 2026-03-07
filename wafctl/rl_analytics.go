package main

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// regexCache caches compiled regular expressions for condition matching.
// Keys are pattern strings, values are *regexp.Regexp.
var regexCache sync.Map

// cachedRegexp returns a compiled regex from the cache, compiling on first use.
func cachedRegexp(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}

// ─── API response types ─────────────────────────────────────────────

type RLSummaryResponse struct {
	Total429s      int              `json:"total_429s"`
	UniqueClients  int              `json:"unique_clients"`
	UniqueServices int              `json:"unique_services"`
	EventsByHour   []HourCount      `json:"events_by_hour"`
	TopClients     []RLClientCount  `json:"top_clients"`
	TopServices    []RLServiceCount `json:"top_services"`
	TopURIs        []RLURICount     `json:"top_uris"`
	RecentEvents   []RateLimitEvent `json:"recent_events"`
}

type RLClientCount struct {
	ClientIP  string `json:"client_ip"`
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

type RLServiceCount struct {
	Service string `json:"service"`
	Count   int    `json:"count"`
}

type RLURICount struct {
	URI      string   `json:"uri"`
	Count    int      `json:"count"`
	Services []string `json:"services"`
}

type RLEventsResponse struct {
	Total  int              `json:"total"`
	Events []RateLimitEvent `json:"events"`
}

// Advisor types, cache, scan logic, and statistical helpers are in rl_advisor.go.

// ─── Analytics methods ──────────────────────────────────────────────

// Summary returns aggregate rate limit analytics.
func (s *AccessLogStore) Summary(hours int) RLSummaryResponse {
	events := s.snapshotSince(hours)

	clients := make(map[string]struct{})
	services := make(map[string]struct{})
	hourBuckets := make(map[string]int)
	clientCounts := make(map[string]*RLClientCount)
	serviceCounts := make(map[string]int)
	type uriInfo struct {
		count    int
		services map[string]bool
	}
	uriCounts := make(map[string]*uriInfo)

	for _, e := range events {
		clients[e.ClientIP] = struct{}{}
		services[e.Service] = struct{}{}

		hourKey := e.Timestamp.UTC().Format("2006-01-02T15:00:00Z")
		hourBuckets[hourKey]++

		if cc, ok := clientCounts[e.ClientIP]; ok {
			cc.Count++
			ts := e.Timestamp.UTC().Format(time.RFC3339)
			if ts < cc.FirstSeen {
				cc.FirstSeen = ts
			}
			if ts > cc.LastSeen {
				cc.LastSeen = ts
			}
		} else {
			ts := e.Timestamp.UTC().Format(time.RFC3339)
			clientCounts[e.ClientIP] = &RLClientCount{
				ClientIP:  e.ClientIP,
				Count:     1,
				FirstSeen: ts,
				LastSeen:  ts,
			}
		}

		serviceCounts[e.Service]++

		if ui, ok := uriCounts[e.URI]; ok {
			ui.count++
			ui.services[e.Service] = true
		} else {
			uriCounts[e.URI] = &uriInfo{count: 1, services: map[string]bool{e.Service: true}}
		}
	}

	// Build sorted lists.
	var topClients []RLClientCount
	for _, cc := range clientCounts {
		topClients = append(topClients, *cc)
	}
	sort.Slice(topClients, func(i, j int) bool { return topClients[i].Count > topClients[j].Count })
	if len(topClients) > topNAnalytics {
		topClients = topClients[:topNAnalytics]
	}

	var topServices []RLServiceCount
	for svc, cnt := range serviceCounts {
		topServices = append(topServices, RLServiceCount{Service: svc, Count: cnt})
	}
	sort.Slice(topServices, func(i, j int) bool { return topServices[i].Count > topServices[j].Count })
	if len(topServices) > topNAnalytics {
		topServices = topServices[:topNAnalytics]
	}

	var topURIs []RLURICount
	for uri, ui := range uriCounts {
		var svcs []string
		for svc := range ui.services {
			svcs = append(svcs, svc)
		}
		sort.Strings(svcs)
		topURIs = append(topURIs, RLURICount{URI: uri, Count: ui.count, Services: svcs})
	}
	sort.Slice(topURIs, func(i, j int) bool { return topURIs[i].Count > topURIs[j].Count })
	if len(topURIs) > topNAnalytics {
		topURIs = topURIs[:topNAnalytics]
	}

	var hourCounts []HourCount
	for h, c := range hourBuckets {
		hourCounts = append(hourCounts, HourCount{Hour: h, Count: c, Blocked: c})
	}
	sort.Slice(hourCounts, func(i, j int) bool { return hourCounts[i].Hour < hourCounts[j].Hour })

	// Recent events (newest first).
	recent := make([]RateLimitEvent, len(events))
	copy(recent, events)
	sort.Slice(recent, func(i, j int) bool { return recent[i].Timestamp.After(recent[j].Timestamp) })
	if len(recent) > topNAnalytics {
		recent = recent[:topNAnalytics]
	}

	return RLSummaryResponse{
		Total429s:      len(events),
		UniqueClients:  len(clients),
		UniqueServices: len(services),
		EventsByHour:   hourCounts,
		TopClients:     topClients,
		TopServices:    topServices,
		TopURIs:        topURIs,
		RecentEvents:   recent,
	}
}

// FilteredEvents returns paginated 429 events with optional filters.
func (s *AccessLogStore) FilteredEvents(service, client, method string, limit, offset, hours int) RLEventsResponse {
	events := s.snapshotSince(hours)

	// Filter.
	var filtered []RateLimitEvent
	for _, e := range events {
		if service != "" && e.Service != service {
			continue
		}
		if client != "" && e.ClientIP != client {
			continue
		}
		if method != "" && e.Method != method {
			continue
		}
		filtered = append(filtered, e)
	}

	total := len(filtered)

	// Sort newest first.
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Timestamp.After(filtered[j].Timestamp) })

	// Paginate.
	if offset >= total {
		return RLEventsResponse{Total: total, Events: []RateLimitEvent{}}
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return RLEventsResponse{Total: total, Events: filtered[offset:end]}
}

// ─── Per-Rule Hit Attribution (condition-based inference) ────────────

// RLRuleHitStats holds per-rule hit counts with a sparkline.
type RLRuleHitStats struct {
	Total     int   `json:"total"`
	Sparkline []int `json:"sparkline"` // Hourly buckets, oldest-first
}

// RuleHits returns per-rule hit counts by matching 429 events against
// stored rule conditions. Uses condition-based inference: for each 429
// event, evaluates rules in priority order and attributes the event to
// the first matching rule.
func (s *AccessLogStore) RuleHits(rules []RateLimitRule, hours int) map[string]RLRuleHitStats {
	events := s.snapshotSince(hours)

	// Pre-initialize all rules so the frontend gets zero-filled entries.
	result := make(map[string]RLRuleHitStats, len(rules))
	numBuckets := hours
	if numBuckets <= 0 || numBuckets > 168 {
		numBuckets = 24
	}
	for _, r := range rules {
		result[r.Name] = RLRuleHitStats{
			Total:     0,
			Sparkline: make([]int, numBuckets),
		}
	}

	if len(events) == 0 || len(rules) == 0 {
		return result
	}

	// Sort rules by priority for evaluation order.
	sorted := make([]RateLimitRule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	// Build sparkline time boundaries.
	now := time.Now().UTC()
	bucketStart := now.Add(-time.Duration(numBuckets) * time.Hour)

	for _, evt := range events {
		// Only count rate-limited events (not ipsum).
		if evt.Source != "" {
			continue
		}

		// Find the first matching rule for this event.
		ruleName := matchEventToRule(evt, sorted)
		if ruleName == "" {
			continue
		}

		stats := result[ruleName]
		stats.Total++

		// Sparkline bucket.
		if evt.Timestamp.After(bucketStart) {
			bucket := int(evt.Timestamp.Sub(bucketStart).Hours())
			if bucket >= 0 && bucket < numBuckets {
				stats.Sparkline[bucket]++
			}
		}
		result[ruleName] = stats
	}

	return result
}

// matchEventToRule evaluates rules in priority order against a 429 event.
// Returns the name of the first matching rule, or "" if none match.
func matchEventToRule(evt RateLimitEvent, rules []RateLimitRule) string {
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		// Service must match.
		if rule.Service != "*" && rule.Service != evt.Service {
			continue
		}
		// If no conditions, rule matches all events for this service.
		if len(rule.Conditions) == 0 {
			return rule.Name
		}
		// Evaluate conditions (AND by default).
		if matchRLConditions(evt, rule.Conditions, rule.GroupOp) {
			return rule.Name
		}
	}
	return ""
}

// matchRLConditions checks if a rate limit event matches the given conditions.
func matchRLConditions(evt RateLimitEvent, conditions []Condition, groupOp string) bool {
	if groupOp == "or" {
		for _, c := range conditions {
			if matchRLCondition(evt, c) {
				return true
			}
		}
		return false
	}
	// AND (default).
	for _, c := range conditions {
		if !matchRLCondition(evt, c) {
			return false
		}
	}
	return true
}

// matchRLCondition checks if a single condition matches a rate limit event.
func matchRLCondition(evt RateLimitEvent, c Condition) bool {
	var target string
	switch c.Field {
	case "path", "uri_path":
		target = evt.URI
	case "method":
		target = evt.Method
	case "ip":
		target = evt.ClientIP
	case "host":
		target = evt.Service
	case "user_agent":
		target = evt.UserAgent
	case "country":
		target = evt.Country
	default:
		return false
	}

	switch c.Operator {
	case "eq", "ip_match":
		return target == c.Value
	case "neq", "not_ip_match":
		return target != c.Value
	case "contains":
		return strings.Contains(target, c.Value)
	case "begins_with":
		return strings.HasPrefix(target, c.Value)
	case "ends_with":
		return strings.HasSuffix(target, c.Value)
	case "in":
		for _, v := range splitPipe(c.Value) {
			if target == v {
				return true
			}
		}
		return false
	case "regex":
		re, err := cachedRegexp(c.Value)
		if err != nil {
			return false
		}
		return re.MatchString(target)
	}
	return false
}
