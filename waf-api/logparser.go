package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store holds the parsed events and precomputed indexes.
type Store struct {
	mu     sync.RWMutex
	events []Event

	// file tailing state
	path   string
	offset int64

	// maxAge is the maximum age of events to retain. Events older than this
	// are evicted during each Load() call. Zero means no eviction.
	maxAge time.Duration
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

// SetMaxAge configures the TTL for in-memory event retention.
// Events older than maxAge are evicted during each Load() cycle.
func (s *Store) SetMaxAge(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxAge = d
}

// Load reads new lines appended since last offset and parses them.
func (s *Store) Load() {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("audit log not found at %s, will retry", s.path)
			return
		}
		log.Printf("error opening audit log: %v", err)
		return
	}
	defer f.Close()

	// Check if the file was truncated/rotated (current size < last offset).
	info, err := f.Stat()
	if err != nil {
		log.Printf("error stat audit log: %v", err)
		return
	}
	if info.Size() < s.offset {
		log.Printf("audit log appears rotated (size %d < offset %d), re-reading from start", info.Size(), s.offset)
		s.offset = 0
		s.mu.Lock()
		s.events = nil
		s.mu.Unlock()
	}

	if info.Size() == s.offset {
		return // nothing new
	}

	// Seek to where we left off.
	if s.offset > 0 {
		if _, err := f.Seek(s.offset, io.SeekStart); err != nil {
			log.Printf("error seeking audit log: %v", err)
			return
		}
	}

	var newEvents []Event
	scanner := bufio.NewScanner(f)
	// Allow large lines (up to 1MB).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry AuditLogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			log.Printf("skipping malformed log line: %v", err)
			continue
		}

		ev := parseEvent(entry)
		newEvents = append(newEvents, ev)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("error scanning audit log: %v", err)
	}

	// Update offset to current position.
	newOffset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		log.Printf("error getting file offset: %v", err)
	} else {
		s.offset = newOffset
	}

	if len(newEvents) > 0 {
		s.mu.Lock()
		s.events = append(s.events, newEvents...)
		s.mu.Unlock()
		log.Printf("loaded %d new events (%d total)", len(newEvents), s.EventCount())
	}

	// Evict events older than maxAge.
	s.evict()
}

// evict removes events older than maxAge from the in-memory store.
func (s *Store) evict() {
	if s.maxAge <= 0 {
		return
	}

	cutoff := time.Now().UTC().Add(-s.maxAge)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Events are appended chronologically, so find the first event within range.
	idx := 0
	for idx < len(s.events) && s.events[idx].Timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		evicted := idx
		// Compact the slice to release memory.
		remaining := make([]Event, len(s.events)-idx)
		copy(remaining, s.events[idx:])
		s.events = remaining
		log.Printf("evicted %d events older than %s (%d remaining)", evicted, s.maxAge, len(s.events))
	}
}

// headerValue extracts the first value for a header key from a map[string][]string.
// Tries the exact key first, then a case-insensitive match.
func headerValue(headers map[string][]string, key string) string {
	if vals, ok := headers[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	// Case-insensitive fallback.
	lowerKey := strings.ToLower(key)
	for k, vals := range headers {
		if strings.ToLower(k) == lowerKey && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// parseEvent normalizes a raw audit log entry into an Event.
func parseEvent(entry AuditLogEntry) Event {
	tx := entry.Transaction

	ts := parseTimestamp(tx.Timestamp)

	ua := headerValue(tx.Request.Headers, "User-Agent")

	eventType := "logged"
	if tx.IsInterrupted {
		eventType = "blocked"
	}

	ev := Event{
		ID:             tx.ID,
		Timestamp:      ts,
		ClientIP:       tx.ClientIP,
		Service:        tx.ServerID,
		Method:         tx.Request.Method,
		URI:            tx.Request.URI,
		Protocol:       tx.Request.Protocol,
		IsBlocked:      tx.IsInterrupted,
		ResponseStatus: tx.Response.Status,
		UserAgent:      ua,
		EventType:      eventType,
	}

	// Extract rule match data from the messages array (audit log part H).
	// Use the highest-severity (lowest number) matched rule as the primary.
	if len(entry.Messages) > 0 {
		best := entry.Messages[0]
		for _, m := range entry.Messages[1:] {
			// Lower severity number = higher severity. 0 means unset.
			if m.Data.Severity > 0 && (best.Data.Severity == 0 || m.Data.Severity < best.Data.Severity) {
				best = m
			}
			// Prefer rules with an actual ID (skip anomaly scoring rules 949110/980170)
			if best.Data.ID == 949110 || best.Data.ID == 980170 {
				if m.Data.ID != 949110 && m.Data.ID != 980170 && m.Data.ID != 0 {
					best = m
				}
			}
		}
		ev.RuleID = best.Data.ID
		ev.RuleMsg = best.Data.Msg
		ev.Severity = best.Data.Severity
		ev.MatchedData = best.Data.Data
		ev.RuleTags = best.Data.Tags
	}

	return ev
}

// parseTimestamp parses Coraza's "2006/01/02 15:04:05" format.
func parseTimestamp(raw string) time.Time {
	t, err := time.Parse("2006/01/02 15:04:05", raw)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func (s *Store) EventCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// StartTailing loads once immediately, then reloads every interval.
func (s *Store) StartTailing(interval time.Duration) {
	s.Load()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.Load()
		}
	}()
}

// Snapshot returns a copy of the events slice for safe iteration.
func (s *Store) Snapshot() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]Event, len(s.events))
	copy(cp, s.events)
	return cp
}

// SnapshotSince returns a copy of events within the last N hours.
// If hours <= 0, returns all events.
func (s *Store) SnapshotSince(hours int) []Event {
	all := s.Snapshot()
	if hours <= 0 {
		return all
	}

	cutoff := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	var filtered []Event
	for i := range all {
		if !all[i].Timestamp.Before(cutoff) {
			filtered = append(filtered, all[i])
		}
	}
	return filtered
}

// SnapshotRange returns a copy of events within [start, end].
func (s *Store) SnapshotRange(start, end time.Time) []Event {
	all := s.Snapshot()
	var filtered []Event
	for i := range all {
		ts := all[i].Timestamp
		if !ts.Before(start) && !ts.After(end) {
			filtered = append(filtered, all[i])
		}
	}
	return filtered
}

// Summary computes aggregate stats from events within the last N hours.
func (s *Store) Summary(hours int) SummaryResponse {
	return summarizeEvents(s.SnapshotSince(hours))
}

// SummaryRange computes aggregate stats from events within [start, end].
func (s *Store) SummaryRange(start, end time.Time) SummaryResponse {
	return summarizeEvents(s.SnapshotRange(start, end))
}

// summarizeEvents computes aggregate stats from a slice of events.
func summarizeEvents(events []Event) SummaryResponse {
	var totalBlocked, totalLogged int

	// Per-hour breakdown with blocked/logged.
	type hourStats struct {
		total, blocked int
	}
	hourMap := make(map[string]*hourStats)

	// Per-service breakdown with blocked/logged.
	type svcStats struct {
		total, blocked int
	}
	svcMap := make(map[string]*svcStats)

	// Per-client breakdown with blocked.
	type clientStats struct {
		total, blocked int
	}
	clientMap := make(map[string]*clientStats)

	uris := make(map[string]int)

	// Collect recent events of all types (newest first, up to 10).
	var recentEvents []Event

	for i := len(events) - 1; i >= 0; i-- {
		ev := &events[i]
		if ev.IsBlocked {
			totalBlocked++
		} else {
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
		if ev.IsBlocked {
			hs.blocked++
		}

		// Per-service.
		ss, ok := svcMap[ev.Service]
		if !ok {
			ss = &svcStats{}
			svcMap[ev.Service] = ss
		}
		ss.total++
		if ev.IsBlocked {
			ss.blocked++
		}

		// Per-client.
		cs, ok := clientMap[ev.ClientIP]
		if !ok {
			cs = &clientStats{}
			clientMap[ev.ClientIP] = cs
		}
		cs.total++
		if ev.IsBlocked {
			cs.blocked++
		}

		uris[ev.URI]++
	}

	// Build sorted hour buckets.
	hourCounts := make([]HourCount, 0, len(hourMap))
	for k, v := range hourMap {
		hourCounts = append(hourCounts, HourCount{
			Hour:    k,
			Count:   v.total,
			Blocked: v.blocked,
			Logged:  v.total - v.blocked,
		})
	}
	sort.Slice(hourCounts, func(i, j int) bool {
		return hourCounts[i].Hour < hourCounts[j].Hour
	})

	// Build service counts (for top_services).
	svcCounts := make([]ServiceCount, 0, len(svcMap))
	for k, v := range svcMap {
		svcCounts = append(svcCounts, ServiceCount{
			Service: k,
			Count:   v.total,
			Blocked: v.blocked,
			Logged:  v.total - v.blocked,
		})
	}
	sort.Slice(svcCounts, func(i, j int) bool {
		return svcCounts[i].Count > svcCounts[j].Count
	})
	if len(svcCounts) > 20 {
		svcCounts = svcCounts[:20]
	}

	// Build service breakdown (same data, different type for convenience).
	svcBreakdown := make([]ServiceDetail, 0, len(svcMap))
	for k, v := range svcMap {
		svcBreakdown = append(svcBreakdown, ServiceDetail{
			Service: k,
			Total:   v.total,
			Blocked: v.blocked,
			Logged:  v.total - v.blocked,
		})
	}
	sort.Slice(svcBreakdown, func(i, j int) bool {
		return svcBreakdown[i].Total > svcBreakdown[j].Total
	})

	// Build client counts.
	clientCounts := make([]ClientCount, 0, len(clientMap))
	for k, v := range clientMap {
		clientCounts = append(clientCounts, ClientCount{
			Client:  k,
			Count:   v.total,
			Blocked: v.blocked,
		})
	}
	sort.Slice(clientCounts, func(i, j int) bool {
		return clientCounts[i].Count > clientCounts[j].Count
	})
	if len(clientCounts) > 20 {
		clientCounts = clientCounts[:20]
	}

	return SummaryResponse{
		TotalEvents:      len(events),
		BlockedEvents:    totalBlocked,
		LoggedEvents:     totalLogged,
		UniqueClients:    len(clientMap),
		UniqueServices:   len(svcMap),
		EventsByHour:     hourCounts,
		TopServices:      svcCounts,
		TopClients:       clientCounts,
		TopURIs:          topN(uris, 20, func(k string, c int) URICount { return URICount{k, c} }),
		ServiceBreakdown: svcBreakdown,
		RecentEvents:     recentEvents,
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

// Services returns per-service breakdown.
func (s *Store) Services(hours int) ServicesResponse {
	return computeServices(s.SnapshotSince(hours))
}

func (s *Store) ServicesRange(start, end time.Time) ServicesResponse {
	return computeServices(s.SnapshotRange(start, end))
}

func computeServices(events []Event) ServicesResponse {
	type counts struct {
		total, blocked int
	}
	m := make(map[string]*counts)

	for i := range events {
		ev := &events[i]
		c, ok := m[ev.Service]
		if !ok {
			c = &counts{}
			m[ev.Service] = c
		}
		c.total++
		if ev.IsBlocked {
			c.blocked++
		}
	}

	result := make([]ServiceDetail, 0, len(m))
	for svc, c := range m {
		result = append(result, ServiceDetail{
			Service: svc,
			Total:   c.total,
			Blocked: c.blocked,
			Logged:  c.total - c.blocked,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Total > result[j].Total
	})

	return ServicesResponse{Services: result}
}

// IPLookup returns all events and stats for a specific IP address.
func (s *Store) IPLookup(ip string, hours int) IPLookupResponse {
	events := s.SnapshotSince(hours)

	var matched []Event
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].ClientIP == ip {
			matched = append(matched, events[i])
		}
	}

	resp := IPLookupResponse{
		IP:     ip,
		Total:  len(matched),
		Events: matched,
	}

	// Compute per-service breakdown, first/last seen, blocked count.
	type counts struct {
		total, blocked int
	}
	svcMap := make(map[string]*counts)

	for i := range matched {
		ev := &matched[i]
		if ev.IsBlocked {
			resp.Blocked++
		}

		// First/last seen (matched is newest-first).
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
	}

	svcList := make([]ServiceDetail, 0, len(svcMap))
	for svc, c := range svcMap {
		svcList = append(svcList, ServiceDetail{
			Service: svc,
			Total:   c.total,
			Blocked: c.blocked,
			Logged:  c.total - c.blocked,
		})
	}
	sort.Slice(svcList, func(i, j int) bool {
		return svcList[i].Total > svcList[j].Total
	})
	resp.Services = svcList

	return resp
}

// TopBlockedIPs returns the top N IPs by blocked count.
func (s *Store) TopBlockedIPs(hours, n int) []TopBlockedIP {
	events := s.SnapshotSince(hours)

	type ipStats struct {
		total, blocked int
		first, last    time.Time
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

// TopTargetedURIs returns the top N URIs by total event count.
func (s *Store) TopTargetedURIs(hours, n int) []TopTargetedURI {
	events := s.SnapshotSince(hours)

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

// --- helpers ---

// topN is a generic helper that converts a map into a sorted top-N slice.
func topN[T any](m map[string]int, n int, conv func(string, int) T) []T {
	type kv struct {
		key   string
		count int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].count > pairs[j].count
	})
	if len(pairs) > n {
		pairs = pairs[:n]
	}
	result := make([]T, len(pairs))
	for i, p := range pairs {
		result[i] = conv(p.key, p.count)
	}
	return result
}
