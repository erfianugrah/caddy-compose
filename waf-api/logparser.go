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
}

func NewStore(path string) *Store {
	return &Store{path: path}
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

	return Event{
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
	}
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

// Summary computes aggregate stats from the current events.
func (s *Store) Summary(hours int) SummaryResponse {
	events := s.SnapshotSince(hours)

	var blocked, logged int
	clients := make(map[string]int)
	services := make(map[string]int)
	uris := make(map[string]int)
	hourBuckets := make(map[string]int)

	for i := range events {
		ev := &events[i]
		if ev.IsBlocked {
			blocked++
		} else {
			logged++
		}
		clients[ev.ClientIP]++
		services[ev.Service]++
		uris[ev.URI]++

		hourKey := ev.Timestamp.Truncate(time.Hour).Format(time.RFC3339)
		hourBuckets[hourKey]++
	}

	return SummaryResponse{
		TotalEvents:    len(events),
		BlockedEvents:  blocked,
		LoggedEvents:   logged,
		UniqueClients:  len(clients),
		UniqueServices: len(services),
		EventsByHour:   sortedHours(hourBuckets),
		TopServices:    topN(services, 20, func(k string, c int) ServiceCount { return ServiceCount{k, c} }),
		TopClients:     topN(clients, 20, func(k string, c int) ClientCount { return ClientCount{k, c} }),
		TopURIs:        topN(uris, 20, func(k string, c int) URICount { return URICount{k, c} }),
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
	events := s.SnapshotSince(hours)

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

// --- helpers ---

func sortedHours(m map[string]int) []HourCount {
	result := make([]HourCount, 0, len(m))
	for k, v := range m {
		result = append(result, HourCount{Hour: k, Count: v})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Hour < result[j].Hour
	})
	return result
}

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
