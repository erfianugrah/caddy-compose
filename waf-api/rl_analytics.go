package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"sort"
	"sync"
	"time"
)

// ─── Caddy access log JSON structure ────────────────────────────────

// AccessLogEntry is the JSON structure Caddy writes for each request.
type AccessLogEntry struct {
	Level    string       `json:"level"`
	Ts       string       `json:"ts"` // wall clock format: "2026/02/22 12:43:20"
	Logger   string       `json:"logger"`
	Msg      string       `json:"msg"`
	Request  AccessLogReq `json:"request"`
	Status   int          `json:"status"`
	Size     int          `json:"size"`
	Duration float64      `json:"duration"`
}

type AccessLogReq struct {
	RemoteIP string              `json:"remote_ip"`
	ClientIP string              `json:"client_ip"`
	Proto    string              `json:"proto"`
	Method   string              `json:"method"`
	Host     string              `json:"host"`
	URI      string              `json:"uri"`
	Headers  map[string][]string `json:"headers"`
}

// ─── Rate Limit Event (parsed 429) ─────────────────────────────────

type RateLimitEvent struct {
	Timestamp time.Time `json:"timestamp"`
	ClientIP  string    `json:"client_ip"`
	Service   string    `json:"service"`
	Method    string    `json:"method"`
	URI       string    `json:"uri"`
	UserAgent string    `json:"user_agent"`
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

// ─── Access Log Store (tails combined-access.log for 429s) ──────────

type AccessLogStore struct {
	mu     sync.RWMutex
	events []RateLimitEvent

	path   string
	offset int64
}

func NewAccessLogStore(path string) *AccessLogStore {
	return &AccessLogStore{path: path}
}

// Load reads new lines from the combined access log and extracts 429 events.
func (s *AccessLogStore) Load() {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("combined access log not found at %s, will retry", s.path)
			return
		}
		log.Printf("error opening combined access log: %v", err)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.Printf("error stat combined access log: %v", err)
		return
	}

	// Detect rotation.
	if info.Size() < s.offset {
		log.Printf("combined access log rotated (size %d < offset %d), re-reading", info.Size(), s.offset)
		s.offset = 0
		s.mu.Lock()
		s.events = nil
		s.mu.Unlock()
	}

	if info.Size() == s.offset {
		return
	}

	if s.offset > 0 {
		if _, err := f.Seek(s.offset, io.SeekStart); err != nil {
			log.Printf("error seeking combined access log: %v", err)
			return
		}
	}

	var newEvents []RateLimitEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry AccessLogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // skip malformed lines silently — high volume log
		}

		// Only collect 429 responses.
		if entry.Status != 429 {
			continue
		}

		ts := parseTimestamp(entry.Ts)
		ua := ""
		if vals, ok := entry.Request.Headers["User-Agent"]; ok && len(vals) > 0 {
			ua = vals[0]
		}

		newEvents = append(newEvents, RateLimitEvent{
			Timestamp: ts,
			ClientIP:  entry.Request.ClientIP,
			Service:   entry.Request.Host,
			Method:    entry.Request.Method,
			URI:       entry.Request.URI,
			UserAgent: ua,
		})
	}

	if err := scanner.Err(); err != nil {
		log.Printf("error scanning combined access log: %v", err)
	}

	newOffset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		log.Printf("error getting combined access log offset: %v", err)
	} else {
		s.offset = newOffset
	}

	if len(newEvents) > 0 {
		s.mu.Lock()
		s.events = append(s.events, newEvents...)
		s.mu.Unlock()
		log.Printf("loaded %d new 429 events (%d total)", len(newEvents), s.EventCount())
	}
}

// StartTailing periodically loads new 429 events.
func (s *AccessLogStore) StartTailing(interval time.Duration) {
	s.Load()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.Load()
		}
	}()
}

func (s *AccessLogStore) EventCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// snapshotSince returns a copy of events within the given hours window (0 = all).
func (s *AccessLogStore) snapshotSince(hours int) []RateLimitEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if hours <= 0 {
		cp := make([]RateLimitEvent, len(s.events))
		copy(cp, s.events)
		return cp
	}

	cutoff := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	var result []RateLimitEvent
	for _, e := range s.events {
		if e.Timestamp.After(cutoff) {
			result = append(result, e)
		}
	}
	return result
}

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
	if len(topClients) > 20 {
		topClients = topClients[:20]
	}

	var topServices []RLServiceCount
	for svc, cnt := range serviceCounts {
		topServices = append(topServices, RLServiceCount{Service: svc, Count: cnt})
	}
	sort.Slice(topServices, func(i, j int) bool { return topServices[i].Count > topServices[j].Count })
	if len(topServices) > 20 {
		topServices = topServices[:20]
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
	if len(topURIs) > 20 {
		topURIs = topURIs[:20]
	}

	var hourCounts []HourCount
	for h, c := range hourBuckets {
		hourCounts = append(hourCounts, HourCount{Hour: h, Count: c, Blocked: c})
	}
	sort.Slice(hourCounts, func(i, j int) bool { return hourCounts[i].Hour < hourCounts[j].Hour })

	// Recent events (newest first, up to 20).
	recent := make([]RateLimitEvent, len(events))
	copy(recent, events)
	sort.Slice(recent, func(i, j int) bool { return recent[i].Timestamp.After(recent[j].Timestamp) })
	if len(recent) > 20 {
		recent = recent[:20]
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
