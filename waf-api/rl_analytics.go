package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── Caddy access log JSON structure ────────────────────────────────

// AccessLogEntry is the JSON structure Caddy writes for each request.
type AccessLogEntry struct {
	Level       string              `json:"level"`
	Ts          string              `json:"ts"` // wall clock format: "2026/02/22 12:43:20"
	Logger      string              `json:"logger"`
	Msg         string              `json:"msg"`
	Request     AccessLogReq        `json:"request"`
	RespHeaders map[string][]string `json:"resp_headers"`
	Status      int                 `json:"status"`
	Size        int                 `json:"size"`
	Duration    float64             `json:"duration"`
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
	Country   string    `json:"country,omitempty"`
	Service   string    `json:"service"`
	Method    string    `json:"method"`
	URI       string    `json:"uri"`
	UserAgent string    `json:"user_agent"`
	Source    string    `json:"source,omitempty"` // "" = rate_limited, "ipsum" = ipsum_blocked
}

// isIpsumBlocked checks if the response headers contain X-Blocked-By: ipsum.
func isIpsumBlocked(headers map[string][]string) bool {
	vals, ok := headers["X-Blocked-By"]
	if !ok {
		return false
	}
	for _, v := range vals {
		if v == "ipsum" {
			return true
		}
	}
	return false
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

	path       string
	offset     int64
	offsetFile string // persistent offset file (empty = don't persist)

	// maxAge is the maximum age of events to retain. Events older than this
	// are evicted during each Load() call. Zero means no eviction.
	maxAge time.Duration

	// geoIP is an optional GeoIP store for country enrichment.
	geoIP *GeoIPStore
}

func NewAccessLogStore(path string) *AccessLogStore {
	return &AccessLogStore{path: path}
}

// SetOffsetFile configures a file path to persist the access log read offset
// across restarts. Without this, the entire log is re-parsed on each startup.
func (s *AccessLogStore) SetOffsetFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offsetFile = path
	if data, err := os.ReadFile(path); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil && v > 0 {
			s.offset = v
			log.Printf("restored access log offset %d from %s", v, path)
		}
	}
}

// saveOffset writes the current offset to the persistent offset file (if configured).
func (s *AccessLogStore) saveOffset() {
	if s.offsetFile == "" {
		return
	}
	data := []byte(strconv.FormatInt(s.offset, 10) + "\n")
	if err := os.WriteFile(s.offsetFile, data, 0644); err != nil {
		log.Printf("error saving access log offset to %s: %v", s.offsetFile, err)
	}
}

// SetGeoIP configures the GeoIP store for country enrichment of events.
func (s *AccessLogStore) SetGeoIP(g *GeoIPStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.geoIP = g
}

// SetMaxAge configures the TTL for in-memory event retention.
// Events older than maxAge are evicted during each Load() cycle.
func (s *AccessLogStore) SetMaxAge(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxAge = d
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
		s.saveOffset()
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
	reader := bufio.NewReaderSize(f, 64*1024)
	// Use ReadBytes instead of Scanner — no line length limit, consistent
	// with the audit log reader. Access log lines are typically small but
	// this avoids a latent stall risk if a line ever exceeds 1MB.
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
		}
		if len(line) > 0 {
			var entry AccessLogEntry
			if jsonErr := json.Unmarshal(line, &entry); jsonErr == nil {
				// Collect 429 (rate limited) and ipsum-blocked (403 + X-Blocked-By: ipsum) responses.
				isRateLimit := entry.Status == 429
				isIpsum := entry.Status == 403 && isIpsumBlocked(entry.RespHeaders)
				if isRateLimit || isIpsum {
					ts := parseTimestamp(entry.Ts)
					ua := ""
					if vals, ok := entry.Request.Headers["User-Agent"]; ok && len(vals) > 0 {
						ua = vals[0]
					}

					evt := RateLimitEvent{
						Timestamp: ts,
						ClientIP:  entry.Request.ClientIP,
						Service:   entry.Request.Host,
						Method:    entry.Request.Method,
						URI:       entry.Request.URI,
						UserAgent: ua,
					}
					if isIpsum {
						evt.Source = "ipsum"
					}
					// Enrich with country from Cf-Ipcountry header or MMDB lookup.
					if s.geoIP != nil {
						cfCountry := headerValue(entry.Request.Headers, "Cf-Ipcountry")
						evt.Country = s.geoIP.Resolve(entry.Request.ClientIP, cfCountry)
					}
					newEvents = append(newEvents, evt)
				}
			}
			// skip malformed lines silently — high volume log
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("error reading combined access log: %v", err)
			}
			break
		}
	}

	newOffset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		log.Printf("error getting combined access log offset: %v", err)
	} else {
		s.offset = newOffset
		s.saveOffset()
	}

	if len(newEvents) > 0 {
		s.mu.Lock()
		s.events = append(s.events, newEvents...)
		s.mu.Unlock()
		rlCount, ipsumCount := 0, 0
		for _, e := range newEvents {
			if e.Source == "ipsum" {
				ipsumCount++
			} else {
				rlCount++
			}
		}
		log.Printf("loaded %d new events (%d rate-limit, %d ipsum) — %d total", len(newEvents), rlCount, ipsumCount, s.EventCount())
	}

	// Evict events older than maxAge.
	s.evict()
}

// evict removes events older than maxAge from the in-memory store.
func (s *AccessLogStore) evict() {
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
		remaining := make([]RateLimitEvent, len(s.events)-idx)
		copy(remaining, s.events[idx:])
		s.events = remaining
		log.Printf("evicted %d events older than %s (%d remaining)", evicted, s.maxAge, len(s.events))
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

// snapshotRange returns a copy of events within [start, end].
func (s *AccessLogStore) snapshotRange(start, end time.Time) []RateLimitEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []RateLimitEvent
	for _, e := range s.events {
		if !e.Timestamp.Before(start) && !e.Timestamp.After(end) {
			result = append(result, e)
		}
	}
	return result
}

// ─── Converter: RateLimitEvent → Event ──────────────────────────────

// RateLimitEventToEvent converts a RateLimitEvent into the unified Event type
// so that 429s can be merged into the shared event stream.
func RateLimitEventToEvent(rle RateLimitEvent) Event {
	eventType := "rate_limited"
	status := 429
	if rle.Source == "ipsum" {
		eventType = "ipsum_blocked"
		status = 403
	}
	return Event{
		ID:             generateUUIDv7(),
		Timestamp:      rle.Timestamp,
		ClientIP:       rle.ClientIP,
		Country:        rle.Country,
		Service:        rle.Service,
		Method:         rle.Method,
		URI:            rle.URI,
		Protocol:       "HTTP/2.0", // access log doesn't differentiate per-request; default
		IsBlocked:      true,
		ResponseStatus: status,
		UserAgent:      rle.UserAgent,
		EventType:      eventType,
	}
}

// SnapshotAsEvents returns 429 events converted to the unified Event type.
func (s *AccessLogStore) SnapshotAsEvents(hours int) []Event {
	rlEvents := s.snapshotSince(hours)
	events := make([]Event, len(rlEvents))
	for i, rle := range rlEvents {
		events[i] = RateLimitEventToEvent(rle)
	}
	return events
}

// SnapshotAsEventsRange returns 429 events within [start, end] as unified Events.
func (s *AccessLogStore) SnapshotAsEventsRange(start, end time.Time) []Event {
	rlEvents := s.snapshotRange(start, end)
	events := make([]Event, len(rlEvents))
	for i, rle := range rlEvents {
		events[i] = RateLimitEventToEvent(rle)
	}
	return events
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
