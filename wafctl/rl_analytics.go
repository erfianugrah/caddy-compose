package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// ─── Rate Limit Advisor (scans raw access log for request rate distribution) ──

// RateAdvisorRequest holds query parameters for the advisor endpoint.
type RateAdvisorRequest struct {
	Window  string // "1m", "5m", "10m"
	Service string // filter by host
	Path    string // filter by URI prefix
	Method  string // filter by HTTP method
	Limit   int    // top N clients (default 50)
}

// RateAdvisorClient represents one client's request rate.
type RateAdvisorClient struct {
	ClientIP string `json:"client_ip"`
	Country  string `json:"country,omitempty"`
	Requests int    `json:"requests"`
	TopPaths []struct {
		Path  string `json:"path"`
		Count int    `json:"count"`
	} `json:"top_paths"`
}

// RateAdvisorResponse is the API response for the advisor endpoint.
type RateAdvisorResponse struct {
	Window        string              `json:"window"`
	Service       string              `json:"service,omitempty"`
	Path          string              `json:"path,omitempty"`
	Method        string              `json:"method,omitempty"`
	TotalRequests int                 `json:"total_requests"`
	UniqueClients int                 `json:"unique_clients"`
	Clients       []RateAdvisorClient `json:"clients"`
	Percentiles   struct {
		P50 int `json:"p50"`
		P75 int `json:"p75"`
		P90 int `json:"p90"`
		P95 int `json:"p95"`
		P99 int `json:"p99"`
	} `json:"percentiles"`
}

// parseAdvisorWindow parses window strings like "1m", "5m", "10m", "1h".
func parseAdvisorWindow(s string) time.Duration {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "1m":
		return time.Minute
	case "5m":
		return 5 * time.Minute
	case "10m":
		return 10 * time.Minute
	case "1h":
		return time.Hour
	default:
		return time.Minute // default 1m
	}
}

// scanAccessLogForRates reads recent entries from the combined access log and
// computes per-client request rates within the given time window. It does a
// tail-read (last tailBytes of the file) to avoid scanning the entire log.
func (s *AccessLogStore) ScanRates(req RateAdvisorRequest) RateAdvisorResponse {
	window := parseAdvisorWindow(req.Window)
	limit := req.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	cutoff := time.Now().Add(-window)

	// Tail-read: seek to max(0, fileSize - tailBytes) and scan forward.
	const tailBytes int64 = 20 * 1024 * 1024 // 20 MB covers ~10 min at typical traffic

	f, err := os.Open(s.path)
	if err != nil {
		log.Printf("advisor: error opening access log: %v", err)
		return RateAdvisorResponse{Window: req.Window}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return RateAdvisorResponse{Window: req.Window}
	}

	seekPos := info.Size() - tailBytes
	if seekPos < 0 {
		seekPos = 0
	}
	if _, err := f.Seek(seekPos, io.SeekStart); err != nil {
		return RateAdvisorResponse{Window: req.Window}
	}

	// If we seeked mid-file, skip the first partial line.
	reader := bufio.NewReaderSize(f, 64*1024)
	if seekPos > 0 {
		_, _ = reader.ReadBytes('\n') // discard partial line
	}

	// Snapshot geoIP for country enrichment.
	s.mu.RLock()
	geoIP := s.geoIP
	s.mu.RUnlock()

	// Count requests per client IP, and track per-client top paths.
	type clientData struct {
		requests int
		country  string
		paths    map[string]int
	}
	clients := make(map[string]*clientData)
	totalRequests := 0

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
		}
		if len(line) > 0 {
			var entry AccessLogEntry
			if jsonErr := json.Unmarshal(line, &entry); jsonErr == nil {
				ts := parseTimestamp(entry.Ts)
				if ts.Before(cutoff) {
					if err != nil {
						break
					}
					continue
				}

				// Apply filters.
				if req.Service != "" && !strings.EqualFold(entry.Request.Host, req.Service) {
					if err != nil {
						break
					}
					continue
				}
				if req.Path != "" && !strings.HasPrefix(entry.Request.URI, req.Path) {
					if err != nil {
						break
					}
					continue
				}
				if req.Method != "" && !strings.EqualFold(entry.Request.Method, req.Method) {
					if err != nil {
						break
					}
					continue
				}

				ip := entry.Request.ClientIP
				totalRequests++

				cd, ok := clients[ip]
				if !ok {
					country := ""
					if geoIP != nil {
						cfCountry := headerValue(entry.Request.Headers, "Cf-Ipcountry")
						country = geoIP.Resolve(ip, cfCountry)
					}
					cd = &clientData{country: country, paths: make(map[string]int)}
					clients[ip] = cd
				}
				cd.requests++

				// Track path (strip query string).
				path := entry.Request.URI
				if idx := strings.IndexByte(path, '?'); idx >= 0 {
					path = path[:idx]
				}
				cd.paths[path]++
			}
		}
		if err != nil {
			break
		}
	}

	// Build sorted client list.
	result := make([]RateAdvisorClient, 0, len(clients))
	for ip, cd := range clients {
		rac := RateAdvisorClient{
			ClientIP: ip,
			Country:  cd.country,
			Requests: cd.requests,
		}
		// Top 3 paths for this client.
		type pathCount struct {
			path  string
			count int
		}
		paths := make([]pathCount, 0, len(cd.paths))
		for p, c := range cd.paths {
			paths = append(paths, pathCount{p, c})
		}
		sort.Slice(paths, func(i, j int) bool { return paths[i].count > paths[j].count })
		topN := 3
		if len(paths) < topN {
			topN = len(paths)
		}
		for _, p := range paths[:topN] {
			rac.TopPaths = append(rac.TopPaths, struct {
				Path  string `json:"path"`
				Count int    `json:"count"`
			}{p.path, p.count})
		}
		result = append(result, rac)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Requests > result[j].Requests })

	if len(result) > limit {
		result = result[:limit]
	}

	// Compute percentiles from ALL clients (not just top N).
	allCounts := make([]int, 0, len(clients))
	for _, cd := range clients {
		allCounts = append(allCounts, cd.requests)
	}
	sort.Ints(allCounts)

	percentile := func(pct int) int {
		if len(allCounts) == 0 {
			return 0
		}
		idx := (pct*len(allCounts) - 1) / 100
		if idx < 0 {
			idx = 0
		}
		if idx >= len(allCounts) {
			idx = len(allCounts) - 1
		}
		return allCounts[idx]
	}

	resp := RateAdvisorResponse{
		Window:        req.Window,
		Service:       req.Service,
		Path:          req.Path,
		Method:        req.Method,
		TotalRequests: totalRequests,
		UniqueClients: len(clients),
		Clients:       result,
	}
	resp.Percentiles.P50 = percentile(50)
	resp.Percentiles.P75 = percentile(75)
	resp.Percentiles.P90 = percentile(90)
	resp.Percentiles.P95 = percentile(95)
	resp.Percentiles.P99 = percentile(99)

	return resp
}

// ─── Access Log Store (tails combined-access.log for 429s) ──────────

type AccessLogStore struct {
	mu     sync.RWMutex
	events []RateLimitEvent

	path       string
	offset     atomic.Int64
	offsetFile string // persistent offset file (empty = don't persist)

	// JSONL event persistence (empty = don't persist events)
	eventFile string

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
			s.offset.Store(v)
			log.Printf("restored access log offset %d from %s", v, path)
		}
	}
}

// saveOffset writes the current offset to the persistent offset file (if configured).
func (s *AccessLogStore) saveOffset() {
	if s.offsetFile == "" {
		return
	}
	data := []byte(strconv.FormatInt(s.offset.Load(), 10) + "\n")
	if err := atomicWriteFile(s.offsetFile, data, 0644); err != nil {
		log.Printf("error saving access log offset to %s: %v", s.offsetFile, err)
	}
}

// SetGeoIP configures the GeoIP store for country enrichment of events.
func (s *AccessLogStore) SetGeoIP(g *GeoIPStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.geoIP = g
}

// SetEventFile configures a JSONL file for persistent rate limit event storage.
// On startup, existing events are loaded from this file so that parsed
// events survive restarts without re-parsing the raw access log.
func (s *AccessLogStore) SetEventFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventFile = path
	// Restore events from JSONL file.
	events, err := loadRLEventsFromJSONL(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("error loading RL events from %s: %v", path, err)
		}
		return
	}
	s.events = events
	log.Printf("restored %d RL events from %s", len(events), path)
}

// appendEventsToJSONL appends rate limit events to the JSONL file.
func (s *AccessLogStore) appendEventsToJSONL(events []RateLimitEvent) {
	if s.eventFile == "" || len(events) == 0 {
		return
	}
	f, err := os.OpenFile(s.eventFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("error opening RL event file for append: %v", err)
		return
	}
	defer f.Close()

	for i := range events {
		data, err := json.Marshal(events[i])
		if err != nil {
			continue
		}
		f.Write(data)
		f.Write([]byte{'\n'})
	}
}

// compactEventFile rewrites the JSONL file with only the current in-memory events.
// Acquires a read lock internally — do NOT call while holding s.mu (use
// compactEventFileLocked instead).
func (s *AccessLogStore) compactEventFile() {
	if s.eventFile == "" {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.compactEventFileLocked()
}

// compactEventFileLocked rewrites the JSONL file with the current in-memory
// events. The caller MUST hold s.mu (at least RLock).
func (s *AccessLogStore) compactEventFileLocked() {
	if s.eventFile == "" {
		return
	}
	tmp := s.eventFile + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		log.Printf("error creating temp RL event file for compaction: %v", err)
		return
	}

	count := len(s.events)
	for i := range s.events {
		data, err := json.Marshal(s.events[i])
		if err != nil {
			continue
		}
		f.Write(data)
		f.Write([]byte{'\n'})
	}

	f.Sync()
	f.Close()
	if err := os.Rename(tmp, s.eventFile); err != nil {
		log.Printf("error renaming compacted RL event file: %v", err)
		return
	}
	log.Printf("compacted RL event file: %d events", count)
}

// loadRLEventsFromJSONL reads rate limit events from a JSONL file.
func loadRLEventsFromJSONL(path string) ([]RateLimitEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []RateLimitEvent
	reader := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
		}
		if len(line) > 0 {
			var ev RateLimitEvent
			if jsonErr := json.Unmarshal(line, &ev); jsonErr == nil {
				events = append(events, ev)
			}
		}
		if err != nil {
			break
		}
	}
	return events, nil
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
	curOffset := s.offset.Load()
	if info.Size() < curOffset {
		log.Printf("combined access log rotated (size %d < offset %d), re-reading", info.Size(), curOffset)
		s.offset.Store(0)
		curOffset = 0
		s.saveOffset()
		// Don't clear in-memory events — with copytruncate rotation the
		// already-parsed events are still valid. The eviction loop will
		// age them out naturally based on maxAge.
	}

	if info.Size() == curOffset {
		// No new data, but still run eviction for time-based cleanup.
		s.evict()
		return
	}

	if curOffset > 0 {
		if _, err := f.Seek(curOffset, io.SeekStart); err != nil {
			log.Printf("error seeking combined access log: %v", err)
			return
		}
	}

	// Snapshot geoIP reference under lock to avoid a data race with SetGeoIP.
	s.mu.RLock()
	geoIP := s.geoIP
	s.mu.RUnlock()

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
					if geoIP != nil {
						cfCountry := headerValue(entry.Request.Headers, "Cf-Ipcountry")
						evt.Country = geoIP.Resolve(entry.Request.ClientIP, cfCountry)
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
		s.offset.Store(newOffset)
		s.saveOffset()
	}

	if len(newEvents) > 0 {
		s.mu.Lock()
		s.events = append(s.events, newEvents...)
		s.mu.Unlock()
		// Persist new events to JSONL.
		s.appendEventsToJSONL(newEvents)
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
		// Compact the JSONL file synchronously to avoid racing with
		// appendEventsToJSONL on the next tail cycle. Use the locked
		// variant since we already hold s.mu.
		s.compactEventFileLocked()
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

// Stats returns health-check information about the access log store.
func (s *AccessLogStore) Stats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := map[string]any{
		"events":     len(s.events),
		"log_file":   s.path,
		"offset":     s.offset.Load(),
		"max_age":    s.maxAge.String(),
		"event_file": s.eventFile,
	}
	if fi, err := os.Stat(s.path); err == nil {
		stats["log_size"] = fi.Size()
	}
	if len(s.events) > 0 {
		stats["oldest_event"] = s.events[0].Timestamp
		stats["newest_event"] = s.events[len(s.events)-1].Timestamp
	}
	return stats
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
		if !e.Timestamp.Before(cutoff) {
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
		re, err := regexp.Compile(c.Value)
		if err != nil {
			return false
		}
		return re.MatchString(target)
	}
	return false
}
