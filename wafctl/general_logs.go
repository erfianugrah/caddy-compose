package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── General Log Store ──────────────────────────────────────────────
// Tails the Caddy combined access log capturing ALL entries (not just
// 429/ipsum like AccessLogStore). Provides a general-purpose log viewer
// for debugging CSP, CORS, security headers, network errors, latency, etc.

// GeneralLogStore captures all access log entries for general debugging.
type GeneralLogStore struct {
	mu     sync.RWMutex
	events []GeneralLogEvent

	path       string
	offset     atomic.Int64
	offsetFile string

	eventFile string

	maxAge   time.Duration
	maxItems int

	geoIP *GeoIPStore

	generation atomic.Int64

	// sampleRate controls what fraction of normal (2xx) responses are stored.
	// 0.0 = store none, 1.0 = store all, 0.1 = store 10%.
	// Non-2xx responses (errors, redirects, auth failures) are always stored.
	sampleRate float64
	sampleN    uint64 // monotonic counter for deterministic sampling
}

func NewGeneralLogStore(path string) *GeneralLogStore {
	return &GeneralLogStore{path: path, sampleRate: 1.0}
}

// SetSampleRate configures the fraction of normal (2xx) responses to store.
// Non-2xx responses are always stored regardless of this setting.
// rate=1.0 stores everything (default), rate=0.1 stores 10% of 2xx traffic.
func (s *GeneralLogStore) SetSampleRate(rate float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rate < 0 {
		rate = 0
	}
	if rate > 1 {
		rate = 1
	}
	s.sampleRate = rate
}

// ─── Offset Persistence ─────────────────────────────────────────────

func (s *GeneralLogStore) SetOffsetFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offsetFile = path
	if data, err := os.ReadFile(path); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil && v > 0 {
			s.offset.Store(v)
			log.Printf("restored general log offset %d from %s", v, path)
		}
	}
}

func (s *GeneralLogStore) saveOffset() {
	if s.offsetFile == "" {
		return
	}
	data := []byte(strconv.FormatInt(s.offset.Load(), 10) + "\n")
	if err := atomicWriteFile(s.offsetFile, data, 0644); err != nil {
		log.Printf("error saving general log offset to %s: %v", s.offsetFile, err)
	}
}

// ─── JSONL Persistence ──────────────────────────────────────────────

func (s *GeneralLogStore) SetEventFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventFile = path
	events, err := loadGeneralEventsFromJSONL(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("error loading general events from %s: %v", path, err)
		}
		return
	}
	s.events = events
	log.Printf("restored %d general log events from %s", len(events), path)
}

func (s *GeneralLogStore) appendEventsToJSONL(events []GeneralLogEvent) {
	if s.eventFile == "" || len(events) == 0 {
		return
	}
	f, err := os.OpenFile(s.eventFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("error opening general event file for append: %v", err)
		return
	}
	defer f.Close()

	for i := range events {
		data, err := json.Marshal(events[i])
		if err != nil {
			continue
		}
		data = append(data, '\n')
		if _, err := f.Write(data); err != nil {
			log.Printf("error writing general event to JSONL: %v", err)
			return
		}
	}
	if err := f.Sync(); err != nil {
		log.Printf("error syncing general event file: %v", err)
	}
}

func (s *GeneralLogStore) compactEventFileLocked() {
	if s.eventFile == "" {
		return
	}
	// Snapshot events under caller's lock, then write to disk.
	snapshot := make([]GeneralLogEvent, len(s.events))
	copy(snapshot, s.events)
	writeCompactedGeneralEvents(s.eventFile, snapshot)
}

// writeCompactedGeneralEvents atomically rewrites a JSONL file from a snapshot.
func writeCompactedGeneralEvents(path string, events []GeneralLogEvent) {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		log.Printf("error creating temp general event file for compaction: %v", err)
		return
	}

	count := len(events)
	var writeErr error
	for i := range events {
		data, err := json.Marshal(events[i])
		if err != nil {
			continue
		}
		data = append(data, '\n')
		if _, err := f.Write(data); err != nil {
			writeErr = err
			break
		}
	}

	if writeErr != nil {
		f.Close()
		os.Remove(tmp)
		log.Printf("error writing compacted general event file: %v", writeErr)
		return
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		log.Printf("error syncing compacted general event file: %v", err)
		return
	}
	f.Close()
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("error renaming compacted general event file: %v", err)
		return
	}
	log.Printf("compacted general event file: %d events", count)
}

func loadGeneralEventsFromJSONL(path string) ([]GeneralLogEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []GeneralLogEvent
	reader := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
		}
		if len(line) > 0 {
			var ev GeneralLogEvent
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

// ─── Configuration ──────────────────────────────────────────────────

func (s *GeneralLogStore) SetMaxAge(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxAge = d
}

func (s *GeneralLogStore) SetMaxItems(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxItems = n
}

func (s *GeneralLogStore) SetGeoIP(g *GeoIPStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.geoIP = g
}

// ─── Load & Tail ────────────────────────────────────────────────────

func (s *GeneralLogStore) Load() {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("combined access log (general) not found at %s, will retry", s.path)
			return
		}
		log.Printf("error opening combined access log (general): %v", err)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.Printf("error stat combined access log (general): %v", err)
		return
	}

	curOffset := s.offset.Load()
	if info.Size() < curOffset {
		log.Printf("combined access log (general) rotated (size %d < offset %d), re-reading", info.Size(), curOffset)
		s.offset.Store(0)
		curOffset = 0
		s.saveOffset()
	}

	if info.Size() == curOffset {
		s.evict()
		return
	}

	if curOffset > 0 {
		if _, err := f.Seek(curOffset, io.SeekStart); err != nil {
			log.Printf("error seeking combined access log (general): %v", err)
			return
		}
	}

	s.mu.RLock()
	geoIP := s.geoIP
	s.mu.RUnlock()

	s.mu.RLock()
	sampleRate := s.sampleRate
	s.mu.RUnlock()

	var newEvents []GeneralLogEvent
	var sampled int
	reader := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
		}
		if len(line) > 0 {
			var entry AccessLogEntry
			if jsonErr := json.Unmarshal(line, &entry); jsonErr == nil {
				// Sampling: always keep non-2xx responses (errors, security events).
				// For 2xx responses, apply the configured sample rate.
				if sampleRate < 1.0 && entry.Status >= 200 && entry.Status < 300 {
					s.sampleN++
					// Deterministic modulo sampling: keep if (counter % (1/rate)) == 0.
					interval := uint64(1.0 / sampleRate)
					if interval < 1 {
						interval = 1
					}
					if s.sampleN%interval != 0 {
						sampled++
						if err != nil {
							break
						}
						continue
					}
				}
				evt := parseGeneralLogEvent(entry, geoIP)
				newEvents = append(newEvents, evt)
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("error reading combined access log (general): %v", err)
			}
			break
		}
	}
	_ = sampled // suppress unused warning when logging is disabled

	newOffset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		log.Printf("error getting combined access log (general) offset: %v", err)
	} else {
		s.offset.Store(newOffset)
		s.saveOffset()
	}

	if len(newEvents) > 0 {
		s.mu.Lock()
		s.events = append(s.events, newEvents...)
		s.mu.Unlock()
		s.generation.Add(1)
		s.appendEventsToJSONL(newEvents)
		log.Printf("loaded %d new general log events — %d total", len(newEvents), s.EventCount())
	}

	s.evict()
}

func (s *GeneralLogStore) evict() {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := 0

	// Time-based eviction.
	if s.maxAge > 0 {
		cutoff := time.Now().UTC().Add(-s.maxAge)
		for idx < len(s.events) && s.events[idx].Timestamp.Before(cutoff) {
			idx++
		}
	}

	// Count-based cap.
	if s.maxItems > 0 && len(s.events)-idx > s.maxItems {
		target := s.maxItems * 80 / 100
		idx = len(s.events) - target
	}
	if idx > 0 {
		evicted := idx
		total := len(s.events)
		remaining := make([]GeneralLogEvent, total-idx)
		copy(remaining, s.events[idx:])
		s.events = remaining
		s.generation.Add(1)

		evictPct := float64(evicted) / float64(total) * 100
		if evicted > 10000 || evictPct > 5.0 {
			log.Printf("evicted %d general log events older than %s (%d remaining, %.1f%%) — compacting", evicted, s.maxAge, len(s.events), evictPct)
			s.compactEventFileLocked()
		} else {
			log.Printf("evicted %d general log events older than %s (%d remaining, %.1f%%) — skipping compaction", evicted, s.maxAge, len(s.events), evictPct)
		}
	}
}

// StartTailing periodically loads new general log entries.
// The goroutine exits when ctx is cancelled.
func (s *GeneralLogStore) StartTailing(ctx context.Context, interval time.Duration) {
	s.Load()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Load()
			}
		}
	}()
}

// ─── Queries ────────────────────────────────────────────────────────

func (s *GeneralLogStore) EventCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

func (s *GeneralLogStore) Stats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.statsLocked()
}

func (s *GeneralLogStore) statsLocked() map[string]any {
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

// searchCutoffGeneral returns the index of the first GeneralLogEvent with
// Timestamp >= cutoff using binary search.
func searchCutoffGeneral(events []GeneralLogEvent, cutoff time.Time) int {
	lo, hi := 0, len(events)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if events[mid].Timestamp.Before(cutoff) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// searchEndGeneral returns the index of the first GeneralLogEvent with
// Timestamp > end using binary search.
func searchEndGeneral(events []GeneralLogEvent, end time.Time) int {
	lo, hi := 0, len(events)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if !events[mid].Timestamp.After(end) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

func (s *GeneralLogStore) snapshotSince(hours int) []GeneralLogEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if hours <= 0 {
		cp := make([]GeneralLogEvent, len(s.events))
		copy(cp, s.events)
		return cp
	}

	cutoff := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	idx := searchCutoffGeneral(s.events, cutoff)
	n := len(s.events) - idx
	cp := make([]GeneralLogEvent, n)
	copy(cp, s.events[idx:])
	return cp
}

func (s *GeneralLogStore) snapshotRange(start, end time.Time) []GeneralLogEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	startIdx := searchCutoffGeneral(s.events, start)
	endIdx := searchEndGeneral(s.events, end)
	if startIdx >= endIdx {
		return nil
	}
	n := endIdx - startIdx
	cp := make([]GeneralLogEvent, n)
	copy(cp, s.events[startIdx:endIdx])
	return cp
}

// ─── Security Header Extraction ─────────────────────────────────────

// securityHeaderKeys maps canonical response header names to their
// SecurityHeaderInfo fields. Using a lookup avoids repeated string comparisons.
var securityHeaderKeys = []struct {
	header string
	setter func(*SecurityHeaderInfo, string)
}{
	{"Content-Security-Policy", func(h *SecurityHeaderInfo, v string) { h.HasCSP = true; h.CSP = v }},
	{"Content-Security-Policy-Report-Only", func(h *SecurityHeaderInfo, v string) {
		if !h.HasCSP {
			h.HasCSP = true
			h.CSP = v
		}
	}},
	{"Strict-Transport-Security", func(h *SecurityHeaderInfo, v string) { h.HasHSTS = true; h.HSTS = v }},
	{"X-Content-Type-Options", func(h *SecurityHeaderInfo, v string) { h.HasXContentTypeOptions = true; h.XContentTypeOptions = v }},
	{"X-Frame-Options", func(h *SecurityHeaderInfo, v string) { h.HasXFrameOptions = true; h.XFrameOptions = v }},
	{"Referrer-Policy", func(h *SecurityHeaderInfo, v string) { h.HasReferrerPolicy = true; h.ReferrerPolicy = v }},
	{"Access-Control-Allow-Origin", func(h *SecurityHeaderInfo, v string) { h.HasCORSOrigin = true; h.CORSOrigin = v }},
	{"Permissions-Policy", func(h *SecurityHeaderInfo, v string) { h.HasPermissionsPolicy = true; h.PermissionsPolicy = v }},
}

// extractSecurityHeaders reads security-relevant headers from the response.
func extractSecurityHeaders(respHeaders map[string][]string) SecurityHeaderInfo {
	var info SecurityHeaderInfo
	for _, sh := range securityHeaderKeys {
		if vals, ok := respHeaders[sh.header]; ok && len(vals) > 0 {
			sh.setter(&info, vals[0])
		}
	}
	return info
}

// accessLogRequestID extracts the request ID from an access log entry.
// Prefers the top-level request_id field (set by Caddy log_append) over the
// X-Request-Id request header (fallback for older log entries without log_append).
func accessLogRequestID(entry AccessLogEntry) string {
	if entry.RequestID != "" {
		return entry.RequestID
	}
	return headerValue(entry.Request.Headers, "X-Request-Id")
}

// parseGeneralLogEvent converts an AccessLogEntry into a GeneralLogEvent.
func parseGeneralLogEvent(entry AccessLogEntry, geoIP *GeoIPStore) GeneralLogEvent {
	ts := parseTimestamp(entry.Ts)
	ua := ""
	if vals, ok := entry.Request.Headers["User-Agent"]; ok && len(vals) > 0 {
		ua = vals[0]
	}

	evt := GeneralLogEvent{
		Timestamp:       ts,
		ClientIP:        entry.Request.ClientIP,
		Service:         entry.Request.Host,
		Method:          entry.Request.Method,
		URI:             entry.Request.URI,
		Protocol:        entry.Request.Proto,
		Status:          entry.Status,
		Size:            entry.Size,
		BytesRead:       entry.BytesRead,
		Duration:        entry.Duration,
		UserAgent:       ua,
		Logger:          entry.Logger,
		Level:           entry.Level,
		RequestID:       accessLogRequestID(entry),
		SecurityHeaders: extractSecurityHeaders(entry.RespHeaders),
		DDoSAction:      entry.DDoSAction,
		DDoSFingerprint: entry.DDoSFingerprint,
		DDoSZScore:      entry.DDoSZScore,
	}

	// Convert raw TLS numeric codes to human-readable names.
	if entry.Request.TLS != nil {
		evt.TLS = &TLSInfo{
			Version:     tlsVersionName(entry.Request.TLS.Version),
			CipherSuite: tlsCipherSuiteName(entry.Request.TLS.CipherSuite),
			Proto:       entry.Request.TLS.Proto,
			ECH:         entry.Request.TLS.ECH,
			Resumed:     entry.Request.TLS.Resumed,
			ServerName:  entry.Request.TLS.ServerName,
		}
	}

	if geoIP != nil {
		cfCountry := headerValue(entry.Request.Headers, "Cf-Ipcountry")
		evt.Country = geoIP.Resolve(entry.Request.ClientIP, cfCountry)
	}

	return evt
}
