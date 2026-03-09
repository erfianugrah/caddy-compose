package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Store holds the parsed events and precomputed indexes.
type Store struct {
	mu     sync.RWMutex
	events []Event

	// file tailing state
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

	// generation increments on every Load() that adds/evicts events.
	// Used by responseCache to invalidate stale entries.
	generation atomic.Int64
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

// SetOffsetFile configures a file path to persist the audit log read offset
// across restarts. Without this, the entire log is re-parsed on each startup.
func (s *Store) SetOffsetFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offsetFile = path
	// Restore offset from disk.
	if data, err := os.ReadFile(path); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil && v > 0 {
			s.offset.Store(v)
			log.Printf("restored audit log offset %d from %s", v, path)
		}
	}
}

// saveOffset writes the current offset to the persistent offset file (if configured).
func (s *Store) saveOffset() {
	if s.offsetFile == "" {
		return
	}
	data := []byte(strconv.FormatInt(s.offset.Load(), 10) + "\n")
	if err := atomicWriteFile(s.offsetFile, data, 0644); err != nil {
		log.Printf("error saving audit log offset to %s: %v", s.offsetFile, err)
	}
}

// SetEventFile configures a JSONL file for persistent event storage.
// On startup, existing events are loaded from this file so that parsed
// events survive restarts without re-parsing the raw audit log.
func (s *Store) SetEventFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventFile = path
	// Restore events from JSONL file.
	events, err := loadEventsFromJSONL(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("error loading events from %s: %v", path, err)
		}
		return
	}
	// Migrate: fix misclassified events where a skip_rule fired but the
	// request was still blocked by other CRS rules. Before the fix, these
	// were labelled "policy_skip" despite being interrupted (is_blocked=true).
	migrated := 0
	for i := range events {
		if events[i].EventType == "policy_skip" && events[i].IsBlocked {
			events[i].EventType = "blocked"
			migrated++
		}
	}

	// Migrate: remap removed event types to their canonical replacements
	// and backfill tags on old events that predate the tag system.
	tagsMigrated := 0
	for i := range events {
		switch events[i].EventType {
		case "honeypot":
			events[i].EventType = "policy_block"
			events[i].IsBlocked = true
			if !containsTag(events[i].Tags, "honeypot") {
				events[i].Tags = append(events[i].Tags, "honeypot")
			}
			tagsMigrated++
		case "scanner":
			events[i].EventType = "policy_block"
			events[i].IsBlocked = true
			if !containsTag(events[i].Tags, "scanner") {
				events[i].Tags = append(events[i].Tags, "scanner")
			}
			if !containsTag(events[i].Tags, "bot-detection") {
				events[i].Tags = append(events[i].Tags, "bot-detection")
			}
			tagsMigrated++
		case "ipsum_blocked":
			events[i].EventType = "rate_limited"
			if !containsTag(events[i].Tags, "blocklist") {
				events[i].Tags = append(events[i].Tags, "blocklist")
			}
			if !containsTag(events[i].Tags, "ipsum") {
				events[i].Tags = append(events[i].Tags, "ipsum")
			}
			tagsMigrated++
		}
	}

	s.events = events
	log.Printf("restored %d events from %s", len(events), path)
	if migrated > 0 {
		log.Printf("migrated %d misclassified policy_skip→blocked events", migrated)
	}
	if tagsMigrated > 0 {
		log.Printf("backfilled tags on %d events", tagsMigrated)
	}
	if migrated > 0 || tagsMigrated > 0 {
		s.compactEventFileLocked()
	}
}

// appendEventsToJSONL appends events to the JSONL file.
func (s *Store) appendEventsToJSONL(events []Event) {
	if s.eventFile == "" || len(events) == 0 {
		return
	}
	f, err := os.OpenFile(s.eventFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("error opening event file for append: %v", err)
		return
	}
	defer f.Close()

	for i := range events {
		data, err := json.Marshal(events[i])
		if err != nil {
			log.Printf("error marshaling event for persistence: %v", err)
			continue
		}
		if _, err := f.Write(data); err != nil {
			log.Printf("error writing event to JSONL: %v", err)
			return
		}
		if _, err := f.Write([]byte{'\n'}); err != nil {
			log.Printf("error writing newline to JSONL: %v", err)
			return
		}
	}
	if err := f.Sync(); err != nil {
		log.Printf("error syncing event file: %v", err)
	}
}

// compactEventFile rewrites the JSONL file with only the current in-memory events.
// Acquires a read lock internally — do NOT call while holding s.mu (use
// compactEventFileLocked instead).
func (s *Store) compactEventFile() {
	if s.eventFile == "" {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.compactEventFileLocked()
}

// compactEventFileLocked rewrites the JSONL file with the current in-memory
// events. The caller MUST hold s.mu (at least RLock).
func (s *Store) compactEventFileLocked() {
	if s.eventFile == "" {
		return
	}

	tmp := s.eventFile + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		log.Printf("error creating temp event file for compaction: %v", err)
		return
	}

	count := len(s.events)
	var writeErr error
	for i := range s.events {
		data, err := json.Marshal(s.events[i])
		if err != nil {
			continue
		}
		if _, err := f.Write(data); err != nil {
			writeErr = err
			break
		}
		if _, err := f.Write([]byte{'\n'}); err != nil {
			writeErr = err
			break
		}
	}

	if writeErr != nil {
		f.Close()
		os.Remove(tmp)
		log.Printf("error writing compacted event file: %v", writeErr)
		return
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		log.Printf("error syncing compacted event file: %v", err)
		return
	}
	f.Close()
	if err := os.Rename(tmp, s.eventFile); err != nil {
		log.Printf("error renaming compacted event file: %v", err)
		return
	}
	log.Printf("compacted event file: %d events", count)
}

// loadEventsFromJSONL reads events from a JSONL file.
func loadEventsFromJSONL(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []Event
	reader := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
		}
		if len(line) > 0 {
			var ev Event
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

// SetGeoIP configures the GeoIP store for country enrichment of events.
func (s *Store) SetGeoIP(g *GeoIPStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.geoIP = g
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
	if info.Size() < s.offset.Load() {
		log.Printf("audit log appears rotated (size %d < offset %d), re-reading from start", info.Size(), s.offset.Load())
		s.offset.Store(0)
		s.saveOffset()
		// Don't clear in-memory events — with copytruncate rotation the
		// already-parsed events are still valid. The eviction loop will
		// age them out naturally based on maxAge.
	}

	bytesToRead := info.Size() - s.offset.Load()
	if bytesToRead == 0 {
		// No new data, but still run eviction for time-based cleanup.
		s.evict()
		return
	}

	log.Printf("audit log: parsing %s from offset %d (%s to read)",
		s.path, s.offset.Load(), formatBytes(bytesToRead))

	// Seek to where we left off.
	if s.offset.Load() > 0 {
		if _, err := f.Seek(s.offset.Load(), io.SeekStart); err != nil {
			log.Printf("error seeking audit log: %v", err)
			return
		}
	}

	// Snapshot geoIP reference under lock to avoid a data race with SetGeoIP.
	s.mu.RLock()
	geoIP := s.geoIP
	s.mu.RUnlock()

	var newEvents []Event
	var linesRead, linesSkipped int
	var bytesRead int64
	startTime := time.Now()
	lastProgress := startTime
	reader := bufio.NewReaderSize(f, 64*1024)
	// Use ReadBytes instead of Scanner — no line length limit.
	// Coraza audit log entries can be arbitrarily large: request bodies up to
	// SecRequestBodyLimit (13MB), headers, and CRS rules with full regex in
	// the "raw" field. Scanner's fixed buffer would permanently stall on
	// oversized lines; ReadBytes just grows the buffer as needed.
	for {
		line, err := reader.ReadBytes('\n')
		bytesRead += int64(len(line))
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
		}
		if len(line) > 0 {
			linesRead++
			var entry AuditLogEntry
			if jsonErr := json.Unmarshal(line, &entry); jsonErr != nil {
				linesSkipped++
				if linesSkipped <= 5 {
					log.Printf("skipping malformed log line: %v", jsonErr)
				}
			} else {
				ev := parseEvent(entry)
				// Enrich with country from Cf-Ipcountry header or MMDB lookup.
				if geoIP != nil {
					cfCountry := headerValue(entry.Transaction.Request.Headers, "Cf-Ipcountry")
					ev.Country = geoIP.Resolve(ev.ClientIP, cfCountry)
				}
				newEvents = append(newEvents, ev)
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("error reading audit log: %v", err)
			}
			break
		}

		// Progress logging every 10s for large parses.
		if now := time.Now(); now.Sub(lastProgress) >= 10*time.Second {
			pct := float64(bytesRead) / float64(bytesToRead) * 100
			log.Printf("audit log: %.1f%% (%s / %s) — %d events parsed, %s elapsed",
				pct, formatBytes(bytesRead), formatBytes(bytesToRead),
				len(newEvents), now.Sub(startTime).Truncate(time.Second))
			lastProgress = now
		}
	}

	elapsed := time.Since(startTime).Truncate(time.Millisecond)

	// Update offset to current position.
	newOffset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		log.Printf("error getting file offset: %v", err)
	} else {
		s.offset.Store(newOffset)
		s.saveOffset()
	}

	if len(newEvents) > 0 {
		s.mu.Lock()
		s.events = append(s.events, newEvents...)
		s.mu.Unlock()
		s.generation.Add(1)
		// Persist new events to JSONL.
		s.appendEventsToJSONL(newEvents)
		log.Printf("audit log: loaded %d new events (%d total) from %d lines (%d skipped) in %s",
			len(newEvents), s.EventCount(), linesRead, linesSkipped, elapsed)
	} else if linesRead > 0 {
		log.Printf("audit log: parsed %d lines (0 new events, %d skipped) in %s",
			linesRead, linesSkipped, elapsed)
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
		s.generation.Add(1)
		// Compact the JSONL file synchronously to avoid racing with
		// appendEventsToJSONL on the next tail cycle. Use the locked
		// variant since we already hold s.mu.
		s.compactEventFileLocked()
	}
}

func (s *Store) EventCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// Stats returns health-check information about the audit log store.
func (s *Store) Stats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := map[string]any{
		"events":     len(s.events),
		"log_file":   s.path,
		"offset":     s.offset.Load(),
		"max_age":    s.maxAge.String(),
		"event_file": s.eventFile,
	}
	// Log file size for comparison with offset.
	if fi, err := os.Stat(s.path); err == nil {
		stats["log_size"] = fi.Size()
	}
	// Oldest / newest event timestamps.
	if len(s.events) > 0 {
		stats["oldest_event"] = s.events[0].Timestamp
		stats["newest_event"] = s.events[len(s.events)-1].Timestamp
	}
	return stats
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

// EventByID returns a copy of the event with the given ID, or nil if not found.
func (s *Store) EventByID(id string) *Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].ID == id {
			ev := s.events[i]
			return &ev
		}
	}
	return nil
}

// searchCutoff returns the index of the first event with Timestamp >= cutoff
// using binary search. Events must be in chronological order.
func searchCutoff(events []Event, cutoff time.Time) int {
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

// searchEnd returns the index of the first event with Timestamp > end
// using binary search. Events must be in chronological order.
func searchEnd(events []Event, end time.Time) int {
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

// SnapshotSince returns a copy of events within the last N hours.
// Uses binary search on chronologically ordered events — O(log N) to find
// the cutoff index, then a single copy of the matching tail.
func (s *Store) SnapshotSince(hours int) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if hours <= 0 {
		cp := make([]Event, len(s.events))
		copy(cp, s.events)
		return cp
	}

	cutoff := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	idx := searchCutoff(s.events, cutoff)
	n := len(s.events) - idx
	cp := make([]Event, n)
	copy(cp, s.events[idx:])
	return cp
}

// SnapshotRange returns a copy of events within [start, end].
// Uses binary search for both bounds — O(log N) each.
func (s *Store) SnapshotRange(start, end time.Time) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	startIdx := searchCutoff(s.events, start)
	endIdx := searchEnd(s.events, end)
	if startIdx >= endIdx {
		return nil
	}
	n := endIdx - startIdx
	cp := make([]Event, n)
	copy(cp, s.events[startIdx:endIdx])
	return cp
}

// Summary computes aggregate stats from events within the last N hours.
func (s *Store) Summary(hours int) SummaryResponse {
	return summarizeEvents(s.SnapshotSince(hours))
}

// SummaryRange computes aggregate stats from events within [start, end].
func (s *Store) SummaryRange(start, end time.Time) SummaryResponse {
	return summarizeEvents(s.SnapshotRange(start, end))
}

// --- helpers ---

// formatBytes formats a byte count as a human-readable string (e.g. "2.7 GB").
func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// containsTag checks if a tag is present in a slice.
func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
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
