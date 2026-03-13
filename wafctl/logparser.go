package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Store holds WAF events and precomputed indexes. Events are fed into this
// store from the AccessLogStore (via the policy engine's log_append fields).
// The Store handles JSONL persistence, eviction, and querying.
type Store struct {
	mu     sync.RWMutex
	events []Event

	// JSONL event persistence (empty = don't persist events)
	eventFile string

	// maxAge is the maximum age of events to retain. Events older than this
	// are evicted during each eviction cycle. Zero means no eviction.
	maxAge time.Duration

	// geoIP is an optional GeoIP store for country enrichment.
	geoIP *GeoIPStore

	// generation increments on every eviction that removes events.
	// Used by responseCache to invalidate stale entries.
	generation atomic.Int64
}

func NewStore() *Store {
	return &Store{}
}

// SetEventFile configures a JSONL file for persistent event storage.
// On startup, existing events are loaded from this file so that parsed
// events survive restarts.
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
	s.events = events
	log.Printf("restored %d events from %s", len(events), path)
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

// evictOld runs time-based eviction of stale events.
func (s *Store) evictOld() {
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

// Stats returns health-check information about the WAF event store.
func (s *Store) Stats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := map[string]any{
		"events":     len(s.events),
		"max_age":    s.maxAge.String(),
		"event_file": s.eventFile,
	}
	// Oldest / newest event timestamps.
	if len(s.events) > 0 {
		stats["oldest_event"] = s.events[0].Timestamp
		stats["newest_event"] = s.events[len(s.events)-1].Timestamp
	}
	return stats
}

// StartEviction runs eviction once immediately, then periodically at interval.
// The goroutine exits when ctx is cancelled.
func (s *Store) StartEviction(ctx context.Context, interval time.Duration) {
	s.evictOld()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.evictOld()
			}
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
