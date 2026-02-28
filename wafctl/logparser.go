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

	s.events = events
	log.Printf("restored %d events from %s", len(events), path)
	if migrated > 0 {
		log.Printf("migrated %d misclassified policy_skip→blocked events", migrated)
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
		f.Write(data)
		f.Write([]byte{'\n'})
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

	// Classify events by checking rule IDs from custom rule ranges.
	// Scan all messages to find the highest-priority classification.
	// Priority: policy engine > honeypot > scanner > default (blocked/logged).
	var candidateType string
	for _, m := range entry.Messages {
		rid := m.Data.ID

		// Policy Engine rules — generated by the UI.
		// Highest priority — immediately finalize.
		if rid >= policyRuleIDMin && rid <= policyRuleIDMax {
			msg := m.Data.Msg
			if strings.HasPrefix(msg, "Policy Allow:") {
				candidateType = "policy_allow"
			} else if strings.HasPrefix(msg, "Policy Skip:") {
				// A skip_rule exclusion fired, but the request may still be
				// blocked by other CRS rules the skip didn't cover. Only
				// classify as "policy_skip" if the request was NOT interrupted.
				if !tx.IsInterrupted {
					candidateType = "policy_skip"
				}
				// If still interrupted, leave candidateType empty so the
				// default "blocked" classification from line 378 is preserved.
			} else if strings.HasPrefix(msg, "Policy Block:") {
				candidateType = "policy_block"
			}
			break // policy classification takes absolute priority
		}

		// Honeypot path rules — known-bad path probes.
		if rid >= honeypotRuleIDMin && rid <= honeypotRuleIDMax && candidateType == "" {
			candidateType = "honeypot"
			// Don't break — keep scanning for policy rules.
		}

		// Heuristic bot signal rules (9100030–9100049).
		// Scanner UA rule uses drop — classify as scanner.
		// Other heuristic rules just adjust anomaly scores and don't
		// change the event type.
		if rid == scannerDropRuleID && candidateType == "" {
			candidateType = "scanner"
			// Don't break — keep scanning for policy rules.
		}
	}
	if candidateType != "" {
		eventType = candidateType
	}

	// When Coraza blocks a request (is_interrupted), the backend never responds,
	// so response.status is 0 in the audit log. Show 403 since that's what the
	// client actually receives.
	status := tx.Response.Status
	if tx.IsInterrupted && status == 0 {
		status = 403
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
		ResponseStatus: status,
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
			// Prefer rules with an actual ID (skip anomaly scoring rules).
			if scoringRuleIDs[best.Data.ID] {
				if !isScoringRule(m.Data.ID) {
					best = m
				}
			}
		}
		ev.RuleID = best.Data.ID
		ev.RuleMsg = best.Data.Msg
		ev.Severity = best.Data.Severity
		ev.MatchedData = best.Data.Data
		ev.RuleTags = best.Data.Tags

		// Extract inbound and outbound anomaly scores separately.
		//
		// Priority order for each score:
		//   1. Rule 949110 (inbound) / 959100 (outbound) — blocking evaluation rules
		//      that fire when the score exceeds the threshold. Message: "Total Score: N"
		//   2. Rule 980170 — phase 5 correlation/reporting rule that logs a full breakdown
		//      of all scores. Message: "Anomaly Scores: (Inbound Scores: blocking=N, ...)
		//      - (Outbound Scores: blocking=N, ...)"
		//   3. Fallback: sum CRS severity-based points from matched rules, filtered by
		//      ID range (inbound: 910000-949999, outbound: 950000-979999).
		var saw949110, saw959100 bool
		for _, m := range entry.Messages {
			switch m.Data.ID {
			case 949110:
				ev.AnomalyScore = extractAnomalyScore(m.Data.Msg)
				saw949110 = true
			case 959100:
				ev.OutboundAnomalyScore = extractAnomalyScore(m.Data.Msg)
				saw959100 = true
			case 980170:
				// 980170 contains both scores — use as fallback for whichever
				// wasn't already set by 949110/959100.
				inbound, outbound := extractScoresFrom980170(m.Data.Msg)
				if ev.AnomalyScore == 0 {
					ev.AnomalyScore = inbound
				}
				if ev.OutboundAnomalyScore == 0 {
					ev.OutboundAnomalyScore = outbound
				}
			}
		}
		// Last resort: compute from individual rule severities.
		if ev.AnomalyScore == 0 {
			ev.AnomalyScore = computeAnomalyScoreByPhase(entry.Messages, false)
		}
		if ev.OutboundAnomalyScore == 0 {
			ev.OutboundAnomalyScore = computeAnomalyScoreByPhase(entry.Messages, true)
		}

		// Determine how the request was blocked.
		if ev.IsBlocked {
			if saw949110 {
				ev.BlockedBy = "anomaly_inbound"
			} else if saw959100 {
				ev.BlockedBy = "anomaly_outbound"
			} else {
				ev.BlockedBy = "direct"
			}
		}

		// Collect all matched rules (skip scoring/evaluation rules).
		seen := make(map[int]bool)
		for _, m := range entry.Messages {
			id := m.Data.ID
			if isScoringRule(id) {
				continue
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			ev.MatchedRules = append(ev.MatchedRules, MatchedRule{
				ID:          id,
				Msg:         m.Data.Msg,
				Severity:    m.Data.Severity,
				MatchedData: m.Data.Data,
				File:        m.Data.File,
				Tags:        m.Data.Tags,
			})
		}
	}

	// Attach request context for full payload inspection.
	if len(tx.Request.Headers) > 0 {
		ev.RequestHeaders = tx.Request.Headers
	}
	if tx.Request.Body != "" {
		ev.RequestBody = tx.Request.Body
	}
	if len(tx.Request.Args) > 0 {
		ev.RequestArgs = tx.Request.Args
	}

	return ev
}

// extractAnomalyScore parses "Total Score: N" from CRS anomaly evaluation rule messages.
// Returns 0 if the pattern is not found.
func extractAnomalyScore(msg string) int {
	const prefix = "Total Score: "
	idx := strings.Index(msg, prefix)
	if idx < 0 {
		return 0
	}
	rest := msg[idx+len(prefix):]
	// Read digits until non-digit or end.
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	score, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return score
}

// extractScoresFrom980170 parses both inbound and outbound blocking scores from
// rule 980170's correlation message. Format:
//
//	"Anomaly Scores: (Inbound Scores: blocking=N, ...) - (Outbound Scores: blocking=N, ...)"
//
// Returns (inbound, outbound). Returns 0 for either if not found.
func extractScoresFrom980170(msg string) (int, int) {
	inbound := extractNamedScore(msg, "Inbound Scores: blocking=")
	outbound := extractNamedScore(msg, "Outbound Scores: blocking=")
	return inbound, outbound
}

// extractNamedScore extracts an integer after the given prefix in a message.
// E.g. extractNamedScore("...blocking=15,...", "blocking=") returns 15.
func extractNamedScore(msg, prefix string) int {
	idx := strings.Index(msg, prefix)
	if idx < 0 {
		return 0
	}
	rest := msg[idx+len(prefix):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	score, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return score
}

// computeAnomalyScoreByPhase sums CRS severity-based anomaly points from
// matched rules, filtered by CRS rule ID range (inbound vs outbound).
//
// CRS 4.x ID ranges:
//
//	Inbound  (request phases 1-2):  910000-949999
//	Outbound (response phases 3-4): 950000-979999
//
// CRS 4.x scoring: CRITICAL(2)=5, ERROR(3)=4, WARNING(4)=3, NOTICE(5)=2.
// Evaluation/scoring rules and ID 0 are excluded.
func computeAnomalyScoreByPhase(messages []AuditMessage, outbound bool) int {
	score := 0
	seen := make(map[int]bool) // deduplicate by rule ID (chain rules repeat)
	for _, m := range messages {
		id := m.Data.ID
		if isScoringRule(id) {
			continue
		}
		if seen[id] {
			continue
		}
		// Filter by CRS rule ID range.
		isOutbound := id >= crsOutboundMin && id <= crsOutboundMax
		if outbound != isOutbound {
			continue
		}
		seen[id] = true
		score += severityScoreMap[m.Data.Severity]
	}
	return score
}

// computeAnomalyScore sums CRS severity-based anomaly points from all matched
// rules (both inbound and outbound). This is the combined total score.
// Kept for backward compatibility with tests; prefer computeAnomalyScoreByPhase.
func computeAnomalyScore(messages []AuditMessage) int {
	return computeAnomalyScoreByPhase(messages, false) + computeAnomalyScoreByPhase(messages, true)
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

// summaryResult bundles the SummaryResponse with internal sets needed for
// efficient merging (avoids re-fetching WAF events just for unique counts).
type summaryResult struct {
	SummaryResponse
	clientSet  map[string]struct{}
	serviceSet map[string]struct{}
}

// summarizeEvents computes aggregate stats from a slice of events.
func summarizeEvents(events []Event) SummaryResponse {
	return summarizeEventsWithSets(events).SummaryResponse
}

// summarizeEventsWithSets computes aggregate stats and also returns the
// unique client/service sets for efficient merging with RL events.
func summarizeEventsWithSets(events []Event) summaryResult {
	var totalBlocked, totalLogged, totalPolicy, totalHoneypot, totalScanner int
	var totalRateLimited, totalIpsumBlocked int

	// Per-hour breakdown with action type counters.
	type hourStats struct {
		total, blocked, honeypot, scanner, policy, rateLimited, ipsumBlocked int
	}
	hourMap := make(map[string]*hourStats)

	// Per-service breakdown with action type counters.
	type svcStats struct {
		total, blocked, honeypot, scanner, policy, rateLimited, ipsumBlocked int
	}
	svcMap := make(map[string]*svcStats)

	// Per-client breakdown with action type counters.
	type clientStats struct {
		total, blocked, honeypot, scanner, policy, rateLimited, ipsumBlocked int
		country                                                              string
	}
	clientMap := make(map[string]*clientStats)

	uris := make(map[string]int)

	// Per-country breakdown (folded into main loop to avoid second full scan).
	countryMap := make(map[string]*CountryCount)

	// Collect recent events of all types (newest first, up to 10).
	var recentEvents []Event

	for i := len(events) - 1; i >= 0; i-- {
		ev := &events[i]
		switch {
		case ev.EventType == "rate_limited":
			totalRateLimited++
		case ev.EventType == "ipsum_blocked":
			totalIpsumBlocked++
		case strings.HasPrefix(ev.EventType, "policy_"):
			totalPolicy++
			// policy_block events are also blocked
			if ev.IsBlocked {
				totalBlocked++
			}
		case ev.EventType == "honeypot":
			totalHoneypot++
			totalBlocked++ // honeypot hits are always denied
		case ev.EventType == "scanner":
			totalScanner++
			totalBlocked++ // scanner drops are always blocked
		case ev.IsBlocked:
			totalBlocked++
		default:
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
		switch ev.EventType {
		case "honeypot":
			hs.honeypot++
		case "scanner":
			hs.scanner++
		case "policy_skip", "policy_allow", "policy_block":
			hs.policy++
		case "rate_limited":
			hs.rateLimited++
		case "ipsum_blocked":
			hs.ipsumBlocked++
		default:
			if ev.IsBlocked {
				hs.blocked++
			}
		}

		// Per-service.
		ss, ok := svcMap[ev.Service]
		if !ok {
			ss = &svcStats{}
			svcMap[ev.Service] = ss
		}
		ss.total++
		switch ev.EventType {
		case "honeypot":
			ss.honeypot++
		case "scanner":
			ss.scanner++
		case "policy_skip", "policy_allow", "policy_block":
			ss.policy++
		case "rate_limited":
			ss.rateLimited++
		case "ipsum_blocked":
			ss.ipsumBlocked++
		default:
			if ev.IsBlocked {
				ss.blocked++
			}
		}

		// Per-client.
		cs, ok := clientMap[ev.ClientIP]
		if !ok {
			cs = &clientStats{}
			clientMap[ev.ClientIP] = cs
		}
		cs.total++
		switch ev.EventType {
		case "honeypot":
			cs.honeypot++
		case "scanner":
			cs.scanner++
		case "policy_skip", "policy_allow", "policy_block":
			cs.policy++
		case "rate_limited":
			cs.rateLimited++
		case "ipsum_blocked":
			cs.ipsumBlocked++
		default:
			if ev.IsBlocked {
				cs.blocked++
			}
		}
		if cs.country == "" && ev.Country != "" {
			cs.country = ev.Country
		}

		uris[ev.URI]++

		// Per-country (avoids second full scan via TopCountries).
		cc := ev.Country
		if cc == "" {
			cc = "XX"
		}
		entry, ok := countryMap[cc]
		if !ok {
			entry = &CountryCount{Country: cc}
			countryMap[cc] = entry
		}
		entry.Count++
		if ev.IsBlocked {
			entry.Blocked++
		}
	}

	// Build sorted country counts from the inline map.
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

	// Build sorted hour buckets.
	hourCounts := make([]HourCount, 0, len(hourMap))
	for k, v := range hourMap {
		logged := v.total - v.blocked - v.rateLimited - v.ipsumBlocked - v.honeypot - v.scanner - v.policy
		if logged < 0 {
			logged = 0
		}
		hourCounts = append(hourCounts, HourCount{
			Hour:         k,
			Count:        v.total,
			Blocked:      v.blocked,
			Logged:       logged,
			RateLimited:  v.rateLimited,
			IpsumBlocked: v.ipsumBlocked,
			Honeypot:     v.honeypot,
			Scanner:      v.scanner,
			Policy:       v.policy,
		})
	}
	sort.Slice(hourCounts, func(i, j int) bool {
		return hourCounts[i].Hour < hourCounts[j].Hour
	})

	// Build service counts (for top_services).
	svcCounts := make([]ServiceCount, 0, len(svcMap))
	for k, v := range svcMap {
		svcCounts = append(svcCounts, ServiceCount{
			Service:      k,
			Count:        v.total,
			Blocked:      v.blocked,
			Logged:       v.total - v.blocked - v.rateLimited - v.ipsumBlocked - v.honeypot - v.scanner - v.policy,
			RateLimited:  v.rateLimited,
			IpsumBlocked: v.ipsumBlocked,
			Honeypot:     v.honeypot,
			Scanner:      v.scanner,
			Policy:       v.policy,
		})
	}
	sort.Slice(svcCounts, func(i, j int) bool {
		return svcCounts[i].Count > svcCounts[j].Count
	})
	if len(svcCounts) > topNAnalytics {
		svcCounts = svcCounts[:topNAnalytics]
	}

	// Build service breakdown (same data, different type for convenience).
	svcBreakdown := make([]ServiceDetail, 0, len(svcMap))
	for k, v := range svcMap {
		svcBreakdown = append(svcBreakdown, ServiceDetail{
			Service:      k,
			Total:        v.total,
			Blocked:      v.blocked,
			Logged:       v.total - v.blocked - v.rateLimited - v.ipsumBlocked - v.honeypot - v.scanner - v.policy,
			RateLimited:  v.rateLimited,
			IpsumBlocked: v.ipsumBlocked,
			Honeypot:     v.honeypot,
			Scanner:      v.scanner,
			Policy:       v.policy,
		})
	}
	sort.Slice(svcBreakdown, func(i, j int) bool {
		return svcBreakdown[i].Total > svcBreakdown[j].Total
	})

	// Build client counts.
	clientCounts := make([]ClientCount, 0, len(clientMap))
	for k, v := range clientMap {
		clientCounts = append(clientCounts, ClientCount{
			Client:       k,
			Country:      v.country,
			Count:        v.total,
			Blocked:      v.blocked,
			RateLimited:  v.rateLimited,
			IpsumBlocked: v.ipsumBlocked,
			Honeypot:     v.honeypot,
			Scanner:      v.scanner,
			Policy:       v.policy,
		})
	}
	sort.Slice(clientCounts, func(i, j int) bool {
		return clientCounts[i].Count > clientCounts[j].Count
	})
	if len(clientCounts) > topNAnalytics {
		clientCounts = clientCounts[:topNAnalytics]
	}

	// Build unique sets for efficient merging with RL events.
	cSet := make(map[string]struct{}, len(clientMap))
	for k := range clientMap {
		cSet[k] = struct{}{}
	}
	sSet := make(map[string]struct{}, len(svcMap))
	for k := range svcMap {
		sSet[k] = struct{}{}
	}

	return summaryResult{
		SummaryResponse: SummaryResponse{
			TotalEvents:      len(events),
			BlockedEvents:    totalBlocked,
			LoggedEvents:     totalLogged,
			RateLimited:      totalRateLimited,
			IpsumBlocked:     totalIpsumBlocked,
			PolicyEvents:     totalPolicy,
			HoneypotEvents:   totalHoneypot,
			ScannerEvents:    totalScanner,
			UniqueClients:    len(clientMap),
			UniqueServices:   len(svcMap),
			EventsByHour:     hourCounts,
			TopServices:      svcCounts,
			TopClients:       clientCounts,
			TopCountries:     countryCounts,
			TopURIs:          topN(uris, topNAnalytics, func(k string, c int) URICount { return URICount{k, c} }),
			ServiceBreakdown: svcBreakdown,
			RecentEvents:     recentEvents,
		},
		clientSet:  cSet,
		serviceSet: sSet,
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
	type uriStats struct {
		count, blocked int
	}
	type ruleKey struct {
		id  int
		msg string
	}
	type svcData struct {
		total, blocked, honeypot, scanner, policy int
		uris                                      map[string]*uriStats
		rules                                     map[ruleKey]int
	}
	m := make(map[string]*svcData)

	for i := range events {
		ev := &events[i]
		d, ok := m[ev.Service]
		if !ok {
			d = &svcData{
				uris:  make(map[string]*uriStats),
				rules: make(map[ruleKey]int),
			}
			m[ev.Service] = d
		}
		d.total++
		if ev.IsBlocked {
			d.blocked++
		}
		switch ev.EventType {
		case "honeypot":
			d.honeypot++
		case "scanner":
			d.scanner++
		case "policy_skip", "policy_allow", "policy_block":
			d.policy++
		}

		// Track per-service URI counts.
		if ev.URI != "" {
			us, ok := d.uris[ev.URI]
			if !ok {
				us = &uriStats{}
				d.uris[ev.URI] = us
			}
			us.count++
			if ev.IsBlocked {
				us.blocked++
			}
		}

		// Track per-service rule counts from all matched rules.
		for _, mr := range ev.MatchedRules {
			if mr.ID > 0 {
				d.rules[ruleKey{id: mr.ID, msg: mr.Msg}]++
			}
		}
		// Fall back to primary rule if no matched rules.
		if len(ev.MatchedRules) == 0 && ev.RuleID > 0 {
			d.rules[ruleKey{id: ev.RuleID, msg: ev.RuleMsg}]++
		}
	}

	result := make([]ServiceDetail, 0, len(m))
	for svc, d := range m {
		sd := ServiceDetail{
			Service:  svc,
			Total:    d.total,
			Blocked:  d.blocked,
			Logged:   d.total - d.blocked,
			Honeypot: d.honeypot,
			Scanner:  d.scanner,
			Policy:   d.policy,
		}

		// Build top URIs.
		uriList := make([]ServiceURI, 0, len(d.uris))
		for uri, us := range d.uris {
			uriList = append(uriList, ServiceURI{URI: uri, Count: us.count, Blocked: us.blocked})
		}
		sort.Slice(uriList, func(i, j int) bool { return uriList[i].Count > uriList[j].Count })
		if len(uriList) > topNSummary {
			uriList = uriList[:topNSummary]
		}
		sd.TopURIs = uriList

		// Build top rules.
		ruleList := make([]ServiceRule, 0, len(d.rules))
		for rk, count := range d.rules {
			ruleList = append(ruleList, ServiceRule{RuleID: rk.id, RuleMsg: rk.msg, Count: count})
		}
		sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].Count > ruleList[j].Count })
		if len(ruleList) > topNSummary {
			ruleList = ruleList[:topNSummary]
		}
		sd.TopRules = ruleList

		result = append(result, sd)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Total > result[j].Total
	})

	return ServicesResponse{Services: result}
}

// IPLookup returns all events and stats for a specific IP address.
func (s *Store) IPLookup(ip string, hours, limit, offset int) IPLookupResponse {
	events := s.SnapshotSince(hours)

	var matched []Event
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].ClientIP == ip {
			matched = append(matched, events[i])
		}
	}

	resp := IPLookupResponse{
		IP:          ip,
		Total:       len(matched),
		EventsTotal: len(matched),
	}

	// Compute per-service breakdown, first/last seen, blocked count.
	type counts struct {
		total, blocked, honeypot, scanner, policy int
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
		switch ev.EventType {
		case "honeypot":
			c.honeypot++
		case "scanner":
			c.scanner++
		case "policy_skip", "policy_allow", "policy_block":
			c.policy++
		}
	}

	// Apply limit/offset pagination to the events slice.
	if offset >= len(matched) {
		resp.Events = []Event{}
	} else {
		end := offset + limit
		if end > len(matched) {
			end = len(matched)
		}
		resp.Events = matched[offset:end]
	}

	svcList := make([]ServiceDetail, 0, len(svcMap))
	for svc, c := range svcMap {
		svcList = append(svcList, ServiceDetail{
			Service:  svc,
			Total:    c.total,
			Blocked:  c.blocked,
			Logged:   c.total - c.blocked,
			Honeypot: c.honeypot,
			Scanner:  c.scanner,
			Policy:   c.policy,
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
	return topBlockedIPs(s.SnapshotSince(hours), n)
}

// TopTargetedURIs returns the top N URIs by total event count.
func (s *Store) TopTargetedURIs(hours, n int) []TopTargetedURI {
	return topTargetedURIs(s.SnapshotSince(hours), n)
}

// topBlockedIPs aggregates the top N IPs by blocked count from a pre-filtered event slice.
func topBlockedIPs(events []Event, n int) []TopBlockedIP {
	type ipStats struct {
		total, blocked int
		first, last    time.Time
		country        string
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
		if st.country == "" && ev.Country != "" {
			st.country = ev.Country
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
			Country:   st.country,
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

// topTargetedURIs aggregates the top N URIs by total event count from a pre-filtered event slice.
func topTargetedURIs(events []Event, n int) []TopTargetedURI {
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
