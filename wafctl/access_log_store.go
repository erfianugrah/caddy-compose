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

// ─── Caddy access log JSON structure ────────────────────────────────

// AccessLogEntry is the JSON structure Caddy writes for each request.
type AccessLogEntry struct {
	Level                string              `json:"level"`
	Ts                   string              `json:"ts"` // wall clock format: "2026/02/22 12:43:20"
	Logger               string              `json:"logger"`
	Msg                  string              `json:"msg"`
	Request              AccessLogReq        `json:"request"`
	RespHeaders          map[string][]string `json:"resp_headers"`
	Status               int                 `json:"status"`
	Size                 int                 `json:"size"`
	Duration             float64             `json:"duration"`
	BytesRead            int                 `json:"bytes_read"`                       // request body bytes consumed
	RequestID            string              `json:"request_id,omitempty"`             // Caddy UUID via log_append
	PolicyAction         string              `json:"policy_action,omitempty"`          // log_append: policy engine action (allow/block/honeypot/detect_block)
	PolicyRule           string              `json:"policy_rule,omitempty"`            // log_append: matched policy engine rule name
	PolicyTags           string              `json:"policy_tags,omitempty"`            // log_append: comma-separated tags from matched rule(s)
	PolicyScore          string              `json:"policy_score,omitempty"`           // log_append: anomaly score (detect rules only)
	PolicyDetectRules    string              `json:"policy_detect_rules,omitempty"`    // log_append: matched detect rule details "id:severity:score,..."
	PolicyDetectMatches  string              `json:"policy_detect_matches,omitempty"`  // log_append: JSON array of per-rule match details (field/var_name/value/matched_data)
	PolicyRequestHeaders string              `json:"policy_request_headers,omitempty"` // log_append: JSON-serialized request headers (block/detect_block only)
	PolicyRequestBody    string              `json:"policy_request_body,omitempty"`    // log_append: truncated request body excerpt (block/detect_block only)
}

type AccessLogReq struct {
	RemoteIP string              `json:"remote_ip"`
	ClientIP string              `json:"client_ip"`
	Proto    string              `json:"proto"`
	Method   string              `json:"method"`
	Host     string              `json:"host"`
	URI      string              `json:"uri"`
	Headers  map[string][]string `json:"headers"`
	TLS      *AccessLogTLS       `json:"tls,omitempty"` // present for HTTPS requests
}

// AccessLogTLS is the TLS connection info Caddy writes in request.tls.
// Version and CipherSuite are numeric codes from Go's crypto/tls package.
type AccessLogTLS struct {
	Version     uint16 `json:"version"`      // e.g. 772 = TLS 1.3, 771 = TLS 1.2
	CipherSuite uint16 `json:"cipher_suite"` // e.g. 4865 = TLS_AES_128_GCM_SHA256
	Proto       string `json:"proto"`        // ALPN negotiated protocol: "h2", "http/1.1"
	ECH         bool   `json:"ech"`          // Encrypted Client Hello accepted
	Resumed     bool   `json:"resumed"`      // TLS session resumed
	ServerName  string `json:"server_name"`  // SNI server name
}

// ─── Rate Limit Event (parsed 429) ─────────────────────────────────

type RateLimitEvent struct {
	Timestamp      time.Time           `json:"timestamp"`
	ClientIP       string              `json:"client_ip"`
	Country        string              `json:"country,omitempty"`
	Service        string              `json:"service"`
	Method         string              `json:"method"`
	URI            string              `json:"uri"`
	Protocol       string              `json:"protocol,omitempty"` // e.g. "HTTP/2.0"
	UserAgent      string              `json:"user_agent"`
	Source         string              `json:"source,omitempty"`          // "" = rate_limited, "ipsum" = ipsum_blocked, "policy" = policy engine block, "detect_block" = anomaly threshold
	RuleName       string              `json:"rule_name,omitempty"`       // policy engine: X-Blocked-Rule header value or detect summary
	RequestID      string              `json:"request_id,omitempty"`      // Caddy UUID for cross-log correlation
	AnomalyScore   int                 `json:"anomaly_score,omitempty"`   // detect_block: total anomaly score
	DetectRules    string              `json:"detect_rules,omitempty"`    // detect_block: "id:severity:score,..." detail string
	DetectMatches  string              `json:"detect_matches,omitempty"`  // detect_block: raw JSON of per-rule match details
	InlineTags     []string            `json:"inline_tags,omitempty"`     // detect_block: tags from policy_tags log_append field
	RequestHeaders map[string][]string `json:"request_headers,omitempty"` // block/detect_block: captured request headers
	RequestBody    string              `json:"request_body,omitempty"`    // block/detect_block: truncated body excerpt
}

// headerValuesCI does a case-insensitive header lookup on a map[string][]string
// that was deserialized from JSON. HTTP/2 lowercases all header names on the wire,
// and Caddy's JSON logger may preserve that casing, so we cannot rely on Title-Case.
func headerValuesCI(headers map[string][]string, key string) []string {
	// Fast path: exact match (Go's http.Header canonical form).
	if vals, ok := headers[key]; ok {
		return vals
	}
	// Slow path: case-insensitive scan.
	lower := strings.ToLower(key)
	for k, vals := range headers {
		if strings.ToLower(k) == lower {
			return vals
		}
	}
	return nil
}

// headerValueCI returns the first value for a case-insensitive header lookup.
func headerValueCI(headers map[string][]string, key string) string {
	for _, v := range headerValuesCI(headers, key) {
		if v != "" {
			return v
		}
	}
	return ""
}

// isPolicyBlocked detects a policy engine block from log_append fields (primary)
// or response headers (fallback). The log_append fields are set as Caddy variables
// by the plugin and are case-safe; response headers may be lowercased by HTTP/2.
func isPolicyBlocked(entry AccessLogEntry) bool {
	// Primary: log_append policy_action field (always lowercase, set by plugin).
	switch entry.PolicyAction {
	case "block", "honeypot", "detect_block":
		return true
	}
	// Fallback: X-Blocked-By response header (case-insensitive lookup).
	return headerValueCI(entry.RespHeaders, "X-Blocked-By") == "policy-engine"
}

// isDetectBlock returns true if this is specifically a detect-threshold block
// (as opposed to an explicit block/honeypot rule).
func isDetectBlock(entry AccessLogEntry) bool {
	if entry.PolicyAction == "detect_block" {
		return true
	}
	// Fallback: if X-Blocked-By is policy-engine AND X-Anomaly-Score is set.
	if headerValueCI(entry.RespHeaders, "X-Blocked-By") == "policy-engine" {
		return headerValueCI(entry.RespHeaders, "X-Anomaly-Score") != ""
	}
	return false
}

// isPolicyRateLimit detects a policy engine rate limit (429) from log_append fields
// (primary) or the X-RateLimit-Policy response header (fallback). This distinguishes
// policy engine 429s (which carry rule name attribution) from legacy caddy-ratelimit 429s.
func isPolicyRateLimit(entry AccessLogEntry) bool {
	// Primary: log_append policy_action field.
	if entry.PolicyAction == "rate_limit" {
		return true
	}
	// Fallback: X-RateLimit-Policy header (set by policy engine, not by caddy-ratelimit).
	return headerValueCI(entry.RespHeaders, "X-RateLimit-Policy") != ""
}

// policyRateLimitRuleName extracts the rule name from log_append (primary) or
// the X-RateLimit-Policy response header (fallback). The header format is
// "limit;w=window;name=\"rule_name\"" — we extract the quoted name.
func policyRateLimitRuleName(entry AccessLogEntry) string {
	if entry.PolicyRule != "" {
		return entry.PolicyRule
	}
	// Fallback: parse name from X-RateLimit-Policy header value.
	policy := headerValueCI(entry.RespHeaders, "X-RateLimit-Policy")
	if policy == "" {
		return ""
	}
	// Format: '10;w=1m;name="my-rule"' — extract the quoted name.
	if idx := strings.Index(policy, "name="); idx >= 0 {
		nameVal := policy[idx+5:]
		nameVal = strings.Trim(nameVal, "\"")
		return nameVal
	}
	return ""
}

// policyBlockedRuleName extracts the rule name from log_append (primary) or
// X-Blocked-Rule response header (fallback).
func policyBlockedRuleName(entry AccessLogEntry) string {
	if entry.PolicyRule != "" {
		return entry.PolicyRule
	}
	return headerValueCI(entry.RespHeaders, "X-Blocked-Rule")
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

	// exclusionStore is an optional reference for enriching policy engine events with tags.
	exclusionStore *ExclusionStore

	// generation increments on every Load() that adds/evicts events.
	generation atomic.Int64

	// advCache caches advisor scan results for 30 seconds to avoid
	// redundant 20MB disk scans on rapid re-queries.
	advCache *advisorCache
}

func NewAccessLogStore(path string) *AccessLogStore {
	return &AccessLogStore{path: path, advCache: newAdvisorCache()}
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

// SetExclusionStore configures the exclusion store for enriching policy engine events with tags.
func (s *AccessLogStore) SetExclusionStore(es *ExclusionStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exclusionStore = es
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
	// Migrate legacy Source="ipsum" events to Source="policy" so they are
	// classified as policy_block instead of rate_limited. This handles events
	// persisted before the policy engine migration.
	migrated := 0
	for i := range events {
		if events[i].Source == "ipsum" {
			events[i].Source = "policy"
			migrated++
		}
	}
	s.events = events
	log.Printf("restored %d RL events from %s", len(events), path)
	if migrated > 0 {
		log.Printf("migrated %d legacy ipsum events to policy source", migrated)
		s.compactEventFileLocked()
	}
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
		if _, err := f.Write(data); err != nil {
			log.Printf("error writing RL event to JSONL: %v", err)
			return
		}
		if _, err := f.Write([]byte{'\n'}); err != nil {
			log.Printf("error writing newline to RL JSONL: %v", err)
			return
		}
	}
	if err := f.Sync(); err != nil {
		log.Printf("error syncing RL event file: %v", err)
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
		log.Printf("error writing compacted RL event file: %v", writeErr)
		return
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		log.Printf("error syncing compacted RL event file: %v", err)
		return
	}
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
				// Collect 429 (rate limited) and policy-engine-blocked (403) responses.
				isRateLimit := entry.Status == 429
				isPolicy := entry.Status == 403 && isPolicyBlocked(entry)
				if isRateLimit || isPolicy {
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
						Protocol:  entry.Request.Proto,
						UserAgent: ua,
						RequestID: accessLogRequestID(entry),
					}
					if isPolicy && isDetectBlock(entry) {
						evt.Source = "detect_block"
						evt.RuleName = policyBlockedRuleName(entry)
						evt.DetectRules = entry.PolicyDetectRules
						evt.DetectMatches = entry.PolicyDetectMatches
						if entry.PolicyScore != "" {
							evt.AnomalyScore, _ = strconv.Atoi(entry.PolicyScore)
						} else if s := headerValueCI(entry.RespHeaders, "X-Anomaly-Score"); s != "" {
							evt.AnomalyScore, _ = strconv.Atoi(s)
						}
						if entry.PolicyTags != "" {
							evt.InlineTags = strings.Split(entry.PolicyTags, ",")
						}
					} else if isPolicy {
						evt.Source = "policy"
						evt.RuleName = policyBlockedRuleName(entry)
					}
					// Capture request context from policy engine (block/detect_block only).
					if isPolicy {
						evt.RequestHeaders = parsePolicyRequestHeaders(entry.PolicyRequestHeaders)
						if entry.PolicyRequestBody != "" {
							evt.RequestBody = entry.PolicyRequestBody
						}
					} else if isRateLimit && isPolicyRateLimit(entry) {
						// Policy engine rate limit — has rule name attribution.
						evt.Source = "policy_rl"
						evt.RuleName = policyRateLimitRuleName(entry)
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
		s.generation.Add(1)
		// Persist new events to JSONL.
		s.appendEventsToJSONL(newEvents)
		rlCount, policyCount, policyRLCount := 0, 0, 0
		for _, e := range newEvents {
			switch e.Source {
			case "policy":
				policyCount++
			case "policy_rl":
				policyRLCount++
			default:
				rlCount++
			}
		}
		log.Printf("loaded %d new events (%d rate-limit, %d policy-rl, %d policy-block) — %d total", len(newEvents), rlCount, policyRLCount, policyCount, s.EventCount())
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
		s.generation.Add(1)
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

// searchCutoffRL returns the index of the first RateLimitEvent with Timestamp >= cutoff
// using binary search. Events must be in chronological order.
func searchCutoffRL(events []RateLimitEvent, cutoff time.Time) int {
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

// searchEndRL returns the index of the first RateLimitEvent with Timestamp > end
// using binary search. Events must be in chronological order.
func searchEndRL(events []RateLimitEvent, end time.Time) int {
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

// snapshotSince returns a copy of events within the given hours window (0 = all).
// Uses binary search on chronologically ordered events.
func (s *AccessLogStore) snapshotSince(hours int) []RateLimitEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if hours <= 0 {
		cp := make([]RateLimitEvent, len(s.events))
		copy(cp, s.events)
		return cp
	}

	cutoff := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	idx := searchCutoffRL(s.events, cutoff)
	n := len(s.events) - idx
	cp := make([]RateLimitEvent, n)
	copy(cp, s.events[idx:])
	return cp
}

// snapshotRange returns a copy of events within [start, end].
// Uses binary search for both bounds.
func (s *AccessLogStore) snapshotRange(start, end time.Time) []RateLimitEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	startIdx := searchCutoffRL(s.events, start)
	endIdx := searchEndRL(s.events, end)
	if startIdx >= endIdx {
		return nil
	}
	n := endIdx - startIdx
	cp := make([]RateLimitEvent, n)
	copy(cp, s.events[startIdx:endIdx])
	return cp
}

// parsePolicyRequestHeaders parses the JSON-serialized request headers
// from the policy_request_headers log_append field. Returns nil on empty
// input or parse failure (graceful degradation for older plugin versions).
func parsePolicyRequestHeaders(raw string) map[string][]string {
	if raw == "" {
		return nil
	}
	var hdrs map[string][]string
	if err := json.Unmarshal([]byte(raw), &hdrs); err != nil {
		return nil
	}
	return hdrs
}

// ─── Converter: RateLimitEvent → Event ──────────────────────────────

// ephemeralCounter generates fast sequential IDs for ephemeral RL→Event conversions.
// These IDs only exist in JSON responses and are never persisted.
var ephemeralCounter atomic.Int64

// ephemeralID returns a fast unique ID without crypto/rand overhead.
func ephemeralID() string {
	n := ephemeralCounter.Add(1)
	return fmt.Sprintf("rl-%d-%d", time.Now().UnixMilli(), n)
}

// RateLimitEventToEvent converts a RateLimitEvent into the unified Event type
// so that 429s and policy engine blocks can be merged into the shared event stream.
// Rate limit events use "rate_limited"; policy engine blocks use "policy_block".
// extraTags from the matched rule or exclusion are appended to the event tags.
func RateLimitEventToEvent(rle RateLimitEvent, extraTags []string) Event {
	status := 429
	eventType := "rate_limited"
	var tags []string
	switch rle.Source {
	case "policy", "ipsum":
		// "ipsum" is a legacy source from before the policy engine migration;
		// JSONL migration converts these but handle gracefully if encountered.
		status = 403
		eventType = "policy_block"
	case "detect_block":
		// Anomaly threshold exceeded by detect rules.
		status = 403
		eventType = "detect_block"
	case "policy_rl":
		// Policy engine rate limit — still a 429/rate_limited but with rule attribution.
		status = 429
		eventType = "rate_limited"
	}
	if len(extraTags) > 0 {
		tags = append(tags, extraTags...)
	}
	// Use the Caddy request UUID as the unified event ID.
	// This ensures the same request has one ID across security events and
	// general logs. Fall back to ephemeralID() only for legacy log entries
	// that pre-date the log_append request_id directive.
	eventID := rle.RequestID
	if eventID == "" {
		eventID = ephemeralID()
	}
	evt := Event{
		ID:             eventID,
		Timestamp:      rle.Timestamp,
		ClientIP:       rle.ClientIP,
		Country:        rle.Country,
		Service:        rle.Service,
		Method:         rle.Method,
		URI:            rle.URI,
		Protocol:       rle.Protocol,
		IsBlocked:      true,
		ResponseStatus: status,
		UserAgent:      rle.UserAgent,
		EventType:      eventType,
		Tags:           tags,
		RequestID:      rle.RequestID,
	}
	// For policy engine blocks, set the rule message from X-Blocked-Rule header.
	if rle.Source == "policy" && rle.RuleName != "" {
		evt.RuleMsg = "Policy Block: " + rle.RuleName
	}
	// For detect_block, include the anomaly score and matched rule details.
	if rle.Source == "detect_block" {
		evt.AnomalyScore = rle.AnomalyScore
		if rle.RuleName != "" {
			evt.RuleMsg = rle.RuleName
		}
		// Parse detect_rules into matched_rules for the event response.
		// If rich match details are available (policy_detect_matches JSON),
		// use those to enrich the MatchedRule entries with per-condition data.
		if rle.DetectRules != "" {
			evt.MatchedRules = parseDetectRulesDetail(rle.DetectRules)
		}
		if rle.DetectMatches != "" {
			enrichMatchedRulesWithDetails(evt.MatchedRules, rle.DetectMatches)
		}
	}
	// For policy engine rate limits, set the rule message from the rule name.
	if rle.Source == "policy_rl" && rle.RuleName != "" {
		evt.RuleMsg = "Rate Limited: " + rle.RuleName
	}
	// Propagate request context (headers/body) for block/detect_block events.
	if len(rle.RequestHeaders) > 0 {
		evt.RequestHeaders = rle.RequestHeaders
	}
	if rle.RequestBody != "" {
		evt.RequestBody = rle.RequestBody
	}
	return evt
}

// SnapshotAsEvents returns 429/policy events converted to the unified Event type.
// Rate limit events are enriched with tags from matching RL rules.
// Policy engine events are enriched with tags from the exclusion store.
func (s *AccessLogStore) SnapshotAsEvents(hours int, rules []RateLimitRule) []Event {
	rlEvents := s.snapshotSince(hours)
	s.mu.RLock()
	es := s.exclusionStore
	s.mu.RUnlock()
	var exclusions []RuleExclusion
	if es != nil {
		exclusions = es.List()
	}
	return enrichAccessEvents(rlEvents, rules, exclusions)
}

// SnapshotAsEventsRange returns 429/policy events within [start, end] as unified Events.
// Rate limit events are enriched with tags from matching RL rules.
// Policy engine events are enriched with tags from the exclusion store.
func (s *AccessLogStore) SnapshotAsEventsRange(start, end time.Time, rules []RateLimitRule) []Event {
	rlEvents := s.snapshotRange(start, end)
	s.mu.RLock()
	es := s.exclusionStore
	s.mu.RUnlock()
	var exclusions []RuleExclusion
	if es != nil {
		exclusions = es.List()
	}
	return enrichAccessEvents(rlEvents, rules, exclusions)
}

// enrichAccessEvents converts RateLimitEvents to unified Events with tag enrichment.
func enrichAccessEvents(rlEvents []RateLimitEvent, rules []RateLimitRule, exclusions []RuleExclusion) []Event {
	sorted := sortRulesByPriority(rules)
	// Build rule-name → tags lookup for policy engine block events.
	excTagsByName := make(map[string][]string, len(exclusions))
	for _, exc := range exclusions {
		if len(exc.Tags) > 0 {
			excTagsByName[exc.Name] = exc.Tags
		}
	}
	// Build rule-name → tags lookup for policy engine rate limit events.
	rlTagsByName := make(map[string][]string, len(rules))
	for _, r := range rules {
		if len(r.Tags) > 0 {
			rlTagsByName[r.Name] = r.Tags
		}
	}
	events := make([]Event, len(rlEvents))
	for i, rle := range rlEvents {
		var tags []string
		switch rle.Source {
		case "detect_block":
			// Detect-threshold block — tags come inline from the plugin (policy_tags log field).
			tags = rle.InlineTags
		case "policy", "ipsum":
			// Match policy engine block to exclusion tags by rule name.
			if t, ok := excTagsByName[rle.RuleName]; ok {
				tags = t
			}
		case "policy_rl":
			// Policy engine rate limit — direct lookup by rule name (no heuristic needed).
			if t, ok := rlTagsByName[rle.RuleName]; ok {
				tags = t
			}
		default:
			// Legacy caddy-ratelimit 429 — heuristic condition matching.
			tags = matchEventToRuleTags(rle, sorted)
		}
		events[i] = RateLimitEventToEvent(rle, tags)
	}
	return events
}

// parseDetectRulesDetail parses the "id:severity:score,id:severity:score,..."
// string from the policy engine's detect_rules log field into MatchedRule structs.
func parseDetectRulesDetail(detail string) []MatchedRule {
	parts := strings.Split(detail, ",")
	var rules []MatchedRule
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Format: "920350:WARNING:3" (or legacy "PE-920350:WARNING:3")
		fields := strings.SplitN(p, ":", 3)
		if len(fields) < 3 {
			continue
		}
		ruleID := fields[0]
		severity := fields[1]
		score, _ := strconv.Atoi(fields[2])
		// Strip PE- prefix if present (backward compat with pre-v6 default rules).
		cleanID := strings.TrimPrefix(ruleID, "PE-")
		// Try to parse as numeric rule ID for the int field.
		numID, _ := strconv.Atoi(cleanID)
		// Map severity string to numeric (matches Coraza convention).
		sevNum := 0
		switch severity {
		case "CRITICAL":
			sevNum = 2
		case "ERROR":
			sevNum = 3
		case "WARNING":
			sevNum = 4
		case "NOTICE":
			sevNum = 5
		}
		rules = append(rules, MatchedRule{
			ID:       numID,
			Name:     cleanID,
			Msg:      cleanID + " (" + severity + ", score " + strconv.Itoa(score) + ")",
			Severity: sevNum,
			Tags:     []string{"detect", "score:" + strconv.Itoa(score)},
		})
	}
	return rules
}

// detectMatchEntry mirrors the plugin's detectMatchEntry struct for JSON deserialization.
type detectMatchEntry struct {
	RuleID   string              `json:"rule_id"`
	RuleName string              `json:"rule_name,omitempty"`
	Severity string              `json:"severity"`
	Score    int                 `json:"score"`
	Matches  []MatchedRuleDetail `json:"matches,omitempty"`
}

// enrichMatchedRulesWithDetails parses the policy_detect_matches JSON and enriches
// the MatchedRule slice with per-condition match details (field, var_name, value,
// matched_data, operator). This provides Coraza-style MATCHED_VAR_NAME / MATCHED_VAR
// observability for detect rules.
func enrichMatchedRulesWithDetails(rules []MatchedRule, detectMatchesJSON string) {
	if detectMatchesJSON == "" || len(rules) == 0 {
		return
	}

	var entries []detectMatchEntry
	if err := json.Unmarshal([]byte(detectMatchesJSON), &entries); err != nil {
		log.Printf("[WARN] failed to parse policy_detect_matches JSON: %v", err)
		return
	}

	// Match by rule name: MatchedRule.Name is the clean rule ID (e.g., "920350").
	// detectMatchEntry.RuleID may have PE- prefix (pre-v6) or be clean.
	for i := range rules {
		for _, entry := range entries {
			entryCleanID := strings.TrimPrefix(entry.RuleID, "PE-")
			if rules[i].Name == entryCleanID || strings.HasPrefix(rules[i].Msg, entry.RuleID+" ") {
				rules[i].Matches = entry.Matches
				// Ensure Name is set from the match entry if not already.
				if rules[i].Name == "" {
					rules[i].Name = entryCleanID
				}
				// Also set MatchedData to a summary if the rule has match details.
				if len(entry.Matches) > 0 && rules[i].MatchedData == "" {
					// Use the first match's data as the primary MatchedData.
					m := entry.Matches[0]
					if m.MatchedData != "" {
						rules[i].MatchedData = m.VarName + ": " + m.MatchedData
					} else if m.Value != "" {
						rules[i].MatchedData = m.VarName + ": " + m.Value
					}
				}
				break
			}
		}
	}
}

// sortRulesByPriority returns a priority-sorted copy of rules for evaluation.
func sortRulesByPriority(rules []RateLimitRule) []RateLimitRule {
	if len(rules) == 0 {
		return nil
	}
	sorted := make([]RateLimitRule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})
	return sorted
}
