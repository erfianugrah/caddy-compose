package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
	BytesRead            int                 `json:"bytes_read"`                             // request body bytes consumed
	RequestID            string              `json:"request_id,omitempty"`                   // Caddy UUID via log_append
	PolicyAction         string              `json:"policy_action,omitempty"`                // log_append: policy engine action (allow/block/honeypot/detect_block)
	PolicyRule           string              `json:"policy_rule,omitempty"`                  // log_append: matched policy engine rule name
	PolicyTags           string              `json:"policy_tags,omitempty"`                  // log_append: comma-separated tags from matched rule(s)
	PolicyScore          string              `json:"policy_score,omitempty"`                 // log_append: anomaly score (detect rules only)
	PolicyDetectRules    string              `json:"policy_detect_rules,omitempty"`          // log_append: matched detect rule details "id:severity:score,..."
	PolicyDetectMatches  string              `json:"policy_detect_matches,omitempty"`        // log_append: JSON array of per-rule match details (field/var_name/value/matched_data)
	PolicyRequestHeaders string              `json:"policy_request_headers,omitempty"`       // log_append: JSON-serialized request headers (block/detect_block only)
	PolicyRequestBody    string              `json:"policy_request_body,omitempty"`          // log_append: truncated request body excerpt (block/detect_block only)
	PolicyJA4            string              `json:"policy_ja4,omitempty"`                   // log_append: JA4 TLS fingerprint
	ChallengeBotScore    string              `json:"policy_challenge_bot_score,omitempty"`   // log_append: bot signal score (0-100)
	ChallengeJTI         string              `json:"policy_challenge_jti,omitempty"`         // log_append: challenge cookie token ID
	ChallengeDifficulty  string              `json:"policy_challenge_difficulty,omitempty"`  // log_append: selected difficulty (after adaptive)
	ChallengeElapsedMs   string              `json:"policy_challenge_elapsed_ms,omitempty"`  // log_append: client-reported solve time in ms
	ChallengePreScore    string              `json:"policy_challenge_pre_score,omitempty"`   // log_append: pre-signal score (L1/L2/L5)
	ChallengeFailReason  string              `json:"policy_challenge_fail_reason,omitempty"` // log_append: why challenge failed (bot_score, timing_hard, ja4_mismatch, etc.)
	ChallengeSignals     string              `json:"policy_challenge_signals,omitempty"`     // log_append: JSON signal breakdown from 5-layer bot scoring
	SessionBeacon        string              `json:"policy_session_beacon,omitempty"`        // log_append: session beacon JSON from service worker/page collector
	SessionJTI           string              `json:"policy_session_jti,omitempty"`           // log_append: challenge cookie JTI for session correlation
	DDoSAction           string              `json:"ddos_action,omitempty"`                  // log_append: ddos mitigator action (pass/blocked/jailed)
	DDoSFingerprint      string              `json:"ddos_fingerprint,omitempty"`             // log_append: FNV-64a request fingerprint
	DDoSZScore           string              `json:"ddos_z_score,omitempty"`                 // log_append: z-score at time of evaluation
	DDoSSpikeMode        string              `json:"ddos_spike_mode,omitempty"`              // log_append: "true"/"false" — spike detection state
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
	Status         int                 `json:"status,omitempty"`   // original HTTP status (for logged events: 200)
	UserAgent      string              `json:"user_agent"`
	Source         string              `json:"source,omitempty"`          // "" = rate_limited, "policy" = policy engine block, "detect_block" = anomaly threshold, "logged" = below-threshold detect
	RuleName       string              `json:"rule_name,omitempty"`       // policy engine: X-Blocked-Rule header value or detect summary
	RequestID      string              `json:"request_id,omitempty"`      // Caddy UUID for cross-log correlation
	AnomalyScore   int                 `json:"anomaly_score,omitempty"`   // detect_block/logged: total anomaly score
	DetectRules    string              `json:"detect_rules,omitempty"`    // detect_block/logged: "id:severity:score,..." detail string
	DetectMatches  string              `json:"detect_matches,omitempty"`  // detect_block/logged: raw JSON of per-rule match details
	InlineTags     []string            `json:"inline_tags,omitempty"`     // detect_block/logged: tags from policy_tags log_append field
	RequestHeaders map[string][]string `json:"request_headers,omitempty"` // block/detect_block: captured request headers
	RequestBody    string              `json:"request_body,omitempty"`    // block/detect_block: truncated body excerpt
	// Challenge/JA4 fields
	JA4                 string `json:"ja4,omitempty"`                   // JA4 TLS fingerprint
	ChallengeBotScore   int    `json:"challenge_bot_score,omitempty"`   // bot signal score (0-100)
	ChallengeJTI        string `json:"challenge_jti,omitempty"`         // challenge cookie token ID
	ChallengeDifficulty int    `json:"challenge_difficulty,omitempty"`  // selected difficulty (after adaptive)
	ChallengeElapsedMs  int    `json:"challenge_elapsed_ms,omitempty"`  // client-reported solve time ms
	ChallengePreScore   int    `json:"challenge_pre_score,omitempty"`   // pre-signal score (L1/L2/L5)
	ChallengeFailReason string `json:"challenge_fail_reason,omitempty"` // why challenge failed: bot_score, timing_hard, timing_soft, ja4_mismatch, bad_pow, hmac_invalid, payload_expired, ip_mismatch, cookie_expired
	ChallengeSignals    string `json:"challenge_signals,omitempty"`     // JSON signal breakdown from 5-layer bot scoring (ja4, headers, js, behavior, spatial)
	ChallengeAlgorithm  string `json:"challenge_algorithm,omitempty"`   // "fast" or "slow" — enriched from matched rule config (not in access log)
	// DDoS mitigator fields (populated for ddos_blocked/ddos_jailed events)
	DDoSAction      string `json:"ddos_action,omitempty"`
	DDoSFingerprint string `json:"ddos_fingerprint,omitempty"`
	DDoSScore       string `json:"ddos_score,omitempty"`
}

// inferChallengeFailReason derives a likely fail reason from existing signal data
// when the plugin doesn't emit an explicit fail_reason field. This provides useful
// context while the plugin is being updated to emit fail reasons natively.
//
// Fail reason hierarchy (checked in order of specificity):
//   - timing_hard:     solve time impossibly fast (elapsed < minSolveMs/3)
//   - timing_soft:     solve time suspiciously fast (elapsed < minSolveMs) — +40 penalty
//   - bot_score:       total bot score >= 70 (most common rejection reason)
//   - bad_pow:         fallback — PoW didn't verify (no specific signal matched)
func inferChallengeFailReason(rle RateLimitEvent) string {
	// Timing violation detection — replicate the plugin's minSolveMs formula.
	// minSolveMs(difficulty, cores) = 2^(difficulty*4) / (cores * 50) * 0.3
	// We don't have cores in the log, so estimate conservatively with cores=16.
	if rle.ChallengeElapsedMs > 0 && rle.ChallengeDifficulty > 0 && rle.ChallengeDifficulty <= 15 {
		estimatedCores := 16
		var minMs float64
		if rle.ChallengeAlgorithm == "slow" {
			// Slow mode: 10ms delay per iteration. Expected iterations / cores.
			iterations := float64(uint64(1)<<(rle.ChallengeDifficulty*4)) / 2.0
			minMs = (iterations / float64(estimatedCores)) * 10.0 * 0.3
		} else {
			// Fast mode: ~2μs per SHA-256 hash via WebCrypto.
			hashSpace := uint64(1) << (rle.ChallengeDifficulty * 4) // 2^(difficulty*4), safe for difficulty 1-15
			minMs = float64(hashSpace) / float64(estimatedCores*50) * 0.3
		}
		if float64(rle.ChallengeElapsedMs) < minMs/3 {
			return "timing_hard"
		}
		if float64(rle.ChallengeElapsedMs) < minMs {
			return "timing_soft"
		}
	}

	// Bot score threshold — the most common rejection reason.
	if rle.ChallengeBotScore >= 70 {
		return "bot_score"
	}

	// If we have a pre-signal score that's very high but the bot score wasn't
	// captured (e.g., failed before JS scoring), flag as pre-signal rejection.
	if rle.ChallengePreScore >= 70 && rle.ChallengeBotScore == 0 {
		return "pre_signal"
	}

	// Fallback — we know it failed but can't determine exactly why from available data.
	return "bad_pow"
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

	// maxItems is a hard cap on in-memory events. When exceeded after ingestion,
	// oldest events are evicted regardless of age. Zero means no cap.
	// This prevents OOM under bombardment (791K events = 630MB JSONL).
	maxItems int

	// geoIP is an optional GeoIP store for country enrichment.
	geoIP *GeoIPStore

	// exclusionStore is an optional reference for enriching policy engine events with tags.
	exclusionStore *ExclusionStore

	// sessionStore is an optional reference for ingesting session beacon data.
	sessionStore *SessionStore

	// generation increments on every Load() that adds/evicts events.
	generation atomic.Int64

	// advCache caches advisor scan results for 30 seconds to avoid
	// redundant 20MB disk scans on rapid re-queries.
	advCache *advisorCache

	// counters holds incrementally-maintained per-hour summary statistics.
	// Updated on ingestion and eviction so that summary queries are O(buckets)
	// instead of O(events).
	counters *summaryCounters

	// Secondary indexes for fast filtered queries. Updated on ingestion/eviction.
	// Maps field value → sorted list of event indices into s.events.
	idxSource  map[string][]int // Source field (event_type after rleEventType)
	idxClient  map[string][]int // ClientIP
	idxService map[string][]int // Service
}

func NewAccessLogStore(path string) *AccessLogStore {
	return &AccessLogStore{
		path:       path,
		advCache:   newAdvisorCache(),
		counters:   newSummaryCounters(),
		idxSource:  make(map[string][]int),
		idxClient:  make(map[string][]int),
		idxService: make(map[string][]int),
	}
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
			log.Printf("[access-log] restored offset %d from %s", v, path)
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
		log.Printf("[access-log] error saving offset to %s: %v", s.offsetFile, err)
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

// SetSessionStore configures the session store for ingesting session beacon data.
func (s *AccessLogStore) SetSessionStore(ss *SessionStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionStore = ss
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
			log.Printf("[access-log] error loading RL events from %s: %v", path, err)
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
	log.Printf("[access-log] restored %d RL events from %s", len(events), path)
	if migrated > 0 {
		log.Printf("[access-log] migrated %d legacy ipsum events to policy source", migrated)
		s.compactEventFileLocked()
	}
	// Initialize incremental counters from restored events.
	s.initCountersFromRLEventsLocked()
	// Rebuild secondary indexes from restored events.
	s.rebuildIndexes()
}

// appendEventsToJSONL appends rate limit events to the JSONL file.
func (s *AccessLogStore) appendEventsToJSONL(events []RateLimitEvent) {
	if s.eventFile == "" || len(events) == 0 {
		return
	}
	f, err := os.OpenFile(s.eventFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[access-log] error opening RL event file for append: %v", err)
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
			log.Printf("[access-log] error writing RL event to JSONL: %v", err)
			return
		}
	}
	if err := f.Sync(); err != nil {
		log.Printf("[access-log] error syncing RL event file: %v", err)
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
	snapshot := make([]RateLimitEvent, len(s.events))
	copy(snapshot, s.events)
	s.mu.RUnlock()
	writeCompactedRLEvents(s.eventFile, snapshot)
}

// compactEventFileLocked rewrites the JSONL file with the current in-memory
// events. The caller MUST hold s.mu (at least RLock).
// Uses a snapshot copy so the write lock can be released before disk I/O.
func (s *AccessLogStore) compactEventFileLocked() {
	if s.eventFile == "" {
		return
	}
	// Copy the events under the caller's lock, then write outside any lock.
	snapshot := make([]RateLimitEvent, len(s.events))
	copy(snapshot, s.events)
	// Note: the caller still holds the write lock here. In the eviction path,
	// the lock is released after this method returns. The disk write uses the
	// snapshot so it doesn't access s.events. This keeps the critical section
	// short (just the copy) while the slow I/O happens on the snapshot.
	writeCompactedRLEvents(s.eventFile, snapshot)
}

// writeCompactedRLEvents atomically rewrites a JSONL file from a snapshot.
// Does not hold any locks — safe to call outside critical sections.
func writeCompactedRLEvents(path string, events []RateLimitEvent) {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		log.Printf("[access-log] error creating temp RL event file for compaction: %v", err)
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
		log.Printf("[access-log] error writing compacted RL event file: %v", writeErr)
		return
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		log.Printf("[access-log] error syncing compacted RL event file: %v", err)
		return
	}
	f.Close()
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[access-log] error renaming compacted RL event file: %v", err)
		return
	}
	log.Printf("[access-log] compacted RL event file: %d events", count)
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

// SetMaxItems configures the hard cap on in-memory events.
// When exceeded, oldest events are evicted regardless of age.
func (s *AccessLogStore) SetMaxItems(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxItems = n
}

// initCountersFromRLEventsLocked initializes incremental counters from the
// current in-memory RateLimitEvents. The caller MUST hold s.mu.
// Uses initFromRLEvents to avoid the O(N) allocation of converting
// every RateLimitEvent to Event.
func (s *AccessLogStore) initCountersFromRLEventsLocked() {
	if s.counters == nil {
		return
	}
	s.counters.initFromRLEvents(s.events)
}

// --- Secondary Index Methods ---

// indexEvent adds a single event at the given index to all secondary indexes.
// Keys are lowercased for case-insensitive lookups consistent with fieldFilter.matchField.
// The caller MUST hold s.mu (at least write lock).
func (s *AccessLogStore) indexEvent(idx int) {
	rle := &s.events[idx]
	eventType := rleEventType(rle.Source)
	s.idxSource[eventType] = append(s.idxSource[eventType], idx)
	clientKey := strings.ToLower(rle.ClientIP)
	s.idxClient[clientKey] = append(s.idxClient[clientKey], idx)
	serviceKey := strings.ToLower(rle.Service)
	s.idxService[serviceKey] = append(s.idxService[serviceKey], idx)
}

// rebuildIndexes rebuilds all secondary indexes from scratch.
// Called after eviction shifts indices. The caller MUST hold s.mu.
func (s *AccessLogStore) rebuildIndexes() {
	s.idxSource = make(map[string][]int, len(s.idxSource))
	s.idxClient = make(map[string][]int, len(s.idxClient))
	s.idxService = make(map[string][]int, len(s.idxService))
	for i := range s.events {
		s.indexEvent(i)
	}
}

// indexedRLSnapshot returns a filtered snapshot of RateLimitEvents using
// secondary indexes when single-value "eq" filters are available.
// Falls back to a full scan when indexes cannot be used. The caller
// does NOT need to hold s.mu — this method acquires RLock internally.
func (s *AccessLogStore) indexedRLSnapshot(eventType, clientIP, service string, hours int) []RateLimitEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.events) == 0 {
		return nil
	}

	// Determine the time window.
	var startIdx int
	if hours > 0 {
		cutoff := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
		startIdx = searchCutoffRL(s.events, cutoff)
	}

	// Try to use the most selective index.
	// Keys are lowercased to match how indexEvent stores them.
	var candidates []int
	used := false

	if eventType != "" {
		etKey := strings.ToLower(eventType)
		if idxList, ok := s.idxSource[etKey]; ok {
			candidates = idxList
			used = true
		} else {
			// No events with this event type — return empty.
			return nil
		}
	}
	if clientIP != "" {
		ciKey := strings.ToLower(clientIP)
		if idxList, ok := s.idxClient[ciKey]; ok {
			if !used || len(idxList) < len(candidates) {
				candidates = idxList
				used = true
			}
		} else {
			return nil
		}
	}
	if service != "" {
		svcKey := strings.ToLower(service)
		if idxList, ok := s.idxService[svcKey]; ok {
			if !used || len(idxList) < len(candidates) {
				candidates = idxList
				used = true
			}
		} else {
			return nil
		}
	}

	if !used {
		// No index applicable — fall back to full snapshot.
		n := len(s.events) - startIdx
		cp := make([]RateLimitEvent, n)
		copy(cp, s.events[startIdx:])
		return cp
	}

	// Filter candidates by all criteria (time window + all three fields).
	// Use case-insensitive comparison consistent with fieldFilter.matchField "eq".
	result := make([]RateLimitEvent, 0, len(candidates)/2)
	for _, idx := range candidates {
		if idx < startIdx {
			continue
		}
		rle := &s.events[idx]
		if eventType != "" && !strings.EqualFold(rleEventType(rle.Source), eventType) {
			continue
		}
		if clientIP != "" && !strings.EqualFold(rle.ClientIP, clientIP) {
			continue
		}
		if service != "" && !strings.EqualFold(rle.Service, service) {
			continue
		}
		result = append(result, *rle)
	}
	return result
}

// Load reads new lines from the combined access log and extracts 429 events.
func (s *AccessLogStore) Load() {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[access-log] combined access log not found at %s, will retry", s.path)
			return
		}
		log.Printf("[access-log] error opening combined access log: %v", err)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.Printf("[access-log] error stat combined access log: %v", err)
		return
	}

	// Detect rotation.
	curOffset := s.offset.Load()
	if info.Size() < curOffset {
		log.Printf("[access-log] combined access log rotated (size %d < offset %d), re-reading", info.Size(), curOffset)
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
			log.Printf("[access-log] error seeking combined access log: %v", err)
			return
		}
	}

	// Snapshot geoIP reference under lock to avoid a data race with SetGeoIP.
	s.mu.RLock()
	geoIP := s.geoIP
	s.mu.RUnlock()

	var newEvents []RateLimitEvent
	reader := bufio.NewReaderSize(f, 64*1024)
	// Use ReadBytes instead of Scanner — no line length limit. Access log
	// lines are typically small but this avoids a latent stall risk if a
	// line ever exceeds 1MB.
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
		}
		if len(line) > 0 {
			var entry AccessLogEntry
			if jsonErr := json.Unmarshal(line, &entry); jsonErr == nil {
				// Collect security-relevant events from the access log:
				// - 429 (rate limited)
				// - 403 with policy engine block
				// - policy_action=skip (selective bypass, non-terminating)
				// - below-threshold detect (score > 0 with CRS rule matches)
				isDDoSBlock := entry.DDoSAction == "blocked" || entry.DDoSAction == "jailed"
				isRateLimit := entry.Status == 429
				isPolicy := entry.Status == 403 && isPolicyBlocked(entry) && !isDDoSBlock
				isSkip := entry.PolicyAction == "skip"
				isChallenge := entry.PolicyAction == "challenge_issued" ||
					entry.PolicyAction == "challenge_passed" ||
					entry.PolicyAction == "challenge_failed" ||
					entry.PolicyAction == "challenge_bypassed"
				// detection_only: plugin logs _logged variants when it would have
				// blocked but detection_only mode suppressed the block action.
				isDetectionOnlyBlock := entry.PolicyAction == "block_logged" ||
					entry.PolicyAction == "honeypot_logged"
				isDetectionOnlyRL := entry.PolicyAction == "rate_limit_logged"

				// Session beacon: forward to session store, don't create a security event.
				if entry.PolicyAction == "session_beacon" && entry.SessionBeacon != "" && s.sessionStore != nil {
					var beacons []SessionBeaconEntry
					if json.Unmarshal([]byte(entry.SessionBeacon), &beacons) == nil {
						jti := filterNone(entry.SessionJTI)
						ip := entry.Request.ClientIP
						ja4 := filterNone(entry.PolicyJA4)
						service := entry.Request.Host
						s.sessionStore.IngestBeacon(jti, ip, ja4, service, beacons)
					}
					continue // session beacons are not security events
				}
				isLogged := !isPolicy && !isRateLimit && !isSkip && !isDDoSBlock && !isChallenge &&
					!isDetectionOnlyBlock && !isDetectionOnlyRL &&
					entry.PolicyScore != "" && entry.PolicyScore != "0" &&
					(entry.PolicyDetectRules != "" || entry.PolicyDetectMatches != "")
				if isDDoSBlock || isRateLimit || isPolicy || isSkip || isChallenge || isLogged ||
					isDetectionOnlyBlock || isDetectionOnlyRL {
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
						Status:    entry.Status,
						UserAgent: ua,
						RequestID: accessLogRequestID(entry),
					}
					if isDDoSBlock {
						evt.Source = "ddos_" + entry.DDoSAction // "ddos_blocked" or "ddos_jailed"
						evt.RuleName = "ddos_mitigator"
						evt.DDoSAction = entry.DDoSAction
						evt.DDoSFingerprint = entry.DDoSFingerprint
						evt.DDoSScore = entry.DDoSZScore
						if entry.DDoSFingerprint != "" {
							evt.InlineTags = []string{"ddos", entry.DDoSAction}
						}
					} else if isPolicy && isDetectBlock(entry) {
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
					} else if isSkip {
						// Policy engine skip: selective bypass of specific rules/phases.
						evt.Source = "policy_skip"
						evt.RuleName = entry.PolicyRule
						if entry.PolicyTags != "" {
							evt.InlineTags = strings.Split(entry.PolicyTags, ",")
						}
					} else if isChallenge {
						// Policy engine challenge: PoW interstitial action.
						evt.Source = entry.PolicyAction // "challenge_issued", "challenge_passed", "challenge_failed", "challenge_bypassed"
						evt.RuleName = entry.PolicyRule
						if entry.PolicyTags != "" {
							evt.InlineTags = strings.Split(entry.PolicyTags, ",")
						}
					} else if isDetectionOnlyBlock {
						// detection_only: block rule matched but suppressed. Log as
						// the original action with a "detection_only" tag for visibility.
						evt.Source = "policy"
						evt.RuleName = policyBlockedRuleName(entry)
						if entry.PolicyTags != "" {
							evt.InlineTags = strings.Split(entry.PolicyTags, ",")
						}
						evt.InlineTags = append(evt.InlineTags, "detection_only")
					} else if isDetectionOnlyRL {
						// detection_only: rate limit exceeded but suppressed.
						evt.Source = "policy_rl"
						evt.RuleName = entry.PolicyRule
						if entry.PolicyTags != "" {
							evt.InlineTags = strings.Split(entry.PolicyTags, ",")
						}
						evt.InlineTags = append(evt.InlineTags, "detection_only")
					} else if isLogged {
						// Below-threshold detect: CRS rules fired but score didn't
						// exceed the inbound threshold. These appear as "logged" events
						// so tuning/log-only mode has visibility.
						evt.Source = "logged"
						evt.DetectRules = entry.PolicyDetectRules
						evt.DetectMatches = entry.PolicyDetectMatches
						evt.AnomalyScore, _ = strconv.Atoi(entry.PolicyScore)
						if entry.PolicyTags != "" {
							evt.InlineTags = strings.Split(entry.PolicyTags, ",")
						}
					}
					// Capture request context from policy engine (all event types).
					if entry.PolicyRequestHeaders != "" && entry.PolicyRequestHeaders != "None" {
						evt.RequestHeaders = parsePolicyRequestHeaders(entry.PolicyRequestHeaders)
					}
					if entry.PolicyRequestBody != "" && entry.PolicyRequestBody != "None" {
						evt.RequestBody = entry.PolicyRequestBody
					}
					if isRateLimit && isPolicyRateLimit(entry) {
						// Policy engine rate limit — has rule name attribution.
						evt.Source = "policy_rl"
						evt.RuleName = policyRateLimitRuleName(entry)
					}
					// Enrich with country from Cf-Ipcountry header or MMDB lookup.
					if geoIP != nil {
						cfCountry := headerValue(entry.Request.Headers, "Cf-Ipcountry")
						evt.Country = geoIP.Resolve(entry.Request.ClientIP, cfCountry)
					}
					// JA4 TLS fingerprint + challenge fields (available on all events).
					if entry.PolicyJA4 != "" && entry.PolicyJA4 != "None" {
						evt.JA4 = entry.PolicyJA4
					}
					if entry.ChallengeBotScore != "" && entry.ChallengeBotScore != "None" {
						evt.ChallengeBotScore, _ = strconv.Atoi(entry.ChallengeBotScore)
					}
					if entry.ChallengeJTI != "" && entry.ChallengeJTI != "None" {
						evt.ChallengeJTI = entry.ChallengeJTI
					}
					if entry.ChallengeDifficulty != "" && entry.ChallengeDifficulty != "None" {
						evt.ChallengeDifficulty, _ = strconv.Atoi(entry.ChallengeDifficulty)
					}
					if entry.ChallengeElapsedMs != "" && entry.ChallengeElapsedMs != "None" {
						evt.ChallengeElapsedMs, _ = strconv.Atoi(entry.ChallengeElapsedMs)
					}
					if entry.ChallengePreScore != "" && entry.ChallengePreScore != "None" {
						evt.ChallengePreScore, _ = strconv.Atoi(entry.ChallengePreScore)
					}
					if entry.ChallengeFailReason != "" && entry.ChallengeFailReason != "None" {
						evt.ChallengeFailReason = entry.ChallengeFailReason
					}
					if entry.ChallengeSignals != "" && entry.ChallengeSignals != "None" {
						evt.ChallengeSignals = entry.ChallengeSignals
					}
					// Heuristic fail reason inference when plugin doesn't emit one.
					if evt.Source == "challenge_failed" && evt.ChallengeFailReason == "" {
						evt.ChallengeFailReason = inferChallengeFailReason(evt)
					}
					newEvents = append(newEvents, evt)
				}
			}
			// skip malformed lines silently — high volume log
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[access-log] error reading combined access log: %v", err)
			}
			break
		}
	}

	newOffset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		log.Printf("[access-log] error getting combined access log offset: %v", err)
	} else {
		s.offset.Store(newOffset)
		s.saveOffset()
	}

	if len(newEvents) > 0 {
		s.mu.Lock()
		baseIdx := len(s.events)
		s.events = append(s.events, newEvents...)
		// Index newly appended events.
		for i := baseIdx; i < len(s.events); i++ {
			s.indexEvent(i)
		}
		s.mu.Unlock()
		s.generation.Add(1)
		// Persist new events to JSONL.
		s.appendEventsToJSONL(newEvents)
		// Update incremental summary counters for new events.
		// Uses incrementRLEvent to avoid temporary Event allocations.
		if s.counters != nil {
			for i := range newEvents {
				s.counters.incrementRLEvent(&newEvents[i])
			}
		}
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
		log.Printf("[access-log] loaded %d new events (%d rate-limit, %d policy-rl, %d policy-block) — %d total", len(newEvents), rlCount, policyRLCount, policyCount, s.EventCount())
	}

	// Evict events older than maxAge.
	s.evict()
}

// evict removes events older than maxAge and enforces maxItems cap.
func (s *AccessLogStore) evict() {
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

	// Count-based cap: if still over maxItems, evict more oldest events.
	// Target 80% of cap to avoid evicting on every ingestion cycle.
	if s.maxItems > 0 && len(s.events)-idx > s.maxItems {
		target := s.maxItems * 80 / 100
		idx = len(s.events) - target
	}
	if idx > 0 {
		// Decrement incremental summary counters for evicted events.
		// Uses decrementRLEvent to avoid temporary Event allocations.
		if s.counters != nil {
			for i := 0; i < idx; i++ {
				s.counters.decrementRLEvent(&s.events[i])
			}
		}
		evicted := idx
		total := len(s.events)
		remaining := make([]RateLimitEvent, total-idx)
		copy(remaining, s.events[idx:])
		s.events = remaining
		// Rebuild secondary indexes — eviction shifts all indices.
		s.rebuildIndexes()
		s.generation.Add(1)

		// Only compact when eviction is significant (>5% or >10K events removed).
		// Rewriting 460MB of JSONL for 21 evicted events out of 208K is wasteful.
		evictPct := float64(evicted) / float64(total) * 100
		if evicted > 10000 || evictPct > 5.0 {
			log.Printf("[access-log] evicted %d events older than %s (%d remaining, %.1f%%) — compacting", evicted, s.maxAge, len(s.events), evictPct)
			s.compactEventFileLocked()
		} else {
			log.Printf("[access-log] evicted %d events older than %s (%d remaining, %.1f%%) — skipping compaction", evicted, s.maxAge, len(s.events), evictPct)
		}
	}
}

// StartTailing periodically loads new 429 events.
// The goroutine exits when ctx is cancelled.
func (s *AccessLogStore) StartTailing(ctx context.Context, interval time.Duration) {
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

func (s *AccessLogStore) EventCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// IngestAbandonedFile reads challenge-abandoned.jsonl written by the plugin,
// converts each entry to a RateLimitEvent with source "challenge_abandoned",
// appends them to the event store, and truncates the file. Called periodically.
func (s *AccessLogStore) IngestAbandonedFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		log.Printf("[access-log] read abandoned file: %v", err)
		return 0
	}
	if len(data) == 0 {
		return 0
	}

	type abandonedEntry struct {
		ClientIP   string `json:"client_ip"`
		Service    string `json:"service"`
		JA4        string `json:"ja4,omitempty"`
		Difficulty int    `json:"difficulty"`
		IssuedAt   int64  `json:"issued_at"`
		ExpiredAt  int64  `json:"expired_at"`
	}

	var events []RateLimitEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var entry abandonedEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			log.Printf("[access-log] parse abandoned entry: %v", err)
			continue
		}
		events = append(events, RateLimitEvent{
			Timestamp:           time.Unix(entry.ExpiredAt, 0).UTC(),
			ClientIP:            entry.ClientIP,
			Service:             entry.Service,
			JA4:                 entry.JA4,
			Source:              "challenge_abandoned",
			ChallengeDifficulty: entry.Difficulty,
			Status:              200, // interstitial was served as 200
		})
	}

	if len(events) == 0 {
		return 0
	}

	// Append to the store.
	s.mu.Lock()
	for i := range events {
		s.events = append(s.events, events[i])
		s.indexEvent(len(s.events) - 1)
		if s.counters != nil {
			s.counters.incrementRLEvent(&events[i])
		}
	}
	s.generation.Add(1)
	s.mu.Unlock()

	// Persist to event JSONL if configured.
	if s.eventFile != "" {
		s.appendEventsToJSONL(events)
	}

	// Truncate the file after successful ingestion.
	if err := os.Truncate(path, 0); err != nil {
		log.Printf("[access-log] truncate abandoned file: %v", err)
	}

	log.Printf("[access-log] ingested %d abandoned challenge events", len(events))
	return len(events)
}

// FastSummary returns a SummaryResponse computed from incremental per-hour
// counters. This is O(buckets) instead of O(events) — typically ~100x faster
// for large event stores. If hours <= 0, all buckets are included.
// Falls back to a full scan if counters are not initialized or empty
// while events exist (e.g. events set directly without going through Load()).
func (s *AccessLogStore) FastSummary(hours int) SummaryResponse {
	if s.counters == nil || (s.counters.totalEvents() == 0 && s.EventCount() > 0) {
		log.Printf("[access-log] perf: FastSummary falling back to O(N) scan (%d events)", s.EventCount())
		// Fallback: convert RL events to unified Events and summarize.
		rlEvents := s.snapshotSince(hours)
		events := make([]Event, len(rlEvents))
		for i := range rlEvents {
			events[i] = RateLimitEventToEvent(rlEvents[i], nil)
		}
		return summarizeEvents(events)
	}
	return s.counters.buildSummary(hours)
}

// Stats returns health-check information about the access log store.
func (s *AccessLogStore) Stats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.statsLocked()
}

func (s *AccessLogStore) statsLocked() map[string]any {
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
	case "ddos_blocked":
		// DDoS mitigator blocked the IP (behavioral anomaly detected).
		status = 403
		eventType = "ddos_blocked"
	case "ddos_jailed":
		// DDoS mitigator auto-jailed the IP (first offense).
		status = 403
		eventType = "ddos_jailed"
	case "policy_skip":
		// Policy engine skip: selective bypass, request passed through.
		status = rle.Status
		eventType = "policy_skip"
	case "challenge_issued":
		// Challenge interstitial served (not a block — client may solve it).
		status = rle.Status
		eventType = "challenge_issued"
	case "challenge_passed":
		// Client solved the PoW challenge successfully.
		status = rle.Status
		eventType = "challenge_passed"
	case "challenge_failed":
		// Client submitted invalid PoW solution.
		status = 403
		eventType = "challenge_failed"
	case "challenge_bypassed":
		// Valid challenge cookie present, challenge skipped.
		status = rle.Status
		eventType = "challenge_bypassed"
	case "challenge_abandoned":
		// Client received interstitial but never submitted to verify endpoint.
		status = 200
		eventType = "challenge_abandoned"
	case "logged":
		// Below-threshold detect: CRS rules scored but didn't exceed threshold.
		status = rle.Status
		eventType = "logged"
	}
	if len(extraTags) > 0 {
		tags = append(tags, extraTags...)
	}
	// Non-blocking event types.
	nonBlocking := map[string]bool{
		"logged": true, "policy_skip": true,
		"challenge_issued": true, "challenge_passed": true, "challenge_bypassed": true, "challenge_abandoned": true,
	}
	isBlocked := !nonBlocking[rle.Source]
	evt := Event{
		ID:             rle.RequestID,
		Timestamp:      rle.Timestamp,
		ClientIP:       rle.ClientIP,
		Country:        rle.Country,
		Service:        rle.Service,
		Method:         rle.Method,
		URI:            rle.URI,
		Protocol:       rle.Protocol,
		IsBlocked:      isBlocked,
		ResponseStatus: status,
		UserAgent:      rle.UserAgent,
		EventType:      eventType,
		Tags:           tags,
		RequestID:      rle.RequestID,
	}
	// JA4 TLS fingerprint + challenge fields (available on all events).
	if rle.JA4 != "" {
		evt.JA4 = rle.JA4
	}
	if rle.ChallengeBotScore > 0 {
		evt.ChallengeBotScore = rle.ChallengeBotScore
	}
	if rle.ChallengeJTI != "" {
		evt.ChallengeJTI = rle.ChallengeJTI
	}
	if rle.ChallengeDifficulty > 0 {
		evt.ChallengeDifficulty = rle.ChallengeDifficulty
	}
	if rle.ChallengeElapsedMs > 0 {
		evt.ChallengeElapsedMs = rle.ChallengeElapsedMs
	}
	if rle.ChallengePreScore > 0 {
		evt.ChallengePreScore = rle.ChallengePreScore
	}
	if rle.ChallengeFailReason != "" {
		evt.ChallengeFailReason = rle.ChallengeFailReason
	}
	if rle.ChallengeSignals != "" {
		evt.ChallengeSignals = rle.ChallengeSignals
	}
	if rle.ChallengeAlgorithm != "" {
		evt.ChallengeAlgorithm = rle.ChallengeAlgorithm
	}
	// For DDoS mitigator blocks, pass through fingerprint and score.
	if rle.Source == "ddos_blocked" || rle.Source == "ddos_jailed" {
		evt.DDoSAction = rle.DDoSAction
		evt.DDoSFingerprint = rle.DDoSFingerprint
		evt.DDoSScore = rle.DDoSScore
		evt.BlockedBy = "ddos_mitigator"
		evt.RuleMsg = "DDoS Mitigator: " + rle.DDoSAction
	}
	// For policy engine blocks, set the rule message from X-Blocked-Rule header.
	if rle.Source == "policy" && rle.RuleName != "" {
		evt.RuleMsg = "Policy Block: " + rle.RuleName
	}
	if rle.Source == "policy_skip" && rle.RuleName != "" {
		evt.RuleMsg = "Policy Skip: " + rle.RuleName
	}
	// For challenge events, set the rule message for display in the event detail.
	if strings.HasPrefix(rle.Source, "challenge_") && rle.RuleName != "" {
		labels := map[string]string{
			"challenge_issued":    "Challenge Issued",
			"challenge_passed":    "Challenge Passed",
			"challenge_failed":    "Challenge Failed",
			"challenge_bypassed":  "Challenge Bypassed",
			"challenge_abandoned": "Challenge Abandoned (no verify attempt)",
		}
		label := labels[rle.Source]
		if label == "" {
			label = "Challenge"
		}
		evt.RuleMsg = label + ": " + rle.RuleName
	}
	// For detect_block and logged, include the anomaly score and matched rule details.
	// Enrich with CRS descriptions and populate top-level fields
	// (rule_id, severity, rule_msg, blocked_by, matched_data, rule_tags).
	if rle.Source == "detect_block" || rle.Source == "logged" {
		evt.AnomalyScore = rle.AnomalyScore
		if rle.Source == "detect_block" {
			evt.BlockedBy = "anomaly_inbound"
		}
		// Parse detect_rules into matched_rules for the event response.
		if rle.DetectRules != "" {
			evt.MatchedRules = parseDetectRulesDetail(rle.DetectRules)
		}
		// Enrich with per-condition match details from the plugin.
		if rle.DetectMatches != "" {
			enrichMatchedRulesWithDetails(evt.MatchedRules, rle.DetectMatches)
		}
		// Enrich each matched rule with CRS descriptions and build top-level fields.
		enrichDetectBlockEvent(&evt, rle.RuleName)
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
		case "detect_block", "logged":
			// Detect-threshold block or below-threshold logged — tags come inline
			// from the plugin (policy_tags log field).
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
		case "policy_skip":
			// Policy engine skip — inline tags from the plugin.
			tags = rle.InlineTags
		default:
			// Legacy caddy-ratelimit 429 — heuristic condition matching.
			tags = matchEventToRuleTags(rle, sorted)
		}
		events[i] = RateLimitEventToEvent(rle, tags)
	}
	return events
}

// parseDetectRulesDetail parses the "id:severity:score[,id:severity:score,...]"
// string from the policy engine's detect_rules log field into MatchedRule structs.
// Format: "920350:WARNING:3" or "920350:WARNING:3:log_only" (4th field = action).
func parseDetectRulesDetail(detail string) []MatchedRule {
	parts := strings.Split(detail, ",")
	var rules []MatchedRule
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Split into up to 4 fields: id:severity:score[:action]
		fields := strings.SplitN(p, ":", 4)
		if len(fields) < 3 {
			continue
		}
		ruleID := fields[0]
		severity := fields[1]
		score, _ := strconv.Atoi(fields[2])
		isLogOnly := len(fields) >= 4 && fields[3] == "log_only"
		// Strip PE- prefix if present (backward compat with pre-v6 default rules).
		cleanID := strings.TrimPrefix(ruleID, "PE-")
		// Try to parse as numeric rule ID for the int field.
		numID, _ := strconv.Atoi(cleanID)
		// Map severity string to numeric using loaded CRS metadata.
		sevNum := GetCRSMetadata().SeverityToNumeric(severity)
		tags := []string{"detect", "score:" + strconv.Itoa(score)}
		msg := cleanID + " (" + severity + ", score " + strconv.Itoa(score) + ")"
		if isLogOnly {
			tags = append(tags, "log_only")
			msg = cleanID + " (" + severity + ", log only)"
		}
		rules = append(rules, MatchedRule{
			ID:       numID,
			Name:     cleanID,
			Msg:      msg,
			Severity: sevNum,
			Tags:     tags,
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
// matched_data, operator).
func enrichMatchedRulesWithDetails(rules []MatchedRule, detectMatchesJSON string) {
	if detectMatchesJSON == "" || len(rules) == 0 {
		return
	}

	var entries []detectMatchEntry
	if err := json.Unmarshal([]byte(detectMatchesJSON), &entries); err != nil {
		log.Printf("[access-log] warning: failed to parse policy_detect_matches JSON: %v", err)
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

// enrichDetectBlockEvent enriches a detect_block Event with CRS rule descriptions
// and populates the top-level fields (RuleID, Severity, RuleMsg, MatchedData, RuleTags)
// from the highest-severity matched rule.
func enrichDetectBlockEvent(evt *Event, rawRuleName string) {
	if len(evt.MatchedRules) == 0 {
		if rawRuleName != "" {
			evt.RuleMsg = rawRuleName
		}
		return
	}

	// Enrich each matched rule with CRS/custom rule descriptions.
	for i := range evt.MatchedRules {
		r := &evt.MatchedRules[i]
		lookupID := r.Name
		if lookupID == "" && r.ID > 0 {
			lookupID = strconv.Itoa(r.ID)
		}
		if crs, ok := LookupCRSRule(lookupID); ok {
			// Replace generated msg with human-readable description.
			r.Msg = crs.Description
			// Enrich tags with CRS tags (append to existing detect/score tags).
			if len(crs.Tags) > 0 {
				r.Tags = append(r.Tags, crs.Tags...)
			}
			// Set source file equivalent from category.
			if r.File == "" && crs.Category != "" {
				r.File = "detect-rules/" + crs.Category
			}
		}
		// Format MatchedData in CRS-compatible "Matched Data: X found within Y: Z"
		// format so parseMatchedData() in the frontend works uniformly.
		if len(r.Matches) > 0 {
			m := r.Matches[0]
			if m.MatchedData != "" && m.VarName != "" {
				fullVal := m.Value
				if fullVal == "" {
					fullVal = m.MatchedData
				}
				r.MatchedData = "Matched Data: " + m.MatchedData + " found within " + m.VarName + ": " + fullVal
			}
		}
	}

	// Find the highest severity matched rule (lowest severity number = highest severity).
	best := &evt.MatchedRules[0]
	for i := 1; i < len(evt.MatchedRules); i++ {
		r := &evt.MatchedRules[i]
		if r.Severity > 0 && (best.Severity == 0 || r.Severity < best.Severity) {
			best = r
		}
	}

	// Populate top-level Event fields from the highest severity rule.
	evt.RuleID = best.ID
	evt.Severity = best.Severity
	evt.RuleMsg = best.Msg
	evt.MatchedData = best.MatchedData
	// Collect CRS category tags from enriched matched rules into RuleTags.
	// These are the tags like "application-multi", "attack-sqli", "language-shell"
	// that the CRS rule lookup adds to each matched rule.
	tagSeen := make(map[string]bool)
	var allTags []string
	// Start with event-level tags (from plugin policy_tags).
	for _, t := range evt.Tags {
		if !tagSeen[t] {
			tagSeen[t] = true
			allTags = append(allTags, t)
		}
	}
	// Add CRS tags from each matched rule (enriched by LookupCRSRule above).
	for _, r := range evt.MatchedRules {
		for _, t := range r.Tags {
			if !tagSeen[t] {
				tagSeen[t] = true
				allTags = append(allTags, t)
			}
		}
	}
	if len(allTags) > 0 {
		evt.RuleTags = allTags
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
