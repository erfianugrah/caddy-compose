package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ─── Session Tracking Store ─────────────────────────────────────────
// Stores per-JTI session data from challenge beacons. Used for session
// behavioral scoring to detect low-and-slow bots that pass challenge PoW
// but exhibit non-human browsing patterns.

// SessionEntry is one tracked session, keyed by challenge cookie JTI.
type SessionEntry struct {
	JTI         string       `json:"jti"`
	IP          string       `json:"ip"`
	JA4         string       `json:"ja4,omitempty"`
	Service     string       `json:"service"`
	FirstSeen   time.Time    `json:"first_seen"`
	LastSeen    time.Time    `json:"last_seen"`
	Navigations []Navigation `json:"navigations"`
	Score       float64      `json:"score"`           // 0-1, higher = more suspicious
	Flags       []string     `json:"flags,omitempty"` // e.g., "single_page", "uniform_dwell"
}

// Navigation is a single page visit within a session.
type Navigation struct {
	Timestamp time.Time `json:"ts"`
	Path      string    `json:"path"`
	DwellMs   int       `json:"dwell_ms,omitempty"`
	VisibleMs int       `json:"vis,omitempty"`  // visible dwell time (from page collector)
	ScrollPct int       `json:"scr,omitempty"`  // max scroll depth %
	Clicks    int       `json:"clk,omitempty"`  // click count on page
	Typed     bool      `json:"key,omitempty"`  // whether user typed on page
	Type      string    `json:"type,omitempty"` // "navigate" (from SW) or "pm" (page metrics)
}

// SessionBeaconEntry is the JSON structure sent by the client-side
// session service worker and page collector.
type SessionBeaconEntry struct {
	Timestamp int64  `json:"ts"`
	Path      string `json:"path"`
	Referrer  string `json:"ref,omitempty"`
	DwellMs   int    `json:"dwell,omitempty"`
	Type      string `json:"type,omitempty"` // "navigate" or "pm" (page metrics)
	VisibleMs int    `json:"vis,omitempty"`
	ScrollPct int    `json:"scr,omitempty"`
	Clicks    int    `json:"clk,omitempty"`
	Typed     int    `json:"key,omitempty"` // 0 or 1
}

// SessionStats is the summary returned by the API.
type SessionStats struct {
	ActiveSessions     int              `json:"active_sessions"`
	SuspiciousSessions int              `json:"suspicious_sessions"`
	TotalNavigations   int              `json:"total_navigations"`
	TopSuspicious      []SessionSummary `json:"top_suspicious"`
}

// SessionSummary is a compact view of one session for the API.
type SessionSummary struct {
	JTI        string    `json:"jti"`
	IP         string    `json:"ip"`
	Service    string    `json:"service"`
	Score      float64   `json:"score"`
	PageCount  int       `json:"page_count"`
	DurationMs int64     `json:"duration_ms"`
	Flags      []string  `json:"flags,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// SessionScoringConfig holds tunable parameters for session behavioral scoring.
// Persisted to JSON, editable via /api/sessions/config.
type SessionScoringConfig struct {
	// DenylistEnabled controls whether suspicious JTIs are written to the
	// denylist file for the plugin to read. When false, scoring still runs
	// (visible in the dashboard) but no cookies are invalidated.
	DenylistEnabled bool `json:"denylist_enabled"`

	// DenylistThreshold is the minimum session score (0-1) to include a JTI
	// in the denylist. Default 0.6.
	DenylistThreshold float64 `json:"denylist_threshold"`

	// Weights for each behavioral indicator. Each value is added to the
	// session score when the indicator triggers.
	WeightSinglePage   float64 `json:"weight_single_page"`    // default 0.4
	WeightShortSession float64 `json:"weight_short_session"`  // default 0.2
	WeightUniformDwell float64 `json:"weight_uniform_dwell"`  // default 0.3
	WeightNoScroll     float64 `json:"weight_no_scroll"`      // default 0.15
	WeightNoInteract   float64 `json:"weight_no_interaction"` // default 0.15
	WeightLowVisible   float64 `json:"weight_low_visible"`    // default 0.2

	// OrganicBonus is subtracted when organic browsing is detected (negative weight).
	OrganicBonus float64 `json:"organic_bonus"` // default -0.3

	// AlertIPThreshold triggers an alert when an IP has this many suspicious sessions.
	// 0 = alerts disabled.
	AlertIPThreshold int `json:"alert_ip_threshold"` // default 0 (disabled)

	// AutoEscalateEnabled auto-creates temporary block rules when an IP exceeds
	// the escalation threshold of suspicious sessions.
	AutoEscalateEnabled bool `json:"auto_escalate_enabled"` // default false

	// AutoEscalateThreshold is the number of suspicious sessions from one IP
	// that triggers auto-escalation.
	AutoEscalateThreshold int `json:"auto_escalate_threshold"` // default 5

	// AutoEscalateTTL is the duration of auto-created block rules (e.g., "1h", "24h").
	AutoEscalateTTL string `json:"auto_escalate_ttl"` // default "1h"
}

func defaultSessionScoringConfig() SessionScoringConfig {
	return SessionScoringConfig{
		DenylistEnabled:       false, // observe-only by default — enable after calibration
		DenylistThreshold:     0.6,
		WeightSinglePage:      0.4,
		WeightShortSession:    0.2,
		WeightUniformDwell:    0.3,
		WeightNoScroll:        0.15,
		WeightNoInteract:      0.15,
		WeightLowVisible:      0.2,
		OrganicBonus:          -0.3,
		AlertIPThreshold:      0, // disabled by default
		AutoEscalateEnabled:   false,
		AutoEscalateThreshold: 5,
		AutoEscalateTTL:       "1h",
	}
}

const (
	maxActiveSessions     = 10000
	sessionDefaultTTL     = time.Hour
	sessionSaveIntervalMs = 60000 // persist every 60s
)

// SessionStore manages in-memory session data with periodic JSON persistence.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionEntry // keyed by JTI
	filePath string
	config   SessionScoringConfig
	cfgPath  string // path to scoring config JSON
	lastSave time.Time
}

// NewSessionStore creates a session store, loading any persisted state.
func NewSessionStore(filePath, cfgPath string) *SessionStore {
	s := &SessionStore{
		sessions: make(map[string]*SessionEntry),
		filePath: filePath,
		config:   defaultSessionScoringConfig(),
		cfgPath:  cfgPath,
		lastSave: time.Now(),
	}
	s.loadConfig()
	s.load()
	return s
}

func (s *SessionStore) loadConfig() {
	if s.cfgPath == "" {
		return
	}
	data, err := os.ReadFile(s.cfgPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[session] error reading config %s: %v", s.cfgPath, err)
		}
		return
	}
	var cfg SessionScoringConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[session] error parsing config %s: %v", s.cfgPath, err)
		return
	}
	s.config = cfg
	log.Printf("[session] loaded scoring config: denylist_enabled=%v threshold=%.2f",
		cfg.DenylistEnabled, cfg.DenylistThreshold)
}

func (s *SessionStore) saveConfig() error {
	if s.cfgPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.cfgPath, data, 0644)
}

// GetConfig returns the current scoring configuration.
func (s *SessionStore) GetConfig() SessionScoringConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// UpdateConfig validates and applies a new scoring configuration.
func (s *SessionStore) UpdateConfig(cfg SessionScoringConfig) (SessionScoringConfig, error) {
	// Validate.
	if cfg.DenylistThreshold < 0 || cfg.DenylistThreshold > 1 {
		return SessionScoringConfig{}, fmt.Errorf("denylist_threshold must be 0-1")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.config
	s.config = cfg
	if err := s.saveConfig(); err != nil {
		s.config = old // rollback
		return SessionScoringConfig{}, err
	}

	// Re-score all active sessions with new weights.
	for _, entry := range s.sessions {
		entry.Score, entry.Flags = s.scoreSessionLocked(entry)
	}

	return cfg, nil
}

func (s *SessionStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Printf("[session] error reading %s: %v", s.filePath, err)
		return
	}
	var entries []SessionEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("[session] error parsing %s: %v", s.filePath, err)
		return
	}
	now := time.Now()
	loaded := 0
	for i := range entries {
		// Skip expired sessions on load.
		if now.Sub(entries[i].LastSeen) > sessionDefaultTTL {
			continue
		}
		s.sessions[entries[i].JTI] = &entries[i]
		loaded++
	}
	log.Printf("[session] loaded %d active sessions from %s", loaded, s.filePath)
}

func (s *SessionStore) saveLocked() error {
	entries := make([]SessionEntry, 0, len(s.sessions))
	for _, e := range s.sessions {
		entries = append(entries, *e)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.filePath, data, 0644)
}

// maybeSave persists to disk if enough time has elapsed. Must be called with lock held.
func (s *SessionStore) maybeSave() {
	if time.Since(s.lastSave).Milliseconds() < sessionSaveIntervalMs {
		return
	}
	if err := s.saveLocked(); err != nil {
		log.Printf("[session] save error: %v", err)
	} else {
		s.lastSave = time.Now()
	}
}

// IngestBeacon processes a session beacon from the plugin. Called from
// access log parsing when a session_beacon action is detected.
func (s *SessionStore) IngestBeacon(jti, ip, ja4, service string, beacons []SessionBeaconEntry) {
	if jti == "" || len(beacons) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.sessions[jti]
	if !exists {
		entry = &SessionEntry{
			JTI:       jti,
			IP:        ip,
			JA4:       ja4,
			Service:   service,
			FirstSeen: time.Now(),
		}
		s.sessions[jti] = entry
	}

	for _, b := range beacons {
		ts := time.UnixMilli(b.Timestamp)
		if ts.IsZero() || ts.Year() < 2020 {
			ts = time.Now()
		}
		nav := Navigation{
			Timestamp: ts,
			Path:      b.Path,
			DwellMs:   b.DwellMs,
			VisibleMs: b.VisibleMs,
			ScrollPct: b.ScrollPct,
			Clicks:    b.Clicks,
			Typed:     b.Typed == 1,
			Type:      b.Type,
		}
		entry.Navigations = append(entry.Navigations, nav)
	}
	entry.LastSeen = time.Now()

	// Re-score after ingesting new data (write lock already held).
	entry.Score, entry.Flags = s.scoreSessionLocked(entry)

	// Evict expired sessions + enforce max size.
	s.evictLocked()
	s.maybeSave()
}

// evictLocked removes expired sessions and enforces the max session count.
// Must be called with write lock held.
func (s *SessionStore) evictLocked() {
	now := time.Now()
	for jti, e := range s.sessions {
		if now.Sub(e.LastSeen) > sessionDefaultTTL {
			delete(s.sessions, jti)
		}
	}
	// If still over limit, remove oldest sessions.
	if len(s.sessions) > maxActiveSessions {
		type jtiTime struct {
			jti      string
			lastSeen time.Time
		}
		sorted := make([]jtiTime, 0, len(s.sessions))
		for jti, e := range s.sessions {
			sorted = append(sorted, jtiTime{jti, e.LastSeen})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].lastSeen.Before(sorted[j].lastSeen)
		})
		toRemove := len(s.sessions) - maxActiveSessions
		for i := 0; i < toRemove; i++ {
			delete(s.sessions, sorted[i].jti)
		}
	}
}

// GetStats returns an aggregate summary of active sessions.
func (s *SessionStore) GetStats() SessionStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := SessionStats{
		ActiveSessions: len(s.sessions),
	}

	threshold := s.config.DenylistThreshold
	suspicious := make([]SessionSummary, 0)
	for _, e := range s.sessions {
		totalNavs := len(e.Navigations)
		stats.TotalNavigations += totalNavs
		if e.Score >= threshold {
			stats.SuspiciousSessions++
		}
		// Collect top suspicious for the API response.
		if e.Score >= 0.4 {
			var durMs int64
			if len(e.Navigations) > 0 {
				durMs = e.LastSeen.Sub(e.FirstSeen).Milliseconds()
			}
			suspicious = append(suspicious, SessionSummary{
				JTI:        e.JTI,
				IP:         e.IP,
				Service:    e.Service,
				Score:      e.Score,
				PageCount:  totalNavs,
				DurationMs: durMs,
				Flags:      e.Flags,
				FirstSeen:  e.FirstSeen,
				LastSeen:   e.LastSeen,
			})
		}
	}

	// Sort by score descending, take top 50.
	sort.Slice(suspicious, func(i, j int) bool {
		return suspicious[i].Score > suspicious[j].Score
	})
	if len(suspicious) > 50 {
		suspicious = suspicious[:50]
	}
	stats.TopSuspicious = suspicious
	return stats
}

// GetSuspiciousJTIs returns JTIs of sessions scoring above the threshold.
// Used by the cookie invalidation system.
func (s *SessionStore) GetSuspiciousJTIs(threshold float64) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var jtis []string
	for jti, e := range s.sessions {
		if e.Score >= threshold {
			jtis = append(jtis, jti)
		}
	}
	return jtis
}

// ─── Session List API ───────────────────────────────────────────────

// SessionListResponse is the paginated session list returned by the API.
type SessionListResponse struct {
	Sessions []SessionDetail `json:"sessions"`
	Total    int             `json:"total"`
	Offset   int             `json:"offset"`
	Limit    int             `json:"limit"`
}

// SessionDetail is a full session view with navigation timeline.
type SessionDetail struct {
	JTI         string       `json:"jti"`
	IP          string       `json:"ip"`
	JA4         string       `json:"ja4,omitempty"`
	Service     string       `json:"service"`
	FirstSeen   time.Time    `json:"first_seen"`
	LastSeen    time.Time    `json:"last_seen"`
	Score       float64      `json:"score"`
	Flags       []string     `json:"flags,omitempty"`
	PageCount   int          `json:"page_count"`
	DurationMs  int64        `json:"duration_ms"`
	Navigations []Navigation `json:"navigations"`
}

// ListSessions returns a paginated, filterable list of sessions.
func (s *SessionStore) ListSessions(offset, limit int, filterIP, filterService string, minScore float64) SessionListResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Collect matching sessions.
	var all []SessionDetail
	for _, e := range s.sessions {
		if filterIP != "" && e.IP != filterIP {
			continue
		}
		if filterService != "" && e.Service != filterService {
			continue
		}
		if e.Score < minScore {
			continue
		}
		all = append(all, SessionDetail{
			JTI:         e.JTI,
			IP:          e.IP,
			JA4:         e.JA4,
			Service:     e.Service,
			FirstSeen:   e.FirstSeen,
			LastSeen:    e.LastSeen,
			Score:       e.Score,
			Flags:       e.Flags,
			PageCount:   len(e.Navigations),
			DurationMs:  e.LastSeen.Sub(e.FirstSeen).Milliseconds(),
			Navigations: e.Navigations,
		})
	}

	// Sort by score descending.
	sort.Slice(all, func(i, j int) bool {
		return all[i].Score > all[j].Score
	})

	total := len(all)
	if offset >= total {
		return SessionListResponse{Sessions: []SessionDetail{}, Total: total, Offset: offset, Limit: limit}
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return SessionListResponse{Sessions: all[offset:end], Total: total, Offset: offset, Limit: limit}
}

// GetSession returns a single session by JTI.
func (s *SessionStore) GetSession(jti string) *SessionDetail {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.sessions[jti]
	if !ok {
		return nil
	}
	return &SessionDetail{
		JTI:         e.JTI,
		IP:          e.IP,
		JA4:         e.JA4,
		Service:     e.Service,
		FirstSeen:   e.FirstSeen,
		LastSeen:    e.LastSeen,
		Score:       e.Score,
		Flags:       e.Flags,
		PageCount:   len(e.Navigations),
		DurationMs:  e.LastSeen.Sub(e.FirstSeen).Milliseconds(),
		Navigations: e.Navigations,
	}
}

// ─── Reputation Integration ─────────────────────────────────────────

// SuspiciousIPSummary aggregates suspicious session data per IP for
// reputation system integration.
type SuspiciousIPSummary struct {
	IP                 string   `json:"ip"`
	SuspiciousSessions int      `json:"suspicious_sessions"`
	UniqueJA4s         int      `json:"unique_ja4s"`
	UniqueServices     int      `json:"unique_services"`
	MaxScore           float64  `json:"max_score"`
	JTIs               []string `json:"jtis"`
}

// GetSuspiciousIPs returns IPs with N+ suspicious sessions for reputation flagging.
func (s *SessionStore) GetSuspiciousIPs(minSessions int) []SuspiciousIPSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	threshold := s.config.DenylistThreshold

	type ipAgg struct {
		sessions int
		ja4s     map[string]bool
		services map[string]bool
		maxScore float64
		jtis     []string
	}
	agg := make(map[string]*ipAgg)

	for _, e := range s.sessions {
		if e.Score < threshold {
			continue
		}
		a, ok := agg[e.IP]
		if !ok {
			a = &ipAgg{ja4s: make(map[string]bool), services: make(map[string]bool)}
			agg[e.IP] = a
		}
		a.sessions++
		if e.JA4 != "" {
			a.ja4s[e.JA4] = true
		}
		a.services[e.Service] = true
		if e.Score > a.maxScore {
			a.maxScore = e.Score
		}
		a.jtis = append(a.jtis, e.JTI)
	}

	var result []SuspiciousIPSummary
	for ip, a := range agg {
		if a.sessions >= minSessions {
			result = append(result, SuspiciousIPSummary{
				IP:                 ip,
				SuspiciousSessions: a.sessions,
				UniqueJA4s:         len(a.ja4s),
				UniqueServices:     len(a.services),
				MaxScore:           a.maxScore,
				JTIs:               a.jtis,
			})
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].SuspiciousSessions > result[j].SuspiciousSessions
	})
	return result
}

// ─── Alert Rules ────────────────────────────────────────────────────

// SessionAlert is generated when alert thresholds are exceeded.
type SessionAlert struct {
	Type      string    `json:"type"` // "ip_threshold", "rate_threshold"
	IP        string    `json:"ip,omitempty"`
	Service   string    `json:"service,omitempty"`
	Count     int       `json:"count"`
	Threshold int       `json:"threshold"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// CheckAlerts evaluates alert conditions against current sessions.
// Returns any triggered alerts. Called periodically by the alert goroutine.
func (s *SessionStore) CheckAlerts() []SessionAlert {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if cfg.AlertIPThreshold <= 0 {
		return nil
	}

	suspiciousIPs := s.GetSuspiciousIPs(1) // get all with at least 1 suspicious session
	var alerts []SessionAlert

	for _, ip := range suspiciousIPs {
		if ip.SuspiciousSessions >= cfg.AlertIPThreshold {
			alerts = append(alerts, SessionAlert{
				Type:      "ip_threshold",
				IP:        ip.IP,
				Count:     ip.SuspiciousSessions,
				Threshold: cfg.AlertIPThreshold,
				Message:   fmt.Sprintf("IP %s has %d suspicious sessions (threshold: %d)", ip.IP, ip.SuspiciousSessions, cfg.AlertIPThreshold),
				Timestamp: time.Now(),
			})
		}
	}

	return alerts
}

// ─── JTI Denylist Writer ─────────────────────────────────────────────

// jtiDenylistFile is the JSON structure read by the plugin.
type jtiDenylistFile struct {
	JTIs      []string `json:"jtis"`
	UpdatedAt string   `json:"updated_at"`
}

// WriteDenylist writes suspicious JTIs to the denylist file for the plugin
// to read. Only JTIs scoring at or above the threshold are included.
func (s *SessionStore) WriteDenylist(path string, threshold float64) error {
	jtis := s.GetSuspiciousJTIs(threshold)

	dl := jtiDenylistFile{
		JTIs:      jtis,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if dl.JTIs == nil {
		dl.JTIs = []string{} // ensure JSON array, not null
	}

	data, err := json.MarshalIndent(dl, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0644)
}

// ─── HTTP Handlers ──────────────────────────────────────────────────

// handleSessionStats returns aggregate session stats.
func handleSessionStats(store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, store.GetStats())
	}
}

// handleSessionList returns a paginated, filterable list of sessions.
func handleSessionList(store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		offset := 0
		limit := 50
		if v := q.Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}
		if v := q.Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}
		minScore := 0.0
		if v := q.Get("min_score"); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				minScore = f
			}
		}
		filterIP := q.Get("ip")
		filterService := q.Get("service")

		writeJSON(w, http.StatusOK, store.ListSessions(offset, limit, filterIP, filterService, minScore))
	}
}

// handleSessionDetail returns a single session by JTI.
func handleSessionDetail(store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jti := r.PathValue("jti")
		if jti == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "missing jti"})
			return
		}
		detail := store.GetSession(jti)
		if detail == nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "session not found"})
			return
		}
		writeJSON(w, http.StatusOK, detail)
	}
}

// handleSessionAlerts returns current triggered alerts.
func handleSessionAlerts(store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		alerts := store.CheckAlerts()
		if alerts == nil {
			alerts = []SessionAlert{}
		}
		writeJSON(w, http.StatusOK, alerts)
	}
}

// handleGetSessionConfig returns the current scoring configuration.
func handleGetSessionConfig(store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, store.GetConfig())
	}
}

// handleUpdateSessionConfig validates and applies a new scoring configuration.
func handleUpdateSessionConfig(store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg SessionScoringConfig
		if _, failed := decodeJSON(w, r, &cfg); failed {
			return
		}
		updated, err := store.UpdateConfig(cfg)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

// ─── Auto-Escalation ────────────────────────────────────────────────

// AutoEscalateResult records an auto-escalation action.
type AutoEscalateResult struct {
	IP      string `json:"ip"`
	RuleID  string `json:"rule_id,omitempty"`
	Message string `json:"message"`
}

// CheckAutoEscalation evaluates whether any IPs should be auto-blocked.
// Returns IPs that exceed the threshold. The caller (main.go goroutine)
// is responsible for creating the actual block rules via the ExclusionStore.
func (s *SessionStore) CheckAutoEscalation() []SuspiciousIPSummary {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if !cfg.AutoEscalateEnabled || cfg.AutoEscalateThreshold <= 0 {
		return nil
	}

	return s.GetSuspiciousIPs(cfg.AutoEscalateThreshold)
}

// ─── Session Scoring ────────────────────────────────────────────────

// scoreSession computes a suspicion score using the store's current config weights.
// Acquires read lock to access config.
func (st *SessionStore) scoreSession(s *SessionEntry) (float64, []string) {
	st.mu.RLock()
	cfg := st.config
	st.mu.RUnlock()
	return scoreSessionWithConfig(s, cfg)
}

// scoreSessionLocked computes a suspicion score. Caller must hold at least RLock.
func (st *SessionStore) scoreSessionLocked(s *SessionEntry) (float64, []string) {
	return scoreSessionWithConfig(s, st.config)
}

// scoreSessionWithConfig computes a suspicion score (0-1) from session behavioral
// features using the provided weights. Rule-based scoring — no ML dependency.
func scoreSessionWithConfig(s *SessionEntry, cfg SessionScoringConfig) (float64, []string) {
	score := 0.0
	var flags []string

	navCount := len(s.Navigations)
	if navCount == 0 {
		return 0, nil
	}

	elapsed := s.LastSeen.Sub(s.FirstSeen)

	// ── Single-page session after challenge ──────────────────────
	if navCount <= 1 && elapsed > 10*time.Second {
		score += cfg.WeightSinglePage
		flags = append(flags, "single_page")
	}

	// ── Very short session with few pages ────────────────────────
	if elapsed < 30*time.Second && navCount <= 3 && navCount > 1 {
		score += cfg.WeightShortSession
		flags = append(flags, "short_session")
	}

	// ── Uniform dwell time (CV < 0.2) ───────────────────────────
	if navCount >= 3 {
		cv := dwellCV(s)
		if cv >= 0 && cv < 0.2 {
			score += cfg.WeightUniformDwell
			flags = append(flags, "uniform_dwell")
		}
	}

	// ── No scroll engagement ────────────────────────────────────
	if navCount >= 2 && meanScrollPct(s) < 10 {
		score += cfg.WeightNoScroll
		flags = append(flags, "no_scroll")
	}

	// ── No interaction (clicks/typing) ──────────────────────────
	if navCount >= 2 && interactionRate(s) < 0.05 {
		score += cfg.WeightNoInteract
		flags = append(flags, "no_interaction")
	}

	// ── Low visible ratio ───────────────────────────────────────
	if navCount >= 2 {
		vr := meanVisibleRatio(s)
		if vr >= 0 && vr < 0.3 {
			score += cfg.WeightLowVisible
			flags = append(flags, "low_visible")
		}
	}

	// ── Positive: real browsing behavior ─────────────────────────
	if navCount >= 5 && dwellCV(s) > 0.5 && interactionRate(s) > 0.3 {
		score += cfg.OrganicBonus // negative value reduces score
		flags = append(flags, "organic_browsing")
	}

	// Clamp.
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score, flags
}

// dwellCV computes the coefficient of variation (stddev/mean) of dwell times.
// Returns -1 if insufficient data. CV < 0.2 indicates suspiciously uniform timing.
func dwellCV(s *SessionEntry) float64 {
	var dwells []float64
	for _, n := range s.Navigations {
		if n.DwellMs > 0 {
			dwells = append(dwells, float64(n.DwellMs))
		}
	}
	if len(dwells) < 2 {
		return -1
	}
	mean := 0.0
	for _, d := range dwells {
		mean += d
	}
	mean /= float64(len(dwells))
	if mean == 0 {
		return -1
	}
	variance := 0.0
	for _, d := range dwells {
		variance += (d - mean) * (d - mean)
	}
	variance /= float64(len(dwells))
	return math.Sqrt(variance) / mean
}

// meanScrollPct computes the average scroll depth across page metric navigations.
func meanScrollPct(s *SessionEntry) float64 {
	total := 0
	count := 0
	for _, n := range s.Navigations {
		if n.Type == "pm" {
			total += n.ScrollPct
			count++
		}
	}
	if count == 0 {
		return -1
	}
	return float64(total) / float64(count)
}

// interactionRate computes the fraction of pages with clicks or typing.
func interactionRate(s *SessionEntry) float64 {
	interactive := 0
	total := 0
	for _, n := range s.Navigations {
		if n.Type == "pm" {
			total++
			if n.Clicks > 0 || n.Typed {
				interactive++
			}
		}
	}
	if total == 0 {
		return -1
	}
	return float64(interactive) / float64(total)
}

// meanVisibleRatio computes visible_ms / dwell_ms across page metrics.
func meanVisibleRatio(s *SessionEntry) float64 {
	totalVis := 0
	totalDwell := 0
	for _, n := range s.Navigations {
		if n.Type == "pm" && n.VisibleMs > 0 && n.DwellMs > 0 {
			totalVis += n.VisibleMs
			totalDwell += n.DwellMs
		}
	}
	if totalDwell == 0 {
		return -1
	}
	return float64(totalVis) / float64(totalDwell)
}
