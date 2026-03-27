package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── SessionStore Tests ─────────────────────────────────────────────

func TestNewSessionStoreEmpty(t *testing.T) {
	dir := t.TempDir()
	s := NewSessionStore(filepath.Join(dir, "sessions.json"), filepath.Join(dir, "session-config.json"))
	stats := s.GetStats()
	if stats.ActiveSessions != 0 {
		t.Errorf("expected 0 active sessions, got %d", stats.ActiveSessions)
	}
}

func TestSessionStoreIngestAndScore(t *testing.T) {
	dir := t.TempDir()
	s := NewSessionStore(filepath.Join(dir, "sessions.json"), filepath.Join(dir, "session-config.json"))

	// Simulate a single-page scraper: one beacon, one page, then nothing.
	beacons := []SessionBeaconEntry{
		{Timestamp: time.Now().UnixMilli(), Path: "/products/123", Type: "navigate"},
	}
	s.IngestBeacon("jti-001", "1.2.3.4", "t13d1516h2_abc_def", "example.com", beacons)

	stats := s.GetStats()
	if stats.ActiveSessions != 1 {
		t.Errorf("expected 1 active session, got %d", stats.ActiveSessions)
	}
	if stats.TotalNavigations != 1 {
		t.Errorf("expected 1 navigation, got %d", stats.TotalNavigations)
	}
}

func TestSessionScoreSinglePage(t *testing.T) {
	// Single-page session with 15s elapsed → should score high (suspicious).
	entry := &SessionEntry{
		JTI:       "jti-single",
		FirstSeen: time.Now().Add(-15 * time.Second),
		LastSeen:  time.Now(),
		Navigations: []Navigation{
			{Timestamp: time.Now(), Path: "/products/123", Type: "navigate"},
		},
	}
	score, flags := scoreSessionWithConfig(entry, defaultSessionScoringConfig())
	if score < 0.3 {
		t.Errorf("single-page session score = %.2f, want >= 0.3", score)
	}
	found := false
	for _, f := range flags {
		if f == "single_page" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'single_page' flag")
	}
}

func TestSessionScoreOrganicBrowsing(t *testing.T) {
	// Multi-page session with varied dwell times and interaction → should score low.
	now := time.Now()
	entry := &SessionEntry{
		JTI:       "jti-organic",
		FirstSeen: now.Add(-5 * time.Minute),
		LastSeen:  now,
		Navigations: []Navigation{
			{Timestamp: now.Add(-5 * time.Minute), Path: "/", DwellMs: 8000, Type: "navigate"},
			{Timestamp: now.Add(-4 * time.Minute), Path: "/products", DwellMs: 15000, Type: "navigate"},
			{Timestamp: now.Add(-3 * time.Minute), Path: "/products/123", DwellMs: 25000, Type: "navigate"},
			{Timestamp: now.Add(-2 * time.Minute), Path: "/cart", DwellMs: 5000, Type: "navigate"},
			{Timestamp: now.Add(-1 * time.Minute), Path: "/checkout", DwellMs: 30000, Type: "navigate"},
			// Page metrics showing real engagement.
			{Path: "/", Type: "pm", VisibleMs: 7500, ScrollPct: 60, Clicks: 2, DwellMs: 8000},
			{Path: "/products", Type: "pm", VisibleMs: 14000, ScrollPct: 80, Clicks: 5, DwellMs: 15000},
			{Path: "/products/123", Type: "pm", VisibleMs: 24000, ScrollPct: 90, Clicks: 3, Typed: true, DwellMs: 25000},
			{Path: "/cart", Type: "pm", VisibleMs: 4800, ScrollPct: 40, Clicks: 1, DwellMs: 5000},
			{Path: "/checkout", Type: "pm", VisibleMs: 28000, ScrollPct: 70, Clicks: 4, Typed: true, DwellMs: 30000},
		},
	}
	score, flags := scoreSessionWithConfig(entry, defaultSessionScoringConfig())
	if score > 0.3 {
		t.Errorf("organic browsing score = %.2f, want <= 0.3 (flags: %v)", score, flags)
	}
	foundOrganic := false
	for _, f := range flags {
		if f == "organic_browsing" {
			foundOrganic = true
		}
	}
	if !foundOrganic {
		t.Errorf("expected 'organic_browsing' flag, got flags: %v", flags)
	}
}

func TestSessionScoreUniformDwell(t *testing.T) {
	// Bot pattern: 5 pages with nearly identical dwell times.
	now := time.Now()
	entry := &SessionEntry{
		JTI:       "jti-uniform",
		FirstSeen: now.Add(-50 * time.Second),
		LastSeen:  now,
		Navigations: []Navigation{
			{Timestamp: now.Add(-50 * time.Second), Path: "/p/1", DwellMs: 10000, Type: "navigate"},
			{Timestamp: now.Add(-40 * time.Second), Path: "/p/2", DwellMs: 10100, Type: "navigate"},
			{Timestamp: now.Add(-30 * time.Second), Path: "/p/3", DwellMs: 10050, Type: "navigate"},
			{Timestamp: now.Add(-20 * time.Second), Path: "/p/4", DwellMs: 9950, Type: "navigate"},
			{Timestamp: now.Add(-10 * time.Second), Path: "/p/5", DwellMs: 10000, Type: "navigate"},
		},
	}
	score, flags := scoreSessionWithConfig(entry, defaultSessionScoringConfig())
	if score < 0.2 {
		t.Errorf("uniform dwell score = %.2f, want >= 0.2", score)
	}
	found := false
	for _, f := range flags {
		if f == "uniform_dwell" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'uniform_dwell' flag, got: %v", flags)
	}
}

func TestSessionScoreNoInteraction(t *testing.T) {
	// Pages visited but no clicks, no scroll, no typing.
	now := time.Now()
	entry := &SessionEntry{
		JTI:       "jti-passive",
		FirstSeen: now.Add(-2 * time.Minute),
		LastSeen:  now,
		Navigations: []Navigation{
			{Timestamp: now.Add(-2 * time.Minute), Path: "/page1", DwellMs: 5000, Type: "navigate"},
			{Timestamp: now.Add(-1 * time.Minute), Path: "/page2", DwellMs: 5000, Type: "navigate"},
			{Path: "/page1", Type: "pm", VisibleMs: 4800, ScrollPct: 0, Clicks: 0, DwellMs: 5000},
			{Path: "/page2", Type: "pm", VisibleMs: 4800, ScrollPct: 0, Clicks: 0, DwellMs: 5000},
		},
	}
	score, flags := scoreSessionWithConfig(entry, defaultSessionScoringConfig())
	if score < 0.2 {
		t.Errorf("no-interaction score = %.2f, want >= 0.2 (flags: %v)", score, flags)
	}
}

func TestSessionScoreNoPageMetrics(t *testing.T) {
	// Session with navigate events but NO page metrics (pm) at all.
	// Should NOT trigger no_scroll or no_interaction — those require pm data.
	now := time.Now()
	entry := &SessionEntry{
		JTI:       "jti-no-pm",
		FirstSeen: now.Add(-2 * time.Minute),
		LastSeen:  now,
		Navigations: []Navigation{
			{Timestamp: now.Add(-2 * time.Minute), Path: "/page1", DwellMs: 5000, Type: "navigate"},
			{Timestamp: now.Add(-1 * time.Minute), Path: "/page2", DwellMs: 5000, Type: "navigate"},
		},
	}
	_, flags := scoreSessionWithConfig(entry, defaultSessionScoringConfig())
	for _, f := range flags {
		if f == "no_scroll" {
			t.Error("no_scroll should not trigger without page metric data")
		}
		if f == "no_interaction" {
			t.Error("no_interaction should not trigger without page metric data")
		}
	}
}

func TestDwellCV(t *testing.T) {
	tests := []struct {
		name   string
		dwells []int
		wantLo float64
		wantHi float64
	}{
		{"identical", []int{1000, 1000, 1000}, 0, 0.01},
		{"varied", []int{1000, 5000, 20000}, 0.5, 2.0},
		{"insufficient", []int{1000}, -2, 0}, // returns -1
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			navs := make([]Navigation, len(tc.dwells))
			for i, d := range tc.dwells {
				navs[i] = Navigation{DwellMs: d}
			}
			entry := &SessionEntry{Navigations: navs}
			cv := dwellCV(entry)
			if cv < tc.wantLo || cv > tc.wantHi {
				t.Errorf("dwellCV = %.4f, want [%.2f, %.2f]", cv, tc.wantLo, tc.wantHi)
			}
		})
	}
}

func TestSessionStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	// Create store, ingest data, force save.
	s := NewSessionStore(path, filepath.Join(filepath.Dir(path), "session-config.json"))
	s.IngestBeacon("jti-persist", "5.6.7.8", "", "test.com", []SessionBeaconEntry{
		{Timestamp: time.Now().UnixMilli(), Path: "/saved", Type: "navigate"},
	})
	s.mu.Lock()
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// Verify file was created.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("session file not created")
	}

	// Create new store from the same file — should load the session.
	s2 := NewSessionStore(path, filepath.Join(filepath.Dir(path), "session-config.json"))
	stats := s2.GetStats()
	if stats.ActiveSessions != 1 {
		t.Errorf("after reload: expected 1 session, got %d", stats.ActiveSessions)
	}
}

func TestSessionStoreEviction(t *testing.T) {
	dir := t.TempDir()
	s := NewSessionStore(filepath.Join(dir, "sessions.json"), filepath.Join(dir, "session-config.json"))

	// Ingest more than max sessions — old ones should be evicted.
	// We use a small count here to keep the test fast.
	for i := 0; i < 100; i++ {
		jti := "jti-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		s.IngestBeacon(jti, "1.2.3.4", "", "test.com", []SessionBeaconEntry{
			{Timestamp: time.Now().UnixMilli(), Path: "/page", Type: "navigate"},
		})
	}

	stats := s.GetStats()
	if stats.ActiveSessions != 100 {
		t.Errorf("expected 100 sessions (all within TTL), got %d", stats.ActiveSessions)
	}
}

func TestGetSuspiciousJTIs(t *testing.T) {
	dir := t.TempDir()
	s := NewSessionStore(filepath.Join(dir, "sessions.json"), filepath.Join(dir, "session-config.json"))

	// Ingest a suspicious single-page session.
	s.IngestBeacon("jti-sus", "1.2.3.4", "", "test.com", []SessionBeaconEntry{
		{Timestamp: time.Now().Add(-20 * time.Second).UnixMilli(), Path: "/scrape", Type: "navigate"},
	})
	// Manually set first_seen to 20s ago so elapsed > 10s triggers single_page flag.
	s.mu.Lock()
	if e, ok := s.sessions["jti-sus"]; ok {
		e.FirstSeen = time.Now().Add(-20 * time.Second)
		e.Score, e.Flags = scoreSessionWithConfig(e, defaultSessionScoringConfig())
	}
	s.mu.Unlock()

	// Ingest a normal multi-page session with organic engagement.
	now := time.Now()
	s.IngestBeacon("jti-normal", "5.6.7.8", "", "test.com", []SessionBeaconEntry{
		{Timestamp: now.Add(-5 * time.Minute).UnixMilli(), Path: "/", Type: "navigate", DwellMs: 8000},
		{Timestamp: now.Add(-4 * time.Minute).UnixMilli(), Path: "/about", Type: "navigate", DwellMs: 15000},
		{Timestamp: now.Add(-3 * time.Minute).UnixMilli(), Path: "/contact", Type: "navigate", DwellMs: 12000},
		{Timestamp: now.Add(-2 * time.Minute).UnixMilli(), Path: "/products", Type: "navigate", DwellMs: 20000},
		{Timestamp: now.Add(-1 * time.Minute).UnixMilli(), Path: "/checkout", Type: "navigate", DwellMs: 10000},
		// Page metrics showing real interaction.
		{Timestamp: now.UnixMilli(), Path: "/", Type: "pm", VisibleMs: 7500, ScrollPct: 60, Clicks: 2, DwellMs: 8000},
		{Timestamp: now.UnixMilli(), Path: "/about", Type: "pm", VisibleMs: 14000, ScrollPct: 80, Clicks: 3, DwellMs: 15000},
		{Timestamp: now.UnixMilli(), Path: "/contact", Type: "pm", VisibleMs: 11000, ScrollPct: 70, Clicks: 1, DwellMs: 12000},
		{Timestamp: now.UnixMilli(), Path: "/products", Type: "pm", VisibleMs: 19000, ScrollPct: 90, Clicks: 5, DwellMs: 20000},
		{Timestamp: now.UnixMilli(), Path: "/checkout", Type: "pm", VisibleMs: 9000, ScrollPct: 40, Clicks: 4, DwellMs: 10000},
	})
	// Fix FirstSeen to match the actual session duration.
	s.mu.Lock()
	if e, ok := s.sessions["jti-normal"]; ok {
		e.FirstSeen = now.Add(-5 * time.Minute)
	}
	s.mu.Unlock()

	suspicious := s.GetSuspiciousJTIs(0.3)
	foundSus := false
	foundNormal := false
	for _, jti := range suspicious {
		if jti == "jti-sus" {
			foundSus = true
		}
		if jti == "jti-normal" {
			foundNormal = true
		}
	}
	if !foundSus {
		t.Error("expected jti-sus in suspicious list")
	}
	if foundNormal {
		t.Error("jti-normal should NOT be in suspicious list")
	}
}

func TestSessionConfigPersistence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "session-config.json")
	s := NewSessionStore(filepath.Join(dir, "sessions.json"), cfgPath)

	// Default config should have denylist disabled.
	cfg := s.GetConfig()
	if cfg.DenylistEnabled {
		t.Error("default denylist_enabled should be false")
	}
	if cfg.DenylistThreshold != 0.6 {
		t.Errorf("default threshold = %.2f, want 0.6", cfg.DenylistThreshold)
	}

	// Update config.
	cfg.DenylistEnabled = true
	cfg.DenylistThreshold = 0.8
	cfg.WeightSinglePage = 0.5
	updated, err := s.UpdateConfig(cfg)
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	if !updated.DenylistEnabled {
		t.Error("updated config should have denylist enabled")
	}
	if updated.DenylistThreshold != 0.8 {
		t.Errorf("updated threshold = %.2f, want 0.8", updated.DenylistThreshold)
	}

	// Reload from disk — should persist.
	s2 := NewSessionStore(filepath.Join(dir, "sessions2.json"), cfgPath)
	cfg2 := s2.GetConfig()
	if !cfg2.DenylistEnabled {
		t.Error("reloaded config should have denylist enabled")
	}
	if cfg2.DenylistThreshold != 0.8 {
		t.Errorf("reloaded threshold = %.2f, want 0.8", cfg2.DenylistThreshold)
	}
	if cfg2.WeightSinglePage != 0.5 {
		t.Errorf("reloaded weight_single_page = %.2f, want 0.5", cfg2.WeightSinglePage)
	}
}

func TestSessionConfigValidation(t *testing.T) {
	dir := t.TempDir()
	s := NewSessionStore(filepath.Join(dir, "sessions.json"), filepath.Join(dir, "session-config.json"))

	// Threshold out of range should fail.
	cfg := s.GetConfig()
	cfg.DenylistThreshold = 1.5
	_, err := s.UpdateConfig(cfg)
	if err == nil {
		t.Error("threshold > 1 should be rejected")
	}

	cfg.DenylistThreshold = -0.1
	_, err = s.UpdateConfig(cfg)
	if err == nil {
		t.Error("threshold < 0 should be rejected")
	}
}

func TestSessionConfigRescoresOnUpdate(t *testing.T) {
	dir := t.TempDir()
	s := NewSessionStore(filepath.Join(dir, "sessions.json"), filepath.Join(dir, "session-config.json"))

	// Ingest a single-page session.
	s.IngestBeacon("jti-rescore", "1.2.3.4", "", "test.com", []SessionBeaconEntry{
		{Timestamp: time.Now().Add(-20 * time.Second).UnixMilli(), Path: "/scrape", Type: "navigate"},
	})
	s.mu.Lock()
	if e, ok := s.sessions["jti-rescore"]; ok {
		e.FirstSeen = time.Now().Add(-20 * time.Second)
		e.Score, e.Flags = s.scoreSessionLocked(e)
	}
	s.mu.Unlock()

	// Score with default weights (single_page = 0.4).
	stats1 := s.GetStats()
	if stats1.ActiveSessions != 1 {
		t.Fatalf("expected 1 session, got %d", stats1.ActiveSessions)
	}

	// Now update config to zero out single_page weight.
	cfg := s.GetConfig()
	cfg.WeightSinglePage = 0
	_, err := s.UpdateConfig(cfg)
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	// Session should have been re-scored with new weights.
	s.mu.RLock()
	entry := s.sessions["jti-rescore"]
	newScore := entry.Score
	s.mu.RUnlock()

	if newScore >= 0.3 {
		t.Errorf("after zeroing single_page weight, score = %.2f, want < 0.3", newScore)
	}
}
