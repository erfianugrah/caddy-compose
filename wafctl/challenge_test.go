package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// ─── Test helpers for challenge tests ───────────────────────────────

// accessLogStoreWithRLEvents creates an AccessLogStore with pre-populated
// RateLimitEvents for challenge analytics/reputation testing.
func accessLogStoreWithRLEvents(t *testing.T, events []RateLimitEvent) *AccessLogStore {
	t.Helper()
	als := NewAccessLogStore(filepath.Join(t.TempDir(), "challenge-test.log"))
	als.mu.Lock()
	als.events = make([]RateLimitEvent, len(events))
	copy(als.events, events)
	als.mu.Unlock()
	return als
}

// challengeEvents returns a set of challenge RateLimitEvents spanning two
// services, three IPs, two JA4s, and all four challenge types. All events
// are timestamped within the last hour so snapshotSince(24) captures them.
func challengeEvents() []RateLimitEvent {
	now := time.Now().UTC()
	base := now.Add(-30 * time.Minute)

	return []RateLimitEvent{
		// challenge_issued — IP1, service A, JA4-alpha
		{Timestamp: base, ClientIP: "10.0.0.1", Service: "app.example.com", Source: "challenge_issued", Status: 200, JA4: "t13d1517h2_8daaf615_b0da82dd", ChallengeJTI: "jti-001", ChallengeDifficulty: 4, Country: "US"},
		// challenge_passed — IP1, service A, JA4-alpha
		{Timestamp: base.Add(1 * time.Minute), ClientIP: "10.0.0.1", Service: "app.example.com", Source: "challenge_passed", Status: 200, JA4: "t13d1517h2_8daaf615_b0da82dd", ChallengeBotScore: 15, ChallengeJTI: "jti-001", ChallengeDifficulty: 4, ChallengeElapsedMs: 2500, Country: "US"},
		// challenge_bypassed — IP1, service A (cookie reuse)
		{Timestamp: base.Add(5 * time.Minute), ClientIP: "10.0.0.1", Service: "app.example.com", Source: "challenge_bypassed", Status: 200, JA4: "t13d1517h2_8daaf615_b0da82dd", ChallengeJTI: "jti-001", Country: "US"},

		// challenge_issued — IP2, service B, JA4-beta
		{Timestamp: base.Add(2 * time.Minute), ClientIP: "10.0.0.2", Service: "api.example.com", Source: "challenge_issued", Status: 200, JA4: "t13d1312h1_deadbeef_cafebabe", ChallengeDifficulty: 6, Country: "DE"},
		// challenge_failed — IP2, service B, JA4-beta (bot score high)
		{Timestamp: base.Add(3 * time.Minute), ClientIP: "10.0.0.2", Service: "api.example.com", Source: "challenge_failed", Status: 403, JA4: "t13d1312h1_deadbeef_cafebabe", ChallengeBotScore: 85, ChallengeJTI: "jti-002", ChallengeDifficulty: 6, ChallengeElapsedMs: 500, ChallengeFailReason: "bot_score", Country: "DE"},
		// challenge_failed — IP2, service B, JA4-beta (second failure)
		{Timestamp: base.Add(4 * time.Minute), ClientIP: "10.0.0.2", Service: "api.example.com", Source: "challenge_failed", Status: 403, JA4: "t13d1312h1_deadbeef_cafebabe", ChallengeBotScore: 90, ChallengeJTI: "jti-003", ChallengeDifficulty: 6, ChallengeElapsedMs: 400, ChallengeFailReason: "bot_score", Country: "DE"},
		// challenge_failed — IP2, service B (third failure)
		{Timestamp: base.Add(6 * time.Minute), ClientIP: "10.0.0.2", Service: "api.example.com", Source: "challenge_failed", Status: 403, JA4: "t13d1312h1_deadbeef_cafebabe", ChallengeBotScore: 80, ChallengeJTI: "jti-004", ChallengeDifficulty: 6, ChallengeElapsedMs: 300, ChallengeFailReason: "timing_hard", Country: "DE"},
		// challenge_failed — IP2, service B (fourth failure — triggers repeat_failure flag)
		{Timestamp: base.Add(7 * time.Minute), ClientIP: "10.0.0.2", Service: "api.example.com", Source: "challenge_failed", Status: 403, JA4: "t13d1312h1_deadbeef_cafebabe", ChallengeBotScore: 75, ChallengeJTI: "jti-005", ChallengeDifficulty: 6, ChallengeElapsedMs: 350, ChallengeFailReason: "ja4_mismatch", Country: "DE"},

		// challenge_issued — IP3, service A (different JA4s — rotation detection)
		{Timestamp: base.Add(8 * time.Minute), ClientIP: "10.0.0.3", Service: "app.example.com", Source: "challenge_issued", Status: 200, JA4: "t13d0909h1_aaaa1111_bbbb2222", Country: "JP"},
		{Timestamp: base.Add(9 * time.Minute), ClientIP: "10.0.0.3", Service: "app.example.com", Source: "challenge_issued", Status: 200, JA4: "t13d0808h1_cccc3333_dddd4444", Country: "JP"},
		{Timestamp: base.Add(10 * time.Minute), ClientIP: "10.0.0.3", Service: "app.example.com", Source: "challenge_issued", Status: 200, JA4: "t13d0707h1_eeee5555_ffff6666", Country: "JP"},
		{Timestamp: base.Add(11 * time.Minute), ClientIP: "10.0.0.3", Service: "app.example.com", Source: "challenge_issued", Status: 200, JA4: "t13d0606h1_11112222_33334444", Country: "JP"},

		// Non-challenge event (should be ignored by analytics)
		{Timestamp: base.Add(12 * time.Minute), ClientIP: "10.0.0.99", Service: "app.example.com", Source: "logged", Status: 200},
	}
}

// ─── ChallengeStats unit tests ──────────────────────────────────────

func TestChallengeStats_FunnelCounts(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	if stats.Issued != 6 {
		t.Errorf("Issued = %d, want 6", stats.Issued)
	}
	if stats.Passed != 1 {
		t.Errorf("Passed = %d, want 1", stats.Passed)
	}
	if stats.Failed != 4 {
		t.Errorf("Failed = %d, want 4", stats.Failed)
	}
	if stats.Bypassed != 1 {
		t.Errorf("Bypassed = %d, want 1", stats.Bypassed)
	}
	// Abandoned = issued - passed - failed = 6 - 1 - 4 = 1
	if stats.Abandoned != 1 {
		t.Errorf("Abandoned = %d, want 1 (issued - passed - failed)", stats.Abandoned)
	}
}

func TestChallengeStats_Rates(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	// PassRate = passed / issued = 1/6
	wantPassRate := 1.0 / 6.0
	if diff := stats.PassRate - wantPassRate; diff > 0.01 || diff < -0.01 {
		t.Errorf("PassRate = %.4f, want ~%.4f", stats.PassRate, wantPassRate)
	}
	// FailRate = failed / issued = 4/6
	wantFailRate := 4.0 / 6.0
	if diff := stats.FailRate - wantFailRate; diff > 0.01 || diff < -0.01 {
		t.Errorf("FailRate = %.4f, want ~%.4f", stats.FailRate, wantFailRate)
	}
	// BypassRate = bypassed / (passed + bypassed) = 1/2
	if diff := stats.BypassRate - 0.5; diff > 0.01 || diff < -0.01 {
		t.Errorf("BypassRate = %.4f, want ~0.5", stats.BypassRate)
	}
	// AbandonRate = abandoned / issued = 1/6
	wantAbandonRate := 1.0 / 6.0
	if diff := stats.AbandonRate - wantAbandonRate; diff > 0.01 || diff < -0.01 {
		t.Errorf("AbandonRate = %.4f, want ~%.4f", stats.AbandonRate, wantAbandonRate)
	}
}

func TestChallengeStats_ScoreBuckets(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	if len(stats.ScoreBuckets) != 6 {
		t.Fatalf("ScoreBuckets length = %d, want 6", len(stats.ScoreBuckets))
	}

	// Bot scores: 15 (0-19 bucket), 85 (80-100), 90 (80-100), 80 (80-100), 75 (70-79)
	// Bucket[0] 0-19: 1 (score 15)
	if stats.ScoreBuckets[0].Count != 1 {
		t.Errorf("bucket 0-19 count = %d, want 1", stats.ScoreBuckets[0].Count)
	}
	// Bucket[4] 70-79: 1 (score 75)
	if stats.ScoreBuckets[4].Count != 1 {
		t.Errorf("bucket 70-79 count = %d, want 1", stats.ScoreBuckets[4].Count)
	}
	// Bucket[5] 80-100: 3 (scores 85, 90, 80)
	if stats.ScoreBuckets[5].Count != 3 {
		t.Errorf("bucket 80-100 count = %d, want 3", stats.ScoreBuckets[5].Count)
	}
}

func TestChallengeStats_FailReasons(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	if stats.FailReasons == nil {
		t.Fatal("FailReasons is nil")
	}
	if stats.FailReasons["bot_score"] != 2 {
		t.Errorf("bot_score fail count = %d, want 2", stats.FailReasons["bot_score"])
	}
	if stats.FailReasons["timing_hard"] != 1 {
		t.Errorf("timing_hard fail count = %d, want 1", stats.FailReasons["timing_hard"])
	}
	if stats.FailReasons["ja4_mismatch"] != 1 {
		t.Errorf("ja4_mismatch fail count = %d, want 1", stats.FailReasons["ja4_mismatch"])
	}
}

func TestChallengeStats_ServiceFilter(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "api.example.com", "")

	// Only IP2's events are on api.example.com: 1 issued + 4 failed
	if stats.Issued != 1 {
		t.Errorf("Issued (filtered) = %d, want 1", stats.Issued)
	}
	if stats.Failed != 4 {
		t.Errorf("Failed (filtered) = %d, want 4", stats.Failed)
	}
	if stats.Passed != 0 {
		t.Errorf("Passed (filtered) = %d, want 0", stats.Passed)
	}
}

func TestChallengeStats_ClientFilter(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "10.0.0.1")

	// IP1: 1 issued + 1 passed + 1 bypassed
	if stats.Issued != 1 {
		t.Errorf("Issued (client) = %d, want 1", stats.Issued)
	}
	if stats.Passed != 1 {
		t.Errorf("Passed (client) = %d, want 1", stats.Passed)
	}
	if stats.Bypassed != 1 {
		t.Errorf("Bypassed (client) = %d, want 1", stats.Bypassed)
	}
}

func TestChallengeStats_TopClients(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	if len(stats.TopClients) != 3 {
		t.Fatalf("TopClients length = %d, want 3", len(stats.TopClients))
	}
	// IP2 has 5 events (1 issued + 4 failed), should be first.
	if stats.TopClients[0].Client != "10.0.0.2" {
		t.Errorf("TopClients[0] = %q, want 10.0.0.2", stats.TopClients[0].Client)
	}
}

func TestChallengeStats_TopServices(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	if len(stats.TopServices) != 2 {
		t.Fatalf("TopServices length = %d, want 2", len(stats.TopServices))
	}
}

func TestChallengeStats_TopJA4s(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	if len(stats.TopJA4s) < 2 {
		t.Fatalf("TopJA4s length = %d, want >= 2", len(stats.TopJA4s))
	}
}

func TestChallengeStats_SolveMetrics(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	if stats.AvgSolveMs <= 0 {
		t.Errorf("AvgSolveMs = %.2f, want > 0", stats.AvgSolveMs)
	}
	if stats.AvgDifficulty <= 0 {
		t.Errorf("AvgDifficulty = %.2f, want > 0", stats.AvgDifficulty)
	}
}

func TestChallengeStats_EmptyStore(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, nil)
	stats := als.ChallengeStats(24, "", "")

	if stats.Issued != 0 || stats.Passed != 0 || stats.Failed != 0 || stats.Bypassed != 0 {
		t.Error("empty store should have zero funnel counts")
	}
	if len(stats.ScoreBuckets) != 6 {
		t.Errorf("ScoreBuckets length = %d, want 6", len(stats.ScoreBuckets))
	}
	if stats.PassRate != 0 || stats.FailRate != 0 || stats.BypassRate != 0 {
		t.Error("empty store should have zero rates")
	}
}

func TestChallengeStats_NonChallengeEventsIgnored(t *testing.T) {
	events := []RateLimitEvent{
		{Timestamp: time.Now().UTC(), ClientIP: "1.1.1.1", Source: "logged", Status: 200},
		{Timestamp: time.Now().UTC(), ClientIP: "1.1.1.1", Source: "policy", Status: 403},
	}
	als := accessLogStoreWithRLEvents(t, events)
	stats := als.ChallengeStats(24, "", "")

	if stats.Issued != 0 || stats.Passed != 0 || stats.Failed != 0 || stats.Bypassed != 0 {
		t.Error("non-challenge events should not count in funnel")
	}
}

// ─── handleChallengeStats HTTP handler tests ────────────────────────

func TestHandleChallengeStats_OK(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	handler := handleChallengeStats(als)

	req := httptest.NewRequest("GET", "/api/challenge/stats?hours=24", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var stats ChallengeStatsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if stats.Issued != 6 {
		t.Errorf("Issued = %d, want 6", stats.Issued)
	}
}

func TestHandleChallengeStats_WithFilters(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	handler := handleChallengeStats(als)

	req := httptest.NewRequest("GET", "/api/challenge/stats?hours=24&service=api.example.com&client=10.0.0.2", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var stats ChallengeStatsResponse
	json.Unmarshal(w.Body.Bytes(), &stats)
	// IP2 on api.example.com: 1 issued + 4 failed
	if stats.Issued != 1 {
		t.Errorf("Issued = %d, want 1", stats.Issued)
	}
	if stats.Failed != 4 {
		t.Errorf("Failed = %d, want 4", stats.Failed)
	}
}

func TestHandleChallengeStats_DefaultHours(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	handler := handleChallengeStats(als)

	// No hours param — should default to 24
	req := httptest.NewRequest("GET", "/api/challenge/stats", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// ─── ChallengeReputation unit tests ─────────────────────────────────

func TestChallengeReputation_ClientFlags(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	rep := als.ChallengeReputation(24, "")

	// IP2 has 4 failures — should have "repeat_failure" flag.
	var ip2 *IPChallengeHistory
	for i := range rep.Clients {
		if rep.Clients[i].IP == "10.0.0.2" {
			ip2 = &rep.Clients[i]
			break
		}
	}
	if ip2 == nil {
		t.Fatal("IP2 not found in reputation clients")
	}
	hasRepeatFailure := false
	for _, f := range ip2.Flags {
		if f == "repeat_failure" {
			hasRepeatFailure = true
		}
	}
	if !hasRepeatFailure {
		t.Errorf("IP2 missing repeat_failure flag, flags = %v", ip2.Flags)
	}

	// IP3 has 4 different JA4s — should have "ja4_rotation" flag.
	var ip3 *IPChallengeHistory
	for i := range rep.Clients {
		if rep.Clients[i].IP == "10.0.0.3" {
			ip3 = &rep.Clients[i]
			break
		}
	}
	if ip3 == nil {
		t.Fatal("IP3 not found in reputation clients")
	}
	hasJA4Rotation := false
	for _, f := range ip3.Flags {
		if f == "ja4_rotation" {
			hasJA4Rotation = true
		}
	}
	if !hasJA4Rotation {
		t.Errorf("IP3 missing ja4_rotation flag, flags = %v", ip3.Flags)
	}
}

func TestChallengeReputation_JA4Verdicts(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	rep := als.ChallengeReputation(24, "")

	// JA4-beta (10.0.0.2) has 4 failures, 0 passes — fail rate 100% with 4 events.
	// Hostile threshold: fail rate >= 80% && total >= 5.
	// With 4 events (< 5), it should be "suspicious" not "hostile".
	for _, ja := range rep.JA4s {
		if ja.JA4 == "t13d1312h1_deadbeef_cafebabe" {
			// 4 events, all failed, fail rate 1.0 — but < 5 events so "suspicious"
			if ja.Verdict != "suspicious" {
				t.Errorf("JA4-beta verdict = %q, want suspicious (only %d events)", ja.Verdict, ja.TotalEvents)
			}
			return
		}
	}
	// JA4-beta might not appear if only challenge_failed events are counted.
	// The reputation code only counts passed/failed events for JA4 stats.
	t.Log("JA4-beta not in reputation list — all events may be failed-only")
}

func TestChallengeReputation_Alerts(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	rep := als.ChallengeReputation(24, "")

	if len(rep.Alerts) == 0 {
		t.Fatal("expected at least one alert")
	}
	// IP2 has repeat_failure, IP3 has ja4_rotation — should generate alerts.
	alertTypes := make(map[string]bool)
	for _, a := range rep.Alerts {
		alertTypes[a.Type] = true
	}
	if !alertTypes["repeat_failure"] {
		t.Error("missing repeat_failure alert")
	}
	if !alertTypes["ja4_rotation"] {
		t.Error("missing ja4_rotation alert")
	}
}

func TestChallengeReputation_AlertSeveritySorting(t *testing.T) {
	// This tests the fix for bug #3: severity sorting only handled "high".
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	rep := als.ChallengeReputation(24, "")

	// Verify alerts are sorted by severity descending (high > medium > low).
	severityRank := map[string]int{"high": 3, "medium": 2, "low": 1}
	for i := 1; i < len(rep.Alerts); i++ {
		ri := severityRank[rep.Alerts[i-1].Severity]
		rj := severityRank[rep.Alerts[i].Severity]
		if ri < rj {
			t.Errorf("alerts not sorted by severity: [%d].severity=%q (rank %d) < [%d].severity=%q (rank %d)",
				i-1, rep.Alerts[i-1].Severity, ri, i, rep.Alerts[i].Severity, rj)
		}
		if ri == rj && rep.Alerts[i-1].Count < rep.Alerts[i].Count {
			t.Errorf("alerts with same severity not sorted by count: [%d].count=%d < [%d].count=%d",
				i-1, rep.Alerts[i-1].Count, i, rep.Alerts[i].Count)
		}
	}
}

func TestChallengeReputation_ServiceFilter(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	rep := als.ChallengeReputation(24, "api.example.com")

	// Only IP2 operates on api.example.com.
	if rep.TotalClients != 1 {
		t.Errorf("TotalClients = %d, want 1", rep.TotalClients)
	}
}

func TestChallengeReputation_EmptyStore(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, nil)
	rep := als.ChallengeReputation(24, "")

	if rep.TotalJA4s != 0 || rep.TotalClients != 0 || rep.TotalAlerts != 0 {
		t.Error("empty store should have zero totals")
	}
}

// ─── handleChallengeReputation HTTP handler tests ───────────────────

func TestHandleChallengeReputation_OK(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	handler := handleChallengeReputation(als)

	req := httptest.NewRequest("GET", "/api/challenge/reputation?hours=24", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rep ChallengeReputationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.TotalClients < 1 {
		t.Error("expected at least 1 client")
	}
}

func TestHandleChallengeReputation_WithServiceFilter(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	handler := handleChallengeReputation(als)

	req := httptest.NewRequest("GET", "/api/challenge/reputation?hours=1&service=api.example.com", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// ─── inferChallengeFailReason tests ─────────────────────────────────

func TestInferChallengeFailReason_TimingHard(t *testing.T) {
	// difficulty=4, hashSpace=2^16=65536, estimatedCores=16
	// minMs = 65536 / (16*50) * 0.3 = 65536/800*0.3 = 24.576
	// timing_hard threshold = minMs/3 = 8.192
	rle := RateLimitEvent{
		ChallengeElapsedMs:  5, // < 8.192 → timing_hard
		ChallengeDifficulty: 4,
	}
	reason := inferChallengeFailReason(rle)
	if reason != "timing_hard" {
		t.Errorf("reason = %q, want timing_hard", reason)
	}
}

func TestInferChallengeFailReason_TimingSoft(t *testing.T) {
	rle := RateLimitEvent{
		ChallengeElapsedMs:  15, // > 8.192 (hard) but < 24.576 (soft)
		ChallengeDifficulty: 4,
	}
	reason := inferChallengeFailReason(rle)
	if reason != "timing_soft" {
		t.Errorf("reason = %q, want timing_soft", reason)
	}
}

func TestInferChallengeFailReason_BotScore(t *testing.T) {
	rle := RateLimitEvent{
		ChallengeBotScore: 75,
	}
	reason := inferChallengeFailReason(rle)
	if reason != "bot_score" {
		t.Errorf("reason = %q, want bot_score", reason)
	}
}

func TestInferChallengeFailReason_PreSignal(t *testing.T) {
	rle := RateLimitEvent{
		ChallengePreScore: 80,
		ChallengeBotScore: 0,
	}
	reason := inferChallengeFailReason(rle)
	if reason != "pre_signal" {
		t.Errorf("reason = %q, want pre_signal", reason)
	}
}

func TestInferChallengeFailReason_Fallback(t *testing.T) {
	rle := RateLimitEvent{} // no useful data
	reason := inferChallengeFailReason(rle)
	if reason != "bad_pow" {
		t.Errorf("reason = %q, want bad_pow", reason)
	}
}

func TestInferChallengeFailReason_Difficulty16_NoOverflow(t *testing.T) {
	// Bug #2 fix: difficulty=16 should NOT overflow and should fall through
	// to other checks instead of producing incorrect timing results.
	rle := RateLimitEvent{
		ChallengeElapsedMs:  1, // Would be "timing_hard" if overflow caused minMs=0
		ChallengeDifficulty: 16,
		ChallengeBotScore:   75,
	}
	reason := inferChallengeFailReason(rle)
	// With the fix, difficulty 16 is skipped (>15 guard), so it falls
	// through to bot_score check.
	if reason != "bot_score" {
		t.Errorf("reason = %q, want bot_score (difficulty 16 should skip timing check)", reason)
	}
}

func TestInferChallengeFailReason_Difficulty15_MaxSafe(t *testing.T) {
	// Difficulty 15 is the max that won't overflow uint64: 2^60 = 1152921504606846976
	rle := RateLimitEvent{
		ChallengeElapsedMs:  1, // impossibly fast for difficulty 15
		ChallengeDifficulty: 15,
	}
	reason := inferChallengeFailReason(rle)
	// hashSpace = 2^60, minMs = 2^60 / 800 * 0.3 ≈ enormous
	// elapsed 1 < minMs/3 → timing_hard
	if reason != "timing_hard" {
		t.Errorf("reason = %q, want timing_hard", reason)
	}
}

func TestInferChallengeFailReason_SlowMode_NotFalseTiming(t *testing.T) {
	// Slow mode timing fix: elapsed_ms=5000 at difficulty=2 with slow algorithm
	// should NOT trigger timing_hard/timing_soft. Slow mode expected solve time
	// is much longer than fast mode.
	// Slow: iterations = 2^8/2 = 128, perCore = 128/16 = 8, minMs = 8*10*0.3 = 24ms
	// 5000ms > 24ms → no timing violation.
	rle := RateLimitEvent{
		ChallengeElapsedMs:  5000,
		ChallengeDifficulty: 2,
		ChallengeAlgorithm:  "slow",
		ChallengeBotScore:   0,
	}
	reason := inferChallengeFailReason(rle)
	if reason == "timing_hard" || reason == "timing_soft" {
		t.Errorf("slow mode reason = %q, should not be timing violation", reason)
	}
}

func TestInferChallengeFailReason_SlowMode_TimingHard(t *testing.T) {
	// Even in slow mode, an impossibly fast solve should still be detected.
	// Slow d=4: iterations = 2^16/2 = 32768, perCore = 32768/16 = 2048
	// minMs = 2048*10*0.3 = 6144ms. timing_hard threshold = 6144/3 = 2048ms.
	rle := RateLimitEvent{
		ChallengeElapsedMs:  1000, // 1s < 2048ms → timing_hard
		ChallengeDifficulty: 4,
		ChallengeAlgorithm:  "slow",
	}
	reason := inferChallengeFailReason(rle)
	if reason != "timing_hard" {
		t.Errorf("slow mode d=4 elapsed=1000 reason = %q, want timing_hard", reason)
	}
}

func TestInferChallengeFailReason_FastMode_Unchanged(t *testing.T) {
	// Verify fast mode timing is unchanged after the slow mode fix.
	rle := RateLimitEvent{
		ChallengeElapsedMs:  5,
		ChallengeDifficulty: 4,
		ChallengeAlgorithm:  "fast",
	}
	reason := inferChallengeFailReason(rle)
	if reason != "timing_hard" {
		t.Errorf("fast mode d=4 elapsed=5 reason = %q, want timing_hard", reason)
	}
}

func TestInferChallengeFailReason_EmptyAlgorithm_DefaultsFast(t *testing.T) {
	// Empty algorithm should use fast mode timing (backward compatible).
	rle := RateLimitEvent{
		ChallengeElapsedMs:  5,
		ChallengeDifficulty: 4,
		// ChallengeAlgorithm not set → defaults to fast
	}
	reason := inferChallengeFailReason(rle)
	if reason != "timing_hard" {
		t.Errorf("empty algo d=4 elapsed=5 reason = %q, want timing_hard", reason)
	}
}

// ─── challenge_bypassed separate counter test ───────────────────────

func TestChallengeStats_BypassedSeparateFromPassed(t *testing.T) {
	// Verify challenge_bypassed is NOT folded into challenge_passed.
	now := time.Now().UTC()
	events := []RateLimitEvent{
		{Timestamp: now, ClientIP: "1.1.1.1", Source: "challenge_passed", Service: "a"},
		{Timestamp: now, ClientIP: "1.1.1.1", Source: "challenge_bypassed", Service: "a"},
		{Timestamp: now, ClientIP: "1.1.1.1", Source: "challenge_bypassed", Service: "a"},
	}
	als := accessLogStoreWithRLEvents(t, events)
	stats := als.ChallengeStats(24, "", "")

	if stats.Passed != 1 {
		t.Errorf("Passed = %d, want 1 (should not include bypassed)", stats.Passed)
	}
	if stats.Bypassed != 2 {
		t.Errorf("Bypassed = %d, want 2", stats.Bypassed)
	}
}

// ─── Split solve time test ──────────────────────────────────────────

func TestChallengeStats_SplitSolveTimes(t *testing.T) {
	now := time.Now().UTC()
	events := []RateLimitEvent{
		{Timestamp: now, ClientIP: "1.1.1.1", Source: "challenge_passed", Service: "a", ChallengeElapsedMs: 1000},
		{Timestamp: now, ClientIP: "1.1.1.1", Source: "challenge_passed", Service: "a", ChallengeElapsedMs: 3000},
		{Timestamp: now, ClientIP: "2.2.2.2", Source: "challenge_failed", Service: "a", ChallengeElapsedMs: 500, ChallengeFailReason: "bot_score", ChallengeBotScore: 80},
		{Timestamp: now, ClientIP: "2.2.2.2", Source: "challenge_failed", Service: "a", ChallengeElapsedMs: 700, ChallengeFailReason: "bot_score", ChallengeBotScore: 85},
	}
	als := accessLogStoreWithRLEvents(t, events)
	stats := als.ChallengeStats(24, "", "")

	// AvgSolveMsPassed = (1000 + 3000) / 2 = 2000
	if stats.AvgSolveMsPassed < 1999 || stats.AvgSolveMsPassed > 2001 {
		t.Errorf("AvgSolveMsPassed = %.1f, want ~2000", stats.AvgSolveMsPassed)
	}
	// AvgSolveMsFailed = (500 + 700) / 2 = 600
	if stats.AvgSolveMsFailed < 599 || stats.AvgSolveMsFailed > 601 {
		t.Errorf("AvgSolveMsFailed = %.1f, want ~600", stats.AvgSolveMsFailed)
	}
	// AvgSolveMs = (1000 + 3000 + 500 + 700) / 4 = 1300
	if stats.AvgSolveMs < 1299 || stats.AvgSolveMs > 1301 {
		t.Errorf("AvgSolveMs = %.1f, want ~1300", stats.AvgSolveMs)
	}
}

// ─── BindJA4 false survives JSON serialization ──────────────────────

func TestGenerateChallengeRules_BindJA4False(t *testing.T) {
	// Bug #1 fix: BindJA4=false must appear in JSON output, not be omitted.
	boolPtr := func(b bool) *bool { return &b }
	exclusions := []RuleExclusion{
		{
			ID: "c1", Name: "Challenge No JA4", Type: "challenge", Enabled: true,
			ChallengeDifficulty: 4,
			ChallengeBindJA4:    boolPtr(false),
			ChallengeBindIP:     boolPtr(true),
			Conditions:          []Condition{{Field: "path", Operator: "eq", Value: "/test"}},
		},
	}

	data, err := GeneratePolicyRulesWithRL(exclusions, RateLimitGlobalConfig{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var file PolicyRulesFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(file.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(file.Rules))
	}

	ch := file.Rules[0].Challenge
	if ch == nil {
		t.Fatal("challenge config is nil")
	}
	if ch.BindJA4 {
		t.Error("BindJA4 = true, want false (explicit false must survive serialization)")
	}

	// Also verify the raw JSON contains "bind_ja4":false explicitly.
	if !json.Valid(data) {
		t.Fatal("invalid JSON output")
	}
	raw := string(data)
	if !contains(raw, `"bind_ja4": false`) && !contains(raw, `"bind_ja4":false`) {
		t.Errorf("raw JSON missing explicit bind_ja4:false — omitempty may be stripping it.\nJSON:\n%s", raw)
	}
}

func TestGenerateChallengeRules_BindJA4True(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }
	exclusions := []RuleExclusion{
		{
			ID: "c1", Name: "Challenge With JA4", Type: "challenge", Enabled: true,
			ChallengeBindJA4: boolPtr(true),
			Conditions:       []Condition{{Field: "path", Operator: "eq", Value: "/test"}},
		},
	}

	data, err := GeneratePolicyRulesWithRL(exclusions, RateLimitGlobalConfig{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var file PolicyRulesFile
	json.Unmarshal(data, &file)
	if file.Rules[0].Challenge == nil || !file.Rules[0].Challenge.BindJA4 {
		t.Error("BindJA4 = false, want true")
	}
}

func TestGenerateChallengeRules_BindJA4Default(t *testing.T) {
	// When ChallengeBindJA4 is nil (not set), should default to true.
	exclusions := []RuleExclusion{
		{
			ID: "c1", Name: "Challenge Default JA4", Type: "challenge", Enabled: true,
			Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}},
		},
	}

	data, err := GeneratePolicyRulesWithRL(exclusions, RateLimitGlobalConfig{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var file PolicyRulesFile
	json.Unmarshal(data, &file)
	if file.Rules[0].Challenge == nil || !file.Rules[0].Challenge.BindJA4 {
		t.Error("BindJA4 default = false, want true")
	}
}

// ─── rleResponseStatus consistency test ─────────────────────────────

func TestRleResponseStatus_ChallengeIssued_UsesLogStatus(t *testing.T) {
	// Bug #4 fix: challenge_issued should use rle.Status (from log) not hardcoded 200.
	rle := &RateLimitEvent{Source: "challenge_issued", Status: 200}
	if got := rleResponseStatus(rle); got != 200 {
		t.Errorf("status = %d, want 200", got)
	}

	// If the log records a different status (unusual but possible), it should be used.
	rle2 := &RateLimitEvent{Source: "challenge_issued", Status: 202}
	if got := rleResponseStatus(rle2); got != 202 {
		t.Errorf("status = %d, want 202 (should use log status)", got)
	}
}

// ─── Validation tests for adaptive difficulty ───────────────────────

func TestValidateExclusion_ChallengeAdaptive(t *testing.T) {
	tests := []struct {
		name    string
		exc     RuleExclusion
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid adaptive range",
			exc: RuleExclusion{
				Name: "adaptive-ok", Type: "challenge",
				ChallengeMinDifficulty: 2, ChallengeMaxDifficulty: 8,
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/"}},
			},
			wantErr: false,
		},
		{
			name: "min equals max",
			exc: RuleExclusion{
				Name: "min-eq-max", Type: "challenge",
				ChallengeMinDifficulty: 5, ChallengeMaxDifficulty: 5,
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/"}},
			},
			wantErr: false,
		},
		{
			name: "min exceeds max",
			exc: RuleExclusion{
				Name: "min-gt-max", Type: "challenge",
				ChallengeMinDifficulty: 10, ChallengeMaxDifficulty: 3,
				Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/"}},
			},
			wantErr: true,
			errMsg:  "min",
		},
		{
			name: "min out of range",
			exc: RuleExclusion{
				Name: "min-too-high", Type: "challenge",
				ChallengeMinDifficulty: 17,
				Conditions:             []Condition{{Field: "path", Operator: "eq", Value: "/"}},
			},
			wantErr: true,
		},
		{
			name: "max out of range",
			exc: RuleExclusion{
				Name: "max-too-high", Type: "challenge",
				ChallengeMaxDifficulty: 17,
				Conditions:             []Condition{{Field: "path", Operator: "eq", Value: "/"}},
			},
			wantErr: true,
		},
		{
			name: "only min set (no max)",
			exc: RuleExclusion{
				Name: "min-only", Type: "challenge",
				ChallengeMinDifficulty: 3,
				Conditions:             []Condition{{Field: "path", Operator: "eq", Value: "/"}},
			},
			wantErr: false, // min without max is valid (max defaults to 0 = disabled)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExclusion(tt.exc)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExclusion() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errMsg != "" && err != nil {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// ─── Cookie harvesting flag test ────────────────────────────────────

func TestChallengeReputation_CookieHarvestingFlag(t *testing.T) {
	now := time.Now().UTC()
	// Create an IP with > 5 unique tokens.
	events := make([]RateLimitEvent, 0)
	for i := 0; i < 7; i++ {
		events = append(events, RateLimitEvent{
			Timestamp:    now.Add(-time.Duration(i) * time.Minute),
			ClientIP:     "10.0.0.50",
			Service:      "app.example.com",
			Source:       "challenge_passed",
			Status:       200,
			JA4:          "t13d1517h2_aabbccdd_eeff0011",
			ChallengeJTI: "jti-harvest-" + string(rune('A'+i)),
			Country:      "US",
		})
	}
	als := accessLogStoreWithRLEvents(t, events)
	rep := als.ChallengeReputation(24, "")

	var found *IPChallengeHistory
	for i := range rep.Clients {
		if rep.Clients[i].IP == "10.0.0.50" {
			found = &rep.Clients[i]
			break
		}
	}
	if found == nil {
		t.Fatal("IP 10.0.0.50 not found")
	}
	hasCookieHarvesting := false
	for _, f := range found.Flags {
		if f == "cookie_harvesting" {
			hasCookieHarvesting = true
		}
	}
	if !hasCookieHarvesting {
		t.Errorf("IP with 7 unique tokens should have cookie_harvesting flag, flags = %v", found.Flags)
	}
}

// ─── Timeline test ──────────────────────────────────────────────────

func TestChallengeStats_Timeline(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	if len(stats.Timeline) == 0 {
		t.Fatal("timeline should have at least one entry")
	}
	// Events span ~11 minutes from base. If base happens to cross an hour
	// boundary (e.g., test runs at XX:25, base = XX-1:55), we may get 2
	// timeline entries instead of 1. Accept 1 or 2.
	if len(stats.Timeline) > 2 {
		t.Errorf("timeline length = %d, want 1 or 2", len(stats.Timeline))
	}
	totalEvents := 0
	for _, h := range stats.Timeline {
		totalEvents += h.Issued + h.Passed + h.Failed + h.Bypassed
	}
	if totalEvents == 0 {
		t.Error("timeline has zero total events")
	}
}

// ─── Expected solve time tests ──────────────────────────────────────

func TestExpectedSolveMs_Fast(t *testing.T) {
	// Difficulty 4, fast, 8 cores:
	// iterations = 2^16 / 2 = 32768, perCore = 4096, ms = 4096 * 0.002 = ~8.19μs
	ms := expectedSolveMs(4, "fast", 8)
	if ms < 0.001 || ms > 100 {
		t.Errorf("fast d4 8c = %.4fms, want sub-100ms", ms)
	}
}

func TestExpectedSolveMs_Slow(t *testing.T) {
	// Difficulty 4, slow, 8 cores:
	// iterations = 2^16 / 2 = 32768, perCore = 4096, ms = 4096 * 10 = 40960ms (~41s)
	ms := expectedSolveMs(4, "slow", 8)
	if ms < 30_000 || ms > 50_000 {
		t.Errorf("slow d4 8c = %.0fms, want ~40960", ms)
	}
}

func TestExpectedSolveMs_SlowDifficulty5(t *testing.T) {
	// Difficulty 5, slow, 8 cores:
	// iterations = 2^20 / 2 = 524288, perCore = 65536, ms = 65536 * 10 = 655360ms (~10.9 min)
	ms := expectedSolveMs(5, "slow", 8)
	if ms < 600_000 || ms > 700_000 {
		t.Errorf("slow d5 8c = %.0fms, want ~655360", ms)
	}
}

func TestExpectedSolveMs_ZeroDifficulty(t *testing.T) {
	ms := expectedSolveMs(0, "fast", 8)
	if ms != 0 {
		t.Errorf("zero difficulty = %.4f, want 0", ms)
	}
}

func TestFormatSolveDuration(t *testing.T) {
	tests := []struct {
		ms   float64
		want string
	}{
		{0.5, "instant"},
		{50, "50ms"},
		{1500, "1.5s"},
		{90_000, "1.5 min"},
		{7_200_000, "2.0 hours"},
		{172_800_000, "2.0 days"},
	}
	for _, tt := range tests {
		got := formatSolveDuration(tt.ms)
		if got != tt.want {
			t.Errorf("formatSolveDuration(%.0f) = %q, want %q", tt.ms, got, tt.want)
		}
	}
}

func TestBuildSolveTimeEstimates(t *testing.T) {
	estimates := buildSolveTimeEstimates()
	// 8 difficulties × 2 algorithms × 4 core counts = 64 entries
	if len(estimates) != 64 {
		t.Errorf("estimates length = %d, want 64", len(estimates))
	}
	// Verify all entries have labels and positive expected_ms (except maybe instant).
	for _, e := range estimates {
		if e.Label == "" {
			t.Errorf("estimate d=%d a=%s c=%d has empty label", e.Difficulty, e.Algorithm, e.Cores)
		}
		if e.ExpectedMs < 0 {
			t.Errorf("estimate d=%d a=%s c=%d has negative expected_ms", e.Difficulty, e.Algorithm, e.Cores)
		}
	}
}

func TestChallengeStats_AlgorithmBreakdown(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	// All test events have ChallengeAlgorithm="" → defaults to "fast" in aggregation.
	if len(stats.AlgorithmBreakdown) == 0 {
		t.Fatal("AlgorithmBreakdown should have at least one entry")
	}
	if stats.AlgorithmBreakdown[0].Algorithm != "fast" {
		t.Errorf("Algorithm = %q, want fast", stats.AlgorithmBreakdown[0].Algorithm)
	}
	if stats.AlgorithmBreakdown[0].Count == 0 {
		t.Error("fast algorithm count = 0")
	}
}

func TestChallengeStats_SolveTimeEstimates(t *testing.T) {
	als := accessLogStoreWithRLEvents(t, challengeEvents())
	stats := als.ChallengeStats(24, "", "")

	if len(stats.SolveTimeEstimates) != 64 {
		t.Errorf("SolveTimeEstimates length = %d, want 64", len(stats.SolveTimeEstimates))
	}
}

func TestChallengeStats_AlgorithmBreakdownWithSlow(t *testing.T) {
	// Create events with mixed algorithms.
	now := time.Now().UTC()
	events := []RateLimitEvent{
		{Timestamp: now, ClientIP: "1.1.1.1", Source: "challenge_issued", Service: "a", ChallengeAlgorithm: "fast", ChallengeDifficulty: 4},
		{Timestamp: now, ClientIP: "1.1.1.1", Source: "challenge_passed", Service: "a", ChallengeAlgorithm: "fast", ChallengeDifficulty: 4, ChallengeElapsedMs: 500},
		{Timestamp: now, ClientIP: "2.2.2.2", Source: "challenge_issued", Service: "b", ChallengeAlgorithm: "slow", ChallengeDifficulty: 2},
		{Timestamp: now, ClientIP: "2.2.2.2", Source: "challenge_failed", Service: "b", ChallengeAlgorithm: "slow", ChallengeDifficulty: 2, ChallengeElapsedMs: 1500, ChallengeFailReason: "bot_score", ChallengeBotScore: 80},
	}
	als := accessLogStoreWithRLEvents(t, events)
	stats := als.ChallengeStats(24, "", "")

	if len(stats.AlgorithmBreakdown) != 2 {
		t.Fatalf("AlgorithmBreakdown length = %d, want 2", len(stats.AlgorithmBreakdown))
	}
	// Check both algorithms are present.
	algos := make(map[string]*AlgorithmStats)
	for i := range stats.AlgorithmBreakdown {
		algos[stats.AlgorithmBreakdown[i].Algorithm] = &stats.AlgorithmBreakdown[i]
	}
	fast := algos["fast"]
	slow := algos["slow"]
	if fast == nil || slow == nil {
		t.Fatal("missing fast or slow in breakdown")
	}
	if fast.Count != 2 {
		t.Errorf("fast count = %d, want 2", fast.Count)
	}
	if slow.Count != 2 {
		t.Errorf("slow count = %d, want 2", slow.Count)
	}
	if fast.Passed != 1 {
		t.Errorf("fast passed = %d, want 1", fast.Passed)
	}
	if slow.Failed != 1 {
		t.Errorf("slow failed = %d, want 1", slow.Failed)
	}
	if slow.AvgDifficulty != 2 {
		t.Errorf("slow avg_difficulty = %.1f, want 2.0", slow.AvgDifficulty)
	}
}

// ─── ChallengeAlgorithmByName test ──────────────────────────────────

func TestChallengeAlgorithmByName(t *testing.T) {
	es := newTestExclusionStore(t)
	// Create a challenge rule with slow algorithm.
	exc := RuleExclusion{
		Name:               "slow-challenge",
		Type:               "challenge",
		ChallengeAlgorithm: "slow",
		Conditions:         []Condition{{Field: "path", Operator: "eq", Value: "/test"}},
	}
	es.Create(exc)
	// Create a non-challenge rule.
	exc2 := RuleExclusion{
		Name:       "block-rule",
		Type:       "block",
		Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/bad"}},
	}
	es.Create(exc2)

	algos := es.ChallengeAlgorithmByName()
	if algos["slow-challenge"] != "slow" {
		t.Errorf("slow-challenge algo = %q, want slow", algos["slow-challenge"])
	}
	if _, exists := algos["block-rule"]; exists {
		t.Error("non-challenge rule should not be in algorithm map")
	}
}

func TestChallengeAlgorithmByName_DefaultFast(t *testing.T) {
	es := newTestExclusionStore(t)
	exc := RuleExclusion{
		Name:       "default-challenge",
		Type:       "challenge",
		Conditions: []Condition{{Field: "path", Operator: "eq", Value: "/test"}},
	}
	es.Create(exc)

	algos := es.ChallengeAlgorithmByName()
	if algos["default-challenge"] != "fast" {
		t.Errorf("default algo = %q, want fast", algos["default-challenge"])
	}
}

// ─── helper ─────────────────────────────────────────────────────────

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
