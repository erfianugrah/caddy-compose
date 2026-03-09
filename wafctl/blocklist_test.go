package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestBlocklistStore creates a BlocklistStore pre-populated from a managed list store.
func newTestBlocklistStore(t *testing.T, ips ...string) *BlocklistStore {
	t.Helper()
	bs := NewBlocklistStore()
	if len(ips) > 0 {
		// Build a managed list store with a single ipsum list.
		ls := NewManagedListStore(filepath.Join(t.TempDir(), "lists.json"), t.TempDir())
		ipsByScore := map[int][]string{1: ips}
		ls.SyncIPsum(ipsByScore)
		bs.loadFromLists(ls)
	}
	return bs
}

func TestBlocklistStatsFromManagedLists(t *testing.T) {
	bs := newTestBlocklistStore(t, "1.2.3.4", "5.6.7.8", "9.10.11.12")

	stats := bs.Stats()
	if stats.BlockedIPs != 3 {
		t.Errorf("BlockedIPs: want 3, got %d", stats.BlockedIPs)
	}
	if stats.Source != "IPsum" {
		t.Errorf("Source: want IPsum, got %q", stats.Source)
	}
	if stats.MinScore != defaultBlocklistMinScore {
		t.Errorf("MinScore: want %d, got %d", defaultBlocklistMinScore, stats.MinScore)
	}
	// LastUpdated should be populated from list UpdatedAt.
	if stats.LastUpdated == "" {
		t.Error("LastUpdated should not be empty")
	}
}

func TestBlocklistCheckIP(t *testing.T) {
	bs := newTestBlocklistStore(t, "1.2.3.4", "5.6.7.8")

	// Blocked IP
	result := bs.Check("1.2.3.4")
	if !result.Blocked {
		t.Error("1.2.3.4 should be blocked")
	}
	if result.Source != "IPsum" {
		t.Errorf("Source: want IPsum, got %q", result.Source)
	}

	// Clean IP
	result = bs.Check("10.0.0.1")
	if result.Blocked {
		t.Error("10.0.0.1 should not be blocked")
	}
}

func TestBlocklistEmpty(t *testing.T) {
	bs := NewBlocklistStore()

	stats := bs.Stats()
	if stats.BlockedIPs != 0 {
		t.Errorf("BlockedIPs: want 0, got %d", stats.BlockedIPs)
	}
	if stats.LastUpdated != "" {
		t.Errorf("LastUpdated: want empty, got %q", stats.LastUpdated)
	}
}

func TestBlocklistStatsEndpoint(t *testing.T) {
	bs := newTestBlocklistStore(t, "1.2.3.4", "5.6.7.8")

	req := httptest.NewRequest("GET", "/api/blocklist/stats", nil)
	w := httptest.NewRecorder()
	handleBlocklistStats(bs)(w, req)

	if w.Code != 200 {
		t.Fatalf("status: want 200, got %d", w.Code)
	}
	var resp BlocklistStatsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.BlockedIPs != 2 {
		t.Errorf("BlockedIPs: want 2, got %d", resp.BlockedIPs)
	}
}

func TestBlocklistCheckEndpoint(t *testing.T) {
	bs := newTestBlocklistStore(t, "1.2.3.4")

	// Check blocked IP
	req := httptest.NewRequest("GET", "/api/blocklist/check/1.2.3.4", nil)
	req.SetPathValue("ip", "1.2.3.4")
	w := httptest.NewRecorder()
	handleBlocklistCheck(bs)(w, req)

	if w.Code != 200 {
		t.Fatalf("status: want 200, got %d", w.Code)
	}
	var resp BlocklistCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Blocked {
		t.Error("1.2.3.4 should be blocked")
	}

	// Check clean IP
	req = httptest.NewRequest("GET", "/api/blocklist/check/10.0.0.1", nil)
	req.SetPathValue("ip", "10.0.0.1")
	w = httptest.NewRecorder()
	handleBlocklistCheck(bs)(w, req)

	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Blocked {
		t.Error("10.0.0.1 should not be blocked")
	}
}

func TestBlocklistCheckInvalidIP(t *testing.T) {
	bs := NewBlocklistStore()

	req := httptest.NewRequest("GET", "/api/blocklist/check/notanip", nil)
	req.SetPathValue("ip", "notanip")
	w := httptest.NewRecorder()
	handleBlocklistCheck(bs)(w, req)

	if w.Code != 400 {
		t.Fatalf("status: want 400, got %d", w.Code)
	}
}

func TestBlocklistLoadFromMultipleLevels(t *testing.T) {
	// Verify loadFromLists aggregates IPs across all ipsum level lists.
	ls := NewManagedListStore(filepath.Join(t.TempDir(), "lists.json"), t.TempDir())
	ipsByScore := map[int][]string{
		1: {"1.1.1.1", "2.2.2.2"},
		3: {"3.3.3.3"},
		8: {"8.8.8.8"},
	}
	ls.SyncIPsum(ipsByScore)

	bs := NewBlocklistStore()
	bs.loadFromLists(ls)

	stats := bs.Stats()
	if stats.BlockedIPs != 4 {
		t.Errorf("BlockedIPs: want 4, got %d", stats.BlockedIPs)
	}

	// All IPs should be checkable.
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "8.8.8.8"} {
		if !bs.Check(ip).Blocked {
			t.Errorf("%s should be blocked", ip)
		}
	}
	if bs.Check("4.4.4.4").Blocked {
		t.Error("4.4.4.4 should not be blocked")
	}
}

func TestBlocklistRefreshRaceGuard(t *testing.T) {
	bs := NewBlocklistStore()
	// Manually set refreshing to simulate an in-progress refresh.
	bs.refreshing.Store(true)

	resp := bs.Refresh()
	if resp.Status != "error" {
		t.Errorf("expected error status for concurrent refresh, got %q", resp.Status)
	}
	if !strings.Contains(resp.Message, "already in progress") {
		t.Errorf("expected 'already in progress' message, got %q", resp.Message)
	}

	// Clear the flag and verify Refresh can proceed (it will fail on HTTP but that's ok).
	bs.refreshing.Store(false)
	resp2 := bs.Refresh()
	// Should not get "already in progress" error — it should attempt the download.
	if strings.Contains(resp2.Message, "already in progress") {
		t.Error("refresh should have proceeded after clearing the flag")
	}
}

func TestBlocklistOnRefreshCallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	bs := NewBlocklistStore()
	var callbackIPs map[int][]string
	bs.SetOnRefresh(func(ipsByScore map[int][]string) {
		callbackIPs = ipsByScore
	})

	// Refresh downloads from the real IPsum server.
	// Verify the onRefresh callback is invoked with parsed IPs.
	resp := bs.Refresh()
	if resp.Status == "error" {
		t.Skipf("IPsum download failed (network unavailable): %s", resp.Message)
	}
	if callbackIPs == nil {
		t.Error("onRefresh callback should be called on successful refresh")
	}
	if len(callbackIPs) == 0 {
		t.Error("onRefresh callback should receive non-empty ipsByScore map")
	}
}

func TestBlocklistOnDeployCallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	bs := NewBlocklistStore()
	deployCalled := false
	bs.SetOnDeploy(func() error {
		deployCalled = true
		return nil
	})

	// Refresh downloads from the real IPsum server.
	// Verify the onDeploy callback is invoked after successful refresh.
	resp := bs.Refresh()
	if resp.Status == "error" {
		t.Skipf("IPsum download failed (network unavailable): %s", resp.Message)
	}
	if !deployCalled {
		t.Error("onDeploy callback should be called on successful refresh")
	}
}

// ─── Scheduled Refresh Tests ────────────────────────────────────────

func TestNextRefreshTime(t *testing.T) {
	tests := []struct {
		name string
		now  time.Time
		hour int
		want time.Time
	}{
		{
			name: "before target hour",
			now:  time.Date(2026, 2, 27, 3, 0, 0, 0, time.UTC),
			hour: 6,
			want: time.Date(2026, 2, 27, 6, 0, 0, 0, time.UTC),
		},
		{
			name: "after target hour",
			now:  time.Date(2026, 2, 27, 10, 0, 0, 0, time.UTC),
			hour: 6,
			want: time.Date(2026, 2, 28, 6, 0, 0, 0, time.UTC),
		},
		{
			name: "exactly at target hour",
			now:  time.Date(2026, 2, 27, 6, 0, 0, 0, time.UTC),
			hour: 6,
			want: time.Date(2026, 2, 28, 6, 0, 0, 0, time.UTC),
		},
		{
			name: "one second before target",
			now:  time.Date(2026, 2, 27, 5, 59, 59, 0, time.UTC),
			hour: 6,
			want: time.Date(2026, 2, 27, 6, 0, 0, 0, time.UTC),
		},
		{
			name: "midnight target",
			now:  time.Date(2026, 2, 27, 23, 30, 0, 0, time.UTC),
			hour: 0,
			want: time.Date(2026, 2, 28, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "end of month rollover",
			now:  time.Date(2026, 2, 28, 10, 0, 0, 0, time.UTC),
			hour: 6,
			want: time.Date(2026, 3, 1, 6, 0, 0, 0, time.UTC),
		},
		{
			name: "end of year rollover",
			now:  time.Date(2026, 12, 31, 10, 0, 0, 0, time.UTC),
			hour: 6,
			want: time.Date(2027, 1, 1, 6, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nextRefreshTime(tt.now, tt.hour)
			if !got.Equal(tt.want) {
				t.Errorf("nextRefreshTime(%v, %d) = %v, want %v", tt.now, tt.hour, got, tt.want)
			}
		})
	}
}
