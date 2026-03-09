package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// defaultBlocklistMinScore is the minimum IPsum score to include in the blocklist.
// Score 1 = all 8 IPsum levels. False positives can be handled via Policy Engine
// allow-type exclusions (ctl:ruleEngine=Off) for specific IPs or paths.
const defaultBlocklistMinScore = 1

// BlocklistStore manages IPsum blocklist downloads and delegates blocking to
// managed lists + the policy engine. The store downloads the raw IPsum list,
// syncs per-level managed lists, and maintains an in-memory IP set for the
// Check(ip) API. The actual blocking is done by the Caddy policy engine
// plugin via exclusion rules that reference ipsum managed lists.
type BlocklistStore struct {
	mu          sync.RWMutex
	ips         map[string]struct{} // set of all blocked IPs (for Check API)
	ipCount     int
	lastUpdated string // timestamp of last successful refresh

	refreshing atomic.Bool // guard against concurrent Refresh calls

	// onRefresh is called after a successful blocklist refresh with IPs
	// grouped by their IPsum threat score (1–8). Used to sync managed lists.
	onRefresh func(ipsByScore map[int][]string)

	// onDeploy is called after managed lists are synced to regenerate
	// policy-rules.json and reload Caddy.
	onDeploy func() error
}

// NewBlocklistStore creates a store for managing IPsum blocklist downloads.
func NewBlocklistStore() *BlocklistStore {
	return &BlocklistStore{
		ips: make(map[string]struct{}),
	}
}

// loadFromLists populates the in-memory IP set from ipsum managed lists.
// Called on startup to enable Check(ip) without requiring a fresh download.
func (bs *BlocklistStore) loadFromLists(ls *ManagedListStore) {
	if ls == nil {
		return
	}
	lists := ls.List()
	ips := make(map[string]struct{})
	for _, l := range lists {
		if l.Source == "ipsum" && l.Kind == "ip" {
			for _, ip := range l.Items {
				ips[ip] = struct{}{}
			}
		}
	}
	bs.mu.Lock()
	bs.ips = ips
	bs.ipCount = len(ips)
	if bs.lastUpdated == "" && len(ips) > 0 {
		// Use the most recent UpdatedAt from ipsum lists as last updated.
		for _, l := range lists {
			if l.Source == "ipsum" && !l.UpdatedAt.IsZero() {
				ts := l.UpdatedAt.UTC().Format(time.RFC3339)
				if ts > bs.lastUpdated {
					bs.lastUpdated = ts
				}
			}
		}
	}
	bs.mu.Unlock()
	if len(ips) > 0 {
		log.Printf("[blocklist] loaded %d IPs from ipsum managed lists", len(ips))
	}
}

// Stats returns blocklist statistics.
func (bs *BlocklistStore) Stats() BlocklistStatsResponse {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return BlocklistStatsResponse{
		BlockedIPs:  bs.ipCount,
		LastUpdated: bs.lastUpdated,
		Source:      "IPsum",
		MinScore:    defaultBlocklistMinScore,
	}
}

// Check returns whether a given IP is in the blocklist.
func (bs *BlocklistStore) Check(ip string) BlocklistCheckResponse {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	_, blocked := bs.ips[ip]
	return BlocklistCheckResponse{
		IP:      ip,
		Blocked: blocked,
		Source:  "IPsum",
	}
}

// SetOnRefresh sets a callback invoked after each successful blocklist refresh
// with IPs grouped by their IPsum threat score (1–8).
func (bs *BlocklistStore) SetOnRefresh(fn func(ipsByScore map[int][]string)) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.onRefresh = fn
}

// SetOnDeploy sets a callback invoked after managed lists are synced to
// regenerate policy-rules.json and reload Caddy.
func (bs *BlocklistStore) SetOnDeploy(fn func() error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.onDeploy = fn
}

// Refresh downloads a fresh IPsum blocklist, syncs managed lists, regenerates
// policy-rules.json, and optionally reloads Caddy. Returns a response suitable
// for the API.
func (bs *BlocklistStore) Refresh() BlocklistRefreshResponse {
	// Prevent concurrent refreshes — the operation is expensive (HTTP download,
	// managed list sync, policy regeneration) and concurrent runs would race.
	if !bs.refreshing.CompareAndSwap(false, true) {
		return BlocklistRefreshResponse{
			Status:  "error",
			Message: "refresh already in progress",
		}
	}
	defer bs.refreshing.Store(false)

	const ipsumURL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

	// Always use the compiled-in default — don't inherit a stale threshold.
	minScore := defaultBlocklistMinScore

	log.Printf("[blocklist] refreshing from %s (min_score=%d)", ipsumURL, minScore)

	// Download the raw list.
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(ipsumURL)
	if err != nil {
		log.Printf("[blocklist] download failed: %v", err)
		return BlocklistRefreshResponse{
			Status:  "error",
			Message: fmt.Sprintf("download failed: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Printf("[blocklist] download returned %d: %s", resp.StatusCode, string(body))
		return BlocklistRefreshResponse{
			Status:  "error",
			Message: fmt.Sprintf("download returned HTTP %d", resp.StatusCode),
		}
	}

	// Parse the IPsum format: lines are "IP\tSCORE" with # comments.
	// Track IPs by score for per-level managed lists.
	var allIPs []string
	ipsByScore := make(map[int][]string)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		score, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		if score >= minScore {
			allIPs = append(allIPs, fields[0])
		}
		if score >= 1 && score <= 8 {
			ipsByScore[score] = append(ipsByScore[score], fields[0])
		}
	}

	if len(allIPs) < 10 {
		msg := fmt.Sprintf("too few IPs (%d), aborting to prevent empty blocklist", len(allIPs))
		log.Printf("[blocklist] %s", msg)
		return BlocklistRefreshResponse{
			Status:  "error",
			Message: msg,
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Update in-memory IP set for Check(ip) API.
	ipSet := make(map[string]struct{}, len(allIPs))
	for _, ip := range allIPs {
		ipSet[ip] = struct{}{}
	}
	bs.mu.Lock()
	bs.ips = ipSet
	bs.ipCount = len(allIPs)
	bs.lastUpdated = now
	bs.mu.Unlock()

	log.Printf("[blocklist] downloaded %d IPs from IPsum", len(allIPs))

	// Sync managed lists with the refreshed IPs (grouped by score).
	bs.mu.RLock()
	cb := bs.onRefresh
	bs.mu.RUnlock()
	if cb != nil {
		cb(ipsByScore)
	}

	// Regenerate policy-rules.json and reload Caddy so the plugin picks up
	// the updated IP lists.
	bs.mu.RLock()
	deployFn := bs.onDeploy
	bs.mu.RUnlock()
	reloaded := true
	if deployFn != nil {
		if err := deployFn(); err != nil {
			log.Printf("[blocklist] warning: deploy after refresh failed: %v", err)
			reloaded = false
		}
	}

	status := "updated"
	msg := fmt.Sprintf("Downloaded %d IPs and updated blocklist", len(allIPs))
	if !reloaded {
		status = "partial"
		msg += " (deploy failed — manual deploy may be needed)"
	}

	return BlocklistRefreshResponse{
		Status:      status,
		Message:     msg,
		BlockedIPs:  len(allIPs),
		MinScore:    minScore,
		LastUpdated: now,
		Reloaded:    reloaded,
	}
}

// --- Scheduled Refresh ---

// nextRefreshTime returns the next UTC time at the given hour (0–23).
// If that hour has already passed today, it returns tomorrow at that hour.
func nextRefreshTime(now time.Time, hour int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, time.UTC)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// StartScheduledRefresh launches a background goroutine that refreshes the
// blocklist daily at the specified UTC hour. This replaces the cron-based
// update-ipsum.sh approach, which was unreliable inside hardened containers
// (BusyBox crond silently skips crontabs with wrong file permissions).
func (bs *BlocklistStore) StartScheduledRefresh(hour int, rs *RateLimitRuleStore, ls *ManagedListStore, deployCfg DeployConfig) {
	go func() {
		for {
			now := time.Now().UTC()
			next := nextRefreshTime(now, hour)
			delay := next.Sub(now)
			log.Printf("[blocklist] next scheduled refresh at %s (in %s)", next.Format(time.RFC3339), delay.Round(time.Second))

			time.Sleep(delay)

			log.Printf("[blocklist] starting scheduled refresh")
			syncCaddyfileServices(rs, ls, deployCfg)
			result := bs.Refresh()
			log.Printf("[blocklist] scheduled refresh complete: status=%s message=%q ips=%d", result.Status, result.Message, result.BlockedIPs)
		}
	}()
}

// --- HTTP Handlers ---

func handleBlocklistStats(bs *BlocklistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, bs.Stats())
	}
}

func handleBlocklistCheck(bs *BlocklistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.PathValue("ip")
		if ip == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "IP address is required"})
			return
		}
		if net.ParseIP(ip) == nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid IP address"})
			return
		}
		writeJSON(w, http.StatusOK, bs.Check(ip))
	}
}

func handleBlocklistRefresh(bs *BlocklistStore, rs *RateLimitRuleStore, ls *ManagedListStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Ensure any new Caddyfile services have rate limit files before Caddy reloads.
		syncCaddyfileServices(rs, ls, deployCfg)

		result := bs.Refresh()
		status := http.StatusOK
		if result.Status == "error" {
			status = http.StatusInternalServerError
		}
		writeJSON(w, status, result)
	}
}
