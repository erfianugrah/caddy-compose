package main

import (
	"net"
	"net/http"
	"strconv"
	"time"
)

// ─── GET /api/dos/status ────────────────────────────────────────────

func handleDosStatus(jailStore *JailStore, dosConfig *DosConfigStore, spike *SpikeDetector, als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := dosConfig.Get()
		spikeStatus := spike.Status()

		// Compute EPS and DDoS event count from the access log store's
		// actual event timestamps — not the volatile sliding window.
		// This gives meaningful values when the dashboard polls every 30s.
		ddosEvents := 0
		var recentEPS float64
		now := time.Now()
		cutoff60s := now.Add(-60 * time.Second)
		cutoff5m := now.Add(-5 * time.Minute)
		recentCount := 0
		var epsHistory []float64

		rateJails := 0
		behavJails := 0

		if als.mu.TryRLock() {
			// Count DDoS events and compute recent EPS from all events
			for i := len(als.events) - 1; i >= 0; i-- {
				e := &als.events[i]
				if e.Source == "ddos_blocked" || e.Source == "ddos_jailed" {
					ddosEvents++
				}
				if e.Timestamp.After(cutoff60s) {
					recentCount++
				}
				if e.Timestamp.Before(cutoff5m) {
					break // events are sorted by time, stop scanning
				}
			}

			// Build EPS history: count events per 5-second bucket for last 5 minutes
			buckets := make([]float64, 60) // 60 buckets × 5s = 5 minutes
			for i := len(als.events) - 1; i >= 0; i-- {
				e := &als.events[i]
				if e.Timestamp.Before(cutoff5m) {
					break
				}
				age := now.Sub(e.Timestamp).Seconds()
				bucket := int(age / 5.0)
				if bucket >= 0 && bucket < 60 {
					buckets[bucket]++
				}
			}
			// Convert counts to EPS (count / 5s) and reverse (oldest first)
			epsHistory = make([]float64, 60)
			for i, c := range buckets {
				epsHistory[59-i] = c / 5.0
			}

			// Count L1 (rate) vs L2 (behavioral) jail events from DDoSAction field.
			for i := len(als.events) - 1; i >= 0; i-- {
				e := &als.events[i]
				if e.Timestamp.Before(cutoff5m) {
					break
				}
				if e.Source == "ddos_jailed" {
					if e.DDoSAction == "auto:rate" {
						rateJails++
					} else {
						behavJails++
					}
				}
			}

			als.mu.RUnlock()
		}

		recentEPS = float64(recentCount) / 60.0

		// Use the higher of spike detector EPS and computed EPS
		eps := spikeStatus.EPS
		if recentEPS > eps {
			eps = recentEPS
		}

		status := DosStatus{
			Mode:           spikeStatus.Mode,
			EPS:            eps,
			PeakEPS:        spikeStatus.PeakEPS,
			JailCount:      jailStore.Count(),
			KernelDrop:     cfg.KernelDrop,
			Strategy:       cfg.Strategy,
			EPSHistory:     epsHistory,
			DDoSEvents:     ddosEvents,
			UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
			RateJailCount:  rateJails,
			BehavJailCount: behavJails,
		}
		writeJSON(w, http.StatusOK, status)
	}
}

// ─── GET /api/dos/profiles ──────────────────────────────────────────

// IPProfile is the API response for a single IP's behavioral summary.
// Built from jail entries and access log events — not the plugin's in-memory
// profiles (those are not accessible to wafctl). Provides enough context to
// diagnose false positives and tune thresholds.
type IPProfile struct {
	IP           string   `json:"ip"`
	IsJailed     bool     `json:"is_jailed"`
	Infractions  int32    `json:"infractions"`
	JailReason   string   `json:"jail_reason,omitempty"`
	AnomalyScore float64  `json:"anomaly_score"`       // from jail event if available
	RecentEvents int      `json:"recent_events"`       // DDoS events in last 5m
	BlockedReqs  int      `json:"blocked_reqs"`        // blocked requests in last 5m
	JailedReqs   int      `json:"jailed_reqs"`         // jailed events in last 5m
	Hosts        []string `json:"hosts,omitempty"`     // unique hosts seen (from access log)
	TopPaths     []string `json:"top_paths,omitempty"` // top 5 paths by frequency
	TTL          string   `json:"ttl,omitempty"`       // remaining jail time if jailed
}

func handleListProfiles(jailStore *JailStore, als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Collect jailed IPs first
		jailEntries := jailStore.List()
		jailMap := make(map[string]JailEntry, len(jailEntries))
		for _, e := range jailEntries {
			jailMap[e.IP] = e
		}

		// Scan access log for recent DDoS events (last 5m) to build per-IP summaries
		type ipData struct {
			blocked int
			jailed  int
			hosts   map[string]struct{}
			paths   map[string]int
			score   float64
		}
		ipStats := make(map[string]*ipData)

		cutoff5m := time.Now().Add(-5 * time.Minute)

		if als.mu.TryRLock() {
			for i := len(als.events) - 1; i >= 0; i-- {
				e := &als.events[i]
				if e.Timestamp.Before(cutoff5m) {
					break
				}
				if e.Source != "ddos_blocked" && e.Source != "ddos_jailed" {
					continue
				}
				ip := e.ClientIP
				if ip == "" {
					continue
				}
				d, ok := ipStats[ip]
				if !ok {
					d = &ipData{
						hosts: make(map[string]struct{}),
						paths: make(map[string]int),
					}
					ipStats[ip] = d
				}
				if e.Source == "ddos_blocked" {
					d.blocked++
				} else {
					d.jailed++
					// DDoSScore is a string like "0.65" — parse to float for comparison
					if score, err := strconv.ParseFloat(e.DDoSScore, 64); err == nil && score > d.score {
						d.score = score
					}
				}
				if e.Service != "" {
					d.hosts[e.Service] = struct{}{}
				}
				if e.URI != "" {
					d.paths[e.URI]++
				}
			}
			als.mu.RUnlock()
		}

		// Also include currently-jailed IPs even if no recent events
		for _, je := range jailEntries {
			if _, ok := ipStats[je.IP]; !ok {
				ipStats[je.IP] = &ipData{
					hosts: make(map[string]struct{}),
					paths: make(map[string]int),
				}
			}
		}

		profiles := make([]IPProfile, 0, len(ipStats))
		for ip, d := range ipStats {
			hosts := make([]string, 0, len(d.hosts))
			for h := range d.hosts {
				hosts = append(hosts, h)
			}

			// Top 5 paths by frequency
			type pathCount struct {
				path  string
				count int
			}
			var pcs []pathCount
			for p, c := range d.paths {
				pcs = append(pcs, pathCount{p, c})
			}
			// Simple insertion sort for top 5 (small N)
			for i := 1; i < len(pcs); i++ {
				for j := i; j > 0 && pcs[j].count > pcs[j-1].count; j-- {
					pcs[j], pcs[j-1] = pcs[j-1], pcs[j]
				}
			}
			topPaths := make([]string, 0, 5)
			for i := 0; i < len(pcs) && i < 5; i++ {
				topPaths = append(topPaths, pcs[i].path)
			}

			p := IPProfile{
				IP:           ip,
				IsJailed:     false,
				AnomalyScore: d.score,
				RecentEvents: d.blocked + d.jailed,
				BlockedReqs:  d.blocked,
				JailedReqs:   d.jailed,
				Hosts:        hosts,
				TopPaths:     topPaths,
			}

			if je, ok := jailMap[ip]; ok {
				p.IsJailed = true
				p.Infractions = je.Infractions
				p.JailReason = je.Reason
				p.TTL = je.TTL
				if je.AnomalyScore > p.AnomalyScore {
					p.AnomalyScore = je.AnomalyScore
				}
			}

			profiles = append(profiles, p)
		}

		writeJSON(w, http.StatusOK, profiles)
	}
}

// ─── GET /api/dos/jail ──────────────────────────────────────────────

func handleListJail(jailStore *JailStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries := jailStore.List()
		writeJSON(w, http.StatusOK, entries)
	}
}

// ─── POST /api/dos/jail ─────────────────────────────────────────────

type addJailRequest struct {
	IP     string `json:"ip"`
	TTL    string `json:"ttl"`
	Reason string `json:"reason"`
}

func handleAddJail(jailStore *JailStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req addJailRequest
		if _, failed := decodeJSON(w, r, &req); failed {
			return
		}
		if req.IP == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "ip is required"})
			return
		}
		if net.ParseIP(req.IP) == nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid IP address"})
			return
		}
		if req.TTL == "" {
			req.TTL = "1h"
		}
		if req.Reason == "" {
			req.Reason = "manual"
		}

		if err := jailStore.Add(req.IP, req.TTL, req.Reason); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "failed to add jail entry", Details: err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"status": "jailed",
			"ip":     req.IP,
			"ttl":    req.TTL,
			"reason": req.Reason,
		})
	}
}

// ─── DELETE /api/dos/jail/{ip} ──────────────────────────────────────

func handleRemoveJail(jailStore *JailStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.PathValue("ip")
		if ip == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "ip is required"})
			return
		}

		if err := jailStore.Remove(ip); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to remove", Details: err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"status": "unjailed",
			"ip":     ip,
		})
	}
}

// ─── GET /api/dos/config ────────────────────────────────────────────

func handleGetDosConfig(store *DosConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := store.Get()
		writeJSON(w, http.StatusOK, cfg)
	}
}

// ─── PUT /api/dos/config ────────────────────────────────────────────

func handleUpdateDosConfig(store *DosConfigStore, jailStore *JailStore, spike *SpikeDetector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg DosConfig
		if _, failed := decodeJSON(w, r, &cfg); failed {
			return
		}

		if err := validateDosConfig(cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid config", Details: err.Error()})
			return
		}

		if err := store.Update(cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to save config", Details: err.Error()})
			return
		}

		// Sync whitelist to jail.json for the DDoS mitigator plugin to pick up.
		if jailStore != nil {
			jailStore.SetWhitelist(cfg.Whitelist)
		}

		// Propagate threshold changes to the running spike detector.
		if spike != nil && cfg.EPSTrigger > 0 {
			cooldownDelay, _ := parseExtendedDuration(cfg.CooldownDelay)
			spike.UpdateThresholds(cfg.EPSTrigger, cfg.EPSCooldown, cooldownDelay)
		}

		writeJSON(w, http.StatusOK, cfg)
	}
}

// ─── GET /api/dos/reports ────────────────────────────────────────────

func handleListSpikeReports(reporter *SpikeReporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reports := reporter.List()
		writeJSON(w, http.StatusOK, reports)
	}
}

// ─── GET /api/dos/reports/{id} ──────────────────────────────────────

func handleGetSpikeReport(reporter *SpikeReporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		report := reporter.Get(id)
		if report == nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "report not found"})
			return
		}
		writeJSON(w, http.StatusOK, report)
	}
}

// writeJSON and decodeJSON are defined in json_helpers.go.
