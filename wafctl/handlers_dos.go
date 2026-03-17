package main

import (
	"net"
	"net/http"
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

			als.mu.RUnlock()
		}

		recentEPS = float64(recentCount) / 60.0

		// Use the higher of spike detector EPS and computed EPS
		eps := spikeStatus.EPS
		if recentEPS > eps {
			eps = recentEPS
		}

		status := DosStatus{
			Mode:       spikeStatus.Mode,
			EPS:        eps,
			PeakEPS:    spikeStatus.PeakEPS,
			JailCount:  jailStore.Count(),
			KernelDrop: cfg.KernelDrop,
			Strategy:   cfg.Strategy,
			EPSHistory: epsHistory,
			DDoSEvents: ddosEvents,
			UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
		}
		writeJSON(w, http.StatusOK, status)
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

func handleUpdateDosConfig(store *DosConfigStore, jailStore *JailStore) http.HandlerFunc {
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
