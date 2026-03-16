package main

import (
	"net/http"
)

// ─── GET /api/dos/status ────────────────────────────────────────────

func handleDosStatus(jailStore *JailStore, dosConfig *DosConfigStore, spike *SpikeDetector, als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := dosConfig.Get()
		spikeStatus := spike.Status()

		// Compute DDoS-specific event count from the access log store
		// for a more meaningful historical view.
		ddosEvents := 0
		if als.mu.TryRLock() {
			for _, e := range als.events {
				if e.Source == "ddos_blocked" || e.Source == "ddos_jailed" {
					ddosEvents++
				}
			}
			als.mu.RUnlock()
		}

		status := DosStatus{
			Mode:       spikeStatus.Mode,
			EPS:        spikeStatus.EPS,
			PeakEPS:    spikeStatus.PeakEPS,
			JailCount:  jailStore.Count(),
			KernelDrop: cfg.KernelDrop,
			Strategy:   cfg.Strategy,
			EPSHistory: spikeStatus.EPSHistory,
			DDoSEvents: ddosEvents,
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

func handleUpdateDosConfig(store *DosConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg DosConfig
		if _, failed := decodeJSON(w, r, &cfg); failed {
			return
		}

		if err := store.Update(cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to save config", Details: err.Error()})
			return
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
