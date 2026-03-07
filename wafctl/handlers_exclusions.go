package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// --- Handlers: Exclusion CRUD ---

// handleExclusionHits returns per-exclusion hit counts derived from policy events.
// It scans events for policy_* event types, matches the msg field in matched_rules
// back to exclusion names, and returns both total hit counts and an hourly sparkline.
//
// Response: { "hits": { "<exclusion_name>": { "total": N, "sparkline": [n, n, ...] } } }
// The sparkline is a 24-element array (one per hour, oldest first).
func handleExclusionHits(store *Store, es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hoursStr := r.URL.Query().Get("hours")
		hours := 24
		if hoursStr != "" {
			if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 && h <= 720 {
				hours = h
			}
		}

		events := store.SnapshotSince(hours)
		exclusions := es.List()

		// Build a set of known exclusion names for fast lookup.
		nameSet := make(map[string]bool, len(exclusions))
		for _, exc := range exclusions {
			nameSet[exc.Name] = true
		}

		// Determine the sparkline bucket boundaries.
		now := time.Now().UTC()
		bucketCount := hours
		if bucketCount > 168 { // cap at 168 buckets (1 week hourly)
			bucketCount = 168
		}
		bucketStart := now.Truncate(time.Hour).Add(-time.Duration(bucketCount-1) * time.Hour)

		type hitData struct {
			Total     int   `json:"total"`
			Sparkline []int `json:"sparkline"`
		}
		hits := make(map[string]*hitData)

		// Initialize entries for all exclusions (so the frontend doesn't need to handle missing keys).
		for _, exc := range exclusions {
			hits[exc.Name] = &hitData{Sparkline: make([]int, bucketCount)}
		}

		for i := range events {
			ev := &events[i]
			if !strings.HasPrefix(ev.EventType, "policy_") {
				continue
			}
			for _, mr := range ev.MatchedRules {
				// msg format: "Policy Allow: <name>", "Policy Skip: <name>", "Policy Block: <name>"
				name := extractPolicyName(mr.Msg)
				if name == "" || !nameSet[name] {
					continue
				}
				hd, ok := hits[name]
				if !ok {
					hd = &hitData{Sparkline: make([]int, bucketCount)}
					hits[name] = hd
				}
				hd.Total++
				// Assign to sparkline bucket.
				bucket := int(ev.Timestamp.Sub(bucketStart).Hours())
				if bucket >= 0 && bucket < bucketCount {
					hd.Sparkline[bucket]++
				}
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{"hits": hits})
	}
}

func handleListExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, es.List())
	}
}

func handleGetExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		exc, found := es.Get(id)
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}
		writeJSON(w, http.StatusOK, exc)
	}
}

func handleCreateExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var exc RuleExclusion
		if _, failed := decodeJSON(w, r, &exc); failed {
			return
		}
		if err := validateExclusion(exc); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		created, err := es.Create(exc)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to create exclusion", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func handleUpdateExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		// Decode into a map first to detect which fields were sent.
		var raw map[string]json.RawMessage
		if _, failed := decodeJSON(w, r, &raw); failed {
			return
		}

		// Fetch the existing exclusion to use as base for merge.
		existing, found := es.Get(id)
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}

		// Marshal existing to JSON, then overlay the incoming fields.
		base, _ := json.Marshal(existing)
		var merged RuleExclusion
		_ = json.Unmarshal(base, &merged)
		overlay, _ := json.Marshal(raw)
		_ = json.Unmarshal(overlay, &merged)

		if err := validateExclusion(merged); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		updated, found, err := es.Update(id, merged)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update exclusion", Details: err.Error()})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func handleDeleteExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		found, err := es.Delete(id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to delete exclusion", Details: err.Error()})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleGenerateExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		exclusions := es.EnabledExclusions()
		// Generate with a default config — this endpoint is exclusion-only.
		result := GenerateConfigs(defaultConfig(), exclusions)
		writeJSON(w, http.StatusOK, result)
	}
}

func handleExportExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, es.Export())
	}
}

func handleImportExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var export ExclusionExport
		if _, failed := decodeJSON(w, r, &export); failed {
			return
		}
		if len(export.Exclusions) == 0 {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "no exclusions in import data"})
			return
		}
		// Validate all exclusions before importing.
		for i, exc := range export.Exclusions {
			if err := validateExclusion(exc); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{
					Error:   "validation failed",
					Details: "exclusion " + strconv.Itoa(i) + ": " + err.Error(),
				})
				return
			}
		}
		if err := es.Import(export.Exclusions); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to import exclusions", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"imported": len(export.Exclusions)})
	}
}

func handleReorderExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IDs []string `json:"ids"`
		}
		if _, failed := decodeJSON(w, r, &req); failed {
			return
		}
		if len(req.IDs) == 0 {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "ids array is required"})
			return
		}
		if err := es.Reorder(req.IDs); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "reorder failed", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, es.List())
	}
}
