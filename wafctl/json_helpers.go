package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
)

// maxJSONBody is the maximum request body size for JSON endpoints (5 MB).
// Generous for bulk imports (~500+ exclusions) while preventing OOM from
// unbounded payloads. The dashboard only sends small payloads; this is a
// safety net, not a functional limit.
const maxJSONBody = 5 << 20

// decodeJSON limits the request body to maxJSONBody and decodes JSON into dst.
// Returns a user-facing error string and true on failure; empty string and false on success.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) (string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		msg := "invalid JSON body"
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			msg = "request body too large (max 5 MB)"
		}
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: msg, Details: err.Error()})
		return msg, true
	}
	return "", false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Printf("[http] error encoding JSON response: %v", err)
	}
}

func queryInt(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}
