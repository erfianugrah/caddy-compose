package main

import (
	"net/http"
)

// ─── Handlers: Rate Limit Analytics ────────────────────────────────
//
// These handlers read from the AccessLogStore, NOT from the removed
// RateLimitRuleStore. They are kept for analytics/advisor endpoints.

func handleRLRuleHits(als *AccessLogStore, es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := parseHours(r)
		exclusions := es.List()
		// Build a []RateLimitRule from rate_limit exclusions for tag enrichment.
		var rules []RateLimitRule
		for _, exc := range exclusions {
			if exc.Type == "rate_limit" {
				rules = append(rules, RateLimitRule{
					Name:    exc.Name,
					Service: exc.Service,
					Tags:    exc.Tags,
				})
			}
		}
		hits := als.RuleHits(rules, hours)
		writeJSON(w, http.StatusOK, hits)
	}
}

// --- Rate Limit Advisor handler ---

func handleRLAdvisor(als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := queryInt(q.Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		req := RateAdvisorRequest{
			Window:  q.Get("window"),
			Service: q.Get("service"),
			Path:    q.Get("path"),
			Method:  q.Get("method"),
			Limit:   limit,
		}
		writeJSON(w, http.StatusOK, als.ScanRates(req))
	}
}

// --- Rate Limit Analytics handlers ---

func handleRLSummary(als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := parseHours(r)
		writeJSON(w, http.StatusOK, als.Summary(hours))
	}
}

func handleRLEvents(als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		service := q.Get("service")
		client := q.Get("client")
		method := q.Get("method")
		limit := queryInt(q.Get("limit"), 50)
		if limit <= 0 || limit > 1000 {
			limit = 50
		}
		offset := queryInt(q.Get("offset"), 0)
		if offset < 0 {
			offset = 0
		}
		hours := parseHours(r)
		writeJSON(w, http.StatusOK, als.FilteredEvents(service, client, method, limit, offset, hours))
	}
}
