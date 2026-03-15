package main

import (
	"net/http"
	"time"
)

// ─── Handlers: Rate Limit Analytics ────────────────────────────────
//
// These handlers read from the AccessLogStore, NOT from the removed
// RateLimitRuleStore. They are kept for analytics/advisor endpoints.

func handleRLRuleHits(als *AccessLogStore, es *ExclusionStore) http.HandlerFunc {
	cache := newResponseCache(20)
	return func(w http.ResponseWriter, r *http.Request) {
		gen := als.generation.Load()
		cacheKey := normalizeCacheKey(r.URL.RawQuery)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
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
		cache.set(cacheKey, hits, gen, 10*time.Second)
		writeJSON(w, http.StatusOK, hits)
	}
}

// --- Rate Limit Advisor handler ---

func handleRLAdvisor(als *AccessLogStore) http.HandlerFunc {
	cache := newResponseCache(20)
	return func(w http.ResponseWriter, r *http.Request) {
		gen := als.generation.Load()
		cacheKey := normalizeCacheKey(r.URL.RawQuery)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
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
		result := als.ScanRates(req)
		cache.set(cacheKey, result, gen, 10*time.Second)
		writeJSON(w, http.StatusOK, result)
	}
}

// --- Rate Limit Analytics handlers ---

func handleRLSummary(als *AccessLogStore) http.HandlerFunc {
	cache := newResponseCache(20)
	return func(w http.ResponseWriter, r *http.Request) {
		gen := als.generation.Load()
		cacheKey := normalizeCacheKey(r.URL.RawQuery)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
		hours := parseHours(r)
		result := als.Summary(hours)
		cache.set(cacheKey, result, gen, 10*time.Second)
		writeJSON(w, http.StatusOK, result)
	}
}

func handleRLEvents(als *AccessLogStore) http.HandlerFunc {
	cache := newResponseCache(50)
	return func(w http.ResponseWriter, r *http.Request) {
		gen := als.generation.Load()
		cacheKey := normalizeCacheKey(r.URL.RawQuery)
		if cached, ok := cache.get(cacheKey, gen); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
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
		result := als.FilteredEvents(service, client, method, limit, offset, hours)
		cache.set(cacheKey, result, gen, 5*time.Second)
		writeJSON(w, http.StatusOK, result)
	}
}
