package main

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── Rate Limit Advisor (scans raw access log for request rate distribution) ──

// RateAdvisorRequest holds query parameters for the advisor endpoint.
type RateAdvisorRequest struct {
	Window  string // duration string: "30s", "5m", "2h", etc.
	Service string // filter by host
	Path    string // filter by URI prefix
	Method  string // filter by HTTP method
	Limit   int    // top N clients (default 50)
}

// RateAdvisorClient represents one client's request rate with anomaly metrics.
type RateAdvisorClient struct {
	ClientIP       string  `json:"client_ip"`
	Country        string  `json:"country,omitempty"`
	Requests       int     `json:"requests"`
	RequestsPerSec float64 `json:"requests_per_sec"` // normalized to req/s for cross-window comparison
	ErrorRate      float64 `json:"error_rate"`       // fraction of 4xx+5xx responses (0.0–1.0)
	PathDiversity  float64 `json:"path_diversity"`   // unique_paths / total_requests (0.0–1.0)
	Burstiness     float64 `json:"burstiness"`       // Fano factor over 10s sub-windows (1.0=random, >>1=bursty)
	Classification string  `json:"classification"`   // "normal", "suspicious", "abusive"
	AnomalyScore   float64 `json:"anomaly_score"`    // composite anomaly score (0–100)
	TopPaths       []struct {
		Path  string `json:"path"`
		Count int    `json:"count"`
	} `json:"top_paths"`
}

// AdvisorRecommendation is a statistically-derived threshold suggestion.
type AdvisorRecommendation struct {
	Threshold        int     `json:"threshold"`         // recommended rate limit threshold
	Confidence       string  `json:"confidence"`        // "low", "medium", "high"
	Method           string  `json:"method"`            // algorithm used: "mad", "p99", "iqr"
	AffectedClients  int     `json:"affected_clients"`  // clients that would exceed this threshold
	AffectedRequests int     `json:"affected_requests"` // total requests from affected clients
	Median           float64 `json:"median"`            // median request rate
	MAD              float64 `json:"mad"`               // Median Absolute Deviation
	Separation       float64 `json:"separation"`        // Cohen's d between normal and flagged groups
}

// ImpactPoint represents one point on the impact curve.
type ImpactPoint struct {
	Threshold        int     `json:"threshold"`
	ClientsAffected  int     `json:"clients_affected"`
	RequestsAffected int     `json:"requests_affected"`
	ClientPct        float64 `json:"client_pct"`  // fraction of unique clients affected
	RequestPct       float64 `json:"request_pct"` // fraction of total requests affected
}

// HistogramBin represents one bin in the rate distribution histogram.
type HistogramBin struct {
	Min   int `json:"min"`   // inclusive lower bound
	Max   int `json:"max"`   // exclusive upper bound
	Count int `json:"count"` // number of clients in this bin
}

// TimeOfDayBaseline represents traffic patterns for a specific hour of day.
type TimeOfDayBaseline struct {
	Hour      int     `json:"hour"`       // 0–23
	MedianRPS float64 `json:"median_rps"` // median req/s across all clients active in this hour
	P95RPS    float64 `json:"p95_rps"`    // P95 req/s
	Clients   int     `json:"clients"`    // unique clients active in this hour
	Requests  int     `json:"requests"`   // total requests in this hour
}

// RateAdvisorResponse is the API response for the advisor endpoint.
type RateAdvisorResponse struct {
	Window             string                 `json:"window"`
	WindowSeconds      float64                `json:"window_seconds"` // window duration in seconds for frontend normalization
	Service            string                 `json:"service,omitempty"`
	Path               string                 `json:"path,omitempty"`
	Method             string                 `json:"method,omitempty"`
	TotalRequests      int                    `json:"total_requests"`
	UniqueClients      int                    `json:"unique_clients"`
	Clients            []RateAdvisorClient    `json:"clients"`
	Percentiles        AdvisorPercentiles     `json:"percentiles"`
	NormalizedPctiles  NormalizedPercentiles  `json:"normalized_percentiles"` // percentiles in req/s
	Recommendation     *AdvisorRecommendation `json:"recommendation,omitempty"`
	ImpactCurve        []ImpactPoint          `json:"impact_curve"`
	Histogram          []HistogramBin         `json:"histogram"`
	TimeOfDayBaselines []TimeOfDayBaseline    `json:"time_of_day_baselines,omitempty"` // per-hour baselines (only for windows ≥10m with enough data)
}

// AdvisorPercentiles holds the standard percentile breakpoints (raw counts per window).
type AdvisorPercentiles struct {
	P50 int `json:"p50"`
	P75 int `json:"p75"`
	P90 int `json:"p90"`
	P95 int `json:"p95"`
	P99 int `json:"p99"`
}

// NormalizedPercentiles holds percentile breakpoints normalized to req/s.
type NormalizedPercentiles struct {
	P50 float64 `json:"p50"`
	P75 float64 `json:"p75"`
	P90 float64 `json:"p90"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
}

// parseAdvisorWindow parses duration strings like "30s", "5m", "2h".
// Accepts any positive integer followed by s, m, or h.
func parseAdvisorWindow(s string) time.Duration {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) < 2 {
		return time.Minute
	}
	unit := s[len(s)-1]
	num, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || num <= 0 {
		return time.Minute
	}
	switch unit {
	case 's':
		return time.Duration(num) * time.Second
	case 'm':
		return time.Duration(num) * time.Minute
	case 'h':
		return time.Duration(num) * time.Hour
	default:
		return time.Minute
	}
}

// ─── Advisor Cache ──────────────────────────────────────────────────

type advisorCacheEntry struct {
	response  RateAdvisorResponse
	expiresAt time.Time
}

type advisorCache struct {
	mu      sync.Mutex
	entries map[string]advisorCacheEntry
}

func newAdvisorCache() *advisorCache {
	return &advisorCache{entries: make(map[string]advisorCacheEntry)}
}

const advisorCacheTTL = 30 * time.Second

// advisorCacheKey builds a cache key from the request parameters.
func advisorCacheKey(req RateAdvisorRequest) string {
	return req.Window + "|" + req.Service + "|" + req.Path + "|" + req.Method + "|" + strconv.Itoa(req.Limit)
}

func (c *advisorCache) get(key string) (RateAdvisorResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		if ok {
			delete(c.entries, key) // expired
		}
		return RateAdvisorResponse{}, false
	}
	return entry.response, true
}

func (c *advisorCache) set(key string, resp RateAdvisorResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Evict expired entries if cache grows large.
	if len(c.entries) > 50 {
		now := time.Now()
		for k, e := range c.entries {
			if now.After(e.expiresAt) {
				delete(c.entries, k)
			}
		}
	}
	c.entries[key] = advisorCacheEntry{response: resp, expiresAt: time.Now().Add(advisorCacheTTL)}
}
