package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── Rate Limit Advisor (scans raw access log for request rate distribution) ──

// RateAdvisorRequest holds query parameters for the advisor endpoint.
type RateAdvisorRequest struct {
	Window  string // "1m", "5m", "10m", "1h"
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

// parseAdvisorWindow parses window strings like "1m", "5m", "10m", "1h".
func parseAdvisorWindow(s string) time.Duration {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "1m":
		return time.Minute
	case "5m":
		return 5 * time.Minute
	case "10m":
		return 10 * time.Minute
	case "1h":
		return time.Hour
	default:
		return time.Minute // default 1m
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

// ─── Advisor Scan ───────────────────────────────────────────────────

// ScanRates reads recent entries from the combined access log and computes
// per-client request rates, anomaly metrics, and a statistical threshold
// recommendation. Results are cached for 30 seconds.
func (s *AccessLogStore) ScanRates(req RateAdvisorRequest) RateAdvisorResponse {
	// Check cache first.
	if s.advCache != nil {
		key := advisorCacheKey(req)
		if cached, ok := s.advCache.get(key); ok {
			return cached
		}
	}

	resp := s.scanRatesUncached(req)

	// Cache the result.
	if s.advCache != nil {
		s.advCache.set(advisorCacheKey(req), resp)
	}
	return resp
}

// scanRatesUncached performs the actual log scan without caching.
func (s *AccessLogStore) scanRatesUncached(req RateAdvisorRequest) RateAdvisorResponse {
	window := parseAdvisorWindow(req.Window)
	windowSecs := window.Seconds()
	limit := req.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	cutoff := time.Now().Add(-window)

	// Tail-read: seek to max(0, fileSize - tailBytes) and scan forward.
	const tailBytes int64 = 20 * 1024 * 1024 // 20 MB covers ~10 min at typical traffic

	f, err := os.Open(s.path)
	if err != nil {
		log.Printf("advisor: error opening access log: %v", err)
		return RateAdvisorResponse{Window: req.Window, WindowSeconds: windowSecs}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return RateAdvisorResponse{Window: req.Window, WindowSeconds: windowSecs}
	}

	seekPos := info.Size() - tailBytes
	if seekPos < 0 {
		seekPos = 0
	}
	if _, err := f.Seek(seekPos, io.SeekStart); err != nil {
		return RateAdvisorResponse{Window: req.Window, WindowSeconds: windowSecs}
	}

	// If we seeked mid-file, skip the first partial line.
	reader := bufio.NewReaderSize(f, 64*1024)
	if seekPos > 0 {
		_, _ = reader.ReadBytes('\n') // discard partial line
	}

	// Snapshot geoIP for country enrichment.
	s.mu.RLock()
	geoIP := s.geoIP
	s.mu.RUnlock()

	// Per-client aggregation with sub-window tracking for burstiness.
	type clientData struct {
		requests   int
		errors     int // 4xx + 5xx count
		country    string
		paths      map[string]int
		subWindows map[int64]int // 10-second bucket epoch → request count
	}
	clients := make(map[string]*clientData)
	totalRequests := 0

	// Per-hour aggregation for time-of-day baselines.
	// Key: hour of day (0–23), value: per-client request counts in that hour.
	hourMap := make(map[int]*advisorHourData)

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
		}
		if len(line) > 0 {
			var entry AccessLogEntry
			if jsonErr := json.Unmarshal(line, &entry); jsonErr == nil {
				ts := parseTimestamp(entry.Ts)
				if ts.Before(cutoff) {
					if err != nil {
						break
					}
					continue
				}

				// Apply filters.
				if req.Service != "" && !strings.EqualFold(entry.Request.Host, req.Service) {
					if err != nil {
						break
					}
					continue
				}
				if req.Path != "" && !strings.HasPrefix(entry.Request.URI, req.Path) {
					if err != nil {
						break
					}
					continue
				}
				if req.Method != "" && !strings.EqualFold(entry.Request.Method, req.Method) {
					if err != nil {
						break
					}
					continue
				}

				ip := entry.Request.ClientIP
				totalRequests++

				cd, ok := clients[ip]
				if !ok {
					country := ""
					if geoIP != nil {
						cfCountry := headerValue(entry.Request.Headers, "Cf-Ipcountry")
						country = geoIP.Resolve(ip, cfCountry)
					}
					cd = &clientData{
						country:    country,
						paths:      make(map[string]int),
						subWindows: make(map[int64]int),
					}
					clients[ip] = cd
				}
				cd.requests++

				// Track errors (4xx + 5xx).
				if entry.Status >= 400 {
					cd.errors++
				}

				// Track 10-second sub-window for burstiness calculation.
				bucket := ts.Unix() / 10
				cd.subWindows[bucket]++

				// Track path (strip query string).
				path := entry.Request.URI
				if idx := strings.IndexByte(path, '?'); idx >= 0 {
					path = path[:idx]
				}
				cd.paths[path]++

				// Track hour-of-day for baselines.
				hour := ts.Hour()
				hd, ok := hourMap[hour]
				if !ok {
					hd = &advisorHourData{clientCounts: make(map[string]int)}
					hourMap[hour] = hd
				}
				hd.clientCounts[ip]++
				hd.total++
			}
		}
		if err != nil {
			break
		}
	}

	if len(clients) == 0 {
		return RateAdvisorResponse{
			Window:        req.Window,
			WindowSeconds: windowSecs,
			Service:       req.Service,
			Path:          req.Path,
			Method:        req.Method,
		}
	}

	// Build client list with anomaly metrics.
	allClients := make([]RateAdvisorClient, 0, len(clients))
	for ip, cd := range clients {
		rac := RateAdvisorClient{
			ClientIP: ip,
			Country:  cd.country,
			Requests: cd.requests,
		}

		// Normalized rate: requests per second.
		if windowSecs > 0 {
			rac.RequestsPerSec = math.Round(float64(cd.requests)/windowSecs*100) / 100
		}

		// Error rate: fraction of 4xx+5xx.
		if cd.requests > 0 {
			rac.ErrorRate = float64(cd.errors) / float64(cd.requests)
		}

		// Path diversity: unique_paths / total_requests.
		if cd.requests > 0 {
			rac.PathDiversity = float64(len(cd.paths)) / float64(cd.requests)
			if rac.PathDiversity > 1.0 {
				rac.PathDiversity = 1.0
			}
		}

		// Burstiness: Fano factor over 10s sub-windows.
		// F = variance / mean. F~1 = Poisson (human), F>>1 = bursty (bot).
		rac.Burstiness = computeFanoFactor(cd.subWindows)

		// Top 5 paths for this client.
		type pathCount struct {
			path  string
			count int
		}
		paths := make([]pathCount, 0, len(cd.paths))
		for p, c := range cd.paths {
			paths = append(paths, pathCount{p, c})
		}
		sort.Slice(paths, func(i, j int) bool { return paths[i].count > paths[j].count })
		topN := 5
		if len(paths) < topN {
			topN = len(paths)
		}
		for _, p := range paths[:topN] {
			rac.TopPaths = append(rac.TopPaths, struct {
				Path  string `json:"path"`
				Count int    `json:"count"`
			}{p.path, p.count})
		}
		allClients = append(allClients, rac)
	}

	// Classify all clients using composite anomaly scoring.
	classifyClients(allClients)

	// Sort by request count descending.
	sort.Slice(allClients, func(i, j int) bool { return allClients[i].Requests > allClients[j].Requests })

	// Compute percentiles from ALL clients (raw counts).
	allCounts := make([]int, len(allClients))
	for i, c := range allClients {
		allCounts[i] = c.Requests
	}
	sort.Ints(allCounts)

	pctiles := AdvisorPercentiles{
		P50: intPercentile(allCounts, 50),
		P75: intPercentile(allCounts, 75),
		P90: intPercentile(allCounts, 90),
		P95: intPercentile(allCounts, 95),
		P99: intPercentile(allCounts, 99),
	}

	// Compute normalized percentiles (req/s).
	normPctiles := NormalizedPercentiles{}
	if windowSecs > 0 {
		normPctiles.P50 = math.Round(float64(pctiles.P50)/windowSecs*100) / 100
		normPctiles.P75 = math.Round(float64(pctiles.P75)/windowSecs*100) / 100
		normPctiles.P90 = math.Round(float64(pctiles.P90)/windowSecs*100) / 100
		normPctiles.P95 = math.Round(float64(pctiles.P95)/windowSecs*100) / 100
		normPctiles.P99 = math.Round(float64(pctiles.P99)/windowSecs*100) / 100
	}

	// Compute recommendation using MAD-based anomaly detection.
	rec := computeRecommendation(allClients, allCounts, totalRequests)

	// Compute impact curve (20 points from min to max).
	impact := computeImpactCurve(allClients, allCounts, totalRequests)

	// Compute rate distribution histogram (log-scale bins).
	histogram := computeHistogram(allCounts)

	// Compute time-of-day baselines (only meaningful with ≥2 hours of data).
	var baselines []TimeOfDayBaseline
	if len(hourMap) >= 2 {
		baselines = computeTimeOfDayBaselines(hourMap)
	}

	// Truncate client list to requested limit.
	topClients := allClients
	if len(topClients) > limit {
		topClients = topClients[:limit]
	}

	return RateAdvisorResponse{
		Window:             req.Window,
		WindowSeconds:      windowSecs,
		Service:            req.Service,
		Path:               req.Path,
		Method:             req.Method,
		TotalRequests:      totalRequests,
		UniqueClients:      len(clients),
		Clients:            topClients,
		Percentiles:        pctiles,
		NormalizedPctiles:  normPctiles,
		Recommendation:     rec,
		ImpactCurve:        impact,
		Histogram:          histogram,
		TimeOfDayBaselines: baselines,
	}
}

// ─── Time-of-Day Baselines ──────────────────────────────────────────

// advisorHourData aggregates per-client request counts within a single hour-of-day.
type advisorHourData struct {
	clientCounts map[string]int // client IP → requests in this hour
	total        int
}

// computeTimeOfDayBaselines computes per-hour traffic baselines from the scan data.
// For each hour-of-day present in the data, it calculates the median and P95
// per-client request rates (normalized to req/s assuming a 1-hour window per hour).
func computeTimeOfDayBaselines(hourMap map[int]*advisorHourData) []TimeOfDayBaseline {
	baselines := make([]TimeOfDayBaseline, 0, len(hourMap))
	for hour, hd := range hourMap {
		if len(hd.clientCounts) == 0 {
			continue
		}
		// Collect per-client counts for this hour.
		counts := make([]float64, 0, len(hd.clientCounts))
		for _, c := range hd.clientCounts {
			counts = append(counts, float64(c))
		}
		sort.Float64s(counts)

		// Compute median and P95 normalized to req/s (per 3600s hour).
		n := len(counts)
		median := counts[n/2]
		p95Idx := int(float64(95) / 100.0 * float64(n))
		if p95Idx >= n {
			p95Idx = n - 1
		}
		p95 := counts[p95Idx]

		baselines = append(baselines, TimeOfDayBaseline{
			Hour:      hour,
			MedianRPS: math.Round(median/3600*1000) / 1000, // 3 decimal places
			P95RPS:    math.Round(p95/3600*1000) / 1000,
			Clients:   len(hd.clientCounts),
			Requests:  hd.total,
		})
	}
	// Sort by hour.
	sort.Slice(baselines, func(i, j int) bool { return baselines[i].Hour < baselines[j].Hour })
	return baselines
}

// ─── Advisor statistical helpers ────────────────────────────────────

// intPercentile computes the p-th percentile from a sorted int slice.
func intPercentile(sorted []int, pct int) int {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	// Use nearest-rank method.
	rank := float64(pct) / 100.0 * float64(n)
	idx := int(rank)
	if idx >= n {
		idx = n - 1
	}
	if idx < 0 {
		idx = 0
	}
	return sorted[idx]
}

// computeFanoFactor calculates the Fano factor (variance/mean) of sub-window
// counts. Returns 1.0 if there aren't enough data points. A value of ~1
// indicates Poisson-like (random human) traffic; >>1 indicates bursty
// machine-generated traffic; <<1 indicates suspiciously regular traffic.
func computeFanoFactor(subWindows map[int64]int) float64 {
	if len(subWindows) < 2 {
		return 1.0 // not enough data, assume normal
	}
	counts := make([]float64, 0, len(subWindows))
	for _, c := range subWindows {
		counts = append(counts, float64(c))
	}
	mean := 0.0
	for _, v := range counts {
		mean += v
	}
	mean /= float64(len(counts))
	if mean == 0 {
		return 1.0
	}
	variance := 0.0
	for _, v := range counts {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(counts))
	return variance / mean
}

// medianFloat64 returns the median of a float64 slice (sorts in place).
func medianFloat64(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sort.Float64s(vals)
	n := len(vals)
	if n%2 == 0 {
		return (vals[n/2-1] + vals[n/2]) / 2
	}
	return vals[n/2]
}

// computeMAD returns the Median Absolute Deviation of a float64 slice.
// The input must NOT be pre-sorted (it is copied internally).
func computeMAD(vals []float64) (median, mad float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	cp := make([]float64, len(vals))
	copy(cp, vals)
	median = medianFloat64(cp)

	deviations := make([]float64, len(vals))
	for i, v := range vals {
		d := v - median
		if d < 0 {
			d = -d
		}
		deviations[i] = d
	}
	mad = medianFloat64(deviations)
	return median, mad
}

// classifyClients assigns a classification ("normal", "suspicious", "abusive")
// and anomaly score (0–100) to each client using a composite scoring approach.
//
// Scoring dimensions (weighted):
//   - Rate Z-score via Modified Z (MAD-based): weight 0.4
//   - Error rate: weight 0.2
//   - Inverse path diversity (1 - diversity): weight 0.2
//   - Burstiness (capped Fano factor): weight 0.2
//
// Modified Z-score: 0.6745 * (x - median) / MAD (robust to outliers).
// Classification: score >= 70 → abusive, score >= 40 → suspicious, else normal.
func classifyClients(clients []RateAdvisorClient) {
	if len(clients) == 0 {
		return
	}

	// Collect rate values for MAD computation.
	rates := make([]float64, len(clients))
	for i, c := range clients {
		rates[i] = float64(c.Requests)
	}
	rateMedian, rateMAD := computeMAD(rates)

	for i := range clients {
		c := &clients[i]

		// Modified Z-score for rate (higher = more anomalous).
		var rateZ float64
		if rateMAD > 0 {
			rateZ = 0.6745 * (float64(c.Requests) - rateMedian) / rateMAD
		} else if rateMedian > 0 {
			// All clients have similar rates (MAD=0). Use simple ratio.
			rateZ = (float64(c.Requests) - rateMedian) / rateMedian
		}
		if rateZ < 0 {
			rateZ = 0
		}

		// Normalize rate Z-score to 0-100 (cap at z=6 → 100).
		rateScore := rateZ / 6.0 * 100.0
		if rateScore > 100 {
			rateScore = 100
		}

		// Error rate score: 0% → 0, 50%+ → 100.
		errorScore := c.ErrorRate * 200.0
		if errorScore > 100 {
			errorScore = 100
		}

		// Inverse path diversity: low diversity → high score.
		// diversity 0 (single path) → 100, diversity 1 (all unique) → 0.
		diversityScore := (1.0 - c.PathDiversity) * 100.0

		// Burstiness score: Fano factor 1 → 0, 10+ → 100.
		burstyScore := 0.0
		if c.Burstiness > 1.0 {
			burstyScore = (c.Burstiness - 1.0) / 9.0 * 100.0
		}
		if burstyScore > 100 {
			burstyScore = 100
		}

		// Composite weighted score.
		score := 0.4*rateScore + 0.2*errorScore + 0.2*diversityScore + 0.2*burstyScore

		c.AnomalyScore = math.Round(score*10) / 10 // 1 decimal place

		switch {
		case score >= 70:
			c.Classification = "abusive"
		case score >= 40:
			c.Classification = "suspicious"
		default:
			c.Classification = "normal"
		}
	}
}

// computeRecommendation generates a threshold recommendation using MAD-based
// anomaly detection. The recommended threshold is:
//
//	threshold = median + 3 * 1.4826 * MAD
//
// This covers ~99.7% of "normal" traffic assuming an approximately normal
// distribution. For heavily skewed distributions (where MAD is very small or
// zero), it falls back to P99 or IQR-based methods.
func computeRecommendation(clients []RateAdvisorClient, sortedCounts []int, totalRequests int) *AdvisorRecommendation {
	if len(sortedCounts) < 3 {
		return nil // not enough data for a meaningful recommendation
	}

	rates := make([]float64, len(sortedCounts))
	for i, c := range sortedCounts {
		rates[i] = float64(c)
	}

	median, mad := computeMAD(rates)
	sigma := 1.4826 * mad // scale factor for normal distribution consistency

	var threshold int
	var method string
	var confidence string

	if sigma > 0 && mad > 0 {
		// MAD-based threshold: median + 3σ.
		madThreshold := median + 3.0*sigma
		threshold = int(math.Ceil(madThreshold))
		method = "mad"

		// Confidence based on how well the data separates.
		// If the threshold is much higher than P95, we have good separation.
		p95 := intPercentile(sortedCounts, 95)
		if threshold > 0 && float64(p95)/float64(threshold) < 0.7 {
			confidence = "high"
		} else if float64(p95)/float64(threshold) < 0.9 {
			confidence = "medium"
		} else {
			confidence = "low"
		}
	} else {
		// Fallback: IQR method when MAD is zero (many clients at the same rate).
		q1 := intPercentile(sortedCounts, 25)
		q3 := intPercentile(sortedCounts, 75)
		iqr := q3 - q1
		if iqr > 0 {
			threshold = q3 + 3*iqr // extreme outlier fence
			method = "iqr"
			confidence = "medium"
		} else {
			// Last resort: P99.
			threshold = intPercentile(sortedCounts, 99)
			if threshold < 1 {
				threshold = 1
			}
			method = "p99"
			confidence = "low"
		}
	}

	// Ensure threshold is at least 1.
	if threshold < 1 {
		threshold = 1
	}

	// Count affected clients and requests at this threshold.
	affectedClients := 0
	affectedRequests := 0
	for _, c := range clients {
		if c.Requests >= threshold {
			affectedClients++
			affectedRequests += c.Requests
		}
	}

	// Compute Cohen's d separation between normal and flagged groups.
	var normalRates, flaggedRates []float64
	for _, c := range clients {
		if c.Requests >= threshold {
			flaggedRates = append(flaggedRates, float64(c.Requests))
		} else {
			normalRates = append(normalRates, float64(c.Requests))
		}
	}
	separation := cohensD(normalRates, flaggedRates)

	// Upgrade confidence if separation is very strong.
	if separation > 2.0 && confidence == "medium" {
		confidence = "high"
	}
	if separation > 3.0 {
		confidence = "high"
	}

	return &AdvisorRecommendation{
		Threshold:        threshold,
		Confidence:       confidence,
		Method:           method,
		AffectedClients:  affectedClients,
		AffectedRequests: affectedRequests,
		Median:           math.Round(median*10) / 10,
		MAD:              math.Round(mad*10) / 10,
		Separation:       math.Round(separation*100) / 100,
	}
}

// cohensD computes Cohen's d effect size between two groups.
// Returns 0 if either group is empty.
func cohensD(group1, group2 []float64) float64 {
	if len(group1) == 0 || len(group2) == 0 {
		return 0
	}
	mean1, mean2 := 0.0, 0.0
	for _, v := range group1 {
		mean1 += v
	}
	mean1 /= float64(len(group1))
	for _, v := range group2 {
		mean2 += v
	}
	mean2 /= float64(len(group2))

	var1, var2 := 0.0, 0.0
	for _, v := range group1 {
		d := v - mean1
		var1 += d * d
	}
	for _, v := range group2 {
		d := v - mean2
		var2 += d * d
	}

	n1, n2 := float64(len(group1)), float64(len(group2))
	if n1 <= 1 && n2 <= 1 {
		return 0
	}

	// Pooled standard deviation.
	var pooledVar float64
	if n1 > 1 && n2 > 1 {
		pooledVar = (var1/(n1-1)*(n1-1) + var2/(n2-1)*(n2-1)) / (n1 + n2 - 2)
	} else if n1 > 1 {
		pooledVar = var1 / (n1 - 1)
	} else {
		pooledVar = var2 / (n2 - 1)
	}

	pooledSD := math.Sqrt(pooledVar)
	if pooledSD == 0 {
		return 0
	}
	d := (mean2 - mean1) / pooledSD
	if d < 0 {
		d = -d
	}
	return d
}

// computeImpactCurve generates ~20 threshold points showing what fraction of
// clients and requests would be affected at each level.
func computeImpactCurve(clients []RateAdvisorClient, sortedCounts []int, totalRequests int) []ImpactPoint {
	if len(sortedCounts) == 0 || totalRequests == 0 {
		return nil
	}

	minRate := sortedCounts[0]
	maxRate := sortedCounts[len(sortedCounts)-1]
	if maxRate <= minRate {
		return nil
	}

	// Pre-compute per-client request totals by sorted rate for efficient lookup.
	// sortedCounts is ascending; we need to count from the right.
	nClients := len(clients)

	// Generate ~20 evenly spaced thresholds.
	numPoints := 20
	step := float64(maxRate-minRate) / float64(numPoints)
	if step < 1 {
		step = 1
	}

	var curve []ImpactPoint
	seen := make(map[int]bool)
	for i := 0; i <= numPoints; i++ {
		t := minRate + int(float64(i)*step)
		if t < 1 {
			t = 1
		}
		if seen[t] {
			continue
		}
		seen[t] = true

		affClients := 0
		affRequests := 0
		for _, c := range clients {
			if c.Requests >= t {
				affClients++
				affRequests += c.Requests
			}
		}

		curve = append(curve, ImpactPoint{
			Threshold:        t,
			ClientsAffected:  affClients,
			RequestsAffected: affRequests,
			ClientPct:        float64(affClients) / float64(nClients),
			RequestPct:       float64(affRequests) / float64(totalRequests),
		})
	}
	return curve
}

// computeHistogram builds a log-scale histogram of client request rates.
// Uses approximately 15-20 bins spanning from 1 to max(rates).
func computeHistogram(sortedCounts []int) []HistogramBin {
	if len(sortedCounts) == 0 {
		return nil
	}
	maxRate := sortedCounts[len(sortedCounts)-1]
	if maxRate <= 0 {
		return nil
	}

	// Generate log-scale bin boundaries.
	// Bins: [1,2), [2,3), [3,5), [5,8), [8,13), [13,21), ... (roughly Fibonacci/log growth)
	boundaries := []int{1}
	b := 1
	for b < maxRate {
		next := b + int(math.Max(1, math.Round(float64(b)*0.6)))
		if next <= b {
			next = b + 1
		}
		boundaries = append(boundaries, next)
		b = next
	}
	// Ensure the last boundary exceeds maxRate.
	if boundaries[len(boundaries)-1] <= maxRate {
		boundaries = append(boundaries, maxRate+1)
	}

	// Cap at ~25 bins by merging.
	for len(boundaries) > 26 {
		merged := []int{boundaries[0]}
		for i := 1; i < len(boundaries); i += 2 {
			if i+1 < len(boundaries) {
				merged = append(merged, boundaries[i+1])
			} else {
				merged = append(merged, boundaries[i])
			}
		}
		boundaries = merged
	}

	// Count clients in each bin.
	bins := make([]HistogramBin, len(boundaries)-1)
	for i := 0; i < len(boundaries)-1; i++ {
		bins[i] = HistogramBin{Min: boundaries[i], Max: boundaries[i+1]}
	}

	ci := 0 // index into sortedCounts
	for bi := range bins {
		for ci < len(sortedCounts) && sortedCounts[ci] < bins[bi].Max {
			if sortedCounts[ci] >= bins[bi].Min {
				bins[bi].Count++
			}
			ci++
		}
	}

	// Remove empty trailing bins.
	for len(bins) > 0 && bins[len(bins)-1].Count == 0 {
		bins = bins[:len(bins)-1]
	}

	return bins
}
