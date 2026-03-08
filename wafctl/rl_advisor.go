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
	"strings"
	"time"
)

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
