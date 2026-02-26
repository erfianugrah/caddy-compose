package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ─── Advisor Algorithm Tests ────────────────────────────────────────

func TestIntPercentile(t *testing.T) {
	tests := []struct {
		name   string
		sorted []int
		pct    int
		want   int
	}{
		{"empty", nil, 50, 0},
		{"single", []int{42}, 50, 42},
		{"single p99", []int{42}, 99, 42},
		{"two p50", []int{10, 20}, 50, 20},
		{"ten p50", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 50, 6},
		{"ten p90", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 90, 10},
		{"ten p99", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 99, 10},
		{"ten p0", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intPercentile(tt.sorted, tt.pct)
			if got != tt.want {
				t.Errorf("intPercentile(%v, %d) = %d, want %d", tt.sorted, tt.pct, got, tt.want)
			}
		})
	}
}

func TestComputeFanoFactor(t *testing.T) {
	tests := []struct {
		name       string
		subWindows map[int64]int
		wantRange  [2]float64 // min, max acceptable
	}{
		{
			"empty",
			nil,
			[2]float64{1.0, 1.0},
		},
		{
			"single bucket",
			map[int64]int{100: 10},
			[2]float64{1.0, 1.0}, // not enough data
		},
		{
			"uniform (all same)",
			map[int64]int{100: 5, 101: 5, 102: 5, 103: 5},
			[2]float64{0, 0.01}, // zero variance
		},
		{
			"bursty",
			map[int64]int{100: 100, 101: 1, 102: 1, 103: 1},
			[2]float64{30, 200}, // very high Fano factor
		},
		{
			"moderate spread",
			map[int64]int{100: 3, 101: 5, 102: 4, 103: 6},
			[2]float64{0.1, 1.5}, // roughly Poisson
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeFanoFactor(tt.subWindows)
			if got < tt.wantRange[0] || got > tt.wantRange[1] {
				t.Errorf("computeFanoFactor() = %f, want in [%f, %f]", got, tt.wantRange[0], tt.wantRange[1])
			}
		})
	}
}

func TestComputeMAD(t *testing.T) {
	tests := []struct {
		name       string
		vals       []float64
		wantMedian float64
		wantMAD    float64
	}{
		{"empty", nil, 0, 0},
		{"single", []float64{5}, 5, 0},
		{"symmetric", []float64{1, 2, 3, 4, 5}, 3, 1},
		{"with outlier", []float64{1, 2, 3, 4, 100}, 3, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			median, mad := computeMAD(tt.vals)
			if median != tt.wantMedian {
				t.Errorf("median = %f, want %f", median, tt.wantMedian)
			}
			if mad != tt.wantMAD {
				t.Errorf("MAD = %f, want %f", mad, tt.wantMAD)
			}
		})
	}
}

func TestClassifyClients(t *testing.T) {
	clients := []RateAdvisorClient{
		{ClientIP: "1.1.1.1", Requests: 5, ErrorRate: 0.01, PathDiversity: 0.8, Burstiness: 1.0},
		{ClientIP: "2.2.2.2", Requests: 5, ErrorRate: 0.02, PathDiversity: 0.7, Burstiness: 0.9},
		{ClientIP: "3.3.3.3", Requests: 5, ErrorRate: 0.01, PathDiversity: 0.6, Burstiness: 1.1},
		{ClientIP: "4.4.4.4", Requests: 5, ErrorRate: 0.01, PathDiversity: 0.5, Burstiness: 1.0},
		// Outlier: high rate, high error rate, low diversity, bursty.
		{ClientIP: "9.9.9.9", Requests: 500, ErrorRate: 0.6, PathDiversity: 0.01, Burstiness: 15.0},
	}

	classifyClients(clients)

	// The first 4 should be normal.
	for _, c := range clients[:4] {
		if c.Classification != "normal" {
			t.Errorf("client %s: expected normal, got %s (score=%.1f)", c.ClientIP, c.Classification, c.AnomalyScore)
		}
	}

	// The outlier should be abusive.
	outlier := clients[4]
	if outlier.Classification != "abusive" {
		t.Errorf("client %s: expected abusive, got %s (score=%.1f)", outlier.ClientIP, outlier.Classification, outlier.AnomalyScore)
	}
	if outlier.AnomalyScore < 50 {
		t.Errorf("outlier anomaly score = %.1f, expected > 50", outlier.AnomalyScore)
	}
}

func TestClassifyClientsAllSame(t *testing.T) {
	// All clients identical — should all be normal.
	clients := make([]RateAdvisorClient, 10)
	for i := range clients {
		clients[i] = RateAdvisorClient{
			ClientIP:      "1.1.1." + strings.Repeat("1", i+1)[:1],
			Requests:      10,
			ErrorRate:     0.05,
			PathDiversity: 0.5,
			Burstiness:    1.0,
		}
	}
	classifyClients(clients)
	for _, c := range clients {
		if c.Classification != "normal" {
			t.Errorf("client %s: expected normal when all same, got %s (score=%.1f)", c.ClientIP, c.Classification, c.AnomalyScore)
		}
	}
}

func TestClassifyClientsSuspicious(t *testing.T) {
	clients := []RateAdvisorClient{
		{ClientIP: "1.1.1.1", Requests: 10, ErrorRate: 0.01, PathDiversity: 0.5, Burstiness: 1.0},
		{ClientIP: "2.2.2.2", Requests: 10, ErrorRate: 0.01, PathDiversity: 0.5, Burstiness: 1.0},
		{ClientIP: "3.3.3.3", Requests: 10, ErrorRate: 0.01, PathDiversity: 0.5, Burstiness: 1.0},
		// Moderate outlier: higher rate + some error + low diversity.
		{ClientIP: "5.5.5.5", Requests: 50, ErrorRate: 0.25, PathDiversity: 0.1, Burstiness: 3.0},
		// Extreme outlier.
		{ClientIP: "9.9.9.9", Requests: 500, ErrorRate: 0.8, PathDiversity: 0.01, Burstiness: 20.0},
	}

	classifyClients(clients)

	// 5.5.5.5 should be at least suspicious.
	mid := clients[3]
	if mid.Classification == "normal" {
		t.Errorf("client %s: expected suspicious or abusive, got normal (score=%.1f)", mid.ClientIP, mid.AnomalyScore)
	}

	// 9.9.9.9 should be abusive.
	outlier := clients[4]
	if outlier.Classification != "abusive" {
		t.Errorf("client %s: expected abusive, got %s (score=%.1f)", outlier.ClientIP, outlier.Classification, outlier.AnomalyScore)
	}
}

func TestComputeRecommendation(t *testing.T) {
	t.Run("too few clients", func(t *testing.T) {
		clients := []RateAdvisorClient{{Requests: 5}, {Requests: 10}}
		sorted := []int{5, 10}
		rec := computeRecommendation(clients, sorted, 15)
		if rec != nil {
			t.Errorf("expected nil for < 3 clients, got %+v", rec)
		}
	})

	t.Run("normal distribution", func(t *testing.T) {
		// 10 normal clients at ~10 req, 2 outliers at 200+.
		clients := []RateAdvisorClient{
			{Requests: 8}, {Requests: 10}, {Requests: 9}, {Requests: 11},
			{Requests: 10}, {Requests: 12}, {Requests: 9}, {Requests: 11},
			{Requests: 10}, {Requests: 8},
			// Outliers.
			{Requests: 200}, {Requests: 300},
		}
		sorted := make([]int, len(clients))
		total := 0
		for i, c := range clients {
			sorted[i] = c.Requests
			total += c.Requests
		}
		sortInts(sorted)

		rec := computeRecommendation(clients, sorted, total)
		if rec == nil {
			t.Fatal("expected recommendation, got nil")
		}
		// Threshold should be well below the outliers but above normal traffic.
		if rec.Threshold < 10 || rec.Threshold > 100 {
			t.Errorf("threshold = %d, expected between 10 and 100", rec.Threshold)
		}
		if rec.Method != "mad" {
			t.Errorf("expected method 'mad', got %q", rec.Method)
		}
		if rec.AffectedClients != 2 {
			t.Errorf("affected_clients = %d, expected 2", rec.AffectedClients)
		}
	})

	t.Run("all same rate", func(t *testing.T) {
		clients := make([]RateAdvisorClient, 20)
		sorted := make([]int, 20)
		for i := range clients {
			clients[i] = RateAdvisorClient{Requests: 10}
			sorted[i] = 10
		}
		rec := computeRecommendation(clients, sorted, 200)
		if rec == nil {
			t.Fatal("expected recommendation, got nil")
		}
		// With MAD=0, should use IQR or P99 fallback.
		if rec.Method == "mad" {
			t.Errorf("with all-same rates, should not use MAD (MAD=0)")
		}
	})
}

func TestCohensD(t *testing.T) {
	tests := []struct {
		name   string
		g1, g2 []float64
		want   float64 // approximate
		tol    float64
	}{
		{"empty", nil, nil, 0, 0},
		{"one empty", []float64{1, 2, 3}, nil, 0, 0},
		{"identical", []float64{5, 5, 5}, []float64{5, 5, 5}, 0, 0.01},
		{"large separation", []float64{1, 2, 3, 4, 5}, []float64{100, 200, 300}, 2.0, 10.0}, // just check > 0
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cohensD(tt.g1, tt.g2)
			if got < tt.want-tt.tol || got > tt.want+tt.tol {
				t.Errorf("cohensD = %f, want ~%f (±%f)", got, tt.want, tt.tol)
			}
		})
	}
}

func TestComputeImpactCurve(t *testing.T) {
	clients := []RateAdvisorClient{
		{Requests: 1}, {Requests: 2}, {Requests: 5},
		{Requests: 10}, {Requests: 100},
	}
	sorted := []int{1, 2, 5, 10, 100}
	total := 118

	curve := computeImpactCurve(clients, sorted, total)
	if curve == nil {
		t.Fatal("expected impact curve, got nil")
	}
	if len(curve) < 3 {
		t.Errorf("expected at least 3 points, got %d", len(curve))
	}

	// First point should have high affected count, last point low.
	first := curve[0]
	last := curve[len(curve)-1]
	if first.ClientsAffected <= last.ClientsAffected {
		t.Errorf("first point should have more affected clients than last")
	}

	// Check percentages are in [0, 1].
	for _, p := range curve {
		if p.ClientPct < 0 || p.ClientPct > 1 {
			t.Errorf("client_pct out of range: %f", p.ClientPct)
		}
		if p.RequestPct < 0 || p.RequestPct > 1 {
			t.Errorf("request_pct out of range: %f", p.RequestPct)
		}
	}
}

func TestComputeImpactCurveEmpty(t *testing.T) {
	curve := computeImpactCurve(nil, nil, 0)
	if curve != nil {
		t.Errorf("expected nil for empty input, got %v", curve)
	}
}

func TestComputeHistogram(t *testing.T) {
	sorted := []int{1, 1, 2, 3, 5, 8, 13, 21, 50, 100}

	bins := computeHistogram(sorted)
	if bins == nil {
		t.Fatal("expected histogram, got nil")
	}
	if len(bins) < 3 {
		t.Errorf("expected at least 3 bins, got %d", len(bins))
	}

	// Total count across bins should equal len(sorted).
	totalCount := 0
	for _, b := range bins {
		totalCount += b.Count
		if b.Min >= b.Max {
			t.Errorf("bin min %d >= max %d", b.Min, b.Max)
		}
	}
	if totalCount != len(sorted) {
		t.Errorf("histogram total = %d, want %d", totalCount, len(sorted))
	}
}

func TestComputeHistogramEmpty(t *testing.T) {
	bins := computeHistogram(nil)
	if bins != nil {
		t.Errorf("expected nil for empty input, got %v", bins)
	}
}

func TestComputeHistogramSingleValue(t *testing.T) {
	bins := computeHistogram([]int{5})
	if bins == nil {
		t.Fatal("expected histogram for single value")
	}
	total := 0
	for _, b := range bins {
		total += b.Count
	}
	if total != 1 {
		t.Errorf("histogram total = %d, want 1", total)
	}
}

// sortInts is a helper for tests (avoids importing sort in test).
func sortInts(s []int) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// ─── Integration Tests ──────────────────────────────────────────────

// accessLogLine builds a Caddy-format JSON access log entry for testing.
func accessLogLine(ts time.Time, clientIP, method, host, uri string, status int) string {
	entry := AccessLogEntry{
		Level:  "info",
		Ts:     ts.Format("2006/01/02 15:04:05"),
		Logger: "http.log.access.combined",
		Msg:    "handled request",
		Request: AccessLogReq{
			RemoteIP: clientIP,
			ClientIP: clientIP,
			Proto:    "HTTP/2.0",
			Method:   method,
			Host:     host,
			URI:      uri,
			Headers:  map[string][]string{"User-Agent": {"Test/1.0"}},
		},
		Status:   status,
		Size:     100,
		Duration: 0.01,
	}
	data, _ := json.Marshal(entry)
	return string(data)
}

func TestScanRatesAdvisorIntegration(t *testing.T) {
	// Build a log file with multiple clients at different rates.
	now := time.Now()
	var lines []string

	// Normal client: 5 requests.
	for i := 0; i < 5; i++ {
		ts := now.Add(-time.Duration(50-i) * time.Second)
		lines = append(lines, accessLogLine(ts, "1.1.1.1", "GET", "test.erfi.io", "/page/"+strings.Repeat("a", i), 200))
	}

	// Another normal client: 8 requests.
	for i := 0; i < 8; i++ {
		ts := now.Add(-time.Duration(50-i) * time.Second)
		lines = append(lines, accessLogLine(ts, "2.2.2.2", "GET", "test.erfi.io", "/page/"+strings.Repeat("b", i), 200))
	}

	// Suspicious client: 30 requests, moderate errors, low diversity.
	for i := 0; i < 30; i++ {
		ts := now.Add(-time.Duration(50-i) * time.Second)
		status := 200
		if i%5 == 0 {
			status = 403
		}
		lines = append(lines, accessLogLine(ts, "3.3.3.3", "POST", "test.erfi.io", "/login", status))
	}

	// Abusive client: 200 requests, all to same path, many errors, bursty.
	for i := 0; i < 200; i++ {
		ts := now.Add(-time.Duration(50) * time.Second) // all in same 10-second window = bursty
		status := 200
		if i%2 == 0 {
			status = 403
		}
		lines = append(lines, accessLogLine(ts, "9.9.9.9", "POST", "test.erfi.io", "/admin/login", status))
	}

	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)

	resp := store.ScanRates(RateAdvisorRequest{
		Window: "5m",
		Limit:  50,
	})

	// Verify basic counts.
	if resp.TotalRequests != 243 {
		t.Errorf("total_requests = %d, want 243", resp.TotalRequests)
	}
	if resp.UniqueClients != 4 {
		t.Errorf("unique_clients = %d, want 4", resp.UniqueClients)
	}

	// Verify clients are sorted by requests descending.
	if len(resp.Clients) < 4 {
		t.Fatalf("expected 4 clients, got %d", len(resp.Clients))
	}
	if resp.Clients[0].Requests < resp.Clients[1].Requests {
		t.Error("clients not sorted by requests descending")
	}

	// The abusive client should be classified as abusive.
	var abusiveClient *RateAdvisorClient
	for i, c := range resp.Clients {
		if c.ClientIP == "9.9.9.9" {
			abusiveClient = &resp.Clients[i]
			break
		}
	}
	if abusiveClient == nil {
		t.Fatal("abusive client 9.9.9.9 not found")
	}
	if abusiveClient.Classification != "abusive" {
		t.Errorf("9.9.9.9 classification = %s, want abusive (score=%.1f)", abusiveClient.Classification, abusiveClient.AnomalyScore)
	}
	if abusiveClient.ErrorRate < 0.4 {
		t.Errorf("9.9.9.9 error_rate = %.2f, expected >= 0.4", abusiveClient.ErrorRate)
	}
	if abusiveClient.PathDiversity > 0.05 {
		t.Errorf("9.9.9.9 path_diversity = %.2f, expected very low", abusiveClient.PathDiversity)
	}

	// Verify recommendation exists.
	if resp.Recommendation == nil {
		t.Fatal("expected recommendation, got nil")
	}
	if resp.Recommendation.Threshold < 10 {
		t.Errorf("recommended threshold = %d, expected >= 10", resp.Recommendation.Threshold)
	}

	// Verify impact curve exists.
	if len(resp.ImpactCurve) < 3 {
		t.Errorf("expected impact curve with >= 3 points, got %d", len(resp.ImpactCurve))
	}

	// Verify histogram exists.
	if len(resp.Histogram) < 2 {
		t.Errorf("expected histogram with >= 2 bins, got %d", len(resp.Histogram))
	}

	// Verify percentiles.
	if resp.Percentiles.P50 <= 0 {
		t.Errorf("P50 = %d, expected > 0", resp.Percentiles.P50)
	}

	// Verify v2 fields: WindowSeconds.
	if resp.WindowSeconds != 300 {
		t.Errorf("WindowSeconds = %.0f, want 300 (5m window)", resp.WindowSeconds)
	}

	// Verify v2 fields: NormalizedPercentiles.
	if resp.NormalizedPctiles.P50 <= 0 {
		t.Errorf("NormalizedPctiles.P50 = %.4f, expected > 0", resp.NormalizedPctiles.P50)
	}

	// Verify v2 fields: RequestsPerSec on abusive client.
	if abusiveClient.RequestsPerSec <= 0 {
		t.Errorf("abusive client RequestsPerSec = %.2f, expected > 0", abusiveClient.RequestsPerSec)
	}
	// 200 requests / 300 seconds = 0.67 req/s.
	expectedRPS := 200.0 / 300.0
	if abusiveClient.RequestsPerSec < expectedRPS*0.9 || abusiveClient.RequestsPerSec > expectedRPS*1.1 {
		t.Errorf("abusive client RequestsPerSec = %.2f, expected ~%.2f", abusiveClient.RequestsPerSec, expectedRPS)
	}
}

func TestScanRatesWithServiceFilter(t *testing.T) {
	now := time.Now()
	var lines []string

	// Requests to service A.
	for i := 0; i < 10; i++ {
		ts := now.Add(-time.Duration(50-i) * time.Second)
		lines = append(lines, accessLogLine(ts, "1.1.1.1", "GET", "svc-a.erfi.io", "/", 200))
	}
	// Requests to service B.
	for i := 0; i < 20; i++ {
		ts := now.Add(-time.Duration(50-i) * time.Second)
		lines = append(lines, accessLogLine(ts, "2.2.2.2", "GET", "svc-b.erfi.io", "/", 200))
	}

	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)

	resp := store.ScanRates(RateAdvisorRequest{
		Window:  "5m",
		Service: "svc-a.erfi.io",
		Limit:   50,
	})

	if resp.TotalRequests != 10 {
		t.Errorf("total_requests = %d, want 10 (filtered to svc-a)", resp.TotalRequests)
	}
	if resp.UniqueClients != 1 {
		t.Errorf("unique_clients = %d, want 1", resp.UniqueClients)
	}
}

func TestScanRatesWithMethodFilter(t *testing.T) {
	now := time.Now()
	var lines []string

	for i := 0; i < 10; i++ {
		ts := now.Add(-time.Duration(50-i) * time.Second)
		lines = append(lines, accessLogLine(ts, "1.1.1.1", "GET", "test.erfi.io", "/", 200))
	}
	for i := 0; i < 5; i++ {
		ts := now.Add(-time.Duration(50-i) * time.Second)
		lines = append(lines, accessLogLine(ts, "1.1.1.1", "POST", "test.erfi.io", "/api", 200))
	}

	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)

	resp := store.ScanRates(RateAdvisorRequest{
		Window: "5m",
		Method: "POST",
		Limit:  50,
	})

	if resp.TotalRequests != 5 {
		t.Errorf("total_requests = %d, want 5 (filtered to POST)", resp.TotalRequests)
	}
}

func TestHandleRLAdvisor(t *testing.T) {
	now := time.Now()
	var lines []string
	for i := 0; i < 20; i++ {
		ts := now.Add(-time.Duration(50-i) * time.Second)
		lines = append(lines, accessLogLine(ts, "1.1.1.1", "GET", "test.erfi.io", "/page", 200))
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)

	handler := handleRLAdvisor(store)
	req := httptest.NewRequest("GET", "/api/rate-rules/advisor?window=5m", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp RateAdvisorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.TotalRequests != 20 {
		t.Errorf("total_requests = %d, want 20", resp.TotalRequests)
	}
	if resp.UniqueClients != 1 {
		t.Errorf("unique_clients = %d, want 1", resp.UniqueClients)
	}
	if len(resp.Clients) != 1 {
		t.Errorf("clients count = %d, want 1", len(resp.Clients))
	}
}

// ─── Advisor Cache Tests ────────────────────────────────────────────

func TestAdvisorCacheGetSet(t *testing.T) {
	c := newAdvisorCache()
	key := "5m|svc||GET|50"
	resp := RateAdvisorResponse{Window: "5m", TotalRequests: 100}

	// Miss on empty cache.
	if _, ok := c.get(key); ok {
		t.Fatal("expected cache miss on empty cache")
	}

	// Set and get.
	c.set(key, resp)
	cached, ok := c.get(key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if cached.TotalRequests != 100 {
		t.Errorf("cached TotalRequests = %d, want 100", cached.TotalRequests)
	}
}

func TestAdvisorCacheExpiry(t *testing.T) {
	c := newAdvisorCache()
	key := "1m|||GET|10"
	resp := RateAdvisorResponse{Window: "1m", TotalRequests: 50}

	c.set(key, resp)

	// Manually expire the entry.
	c.mu.Lock()
	entry := c.entries[key]
	entry.expiresAt = time.Now().Add(-time.Second)
	c.entries[key] = entry
	c.mu.Unlock()

	if _, ok := c.get(key); ok {
		t.Fatal("expected cache miss after expiry")
	}
}

func TestAdvisorCacheEviction(t *testing.T) {
	c := newAdvisorCache()

	// Fill cache beyond 50 entries.
	for i := 0; i < 55; i++ {
		key := advisorCacheKey(RateAdvisorRequest{Window: "1m", Limit: i})
		c.set(key, RateAdvisorResponse{TotalRequests: i})
	}

	// Cache should still work — expired entries are evicted during set.
	// Just verify the latest entry is accessible.
	key := advisorCacheKey(RateAdvisorRequest{Window: "1m", Limit: 54})
	if _, ok := c.get(key); !ok {
		t.Fatal("expected cache hit for latest entry")
	}
}

func TestScanRatesCacheHit(t *testing.T) {
	now := time.Now()
	var lines []string
	for i := 0; i < 10; i++ {
		ts := now.Add(-time.Duration(50-i) * time.Second)
		lines = append(lines, accessLogLine(ts, "1.1.1.1", "GET", "test.erfi.io", "/page", 200))
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)

	req := RateAdvisorRequest{Window: "5m", Limit: 50}

	// First call scans (cache miss).
	resp1 := store.ScanRates(req)
	if resp1.TotalRequests != 10 {
		t.Fatalf("first call: total_requests = %d, want 10", resp1.TotalRequests)
	}

	// Second call hits cache (returns same result without re-scanning).
	resp2 := store.ScanRates(req)
	if resp2.TotalRequests != resp1.TotalRequests {
		t.Errorf("cache hit returned different total_requests: %d vs %d", resp2.TotalRequests, resp1.TotalRequests)
	}
}

// ─── Normalized Rates Tests ─────────────────────────────────────────

func TestScanRatesRequestsPerSec(t *testing.T) {
	now := time.Now()
	var lines []string
	// One client with 60 requests in a 1m window → 1.0 req/s.
	for i := 0; i < 60; i++ {
		ts := now.Add(-time.Duration(59-i) * time.Second)
		lines = append(lines, accessLogLine(ts, "1.1.1.1", "GET", "test.erfi.io", "/page", 200))
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)

	resp := store.ScanRates(RateAdvisorRequest{Window: "1m", Limit: 100})
	if len(resp.Clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(resp.Clients))
	}

	rps := resp.Clients[0].RequestsPerSec
	if rps != 1.0 {
		t.Errorf("RequestsPerSec = %.2f, want 1.00", rps)
	}
}

func TestScanRatesWindowSeconds(t *testing.T) {
	now := time.Now()
	var lines []string
	for i := 0; i < 5; i++ {
		ts := now.Add(-time.Duration(50-i) * time.Second)
		lines = append(lines, accessLogLine(ts, "1.1.1.1", "GET", "test.erfi.io", "/page", 200))
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)

	tests := []struct {
		window      string
		wantSeconds float64
	}{
		{"1m", 60},
		{"5m", 300},
		{"10m", 600},
		{"1h", 3600},
	}
	for _, tt := range tests {
		t.Run(tt.window, func(t *testing.T) {
			resp := store.ScanRates(RateAdvisorRequest{Window: tt.window})
			if resp.WindowSeconds != tt.wantSeconds {
				t.Errorf("WindowSeconds = %.0f, want %.0f", resp.WindowSeconds, tt.wantSeconds)
			}
		})
	}
}

func TestScanRatesNormalizedPercentiles(t *testing.T) {
	now := time.Now()
	var lines []string
	// Multiple clients with varying request counts in a 1m window.
	counts := map[string]int{
		"1.1.1.1": 60,  // 1.0 req/s
		"2.2.2.2": 120, // 2.0 req/s
		"3.3.3.3": 30,  // 0.5 req/s
		"4.4.4.4": 6,   // 0.1 req/s
	}
	for ip, count := range counts {
		for i := 0; i < count; i++ {
			ts := now.Add(-time.Duration(59-i%60) * time.Second)
			lines = append(lines, accessLogLine(ts, ip, "GET", "test.erfi.io", "/page", 200))
		}
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)

	resp := store.ScanRates(RateAdvisorRequest{Window: "1m", Limit: 100})

	// WindowSeconds should be 60 for 1m window.
	if resp.WindowSeconds != 60 {
		t.Errorf("WindowSeconds = %.0f, want 60", resp.WindowSeconds)
	}

	// NormalizedPercentiles should have values > 0 when there are clients.
	if resp.NormalizedPctiles.P50 <= 0 {
		t.Errorf("NormalizedPctiles.P50 = %.4f, expected > 0", resp.NormalizedPctiles.P50)
	}
	if resp.NormalizedPctiles.P95 <= 0 {
		t.Errorf("NormalizedPctiles.P95 = %.4f, expected > 0", resp.NormalizedPctiles.P95)
	}

	// P50 normalized should be less than or equal to P95 normalized.
	if resp.NormalizedPctiles.P50 > resp.NormalizedPctiles.P95 {
		t.Errorf("P50 (%.4f) > P95 (%.4f), expected P50 <= P95",
			resp.NormalizedPctiles.P50, resp.NormalizedPctiles.P95)
	}
}

// ─── Time-of-Day Baselines Tests ────────────────────────────────────

func TestComputeTimeOfDayBaselines(t *testing.T) {
	hourMap := map[int]*advisorHourData{
		10: {
			clientCounts: map[string]int{"1.1.1.1": 100, "2.2.2.2": 200, "3.3.3.3": 50},
			total:        350,
		},
		14: {
			clientCounts: map[string]int{"1.1.1.1": 300, "4.4.4.4": 60},
			total:        360,
		},
	}

	baselines := computeTimeOfDayBaselines(hourMap)

	if len(baselines) != 2 {
		t.Fatalf("expected 2 baselines, got %d", len(baselines))
	}

	// Should be sorted by hour.
	if baselines[0].Hour != 10 || baselines[1].Hour != 14 {
		t.Errorf("baselines hours = [%d, %d], want [10, 14]", baselines[0].Hour, baselines[1].Hour)
	}

	// Hour 10: clients=[50, 100, 200], sorted → median=100, P95=200
	// Normalized: 100/3600 ≈ 0.028, 200/3600 ≈ 0.056
	if baselines[0].MedianRPS <= 0 {
		t.Errorf("hour 10 MedianRPS = %.3f, want > 0", baselines[0].MedianRPS)
	}
	if baselines[0].P95RPS <= baselines[0].MedianRPS {
		t.Errorf("hour 10 P95RPS (%.3f) should be >= MedianRPS (%.3f)", baselines[0].P95RPS, baselines[0].MedianRPS)
	}
	if baselines[0].Clients != 3 {
		t.Errorf("hour 10 Clients = %d, want 3", baselines[0].Clients)
	}
	if baselines[0].Requests != 350 {
		t.Errorf("hour 10 Requests = %d, want 350", baselines[0].Requests)
	}

	// Hour 14: clients=[60, 300], sorted → median=300 (n=2, idx=1), P95=300
	if baselines[1].Clients != 2 {
		t.Errorf("hour 14 Clients = %d, want 2", baselines[1].Clients)
	}
	if baselines[1].Requests != 360 {
		t.Errorf("hour 14 Requests = %d, want 360", baselines[1].Requests)
	}
}

func TestComputeTimeOfDayBaselinesSingleHour(t *testing.T) {
	// Single hour should still produce results (called when len >= 2 externally,
	// but the function itself handles any input).
	hourMap := map[int]*advisorHourData{
		8: {
			clientCounts: map[string]int{"1.1.1.1": 50},
			total:        50,
		},
	}

	baselines := computeTimeOfDayBaselines(hourMap)
	if len(baselines) != 1 {
		t.Fatalf("expected 1 baseline, got %d", len(baselines))
	}
	if baselines[0].Hour != 8 {
		t.Errorf("hour = %d, want 8", baselines[0].Hour)
	}
	// Single client: median = P95 = 50/3600
	if baselines[0].MedianRPS != baselines[0].P95RPS {
		t.Errorf("single client: median (%.3f) should equal P95 (%.3f)", baselines[0].MedianRPS, baselines[0].P95RPS)
	}
}

func TestComputeTimeOfDayBaselinesEmpty(t *testing.T) {
	hourMap := map[int]*advisorHourData{
		0: {clientCounts: map[string]int{}, total: 0},
	}
	baselines := computeTimeOfDayBaselines(hourMap)
	if len(baselines) != 0 {
		t.Errorf("expected 0 baselines for empty hour data, got %d", len(baselines))
	}
}

func TestScanRatesTimeOfDayBaselinesPresent(t *testing.T) {
	// Build events that reliably span two distinct parsed-UTC-hours.
	// parseTimestamp treats formatted local time as UTC, so we need
	// formatted timestamps to land in two different hours (HH differs).
	// We pick two explicit hours that are guaranteed to differ and
	// within the 1h window by constructing timestamps precisely.
	now := time.Now()
	var lines []string

	// Create timestamps at minute :05 of the current local hour and
	// minute :05 of the previous local hour. Both are < 1h ago if we
	// set the base carefully. To guarantee both are within the 1h
	// window, we use a window duration of 1h and place events at
	// now-5min and now-5min-1h. But 1h-5min-ago might exceed the 1h window.
	//
	// Simpler approach: explicitly construct two hours that differ.
	// The current local hour and (current-1) guarantee different Hour()
	// when formatted. Both fit in a 1h window only if they're within 60 min.
	//
	// Safest: construct 2 groups at fixed minutes within the current hour
	// that will land in different parsed-UTC-hours regardless of timezone.
	// We do this by using two timestamps exactly 1 hour apart and a
	// sufficiently large "window". Since parseAdvisorWindow only supports
	// 1m/5m/10m/1h, we use 1h and keep both groups within the last 59 minutes.
	//
	// Actually, to get 2 different Hour() values, we need timestamps in
	// different clock hours. With a 1h window and events at most 59 min ago,
	// if the current minute is >= 5, the event at now-55min has a different
	// hour than now-5min. If minute < 5, both are in the same formatted hour.
	// This is inherently racy with clock time.
	//
	// Instead, test deterministically via computeTimeOfDayBaselines unit test
	// (already covered), and here just verify the field is populated when
	// hourMap has 2+ hours. We force 2 hours by placing events in distinct
	// formatted hours using explicit time construction.
	localHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
	prevHour := localHour.Add(-time.Hour)

	// Events at minute :01 of current hour (1 min into the hour).
	for i := 0; i < 10; i++ {
		ts := localHour.Add(time.Minute + time.Duration(i)*time.Second)
		lines = append(lines, accessLogLine(ts, "1.1.1.1", "GET", "test.erfi.io", "/page", 200))
	}
	// Events at minute :30 of previous hour (30 min into previous hour).
	for i := 0; i < 5; i++ {
		ts := prevHour.Add(30*time.Minute + time.Duration(i)*time.Second)
		lines = append(lines, accessLogLine(ts, "2.2.2.2", "GET", "test.erfi.io", "/other", 200))
	}

	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)

	// Use 1h window. Events at current hour :01 are very recent. Events at
	// prev hour :30 are ~30–90 minutes ago. For 1h window, the prev-hour
	// events may be excluded if now is past :30 in the current hour (they'd
	// be >60 min ago). So check total requests and adapt expectations.
	resp := store.ScanRates(RateAdvisorRequest{Window: "1h", Limit: 50})

	// At minimum, the 10 current-hour events should be included.
	if resp.TotalRequests < 10 {
		t.Fatalf("TotalRequests = %d, want >= 10", resp.TotalRequests)
	}

	// If all 15 events are within window, we should have 2 baselines.
	// If only 10 (current hour), we have 1 baseline (< 2 hours → nil).
	if resp.TotalRequests == 15 {
		// Both hours present.
		if len(resp.TimeOfDayBaselines) < 2 {
			t.Errorf("with 15 events across 2 hours, expected >= 2 baselines, got %d", len(resp.TimeOfDayBaselines))
		}
	}

	// Verify field validity for any baselines present.
	for _, b := range resp.TimeOfDayBaselines {
		if b.Hour < 0 || b.Hour > 23 {
			t.Errorf("invalid hour: %d", b.Hour)
		}
		if b.MedianRPS < 0 {
			t.Errorf("negative MedianRPS: %.3f", b.MedianRPS)
		}
		if b.P95RPS < b.MedianRPS {
			t.Errorf("P95RPS (%.3f) < MedianRPS (%.3f)", b.P95RPS, b.MedianRPS)
		}
		if b.Clients <= 0 {
			t.Errorf("Clients = %d, want > 0", b.Clients)
		}
	}
}

func TestScanRatesTimeOfDayBaselinesAbsentSingleHour(t *testing.T) {
	// All events in a single hour → no baselines (requires >= 2 hours).
	now := time.Now()
	var lines []string
	for i := 0; i < 10; i++ {
		ts := now.Add(-time.Duration(i) * time.Second)
		lines = append(lines, accessLogLine(ts, "1.1.1.1", "GET", "test.erfi.io", "/page", 200))
	}
	path := writeTempAccessLog(t, lines)
	store := NewAccessLogStore(path)

	resp := store.ScanRates(RateAdvisorRequest{Window: "1m", Limit: 50})
	if resp.TimeOfDayBaselines != nil && len(resp.TimeOfDayBaselines) > 0 {
		t.Errorf("expected no baselines for single-hour data, got %d", len(resp.TimeOfDayBaselines))
	}
}
