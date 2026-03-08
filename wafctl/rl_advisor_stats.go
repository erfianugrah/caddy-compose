package main

import (
	"math"
	"sort"
)

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
