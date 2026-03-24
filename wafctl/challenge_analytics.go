package main

import (
	"net/http"
	"sort"
	"strconv"
)

// ─── Challenge Analytics ────────────────────────────────────────────
//
// Aggregates challenge events (issued/passed/failed/bypassed) into a
// stats response with funnel metrics, bot score distribution, top
// challenged clients, and top challenged services.

// ChallengeStatsResponse is the response for GET /api/challenge/stats.
type ChallengeStatsResponse struct {
	// Funnel — total counts for each challenge outcome.
	Issued   int `json:"issued"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Bypassed int `json:"bypassed"`

	// Rates — derived from funnel counts (0.0 - 1.0).
	PassRate   float64 `json:"pass_rate"`   // passed / issued
	FailRate   float64 `json:"fail_rate"`   // failed / issued
	BypassRate float64 `json:"bypass_rate"` // bypassed / (passed + bypassed)

	// Bot score distribution — counts per bucket.
	ScoreBuckets []ScoreBucket `json:"score_buckets"`

	// Hourly challenge timeline.
	Timeline []ChallengeHour `json:"timeline"`

	// Top challenged clients (by total challenge events, max 20).
	TopClients []ChallengeClient `json:"top_clients"`

	// Top challenged services (by total challenge events, max 20).
	TopServices []ChallengeService `json:"top_services"`
}

// ScoreBucket is a bot score histogram bucket.
type ScoreBucket struct {
	Label string `json:"label"` // e.g. "0-19", "20-39", "70+"
	Min   int    `json:"min"`
	Max   int    `json:"max"`
	Count int    `json:"count"`
}

// ChallengeHour is a per-hour breakdown of challenge events.
type ChallengeHour struct {
	Hour     string `json:"hour"`
	Issued   int    `json:"issued"`
	Passed   int    `json:"passed"`
	Failed   int    `json:"failed"`
	Bypassed int    `json:"bypassed"`
}

// ChallengeClient is a per-client breakdown.
type ChallengeClient struct {
	Client      string  `json:"client"`
	Country     string  `json:"country,omitempty"`
	Issued      int     `json:"issued"`
	Passed      int     `json:"passed"`
	Failed      int     `json:"failed"`
	Bypassed    int     `json:"bypassed"`
	AvgBotScore float64 `json:"avg_bot_score"`
	MaxBotScore int     `json:"max_bot_score"`
}

// ChallengeService is a per-service breakdown.
type ChallengeService struct {
	Service  string `json:"service"`
	Issued   int    `json:"issued"`
	Passed   int    `json:"passed"`
	Failed   int    `json:"failed"`
	Bypassed int    `json:"bypassed"`
}

// ChallengeStats aggregates challenge analytics from the event store.
func (s *AccessLogStore) ChallengeStats(hours int) ChallengeStatsResponse {
	events := s.snapshotSince(hours)

	var resp ChallengeStatsResponse

	// Bot score histogram buckets.
	buckets := []ScoreBucket{
		{Label: "0-19 (clean)", Min: 0, Max: 19},
		{Label: "20-39 (moderate)", Min: 20, Max: 39},
		{Label: "40-59 (suspicious)", Min: 40, Max: 59},
		{Label: "60-69 (borderline)", Min: 60, Max: 69},
		{Label: "70-79 (rejected)", Min: 70, Max: 79},
		{Label: "80-100 (automated)", Min: 80, Max: 100},
	}

	hourMap := make(map[string]*ChallengeHour)

	type clientAgg struct {
		country    string
		issued     int
		passed     int
		failed     int
		bypassed   int
		scoreSum   int
		scoreCount int
		maxScore   int
	}
	clientMap := make(map[string]*clientAgg)

	type serviceAgg struct {
		issued   int
		passed   int
		failed   int
		bypassed int
	}
	serviceMap := make(map[string]*serviceAgg)

	for _, e := range events {
		src := e.Source
		isChallengeEvent := src == "challenge_issued" || src == "challenge_passed" ||
			src == "challenge_failed" || src == "challenge_bypassed"
		if !isChallengeEvent {
			continue
		}

		// Funnel
		switch src {
		case "challenge_issued":
			resp.Issued++
		case "challenge_passed":
			resp.Passed++
		case "challenge_failed":
			resp.Failed++
		case "challenge_bypassed":
			resp.Bypassed++
		}

		// Bot score distribution (only on passed/failed — these have scores).
		if (src == "challenge_passed" || src == "challenge_failed") && e.ChallengeBotScore >= 0 {
			for i := range buckets {
				if e.ChallengeBotScore >= buckets[i].Min && e.ChallengeBotScore <= buckets[i].Max {
					buckets[i].Count++
					break
				}
			}
		}

		// Hourly timeline
		hourKey := e.Timestamp.UTC().Format("2006-01-02T15:00:00Z")
		h, ok := hourMap[hourKey]
		if !ok {
			h = &ChallengeHour{Hour: hourKey}
			hourMap[hourKey] = h
		}
		switch src {
		case "challenge_issued":
			h.Issued++
		case "challenge_passed":
			h.Passed++
		case "challenge_failed":
			h.Failed++
		case "challenge_bypassed":
			h.Bypassed++
		}

		// Per-client
		ca, ok := clientMap[e.ClientIP]
		if !ok {
			ca = &clientAgg{country: e.Country}
			clientMap[e.ClientIP] = ca
		}
		switch src {
		case "challenge_issued":
			ca.issued++
		case "challenge_passed":
			ca.passed++
		case "challenge_failed":
			ca.failed++
		case "challenge_bypassed":
			ca.bypassed++
		}
		if (src == "challenge_passed" || src == "challenge_failed") && e.ChallengeBotScore > 0 {
			ca.scoreSum += e.ChallengeBotScore
			ca.scoreCount++
			if e.ChallengeBotScore > ca.maxScore {
				ca.maxScore = e.ChallengeBotScore
			}
		}

		// Per-service
		sa, ok := serviceMap[e.Service]
		if !ok {
			sa = &serviceAgg{}
			serviceMap[e.Service] = sa
		}
		switch src {
		case "challenge_issued":
			sa.issued++
		case "challenge_passed":
			sa.passed++
		case "challenge_failed":
			sa.failed++
		case "challenge_bypassed":
			sa.bypassed++
		}
	}

	// Compute rates.
	if resp.Issued > 0 {
		resp.PassRate = float64(resp.Passed) / float64(resp.Issued)
		resp.FailRate = float64(resp.Failed) / float64(resp.Issued)
	}
	totalSolved := resp.Passed + resp.Bypassed
	if totalSolved > 0 {
		resp.BypassRate = float64(resp.Bypassed) / float64(totalSolved)
	}

	resp.ScoreBuckets = buckets

	// Sort timeline by hour.
	timeline := make([]ChallengeHour, 0, len(hourMap))
	for _, h := range hourMap {
		timeline = append(timeline, *h)
	}
	sort.Slice(timeline, func(i, j int) bool { return timeline[i].Hour < timeline[j].Hour })
	resp.Timeline = timeline

	// Top clients — sort by total events descending, limit 20.
	clients := make([]ChallengeClient, 0, len(clientMap))
	for ip, ca := range clientMap {
		cc := ChallengeClient{
			Client:      ip,
			Country:     ca.country,
			Issued:      ca.issued,
			Passed:      ca.passed,
			Failed:      ca.failed,
			Bypassed:    ca.bypassed,
			MaxBotScore: ca.maxScore,
		}
		if ca.scoreCount > 0 {
			cc.AvgBotScore = float64(ca.scoreSum) / float64(ca.scoreCount)
		}
		clients = append(clients, cc)
	}
	sort.Slice(clients, func(i, j int) bool {
		ti := clients[i].Issued + clients[i].Passed + clients[i].Failed + clients[i].Bypassed
		tj := clients[j].Issued + clients[j].Passed + clients[j].Failed + clients[j].Bypassed
		return ti > tj
	})
	if len(clients) > 20 {
		clients = clients[:20]
	}
	resp.TopClients = clients

	// Top services — sort by total events descending, limit 20.
	services := make([]ChallengeService, 0, len(serviceMap))
	for svc, sa := range serviceMap {
		services = append(services, ChallengeService{
			Service:  svc,
			Issued:   sa.issued,
			Passed:   sa.passed,
			Failed:   sa.failed,
			Bypassed: sa.bypassed,
		})
	}
	sort.Slice(services, func(i, j int) bool {
		ti := services[i].Issued + services[i].Passed + services[i].Failed + services[i].Bypassed
		tj := services[j].Issued + services[j].Passed + services[j].Failed + services[j].Bypassed
		return ti > tj
	})
	if len(services) > 20 {
		services = services[:20]
	}
	resp.TopServices = services

	return resp
}

// handleChallengeStats serves GET /api/challenge/stats?hours=24.
func handleChallengeStats(als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if v, err := strconv.Atoi(h); err == nil && v > 0 {
				hours = v
			}
		}
		stats := als.ChallengeStats(hours)
		writeJSON(w, http.StatusOK, stats)
	}
}
