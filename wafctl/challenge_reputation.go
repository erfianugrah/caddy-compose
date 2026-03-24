package main

import (
	"net/http"
	"sort"
	"strconv"
	"time"
)

// ─── Challenge Reputation ───────────────────────────────────────────
//
// Builds reputation data from challenge results: JA4 verdicts, IP
// challenge history with flags, and cookie harvesting detection.

// ChallengeReputationResponse is the response for GET /api/challenge/reputation.
type ChallengeReputationResponse struct {
	JA4s         []JA4Reputation      `json:"ja4s"`
	Clients      []IPChallengeHistory `json:"clients"`
	Alerts       []ReputationAlert    `json:"alerts,omitempty"`
	TotalJA4s    int                  `json:"total_ja4s"`
	TotalClients int                  `json:"total_clients"`
	TotalAlerts  int                  `json:"total_alerts"`
}

// JA4Reputation is the per-JA4 challenge verdict.
type JA4Reputation struct {
	JA4         string  `json:"ja4"`
	TotalEvents int     `json:"total_events"`
	Passed      int     `json:"passed"`
	Failed      int     `json:"failed"`
	PassRate    float64 `json:"pass_rate"`
	FailRate    float64 `json:"fail_rate"`
	AvgBotScore float64 `json:"avg_bot_score"`
	UniqueIPs   int     `json:"unique_ips"`
	FirstSeen   string  `json:"first_seen"`
	LastSeen    string  `json:"last_seen"`
	Verdict     string  `json:"verdict"` // "trusted", "suspicious", "hostile"
}

// IPChallengeHistory is the per-IP challenge breakdown with flags.
type IPChallengeHistory struct {
	IP           string   `json:"ip"`
	Country      string   `json:"country,omitempty"`
	Issued       int      `json:"issued"`
	Passed       int      `json:"passed"`
	Failed       int      `json:"failed"`
	Bypassed     int      `json:"bypassed"`
	UniqueTokens int      `json:"unique_tokens"`
	UniqueJA4s   int      `json:"unique_ja4s"`
	AvgBotScore  float64  `json:"avg_bot_score"`
	MaxBotScore  int      `json:"max_bot_score"`
	AvgSolveMs   float64  `json:"avg_solve_ms"`
	FirstSeen    string   `json:"first_seen"`
	LastSeen     string   `json:"last_seen"`
	Flags        []string `json:"flags,omitempty"`
}

// ReputationAlert is a flagged pattern requiring operator attention.
type ReputationAlert struct {
	Type     string `json:"type"`     // "cookie_harvesting", "repeat_failure", "ja4_rotation", "hostile_ja4"
	Target   string `json:"target"`   // IP or JA4 fingerprint
	Detail   string `json:"detail"`   // human-readable description
	Count    int    `json:"count"`    // relevant count (tokens, failures, etc.)
	Severity string `json:"severity"` // "high", "medium", "low"
}

// ChallengeReputation builds reputation data from challenge events.
func (s *AccessLogStore) ChallengeReputation(hours int, filterService string) ChallengeReputationResponse {
	events := s.snapshotSince(hours)

	type ja4Agg struct {
		total     int
		passed    int
		failed    int
		scoreSum  int
		scoreN    int
		ips       map[string]struct{}
		firstSeen time.Time
		lastSeen  time.Time
	}
	ja4Map := make(map[string]*ja4Agg)

	type ipAgg struct {
		country   string
		issued    int
		passed    int
		failed    int
		bypassed  int
		scoreSum  int
		scoreN    int
		maxScore  int
		solveSum  int
		solveN    int
		tokens    map[string]struct{}
		ja4s      map[string]struct{}
		firstSeen time.Time
		lastSeen  time.Time
	}
	ipMap := make(map[string]*ipAgg)

	for _, e := range events {
		src := e.Source
		isChallenge := src == "challenge_issued" || src == "challenge_passed" ||
			src == "challenge_failed" || src == "challenge_bypassed"
		if !isChallenge {
			continue
		}
		if filterService != "" && e.Service != filterService {
			continue
		}

		ts := e.Timestamp

		// JA4 aggregation
		if e.JA4 != "" && (src == "challenge_passed" || src == "challenge_failed") {
			ja, ok := ja4Map[e.JA4]
			if !ok {
				ja = &ja4Agg{ips: make(map[string]struct{}), firstSeen: ts, lastSeen: ts}
				ja4Map[e.JA4] = ja
			}
			ja.total++
			if src == "challenge_passed" {
				ja.passed++
			} else {
				ja.failed++
			}
			if e.ChallengeBotScore > 0 {
				ja.scoreSum += e.ChallengeBotScore
				ja.scoreN++
			}
			ja.ips[e.ClientIP] = struct{}{}
			if ts.Before(ja.firstSeen) {
				ja.firstSeen = ts
			}
			if ts.After(ja.lastSeen) {
				ja.lastSeen = ts
			}
		}

		// IP aggregation
		ip, ok := ipMap[e.ClientIP]
		if !ok {
			ip = &ipAgg{
				country:   e.Country,
				tokens:    make(map[string]struct{}),
				ja4s:      make(map[string]struct{}),
				firstSeen: ts,
				lastSeen:  ts,
			}
			ipMap[e.ClientIP] = ip
		}
		switch src {
		case "challenge_issued":
			ip.issued++
		case "challenge_passed":
			ip.passed++
		case "challenge_failed":
			ip.failed++
		case "challenge_bypassed":
			ip.bypassed++
		}
		if e.ChallengeBotScore > 0 {
			ip.scoreSum += e.ChallengeBotScore
			ip.scoreN++
			if e.ChallengeBotScore > ip.maxScore {
				ip.maxScore = e.ChallengeBotScore
			}
		}
		if e.ChallengeElapsedMs > 0 {
			ip.solveSum += e.ChallengeElapsedMs
			ip.solveN++
		}
		if e.ChallengeJTI != "" {
			ip.tokens[e.ChallengeJTI] = struct{}{}
		}
		if e.JA4 != "" {
			ip.ja4s[e.JA4] = struct{}{}
		}
		if ts.Before(ip.firstSeen) {
			ip.firstSeen = ts
		}
		if ts.After(ip.lastSeen) {
			ip.lastSeen = ts
		}
	}

	// Build JA4 reputation list.
	ja4s := make([]JA4Reputation, 0, len(ja4Map))
	for fp, ja := range ja4Map {
		scored := ja.passed + ja.failed
		jr := JA4Reputation{
			JA4:         fp,
			TotalEvents: ja.total,
			Passed:      ja.passed,
			Failed:      ja.failed,
			UniqueIPs:   len(ja.ips),
			FirstSeen:   ja.firstSeen.UTC().Format(time.RFC3339),
			LastSeen:    ja.lastSeen.UTC().Format(time.RFC3339),
		}
		if scored > 0 {
			jr.PassRate = float64(ja.passed) / float64(scored)
			jr.FailRate = float64(ja.failed) / float64(scored)
		}
		if ja.scoreN > 0 {
			jr.AvgBotScore = float64(ja.scoreSum) / float64(ja.scoreN)
		}
		// Verdict logic.
		if jr.FailRate >= 0.8 && ja.total >= 5 {
			jr.Verdict = "hostile"
		} else if jr.FailRate >= 0.3 || jr.AvgBotScore >= 50 {
			jr.Verdict = "suspicious"
		} else {
			jr.Verdict = "trusted"
		}
		ja4s = append(ja4s, jr)
	}
	sort.Slice(ja4s, func(i, j int) bool { return ja4s[i].TotalEvents > ja4s[j].TotalEvents })
	if len(ja4s) > 30 {
		ja4s = ja4s[:30]
	}

	// Build IP history list + detect flags.
	var alerts []ReputationAlert
	clients := make([]IPChallengeHistory, 0, len(ipMap))
	for addr, ip := range ipMap {
		ch := IPChallengeHistory{
			IP:           addr,
			Country:      ip.country,
			Issued:       ip.issued,
			Passed:       ip.passed,
			Failed:       ip.failed,
			Bypassed:     ip.bypassed,
			UniqueTokens: len(ip.tokens),
			UniqueJA4s:   len(ip.ja4s),
			MaxBotScore:  ip.maxScore,
			FirstSeen:    ip.firstSeen.UTC().Format(time.RFC3339),
			LastSeen:     ip.lastSeen.UTC().Format(time.RFC3339),
		}
		if ip.scoreN > 0 {
			ch.AvgBotScore = float64(ip.scoreSum) / float64(ip.scoreN)
		}
		if ip.solveN > 0 {
			ch.AvgSolveMs = float64(ip.solveSum) / float64(ip.solveN)
		}

		// Flag detection.
		if ip.failed > 3 {
			ch.Flags = append(ch.Flags, "repeat_failure")
			alerts = append(alerts, ReputationAlert{
				Type:     "repeat_failure",
				Target:   addr,
				Detail:   addr + " failed " + strconv.Itoa(ip.failed) + " challenges",
				Count:    ip.failed,
				Severity: "high",
			})
		}
		if len(ip.tokens) > 5 {
			ch.Flags = append(ch.Flags, "cookie_harvesting")
			alerts = append(alerts, ReputationAlert{
				Type:     "cookie_harvesting",
				Target:   addr,
				Detail:   addr + " solved " + strconv.Itoa(len(ip.tokens)) + " unique tokens (possible cookie farming)",
				Count:    len(ip.tokens),
				Severity: "high",
			})
		}
		if len(ip.ja4s) > 3 {
			ch.Flags = append(ch.Flags, "ja4_rotation")
			alerts = append(alerts, ReputationAlert{
				Type:     "ja4_rotation",
				Target:   addr,
				Detail:   addr + " used " + strconv.Itoa(len(ip.ja4s)) + " different TLS stacks (JA4 rotation)",
				Count:    len(ip.ja4s),
				Severity: "medium",
			})
		}

		clients = append(clients, ch)
	}

	// Sort clients by total events descending.
	sort.Slice(clients, func(i, j int) bool {
		ti := clients[i].Issued + clients[i].Passed + clients[i].Failed + clients[i].Bypassed
		tj := clients[j].Issued + clients[j].Passed + clients[j].Failed + clients[j].Bypassed
		return ti > tj
	})
	if len(clients) > 30 {
		clients = clients[:30]
	}

	// Add hostile JA4 alerts.
	for _, ja := range ja4s {
		if ja.Verdict == "hostile" {
			alerts = append(alerts, ReputationAlert{
				Type:     "hostile_ja4",
				Target:   ja.JA4,
				Detail:   "JA4 " + ja.JA4[:min(24, len(ja.JA4))] + "... has " + strconv.Itoa(int(ja.FailRate*100)) + "% fail rate across " + strconv.Itoa(ja.TotalEvents) + " events",
				Count:    ja.Failed,
				Severity: "high",
			})
		}
	}

	// Sort alerts by severity (high first).
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].Severity != alerts[j].Severity {
			return alerts[i].Severity == "high"
		}
		return alerts[i].Count > alerts[j].Count
	})

	return ChallengeReputationResponse{
		JA4s:         ja4s,
		Clients:      clients,
		Alerts:       alerts,
		TotalJA4s:    len(ja4Map),
		TotalClients: len(ipMap),
		TotalAlerts:  len(alerts),
	}
}

// handleChallengeReputation serves GET /api/challenge/reputation?hours=24&service=x.
func handleChallengeReputation(als *AccessLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if v, err := strconv.Atoi(h); err == nil && v > 0 {
				hours = v
			}
		}
		service := r.URL.Query().Get("service")
		resp := als.ChallengeReputation(hours, service)
		writeJSON(w, http.StatusOK, resp)
	}
}
