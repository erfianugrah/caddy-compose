# Challenge Platform — Next Phase Plan

Work plan for challenge-informed reputation, endpoint discovery, and data
pipeline improvements. Implementation order is by dependency, not priority.

---

## Phase 1: Data Pipeline (plugin + wafctl)

**Goal:** Log challenge-specific fields to the access log so wafctl can
aggregate them. Currently `elapsed_ms` and the adaptively-selected difficulty
are validated server-side but never persisted.

### Plugin changes (caddy-policy-engine)

| File | Change |
|------|--------|
| `challenge.go` `serveChallengeInterstitial()` | Set `policy_engine.challenge_difficulty` Caddy variable to the selected difficulty (after `selectDifficulty()` runs). This makes the *actual* difficulty served visible in the access log. |
| `challenge.go` `handleChallengeVerify()` | Set `policy_engine.challenge_elapsed_ms` Caddy variable to the parsed `elapsed_ms` value. Already parsed but never stored. |
| `challenge.go` `handleChallengeVerify()` | Set `policy_engine.challenge_pre_score` to the `preSignalScore(r)` at verify time. This is the L1/L2/L5 passive score that drove the difficulty selection. |

All three are `caddyhttp.SetVar()` calls — minimal code. They flow into the
access log via the existing `log_append` Caddyfile directive which captures
all `policy_engine.*` variables.

### Caddyfile changes (caddy-compose)

No changes needed — `log_append` already captures all `policy_engine.*`
variables generically. The new variables appear in logs automatically.

### wafctl changes (caddy-compose/wafctl)

| File | Change |
|------|--------|
| `access_log_store.go` `AccessLogEntry` | Add `ChallengeDifficulty string`, `ChallengeElapsedMs string`, `ChallengePreScore string` fields with JSON tags matching the log field names (`policy_challenge_difficulty`, etc.). |
| `access_log_store.go` `RateLimitEvent` | Add `ChallengeDifficulty int`, `ChallengeElapsedMs int`, `ChallengePreScore int` fields. |
| `access_log_store.go` `Load()` | Parse and propagate the three new fields from `AccessLogEntry` to `RateLimitEvent` (same pattern as `ChallengeBotScore`). |
| `access_log_store.go` `RateLimitEventToEvent()` | Propagate to `Event` struct for the events API. |
| `models.go` `Event` | Add `ChallengeDifficulty int`, `ChallengeElapsedMs int`, `ChallengePreScore int` fields. |

### Frontend changes (waf-dashboard)

| File | Change |
|------|--------|
| `waf-events.ts` `WAFEvent` | Add `challenge_difficulty?`, `challenge_elapsed_ms?`, `challenge_pre_score?` fields. |
| `waf-events.ts` `RawEvent` | Same fields. |
| `waf-events.ts` `mapEvent()` | Propagate. |
| `EventDetailPanel.tsx` | Show difficulty and solve time in challenge event details. |

### Challenge analytics enrichment (wafctl)

| File | Change |
|------|--------|
| `challenge_analytics.go` `ChallengeStatsResponse` | Add `AvgSolveMs float64`, `AvgDifficulty float64` to funnel stats. |
| `challenge_analytics.go` `ChallengeClient` | Add `AvgSolveMs float64` per client. |
| `challenge_analytics.go` `ChallengeStats()` | Accumulate elapsed_ms and difficulty in the aggregation loop. |

### Tests

- Plugin unit: verify the three variables are set after `serveChallengeInterstitial` and `handleChallengeVerify`.
- E2E: verify new fields appear in `/api/events` response for challenge events.
- Dashboard: verify event detail panel shows difficulty and solve time.

### Versioning

- Tag plugin as v0.26.1 (or v0.27.0 if scope grows).
- Update Dockerfile `xcaddy build` line.

---

## Phase 2: Endpoint Discovery (wafctl + dashboard, no plugin changes)

**Goal:** Show operators their API surface, which paths have traffic, which
are covered by challenge rules, and which have suspicious traffic patterns
that suggest they should be challenged.

### Backend — new file `wafctl/endpoint_discovery.go`

**Endpoint:** `GET /api/discovery/endpoints?hours=24&service=x`

Scans `RateLimitEvent` store (same as challenge analytics) and aggregates
by `(service, method, path)` tuple. For each endpoint:

```go
type DiscoveredEndpoint struct {
    Service       string  `json:"service"`
    Method        string  `json:"method"`
    Path          string  `json:"path"`            // normalized (query stripped, IDs collapsed)
    Requests      int     `json:"requests"`
    UniqueIPs     int     `json:"unique_ips"`
    UniqueJA4s    int     `json:"unique_ja4s"`
    UniqueUAs     int     `json:"unique_uas"`
    NonBrowserPct float64 `json:"non_browser_pct"` // % of requests with non-browser JA4
    HasChallenge  bool    `json:"has_challenge"`   // covered by an existing challenge rule
    HasRateLimit  bool    `json:"has_rate_limit"`  // covered by a rate limit rule
    TopJA4        string  `json:"top_ja4,omitempty"` // most common JA4 fingerprint
    StatusCodes   map[int]int `json:"status_codes,omitempty"` // 200: N, 403: M, etc.
}
```

**Path normalization:** Collapse numeric/UUID path segments into `{id}` to
group `/users/123` and `/users/456` into `/users/{id}`. This prevents the
endpoint list from exploding.

**Non-browser detection:** Parse JA4 `a` section — check ALPN (position 8:10).
`00` or `h1` = non-browser. Also check: missing `Accept-Language` header in
the request implies non-interactive client. The `non_browser_pct` is computed
from the JA4 ALPN check.

**Challenge rule coverage:** The handler receives the `ExclusionStore` and
checks each endpoint's `(service, path)` against existing challenge rules'
conditions. If any challenge rule's conditions would match the path, mark
`has_challenge = true`. Same for rate limit rules.

**Response:**
```go
type EndpointDiscoveryResponse struct {
    Endpoints     []DiscoveredEndpoint `json:"endpoints"`
    TotalRequests int                  `json:"total_requests"`
    TotalPaths    int                  `json:"total_paths"`
    UncoveredPct  float64             `json:"uncovered_pct"` // % of traffic on paths without challenge rules
}
```

Sorted by `requests` descending, limited to top 100 endpoints.

### Route registration

`main.go`: `mux.HandleFunc("GET /api/discovery/endpoints", handleEndpointDiscovery(accessLogStore, exclusionStore))`

### Frontend — new component or tab

**Option A:** Tab on the Challenge Analytics page.
**Option B:** Standalone `/discovery` page.

Recommend **Option A** — it's contextually related ("what should I challenge?")
and avoids yet another nav entry.

**UI components:**

1. **Endpoint table** — sortable by requests, non-browser %, coverage status.
   Columns: Service, Method, Path, Requests, Unique IPs, Unique JA4s,
   Non-Browser %, Coverage (challenge/rate-limit/none), Top JA4.

2. **Coverage indicator** — green shield = challenge rule covers it,
   blue shield = rate limit, red circle = no protection.

3. **Quick action button** — "Create Challenge Rule" pre-fills a challenge
   rule with the path and service from the selected endpoint. Opens the
   Policy Engine create form with conditions pre-populated.

4. **Filters** — service dropdown, method dropdown, "uncovered only" toggle,
   "high non-browser traffic" toggle (>20% non-browser).

5. **Summary bar** — "N endpoints discovered, M uncovered, X% of traffic
   unprotected."

### Frontend API

```typescript
// src/lib/api/challenge.ts (extend existing)
export interface DiscoveredEndpoint {
  service: string;
  method: string;
  path: string;
  requests: number;
  unique_ips: number;
  unique_ja4s: number;
  unique_uas: number;
  non_browser_pct: number;
  has_challenge: boolean;
  has_rate_limit: boolean;
  top_ja4?: string;
  status_codes?: Record<number, number>;
}

export interface EndpointDiscoveryResponse {
  endpoints: DiscoveredEndpoint[];
  total_requests: number;
  total_paths: number;
  uncovered_pct: number;
}

export async function fetchEndpointDiscovery(
  hours?: number, service?: string
): Promise<EndpointDiscoveryResponse> { ... }
```

### Tests

- E2E: hit several paths, then call `/api/discovery/endpoints` and verify
  the paths appear with correct counts.
- E2E: create a challenge rule, verify the matching endpoint shows
  `has_challenge: true`.
- Playwright: verify the endpoint table renders, quick-action button exists.

---

## Phase 3: Challenge Reputation (wafctl + dashboard, no plugin changes)

**Goal:** Build reputation data from challenge results so operators can
identify and act on bot JA4 fingerprints, repeat-offender IPs, and
cookie harvesting patterns.

### Backend — new file `wafctl/challenge_reputation.go`

**Endpoint:** `GET /api/challenge/reputation?hours=24`

Scans challenge events and builds three reputation tables:

#### 3a. JA4 Reputation

```go
type JA4Reputation struct {
    JA4          string  `json:"ja4"`
    TotalEvents  int     `json:"total_events"`
    Passed       int     `json:"passed"`
    Failed       int     `json:"failed"`
    PassRate     float64 `json:"pass_rate"`
    AvgBotScore  float64 `json:"avg_bot_score"`
    UniqueIPs    int     `json:"unique_ips"`
    FirstSeen    string  `json:"first_seen"`
    LastSeen     string  `json:"last_seen"`
    Verdict      string  `json:"verdict"` // "trusted", "suspicious", "hostile"
}
```

**Verdict logic:**
- `fail_rate >= 0.8 && total >= 5` → "hostile"
- `fail_rate >= 0.3 || avg_bot_score >= 50` → "suspicious"
- else → "trusted"

**Actionable:** "Block this JA4" button creates a block rule with
`ja4 eq <fingerprint>` condition. "Challenge this JA4" creates a
challenge rule.

#### 3b. IP Challenge History

```go
type IPChallengeHistory struct {
    IP             string  `json:"ip"`
    Country        string  `json:"country,omitempty"`
    Issued         int     `json:"issued"`
    Passed         int     `json:"passed"`
    Failed         int     `json:"failed"`
    Bypassed       int     `json:"bypassed"`
    UniqueTokens   int     `json:"unique_tokens"`  // distinct JTI count
    UniqueJA4s     int     `json:"unique_ja4s"`    // JA4 diversity
    AvgBotScore    float64 `json:"avg_bot_score"`
    MaxBotScore    int     `json:"max_bot_score"`
    FirstSeen      string  `json:"first_seen"`
    LastSeen       string  `json:"last_seen"`
    Flags          []string `json:"flags,omitempty"` // "repeat_failure", "cookie_harvesting", "ja4_rotation"
}
```

**Flag detection:**
- `repeat_failure`: failed > 3 in the time window
- `cookie_harvesting`: unique_tokens > 5 (solving repeatedly to farm cookies)
- `ja4_rotation`: unique_ja4s > 3 (rotating TLS stacks, likely evasion)

#### 3c. Cookie Harvesting Alert

Part of the IP history — any IP with `cookie_harvesting` flag is surfaced
prominently in the dashboard as an alert.

### Dashboard additions

Add a "Reputation" tab or section to the Challenge Analytics page:

1. **JA4 Reputation Table** — sortable, color-coded by verdict (green/yellow/red).
   Quick-action buttons: "Block JA4", "Challenge JA4", "View Events".

2. **Flagged IPs** — IPs with active flags. Color-coded flags as pills.
   Quick-action: "Block IP", "View in IP Lookup".

3. **Cookie Harvesting Alerts** — prominent banner when detected.
   Shows the IP, token count, time range, and recommended action.

### Tests

- E2E: verify `/api/challenge/reputation` returns valid structure.
- Unit: test verdict logic with known pass/fail rates.
- Unit: test flag detection (repeat_failure, cookie_harvesting, ja4_rotation).

---

## Phase 4: Rule Engine Integration (plugin + wafctl)

**Goal:** Make challenge reputation data actionable through the rule engine,
so operators can write conditions like "if this IP has failed challenges
recently, block/challenge/rate-limit it."

### New condition field: `challenge_history`

**Plugin changes:**

| File | Change |
|------|--------|
| `policyengine.go` `extractFieldValue()` | Add `case "challenge_history"` — returns a value like `"passed"`, `"failed"`, `"none"` based on whether the client IP has a valid challenge cookie, a recent failure, or no challenge interaction. |
| `policyengine.go` | The challenge cookie is already validated in `validateChallengeCookie()`. Extend to expose the result as a field value, not just a boolean. If cookie is valid → `"passed"`. If cookie is invalid/expired → `"expired"`. If no cookie → `"none"`. |

This is lightweight — it doesn't require a reputation lookup, just cookie
inspection. The heavier reputation features (JA4 verdicts, IP history) stay
in wafctl and are used for rule creation, not real-time evaluation.

**wafctl model changes:**

| File | Change |
|------|--------|
| `models_exclusions.go` `validPolicyEngineFields` | Add `"challenge_history"`. |
| `models_exclusions.go` `validOperatorsForField` | Add `"challenge_history": {"eq", "neq", "in"}`. |

**Dashboard changes:**

| File | Change |
|------|--------|
| `exclusions.ts` `ConditionField` | Add `"challenge_history"`. |
| `constants.ts` `CONDITION_FIELDS` | Add field with operators `eq`, `neq`, `in`. Values: `passed`, `failed`, `expired`, `none`. |

### Rule templates

Add a "Challenge Escalation" template to the templates API:

```json
{
  "id": "challenge-escalation",
  "name": "Challenge Escalation",
  "description": "Escalate protection for clients with challenge failures",
  "rules": [
    {
      "name": "Block repeat challenge failures",
      "type": "block",
      "conditions": [
        {"field": "challenge_history", "operator": "eq", "value": "failed"}
      ],
      "tags": ["bot-mitigation", "challenge-escalation"]
    }
  ]
}
```

### Tests

- Plugin unit: test `extractFieldValue("challenge_history")` returns correct
  values for valid cookie, expired cookie, no cookie.
- E2E: create a rule with `challenge_history` condition, verify it's accepted.
- E2E: verify the template is available via `/api/templates`.

---

## Implementation Order

```
Phase 2 (endpoint discovery)     — no plugin changes, immediately useful
  ↓
Phase 1 (data pipeline)          — plugin tag required, unblocks Phase 3
  ↓
Phase 3 (challenge reputation)   — consumes Phase 1 data
  ↓
Phase 4 (rule engine integration) — plugin tag required, builds on Phase 3
```

Phase 2 first because it's self-contained and directly addresses the
"how do I know what to challenge?" question. Phase 1 next because it
unblocks the richer analytics in Phase 3. Phase 4 last because it's
the most invasive (new condition field in the plugin).

## Version Plan

| Phase | Plugin Version | Caddy Tag | wafctl Tag |
|-------|---------------|-----------|------------|
| 2     | v0.26.0 (current) | 3.67.0 | 2.71.0 |
| 1     | v0.27.0       | 3.68.0    | 2.72.0     |
| 3     | v0.27.0 (same) | 3.69.0   | 2.73.0     |
| 4     | v0.28.0       | 3.70.0    | 2.74.0     |
