# PLAN.md — Policy Engine Roadmap

## Current State (v2.36.0 / caddy 3.35.0 / plugin v0.17.0)

Fully operational WAF with custom policy engine, CRS 4.24.1 (313 rules: 254 inbound +
59 outbound), 6-pass evaluation (allow → block → skip → rate_limit → detect →
response_header), unified rule store (`/api/rules` + `/api/deploy`), response-phase
support for all rule types, structured CORS (preflight + origin validation), rule
templates, per-service category masks, outbound anomaly scoring + rate limiting,
incremental summary (O(hours)), managed lists, IPsum blocklist (618K IPs), CRS
auto-update workflow, and e2e CI pipeline (117 e2e tests, 500 Go tests, 326 frontend).

---

## Pending Work

### CRS Converter Fidelity

CRS regression: 90.8% (216/238 rules). 22 failures:
- 9 Go http client limitations (can't send malformed HTTP)
- 9 correct detections with different status (403 vs expected 400)
- 13 false positives from CRS exclusion chains not translated by converter
- 1 genuine miss (920521)

Root cause: CRS uses chained rules with `ctl:ruleRemoveByTag` to suppress
false positives in specific contexts. The converter doesn't translate these chains,
causing 4 rules (932236, 932260, 941130, 942200) to over-match on `request_combined`.

**Done:**
- [x] Variable exclusion support in converter (Excludes field from CRS negation variables)
- [x] Plugin v0.18.0: isExcluded() filters cookies/headers during multi-field extraction
- [x] Plugin v0.19.0: nested condition groups (recursive AND/OR evaluation)
- [x] Attempted per-field OR groups in converter — broke 203/238 rules (reverted).
      request_combined's isMulti already evaluates per-variable correctly; the issue
      is that detect_sqli/detect_xss operators don't work through nested group paths.

**To reach 95%+ (needs deeper investigation):**
- [ ] Fix detect_sqli/detect_xss in nested group evaluation path
- [ ] SecRuleUpdateTargetById processing in converter parser
- [ ] CRS ctl:ruleRemoveByTag translation (runtime suppression chains)

### WebSocket + Stream Deep Inspection (Long-Term)

MITM proxy for WebSocket frame inspection and SSE event inspection. Design complete
(RFC 6455 frame parsing, hijack-and-wrap pattern, blocking/tap modes). See prior art
from tailscale, K8s streamtunnel, goproxy.

**Implementation phases (~11 days estimated):**
1. WebSocket frame parser (RFC 6455): read/write, masking, fragmentation
2. MITM proxy: intercept upgrade, dial upstream, bidirectional pump
3. Frame inspection: extract payload, run against compiled conditions
4. SSE wrapper: intercept Writer, parse events, inspect
5. Connection-level rate limiting: frames/sec per connection
6. wafctl: `ws_message`, `sse_event` fields, `phase: "stream"` UI
7. E2E tests

### Production Deployment

- [ ] Run `scripts/setup-cors.sh` to configure production CORS origins
- [ ] Apply cache-static-assets template via `/api/rules/templates/cache-static-assets/apply`
- [ ] Verify CORS preflight + origin validation in production
- [ ] Monitor event store disk/memory usage (see README sizing guide)

---

### DDoS/DoS Mitigation Layer

First-pass mitigation layer that runs before all other policy engine evaluation.
Reuses the same sliding-window counter and condition evaluation infrastructure
as the existing rate limit rules, but with different response behavior.

**Problem:** Under a bombardment (791K events in hours), the observation layer
(event stores, JSONL persistence, API handlers) collapses — 2GB JSONL files,
3-minute startup, health endpoint timeouts, dashboard unreachable. Rate limiting
blocks the requests but the WAF still logs every single block event individually.

**Solution:** Request fingerprinting + hash-bucketed dedup during volumetric attacks.

#### Architecture

```
Normal traffic:     request → policy engine → store event individually
Volumetric attack:  request → DDoS mitigation layer detects spike
                    → fingerprint(ip, method, uri, ua) → dedup bucket
                    → bucket: {first_event, count, first_seen, last_seen, top_ips, top_uris}
                    → summary counters still updated (aggregates preserved)
                    → individual event storage paused (ring buffer doesn't grow)
                    → on cooldown: emit spike report with full forensics
```

#### Fingerprinting

Hash `(client_ip, method, normalized_uri, user_agent)` with FNV-64a.
URI normalized: strip query params, collapse path traversal.
Same infrastructure as policy engine's `rate_limit_key` field extraction.

#### Spike Detection (sliding window EPS)

Reuses the same sliding-window counter pattern as rate limit rules:
- 10-second windows, 6-window history (1 minute lookback)
- Configurable thresholds: `WAF_DOS_EPS_TRIGGER=50`, `WAF_DOS_EPS_COOLDOWN=10`
- Hysteresis: must sustain below cooldown for `WAF_DOS_COOLDOWN_DELAY=30s` before exiting

#### Dedup Buckets

During spike mode, each unique fingerprint gets a `SpikeBucket`:
```go
type SpikeBucket struct {
    Fingerprint uint64
    Count       int64
    FirstEvent  RateLimitEvent   // full detail of first occurrence
    FirstSeen   time.Time
    LastSeen    time.Time
    ClientIPs   map[string]int   // top contributing IPs
    Services    map[string]int
    URIs        map[string]int
    StatusCodes map[int]int
    Countries   map[string]int
}
```
Max buckets capped at 10K to bound memory.

#### Spike Reports (forensic snapshots)

On cooldown, generate a `SpikeReport`:
- Duration, total events, peak EPS, unique fingerprints
- Top 50 fingerprints by count (with full first-event detail)
- Top 20 IPs, URIs, countries
- Persisted to `/data/spike-reports/` as JSON, keeps last 100

#### API Endpoints

- `GET /api/dos/status` — current mode (normal/spike), EPS, active buckets
- `GET /api/dos/reports` — historical spike reports
- `GET /api/dos/reports/{id}` — single report detail

#### Dashboard

- Health indicator: `MONITORING` → `SPIKE: 150 EPS` (amber pulsing)
- Overview page: real-time EPS sparkline, active spike banner
- New "Spike Reports" section with forensic drill-down

#### Configuration

```bash
WAF_DOS_EPS_TRIGGER=50        # events/sec to enter spike mode
WAF_DOS_EPS_COOLDOWN=10       # events/sec to exit spike mode
WAF_DOS_COOLDOWN_DELAY=30s    # sustain below cooldown before exiting
WAF_DOS_MAX_BUCKETS=10000     # max fingerprint buckets per spike
WAF_DOS_MAX_REPORTS=100       # keep last N spike reports
```

#### Why Better Than Fail2Ban

| Feature | Fail2Ban | This |
|---------|----------|------|
| Detection | IP only, regex log scan | Multi-field fingerprint (IP+method+URI+UA) |
| Response | Binary ban (iptables) | Adaptive: dedup logging, preserve forensics |
| Distributed attacks | Missed (each IP below threshold) | Caught (fingerprint groups by pattern) |
| Data retention | None | Full spike reports with forensic detail |
| Recovery | Manual unban | Auto-cooldown with report |
| Integration | Separate daemon | Built into policy engine, same condition syntax |

#### Implementation Phases

1. `dos_mitigation.go` — DosMitigation struct, fingerprint fn, EPS tracker, mode transitions
2. Wire into `AccessLogStore.Load()` — route new events through mitigation layer
3. Spike report persistence + API endpoints
4. Dashboard UI: spike indicator, EPS chart, report viewer
5. Wire into `GeneralLogStore.Load()` — separate mitigation instance

---

## Performance Improvements

Full-stack performance audit. Branch: `perf/events-deferred-enrichment`.

### Completed

- [x] **Backend: Deferred enrichment in `/api/events`** — Merge loop works with raw
  `[]RateLimitEvent`, only enriches ~25-50 page results instead of all 148K events (~60MB saved).
  `wafctl/handlers_events.go`, `wafctl/query_helpers.go`
- [x] **Backend: Response cache on `/api/events`** — 5s TTL, generation-invalidated.
  `wafctl/handlers_events.go`
- [x] **Backend 1.1: Analytics handlers use deferred enrichment** — `handleTopBlockedIPs`,
  `handleTopTargetedURIs` now use raw `[]RateLimitEvent` (no enrichment). `handleTopCountries`
  uses `FastSummary()` O(buckets) path. Cache TTL bumped 3s→10s.
  `wafctl/handlers_analytics.go`, `wafctl/waf_analytics.go`
- [x] **Backend 1.2: handleExclusionHits response cache + raw RLE** — Added
  `newResponseCache(20)` with 10s TTL. Uses raw `snapshotSince` + `rleEventType` instead
  of enriched `getRLEvents`. `wafctl/handlers_exclusions.go`
- [x] **Backend 3.1: FastSummary fallback warning** — Added `log.Printf("[perf]...")` when
  FastSummary falls back to O(N) scan. `wafctl/logparser.go`, `wafctl/access_log_store.go`
- [x] **Backend 1.3-1.5: Response caches on RL/IP handlers** — Added caches to
  `handleRLRuleHits` (10s), `handleRLSummary` (10s), `handleRLEvents` (5s),
  `handleIPLookup` (10s). `wafctl/handlers_ratelimit.go`, `wafctl/handlers_analytics.go`
- [x] **Backend 1.6: ExclusionStore.Count()** — New method avoids deep-copying all exclusions
  just to count. Used in health check. `wafctl/exclusions.go`, `wafctl/handlers_events.go`
- [x] **Backend 6.2: matchIntField cached parse** — Pre-parse int value at filter creation,
  avoiding per-event `strconv.Atoi`. `wafctl/query_helpers.go`
- [x] **Backend 6.3: extractPolicyName prefixes** — Moved to package-level var.
  `wafctl/handlers_analytics.go`
- [x] **Backend 6.9: JSONL single write syscall** — Append newline to data bytes before
  writing (1 syscall instead of 2 per event). `wafctl/logparser.go`,
  `wafctl/access_log_store.go`, `wafctl/general_logs.go`
- [x] **Frontend: Visibility API for polling** — Health check (30s) and auto-refresh pause
  when tab is hidden, fire immediately on focus.
  `waf-dashboard/src/layouts/DashboardLayout.astro`, `waf-dashboard/src/components/TimeRangePicker.tsx`
- [x] **Frontend: Retry button on EventsTable error** — Error card now has a clickable retry.
  `waf-dashboard/src/components/EventsTable.tsx`
- [x] **Frontend F-01: AbortController on OverviewDashboard** — Cancels in-flight summary
  requests when filters/time change. `waf-dashboard/src/components/OverviewDashboard.tsx`,
  `waf-dashboard/src/lib/api/waf-events.ts` (fetchSummary accepts RequestInit)
- [x] **Frontend F-11: RateLimitsPanel bulk operations** — Replaced sequential `for await`
  loop with single `bulkRLAction()` call via `/api/exclusions/bulk`.
  `waf-dashboard/src/components/RateLimitsPanel.tsx`, `waf-dashboard/src/lib/api/rate-limits.ts`
- [x] **Frontend F-17: LogViewer stale request guard** — Added `requestGenRef` pattern.
  `waf-dashboard/src/components/LogViewer.tsx`
- [x] **Frontend F-25: fetchServices module-level cache** — 30s TTL cache avoids redundant
  calls from 5+ components. `waf-dashboard/src/lib/api/waf-events.ts`
- [x] **Frontend F-08: donutData memoized** — Wrapped in `useMemo`.
  `waf-dashboard/src/components/OverviewDashboard.tsx`
- [x] **Frontend F-23: globalDirty memoized** — Wrapped `JSON.stringify` comparison in
  `useMemo`. `waf-dashboard/src/components/RateLimitsPanel.tsx`
- [x] **Backend 2.1-2.2: ALS counter uses RLE directly** — Added `incrementRLEvent`,
  `decrementRLEvent`, `initFromRLEvents` to `summaryCounters`. Avoids O(N) temporary
  `[]Event` allocation at startup and per eviction cycle.
  `wafctl/summary_counters.go`, `wafctl/access_log_store.go`
- [x] **Backend 3.3: RecentEvents append-to-tail** — Changed from prepend (alloc-heavy)
  to append + trim front. `buildSummary` already sorts newest-first.
  `wafctl/summary_counters.go`
- [x] **Backend 2.3: JSONL compaction snapshot under lock, write outside** — All three
  stores (WAF, ALS, general logs) now snapshot events under the existing lock and write
  to disk using the snapshot copy. `wafctl/logparser.go`, `wafctl/access_log_store.go`,
  `wafctl/general_logs.go`
- [x] **Frontend F-07: Analytics section default collapsed** — Saves 3 API calls on
  page load. Users expand on demand. `waf-dashboard/src/components/OverviewDashboard.tsx`
- [x] **Frontend F-16: LogViewer split summary from pagination** — Summary only re-fetches
  on filter/time changes, not page changes. `waf-dashboard/src/components/LogViewer.tsx`
- [x] **Infra F6: Removed dead wafctl stage from Dockerfile** — Stage was built but never
  referenced by the final image. `Dockerfile`
- [x] **Infra F3/F4: Replaced curl with wget in Dockerfile** — Alpine has wget built-in.
  Removed curl install from both cloudflare-ips stage and final image (~5MB saved). `Dockerfile`
- [x] **Infra F19: Makefile parallel build and test** — `build` and `test` targets now
  use `$(MAKE) -j2` for parallel execution. `Makefile`

- [x] **Backend 5.1: Deploy dedup — shared generatePolicyData()** — Extracted common
  pipeline into single function used by `handleDeploy`, `handleGenerateConfig`,
  `generateOnBoot`, and `deployAll`. `wafctl/deploy.go`, `wafctl/handlers_config.go`
- [x] **Backend 6.6: General logs summary cache TTL bumped** — 3s→10s.
  `wafctl/general_logs_handlers.go`
- [x] **Backend 2.5: ExclusionStore.TagsByName()** — Lightweight name→tags lookup without
  deep copy. Used by enrichment path. `wafctl/exclusions.go`, `wafctl/query_helpers.go`
- [x] **Backend 2.6: EventByID O(1) index** — Added `idIndex map[string]int` maintained
  at load and eviction. `wafctl/logparser.go`
- [x] **Frontend F-02: getRLRules server-side type filter** — Uses `?type=rate_limit`
  query param. Backend `handleListExclusions` supports `?type=` filter.
  `waf-dashboard/src/lib/api/rate-limits.ts`, `wafctl/handlers_exclusions.go`
- [x] **Backend/Frontend F-18: IPLookup skip intel on pagination** — Backend skips GeoIP
  and IP intelligence lookups when `offset > 0`. `wafctl/handlers_analytics.go`
- [x] **Infra F12: Jellyfin streaming transport config** — Added `flush_interval -1` and
  transport timeouts for media streaming. `Caddyfile`
- [x] **Infra F15: Log retention reduced** — Per-site: 256MB×5 → 128MB×3. Combined:
  256MB×3 → 256MB×2. Max disk ~13GB → ~8GB. `Caddyfile`
- [x] **Infra F10: Caddy start_period 10s → 120s** — Covers ACME DNS propagation delay.
  `compose.yaml`

### Remaining (future)

- [ ] **F-06 — fetchAllEvents unbounded response** (`waf-events.ts:377-389`) — Backend caps
  at 10K; low priority since it's an explicit user action with loading indicator.
- [ ] **F-20 — PolicyEngine + RateLimitsPanel ~700 lines duplication** — Large refactor to
  extract shared `<RuleTable>` component. Deferred to a dedicated PR.
