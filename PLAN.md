# PLAN.md — Policy Engine Roadmap

## Current State (v2.59.0 / caddy 3.55.0 / body-matcher v0.2.1 / policy-engine v0.23.0 / ddos-mitigator v0.14.0)

Fully operational WAF with custom policy engine, CRS 4.24.1 (313 rules: 254 inbound +
59 outbound), 6-pass evaluation (allow → block → skip → rate_limit → detect →
response_header), unified rule store (`/api/rules` + `/api/deploy`), response-phase
support for all rule types, structured CORS (preflight + origin validation), rule
templates, per-service category masks, outbound anomaly scoring + rate limiting,
incremental summary (O(hours)), managed lists, IPsum blocklist (571K IPs), CRS
metadata driven by converter (crs-metadata.json), auto-update workflow, and e2e CI
pipeline (118 e2e tests, ~530 Go tests, 334 frontend tests).

DDoS mitigator: `caddy-ddos-mitigator` v0.14.0 — behavioral IP profiling, 4-layer
enforcement (L3 nftables kernel drop, L4 TCP RST, L7 HTTP 403, eBPF/XDP NIC drop),
immediate nftables sync on jail (zero propagation window), 64-shard IP jail shared
with wafctl, CMS, CIDR /24 aggregation. ~90ns/req hot path. Load tested at 30K RPS
from loopback: 0.97% CPU, zero goroutine leaks, instant recovery.

Full-stack performance audit complete: deferred enrichment, response caches (5-10s TTL),
O(1) event-by-ID index, streaming JSON export, JSONL single-syscall writes, frontend
AbortController/visibility API/memoization, Makefile parallel build.

---

## Pending Work

### CRS Metadata: Converter-Driven Single Source of Truth — COMPLETED (v2.57.0)

> **Status**: All 4 phases implemented. CRS version bumps now require zero manual
> Go/TS edits — re-run the converter only. Auto-discovered RESPONSE-956 (Ruby
> Data Leakages) that was missing from all hardcoded maps.

**Problem** (now solved): CRS category taxonomy was hardcoded across 4 files that drifted independently:

| File | What it hardcodes | Lines |
|------|-------------------|-------|
| `wafctl/crs_rules.go` | `crsCategories` (14 entries), `categoryFromCRSFile` (19 entries), `customRulesFallback` (11 rules) | ~80 lines of static data |
| `wafctl/config.go` | `validCRSCategoryPrefixes` (21 entries) | ~25 lines |
| `waf-dashboard/src/lib/api/default-rules.ts` | `CRS_CATEGORIES` (20 entries with shortName, color, icon) | ~45 lines |
| `wafctl/access_log_store.go` | Severity-to-numeric mapping, `"PE-"` prefix, `"Matched Data: "` format | scattered |

When CRS bumps from v4.24 to v4.25+ (or eventually v5), every one of these must be
manually updated. The `crs-converter` already parses every `.conf` file at build time
and knows all categories, rule IDs, severities, and tags — but none of that knowledge
flows back to inform the Go code or frontend.

**Goal**: The converter becomes the single source of truth. CRS version bumps require
re-running the converter — zero manual Go/TS edits.

#### Phase 1 — Converter emits `crs-metadata.json` at build time

Extend `tools/crs-converter/` to emit a second output file alongside `default-rules.json`:

```json
{
  "crs_version": "4.24.1",
  "generated_at": "2025-03-18T09:00:00Z",
  "categories": [
    {
      "id": "protocol-enforcement",
      "name": "Protocol Enforcement",
      "description": "HTTP protocol violations and anomalies",
      "prefix": "920",
      "rule_range": "920000-920999",
      "tag": "attack-protocol",
      "phase": "inbound",
      "rule_count": 42
    }
  ],
  "category_map": {
    "REQUEST-920-PROTOCOL-ENFORCEMENT": "protocol-enforcement",
    "RESPONSE-950-DATA-LEAKAGES": "data-leakage"
  },
  "valid_prefixes": ["913", "920", "921", "922", "930", "931", "932", "933", "934", "941", "942", "943", "944", "950", "951", "952", "953", "954", "955"],
  "severity_levels": {
    "CRITICAL": 2,
    "ERROR": 3,
    "WARNING": 4,
    "NOTICE": 5
  },
  "custom_rule_prefix": "9100"
}
```

The converter already iterates `.conf` filenames to derive categories. Adding metadata
emission is ~100 lines of Go in the converter. The `rule_count` per category and
`phase` (inbound/outbound from `REQUEST-` vs `RESPONSE-` prefix) come for free.

**Converter changes** (`tools/crs-converter/main.go`):
- New flag: `-metadata-output /path/to/crs-metadata.json`
- After processing all `.conf` files, build the metadata struct from observed categories
- Emit as indented JSON alongside `default-rules.json`

**Dockerfile changes** (stage `crs-rules`):
- Add `-metadata-output /build/crs-metadata.json` to the converter invocation
- `COPY --from=crs-rules /build/crs-metadata.json /etc/caddy/waf/crs-metadata.json`

#### Phase 2 — Go code loads metadata at startup

New file: `wafctl/crs_metadata.go`

```go
// CRSMetadata is loaded from crs-metadata.json at startup.
// All category taxonomy, prefix validation, and normalization
// is derived from this rather than hardcoded Go maps.
type CRSMetadata struct {
    CRSVersion     string                       `json:"crs_version"`
    Categories     []CRSCategory                `json:"categories"`
    CategoryMap    map[string]string             `json:"category_map"`
    ValidPrefixes  []string                      `json:"valid_prefixes"`
    SeverityLevels map[string]int                `json:"severity_levels"`
}

var defaultMetadata atomic.Pointer[CRSMetadata]
```

**What each file drops:**

| File | Removed | Replaced by |
|------|---------|-------------|
| `crs_rules.go` | `crsCategories` slice | `defaultMetadata.Load().Categories` |
| `crs_rules.go` | `categoryFromCRSFile` map | `defaultMetadata.Load().CategoryMap` |
| `config.go` | `validCRSCategoryPrefixes` map | `defaultMetadata.Load().ValidPrefixes` as a set |
| `access_log_store.go` | Severity switch statement | `defaultMetadata.Load().SeverityLevels` |

The hardcoded Go maps remain as **compile-time fallbacks** for tests that don't load
metadata (same pattern as `customRulesFallback` today). But production always loads
from the generated file.

**Startup sequence** (`main.go`):
```go
meta, err := LoadCRSMetadata(filepath.Join(wafDir, "crs-metadata.json"))
if err != nil {
    log.Printf("[crs] warning: %v, using fallback metadata", err)
    meta = fallbackMetadata() // hardcoded Go maps, current behavior
}
SetCRSMetadata(meta)
```

#### Phase 3 — Frontend drops its category constant

The frontend already fetches categories from `GET /api/crs/rules` (which returns
`CRSCatalogResponse.Categories`). The `CRS_CATEGORIES` constant in
`waf-dashboard/src/lib/api/default-rules.ts` is only used for:
1. Mapping category IDs to display names/colors in the UI
2. Populating category filter dropdowns

**Changes:**
- `/api/crs/rules` response already includes categories — add `color` and `icon` fields
  to `CRSCategory` struct (or let the frontend derive them from the category ID via a
  small lookup, which is already partially done)
- Remove the `CRS_CATEGORIES` constant from `default-rules.ts`
- Category filter dropdowns fetch from the API on mount (with caching)

This decouples the frontend entirely from CRS version knowledge. Adding a new category
in CRS v5 would automatically appear in the UI without any frontend code change.

#### Phase 4 — Test infrastructure

**Converter tests** (`tools/crs-converter/`):
- Test that the metadata output contains all observed categories
- Test that `category_map` keys match `.conf` filenames
- Test that `valid_prefixes` covers all observed rule ID prefixes

**Go unit tests** (`wafctl/`):
- `TestLoadCRSMetadata_FromFile` — loads test fixture, verifies categories
- `TestLoadCRSMetadata_Missing` — falls back to hardcoded, logs warning
- `TestNormalizeCRSCategory_Dynamic` — uses loaded metadata instead of static map
- `TestValidateCategoryPrefix_Dynamic` — validates against loaded prefixes
- Remove or relax tests that assert specific category counts (they change with CRS versions)

**E2E tests**:
- `GET /api/crs/rules` already tested; verify `categories[].rule_count` is populated
- Verify that `disabled_categories` accepts all prefixes from the metadata

#### Migration path

This is backward-compatible. The fallback metadata (hardcoded maps) ensures the code
works without `crs-metadata.json` — same behavior as today. The migration is:

1. PR 1: Converter emits `crs-metadata.json` (additive, no Go changes)
2. PR 2: Go loads metadata at startup, falls back to hardcoded (no behavior change)
3. PR 3: Frontend fetches categories from API, removes constant
4. PR 4: Remove hardcoded maps (breaking change — requires metadata file)

PRs 1-3 can each be deployed independently with zero risk. PR 4 is optional cleanup.

**Estimated effort**: ~3-4 days total (converter: 1 day, Go loader: 1 day, frontend: 0.5 day, tests: 1 day).

---

### CRS Converter Fidelity

CRS regression: 90.8% (216/238 rules). 22 failures:
- 9 Go http client limitations (can't send malformed HTTP)
- 9 correct detections with different status (403 vs expected 400)
- 13 false positives from CRS exclusion chains not translated by converter
- 1 genuine miss (920521)

Root cause: CRS uses chained rules with `ctl:ruleRemoveByTag` to suppress
false positives in specific contexts. The converter doesn't translate these chains,
causing 4 rules (932236, 932260, 941130, 942200) to over-match on `request_combined`.

**To reach 95%+ (needs deeper investigation):**
- [ ] Fix detect_sqli/detect_xss in nested group evaluation path
- [ ] SecRuleUpdateTargetById processing in converter parser
- [ ] CRS ctl:ruleRemoveByTag translation (runtime suppression chains)

### WebSocket + Stream Deep Inspection (Long-Term)

MITM proxy for WebSocket frame inspection and SSE event inspection. Design complete
(RFC 6455 frame parsing, hijack-and-wrap pattern, blocking/tap modes).

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

### Edge Caching & Request Coalescing (Caddy as Edge)

Goal: run Caddy as a full edge server with HTTP response caching, request coalescing
(thundering herd protection), and stale-while-revalidate — replacing the need for a
separate Varnish/Nginx caching layer.

#### RFC Foundations

**RFC 9111 (HTTP Caching)** — the authoritative specification.

- **Section 4 ¶7 — Request collapsing**: "A cache can use a response that is stored or
  storable to satisfy multiple requests... This enables a cache to 'collapse requests' —
  or combine multiple incoming requests into a single forward request upon a cache miss —
  thereby reducing load on the origin server and network. Note, however, that if the cache
  cannot use the returned response for some or all of the collapsed requests, it will need
  to forward the requests in order to satisfy them, potentially introducing additional
  latency." Collapsing is explicitly **permitted** (MAY), not required.

- **Section 2 — Cache key**: at minimum `method + target URI`. Must also incorporate
  `Vary`-nominated headers (Section 4.1). `Vary: *` always fails to match and kills
  caching entirely.

- **Section 4.2.1 — Freshness lifetime precedence** (first match wins for shared caches):
  1. `s-maxage` (shared caches only; implies `proxy-revalidate`)
  2. `max-age`
  3. `Expires - Date`
  4. Heuristic (typically 10% of `Last-Modified` age, per Section 4.2.2)

- **Section 4.2.4 — Stale serving**: a shared cache MUST NOT serve stale unless explicitly
  permitted by RFC 5861, `max-stale`, or out-of-band contract. `must-revalidate` and
  `s-maxage` both prohibit stale serving.

- **Section 5.2.2.7 — `private`**: shared caches MUST NOT store. `Authorization` in
  requests: MUST NOT cache unless `public`, `must-revalidate`, or `s-maxage` present
  (Section 3.5).

- **Section 5.2.2.10 — `s-maxage`**: overrides `max-age` for shared caches; incorporates
  `proxy-revalidate` semantics (MUST NOT reuse stale without successful revalidation).

**RFC 5861 (Stale Content Extensions)** — the thundering herd defense.

- **Section 3 — `stale-while-revalidate`**: "caches MAY serve the response in which it
  appears after it becomes stale, up to the indicated number of seconds... the cache
  SHOULD attempt to revalidate it while still serving stale responses (i.e., without
  blocking)." Example: `Cache-Control: max-age=600, stale-while-revalidate=30` — fresh
  600s, serveable-stale for 30 more while one async revalidation runs. This is the single
  most effective thundering herd defense: N clients get instant stale responses, 1 origin
  request.

- **Section 4 — `stale-if-error`**: "when an error is encountered, a cached stale response
  MAY be used to satisfy the request." Errors = 500/502/503/504. Combined with coalescing,
  all collapsed waiters get the stale response instead of cascading retries.

**RFC 8246 (Immutable Responses)** — `Cache-Control: max-age=31536000, immutable`. Origin
will not update the resource during freshness. Proxies SHOULD skip conditional revalidation
while fresh. Ideal for versioned/fingerprinted static assets. No coalescing needed — no
origin request fires while fresh.

**RFC 9110 (HTTP Semantics)**:

- **Section 13 — Conditional requests**: `If-None-Match` (ETag, weak comparison) takes
  precedence over `If-Modified-Since` (Section 13.2.2). Used during cache revalidation.

- **Section 12.5.5 — Vary**: determines which request headers expand the cache key. Proxy
  MUST NOT generate `Vary: *`. When collapsing requests, each collapsed request must have
  matching Vary-nominated header values.

**RFC 9211** — `Cache-Status` structured response header for reporting hit/miss/revalidated.

#### How CDN/Edge Services Implement Coalescing

**Varnish** — automatic coalescing + **Grace mode**:
- `beresp.grace = 2m` — serve stale for 2 min while revalidating in background
- `beresp.keep = 8m` — retain object for conditional revalidation after grace expires
- During grace with an active backend fetch: stale served instantly, no waiting list
- `req.hash_ignore_busy` — per-request toggle to disable coalescing
- Background fetch errors: `return(abandon)` in `vcl_backend_response` protects grace
  objects from being replaced by 5xx responses
- Health-aware grace: short grace (10s) when backend healthy, long grace when sick

**Nginx** — `proxy_cache_lock` directive:
```nginx
proxy_cache_lock on;              # Enable coalescing (default: off)
proxy_cache_lock_timeout 5s;      # Max wait before bypass (response NOT cached)
proxy_cache_lock_age 5s;          # Allow another request through if first hasn't completed
proxy_cache_background_update on; # Async stale-while-revalidate subrequest
proxy_cache_use_stale updating error timeout http_500 http_502 http_503 http_504;
proxy_cache_revalidate on;        # Use If-Modified-Since / If-None-Match
```
After `proxy_cache_lock_timeout`: waiting requests forwarded to origin individually,
responses NOT cached. After `proxy_cache_lock_age`: a second request allowed through to
origin (prevents total stall if first request hangs).

**Fastly** (Varnish-based) — most detailed documentation on edge cases:

| Scenario                             | Behavior                                        |
|--------------------------------------|-------------------------------------------------|
| Miss → cacheable response            | All queued requests get copies                  |
| Miss → uncacheable, no hit-for-pass  | **Serial drain** — one at a time, can cause minutes of latency |
| Miss → `return(pass)` in vcl_fetch   | Hit-for-pass marker (2min-1h TTL); queued requests dequeue concurrently |
| Hit-for-pass marker exists           | Bypasses collapsing entirely                    |
| `return(pass)` in vcl_recv           | Not eligible for collapsing                     |

The **hit-for-pass** mechanism is critical: without it, uncacheable responses during
coalescing cause serial queue drain. Fastly explicitly warns this creates "extreme
response times of several minutes."

**Cloudflare** — implicit coalescing + **Tiered Cache** (lower-tier edge → upper-tier →
origin). Only upper-tier contacts origin. Smart Tiered Cache auto-selects optimal upper-tier
based on origin location.

**AWS CloudFront** — automatic collapsing. First request logged as `Miss`, collapsed as
`Hit`. Does NOT coalesce when cookie forwarding is enabled. **Origin Shield** adds a
second coalescing opportunity.

**Google Cloud CDN** — exposes `requestCoalescing` as an explicit boolean (default: true),
plus `serveWhileStale` and `negativeCaching` as first-class config options.

**Envoy** — cache filter does NOT implement coalescing. Known limitation.

**HAProxy** — cache does NOT implement coalescing.

#### Caddy's Current Caching State

Caddy has **no built-in HTTP response cache**. The plugin ecosystem:

- **`github.com/caddyserver/cache-handler`** (v0.16.0) — under the `caddyserver` org,
  built on Souin. Semi-official. `xcaddy build --with github.com/caddyserver/cache-handler`

- **`github.com/darkweak/souin`** (~950 stars) — upstream development repo. Single primary
  maintainer (@darkweak). MIT license.

- **`github.com/darkweak/storages`** (v0.0.19) — externalized storage backends since
  Souin v1.7.0. Must be included explicitly for non-default backends.

**What Souin/cache-handler provides:**

| Feature                    | Status    | Notes |
|----------------------------|-----------|-------|
| RFC 7234/9111 compliance   | Full      | Cache-Control, Vary, Age, conditional requests |
| RFC 9211 Cache-Status      | Yes       | Structured hit/miss/revalidated reporting |
| Request coalescing         | Yes       | Via `golang.org/x/sync/singleflight` internally |
| stale-while-revalidate     | Yes       | `stale` directive + RFC 5861 header parsing |
| Cache key configuration    | Extensive | Per-route regex, scheme/host/method/path/query/body/headers/Vary, templates via Caddy placeholders |
| Tag-based invalidation     | Yes       | Surrogate keys with Akamai/Fastly/Cloudflare purge providers |
| Purge API                  | Yes       | `PURGE /souin-api/souin/{key-or-regex}`, flush all, surrogate key purge |
| ESI                        | Yes       | Via `github.com/darkweak/go-esi` |
| Storage backends           | 9         | Badger (default), Otter (in-memory), NutsDB, Redis (rueidis), go-redis, Olric, Etcd, Nats, Simplefs |
| Distributed cache          | Yes       | Redis, Olric, Etcd, Nats |
| Negative caching           | Via headers | Respects origin Cache-Control on error responses |
| Prometheus metrics         | Yes       | `souin_request_upstream_counter`, `souin_cached_response_counter`, `souin_avg_response_time` |

#### Gap Analysis: Caddy + Souin vs. Varnish/Nginx

| Capability                          | Varnish              | Nginx                        | Caddy + Souin              |
|-------------------------------------|----------------------|------------------------------|----------------------------|
| Coalescing                          | Automatic + per-req toggle | `proxy_cache_lock` + timeout/age | `singleflight` (no timeout config) |
| Grace / SWR                         | Mature, per-request override | `background_update` + `use_stale` | `stale` directive          |
| Hit-for-pass (uncacheable bypass)   | Native               | Lock timeout serves as bypass | **Not documented**         |
| Coalescing timeout                  | Backend timeouts     | `lock_timeout` / `lock_age`  | **None — hung origin blocks all** |
| Streaming cache (serve while fetch) | `beresp.do_stream`   | Inherent in proxy_cache      | **Not supported** (full buffer) |
| Negative caching                    | VCL configurable     | `proxy_cache_valid 404 1m`   | Via Cache-Control headers  |
| Cache warming / preload             | varnishadm           | N/A                          | **Not supported**          |
| Observability                       | varnishstat/varnishlog (rich) | Log variables         | Prometheus counters (basic) |
| Auto-HTTPS                          | Requires separate proxy | Manual certs              | **Best-in-class** (ACME)  |
| Maturity                            | 15+ years            | 10+ years                    | ~3-4 years (Souin)        |
| Maintainer bus factor               | Varnish Software     | F5/Nginx Inc.                | Single maintainer (@darkweak) |

#### Critical Design Decisions for Edge Implementation

Five decisions that determine whether a coalescing cache works in production:

**1. Cache key computation.** Minimum: `method + host + path + sorted query + Vary-nominated
headers`. Normalize `Accept-Encoding` to reduce variants (gzip/br/identity → canonical
form). Make configurable per-route — static assets need different keys than API responses.
Souin already does this well.

**2. Coalescing timeout.** A hung origin with no timeout blocks ALL collapsed requests for
that key forever. Nginx uses 5s for both `lock_timeout` and `lock_age`. Go pattern:
`singleflight.DoChan()` + `select { case <-ch: ... case <-time.After(timeout): ... }`.
Souin currently uses bare `singleflight.Do()` with no timeout — **this is a gap**.

**3. Hit-for-pass.** When origin returns uncacheable (`private`, `no-store`, `Set-Cookie`
without explicit caching), store a short-lived marker (2-5 min TTL) that says "don't
coalesce future requests for this key — send them directly to origin." Without this,
Fastly documents that uncacheable responses during coalescing cause serial queue drain
with "extreme response times of several minutes." **Souin does not implement this — this
is the most dangerous gap.**

**4. Stale-while-revalidate.** The best thundering herd defense. When an object enters the
SWR window: first request triggers background revalidation, all subsequent requests during
that window get the stale response instantly. Zero client latency, one origin request. Both
Varnish (grace mode) and Nginx (`proxy_cache_background_update`) implement this. Souin
supports it via the `stale` directive.

**5. Stale-if-error.** On 5xx from origin, serve stale to all collapsed waiters instead of
fanning out retries. Prevents cascading failures during origin outages. Varnish:
`return(abandon)` on background fetch 5xx. Combined with SWR, this makes the cache
resilient to transient origin errors.

**Defense-in-depth ordering** (most to least effective):
1. `stale-while-revalidate` — serve stale instantly, revalidate async. Zero latency.
2. Request coalescing — queue N-1 behind 1 origin fetch. Adds origin-RTT latency.
3. Tiered cache / origin shield — second coalescing layer. N edge misses → 1 shield miss.
4. Hit-for-pass — bypass coalescing for known-uncacheable resources. Prevents serial drain.
5. Coalescing timeout — fail fast rather than queue indefinitely.

#### Implementation Plan

**Phase 1 — Evaluate Souin/cache-handler:**
- [ ] Build Caddy with `cache-handler` + Otter storage (in-memory, high performance)
- [ ] Configure per-route caching: static assets (immutable, long TTL), API responses
      (short TTL, Vary-aware), uncacheable paths (bypass)
- [ ] Verify `singleflight` coalescing under load (k6 stampede test)
- [ ] Measure SWR behavior — confirm only one revalidation fires per stale key
- [ ] Test `Cache-Status` header output for debugging
- [ ] Benchmark: response times, origin request reduction, memory usage

**Phase 2 — Address critical gaps (contribute upstream or fork):**
- [ ] Add coalescing timeout to singleflight usage (`DoChan` + `select` with deadline)
- [ ] Implement hit-for-pass: on uncacheable origin response, store a negative marker
      (configurable TTL, default 2 min) that bypasses coalescing for that cache key
- [ ] Add `stale-if-error` support if not already working end-to-end
- [ ] Add per-route coalescing toggle (disable for known-uncacheable paths like auth
      endpoints, similar to Varnish `req.hash_ignore_busy`)

**Phase 3 — Integration with existing stack:**
- [ ] Handler ordering: `ddos_mitigator` → `cache` → `policy_engine` → `reverse_proxy`
      (cache sits between DDoS and WAF — cached responses skip WAF evaluation entirely)
- [ ] Cache invalidation on WAF deploy: purge cached responses when policy rules change
      (especially response_header rules that modify cached content)
- [ ] Dashboard integration: cache hit/miss/SWR metrics on overview page
- [ ] Jail integration: jailed IPs should bypass cache (serve 403 directly, don't pollute
      cache with block responses)

**Phase 4 — Tiered caching (optional, multi-node):**
- [ ] Redis or Olric as shared storage backend across multiple Caddy instances
- [ ] Origin shield pattern: designate one Caddy instance as shield, others as edge
- [ ] Surrogate key purge propagation across nodes

---

## Completed (changelog)

### v2.59.0 / caddy 3.55.0

- **DDoS mitigator v0.14.0**: Immediate nftables sync on jail — zero propagation window
  between L7 behavioral jail and L3 kernel drop. Previously 1-5s sync interval allowed
  10K-50K connections to queue in Caddy during DDoS storms, causing goroutine leaks in
  Caddy's reverse proxy health-check metrics. Now the first jailing request triggers
  nftables sync via a buffered channel, and subsequent packets are kernel-dropped.
  Load tested: 30K RPS loopback → 0.97% Caddy CPU, instant recovery, zero goroutine leak.
- **CRS metadata (converter-driven)**: `crs-converter` now emits `crs-metadata.json` at
  Docker build time. All hardcoded category maps removed from `crs_rules.go`, `config.go`,
  and `access_log_store.go`. Replaced by `crs_metadata.go` loader with `atomic.Pointer`.
  Auto-discovered RESPONSE-956 (Ruby Data Leakages) missing from all previous maps.
  Frontend `CRS_CATEGORIES` now refreshable from API via `refreshCRSCategories()`.
- **E2E fixes**: All 3 pre-existing failures resolved — `TestPolicyEngineResponseHeaders`
  (uses explicit block rule instead of CRS with threshold=0), `TestEventRequestID` (uses
  block rule to generate events), `TestUnifiedRulesCRUD` (cache-bust + unique names).
  New `TestDDoS_JailSyncToPlugin` verifies jail propagation to plugin within sync interval.
- **Go 1.26.1**: Fixes CVE-2026-25679 (net/url IPv6 parsing). All Dockerfiles and CI updated.
- **Error page**: Request ID moved below buttons, improved visibility.
- Caddyfile: `sync_interval 1s`, `idle timeout 30s` for faster jail propagation and
  connection cleanup.

### v2.57.0 / caddy 3.53.0

- **Code review sweep (31 fixes)**: Critical bug fixes, test coverage, and design improvements
  across CRS, policy engine, DDoS mitigation, and E2E test suite.
- **Critical fixes**: `response_content_type` field made usable (added operator map),
  rate limit priority capped to prevent detect-band collision, `JailStore.SetWhitelist`
  double-lock race eliminated, `SpikeDetector` thresholds now updateable at runtime via
  `PUT /api/dos/config`.
- **DDoS improvements**: `SpikeReport.TotalEvents` tracks cumulative spike events (not
  sliding window), log tailing uses actual timestamps (prevents false burst on restart),
  `JailStore.Count()` optimized from O(n) alloc to O(n) count-only, `SpikeReporter.cleanDir()`
  filters only `spike-*.json` files, removed dead `TopIPs`/`TopPaths`/`TopFingerprints`
  fields from `SpikeReport`.
- **Policy engine**: `mapServiceBoth` generic helper replaces 3 copy-pasted dual-mapping
  blocks, `ResetFQDNCache()` exported for test isolation, `defaultCRSCatalog` uses
  `atomic.Pointer` for thread-safe access, tiebreaker cap logs warning at >1000 rules.
- **CRS**: Category 934 renamed from "Node.js Injection" to "Generic Attack" (CRS v4),
  response-phase categories added to `categoryFromCRSFile`, `disabled_categories` validated
  against known CRS prefixes, threshold validation accepts 0 as "blocking disabled".
- **New test coverage**: `handlers_dos_test.go` (6 handler tests), `spike_reporter_test.go`
  (7 tests), `response_header` rule generation tests (4 tests), `IsPolicyEngineType` test
  covers all 6 types, `detect_action` passthrough test.
- **E2E fixes**: Wrong `DELETE /api/default-rules/{id}` → correct `/override` suffix,
  `t.Fatalf` in goroutines replaced with error channel, summary test gracefully skips when
  no detect_block events exist, DDoS config test restores original config on cleanup,
  WAF config test restores defaults after update.

### v2.53.0 / caddy 3.49.0

- **Cross-repo audit**: Fixed unjail-via-wafctl for long-TTL entries (ddos-mitigator
  file sync was additive-only), aligned withFileLock error handling between wafctl and
  plugin, fixed Makefile stale endpoint, removed dead env vars (WAF_AUDIT_LOG,
  WAF_RATELIMIT_FILE), fixed WAF_CADDY_ADMIN_URL default, corrected doc comments and
  README across all 4 repos.
- Plugin bumps: body-matcher v0.2.1, policy-engine v0.20.1, ddos-mitigator v0.9.0.

### v2.52.0 / caddy 3.48.0

- **F-06**: `fetchAllEvents` returns `ExportResult` with `totalEmitted`/`truncated`;
  UI alerts when 10K export cap is hit.
- **F-20**: Extracted shared rule table infrastructure from PolicyEngine (1187→955 lines)
  and RateLimitsPanel (1107→868 lines): `useRuleReorder` hook, `useRuleSelection` hook,
  `StatusAlerts`, `BulkActionsBar`, `InlinePositionEditor`, `DeleteConfirmDialog`.

### v2.51.0 / caddy 3.47.0

- Full-stack performance audit (30+ items): deferred enrichment, response caches,
  O(1) event index, streaming export, JSONL single-syscall writes, frontend
  AbortController/visibility API/memoization, Makefile parallel build, Dockerfile cleanup.

### v2.50.0 and earlier

- DDoS mitigator: 7-phase implementation (plugin, wafctl stores, L4 handler, dashboard,
  nftables, eBPF/XDP, k6 load tests).
- CRS converter: variable exclusions, isExcluded() filtering, nested condition groups.
