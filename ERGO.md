# ERGO: Edge Request Gateway & Optimization

Design document for implementing request collapsing, response caching, and
hot-path optimization in caddy-compose. The goal is to turn Caddy into a
self-contained edge proxy (no Cloudflare or external CDN) that can be deployed
on bare metal, Docker Compose, or Kubernetes.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Architecture Overview](#2-architecture-overview)
3. [Phase 1 — Per-Pod In-Memory Response Cache + Singleflight](#3-phase-1--per-pod-in-memory-response-cache--singleflight)
4. [Phase 2 — Policy Engine Hot-Path Optimization](#4-phase-2--policy-engine-hot-path-optimization)
5. [Phase 3 — Log Shipping (Disk-Free Ingestion)](#5-phase-3--log-shipping-disk-free-ingestion)
6. [Phase 4 — WAF State Distribution](#6-phase-4--waf-state-distribution)
7. [Phase 5 — K8s-Aware Load Balancing](#7-phase-5--k8s-aware-load-balancing)
8. [Phase 6 — Optional L2 Shared Cache](#8-phase-6--optional-l2-shared-cache)
9. [RFC Compliance Reference](#9-rfc-compliance-reference)
10. [Security Considerations](#10-security-considerations)
11. [Observability](#11-observability)
12. [Open Questions](#12-open-questions)

---

## 1. Problem Statement

Without an external CDN in front, Caddy is the edge. Every request — static
assets, API calls, media streams, WebSocket upgrades — hits the Caddy process
directly. This means:

- **No edge cache.** The `(static_cache)` Caddyfile snippet sets
  `Cache-Control` headers for browsers but does nothing for first-visit
  latency or bot traffic that ignores cache headers.
- **No request deduplication.** If 50 clients request the same Jellyfin poster
  simultaneously, 50 independent requests hit the upstream.
- **Policy engine on every request.** The WAF rule evaluation loop is the
  single hottest code path and has no CDN to absorb traffic in front of it.
- **Single-process state.** Stores (exclusions, config, events) are in-memory
  with JSON file persistence, tied to a single Caddy instance.

### Design Goals

| Goal | Constraint |
|------|-----------|
| Zero external dependencies | Go stdlib only (consistent with wafctl policy) |
| Single-binary deployment | Implemented as Caddy HTTP middleware plugins |
| K8s-ready | Stateless per-pod; shared state via PVC or HTTP sync |
| RFC 9111 compliant | Correct `Cache-Control` / `Vary` / `Age` semantics |
| Observable | Prometheus metrics for cache hit/miss/eviction/collapse |
| Safe defaults | Never cache `Set-Cookie`, `Authorization`, `private` responses |

---

## 2. Architecture Overview

### Request Flow (Current)

```
Client -> TLS (Caddy) -> log_append -> policy_engine -> reverse_proxy -> upstream
```

### Request Flow (Proposed)

```
Client -> TLS (Caddy) -> log_append -> policy_engine -> cache_proxy -> reverse_proxy -> upstream
                                                          |
                                                    [L1 in-memory]
                                                    [singleflight]
```

The `cache_proxy` middleware sits **after** `policy_engine` so that:
- Blocked requests never reach the cache or upstream.
- Rate-limited requests are rejected before cache lookup.
- Detect-mode requests still flow through (logging only).

Caddy handler order directive:

```
order log_append first
order policy_engine after log_append
order cache_proxy after policy_engine
```

### Per-Pod Architecture (K8s)

```
                      +-- Caddy pod 1 --+
                      |  L1 cache       |
Client -> LB/Ingress -+-- Caddy pod 2 --+-> upstream services
                      |  L1 cache       |
                      +-- Caddy pod 3 --+
                           L1 cache

Each pod:
  - Independent in-memory cache (L1)
  - Independent singleflight (per-process)
  - Shared WAF state via ReadWriteMany PVC or HTTP config sync
  - Logs shipped via HTTP push (no shared disk)
```

With sticky session LB (ClientIP affinity), repeat requests from the same
client hit the same pod, maximizing L1 hit rate.

---

## 3. Phase 1 — Per-Pod In-Memory Response Cache + Singleflight

This is the highest-impact change. A single Caddy middleware plugin that
combines RFC 9111-compliant response caching with request collapsing.

### 3.1 Singleflight (Request Collapsing)

**What:** When multiple concurrent requests arrive for the same resource and
the cache has no entry, only one request is forwarded to the upstream. All
other callers block and receive the same response.

**RFC basis:** RFC 9111 Section 4 paragraph 7:
> "A cache can use a response that is stored or storable to satisfy multiple
> requests [...] This enables a cache to 'collapse requests' — or combine
> multiple incoming requests into a single forward request upon a cache miss —
> thereby reducing load on the origin server and network."

**Implementation — stdlib-only singleflight:**

The canonical pattern from `golang/groupcache` uses only `sync.Mutex` and
`sync.WaitGroup`:

```go
package cacheproxy

import "sync"

type call struct {
    wg  sync.WaitGroup
    val *CachedResponse
    err error
}

type singleflight struct {
    mu sync.Mutex
    m  map[string]*call
}

func (g *singleflight) Do(key string, fn func() (*CachedResponse, error)) (*CachedResponse, bool, error) {
    g.mu.Lock()
    if g.m == nil {
        g.m = make(map[string]*call)
    }
    if c, ok := g.m[key]; ok {
        g.mu.Unlock()
        c.wg.Wait()
        return c.val, true, c.err // shared=true
    }
    c := new(call)
    c.wg.Add(1)
    g.m[key] = c
    g.mu.Unlock()

    c.val, c.err = fn()
    c.wg.Done()

    g.mu.Lock()
    delete(g.m, key)
    g.mu.Unlock()

    return c.val, false, c.err // shared=false
}
```

Properties:
- First caller runs `fn()`, all duplicates block on `wg.Wait()`.
- After `fn()` completes, the key is deleted so the next request starts fresh.
- `shared` return value indicates whether the result was reused (for metrics).
- Zero allocations on the fast path (cache hit bypasses singleflight entirely).

**What to collapse:**
- GET and HEAD requests only (safe, idempotent per RFC 9110 Section 9.2.1).
- Exclude WebSocket upgrades (`Connection: Upgrade` or HTTP/2 CONNECT).
- Exclude range requests (`Range` header present) unless identical ranges.

**What NOT to collapse:**
- POST, PUT, DELETE, PATCH (unsafe methods).
- Requests with differing `Authorization` headers.
- Streaming responses over a size threshold (see Section 3.4).

### 3.2 Cache Key Construction

Per RFC 9111 Section 2, the cache key is composed from "at a minimum, the
request method and target URI." We extend this to handle `Vary` and
authentication.

```go
func cacheKey(r *http.Request, varyFields []string) string {
    h := fnv.New128a()
    h.Write([]byte(r.Method))
    h.Write([]byte(r.Host))
    h.Write([]byte(r.URL.Path))
    h.Write([]byte(normalizeQuery(r.URL.RawQuery)))
    // Include Vary-nominated request headers
    for _, field := range varyFields {
        h.Write([]byte(r.Header.Get(field)))
    }
    return hex.EncodeToString(h.Sum(nil))
}
```

**Vary handling (RFC 9111 Section 4.1):**
- On cache store, record the `Vary` header from the response.
- On cache lookup, compute the key including the Vary-nominated request headers.
- `Vary: *` always forces a cache miss.
- Secondary Vary keys stored as sub-entries under the primary URI key.

**Auth-aware keying:**
- For services behind `forward_auth`, the Authelia-injected headers
  (`Remote-User`, `Remote-Groups`) become part of the cache key automatically
  via `Vary` if the upstream sets `Vary: Remote-User` or similar.
- If the upstream does NOT set Vary but responses differ by user, the cache
  should be configured to include auth identity headers in the key for those
  routes (configurable per-service in the Caddyfile).

### 3.3 Cache Storage

**Data structure:**

```go
type CachedResponse struct {
    StatusCode int
    Header     http.Header
    Body       []byte
    Created    time.Time     // response_time for Age calculation
    RequestAt  time.Time     // request_time for Age calculation
    DateHeader time.Time     // Date header value from origin
    TTL        time.Duration // freshness_lifetime (computed)
    VaryFields []string      // Vary header field names
    ETag       string        // for conditional revalidation
    LastMod    string        // Last-Modified value
    BodySize   int64         // for memory accounting
}

type cacheStore struct {
    mu       sync.RWMutex
    entries  map[string]*cacheNode // primary key -> node
    lru      *lruList              // for eviction ordering
    curBytes int64
    maxBytes int64                 // hard memory cap
    metrics  *cacheMetrics
}
```

**Eviction policy:** LRU with a hard byte cap. When `curBytes` exceeds
`maxBytes`, evict least-recently-used entries until under the limit.

**Memory budget:** Configurable via Caddyfile directive. Default 256 MB per
pod. For a K8s deployment with 3 pods, that's 768 MB total L1 cache.

```
cache_proxy {
    max_memory 256MB
    default_ttl 60s
    max_object_size 5MB
    stale_while_revalidate 30s
    stale_if_error 300s
    collapse_requests true
}
```

### 3.4 Freshness Lifetime Calculation (RFC 9111 Section 4.2.1)

Per RFC 9111, freshness is determined by (in priority order):

1. `s-maxage` response directive (shared cache only — this is a shared cache).
2. `max-age` response directive.
3. `Expires` header minus `Date` header.
4. Heuristic freshness (10% of `Last-Modified` age, capped).

```go
func freshnessLifetime(resp *http.Response) time.Duration {
    cc := parseCacheControl(resp.Header.Get("Cache-Control"))

    // 1. s-maxage (shared cache)
    if v, ok := cc["s-maxage"]; ok {
        return time.Duration(v) * time.Second
    }
    // 2. max-age
    if v, ok := cc["max-age"]; ok {
        return time.Duration(v) * time.Second
    }
    // 3. Expires
    if exp := resp.Header.Get("Expires"); exp != "" {
        expTime, err := http.ParseTime(exp)
        if err == nil {
            date := resp.Header.Get("Date")
            dateTime, _ := http.ParseTime(date)
            if dateTime.IsZero() {
                dateTime = time.Now()
            }
            return expTime.Sub(dateTime)
        }
    }
    // 4. Heuristic (10% of Last-Modified age, max 24h)
    if lm := resp.Header.Get("Last-Modified"); lm != "" {
        lmTime, err := http.ParseTime(lm)
        if err == nil {
            age := time.Since(lmTime)
            heuristic := age / 10
            if heuristic > 24*time.Hour {
                heuristic = 24 * time.Hour
            }
            return heuristic
        }
    }
    return 0 // not cacheable without explicit freshness
}
```

### 3.5 Age Calculation (RFC 9111 Section 4.2.3)

When serving from cache, the `Age` header must reflect how old the response is:

```go
func currentAge(entry *CachedResponse) time.Duration {
    // apparent_age = max(0, response_time - date_value)
    apparentAge := entry.Created.Sub(entry.DateHeader)
    if apparentAge < 0 {
        apparentAge = 0
    }
    // corrected_age_value = age_value + response_delay
    responseDelay := entry.Created.Sub(entry.RequestAt)
    correctedAgeValue := responseDelay // age_value is 0 for origin responses

    correctedInitialAge := apparentAge
    if correctedAgeValue > correctedInitialAge {
        correctedInitialAge = correctedAgeValue
    }

    // resident_time = now - response_time
    residentTime := time.Since(entry.Created)
    return correctedInitialAge + residentTime
}
```

The `Age` header is set (or replaced) on every cached response served.

### 3.6 Storeability Rules (RFC 9111 Section 3)

A response MUST NOT be stored if any of these are true:

```go
func isStoreable(req *http.Request, resp *http.Response) bool {
    // Request method must be understood (GET, HEAD)
    if req.Method != http.MethodGet && req.Method != http.MethodHead {
        return false
    }
    // Response must be final (2xx, 3xx, 4xx, 5xx — not 1xx)
    if resp.StatusCode < 200 {
        return false
    }
    cc := parseCacheControl(resp.Header.Get("Cache-Control"))
    // no-store directive
    if _, ok := cc["no-store"]; ok {
        return false
    }
    // private directive (this is a shared cache)
    if _, ok := cc["private"]; ok {
        return false
    }
    // Authorization present without explicit cache permission
    if req.Header.Get("Authorization") != "" {
        if _, ok := cc["must-revalidate"]; !ok {
            if _, ok := cc["public"]; !ok {
                if _, ok := cc["s-maxage"]; !ok {
                    return false
                }
            }
        }
    }
    // Must have explicit freshness or be heuristically cacheable
    hasFreshness := false
    if _, ok := cc["max-age"]; ok {
        hasFreshness = true
    }
    if _, ok := cc["s-maxage"]; ok {
        hasFreshness = true
    }
    if resp.Header.Get("Expires") != "" {
        hasFreshness = true
    }
    if !hasFreshness {
        // Heuristically cacheable status codes: 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501
        switch resp.StatusCode {
        case 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501:
            hasFreshness = true // heuristic freshness applies
        }
    }
    return hasFreshness
}
```

### 3.7 Stale-While-Revalidate (RFC 5861 Section 3)

When a cached entry is stale but within the `stale-while-revalidate` window:
1. Serve the stale response immediately (non-blocking).
2. Trigger an asynchronous background revalidation.
3. The revalidation uses conditional requests (`If-None-Match` / `If-Modified-Since`).
4. If the origin returns 304 Not Modified, the cached entry is freshened.
5. If the origin returns a new response, the cache is updated.

```go
func (c *cacheStore) getOrRevalidate(key string, entry *CachedResponse) (*CachedResponse, cacheStatus) {
    age := currentAge(entry)
    if age <= entry.TTL {
        return entry, cacheHit
    }
    // Stale but within stale-while-revalidate window
    swr := entry.StaleWhileRevalidate
    if age <= entry.TTL+swr {
        // Serve stale, trigger async revalidation
        go c.revalidateAsync(key, entry)
        return entry, cacheStale
    }
    // Stale beyond SWR window — must revalidate synchronously
    return nil, cacheMiss
}
```

### 3.8 Stale-If-Error (RFC 5861 Section 4)

When the upstream returns a 5xx error (500, 502, 503, 504) or is unreachable,
and the cached entry is within the `stale-if-error` window, serve the stale
cached response instead of the error. This is critical for availability when
upstream services crash.

```go
func (c *cacheStore) handleUpstreamError(key string, entry *CachedResponse, upstreamErr error) (*CachedResponse, bool) {
    if entry == nil {
        return nil, false
    }
    age := currentAge(entry)
    sie := entry.StaleIfError
    if age <= entry.TTL+sie {
        return entry, true // serve stale on error
    }
    return nil, false // stale-if-error window expired
}
```

### 3.9 Conditional Revalidation (RFC 9110 Section 13)

When revalidating a stale entry, send conditional headers to avoid retransmitting
an unchanged body:

```go
func addRevalidationHeaders(req *http.Request, entry *CachedResponse) {
    if entry.ETag != "" {
        req.Header.Set("If-None-Match", entry.ETag)
    }
    if entry.LastMod != "" {
        req.Header.Set("If-Modified-Since", entry.LastMod)
    }
}
```

On a 304 Not Modified response, freshen the cached entry's metadata per
RFC 9111 Section 4.3.4 (update stored headers from the 304, recalculate
freshness, reset Age).

### 3.10 Cache Invalidation (RFC 9111 Section 4.4)

When an unsafe request (POST, PUT, DELETE, PATCH) succeeds (2xx or 3xx response),
invalidate cached entries whose target URI matches:

```go
func (c *cacheStore) invalidateOnUnsafe(req *http.Request, resp *http.Response) {
    if req.Method == http.MethodGet || req.Method == http.MethodHead {
        return
    }
    if resp.StatusCode >= 200 && resp.StatusCode < 400 {
        prefix := req.Host + req.URL.Path
        c.evictByPrefix(prefix)
        // Also invalidate Location and Content-Location if present
        if loc := resp.Header.Get("Location"); loc != "" {
            c.evictByURI(loc)
        }
        if cloc := resp.Header.Get("Content-Location"); cloc != "" {
            c.evictByURI(cloc)
        }
    }
}
```

### 3.11 Streaming / Large Response Handling

Responses exceeding `max_object_size` (default 5 MB) are NOT cached. They
stream directly through to the client. This prevents memory exhaustion from
large media files (Jellyfin video, Immich photos, Navidrome audio).

For Phase 1, we do NOT implement fan-out streaming (where multiple callers
share a single upstream stream). Requests for large objects bypass both
the cache and singleflight entirely.

```go
func (c *cacheProxy) shouldBypass(r *http.Request) bool {
    // WebSocket upgrade
    if r.Header.Get("Connection") == "Upgrade" || r.Header.Get("Upgrade") != "" {
        return true
    }
    // Range requests (complex partial content semantics)
    if r.Header.Get("Range") != "" {
        return true
    }
    // SSE / event-stream
    if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
        return true
    }
    return false
}
```

### 3.12 Complete Request Flow

```
1. Request arrives at cache_proxy middleware
2. shouldBypass(req)?
   YES -> pass through to next handler (reverse_proxy), DONE
3. Compute primary cache key: method + host + path + sorted query
4. cacheStore.RLock -> lookup(primaryKey)
   HIT (fresh) -> serve from cache with updated Age header, DONE
   HIT (stale, within SWR) -> serve stale, trigger async revalidation, DONE
   HIT (stale, beyond SWR) -> fall through to step 5
   MISS -> fall through to step 5
5. singleflight.Do(primaryKey, func() {
     forward request to next handler (reverse_proxy)
     capture response via ResponseWriter wrapper
     if isStoreable(req, resp) && resp.Body <= maxObjectSize:
       compute secondary Vary key
       store in cacheStore
     return captured response
   })
6. If singleflight returned shared=true, replay buffered response
7. If upstream error AND stale entry exists within stale-if-error:
   serve stale entry instead of error
8. Otherwise, forward error to client
```

### 3.13 Caddyfile Syntax

```
cache_proxy {
    # Memory budget for this pod's L1 cache
    max_memory 256MB

    # Maximum size of a single cached object
    max_object_size 5MB

    # Default TTL when upstream provides no Cache-Control / Expires
    default_ttl 60s

    # Default stale-while-revalidate window (overridden by upstream header)
    stale_while_revalidate 30s

    # Default stale-if-error window
    stale_if_error 300s

    # Enable/disable request collapsing
    collapse_requests true

    # Headers to always include in cache key (in addition to Vary)
    # Useful for forward_auth services where upstream doesn't set Vary
    extra_key_headers Remote-User Remote-Groups

    # Paths to never cache (glob patterns)
    bypass /api/auth/*
    bypass /api/stream/*

    # Paths with custom TTL overrides
    ttl_override /_astro/* 86400s
    ttl_override *.woff2 86400s
}
```

### 3.14 Files to Create

```
wafctl/           (or a separate caddy plugin module)
  cache_proxy.go           — Caddy middleware: ServeHTTP, provisioning, Caddyfile parsing
  cache_store.go           — In-memory LRU cache store with byte accounting
  cache_singleflight.go    — Stdlib-only singleflight implementation
  cache_rfc.go             — RFC 9111 compliance: freshness, age, storeability, vary
  cache_revalidate.go      — Conditional revalidation, 304 handling, stale-while-revalidate
  cache_key.go             — Cache key construction and normalization
  cache_metrics.go         — Prometheus counters: hit/miss/stale/collapse/evict/bypass
  cache_proxy_test.go      — Table-driven tests with httptest
  cache_store_test.go      — LRU eviction, memory accounting, TTL expiry tests
  cache_rfc_test.go        — RFC compliance tests (storeability, freshness, age calc)
```

---

## 4. Phase 2 — Policy Engine Hot-Path Optimization

The policy engine evaluates rules on every request. Without a CDN absorbing
traffic, this is the throughput bottleneck.

### 4.1 Struct Field Ordering for Cache-Line Packing

CPU cache lines are 64 bytes on x86-64 and ARM64 (128 bytes on Apple M-series).
Hot fields (accessed on every rule evaluation) should be packed into the first
cache line.

**Current `RuleExclusion` layout (approximate):**

Fields are organized by logical grouping, not by access frequency. Hot fields
(`Type`, `Enabled`, `Conditions`) may span multiple cache lines along with
cold fields (`Description`, `Tags`, `CreatedAt`, `UpdatedAt`).

**Proposed layout — hot fields first:**

```go
type RuleExclusion struct {
    // --- Hot fields (first 64 bytes, 1 cache line) ---
    Type       string      // 16 bytes (string header) — first branch in eval
    ID         string      // 16 bytes — lookup/match
    Conditions []Condition // 24 bytes (slice header) — core evaluation
    Enabled    bool        // 1 byte + 7 padding
    // --- Cache line boundary ---
    // Cold fields — only touched on match/log/CRUD
    Priority    int
    Name        string
    Description string
    Action      string
    Tags        []string
    CreatedAt   time.Time
    UpdatedAt   time.Time
    // ... remaining fields
}
```

### 4.2 Cache-Line Padding on Atomic Counters

The `Store` and `AccessLogStore` structs have `atomic.Int64` generation counters
that are read on every cache check (hot read path) and written during eviction
(write path). If the counter shares a cache line with the `sync.RWMutex` or
the events slice header, reader goroutines cause false sharing.

```go
type Store struct {
    mu         sync.RWMutex  // 24 bytes
    events     []Event       // 24 bytes
    eventFile  string        // 16 bytes = 64 bytes total, likely 1 cache line
    maxAge     time.Duration
    geoIP      *GeoIPStore
    _          [64]byte         // explicit padding
    generation atomic.Int64     // now on its own cache line
}
```

The `[64]byte` pad forces `generation` onto a separate cache line, eliminating
false sharing between reader goroutines (checking generation for cache
invalidation) and writer goroutines (incrementing generation during eviction).

### 4.3 Per-Host Rule Index

Currently, every request evaluates every rule. A per-host index skips rules
that cannot match:

```go
type ruleIndex struct {
    byHost   map[string][]*RuleExclusion // exact host -> applicable rules
    byPath   map[string][]*RuleExclusion // exact path prefix -> rules
    wildcard []*RuleExclusion            // rules with no host/path condition
}

// Rebuild on rule change (deploy)
func buildIndex(rules []RuleExclusion) *ruleIndex { ... }

// Lookup: O(|matching rules|) instead of O(|all rules|)
func (idx *ruleIndex) rulesFor(host, path string) []*RuleExclusion {
    result := idx.wildcard
    if hostRules, ok := idx.byHost[host]; ok {
        result = append(result, hostRules...)
    }
    for prefix, pathRules := range idx.byPath {
        if strings.HasPrefix(path, prefix) {
            result = append(result, pathRules...)
        }
    }
    return result
}
```

With 20 services and rules scoped per-service, this can reduce per-request
evaluation from O(N) to O(N/20) or better.

### 4.4 Pre-Compiled Regex Conditions

The existing `boundedRegexCache` (256 entries, LRU) compiles regexes lazily.
Move compilation to rule load time:

```go
type CompiledCondition struct {
    Condition                    // embedded original
    compiledRegex *regexp.Regexp // pre-compiled if operator is regex/matches
    lowerValue    string         // pre-lowercased for case-insensitive compare
}

func compileConditions(conds []Condition) []CompiledCondition {
    result := make([]CompiledCondition, len(conds))
    for i, c := range conds {
        result[i].Condition = c
        if c.Operator == "regex" || c.Operator == "matches" {
            result[i].compiledRegex, _ = regexp.Compile(c.Value)
        }
        result[i].lowerValue = strings.ToLower(c.Value)
    }
    return result
}
```

### 4.5 Condition Ordering by Selectivity

Evaluate cheap conditions first to short-circuit expensive ones:

1. **Method** (string equality, ~1ns)
2. **Host** (string equality, ~1ns)
3. **Path prefix** (strings.HasPrefix, ~5ns)
4. **IP match** (net.IP.Equal or CIDR, ~10ns)
5. **Header/cookie** (map lookup + string compare, ~20ns)
6. **Regex** (compiled regexp.Match, ~100ns-10us)
7. **Body** (read + match, ~1us+)

Sort conditions within each rule by selectivity tier at load time.

### 4.6 Allocation-Free Hot Path

Minimize allocations in the eval loop to reduce GC pressure:

- Use `sync.Pool` for scratch buffers (e.g., matched rule result slices).
- Compare `[]byte` directly where possible (avoid `string([]byte)`).
- Pre-allocate result slices with expected capacity.
- Use `strings.EqualFold` instead of `strings.ToLower` + `==`.
- Avoid `fmt.Sprintf` in hot path (use `strconv` or direct writes).

---

## 5. Phase 3 — Log Shipping (Disk-Free Ingestion)

**Current:** Caddy writes `combined-access.log` on disk. `AccessLogStore` and
`GeneralLogStore` tail the file every 5 seconds via seek + read.

**Problem:** In K8s, pods don't share a filesystem (unless using ReadWriteMany
PVCs, which add latency and complexity). Disk I/O is also a bottleneck under
high request rates.

**Proposed:** The policy engine plugin ships events directly to wafctl via
HTTP POST instead of writing to a log file. wafctl's `AccessLogStore.Load()`
is replaced by an HTTP receiver endpoint.

### 5.1 Event Shipping Endpoint

```
POST /internal/events
Content-Type: application/x-ndjson

{"timestamp":"...","host":"...","status":429,"policy_action":"rate_limit",...}
{"timestamp":"...","host":"...","status":403,"policy_action":"block",...}
```

- Batched: policy engine buffers events in memory and flushes every 1-2 seconds
  or when batch reaches 100 events.
- NDJSON format (same as current JSONL persistence).
- Internal-only endpoint, restricted to pod-local or cluster CIDR.

### 5.2 Fallback

Keep the file-tailing path as a fallback for Docker Compose / single-instance
deployments where shared disk is trivial. The log shipping mode is enabled via
environment variable (`WAFCTL_LOG_MODE=http` vs `WAFCTL_LOG_MODE=file`).

---

## 6. Phase 4 — WAF State Distribution

**Current:** `policy-rules.json` is written to disk by wafctl. The policy
engine plugin polls for mtime changes every 5 seconds.

**K8s options (in order of preference):**

### 6.1 ReadWriteMany PVC (Simplest)

All Caddy pods and wafctl mount the same PVC (NFS, EFS, Longhorn, etc.).
wafctl writes `policy-rules.json` once. All pods detect the mtime change
within their `reload_interval`.

- Zero code changes.
- Requires a storage class that supports RWX.
- Latency: up to `reload_interval` (5s) after deploy.

### 6.2 HTTP Config Sync

wafctl exposes `GET /internal/policy-rules.json`. Each Caddy pod polls this
endpoint instead of reading from disk. Uses `If-None-Match` / `ETag` to avoid
transferring unchanged data.

- Requires a small change to the policy engine plugin (HTTP fetch instead of
  file read).
- Works without any shared filesystem.
- Latency: up to poll interval.

### 6.3 Push-Based Sync

wafctl pushes to each Caddy pod's admin API after deploy. Requires pod
discovery (K8s API or DNS-based headless service).

- Lowest latency (immediate).
- Most complex (pod discovery, failure handling, retries).
- Best for production-grade deployment.

**Recommendation:** Start with 6.1 (RWX PVC) for initial K8s support. Migrate
to 6.2 (HTTP sync) if RWX is unavailable. Reserve 6.3 for production.

---

## 7. Phase 5 — K8s-Aware Load Balancing

### 7.1 Session Affinity

```yaml
apiVersion: v1
kind: Service
metadata:
  name: caddy-edge
spec:
  type: LoadBalancer
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 10800
  ports:
    - name: https
      port: 443
      targetPort: 443
    - name: http
      port: 80
      targetPort: 80
```

Same client -> same pod -> L1 cache hit rate maximized.

### 7.2 Pod Topology

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: caddy-edge
spec:
  replicas: 3
  template:
    spec:
      # Anti-affinity: spread pods across nodes
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app
                      operator: In
                      values: [caddy-edge]
                topologyKey: kubernetes.io/hostname
      containers:
        - name: caddy
          image: caddy-compose:latest
          resources:
            requests:
              memory: "512Mi"  # 256MB cache + 256MB working set
              cpu: "500m"
            limits:
              memory: "1Gi"
              cpu: "2"
          ports:
            - containerPort: 443
            - containerPort: 80
          volumeMounts:
            - name: waf-data
              mountPath: /data/waf
      volumes:
        - name: waf-data
          persistentVolumeClaim:
            claimName: waf-data-rwx
```

### 7.3 wafctl Sidecar Pattern

wafctl runs as a sidecar in each Caddy pod, or as a separate Deployment
with a Service for the dashboard/API. The sidecar pattern keeps wafctl
close to the policy engine for low-latency config writes and log shipping.

```yaml
      containers:
        - name: caddy
          image: caddy-compose:latest
          # ...
        - name: wafctl
          image: wafctl:latest
          env:
            - name: WAFCTL_LOG_MODE
              value: http
            - name: CADDY_LOG_ENDPOINT
              value: http://localhost:8080/internal/events
          volumeMounts:
            - name: waf-data
              mountPath: /data/waf
```

---

## 8. Phase 6 — Optional L2 Shared Cache

If per-pod L1 + sticky sessions don't achieve sufficient hit rates (measured
via Prometheus metrics), add a shared L2 layer.

### 8.1 Options

| Option | Latency | Complexity | Notes |
|--------|---------|-----------|-------|
| Redis / Valkey | ~0.5ms | Low | External StatefulSet. Serialization overhead. |
| Peer HTTP mesh | ~1-2ms | High | Pods query each other on L1 miss. Requires peer discovery. |
| tmpfs emptyDir | ~0.1ms | Very low | Only for pods on same node. |

### 8.2 Redis/Valkey Integration

If L2 is needed, a Redis sidecar or external service stores serialized
`CachedResponse` objects. On L1 miss, check L2 before hitting upstream.
On upstream fetch, write to both L1 and L2.

```
L1 miss -> L2 check -> L2 hit: deserialize, store in L1, serve
                     -> L2 miss: upstream fetch, store in L1 + L2, serve
```

**Note:** This breaks the zero-external-dependencies constraint. Defer to
Phase 6 only if metrics prove it necessary. For most deployments, L1 +
sticky sessions will be sufficient.

---

## 9. RFC Compliance Reference

### 9.1 RFC 9111 — HTTP Caching (Obsoletes RFC 7234)

| Section | Requirement | Implementation |
|---------|-------------|---------------|
| 2 | Cache key = method + target URI (minimum) | `cacheKey()` in `cache_key.go` |
| 3 | Storeability rules (no-store, private, Authorization) | `isStoreable()` in `cache_rfc.go` |
| 3.1 | Store all response headers (except Connection hop-by-hop) | `CachedResponse.Header` stores full header map |
| 3.5 | Shared cache MUST NOT use cached response to auth'd request without explicit permission | Auth check in `isStoreable()` |
| 4 | Reuse rules (fresh, stale-allowed, validated) | `getOrRevalidate()` in `cache_store.go` |
| 4.1 | Vary header secondary keys | Secondary key map in `cacheStore` |
| 4.2 | Freshness: s-maxage > max-age > Expires > heuristic | `freshnessLifetime()` in `cache_rfc.go` |
| 4.2.3 | Age calculation (apparent_age, corrected_age_value, resident_time) | `currentAge()` in `cache_rfc.go` |
| 4.2.4 | Stale responses: only when disconnected or explicitly permitted | `stale-while-revalidate` / `stale-if-error` |
| 4.3 | Conditional revalidation (If-None-Match, If-Modified-Since) | `addRevalidationHeaders()` in `cache_revalidate.go` |
| 4.3.4 | Freshen on 304 (update headers, recalculate freshness) | `freshenEntry()` in `cache_revalidate.go` |
| 4.4 | Invalidate on unsafe method success | `invalidateOnUnsafe()` in `cache_store.go` |
| 5.1 | Generate Age header on cached responses | Set in `serveFromCache()` |
| 5.2 | Parse and respect all Cache-Control directives | `parseCacheControl()` in `cache_rfc.go` |

### 9.2 RFC 9110 — HTTP Semantics

| Section | Requirement | Implementation |
|---------|-------------|---------------|
| 9.2.1 | Safe methods (GET, HEAD) — cacheable | Only cache GET/HEAD |
| 9.2.2 | Idempotent methods — safe for singleflight | Collapse GET/HEAD only |
| 9.2.3 | Methods and caching — GET is cacheable by default | Default storeability |
| 13.1.2 | If-None-Match (ETag validation) | Conditional revalidation |
| 13.1.3 | If-Modified-Since (timestamp validation) | Conditional revalidation |

### 9.3 RFC 5861 — Cache-Control Extensions for Stale Content

| Directive | Behavior | Implementation |
|-----------|----------|---------------|
| `stale-while-revalidate` | Serve stale, async revalidate | `getOrRevalidate()` async path |
| `stale-if-error` | Serve stale on 5xx/network error | `handleUpstreamError()` |

---

## 10. Security Considerations

### 10.1 Cache Poisoning (RFC 9111 Section 7.1)

**Risk:** An attacker sends a crafted request that causes the cache to store
a malicious response, served to other users.

**Mitigations:**
- Cache key always includes `Host` header (prevents host-header attacks).
- `Vary` headers are respected (prevents serving user A's response to user B).
- Only cache responses from the upstream (never from client-provided data).
- Normalize cache keys (sorted query params, lowercased host).
- Strip hop-by-hop headers before storing.

### 10.2 Timing Attacks (RFC 9111 Section 7.2)

**Risk:** Attacker measures response times to determine if a resource is cached
(revealing whether another user accessed it).

**Mitigations:**
- For privacy-sensitive services, disable caching or use per-user cache keys.
- The `extra_key_headers` directive allows including auth identity in the key.

### 10.3 Sensitive Information (RFC 9111 Section 7.3)

**Risk:** Cached responses containing sensitive data (session tokens, personal
info) served to wrong users.

**Mitigations:**
- Never cache responses with `Set-Cookie` headers.
- Never cache responses with `Cache-Control: private` or `no-store`.
- Never cache responses to requests with `Authorization` unless explicitly
  permitted by `public`, `must-revalidate`, or `s-maxage`.
- Log cache events (key, hit/miss, TTL) for audit.

### 10.4 Cache Key Splitting

**Risk:** Attacker reorders query parameters to create separate cache entries
for the same resource, diluting cache effectiveness.

**Mitigation:** `normalizeQuery()` sorts query parameters and values
canonically (already implemented as `normalizeCacheKey()` in `cache.go`).

### 10.5 Memory Exhaustion

**Risk:** Attacker sends requests for many unique URLs to fill the cache
with useless entries, evicting legitimate cached content.

**Mitigations:**
- Hard `max_memory` cap with LRU eviction.
- `max_object_size` prevents single large responses from consuming the cache.
- Rate limiting (policy engine) runs before the cache, blocking abusive clients.

---

## 11. Observability

### 11.1 Prometheus Metrics

```
# Cache operations
cache_proxy_requests_total{status="hit|miss|stale|bypass|error"} counter
cache_proxy_bytes_served_total{source="cache|upstream"} counter
cache_proxy_store_operations_total{result="stored|rejected|evicted"} counter

# Singleflight
cache_proxy_collapse_total counter           # requests that shared a result
cache_proxy_collapse_waiters histogram       # number of waiters per collapsed group

# Memory
cache_proxy_memory_bytes gauge               # current cache memory usage
cache_proxy_memory_limit_bytes gauge         # configured max_memory
cache_proxy_entries_count gauge              # number of cached entries

# Latency
cache_proxy_latency_seconds histogram{source="cache|upstream"}

# Revalidation
cache_proxy_revalidation_total{result="freshened|replaced|error"} counter
```

### 11.2 Cache-Status Response Header

Add a `Cache-Status` header to responses (per the emerging
`Cache-Status` HTTP field specification):

```
Cache-Status: caddy-edge; hit
Cache-Status: caddy-edge; fwd=miss
Cache-Status: caddy-edge; fwd=stale; fwd-status=304; collapsed
Cache-Status: caddy-edge; fwd=bypass; detail=websocket
```

### 11.3 Logging

Integration with the existing `log_append` mechanism:

```
log_append cache_status {http.vars.cache_proxy.status}
log_append cache_age {http.vars.cache_proxy.age}
log_append cache_key {http.vars.cache_proxy.key}
```

---

## 12. Open Questions

1. **Plugin boundary:** Should `cache_proxy` be a separate Caddy plugin module
   (in its own Go module/directory) or part of the existing policy engine
   plugin? Separate module is cleaner but adds build complexity.

2. **Fan-out streaming:** Phase 1 explicitly skips streaming collapsing (large
   responses bypass singleflight). Should Phase 2 or a future phase implement
   `io.TeeReader`-based fan-out for media streaming? Varnish and Nginx both
   do this, but it adds significant complexity.

3. **Purge API:** Should there be an explicit cache purge endpoint
   (`POST /api/cache/purge`) accessible from the wafctl dashboard? Useful for
   debugging and after deploys.

4. **Per-service cache config:** Should cache TTL, max-size, and enable/disable
   be configurable per-service (per `Host`) in the Caddyfile or via the wafctl
   API? This adds flexibility but also complexity.

5. **Cache warming:** On pod startup, the L1 cache is cold. Should we implement
   a cache warming mechanism (pre-fetch popular URLs from a manifest or from
   the previous pod's cache dump)?

6. **Compression interaction:** Caddy's `encode` directive (zstd, gzip) runs
   in the handler chain. Should the cache store compressed or uncompressed
   bodies? Storing compressed saves memory but complicates Vary handling
   (need to vary by `Accept-Encoding`).

---

## Implementation Priority

| Phase | What | Effort | Impact | Dependencies |
|-------|------|--------|--------|-------------|
| **1** | In-memory response cache + singleflight middleware | 2-3 weeks | Highest — eliminates redundant upstream requests, sub-ms cached responses | None |
| **2** | Policy engine hot-path optimization | 1 week | High — reduces per-request CPU cost | None |
| **3** | Log shipping (HTTP push) | 1 week | Medium — removes disk dependency for K8s | None |
| **4** | WAF state distribution (RWX PVC / HTTP sync) | 3-5 days | Medium — enables multi-pod deployment | Phase 3 |
| **5** | K8s manifests + sticky LB | 2-3 days | Medium — production K8s deployment | Phases 3-4 |
| **6** | L2 shared cache (Redis/Valkey) | 1-2 weeks | Low-Medium — only if L1 hit rates insufficient | Phase 1 metrics |

Phases 1-2 are pure Go, zero dependencies, single-process improvements that
work identically on Docker Compose and K8s. Start here.
