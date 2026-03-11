# PLAN.md — Policy Engine Roadmap

## Status Key

- [ ] Not started
- [~] In progress
- [x] Completed

---

## v0.6.1 — Client IP Fix (COMPLETED)

- [x] **Root cause**: `clientIP()` read `r.RemoteAddr` (raw TCP peer — Cloudflare proxy IP) instead of Caddy's `ClientIPVarKey` context variable (real client IP after `trusted_proxies` resolution)
- [x] **Impact**: All IP-based rules (IPsum blocklist, `ip_match`, `ip eq`) compared against CF edge IPs instead of real client IPs — never matched for CF-proxied traffic. Path/host-based rules (honeypot, allow) were unaffected.
- [x] **Fix**: Read `caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey)` first, fall back to `r.RemoteAddr` for non-Caddy contexts (unit tests)
- [x] **Tests**: 6 new tests — CaddyVar, CaddyVarNoPort, FallbackToRemoteAddr, EmptyCaddyVar, IPv6CaddyVar, IPBlockWithCaddyVar
- [x] **Confirmed**: Post-deploy, honeypot block log shows `195.240.81.42` (real IP) instead of `172.71.x.x` (CF proxy)

---

## v0.7.0 — Response Phase: CSP & Security Headers

### Problem

CSP headers are managed through 52 `import /data/caddy/csp/*` lines in the Caddyfile (26 services × 2 imports each: short name + FQDN). Changing any CSP policy requires regenerating `.caddy` files AND reloading Caddy. Security headers are baked into 4 snippet variants (`security_headers_base`, `_strict`, `_relaxed`, default) that are functionally identical.

### Goal

Move CSP and security header injection into the policy engine plugin. Changes hot-reload via mtime polling (5s) — no Caddy restart required.

### Current State (What Exists)

**Caddyfile CSP imports** (52 lines across 26 services):
```
import /data/caddy/csp/httpbun_csp*.caddy
import /data/caddy/csp/httpbun.erfi.io_csp*.caddy
```

**CSP generator** (`wafctl/csp_generator.go`): Produces single-line `header Content-Security-Policy "..."` directives per service. Modes: `set` (overwrite), `default` (only if upstream didn't send), `none` (no-op). Supports `report_only` variant.

**CSP store** (`wafctl/csp.go`): `CSPConfig` with `global_defaults`, per-service `CSPServiceConfig` (mode, report_only, inherit, policy). Merge logic: non-empty override slices replace base; empty slices keep base. `upgrade_insecure_requests` is sticky.

**CSP data model**:
```
CSPConfig {
    enabled         *bool                        // nil = true (backward compat)
    global_defaults CSPPolicy                    // baseline for all services
    services        map[string]CSPServiceConfig  // per-service overrides
}

CSPServiceConfig {
    mode        string    // "set" | "default" | "none"
    report_only bool      // Content-Security-Policy-Report-Only
    inherit     bool      // merge on top of global_defaults
    policy      CSPPolicy
}

CSPPolicy {
    default_src, script_src, style_src, img_src, font_src, connect_src,
    media_src, frame_src, worker_src, object_src, child_src, manifest_src,
    base_uri, form_action, frame_ancestors   []string
    upgrade_insecure_requests                bool
    raw_directives                           string  // verbatim escape hatch
}
```

**Security headers snippet** (`(security_headers_base)` in Caddyfile):
```
Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
X-Content-Type-Options "nosniff"
Referrer-Policy "strict-origin-when-cross-origin"
Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
Cross-Origin-Opener-Policy "same-origin"
Cross-Origin-Resource-Policy "cross-origin"
X-Permitted-Cross-Domain-Policies "none"
-Server
-X-Powered-By
```

Used by all 26 services through 3 tier variants (strict/default/relaxed) that are currently identical.

**Plugin's current response capability**: Only sets headers via `w.Header().Set()` before `next.ServeHTTP()` or returning `caddyhttp.Error()`. No ResponseWriter wrapping exists yet.

### Design

#### JSON Schema Extension

Add `response_headers` to `PolicyRulesFile`:

```json
{
  "rules": [...],
  "rate_limit_config": {...},
  "response_headers": {
    "csp": {
      "enabled": true,
      "global_defaults": {
        "default_src": ["'self'"],
        "script_src": ["'self'", "'unsafe-inline'"],
        "style_src": ["'self'", "'unsafe-inline'"],
        "img_src": ["'self'", "data:"],
        "font_src": ["'self'", "data:"],
        "connect_src": ["'self'", "wss:"],
        "object_src": ["'none'"],
        "base_uri": ["'self'"],
        "frame_ancestors": ["'self'"],
        "upgrade_insecure_requests": true
      },
      "services": {
        "httpbun.erfi.io": {
          "mode": "set",
          "report_only": false,
          "inherit": true,
          "policy": {
            "script_src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"]
          }
        }
      }
    },
    "security": {
      "enabled": true,
      "headers": {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "cross-origin",
        "X-Permitted-Cross-Domain-Policies": "none"
      },
      "remove": ["Server", "X-Powered-By"],
      "per_service": {
        "immich.erfi.io": {
          "headers": { "Cross-Origin-Opener-Policy": "same-origin-allow-popups" }
        }
      }
    }
  }
}
```

#### Implementation Approach by CSP Mode

| Mode | Technique | Complexity |
|------|-----------|------------|
| `set` | `w.Header().Set("Content-Security-Policy", ...)` before `next.ServeHTTP()` | Simple — headers set before WriteHeader are included in response |
| `default` | Wrap `w` with `cspResponseWriter` that intercepts `WriteHeader()`, checks if upstream set CSP, injects if absent | Medium — requires ResponseWriter wrapper |
| `none` | No-op | None |
| `report_only` | Same as above but header name is `Content-Security-Policy-Report-Only` | Same |

Security headers are always `set` mode — simple pre-response `w.Header().Set()`.

Header removal (`-Server`, `-X-Powered-By`) requires the ResponseWriter wrapper to intercept `WriteHeader()` and call `w.Header().Del()` before the real write.

#### ResponseWriter Wrapper

```go
type responseHeaderWriter struct {
    http.ResponseWriter
    cspHeader     string // "" = no CSP to inject
    cspMode       string // "set" or "default"
    cspReportOnly bool
    removeHeaders []string
    wroteHeader   bool
}

func (rw *responseHeaderWriter) WriteHeader(code int) {
    if rw.wroteHeader {
        return
    }
    rw.wroteHeader = true

    // Remove unwanted upstream headers.
    for _, h := range rw.removeHeaders {
        rw.Header().Del(h)
    }

    // Inject CSP in "default" mode only if upstream didn't set it.
    if rw.cspMode == "default" && rw.cspHeader != "" {
        name := "Content-Security-Policy"
        if rw.cspReportOnly {
            name = "Content-Security-Policy-Report-Only"
        }
        if rw.Header().Get(name) == "" {
            rw.Header().Set(name, rw.cspHeader)
        }
    }

    rw.ResponseWriter.WriteHeader(code)
}
```

For `"set"` mode, CSP is injected pre-response (before `next.ServeHTTP()`) so no wrapper needed.

#### ServeHTTP Integration Point

After rule evaluation (block/allow/rate_limit) and before `next.ServeHTTP()`:

```go
// After rule evaluation, before passing to next handler:

// 1. Security headers (always "set" mode).
if pe.securityHeaders != nil && pe.securityHeaders.Enabled {
    cfg := pe.resolveSecurityHeaders(host)
    for k, v := range cfg.Headers {
        w.Header().Set(k, v)
    }
    // Removal headers need the wrapper (handled below).
}

// 2. CSP headers.
needsWrapper := false
var cspValue, cspMode string
var cspReportOnly bool
if pe.cspConfig != nil && pe.cspConfig.Enabled {
    svc := pe.resolveCSPService(host)
    if svc.Mode == "set" {
        name := "Content-Security-Policy"
        if svc.ReportOnly { name = "Content-Security-Policy-Report-Only" }
        w.Header().Set(name, svc.rendered)
    } else if svc.Mode == "default" {
        needsWrapper = true
        cspValue = svc.rendered
        cspMode = "default"
        cspReportOnly = svc.ReportOnly
    }
}

// 3. Wrap ResponseWriter if needed.
if needsWrapper || len(removeHeaders) > 0 {
    w = &responseHeaderWriter{
        ResponseWriter: w,
        cspHeader: cspValue, cspMode: cspMode,
        cspReportOnly: cspReportOnly,
        removeHeaders: removeHeaders,
    }
}

return next.ServeHTTP(w, r)
```

#### CSP Merge Logic (Port from wafctl)

Port `mergeCSPPolicy()` from `wafctl/csp.go`:
- Non-empty override slices **replace** base (not append)
- Empty slices keep base
- `upgrade_insecure_requests` is sticky (true in either → true in result)
- `raw_directives` replaced if non-empty in override

Pre-compile CSP strings at rule load time (not per-request):
```go
type compiledCSPConfig struct {
    services map[string]compiledCSPService // keyed by Host (FQDN)
    fallback compiledCSPService            // global defaults
}

type compiledCSPService struct {
    mode       string // "set", "default", "none"
    reportOnly bool
    rendered   string // pre-built CSP header value
}
```

The `rendered` string is built once at load time by joining directives. Per-request lookup is just a map access by Host header.

### Tasks

- [x] Add `ResponseHeaderConfig`, `CSPConfig`, `SecurityHeaderConfig` types to plugin
- [x] Implement CSP merge/inherit logic (port from `wafctl/csp.go`)
- [x] Pre-compile CSP strings at rule load time into `compiledCSPConfig`
- [x] Implement `responseHeaderWriter` wrapper for `"default"` mode and header removal
- [x] Add response header injection in `ServeHTTP()` (between rule eval and `next.ServeHTTP()`)
- [x] Add hot-reload support (recompile CSP on rules file mtime change)
- [x] Tests: CSP set/default/none modes, merge/inherit, report-only, security headers, header removal, per-service resolution (45 tests in plugin)
- [x] Update `wafctl/policy_generator.go` to emit `response_headers` section (`BuildPolicyResponseHeaders`)
- [x] Update wafctl CSP deploy handler to write to `policy-rules.json` when policy engine enabled
- [x] Remove 52 CSP import lines from Caddyfile
- [x] Remove `(security_headers_base)`, `(security_headers_strict)`, `(security_headers)`, `(security_headers_relaxed)` snippets
- [x] Remove per-service `import security_headers*` lines (26 sites)
- [x] Keep `wafctl/csp.go` store and API endpoints (frontend still uses them)
- [x] Remove `wafctl/csp_generator.go` — deleted file, moved needed functions to `csp.go`, legacy deploy path removed
- [x] Update AGENTS.md with new architecture
- [x] Add `SecurityHeaderStore` with 4 profiles (strict/default/relaxed/api), per-service overrides, validation, HTTP handlers
- [x] Add Security Headers UI (`SecurityHeadersPanel.tsx`) with profile presets, per-service overrides, preview, export/import
- [x] Add `/headers` page and nav link in dashboard
- [x] Add security headers API client (`security-headers.ts`) with 5 functions + types
- [x] Add security header store to backup/restore (6th config store)
- [x] Add security header store to health endpoint
- [x] Frontend tests for security-headers API client (11 tests)
- [x] Go tests for SecurityHeaderStore (15 test functions in `security_headers_test.go`)

### Migration Strategy

1. Deploy plugin v0.7.0 with response header support
2. Update wafctl to write CSP config into `policy-rules.json`
3. Verify CSP headers are correctly set via plugin (check response headers)
4. Remove CSP imports from Caddyfile one service at a time (or all at once if confident)
5. Remove security_headers snippets last

### What This Eliminates

| Before | After |
|--------|-------|
| 52 CSP import lines in Caddyfile | 0 |
| 26 `_csp.caddy` generated files | 0 (config lives in policy-rules.json) |
| 4 security_headers snippet variants | 0 (config in policy-rules.json) |
| 26 `import security_headers*` lines | 0 |
| Caddy reload for CSP changes | Hot-reload (5s mtime poll) |
| `csp_generator.go` file generation | Direct JSON emission |

---

## v0.8.0 — Anomaly Scoring Engine

### Problem

CRS uses cumulative anomaly scoring — each rule adds points, and only when the total exceeds a threshold is the request blocked. The policy engine currently only supports binary block/allow/rate_limit actions. To replace CRS, we need the same scoring model.

### Goal

Add a `detect` rule type that contributes to a per-request anomaly score. After all rules evaluate, compare against configurable thresholds. This is the foundation for all subsequent CRS rule porting.

### Design

#### New Rule Type: `detect`

```json
{
  "id": "custom-920001",
  "name": "Missing Accept header",
  "type": "detect",
  "enabled": true,
  "priority": 150,
  "severity": "NOTICE",
  "paranoia_level": 1,
  "tags": ["protocol-enforcement", "anomaly"],
  "conditions": [
    { "field": "header", "operator": "eq", "value": "Accept:", "transforms": ["lowercase"] }
  ],
  "group_operator": "and"
}
```

New fields on `PolicyRule`:
- `severity`: `"CRITICAL"` (5), `"ERROR"` (4), `"WARNING"` (3), `"NOTICE"` (2) — maps to score points
- `paranoia_level`: 1–4 — rule only evaluates if configured PL ≥ rule PL
- Both fields are only relevant for `type: "detect"`

#### Per-Request Score Accumulator

```go
type scoreAccumulator struct {
    inbound  int
    outbound int // reserved for response-phase (v0.9+)
    matched  []matchedRule // audit trail
}

type matchedRule struct {
    ruleID   string
    ruleName string
    severity string
    score    int
    field    string // which field matched
    value    string // matched value (truncated for logging)
}
```

#### Evaluation Flow (Extended 4-Pass Model)

```
Pass 1: block/honeypot rules (priority 100-130) → hard terminate on match
Pass 2: allow rules (priority 200-210) → set allow flag, continue
Pass 3: detect rules (priority 140-199) → accumulate scores
Pass 4: rate_limit rules (priority 300+) → always evaluate

After passes complete:
  - If accumulated inbound score > threshold → 403
  - Set Caddy vars: policy_engine.anomaly_score, policy_engine.matched_rules
  - Log score breakdown
```

Note: detect rules run between block and allow in priority space. Block rules still hard-terminate before scoring. Allow rules bypass scoring (allowed traffic isn't scored).

#### WAF Configuration in PolicyRulesFile

```json
{
  "rules": [...],
  "waf_config": {
    "paranoia_level": 2,
    "inbound_threshold": 10,
    "outbound_threshold": 10,
    "per_service": {
      "httpbun.erfi.io": {
        "paranoia_level": 1,
        "inbound_threshold": 15
      }
    }
  }
}
```

Pre-compiled at load time into a map for O(1) per-request lookup.

#### Severity-to-Score Mapping

| Severity | Score | CRS Equivalent |
|----------|-------|----------------|
| CRITICAL | 5 | Severity 2 |
| ERROR | 4 | Severity 3 |
| WARNING | 3 | Severity 4 |
| NOTICE | 2 | Severity 5 |

Matches the CRS scoring model exactly.

#### Caddy Variables Set on Scored Requests

```
policy_engine.anomaly_score = "12"          // total inbound score
policy_engine.anomaly_threshold = "10"      // configured threshold
policy_engine.matched_rules = "3"           // count of detect rules that fired
policy_engine.action = "detect_block"       // when score exceeds threshold
```

These appear in `log_append` for wafctl to parse and display in the dashboard.

### Tasks

- [x] Add `severity` and `paranoia_level` fields to `PolicyRule`
- [x] Add `scoreAccumulator` struct
- [x] Add `detect` rule type to `compileRule()` — skip if PL > configured
- [x] Extend `ServeHTTP()` evaluation loop with score accumulation pass
- [x] Add threshold check after all detect rules evaluate
- [x] Add `WafConfig` type to `PolicyRulesFile` with per-service overrides
- [x] Pre-compile WAF config at load time
- [x] Set Caddy variables for scored/blocked requests
- [x] Log score breakdown (rule IDs, severities, total)
- [x] Tests: single detect rule scoring, multiple rules cumulative, threshold blocking, per-service thresholds, paranoia level filtering, severity mapping
- [x] Update wafctl to generate `waf_config` section from existing `WAFConfig` store
- [x] Port existing heuristic bot rules (9100030, 9100033, 9100034) to `detect` type as proof-of-concept

**Shipped:** Plugin v0.8.0 (commit `6d45c85`), caddy 3.4.0-2.11.1, wafctl 2.5.0. 3 seeded PL1 heuristic detect rules, 37 e2e tests pass.

---

## v0.8.x — Transform Functions

### Problem

CRS rules apply transformations before pattern matching: `t:lowercase,t:urlDecodeUni,t:htmlEntityDecode`. Without transforms, attackers bypass regex patterns with encoding (e.g., `%3Cscript%3E` bypasses a literal `<script>` regex).

### Goal

Add a `transforms` field to `PolicyCondition` — an ordered list of transform functions applied to the extracted field value before operator evaluation.

### Design

```json
{
  "field": "args",
  "operator": "regex",
  "value": "<script",
  "transforms": ["urlDecode", "htmlEntityDecode", "lowercase"]
}
```

Transforms applied left-to-right. The transformed value is passed to `evalOperator()`.

#### Priority Transforms (Phase 1 — Covers ~90% of CRS Usage)

| Transform | Description | CRS Equivalent |
|-----------|-------------|----------------|
| `lowercase` | `strings.ToLower()` | `t:lowercase` |
| `urlDecode` | Decode `%XX` sequences | `t:urlDecode` |
| `urlDecodeUni` | Decode `%uXXXX` Unicode sequences + `%XX` | `t:urlDecodeUni` |
| `htmlEntityDecode` | Decode `&amp;`, `&#NN;`, `&#xHH;` | `t:htmlEntityDecode` |
| `normalizePath` | Collapse `/../`, `/./`, `//` | `t:normalizePath` |
| `normalizePathWin` | Same + backslash normalization | `t:normalizePathWin` |
| `removeNulls` | Strip `\x00` bytes | `t:removeNulls` |
| `compressWhitespace` | Collapse whitespace runs to single space | `t:compressWhitespace` |
| `removeWhitespace` | Strip all whitespace | `t:removeWhitespace` |

#### Extended Transforms (Phase 2)

| Transform | Description | CRS Equivalent |
|-----------|-------------|----------------|
| `base64Decode` | Standard base64 decode | `t:base64Decode` |
| `hexDecode` | Decode hex-encoded bytes | `t:hexDecode` |
| `jsDecode` | Decode JS escape sequences (`\xHH`, `\uHHHH`, `\n`, etc.) | `t:jsDecode` |
| `cssDecode` | Decode CSS escape sequences (`\HH`, `\HHHHHH`) | `t:cssDecode` |
| `utf8toUnicode` | Convert UTF-8 to Unicode code points | `t:utf8toUnicode` |
| `removeComments` | Strip `/* ... */` and `<!-- ... -->` | `t:removeComments` |
| `trim` | Strip leading/trailing whitespace | `t:trim` |
| `length` | Replace value with its string length | `t:length` |

#### Implementation

```go
type transformFunc func(string) string

var transforms = map[string]transformFunc{
    "lowercase":          strings.ToLower,
    "urlDecode":          urlDecode,
    "htmlEntityDecode":   htmlEntityDecode,
    "normalizePath":      normalizePath,
    "removeNulls":        removeNulls,
    "compressWhitespace": compressWhitespace,
    // ...
}

// In compileCondition():
for _, name := range cond.Transforms {
    fn, ok := transforms[name]
    if !ok {
        return cc, fmt.Errorf("unknown transform %q", name)
    }
    cc.transforms = append(cc.transforms, fn)
}

// In evalOperator() or matchCondition():
target := extractField(cc, r, pb)
for _, fn := range cc.transforms {
    target = fn(target)
}
result := evalOperator(cc, target)
```

Transform functions are resolved at compile time (rule load) — per-request cost is just the function calls on the extracted value.

### Tasks

- [x] Implement Phase 1 transforms (9 functions) as pure Go
- [x] Add `transforms` field to `PolicyCondition` and `compiledCondition`
- [x] Resolve transforms at compile time in `compileCondition()`
- [x] Apply transforms in `matchCondition()` before `evalOperator()`
- [x] Tests: each transform function unit test, transform chains, empty transforms (no-op)
- [x] Implement Phase 2 transforms (8 functions)
- [x] Update wafctl condition model and validation
- [x] Update frontend ConditionRow to allow transform selection

**Shipped:** Plugin v0.8.1 (commit `96336af`), caddy 3.5.0-2.11.1, wafctl 2.6.0. All 17 transforms (Phase 1 + Phase 2) in one release. 40 plugin tests, 19 wafctl tests, 6 e2e transform tests, 8 frontend tests. 43 total e2e tests pass. Frontend TransformSelect UI deployed (commit `cd92b11`).

---

## v0.9.0 — Multi-Variable Inspection + Aho-Corasick (COMPLETED)

### Problem

CRS rules inspect multiple variables simultaneously with the same pattern. Rule 941100 (XSS) checks `ARGS`, `ARGS_NAMES`, `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `REQUEST_HEADERS`, `REQUEST_FILENAME`, `REQUEST_BODY` — all with one rule. The current policy engine can only inspect one field per condition.

CRS also uses `@pmFromFile` (Aho-Corasick multi-pattern substring matching) against wordlists of thousands of patterns (SQL keywords, XSS vectors, command names). The current `in` operator does exact match only.

### Design

#### Multi-Variable Fields

New aggregate field names that iterate over collections:

| Field | Iterates Over | CRS Equivalent |
|-------|--------------|----------------|
| `all_args` | All query params + POST params (names + values) | `ARGS\|ARGS_NAMES` |
| `all_args_values` | All query params + POST params (values only) | `ARGS` |
| `all_args_names` | All query/POST param names | `ARGS_NAMES` |
| `all_headers` | All request header values | `REQUEST_HEADERS` |
| `all_headers_names` | All request header names | `REQUEST_HEADERS_NAMES` |
| `all_cookies` | All cookie values | `REQUEST_COOKIES` |
| `all_cookies_names` | All cookie names | `REQUEST_COOKIES_NAMES` |

When a condition uses an aggregate field, `matchCondition()` iterates all values and returns true if ANY value matches (OR semantics).

```go
func extractMultiField(cc compiledCondition, r *http.Request, pb *parsedBody) []string {
    switch cc.field {
    case "all_args":
        var vals []string
        for k, vs := range r.URL.Query() {
            vals = append(vals, k)
            vals = append(vals, vs...)
        }
        if pb != nil {
            for k, vs := range pb.getForm() {
                vals = append(vals, k)
                vals = append(vals, vs...)
            }
        }
        return vals
    // ...
    }
}
```

#### Aho-Corasick Phrase Match Operator

New operator: `phrase_match` — multi-pattern substring search.

```json
{
  "field": "all_args",
  "operator": "phrase_match",
  "value": "",
  "list_items": ["select", "union", "insert", "update", "delete", "drop", "exec", "execute"],
  "transforms": ["lowercase", "urlDecode"]
}
```

Implementation uses a compiled Aho-Corasick automaton:

```go
// In compiledCondition:
type compiledCondition struct {
    // ... existing fields ...
    acMatcher *ahocorasick.Matcher // compiled Aho-Corasick automaton
    isMulti   bool                 // true for aggregate fields
}

// Compilation:
case "phrase_match":
    patterns := cond.ListItems
    if len(patterns) == 0 {
        return cc, fmt.Errorf("phrase_match requires list_items")
    }
    cc.acMatcher = ahocorasick.CompileStrings(patterns)
```

**Performance**: Aho-Corasick is O(n + m) where n = input length, m = number of matches. Pattern count doesn't affect scan time. Compilation happens once at rule load.

**Dependency**: Pure Go implementation. Options:
- `github.com/cloudflare/ahocorasick` — Cloudflare's production library
- `github.com/petar-dambovaliev/aho-corasick` — already a transitive dependency via Coraza
- Hand-roll a minimal implementation to keep zero-dep policy

#### Numeric Comparison Operators

CRS uses numeric comparison for content-length checks, argument counts, etc.

| Operator | Description |
|----------|-------------|
| `gt` | Greater than (numeric) |
| `ge` | Greater than or equal |
| `lt` | Less than |
| `le` | Less than or equal |

With the `length` transform, this enables rules like "block if any arg name is longer than 100 chars":
```json
{ "field": "all_args_names", "operator": "gt", "value": "100", "transforms": ["length"] }
```

#### Count Pseudo-Field

New pseudo-field `count:<field>` returns the number of values in a collection:

```json
{ "field": "count:all_args", "operator": "gt", "value": "255" }
```

CRS equivalent: `&ARGS @gt 255` (max_num_args).

### Tasks

- [x] Implement aggregate field extraction (`all_args`, `all_headers`, `all_cookies`, etc.) — 7 fields: `all_args`, `all_args_values`, `all_args_names`, `all_headers`, `all_headers_names`, `all_cookies`, `all_cookies_names`
- [x] Implement multi-value matching loop in `matchCondition()` — OR semantics (match if ANY value matches), negate as NOT-ANY = ALL-NOT
- [x] Evaluate Aho-Corasick library options (zero-dep vs. external) — hand-rolled zero-dep in `ahocorasick.go` (~163 lines)
- [x] Implement `phrase_match` operator with compiled automaton — works on all string-searchable fields (aggregates + singles)
- [x] Implement numeric comparison operators (`gt`, `ge`, `lt`, `le`) — named fields use `Name:number` format
- [x] Implement `count:` pseudo-field — returns `strconv.Itoa(count)` of aggregate field values
- [ ] Implement `length` transform (deferred — not needed for v0.9.0 CRS porting)
- [x] Tests: multi-field iteration, phrase_match compilation and matching, numeric operators, count field — 318 plugin tests, 15 AC-specific tests + 3 benchmarks
- [x] Load testing: phrase_match with 1000+ patterns against realistic request data — 3.7µs per search, zero allocations
- [x] wafctl backend: validation for aggregate fields, phrase_match, numeric ops, count: prefix, ListItems on Condition struct
- [x] E2e tests: 5 new test functions (22 subtests) covering phrase_match, aggregates, count, numeric ops
- [x] Deployed: plugin v0.9.0, caddy 3.6.0-2.11.1, wafctl 2.7.0

---

## v0.9.x–v1.0 — Port CRS Rules

### Approach

Port CRS rules category by category, starting with highest value and lowest effort. Each category becomes a set of `detect` rules with appropriate severity, paranoia level, transforms, and conditions.

Rules are shipped as a default rule set in JSON format, loaded alongside user-defined rules. Users can disable/override individual rules via the existing exclusion system.

### Category Porting Order

| Priority | Category | Rule Range | Effort | Key Techniques Needed |
|----------|----------|------------|--------|-----------------------|
| 1 | Protocol Enforcement | 920xxx | Low | Header checks, byte range validation, numeric operators |
| 2 | Path Traversal / LFI | 930xxx | Low | Regex, normalizePath transform |
| 3 | HTTP Response Splitting | 921xxx | Low | Regex (CRLF detection) — already partially in post-crs.conf |
| 4 | Session Fixation | 943xxx | Low | Regex patterns |
| 5 | RCE | 932xxx | Medium | Regex + phrase_match against command wordlists |
| 6 | RFI | 931xxx | Medium | Regex for URL patterns in params |
| 7 | PHP/Node.js/Java Injection | 933, 934, 944xxx | Medium | Regex + phrase_match against function name wordlists |
| 8 | XSS | 941xxx | High | ~30 regex patterns + libinjection |
| 9 | SQLi | 942xxx | High | ~40 regex patterns + libinjection |

### What Each Category Needs

**Protocol Enforcement (920xxx)** — Low effort:
- Missing/invalid Content-Type → `header` field + `eq`/`regex`
- Invalid HTTP version → `http_version` field
- Byte range validation → new `validate_byte_range` operator or transform
- Content-Length checks → numeric operators
- Max arg count/length → `count:` pseudo-field + numeric operators
- Restricted file extensions → `uri_path` + `ends_with` or `regex`
- Restricted headers → `all_headers_names` + `in` / `phrase_match`

**Path Traversal / LFI (930xxx)** — Low effort:
- `../` patterns → `regex` with `normalizePath` transform
- OS file path patterns → `regex` on `all_args`
- Null byte injection → `regex` for `%00` / `\x00`

**RCE (932xxx)** — Medium effort:
- Pipe to command (`|id`, `|cat /etc/passwd`) → `regex` on `all_args`
- Backtick substitution → `regex`
- Command wordlist → `phrase_match` with ~100 command names
- Shell metacharacter detection → `regex`

**XSS (941xxx)** — High effort:
- ~30 regex patterns from CRS (event handlers, script tags, data URIs, etc.)
- Transform chains: `urlDecode` + `htmlEntityDecode` + `jsDecode` + `lowercase`
- `phrase_match` for XSS vector wordlists
- `@detectXSS` (libinjection) — Phase 5

**SQLi (942xxx)** — High effort:
- ~40 regex patterns from CRS (UNION SELECT, comment sequences, tautologies, etc.)
- Transform chains: `urlDecode` + `htmlEntityDecode` + `lowercase` + `removeComments`
- `phrase_match` for SQL keyword wordlists
- `@detectSQLi` (libinjection) — Phase 5

### Rule File Format

Default rules ship in a separate JSON file (e.g., `default-rules.json`) that's merged with user rules at load time. User rules take priority. Users can disable default rules by ID.

```json
{
  "default_rules": [
    {
      "id": "PE-920001",
      "name": "Missing Accept header",
      "type": "detect",
      "severity": "NOTICE",
      "paranoia_level": 1,
      "tags": ["protocol-enforcement", "920xxx"],
      "conditions": [
        { "field": "header", "operator": "eq", "value": "Accept:" }
      ],
      "description": "Real browsers always send an Accept header. Absence suggests automated tooling."
    }
  ]
}
```

### Existing Custom Rules to Port (Already Baked in pre-crs.conf / post-crs.conf)

These are the immediate candidates — they're already written as SecRules and just need translation to policy engine JSON:

| Rule ID | Description | Target Type |
|---------|-------------|-------------|
| 9100003 | XXE: DOCTYPE/ENTITY with SYSTEM/PUBLIC | `detect` CRITICAL |
| 9100006 | XXE: Parameter entity (`<!ENTITY %`) | `detect` CRITICAL |
| 9100010 | Pipe to shell command in ARGS | `detect` CRITICAL |
| 9100011 | Backtick command substitution | `detect` CRITICAL |
| 9100012 | CRLF injection in query string | `detect` CRITICAL |
| 9100013 | CRLF injection in headers | `detect` CRITICAL |
| 9100030 | Missing Accept header (heuristic) | `detect` NOTICE |
| 9100033 | Empty/missing User-Agent (heuristic) | `detect` WARNING |
| 9100034 | Missing Referer on non-API GET (heuristic) | `detect` NOTICE |

### Tasks

- [ ] Define default rule JSON schema and loading mechanism
- [ ] Port Protocol Enforcement rules (920xxx subset)
- [ ] Port LFI rules (930xxx subset)
- [ ] Port RCE rules (932xxx subset) — requires phrase_match
- [ ] Port existing custom rules (9100003, 9100006, 9100010-9100013)
- [ ] Port heuristic bot rules from pre-crs.conf to detect type
- [ ] Port XSS rules (941xxx subset) — requires transform chains
- [ ] Port SQLi rules (942xxx subset) — requires transform chains
- [ ] Ship scanner-useragents.txt equivalent as phrase_match data
- [ ] Ship generic-useragents.txt equivalent as phrase_match data

---

## v1.0+ — libinjection Integration

### Problem

CRS's most effective SQLi and XSS detection uses libinjection — a tokenizer-based approach that analyzes the syntactic structure of input rather than matching regex patterns. It's significantly more accurate than regex alone and harder to evade.

### Options

| Approach | Pros | Cons |
|----------|------|------|
| Pure Go port (`go-libinjection`) | No CGo, simple build | Needs validation against reference C implementation |
| CGo wrapper | Most accurate (uses reference C code) | Adds CGo build complexity, breaks `CGO_ENABLED=0` |
| Skip it | No additional dependency | Reduced detection accuracy for SQLi/XSS |

### Recommendation

Start with regex-only detection (CRS has ~40 SQLi and ~30 XSS regex rules that work without libinjection). Evaluate detection accuracy in production. Add `go-libinjection` if false negative rates are unacceptable.

### New Operators

| Operator | Description |
|----------|-------------|
| `detect_sqli` | libinjection SQL injection detection |
| `detect_xss` | libinjection XSS detection |

Usage:
```json
{
  "field": "all_args",
  "operator": "detect_sqli",
  "transforms": ["urlDecode", "htmlEntityDecode", "lowercase"]
}
```

### Tasks

- [ ] Evaluate `go-libinjection` accuracy against CRS test suite
- [ ] Implement `detect_sqli` operator
- [ ] Implement `detect_xss` operator
- [ ] Benchmark: latency impact per request with libinjection enabled
- [ ] Compare detection rates: regex-only vs. regex+libinjection

---

## Incremental Migration Strategy

The policy engine runs **alongside** Coraza during the entire transition. Each phase adds capabilities without removing Coraza.

| Phase | Policy Engine Handles | Coraza Still Handles |
|-------|----------------------|---------------------|
| v0.6.x | block, allow, honeypot, rate_limit | All CRS detection + scoring |
| v0.7.0 | + CSP headers, security headers | CRS detection + scoring |
| v0.8.0 | + anomaly scoring, heuristic bot detect rules | CRS detection (score comparison possible) |
| v0.8.x | + transform-resistant detection | CRS detection (for categories not yet ported) |
| v0.9.0 (current) | + multi-variable, phrase matching, numeric ops, count: | Remaining CRS categories |
| v0.9.x | + LFI, RCE, injection categories | XSS, SQLi (hardest categories) |
| v1.0 | + XSS, SQLi with libinjection | Nothing — Coraza can be removed |

At each phase, you can compare scores between the policy engine's `detect` rules and Coraza's CRS rules to validate detection parity before removing Coraza.

### Coraza Removal Checklist

Before removing Coraza entirely:

- [ ] All 11 CRS categories have equivalent `detect` rules
- [ ] Transform chains cover all evasion techniques CRS handles
- [ ] Phrase match wordlists cover CRS's `@pmFromFile` data
- [ ] libinjection or equivalent covers `@detectSQLi`/`@detectXSS`
- [ ] Anomaly scoring produces comparable scores to CRS for a representative request sample
- [ ] False positive rate is equal to or better than CRS
- [ ] False negative rate is equal to or better than CRS (validated against CRS test suite)
- [ ] Response-phase detection exists (outbound rules) if needed
- [ ] Audit logging captures equivalent detail to Coraza audit log

### What Full Coraza Removal Eliminates

| Component | Status |
|-----------|--------|
| `coraza-caddy` fork dependency | Removed |
| CRS v4 rule files (~4MB) | Removed |
| `coraza/pre-crs.conf`, `post-crs.conf` | Removed (rules ported to JSON) |
| `scanner-useragents.txt`, `generic-useragents.txt` | Removed (ported to phrase_match data) |
| `wafctl/generator.go` (SecRule generation, ~458 lines) | Removed |
| `wafctl/generator_helpers.go` (~187 lines) | Removed |
| `wafctl/waf_settings_generator.go` | Removed |
| `custom-pre-crs.conf`, `custom-post-crs.conf`, `custom-waf-settings.conf` | Removed |
| `order coraza_waf after policy_engine` in Caddyfile | Removed |
| `@needs_waf` / `@not_websocket` matcher blocks | Removed |
| Coraza audit log parsing (`logparser.go`) | Simplified (only access log needed) |
| SecRule exclusion types (12 types in AGENTS.md) | Simplified to policy engine types only |
| Docker image size (~30-40MB from Coraza + CRS) | Reduced |
| Caddy startup time (CRS rule compilation) | Faster |
| WebSocket bypass workaround | Removed (policy engine doesn't inspect upgraded connections) |
