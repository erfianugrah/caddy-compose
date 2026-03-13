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

## v0.7.0 — Response Phase: CSP & Security Headers (COMPLETED)

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

## v0.8.0 — Anomaly Scoring Engine (COMPLETED)

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

## v0.8.1 — Transform Functions (COMPLETED)

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

**Dependency**: Hand-rolled zero-dep Aho-Corasick in `ahocorasick.go` (~163 lines). 15 unit tests + 3 benchmarks. 3.7µs per search with 1000+ patterns, zero allocations.

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
- [x] Tests: multi-field iteration, phrase_match compilation and matching, numeric operators, count field — 318 plugin tests, 15 AC-specific tests + 3 benchmarks
- [x] Load testing: phrase_match with 1000+ patterns against realistic request data — 3.7µs per search, zero allocations
- [x] wafctl backend: validation for aggregate fields, phrase_match, numeric ops, count: prefix, ListItems on Condition struct
- [x] E2e tests: 5 new test functions (22 subtests) covering phrase_match, aggregates, count, numeric ops
- [x] Deployed: plugin v0.9.0, caddy 3.6.0-2.11.1, wafctl 2.7.0

**Note:** Frontend UI for aggregate fields, phrase_match, numeric ops, and count: was deferred — see [Deferred Work](#deferred-work) section.

---

## v0.10.0 — Default Rules Loading (COMPLETED)

### Problem

CRS-equivalent rules will ship as built-in detection rules with the Docker image. Need a mechanism to load these alongside user-defined rules, with user rules taking priority, and the ability to disable individual defaults.

### Design

- Separate `DefaultRulesFile` (ships at `/etc/caddy/default-rules.json`) vs user `RulesFile` (generated by wafctl at `/data/coraza/policy-rules.json`)
- `DefaultRulesFile` struct: `{ "rules": [...], "version": N }`
- `PolicyRulesFile` gains `DisabledDefaultRules []string` field
- `mergeDefaultAndUserRules()` combines: defaults first, user rules override by same ID, disabled IDs filtered out
- `loadDefaultRulesFile()` returns nil for missing file (not fatal — graceful degradation)
- Hot-reload watches both files via separate mtime timestamps; either file changing triggers full reload
- Inline `DefaultRules` field on `PolicyEngine` struct for testing without temp files

### Tasks

- [x] `DefaultRulesFile` Caddyfile directive + JSON config field
- [x] `DefaultRulesFile` struct for built-in rules JSON format
- [x] `DisabledDefaultRules` field on `PolicyRulesFile`
- [x] `mergeDefaultAndUserRules()` merge function
- [x] `loadDefaultRulesFile()` file loader (missing file = graceful nil)
- [x] Hot-reload watches both default and user rules files
- [x] Inline `DefaultRules` support for testing
- [x] 9 new test functions (18 subtests), 327 total plugin tests passing
- [x] Plugin committed as `d15dc39`, tagged `v0.10.0`, pushed to GitHub
- [x] Dockerfile updated: `@v0.9.0` → `@v0.10.0`
- [x] Caddyfile + test/Caddyfile.e2e: added `default_rules_file /etc/caddy/default-rules.json`
- [x] wafctl `PolicyRulesFile` struct: added `DisabledDefaultRules` field
- [x] Version bumps: caddy `3.7.0-2.11.1`, wafctl `2.8.0` (all 5 locations)
- [x] E2e smoke tests: 50 test functions (~180 subtests, 302s) all passing
- [x] Deployed to production, health verified, WAF deploy triggered

**Shipped:** Plugin v0.10.0 (commit `d15dc39`), caddy 3.7.0-2.11.1, wafctl 2.8.0. 327 plugin tests, 50 e2e test functions.

### v0.10.1 — Default Rules Content & Heuristic Dedup

- [x] Created `coraza/default-rules.json` with 9 rules (6 attack detect + 3 heuristic detect)
  - PE-9100003: XXE DOCTYPE/ENTITY (CRITICAL, PL1)
  - PE-9100006: XXE parameter entity (CRITICAL, PL1)
  - PE-9100010: Pipe to shell RCE (CRITICAL, PL1)
  - PE-9100011: Backtick substitution RCE (CRITICAL, PL1)
  - PE-9100012: CRLF in query string (WARNING, PL1)
  - PE-9100013: CRLF in headers (WARNING, PL1)
  - PE-9100030: Missing Accept Header (NOTICE, PL1)
  - PE-9100033: Missing User-Agent (WARNING, PL1)
  - PE-9100034: Missing Referer on Non-API GET (NOTICE, PL1)
- [x] Removed heuristic SecRules (9100030/33/34) from `coraza/pre-crs.conf`
- [x] Changed `migrateV3toV4` to no-op (detect rules no longer seeded in user store)
- [x] Added `migrateV4toV5` to remove previously-seeded heuristic detect rules from existing stores
- [x] Updated `currentStoreVersion` from 4 to 5
- [x] Fixed Caddyfile + test/Caddyfile.e2e paths to `/etc/caddy/coraza/default-rules.json`
- [x] Fixed 6 migration tests + added 3 new v5 migration tests
- [x] Updated e2e `TestPolicyEngineDetectMigrationSeedRules` for new behavior
- [x] Version bumps: caddy `3.8.0-2.11.1`, wafctl `2.9.0` (all 5/4 locations)
- [x] E2e smoke tests: 50 test functions all passing
- [x] Deployed to production, health verified, WAF deploy triggered

**Shipped:** caddy 3.8.0-2.11.1, wafctl 2.9.0. Default rules file with 9 rules live in production.

### v0.10.2 — Default Rule Override API

- [x] Created `wafctl/default_rules.go` — `DefaultRuleStore` with JSON merge overrides
  - `NewDefaultRuleStore(defaultsPath, overridesPath)` loads baked defaults + persisted overrides
  - `List()` returns all defaults with `is_default`, `has_override`, `override_fields` metadata
  - `Get(id)` single rule lookup with override applied
  - `SetOverride(id, json.RawMessage)` partial JSON merge (strips `id` field, persists)
  - `RemoveOverride(id)` revert to baked default
  - `GetOverriddenRules()` returns modified rules for policy-rules.json emission
  - `GetDisabledIDs()` returns IDs where `enabled: false` for `DisabledDefaultRules`
- [x] Added `ApplyDefaultRuleOverrides()` in `policy_generator.go` — appends overridden rules + sets `DisabledDefaultRules`
- [x] Wired `*DefaultRuleStore` through all 6 deploy paths (generateOnBoot, deployAll, handleDeploy, handleDeployRLRules, handleDeployCSP, handleDeploySecurityHeaders)
- [x] 4 new API endpoints: `GET /api/default-rules`, `GET /api/default-rules/{id}`, `PUT /api/default-rules/{id}`, `DELETE /api/default-rules/{id}/override`
- [x] Env vars: `WAF_DEFAULT_RULES_FILE`, `WAF_DEFAULT_RULES_OVERRIDES_FILE`
- [x] 24 unit tests in `default_rules_test.go` (store, generator integration, HTTP handlers)
- [x] Fixed SecurityHeadersPanel.tsx crash (React error #130 — `T` used as JSX components instead of className strings)
- [x] Version bumps: caddy `3.9.0-2.11.1`, wafctl `2.10.0` (all 5/4 locations)
- [x] E2e smoke tests: 50 test functions all passing
- [x] Deployed to production, health verified

**Shipped:** caddy 3.9.0-2.11.1, wafctl 2.10.0. Default rule override API live — no plugin changes needed (existing `mergeDefaultAndUserRules()` handles same-ID replacement).

### v0.10.3 — Scanner/Generic UA Default Rules + v6 Migration

- [x] Added 3 new default rules to `coraza/default-rules.json` (version 1 → 2):
  - PE-9100032: Scanner UA Block (`block` type, `phrase_match` with 30 scanner UA substrings from scanner-useragents.txt)
  - PE-9100035: Generic UA Anomaly (`detect` CRITICAL, `phrase_match` with 8 generic library UA substrings from generic-useragents.txt)
  - PE-9100036: HTTP/1.0 Anomaly (`detect` NOTICE, `http_version eq HTTP/1.0`)
- [x] Added `migrateV5toV6` — removes v1-seeded bot rules ("Scanner UA Block", "HTTP/1.0 Anomaly", "Generic UA Anomaly") from user store (now default rules)
- [x] Updated `currentStoreVersion` from 5 to 6
- [x] Fixed SecurityHeadersPanel.tsx crash (React error #130)
- [x] Updated 6 migration tests for v6 behavior (fresh install yields 8 ipsum rules, bot rules removed)
- [x] Added 3 new v6 migration unit tests
- [x] Added e2e test `TestDefaultRulesAPI` (verifies 12 rules including new scanner/generic)
- [x] Updated e2e `TestPolicyEngineDetectMigrationSeedRules` to also verify bot rule removal
- [x] Version bumps: caddy `3.10.0-2.11.1`, wafctl `2.11.0` (all 5/4 locations)

**Shipped:** caddy 3.10.0-2.11.1, wafctl 2.11.0. 12 default rules total (6 attack + 3 heuristic + 3 bot). Scanner/generic UA detection now via policy engine `phrase_match` (Aho-Corasick) instead of Coraza `@pmFromFile` SecRules.

### v0.10.4 — CRS 920xxx Protocol Enforcement Rules

First batch of CRS rule porting. These rules are part of the Coraza→policy engine migration — the policy engine is replacing Coraza entirely (see [Coraza Removal Checklist](#coraza-removal-checklist)), so every CRS category needs equivalent `detect` rules in `default-rules.json`.

During the transition, these rules dual-run alongside Coraza's CRS 920xxx rules. Both produce anomaly scores independently (Coraza via `tx.inbound_anomaly_score`, policy engine via `scoreAccumulator`). Once all CRS categories are ported and detection parity is validated, Coraza is removed.

- [x] Added 14 new Protocol Enforcement rules to `coraza/default-rules.json` (version 2 → 3, 26 rules total):

  **Header Validation (PL1):**
  - PE-920280: Request missing Host header (`header eq Host:` — empty value = missing, WARNING)
  - PE-920350: Host header is numeric IP (`host regex`, WARNING)
  - PE-920170: GET/HEAD request with body content (`method in GET|HEAD` + `header regex Content-Length:[1-9]`, WARNING)
  - PE-920180: POST request missing Content-Type (`method eq POST` + `header eq Content-Type:`, NOTICE)
  - PE-920160: Content-Length not numeric (`header regex Content-Length:[^0-9]`, CRITICAL)
  - PE-920210: Multiple/conflicting Connection header values (`header regex Connection:.*,.*`, WARNING)

  **Encoding Validation (PL1):**
  - PE-920270: Null byte in request arguments (`all_args regex (?:%00|\\x00)`, CRITICAL)
  - PE-920220: URL encoding abuse in path (`uri_path regex %(?![0-9a-fA-F]{2})`, WARNING)

  **Policy Enforcement (PL1, unless noted):**
  - PE-920430: HTTP version not allowed (`http_version regex ^HTTP/(?:0\\.9|1\\.0)$`, WARNING)
  - PE-920440: Restricted file extensions (`uri_path phrase_match` with 50 extensions + `lowercase` transform, CRITICAL)
  - PE-920450: Restricted HTTP headers (`all_headers_names phrase_match` with 8 headers + `lowercase` transform, WARNING)
  - PE-920300: Max args count exceeded (`count:all_args_names gt 255`, CRITICAL)
  - PE-920310: Argument name too long (`all_args_names` + `length` transform + `gt 100`, CRITICAL)
  - PE-920311: Argument value too long (`all_args_values` + `length` transform + `gt 400`, CRITICAL, **PL2**)

- [x] All 14 rules use plugin capabilities verified from source:
  - `header` field `Name:value` split correctly extracts header name for `r.Header.Get()`, regex applied to header value
  - `length` transform on multi-value fields (`all_args_names`, `all_args_values`) applies per-value via `isMulti` iteration
  - `count:` pseudo-field returns `strconv.Itoa(len(values))`, compared via `gt` numeric operator
  - `phrase_match` + `transforms` on aggregate fields works (transforms applied per-value before Aho-Corasick search)
- [x] Update e2e test `TestDefaultRulesAPI` expected count (12 → 26)
- [x] Version bumps: caddy `3.11.0-2.11.1`, wafctl `2.12.0`
- [x] E2e tests passing
- [x] Deployed to production

### v0.11.0 — CRS 930xxx/921xxx/943xxx: LFI, Protocol Attack, Session Fixation

Second batch of CRS rule porting. Three categories in one release — all low effort with well-understood patterns. 11 new rules bring the total to 37 default rules. `default-rules.json` version 3 → 4.

- [x] Added 11 new rules to `coraza/default-rules.json` (version 3 → 4, 37 rules total):

  **LFI / Path Traversal (930xxx) — 4 rules, all PL1 CRITICAL:**
  - PE-930110: Path traversal in arguments (decoded `../` sequences, `all_args regex` with `urlDecodeUni`+`normalizePath`+`removeNulls` transforms)
  - PE-930111: Path traversal in URI path (same pattern on `uri_path`, separate rule for clarity)
  - PE-930120: OS file access attempt (`all_args phrase_match` with 80 curated entries from CRS `lfi-os-files.data` — `.ssh/`, `.aws/`, `etc/passwd`, `proc/self`, SSH keys, cloud creds, etc. + `urlDecodeUni`+`normalizePathWin` transforms)
  - PE-930130: Restricted file access in URI (`uri_path phrase_match` with 55 curated entries from CRS `restricted-files.data` — `.git/`, `.env`, `wp-config.`, `Dockerfile`, `secrets.json`, Vite CVE paths, etc. + `urlDecodeUni`+`normalizePathWin` transforms)

  **Protocol Attack / HTTP Response Splitting (921xxx) — 5 rules, all PL1 CRITICAL:**
  - PE-921110: HTTP request smuggling (embedded method+version in args, `htmlEntityDecode`+`lowercase` transforms. CRS 921110)
  - PE-921120: HTTP response splitting (CRLF + response header names in args, `urlDecodeUni`+`lowercase` transforms. CRS 921120)
  - PE-921130: Embedded response body (CRLF + `http/N` or HTML tags in args, `htmlEntityDecode`+`lowercase` transforms. CRS 921130)
  - PE-921150: CRLF in argument names (`all_args_names regex [\r\n]`. CRS 921150)
  - PE-921200: LDAP injection (LDAP filter syntax + DN components in args, `htmlEntityDecode`+`lowercase` transforms. CRS 921200)

  **Session Fixation (943xxx) — 2 rules, all PL1 CRITICAL:**
  - PE-943100: Cookie setting via HTML (`document.cookie` + `http-equiv set-cookie` patterns in args. CRS 943100)
  - PE-943120: Session ID param without referer (AND condition: `all_args_names phrase_match` 14 session param names + `referer eq ""`. CRS 943110/943120 merged)

  **Skipped (with rationale):**
  - 921140: CRLF in headers — already covered by PE-9100013
  - 921160: CRLF in arg names — similar to PE-921150
  - 921190: CRLF in path — covered by PE-920220 + PE-9100012
  - 921240: Apache mod_proxy — Apache-specific, not relevant to Caddy
  - 921250: Old cookie V1 — edge case, low value
  - 921421: Body processor bypass — Coraza-specific, not applicable to policy engine
  - 943110: Session ID + off-domain referer (chained) — requires cross-field chain comparison, merged into PE-943120

- [x] Updated e2e test `TestDefaultRulesAPI` (expected 26 → 37, spot checks for all 3 categories)
- [x] Version bumps: caddy `3.12.0-2.11.1`, wafctl `2.13.0` (all 5+4 locations)
- [x] E2e tests passing
- [x] Deployed to production

### v0.11.1 — Critical bugfix: RE2 regex + broken default rule + e2e hardening

**Root cause**: PE-920220 used PCRE negative lookahead `(?!...)` which Go's RE2 regex engine rejects. The policy engine compiles ALL rules at load time — if ANY regex fails, the ENTIRE rule set is rejected. This meant the plugin ran with 0 rules since v0.10.4, breaking ALL policy engine features (block, allow, rate limit, detect, response headers, CSP).

**Fixes:**
- [x] PE-920220 regex: `%(?![0-9a-fA-F]{2})` → `%(?:$|[^0-9a-fA-F]|[0-9a-fA-F](?:$|[^0-9a-fA-F]))` (RE2-compatible equivalent)
- [x] Removed PE-920280 (Request missing Host header): Go's `net/http` server always strips Host from `r.Header` and puts it in `r.Host`, so `header:Host eq ""` fires on EVERY request. HTTP/1.1 requests without Host are rejected with 400 by Go before middleware runs. Rule is dead code. 37 → 36 default rules.
- [x] E2e `browserTransport`: injects `User-Agent` and `Accept` headers on bare requests. Without these, default detect rules (PE-9100030 Missing Accept, PE-9100033 Missing UA, PE-9100034 Missing Referer) accumulated anomaly scores exceeding the default threshold of 5, causing all test requests to be blocked.
- [x] E2e `not_in_list` safe list updated to include the new UA string
- [x] E2e rule count assertions updated (37 → 36)
- [x] `TestBlocklistRefresh` added: downloads real IPsum data, verifies 8 managed lists, >1000 blocked IPs, waits for hot-reload
- [x] Version bumps: caddy `3.12.1-2.11.1`, wafctl `2.13.1`
- [x] All tests passing: 1425 Go + 340 frontend + full e2e suite
- [x] Deployed to production (2026-03-11)

---

## Deferred Work

Accumulated technical debt and planned improvements. Items marked DONE were completed
in the deep cleanup + frontend features sprint (commits `df3aa3a`, `0213932`).

### Frontend — Dashboard UI

| Feature | Status | Notes |
|---------|--------|-------|
| ~~`detect` exclusion type~~ | **DONE** | Wired in policy/constants.ts |
| ~~`severity` + `detect_paranoia_level` fields~~ | **DONE** | Via CRS rules page |
| ~~`detect_block` event type~~ | **DONE** | EventTypeBadge, overview cards |
| ~~Aggregate fields (`all_args`, `all_headers`, etc.)~~ | **DONE** | 10 aggregate fields in ConditionBuilder |
| ~~`phrase_match` operator~~ | **DONE** | Wired with list_items conversion |
| ~~`list_items` on Condition~~ | **DONE** | PipeTagInput populates list_items for phrase_match |
| ~~Numeric operators (`gt`/`ge`/`lt`/`le`)~~ | **DONE** | On response_status + count: fields |
| ~~`count:` pseudo-field prefix~~ | **DONE** | 7 count: fields with numeric operators |
| ~~Default rules list + disable/enable UI~~ | **DONE** | RulesPanel.tsx (now at /rules/crs) |
| ~~Policy rule position indicator~~ | **DONE** | Tooltip "Rule #N of M" on globalIdx cell |
| ~~Move to top / Move to bottom buttons~~ | **DONE** | ArrowUpToLine/ArrowDownToLine in PolicyEngine |
| ~~Matched data fields overflow UI~~ | **DONE** | TruncatedCode component |
| ~~Create Exception fails for detect_block~~ | **DONE** | Smart action defaulting + isWafEvent fix |

### Frontend — Pending UI Work (pre-deploy)

#### Overview Stat Card Taxonomy

**Problem:** The "BLOCKED" stat card mixes `detect_block` (CRS scoring) with `policy_block`
(policy engine explicit blocks). The "POLICY" card lumps all policy actions into one number.
After nuking legacy JSONL files, old Coraza `blocked` events will never appear — the only
event types are: `detect_block`, `logged`, `policy_block`, `policy_allow`, `policy_skip`,
`rate_limited`.

**Design:** Dynamic stat cards driven by event type + tags, not a hardcoded set of 4.

The existing `tag_counts` array on the summary API already provides flexible per-tag
aggregation. Stat cards should work the same way — auto-generated from distinct event
types present in the time window, with color and icon mapping per type. Custom actions
added in the future automatically get their own card.

**Proposed card taxonomy (current event types):**

| Card | Event Type | Color | Description |
|------|-----------|-------|-------------|
| Security Events | (total) | green | All events combined |
| CRS Blocked | `detect_block` | pink | CRS anomaly threshold exceeded |
| Rate Limited | `rate_limited` | yellow | 429 responses |
| Policy Block | `policy_block` | rose | Explicit blocks (honeypot, country, IPsum) |
| Policy Allow | `policy_allow` | emerald | WAF bypass for trusted traffic |
| Policy Skip | `policy_skip` | emerald | Specific rules skipped |
| Logged | `logged` | blue | CRS detected but below threshold |

Cards with zero count can be hidden or shown dimmed. Future custom action types
would auto-appear as new cards.

**Backend changes:**
- [x] `waf_summary.go`: Split `detect_block` out of `totalPolicyBlock` into `totalDetectBlock`
- [x] `models.go`: Add `DetectBlocked int json:"detect_blocked"` to `SummaryResponse`
- [x] `models.go`: `PolicyBlocked` only counts `policy_block` (not `detect_block`)
- [x] Per-hour/service/client breakdowns: add `detect_block` field alongside existing `policy_block`
- [x] Nuke legacy `blocked` field → `total_blocked` rename across full stack (commit `6381245`)

**Frontend changes:**
- [x] `SummaryData`: Add `detectBlocked` field
- [x] `OverviewDashboard.tsx`: Replace hardcoded 4 cards with dynamic card generation from `STAT_CARD_DEFS`
- [x] Timeline chart: Add `detect_block` as separate series
- [x] Per-service/client breakdowns: Show detect_block separately from policy_block
- [x] Color mapping: Add `detect_block` to `ACTION_COLORS` and `ACTION_LABELS`

#### TypeScript Errors (pre-commit)

- [x] `SecurityHeadersPanel.tsx:318` — `Property 'name' does not exist on type 'ServiceDetail'`.
  The `fetchServices()` API returns objects without a `name` field; the component accesses `.name`
  when it should use the map key or a different field. (Fixed — `tsc --noEmit` passes clean.)
- [x] `eventPrefill.test.ts:123,129,135,141` — `Type 'string' is not assignable to type 'EventType'`.
  Test fixtures use plain string literals for `event_type`; need `as const` or cast to `EventType`.
  (Fixed — `tsc --noEmit` passes clean.)

#### Dead Code Cleanup

- [x] Delete `SettingsPanel.tsx` — no page imports it after settings→rules merge. The reused
  sub-components (`settings/SettingsFormSections.tsx`, `settings/AdvancedSettings.tsx`,
  `settings/ServiceSettingsCard.tsx`, `settings/constants.tsx`) are imported directly by
  `RulesOverview.tsx` and remain alive.

#### E2e Test Fixes (pre-deploy)

- [x] `test/e2e/smoke_test.go:279-282` — `TestAPIEndpoints/CRS_Autocomplete` subtests the
  removed `/api/crs/autocomplete` endpoint. Either remove the subtest or point it at the
  replacement endpoint.
- [x] `test/e2e/smoke_test.go:341-345` — `TestDeployPipeline` creates an exclusion with
  `type: "skip_rule"` which may no longer be valid after Coraza removal. Update to a
  policy-engine-compatible type (`allow`, `block`, `detect`).
- [x] `RuleHits` panic — `AccessLogStore.RuleHits()` panicked with `index out of range [23]
  with length 0` when an event referenced a rule name not in the current rules list. The
  zero-value `RLRuleHitStats` has `Sparkline: nil`. Fixed by initializing a fresh entry
  for orphaned rule names. Regression test added in `rl_handlers_test.go`.
- [x] CRS regression gating — `TestCRSRegression` now skips unless `CRS_REGRESSION=1` env
  var is set. Without this, the 3925-test CRS suite blocks all `t.Parallel()` smoke tests
  (Go runs all sequential tests before releasing parallel ones), causing 600s timeouts.

#### E2e Test Runtime Optimization (post-deploy)

**Problem:** Full smoke suite takes ~600s. 44 sequential mutating tests run one-by-one,
each with generous sleep waits. The biggest time sinks:

| Source | Cost | Count | Total |
|--------|------|-------|-------|
| `setCRSv7TestConfig` + `restoreCRSv7TestConfig` | 10s+10s | 5 tests | ~100s |
| `verifyDetectBlockEvent` event tailing sleep | 12s | 5 tests | ~60s |
| Policy engine hot-reload sleep (8s) | 8s | ~10 deploys | ~80s |
| Rate limit window recovery | 22s | 1 test | ~22s |
| Other deploy + sleep waits | 2-3s | ~15 | ~40s |

**Fixes (in priority order):**

- [ ] **Share CRSv7 config across tests** — `setCRSv7TestConfig` + `restoreCRSv7TestConfig`
  each take ~10s (deploy + 8s hot-reload wait). All 5 CRSv7 tests use the same config.
  Instead: set once, run all 5, restore once. Saves ~80s.
- [ ] **Reduce hot-reload sleep from 8s to 6s** — plugin polls every 5s, so 6s is safe.
  Saves ~20s across all deploy waits.
- [ ] **Reduce event tailing sleep** — 12s is very conservative. `WAF_TAIL_INTERVAL` is 5s,
  so 7s should be sufficient. Or better: poll the events API until the sentinel appears
  (retry loop with 500ms intervals, 10s timeout). Saves ~25s.
- [ ] **Group mutating tests that share config** — tests that use the same WAF config
  (e.g., all detect scoring tests) can share one setup/teardown cycle.
- [ ] **Target: <300s** for the full smoke suite (currently ~600s).

#### Rules Page Restructure (PARTIALLY DONE)

**Done:**
- [x] `/rules` → overview with WAF settings + CRS ruleset card + backup/restore (`RulesOverview.tsx`)
- [x] `/rules/crs` → CRS rules grouped by PL with collapsible sections + sortable columns (`RulesPanel.tsx`)
- [x] Settings page deleted (`settings.astro` removed), nav link removed from `DashboardLayout.astro`
- [x] Settings sub-components reused in RulesOverview (ModeSelector, SensitivitySettings, etc.)
- [x] Astro file-based routing: `src/pages/rules/index.astro` + `src/pages/rules/crs.astro`

**Pending:**
- [ ] CRS rules: Pagination per PL section (PL1 has ~160 rules — needs page size selector + page controls)
- [x] CRS rules: Bulk actions — checkbox column, select all, bulk toolbar (enable/disable/severity/reset)
- [x] CRS rules: Bulk action API — `POST /api/default-rules/bulk` with `{ ids, action: "override"|"reset", override }` + tests
- [ ] CRS rules: Global PL controls on section headers — each PL section header should have:
  - PL-level enable/disable toggle (disable all rules at this PL)
  - Anomaly score threshold display/edit (leverages WAF engine settings via policy engine)
  - These controls map to the existing `WAFConfig` (paranoia_level, inbound_threshold) but
    presented at the ruleset level as an abstraction — "PL2: Enabled | Threshold: 10"
  - Changing PL toggle updates `paranoia_level` in WAFConfig; changing threshold updates
    `inbound_threshold` (or per-PL thresholds if we add blocking_paranoia_level support)

#### Policy Engine Bugs

- [x] Tags input missing from Create Rule quick actions form — Edit Rule (Advanced) has the
  Tags field but Create Rule (Quick Actions) does not. Both should show the tag input.
  Location: `PolicyForms.tsx` quick action forms for Allow/Block/Detect

#### Policy Engine Bulk Actions

- [x] Checkbox column for multi-select
- [x] Select all in current filter / page
- [x] Bulk action toolbar (enable/disable/delete with confirmation)
- [x] Bulk action API — `POST /api/exclusions/bulk` with `{ ids, action: "enable"|"disable"|"delete" }` + tests

#### Comprehensive Form / API Audit (pre-deploy) — DONE

Review ALL forms across the dashboard for consistency, missing fields, and broken states:

- [x] Policy Engine: Create Rule (Quick Actions) — tags input already present, all fields match Edit Rule
- [x] Policy Engine: Edit Rule (Advanced) — all condition fields, operators, transforms verified working
- [x] CRS Rules: Override form — severity/PL/enabled toggles save correctly
- [x] Rate Limits: Rule form — all key types, actions, conditions verified
- [x] CSP: Directive editor — all source types, modes, inherit behavior verified
- [x] Security Headers: Profile editor — profile inheritance, per-service overrides verified
- [x] Managed Lists: CRUD — type validation, item format per type verified
- [x] Settings (now in Rules): WAF config — mode, paranoia, thresholds, per-service overrides verified
- [x] Backup/Restore — export/import round-trip for all 6 config stores verified
- [x] API type consistency — all frontend types match Go struct JSON tags; fixed `RawEvent.request_id` gap
- [x] Error handling — fixed 5 silently swallowed errors (OverviewDashboard events, IPLookupPanel pagination, RateAdvisorPanel load, ManagedListsPanel stats/check)

### Backend — wafctl API

| Feature | Description | Effort |
|---------|-------------|--------|
| ~~Default rules list API~~ | **DONE v0.10.2** | |
| ~~Default rules disable API~~ | **DONE v0.10.2** | |
| IP lookup managed-list check | Show which managed lists contain a given IP during `/api/lookup/{ip}` | Low |
| Default rules bulk API | `POST /api/default-rules/bulk` — batch override for CRS rules bulk actions | Medium |
| Exclusions bulk API | `POST /api/exclusions/bulk` — batch enable/disable/delete for policy engine bulk actions | Medium |

### Architecture — UI Bundling into wafctl — DONE

Dashboard moved from Caddy image to wafctl sidecar. Changes:

- [x] Dockerfile: Removed `waf-dashboard` build stage and `COPY --from=waf-dashboard` from caddy image
- [x] wafctl/Dockerfile: Added `frontend` build stage, `COPY --from=frontend /build/dist/ /app/waf-ui/`
- [x] wafctl `main.go`: Added `uiFileServer` handler for `/` (configurable via `WAF_UI_DIR`)
- [x] wafctl `ui_server.go`: MPA file server with try_files semantics (exact → path/index.html → 404.html), path traversal rejection, no SPA catch-all
- [x] Caddyfile: Replaced `root * /etc/caddy/waf-ui` + `file_server` with single `reverse_proxy` to wafctl
- [x] E2E Caddyfile updated: `:8081` block now proxies to wafctl
- [x] Tests: `ui_server_test.go` — exact file, root index, directory routes, 404, path traversal, Web Cache Deception prevention

### Plugin — WebSocket / HTTP Upgrade Support

When Coraza is removed (v1.0), the `@not_websocket` Caddyfile bypass goes away. Currently WebSocket connections bypass both Coraza and the policy engine via:

```
@not_websocket {
    not header Connection *Upgrade*
    not header Upgrade websocket
}
route @not_websocket {
    coraza_waf { ... }
}
```

The policy engine's `responseHeaderWriter` (used for CSP `default` mode and security header removal) wraps `http.ResponseWriter`. If the wrapper doesn't implement `http.Hijacker`, WebSocket upgrades will fail with `NS_ERROR_WEBSOCKET_CONNECTION_REFUSED` — the same issue the coraza-caddy fork fixed with its `hijackTracker`.

**Two-phase approach:**

**Phase 1 (pre-Coraza removal):** The `@not_websocket` bypass is still in the Caddyfile, so WebSocket traffic never hits either engine. No action needed yet, but the `responseHeaderWriter` should still implement `http.Hijacker` for correctness when CSP `default` mode is active.

**Phase 2 (post-Coraza removal, v1.0):** Remove `@not_websocket` bypass. The policy engine must:
- [x] Implement `http.Hijacker` on `responseHeaderWriter` — delegates to underlying `ResponseWriter` if it implements `Hijacker`
- [x] Implement `http.Flusher` on `responseHeaderWriter` — required for SSE streams
- [x] `Unwrap()` already present for Caddy's interface detection chain
- [ ] Decide: should `detect` rules evaluate on WebSocket upgrade requests? The initial HTTP upgrade request is a normal HTTP request that could carry attack payloads in headers/query params. CRS currently does NOT inspect it (bypassed by `@not_websocket`). Options:
  - **Inspect upgrade request** (stricter) — evaluate rules normally, only skip response-phase logic after hijack
  - **Skip entirely** (current behavior) — maintain backward compat, WebSocket traffic is never scored
- [ ] Test: WebSocket connections work through the policy engine, CSP `default` mode doesn't break upgrades

**Effort:** Low for Phase 1 (just implement the interface). Medium for Phase 2 (needs design decision on upgrade request inspection + integration testing).

### CRS Sync — Automatic Policy List Updates

Default rules ship with hardcoded `list_items` from CRS 4.23.0 (restricted extensions, headers, etc.). These values change between CRS releases. A periodic sync mechanism should fetch updates directly from the CRS GitHub repository.

**Source:** `https://raw.githubusercontent.com/coreruleset/coreruleset/main/crs-setup.conf.example`

**Values to sync** (CRS `tx.*` variables → default rule `list_items`):
- `tx.restricted_extensions` → PE-920440
- `tx.restricted_headers` → PE-920450
- `tx.allowed_methods` → (future rule)
- `tx.allowed_request_content_type` → (future rule)
- `tx.allowed_http_versions` → PE-920430

**Design:**
- wafctl `CRSSyncStore` — fetches `crs-setup.conf.example`, parses `setvar:'tx.*=...'` directives
- Periodic refresh (configurable, default weekly via `WAF_CRS_SYNC_INTERVAL`)
- Applies diffs via `DefaultRuleStore.SetOverride()` (JSON merge pattern)
- Logs when values change, optionally triggers auto-deploy
- Same pattern as IPsum blocklist refresh (`onRefresh` callback → `onDeploy` callback)
- Env vars: `WAF_CRS_SYNC_ENABLED` (default `false`), `WAF_CRS_SYNC_INTERVAL` (default `168h`), `WAF_CRS_SYNC_URL`
- Stores last-synced CRS version + hash in `/data/crs-sync-state.json`

**Effort:** Medium (parser + store + periodic goroutine + deploy integration)

### Unified Event ID

Currently every request can generate multiple unrelated IDs across subsystems:

| Subsystem | ID Source | Format | Example |
|-----------|----------|--------|---------|
| Caddy | `{http.request.uuid}` | UUID | `a1b2c3d4-e5f6-4789-abcd-0123456789ab` |
| Coraza audit log | `transaction.id` | Opaque hex | `AAA111BBB222` |
| wafctl access events | `ephemeralID()` | `rl-<millis>-<counter>` | `rl-1773299701769-362807` |
| wafctl WAF events | Coraza passthrough | Same as Coraza | `AAA111BBB222` |

The same HTTP request produces a Caddy UUID, a Coraza transaction ID, and an ephemeral
`rl-` ID — three different identifiers for one request. There is no single request ID to
correlate a security event in the events page with the same request in general logs.

**Goal:** One request = one ID everywhere (similar concept to Cloudflare's `cf-ray`). Caddy's
`{http.request.uuid}` is the natural choice — it's per-request, unique, and already
available to all middleware (policy engine, Coraza, access log, general log).

**Current state (partial):**
- Caddy already emits `{http.request.uuid}` as `X-Request-Id` header AND `log_append request_id`
- Access log events already parse `RequestID` from the log (via `accessLogRequestID()`)
- WAF events extract `RequestID` from the `X-Request-Id` request header (Coraza sees it)
- General log events carry `RequestID` from the same header
- BUT: `Event.ID` is a SEPARATE field from `Event.RequestID` — the "event ID" shown in
  the UI is the ephemeral `rl-` or Coraza transaction ID, not the Caddy UUID

**Design:**
- `Event.ID` = Caddy request UUID. One field, one source of truth.
- Drop `ephemeralID()` entirely — access log events use `RequestID` as their `Event.ID`
- WAF events (transitional, until Coraza removal): use `RequestID` (from `X-Request-Id`
  header) as `Event.ID`, fall back to Coraza transaction ID only if header is missing
  (shouldn't happen since the header is set in the Caddyfile before Coraza runs)
- `Event.RequestID` field: keep for backward compat but it equals `Event.ID` — eventually
  deprecate and remove in a breaking API version
- General logs already have `RequestID` — clicking a security event can jump to the
  general log entry for the same request (cross-reference by ID)
- Frontend: event detail panel shows the request ID prominently; "View in General Logs" link
  filters by `request_id=<event_id>`

**Migration:**
- Existing JSONL events on disk have old-format IDs — these are fine, they age out
  naturally via `WAF_EVENT_MAX_AGE` (90 days). No backfill needed.
- API consumers see UUID-format IDs going forward. The `rl-` prefix disappears.

**Tasks:**
- [x] wafctl: `RateLimitEventToEvent()` — uses `rle.RequestID` as `Event.ID`, falls back to `ephemeralID()`
- [x] wafctl: `parseEvent()` — uses `X-Request-Id` header as `Event.ID`, falls back to `tx.ID`
- [x] wafctl: Updated tests — unified request ID assertions in `TestParseEvent_RequestID`, `TestRateLimitEventToEvent_RequestID`, `TestAccessLogStoreRequestID_PropagatedToEvent`
- [ ] wafctl: Remove `ephemeralID()` and `ephemeralCounter` once Coraza is fully removed (v1.0)
- [ ] Frontend: Show unified request ID prominently in event detail, add "View in General Logs" cross-link
- [x] E2e: `TestPolicyBlockEvent_RequestContext` verifies non-`rl-` event ID

**Effort:** Low-Medium. The plumbing exists; this is mostly wiring `RequestID` into `Event.ID`.

### Full Request Context for Policy Engine Events

Policy engine events (block, allow, rate_limit, detect_block) arrive via the Caddy access
log. Unlike Coraza's audit log — which includes the complete request payload (all headers,
body, args, response headers) — the access log only contains what Caddy logs by default
plus `log_append` fields. This means policy engine events are missing:

| Data | Coraza Had It | Policy Engine Has It | Source |
|------|:---:|:---:|--------|
| Request headers (all) | Yes | No | Audit log part B |
| Request body | Yes | No | Audit log part I |
| Request args (parsed) | Yes | No | Audit log part C |
| Response headers (all) | Yes | Partial (`resp_headers`) | Caddy logs selected |
| Matched rule details | Yes | Yes (v0.11.0) | `policy_detect_matches` |
| Anomaly score | Yes | Yes | `policy_anomaly_score` |
| Client IP, method, URI, UA | Yes | Yes | Standard access log fields |

**Impact:** The event detail panel for policy engine events shows only basic request
info (method, URI, client, status, user-agent). No request headers, no body, no args.
For investigating why a rule fired, operators need the full request context — especially
headers (which trigger many CRS rules like restricted headers, missing Host, etc.).

**Design — Plugin-side header capture:**

The policy engine plugin already has access to the full `*http.Request`. When a request
matches any rule (block, detect, rate_limit), the plugin can serialize the request headers
and body excerpt into Caddy variables for `log_append`:

- `{http.vars.policy_engine.request_headers}` — JSON-serialized request headers (all)
- `{http.vars.policy_engine.request_body}` — first N bytes of request body (capped,
  same 13 MiB limit as existing body reading, but truncated for logging — e.g., 8 KB)

These are only populated for requests that actually trigger a rule action (not every
request — that would bloat access logs). The plugin already reads the body when
`needsBody` is true; for header capture there's zero overhead since `r.Header` is
already available.

**Alternatively — selective header capture:** Only emit headers for block/detect_block
events (not allow/rate_limit) to keep log volume reasonable. Or emit a configurable
subset (e.g., all request headers minus large Cookie values).

**wafctl changes:**
- `AccessLogEntry` gets `PolicyRequestHeaders` field (parsed from log_append JSON)
- `RateLimitEvent` gets `RequestHeaders` field, propagated through `RateLimitEventToEvent()`
- `Event` already has `RequestHeaders`, `RequestBody`, `RequestArgs` fields from Coraza — just wire them up

**Caddyfile changes:**
- Add `log_append policy_request_headers {http.vars.policy_engine.request_headers}`
- Add `log_append policy_request_body {http.vars.policy_engine.request_body}` (optional)

**Frontend changes:**
- Event detail panel already renders headers/body/args when present — no UI changes needed
- Policy engine events will show the same rich detail as Coraza events once the data flows through

**Tasks:**
- [x] Plugin: `serializeRequestHeaders()` — JSON-serializes `r.Header` with 500-char truncation per value
- [x] Plugin: `captureRequestContext()` — sets `policy_engine.request_headers` + `policy_engine.request_body` vars
- [x] Plugin: Wired into block/honeypot (line 527) and detect_block (line 645) emit paths
- [x] Plugin: Body excerpt capture from `parsedBody.raw` (only if already read for body conditions)
- [x] Plugin: 7 new tests — header serialization, truncation, block/detect_block capture, allow/below-threshold don't capture
- [x] Caddyfile: Added `log_append policy_request_headers` + `log_append policy_request_body` to `(site_log)`
- [x] E2e Caddyfile: Same log_append additions
- [x] wafctl: `parsePolicyRequestHeaders()` + `RequestHeaders`/`RequestBody` on `RateLimitEvent`
- [x] wafctl: Wired through access log parsing and `RateLimitEventToEvent()` → `Event.RequestHeaders`/`RequestBody`
- [x] wafctl: 5 new tests (propagation, parse, empty, invalid JSON)
- [x] E2e: `TestPolicyBlockEvent_RequestContext` — full pipeline test
- [ ] Frontend: Already renders `request_headers` when present — no changes needed

**Effort:** Medium. Plugin changes are straightforward (serialize `r.Header`). Main risk is
log volume — full headers per blocked request could add 1-2 KB per event line. At typical
block rates (<100/day for legitimate traffic) this is negligible.

### Recommended Order

**Revised 2026-03-12**: Manual porting replaced by automated CRS converter. Added unified event ID and request context.

1. ~~Port existing custom rules → `default-rules.json`~~ — **DONE** (v0.10.1, proof of concept)
2. ~~Port Protocol Enforcement (920xxx)~~ — **DONE** (v0.10.4, 14 rules)
3. ~~Port LFI + Response Splitting + Session Fixation~~ — **DONE** (v0.11.0)
4. ~~Port RCE (932xxx)~~ — **DONE** (v0.12.0, 11 rules)
5. ~~Matched payload observability~~ — **DONE** (plugin v0.11.0, per-condition match detail)
6. ~~Unified Event ID~~ — **DONE** (wafctl 2.15.0, Caddy UUID as Event.ID)
7. ~~Full request context for policy engine events~~ — **DONE** (plugin v0.11.0, request headers + body capture)
8. **Event detail parity + PE- prefix removal** — **IN PROGRESS** (see below)
9. **Build CRS auto-converter** (`tools/crs-converter/`) — replaces all remaining manual porting
10. **Add missing plugin features** (transforms, operators, condition enhancements) — parallel with 9
11. **Run converter + validate against CRS regression tests** — validates correctness
12. Frontend catch-up sprint (request ID cross-links to general logs) — can happen in parallel
13. Remove Coraza from Docker image (v1.0)

### Event Detail Parity + Rule ID Cleanup (step 8)

**Problem:** Deployed v0.11.0 revealed several gaps vs Coraza's event detail:

1. **PE- prefix on rule IDs** — Rules in `default-rules.json` use `PE-920350` format.
   These should just be `920350` to align with CRS numbering and work with skip_rule
   exclusions. The `PE-` prefix was added during manual porting but serves no purpose
   now that the policy engine is the primary WAF.

2. **Matched rules displayed twice** — The detect_block event detail shows matched rules
   in the "Policy Engine Match" summary section AND again in the "All Matched Rules"
   expandable section. Should only show in the expandable section with full detail.

3. **Missing highest severity rule summary** — Coraza events show a prominent block with:
   Rule ID, Message, Severity, Variable, Trigger value, Full Value. The detect_block
   event detail needs an equivalent "Highest Severity Rule" summary.

4. **Create Exception doesn't pre-fill rule IDs** — `MatchedRule.ID` is `int` (always 0
   for PE rules since IDs are strings like `PE-920350`). The eventPrefill extracts
   `matched_rules[].id` and gets nothing useful. Need a `Name` string field.

5. **Missing per-rule human-readable message** — Coraza shows "Found User-Agent associated
   with security scanner". PE rules show "PE-9100034 (NOTICE, score 2)" which is a
   formatted msg string, not the description. Need to include the rule description.

**Tasks:**
- [x] Remove `PE-` prefix from all rule IDs in `default-rules.json` (done — CRS auto-converter
  generated 254 clean-ID rules, superseding the old 45 manually-ported PE- rules)
- [x] Update plugin tests that reference PE- IDs (plugin repo uses clean IDs)
- [x] Add `Name string` field to `MatchedRule` model in wafctl (already present)
- [x] `parseDetectRulesDetail()`: store rule ID string in `Name`, strip `PE-` for backward compat
- [x] `enrichMatchedRulesWithDetails()`: also set `Name` from detectMatchEntry
- [x] Frontend `MatchedRuleInfo`: add `name` field (already present)
- [x] Frontend `EventDetailPanel`: remove doubled matched rules display (dedupe by `rule_id`)
- [x] Frontend `EventDetailPanel`: add highest severity rule summary for detect_block
- [x] Frontend `EventDetailPanel`: show rule name + description in expandable section
- [x] Frontend `eventPrefill`: use `name` field for Create Exception rule ID pre-fill
- [x] Update wafctl tests, frontend tests, e2e tests (backward compat tests in place)

---

## v0.9.x–v1.0 — Automated CRS Conversion + Coraza Removal

### Decision Record (2026-03-11)

Manual rule porting is error-prone, slow, and doesn't scale. Instead of hand-writing
policy engine rules one category at a time, we will:

1. **Build an automated CRS-to-PolicyEngine converter** that parses CRS `.conf` files
   directly from the `coreruleset/coreruleset` GitHub repo and outputs `default-rules.json`
2. **Add matched payload observability** to the policy engine so detect events have the
   same detail as Coraza audit logs (variable name, matched value, rule message, tags)
3. **Import libinjection** as a Go dependency for `@detectSQLi`/`@detectXSS` operators
4. **Validate using CRS's own regression test suite** (315 YAML test files, ~2500+ test cases)
5. **Remove Coraza entirely** once parity is confirmed

The existing 45 hand-ported rules in `default-rules.json` (920xxx, 921xxx, 930xxx, 932xxx,
943xxx, plus heuristic bot rules) will be superseded by the auto-converter output. The
hand-ported rules served as proof-of-concept for the rule format and scoring system.

### Why Not Keep Coraza

Coraza provides rich detection with excellent observability, but has fundamental problems:

| Issue | Impact |
|-------|--------|
| `@pm` uses Aho-Corasick substring match | `/admin` matches `/administrator` — security bug |
| `.conf` file generation + Caddy reload | 10+ second reload with CRS compilation; any rule change needs full cycle |
| SecRule language is write-only | Chained rules, `skipAfter`, `ctl:` quirks make debugging painful |
| Dual-engine complexity | Two WAF engines in the request path, two config formats, two reload mechanisms |
| WebSocket `@not_websocket` bypass needed | Coraza's deep `rwInterceptor` wrapping breaks hijack |
| ~30-40MB added to Docker image | CRS rules + Coraza engine |

The policy engine already handles allow/block/rate_limit with correct exact-match semantics,
hot-reloads via mtime polling (5s, no Caddy restart), and preserves rate limit counter state
across reloads. Extending it to cover detection is the natural path.

---

### Coraza Full Feature Inventory

Everything below must be replicated, explicitly deferred, or confirmed unnecessary.

#### Operators (28 registered, 15 used by CRS)

| Operator | CRS Rules | Plugin Status | Converter Action |
|----------|-----------|---------------|------------------|
| `@rx` | 295 | `regex` operator ✅ | Direct map |
| `@lt` | 182 | Not needed | Paranoia gating — handled by `paranoia_level` field |
| `@eq` | 48 | Not needed | TX variable checks — handled by scoring system |
| `@ge` | 42 | Not needed | Threshold checks — handled by scoring system |
| `@pmFromFile` | 21 | `phrase_match` ✅ | Inline file contents as JSON array |
| `@gt` | 12 | Not needed | Numeric checks — handled by scoring system |
| `@within` | 9 | Not needed | CRS config checks (allowed methods, etc.) |
| `@endsWith` | 7 | `ends_with` ✅ | Direct map |
| `@validateByteRange` | 6 | **NEEDED** | New `validate_byte_range` operator |
| `@pm` | 6 | `phrase_match` ✅ | Split space-separated patterns into array |
| `@streq` | 5 | `eq` ✅ | Direct map (macro expansion not needed — static values) |
| `@contains` | 4 | `contains` ✅ | Direct map |
| `@ipMatch` | 2 | `ip_match` ✅ | Direct map |
| `@detectSQLi` | 2 | **NEEDED** | Import `corazawaf/libinjection-go` |
| `@detectXSS` | 2 | **NEEDED** | Import `corazawaf/libinjection-go` |
| `@beginsWith` | 0 | `begins_with` ✅ | Available (unused by CRS) |
| `@unconditionalMatch` | 0 | N/A | Used by `SecAction` — not a detection rule |
| `@le`, `@rbl`, `@inspectFile`, `@restpath`, `@geoLookup`, `@noMatch`, `@validateUrlEncoding`, `@validateUtf8Encoding`, `@validateNid`, `@pmFromDataset`, `@ipMatchFromFile`, `@ipMatchFromDataset` | 0 | N/A | Unused by CRS — skip |

**New operators needed**: `validate_byte_range`, `detect_sqli`, `detect_xss` (3 total).

**Operators NOT needed**: `@lt`, `@eq`, `@ge`, `@gt`, `@within` — these are used for CRS
internal flow control (paranoia gating via `TX:DETECTION_PARANOIA_LEVEL`, anomaly threshold
checks via `TX:BLOCKING_INBOUND_ANOMALY_SCORE`). The policy engine handles paranoia levels
via the `paranoia_level` field on each rule, and anomaly scoring via the built-in severity
→ score → threshold system. The converter skips these flow-control rules entirely.

#### Operator Negation (`!@`)

Any operator can be negated with `!@` prefix. The policy engine needs a `negate: true`
field on conditions. Currently not implemented — **NEEDED** for ~15 CRS rules that use
`!@rx`, `!@eq`, `!@within`, etc.

#### Variables (81 supported, ~30 used by CRS detection rules)

**Request-phase — already in plugin:**

| SecRule Variable | Plugin Field | Named | Multi-value |
|------------------|-------------|-------|-------------|
| `ARGS` | `all_args_values` | `args:Name` | ✅ |
| `ARGS_NAMES` | `all_args_names` | — | ✅ |
| `ARGS_GET` | — | **NEEDED** | ✅ |
| `ARGS_POST` | — | **NEEDED** | ✅ |
| `REQUEST_COOKIES` | `all_cookies` | `cookie:Name` | ✅ |
| `REQUEST_COOKIES_NAMES` | `all_cookies_names` | — | ✅ |
| `REQUEST_HEADERS` | `all_headers` | `header:Name` | ✅ |
| `REQUEST_HEADERS_NAMES` | `all_headers_names` | — | ✅ |
| `REQUEST_URI` | `path` | — | Single |
| `REQUEST_FILENAME` | `uri_path` | — | Single |
| `REQUEST_BASENAME` | — | **NEEDED** | Single |
| `REQUEST_LINE` | — | **NEEDED** | Single |
| `QUERY_STRING` | `query_string` | — | Single |
| `REQUEST_METHOD` | `method` | — | Single |
| `REQUEST_PROTOCOL` | `http_version` | — | Single |
| `REMOTE_ADDR` | `ip` | — | Single |
| `SERVER_NAME` | `host` | — | Single |
| `REQUEST_BODY` | `body` | — | Single |
| `REQUEST_HEADERS:User-Agent` | `user_agent` | — | Single |
| `REQUEST_HEADERS:Referer` | `referer` | — | Single |
| `REQUEST_HEADERS:Content-Type` | `content_type` | — | Single |
| `REQUEST_HEADERS:Content-Length` | `content_length` | — | Single |
| `REQUEST_HEADERS:Cf-Ipcountry` | `country` | — | Single |

**Request-phase — needed for CRS coverage:**

| SecRule Variable | Needed For | Priority |
|------------------|-----------|----------|
| `ARGS_GET` / `ARGS_POST` | Some CRS rules target GET-only or POST-only args | Medium |
| `REQUEST_BASENAME` | File extension checks (920440) | Medium |
| `REQUEST_LINE` | Full request line inspection | Low |
| `XML:/*` / `XML://@*` | XML body attack detection (XXE, etc.) | Medium |
| `FILES` / `FILES_NAMES` | File upload rules (922xxx) | Medium |
| `MULTIPART_STRICT_ERROR` | Multipart attack detection | Medium |
| `REQBODY_ERROR` | Body parse error detection | Low |
| `ARGS_COMBINED_SIZE` | Request size limits | Low |
| `REQUEST_BODY_LENGTH` | Body size enforcement | Low |

**Response-phase — deferred (Phase 2):**

| SecRule Variable | CRS Rules | Notes |
|------------------|-----------|-------|
| `RESPONSE_STATUS` | ~14 rules | Outbound anomaly scoring |
| `RESPONSE_HEADERS` | ~14 rules | Info leakage detection |
| `RESPONSE_BODY` | ~100+ rules | Data leakage (SSN, CC, error messages, web shells) |
| `RESPONSE_CONTENT_TYPE` | ~5 rules | MIME type enforcement |

Response-phase detection is a significant architectural addition (requires intercepting the
response body before it's sent to the client). Deferred to Phase 2 of Coraza removal.

**Variables NOT needed (CRS internal flow control):**

`TX` (handled by scoring system), `MATCHED_VAR`/`MATCHED_VARS` (observability — see below),
`RULE` (metadata — embedded in rule definition), `UNIQUE_ID` (transaction correlation —
use Caddy request ID), `DURATION`, `HIGHEST_SEVERITY`, `ENV`, time variables, GEO (handled
by `country` field via CF header / MMDB), persistent collections (IP, SESSION — not
implemented in Coraza either).

#### Variable Mechanics to Support

| Mechanic | CRS Usage | Plugin Status |
|----------|-----------|---------------|
| Named access (`:key`) | Extensive | ✅ for `header:`, `cookie:`, `args:` |
| Regex key (`:/pattern/`) | ~20 rules | **NEEDED** — `header:/^X-/` syntax |
| Count prefix (`&`) | ~30 rules | **NEEDED** — `count:args` or similar |
| Variable negation (`\|!VAR:key`) | ~40 rules | **NEEDED** — exclude specific args/headers |
| Pipe-separated multi-var (`ARGS\|COOKIES`) | All detection rules | ✅ via multi-value fields |

#### Transforms (30 unique functions, 20 used by CRS)

| Transform | CRS Uses | Plugin Status |
|-----------|----------|---------------|
| `urlDecodeUni` | 135 | ✅ |
| `lowercase` | 45 | ✅ |
| `jsDecode` | 37 | ✅ |
| `htmlEntityDecode` | 35 | ✅ |
| `utf8toUnicode` | 31 | ✅ |
| `removeNulls` | 27 | ✅ |
| `cssDecode` | 23 | ✅ |
| `cmdLine` | 13 | **NEEDED** — Windows command anti-evasion |
| `replaceComments` | 9 | **NEEDED** — C-style `/* */` → space |
| `normalizePath` | 8 | ✅ |
| `removeWhitespace` | 7 | ✅ |
| `escapeSeqDecode` | 7 | **NEEDED** — ANSI C escape sequences |
| `compressWhitespace` | 5 | ✅ |
| `normalizePathWin` | 3 | ✅ |
| `length` | 3 | ✅ |
| `base64Decode` | 3 | ✅ |
| `sha1` | 2 | Low priority (hashing pipeline) |
| `hexEncode` | 2 | Low priority (hashing pipeline) |
| `removeCommentsChar` | 1 | Low priority |
| `none` | 422 | ✅ (implicit — empty transform list) |

**New transforms needed**: `cmdLine`, `replaceComments`, `escapeSeqDecode` (3 total).

**Low priority**: `sha1`, `hexEncode`, `removeCommentsChar` (used by 5 rules total,
mostly in PL2+ or correlation rules).

#### Matched Payload Observability (CRITICAL)

Coraza provides per-rule-match detail that the policy engine currently lacks:

| Data Point | Coraza Source | Current Plugin | Needed |
|------------|---------------|----------------|--------|
| Matched variable name | `MATCHED_VAR_NAME` (e.g., `ARGS:username`) | ❌ | ✅ |
| Matched value | `MATCHED_VAR` (e.g., `' OR 1=1--`) | ❌ | ✅ |
| Captured group | `TX:0` via `capture` action | ❌ | ✅ (regex capture group 0) |
| Rule message | `msg:'...'` action | Rule `name` field only | ✅ (add `message` field) |
| Rule tags | `tag:'...'` action (multiple) | `tags` field ✅ | ✅ |
| Source file | `@owasp_crs/REQUEST-932-*.conf` | Rule `id` prefix identifies category | Nice-to-have |
| Severity | `severity:'CRITICAL'` | `severity` field ✅ | ✅ |
| Score contribution | `setvar:tx.inbound_anomaly_score_pl1=+5` | Computed from severity ✅ | ✅ |
| logdata template | `logdata:'Matched Data: %{TX.0}...'` | ❌ | ✅ (formatted string) |

**Implementation in plugin**: When a detect rule's condition matches, capture:
- `matched_field`: the field that was evaluated (e.g., `all_args_values`, `header:User-Agent`)
- `matched_value`: the actual input value that was tested (truncated to 200 chars)
- `matched_data`: for regex, the portion that matched (capture group 0); for phrase_match,
  the matched phrase
- These go into a `MatchDetail` struct per condition, emitted alongside rule ID/severity/score

**Emission path**: Caddy vars → `log_append` → access log → wafctl parsing → frontend display.
Same path as current `policy_detect_rules` but with richer per-match data.

**Frontend target**: Match the Coraza event detail view — per rule: variable name (green),
matched value (yellow highlight), rule message, severity badge, source category. Plus the
anomaly score block with highest-severity rule breakdown.

#### Actions & Flow Control

| Action | CRS Usage | How Handled |
|--------|-----------|-------------|
| `block`/`deny`/`pass` | Every rule | Plugin: `detect` scores, `block` blocks — no per-rule disruptive action needed |
| `chain` | ~50 rules | Converter: multi-condition rule with `group_operator: "AND"` |
| `setvar` | 633 uses | Not needed — anomaly scoring built into severity system |
| `skipAfter`/`SecMarker` | 182 uses | Not needed — paranoia gating via `paranoia_level` field |
| `capture` + `TX:0-9` | 244 uses | Plugin captures regex group 0 for `matched_data` |
| `log`/`nolog`/`auditlog` | Every rule | All detect rules log; suppressible via `enabled: false` |
| `logdata` | ~300 rules | Plugin generates equivalent from `matched_field` + `matched_data` |
| `msg` | Every rule | Map to rule `description` (human-readable) |
| `tag` | Every rule | Map to rule `tags` array |
| `severity` | Every rule | Map to rule `severity` field |
| `phase` | Every rule | Converter filters: phase 1+2 = request (supported), phase 3+4 = response (deferred) |
| `ctl:` actions | ~40 rules | Not needed — runtime rule removal handled by user exclusions |
| `multiMatch` | ~15 rules | **NEEDED** — run operator at each transform stage, not just final |
| `expirevar` / `initcol` | ~5 rules | Not implemented in Coraza either — skip |

**New plugin features needed**: `multiMatch` equivalent (medium effort), `negate` on
conditions (low effort).

#### Phase Execution Model

Coraza processes rules in 5 phases. The policy engine runs once per request (equivalent
to phase 2 — after request body is available). Mapping:

| CRS Phase | Converter Action |
|-----------|------------------|
| Phase 1 (request headers) | Include — all header/URI variables available |
| Phase 2 (request body) | Include — body/args/files available |
| Phase 3 (response headers) | **Defer** — response-phase detection (Phase 2 of removal) |
| Phase 4 (response body) | **Defer** — response-phase detection |
| Phase 5 (logging) | Skip — correlation/logging rules, not detection |

#### CRS Internal Rules (Skip)

These CRS rules are flow control / bookkeeping, NOT detection. The converter skips them:

| Rule Range | Purpose | Why Skip |
|------------|---------|----------|
| 901xxx | Initialization — set TX variables, paranoia thresholds | Plugin has `paranoia_level` field |
| 905xxx | Common exceptions | Plugin has user exclusions |
| 949xxx | Blocking evaluation — compare score to threshold | Plugin's scoring system handles this |
| 959xxx | Outbound blocking evaluation | Deferred (response phase) |
| 980xxx | Correlation — cross-phase logging | Deferred |
| 999xxx | User exceptions placeholder | Plugin has user exclusions |

---

### CRS Auto-Converter Tool

#### Architecture

Standalone Go tool at `tools/crs-converter/` that reads CRS `.conf` files and outputs
`default-rules.json` for the policy engine plugin.

```
tools/crs-converter/
  main.go              — CLI: download CRS, run converter, output JSON
  parser.go            — SecRule tokenizer + AST builder
  parser_test.go       — Parser unit tests
  mapper.go            — Variable/operator/transform/severity mapping
  mapper_test.go       — Mapper unit tests
  converter.go         — AST → PolicyRule conversion, chain resolution
  converter_test.go    — Converter integration tests
  datafiles.go         — @pmFromFile resolver (reads .data files)
  report.go            — Gap analysis / coverage report
  go.mod               — Standalone module (no dependency on plugin or wafctl)
```

#### SecRule Parser

Parses CRS `.conf` files into a structured AST. Each `SecRule` becomes:

```go
type SecRule struct {
    Variables    []Variable      // ARGS|REQUEST_COOKIES|...
    Operator     Operator        // @rx, @pm, @pmFromFile, etc.
    Negated      bool            // !@ prefix
    Actions      []Action        // id, phase, msg, tag, severity, setvar, etc.
    Chain        *SecRule         // Next rule in chain (nil if no chain)
}

type Variable struct {
    Name       string   // ARGS, REQUEST_HEADERS, etc.
    Key        string   // :User-Agent, :/pattern/, etc.
    KeyIsRegex bool     // /pattern/ vs literal
    IsCount    bool     // & prefix
    IsNegation bool     // ! prefix (exclusion)
}

type Operator struct {
    Name    string   // rx, pm, pmFromFile, detectSQLi, etc.
    Value   string   // Pattern, filename, etc.
    Negated bool     // !@ prefix
}
```

**Parsing challenges**:
- Multi-line rules with `\` continuation — rejoin before tokenizing
- Quoted strings with escaped quotes — `msg:'it\'s a test'`
- Pipe-separated variables with negation — `ARGS|!ARGS:foo|REQUEST_COOKIES`
- XPath keys — `XML:/*` (colon starts XPath, not a simple key)
- `SecAction` (no variable/operator) — skip, these are setvar-only
- `SecMarker` — skip, these are skipAfter labels

#### Conversion Pipeline

```
1. Download CRS from GitHub (or use local checkout)
   └─ coreruleset/coreruleset @ tag v4.x.y
   └─ Rules: rules/@owasp_crs/*.conf
   └─ Data files: rules/@owasp_crs/*.data

2. Parse all .conf files → []SecRule AST

3. Filter: keep only detection rules
   └─ Skip: 901xxx (init), 905xxx (exceptions), 949xxx/959xxx (evaluation),
      980xxx (correlation), 999xxx (placeholder)
   └─ Skip: paranoia gating rules (TX:DETECTION_PARANOIA_LEVEL @lt N + skipAfter)
   └─ Skip: SecAction (no variable/operator)
   └─ Skip: response-phase rules (phase 3/4) — flag for Phase 2

4. For each SecRule (or chain):
   a. Map variables → policy engine fields
      └─ ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES → all_args_values
         (CRS's most common variable combo)
      └─ Pipe-separated vars with overlapping coverage → appropriate multi-value field
      └─ Named vars → field:Name syntax
      └─ Variable negation → note for exclusion handling
   b. Map operator → policy engine operator
      └─ @rx → regex (validate RE2 compat, flag PCRE-only features)
      └─ @pm → phrase_match (split space-separated)
      └─ @pmFromFile → phrase_match (read .data file, inline as array)
      └─ @detectSQLi/@detectXSS → detect_sqli/detect_xss
      └─ Unsupported → flag in gap report
   c. Map transforms → policy engine transforms array
      └─ Strip t:none (it's implicit)
      └─ Validate all transforms exist in plugin registry
      └─ Flag missing transforms (cmdLine, replaceComments, escapeSeqDecode)
   d. Map severity → policy engine severity field
      └─ CRITICAL → "CRITICAL" (5 pts)
      └─ ERROR → "ERROR" (4 pts)
      └─ WARNING → "WARNING" (3 pts)
      └─ NOTICE → "NOTICE" (2 pts)
   e. Extract paranoia level from tags
      └─ tag:'paranoia-level/N' → paranoia_level: N
   f. Resolve chains → multi-condition rules
      └─ SecRule A chain → SecRule B
      └─ Becomes: conditions: [A_condition, B_condition], group_operator: "AND"
    g. Map CRS rule ID to policy engine rule ID
       └─ CRS 932120 → 932120 (plain numeric ID, no prefix)
   h. Build tags from CRS tag hierarchy
      └─ tag:'attack-rce' → "attack-rce"
      └─ tag:'OWASP_CRS/ATTACK-RCE' → "crs-rce"
      └─ tag:'platform-unix' → "platform-unix"

5. Validate all regex patterns against Go RE2 engine
   └─ Flag PCRE-only features (lookahead, lookbehind, backreferences)
   └─ Attempt automatic conversion where possible
   └─ Log unconvertible patterns in gap report

6. Output default-rules.json with version number

7. Generate gap report:
   └─ Rules successfully converted (count + IDs)
   └─ Rules skipped — unsupported operator (list with reasons)
   └─ Rules skipped — unsupported variable (list)
   └─ Rules skipped — response phase (list — deferred)
   └─ Rules skipped — PCRE regex (list — need RE2 conversion)
   └─ Rules skipped — flow control (list — not detection)
   └─ Missing transforms (list)
   └─ Missing operators (list)
   └─ Coverage percentage per category
```

#### PCRE → RE2 Conversion

**CONFIRMED: All 210 CRS regex rules compile cleanly in Go RE2.**

The initial converter run showed 76 "PCRE-only" failures, but these were caused by a
parser bug: `extractQuotedString()` was stripping backslashes (treating `\x5c` as an
escape sequence), corrupting regex patterns. After fixing to only treat `\"` as escape,
all 210 regex conditions compile without error.

The converter auto-fixes possessive quantifiers (`++` → `+`) and atomic groups
(`(?>...)` → `(?:...)`), but no CRS 4.24.1 rules needed these fixes.

CRS regexes use PCRE syntax that is fully RE2-compatible:

| PCRE Feature | CRS Usage | RE2 Status |
|--------------|-----------|------------|
| `(?:...)` non-capturing group | Extensive | ✅ Supported |
| `\b` word boundary | Extensive | ✅ Supported |
| `(?i)` case-insensitive | Extensive | ✅ Supported |
| `(?s)` dotall mode | Some | ✅ Supported |
| `\x5c`, `\x0b` hex escapes | Extensive | ✅ Supported |
| `{1,10}` bounded repetition | Common | ✅ Supported |
| Character classes `[...]` | Extensive | ✅ Supported |

#### @pmFromFile Data File Resolution

CRS ships 19 `.data` files. The converter reads each and inlines as `phrase_match` arrays:

| Data File | Entries | Used By |
|-----------|---------|---------|
| `unix-shell.data` | ~400 | 932xxx RCE |
| `windows-powershell-commands.data` | ~60 | 932xxx RCE |
| `unix-shell-builtins.data` | ~30 | 932xxx RCE |
| `php-function-names-933150.data` | 212 | 933xxx PHP injection |
| `php-variables.data` | 22 | 933xxx PHP injection |
| `ssrf.data` | ~130 | 934xxx Generic |
| `ssrf-no-scheme.data` | 18 | 934xxx Generic |
| `java-classes.data` | 64 | 944xxx Java injection |
| `scanners-user-agents.data` | 48 | 913xxx Scanner detection |
| `lfi-os-files.data` | ~100 | 930xxx LFI |
| `restricted-files.data` | 526 | 930xxx LFI |
| `restricted-upload.data` | ~50 | 932xxx RCE |
| `sql-errors.data` | ~100 | 951xxx Response SQL leakage |
| `php-errors.data` | ~30 | 953xxx Response PHP leakage |
| `java-classes.data` | 64 | 952xxx Response Java leakage |
| `iis-errors.data` | ~50 | 954xxx Response IIS leakage |
| `asp-dotnet-errors.data` | ~30 | 954xxx Response ASP leakage |
| `ruby-errors.data` | ~20 | 956xxx Response Ruby leakage |
| `web-shells-php.data` / `web-shells-asp.data` | ~200 | 955xxx Web shells |

Response-phase data files are flagged as deferred but still parsed (ready for Phase 2).

---

### CRS Regression Test Adaptation

CRS ships 315 YAML test files (~2500+ test cases) using the `go-ftw` format. Each test
specifies an HTTP request input and expected output (rule ID should/shouldn't fire).

#### Test Format (go-ftw YAML)

```yaml
meta:
  author: "CRS project"
rule_id: 932120
tests:
  - test_id: 1
    desc: "PowerShell command in query parameter"
    stages:
      - input:
          method: "GET"
          uri: "/get?param=Invoke-Expression"
          headers:
            Host: "localhost"
            User-Agent: "OWASP CRS test agent"
            Accept: "*/*"
        output:
          log:
            expect_ids: [932120]      # Rule SHOULD fire
  - test_id: 2
    desc: "Benign parameter should not trigger"
    stages:
      - input:
          method: "GET"
          uri: "/get?param=hello"
          headers: { ... }
        output:
          log:
            no_expect_ids: [932120]   # Rule should NOT fire
```

#### Adaptation Strategy

Build a Go test runner at `tools/crs-test-runner/` (or integrate into `test/e2e/`):

1. **Parse YAML test files** — read `input` (method, URI, headers, body) and `output`
   (expect_ids, no_expect_ids)
2. **Build HTTP request** from input fields
3. **Send through policy engine** — either:
   a. In-process: instantiate plugin, call `ServeHTTP()` directly (fastest, no Docker)
   b. Via e2e: send to running Caddy with policy engine (validates full stack)
4. **Check results**:
   - `expect_ids`: verify the rule ID appears in `policy_detect_rules` output
   - `no_expect_ids`: verify the rule ID does NOT appear
   - `status`: verify HTTP response code
5. **Report**: pass/fail per test case, overall coverage per category

**Key adaptations from go-ftw format**:
- go-ftw checks WAF engine logs for rule IDs; we check Caddy vars / response headers
- `encoded_request` fields need base64 decoding into raw HTTP bytes
- Response-phase tests (950-980) need the `/reflect` endpoint pattern — defer to Phase 2
- Some tests rely on Coraza-specific behavior (MULTIPART_STRICT_ERROR, etc.) — flag as skipped

#### Expected Coverage

| Category | Test Files | Convertible | Notes |
|----------|-----------|-------------|-------|
| 911 Method Enforcement | 1 | ✅ | Simple method checks |
| 913 Scanner Detection | 1 | ✅ | UA phrase_match |
| 920 Protocol Enforcement | 59 | ~50 | Some need `validate_byte_range`, numeric ops |
| 921 Protocol Attack | 17 | ✅ | CR/LF injection regex |
| 922 Multipart Attack | 4 | ⚠️ | Needs multipart variable support |
| 930 LFI | 5 | ✅ | Path traversal regex |
| 931 RFI | 5 | ✅ | URL pattern regex |
| 932 RCE | 46 | ~40 | Some need `cmdLine` transform |
| 933 PHP Injection | 21 | ✅ | Regex + phrase_match |
| 934 Generic | 11 | ✅ | SSRF, Node.js, prototype pollution |
| 941 XSS | 33 | ~30 | 2 need `@detectXSS` (libinjection) |
| 942 SQLi | 60 | ~55 | 2 need `@detectSQLi` (libinjection) |
| 943 Session Fixation | 3 | ✅ | Simple regex |
| 944 Java Injection | 15 | ✅ | Regex + phrase_match |
| 949 Blocking Eval | 1 | Skip | Flow control |
| 950-980 Response | 32 | Defer | Response phase |
| **Total** | **315** | **~250+** | **~80%+ request-phase coverage** |

---

### Plugin Changes Required

#### v0.11.x — Matched Payload Observability

**Priority: HIGHEST** — this is the biggest regression from Coraza.

Add per-condition match detail to detect rule output:

```go
type MatchDetail struct {
    Field       string `json:"field"`        // "all_args_values", "header:User-Agent"
    MatchedVar  string `json:"matched_var"`  // "ARGS:username" (SecRule-style name)
    Value       string `json:"value"`        // actual input value (truncated 200 chars)
    MatchedData string `json:"matched_data"` // regex group 0, or phrase_match hit
    Operator    string `json:"operator"`     // "regex", "phrase_match", etc.
    Pattern     string `json:"pattern"`      // the pattern/phrases that matched (truncated)
}
```

Emit as Caddy var `policy_detect_matches` (JSON array of MatchDetail per rule).
wafctl parses into `Event.MatchedRules[].Matches[]`. Frontend renders:
- Variable name in green (`ARGS:username`)
- Matched value with yellow highlight (`' OR 1=1--`)
- Rule message, severity badge, category tag

For multi-value fields (`all_args_values`, `all_headers`, etc.), the match detail includes
which specific key/value pair triggered. This requires the evaluation loop to track which
item in the collection matched, not just whether any item matched.

#### v0.12.x — New Operators

1. **`detect_sqli`** — Import `github.com/corazawaf/libinjection-go`. Call `libinjection.IsSQLi()`.
   Capture fingerprint as `matched_data`. ~20 lines of code.
2. **`detect_xss`** — Same library, `libinjection.IsXSS()`. ~15 lines.
3. **`validate_byte_range`** — Check if input contains bytes outside specified ranges.
   Port from Coraza's implementation (~50 lines). Used by 6 CRS protocol rules.

#### v0.12.x — New Transforms

1. **`cmdLine`** — Port from Coraza (`transformations/cmdline.go`, ~60 lines). Delete
   `\`, `"`, `'`, `^`; normalize whitespace; lowercase. Used by 13 CRS RCE rules.
2. **`replaceComments`** — Replace C-style `/* */` with space. ~20 lines. Used by 9 rules.
3. **`escapeSeqDecode`** — Decode ANSI C escapes (`\n`, `\xHH`, `\OOO`). Port from
   Coraza (~40 lines). Used by 7 rules.

#### v0.13.x — Condition Enhancements

1. **`negate: true`** on conditions — invert match result. ~5 lines in evaluation loop.
2. **`multiMatch`** on rules — run operator before AND after each transform in the chain.
   ~30 lines (loop over transform pipeline, check at each stage).
3. **Regex key support** — `header:/^X-/` matches headers by regex pattern. ~20 lines.
4. **Count support** — `count:args` returns the number of matching items as a string.
   Used with numeric comparison (not directly needed if we handle differently).

---

### Execution Order

| Phase | Work | Depends On | Effort |
|-------|------|------------|--------|
| **1** | Matched payload observability (plugin v0.11.x) | Nothing | 2 days |
| **2** | CRS converter tool (parser + mapper + output) | Nothing | 3-4 days |
| **3** | New transforms (`cmdLine`, `replaceComments`, `escapeSeqDecode`) | Nothing | 1 day |
| **4** | New operators (`detect_sqli`, `detect_xss`, `validate_byte_range`) | Nothing | 1 day |
| **5** | Condition enhancements (`negate`, `multiMatch`, regex keys) | Nothing | 1 day |
| **6** | Run converter, validate output, fix edge cases | Phases 2-5 | 2 days |
| **7** | CRS test runner + validate against regression suite | Phases 2-6 | 2 days |
| **8** | Deploy: replace `default-rules.json`, remove Coraza from Dockerfile | Phases 1-7 | 1 day |
| **9** | Frontend catch-up (matched payload display, CRS category views) | Phase 1 | 2 days |
| **10** | Response-phase detection (Phase 2 of Coraza removal) | Phase 8 | Future |

Phases 1-5 are independent and can be parallelized. Total estimate: ~2-3 weeks.

---

### What the Converter Supersedes

The existing 45 hand-ported rules in `default-rules.json` (PE-920xxx, PE-921xxx, PE-930xxx,
PE-932xxx, PE-943xxx, PE-9100030-9100035) will be **replaced** by converter output.
The hand-ported rules served as proof-of-concept for:
- Rule format and schema validation
- Severity → score mapping
- Transform chain support
- `phrase_match` operator
- `detect` + threshold blocking flow
- Frontend integration (badges, anomaly score display, create exception)

The converter output preserves the same schema but with full CRS coverage, accurate
regex patterns (not simplified approximations), and proper transform chains.

### CRS Version Pinning

The converter pins to a specific CRS release tag (initially `v4.23.0` to match current
production). The tag is configurable. Output `default-rules.json` includes:
- `version` field (incremented on each converter run)
- `crs_version` field (e.g., `"4.23.0"`)
- `generated_at` timestamp
- `converter_version` field

To upgrade CRS: change the tag, re-run converter, review diff, ship new Docker image.
Future: periodic runtime sync (already in deferred work — lower priority now that
converter makes upgrades a single command).

### Rule File Format

Default rules ship in `default-rules.json` with a `rules` array and `version` number:

```json
{
  "version": 1,
  "rules": [
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
| ~~9100010~~ | ~~Pipe to shell command in ARGS~~ | **Replaced** by PE-932100 (broader cmd injection) |
| ~~9100011~~ | ~~Backtick command substitution~~ | **Replaced** by PE-932130 (shell expressions) |
| 9100012 | CRLF injection in query string | `detect` CRITICAL |
| 9100013 | CRLF injection in headers | `detect` CRITICAL |
| 9100030 | Missing Accept header (heuristic) | `detect` NOTICE |
| 9100033 | Empty/missing User-Agent (heuristic) | `detect` WARNING |
| 9100034 | Missing Referer on non-API GET (heuristic) | `detect` NOTICE |

Note: 9100030, 9100033, 9100034 are now shipped exclusively in `default-rules.json`. The v4 migration (previously seeded these as user rules) is a no-op, and v5 migration removes any previously-seeded copies. The corresponding SecRules were removed from `coraza/pre-crs.conf`. Attack detect rules (9100003, 9100006, 9100010-9100013) are in `default-rules.json` AND still in SecRules (dual-running during transition). The 920xxx rules (v0.10.4) also dual-run alongside CRS — both produce anomaly scores independently. This is intentional: it allows comparing policy engine scores vs Coraza scores to validate detection parity before removing Coraza.

9100032 (Scanner UA Block), 9100035 (Generic UA Anomaly), and 9100036 (HTTP/1.0 Anomaly) are now default rules using `phrase_match`. The v1-seeded user store copies were removed by v6 migration. The original SecRules (9100032, 9100035) in `pre-crs.conf` were already removed in v0.10.1; the `scanner-useragents.txt` and `generic-useragents.txt` files remain for reference but are no longer loaded by any SecRule.

### Tasks

- [x] Define default rule JSON schema and loading mechanism — **COMPLETED** (plugin v0.10.0)
- [x] Create initial `default-rules.json` with existing custom rules (9100003, 9100006, 9100010-9100013) — **COMPLETED** (v0.10.1)
- [x] Port heuristic bot rules (9100030, 9100033, 9100034) to default-rules.json — **COMPLETED** (v0.10.1)
- [x] Ship scanner-useragents.txt equivalent as phrase_match default rule — **COMPLETED** (v0.10.3)
- [x] Ship generic-useragents.txt equivalent as phrase_match default rule — **COMPLETED** (v0.10.3)
- [x] Port all CRS categories via auto-converter — **COMPLETED** (v0.12.5): 254 rules from CRS 4.24.1 (251 enabled, 3 disabled). Replaces all manual porting.
- [x] Add `default-rules.json` to Dockerfile COPY — **COMPLETED** (`COPY waf/default-rules.json /etc/caddy/waf/default-rules.json`)
- [x] CRS regression test runner — **COMPLETED**: 3925 tests, 97.5% pass rate, **zero detection misses**
- [x] Remove Coraza entirely — **COMPLETED**: coraza-caddy removed from Dockerfile, all `coraza/` paths renamed to `waf/`, policy engine is sole WAF
- [x] Build rules management UI — **COMPLETED**: `/rules` page with `RulesPanel.tsx`, category pill filters, search, per-rule toggle/override, Save & Deploy
- [x] Clean up dead wafctl code — **COMPLETED**: 43 files changed, -8,287 net lines. Go: deleted 7 files, cleaned 18+ files. Frontend: deleted SecRuleEditor.tsx, rewrote PolicyForms.tsx, trimmed to 3 exclusion types (allow/block/detect)
- [x] Fix "Create Exception" for policy engine events — **COMPLETED**: button was hidden for all `policy_*` events, action defaulted wrong, name generation broke on empty rule IDs
- [ ] Deploy to production
- [ ] Response-phase detection (Phase 2 — deferred)

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

**Goal: Replace Coraza entirely with the policy engine.** The policy engine runs alongside Coraza during the transition, with each phase porting more CRS detection categories into `default-rules.json`. Both engines score requests independently during dual-running, allowing detection parity validation before Coraza removal. At v1.0, all CRS categories have equivalent policy engine rules and Coraza is removed from the Docker image.

| Phase | Policy Engine Handles | Coraza Still Handles |
|-------|----------------------|---------------------|
| v0.6.x | block, allow, honeypot, rate_limit | All CRS detection + scoring |
| v0.7.0 | + CSP headers, security headers | CRS detection + scoring |
| v0.8.0 | + anomaly scoring, heuristic bot detect rules | CRS detection (score comparison possible) |
| v0.8.1 | + transform-resistant detection (17 transforms) | CRS detection (for categories not yet ported) |
| v0.9.0 | + multi-variable, phrase matching, numeric ops, count: | Remaining CRS categories |
| v0.10.0 | + default rules loading/merging | Remaining CRS categories |
| v0.10.2 | + default rule override API (list/get/set/reset) | Remaining CRS categories |
| v0.10.3 | + scanner/generic UA as phrase_match default rules, v6 migration | Remaining CRS categories |
| v0.10.4 | + 14 CRS 920xxx Protocol Enforcement rules (26 defaults total) | Remaining CRS categories (930–944xxx) |
| v0.11.1 | + per-condition match detail, request context, PE- prefix removed, detect_block parity | CRS auto-converter integration |
| v0.12.5 | + `request_combined` field, CRS auto-converter output (254 rules from CRS 4.24.1), `cmdLine`/`escapeSeqDecode`/`removeCommentsChar` transforms, `validate_byte_range`/`validate_url_encoding` operators | Nothing |
| **v0.12.5 (current)** | **Coraza fully removed. Policy engine is sole WAF.** 97.5% CRS regression pass, zero detection misses. | Nothing — Coraza removed |
| v1.0 | + rules management UI, dead code cleanup, exception creation fix, production deploy | libinjection (deferred) |

### Coraza Removal Checklist

**COMPLETED — Coraza removed as of v0.12.5 (2026-03-12).**

**Automated conversion:**
- [x] CRS converter tool built and tested (`tools/crs-converter/`, 28 tests)
- [x] Converter successfully parses CRS 4.24.1 (623 rules parsed, 254 shipped)
- [x] All regex patterns compile in Go RE2
- [x] All 20 CRS `.data` files inlined as `phrase_match` arrays
- [x] `request_combined` aggregate field replaces per-variable CRS rules — zero detection misses
- [x] Converter output validates against CRS regression test suite: **97.5% pass rate** (3809/3908 non-skipped)
  - 0 detection misses (wanted 403, got 200)
  - 85 "FPs" from `no_expect_ids` — expected behavior of aggregate `request_combined` field at PL4/threshold=1; tunable via PL + threshold as designed
  - 11 status 400 vs 403 — Go rejects malformed requests before WAF sees them
  - 3 request build failures — Go client can't construct malformed HTTP

**Plugin feature parity:**
- [x] Matched payload observability: `matched_var`, `matched_data`, `matched_field` per rule match (v0.11.1)
- [x] `negate: true` on conditions (v0.11.1)
- [x] `request_combined` aggregate field with multi-source extraction (v0.12.5)
- [x] `validate_byte_range` operator
- [x] `validate_url_encoding` operator
- [x] `cmdLine` transform
- [x] `escapeSeqDecode` transform
- [x] `removeCommentsChar` transform

**Infrastructure:**
- [x] Coraza removed from Dockerfile (no more `coraza-caddy` xcaddy `--with`)
- [x] All `coraza/` paths renamed to `waf/` across entire codebase
- [x] Policy engine is sole WAF — `order policy_engine first` in Caddyfile
- [x] `coraza/` directory removed (pre-crs.conf, post-crs.conf, scanner-useragents.txt, generic-useragents.txt)
- [x] `scripts/rotate-audit-log.sh` removed (no more Coraza audit log)
- [x] Frontend displays matched payload detail (variable name, matched value, rule message)

**Deferred:**
- [ ] `detect_sqli` / `detect_xss` operators (libinjection) — 4 CRS rules use these; regex alternatives cover the same attacks
- [ ] `multiMatch` support — ~15 CRS rules; regex patterns already match post-transform
- [ ] Response-phase detection (Phase 2) — 100+ CRS outbound rules
- [x] Dead code cleanup in wafctl — **COMPLETED**: SecRule generators, audit log parser, SecRule exclusion types in frontend. 43 files, -8,287 net lines
- [x] Rules management UI — **COMPLETED**: `/rules` page with CF-style browse/toggle/override
- [ ] WebSocket `http.Hijacker` support (currently using `@not_websocket` bypass in Caddyfile)

### What Full Coraza Removal Eliminates

| Component | Status |
|-----------|--------|
| `coraza-caddy` fork dependency | ✅ Removed |
| CRS v4 rule files (~4MB) | ✅ Removed (replaced by `default-rules.json`) |
| `coraza/pre-crs.conf`, `post-crs.conf` | ✅ Removed (rules in JSON) |
| `scanner-useragents.txt`, `generic-useragents.txt` | ✅ Removed (ported to phrase_match) |
| `coraza/` directory | ✅ Removed (renamed to `waf/`) |
| `scripts/rotate-audit-log.sh` | ✅ Removed |
| `order coraza_waf after policy_engine` in Caddyfile | ✅ Removed |
| `@needs_waf` matcher block | ✅ Removed |
| Docker image size (~30-40MB from Coraza + CRS) | ✅ Reduced |
| Caddy startup time (CRS rule compilation) | ✅ Faster (JSON parse + hot-reload vs SecRule compilation) |
| `wafctl/generator.go` (SecRule generation, ~458 lines) | ✅ Deleted |
| `wafctl/generator_helpers.go` (~187 lines) | ✅ Deleted |
| `wafctl/waf_settings_generator.go` | ✅ Deleted |
| SecRule exclusion types in frontend | ✅ Cleaned (3 types only) |
| Coraza audit log parsing (`logparser.go`) | ✅ Gutted to eviction-only |
| `ephemeralID()` / `ephemeralCounter` | ✅ Removed (Caddy request UUID is sole event ID) |
| `PolicyEngineEnabled` flag | ✅ Removed (guards deleted, always policy engine) |
| Legacy RL `.caddy` generator (`rl_generator.go`) | ✅ Deleted (policy engine handles RL) |
| CRS autocomplete data (`crs_rules.go` lines 263-345) | ✅ Deleted (SecRule editor removed) |
| `RawRule`, `RuleID`, `RuleTag`, `Variable` fields on `RuleExclusion` | ✅ Removed from Go + frontend |
| JSONL migration code (6 exclusion versions, RL v1, config old format) | Kept (handles existing production stores) |

---

## Code Review Findings (2026-03-13)

Full codebase review: 62,762 lines across 178 files (Go 34.6k, TypeScript 27k, infra configs).

### CRITICAL

#### CR-1: SSRF in `ManagedListStore.RefreshURL` — `wafctl/managed_lists.go:412`

User-controlled `l.URL` passed directly to `http.Client.Get()` with no validation of
scheme or target. An attacker who can create a managed list with `source: "url"` can
target internal services (`http://169.254.169.254/`, `http://localhost:8080/api/...`).

```go
resp, err := client.Get(l.URL)  // l.URL is user-controlled
```

**Fix**: Validate URL scheme (allow `https://` only or whitelist), reject private/loopback
IP ranges via custom `net.Dialer`, or restrict to known external domains.

- [x] Add URL validation to `RefreshURL` (scheme allowlist + private IP rejection) — already implemented in `validateRefreshURL()`

#### CR-2: HTTP Request Under Exclusive Mutex Lock — `wafctl/managed_lists.go:388-412`

`RefreshURL()` acquires `s.mu.Lock()` at line 388, then performs a 60-second HTTP GET at
line 412 while holding the exclusive lock. All concurrent managed list operations (CRUD,
import, SyncIPsum) are blocked for the entire duration.

**Fix**: Read list metadata under `RLock`, release, perform HTTP request, then re-acquire
`Lock` for the mutation.

- [x] Restructure `RefreshURL` to release lock during HTTP request — already implemented (Phase 1: RLock, Phase 2: no lock)

### HIGH

#### CR-3: No Graceful Shutdown — `wafctl/main.go:296`

`srv.ListenAndServe()` blocks with no signal handler for SIGTERM/SIGINT. Container stop
kills in-flight requests abruptly, potentially corrupting partially-written atomic files.

- [x] Add `signal.NotifyContext` for SIGTERM/SIGINT and call `srv.Shutdown(ctx)`
- [x] Pass context to background goroutines for clean cancellation

#### CR-4: Store Getters Return Shallow Copies — `wafctl/exclusions.go:107-116`

`ExclusionStore.Get()` returns a struct copy, but slices (`Conditions`, `Tags`) share
backing arrays with the store's internal data. Same issue in `RateLimitRuleStore.listLocked()`
(`rl_rules.go:147`).

- [x] Add deep copy helper for `RuleExclusion` (clone Conditions/Tags slices) — `deepCopyExclusion()` in exclusions.go
- [x] Add deep copy for `RateLimitRule` in `listLocked()` — `deepCopyRLRule()` in rl_rules.go

#### CR-5: Background Goroutines Have No Cancellation — `wafctl/logparser.go:261`

`StartEviction`, `StartTailing`, `StartScheduledRefresh` all launch goroutines with
`time.NewTicker` loops that run forever with no `context.Context` cancellation.

- [x] Accept `context.Context` in all `Start*` methods, select on `ctx.Done()`

#### CR-6: `MergeCaddyfileServices` Doesn't Roll Back on Save Failure — `wafctl/rl_rules.go:437-439`

When auto-discovered services are added to memory and `save()` fails, in-memory state
diverges from on-disk state.

- [x] Save original rules slice, restore on `save()` failure

#### CR-7: Final Docker Image Runs as Root — `Dockerfile:39-49`

The `caddy:2.11.1-alpine` base runs as root. `DAC_OVERRIDE` capability added back.
`wafctl/Dockerfile` correctly uses `USER 65534:65534`.

- [x] Add dedicated caddy user (UID 10000), run as non-root after entrypoint setup via su-exec
- [x] Drop `DAC_OVERRIDE` capability from compose.yaml

#### CR-8: `CF_API_TOKEN` as Environment Variable — `compose.yaml:60`

Visible in `docker inspect` and `/proc/1/environ`. Authelia correctly uses file-based
secrets pattern.

- [x] Move `CF_API_TOKEN` to file-based secret matching Authelia's pattern (entrypoint reads from /run/secrets/)

#### CR-9: Services Without `forward_auth` — `Caddyfile:300-540`

Dockge (Docker management), sonarr, radarr, bazarr, prowlarr, sabnzbd, qbit, copyparty
exposed without Authelia forward auth. Some have their own auth. **Dockge** is particularly
concerning — gives Docker control.

- [ ] Audit each service's built-in auth and document decisions
- [ ] Add `forward_auth` to dockge at minimum

### MEDIUM

#### CR-10: Response Cache Key Abuse — `wafctl/cache.go`

`r.URL.RawQuery` as cache key. Attackers can craft unique query strings to thrash the
cache (max 50 entries, but each `SummaryResponse` can be large).

- [x] Add cache key normalization (sort params, strip unknown keys)

#### CR-11: Missing `Access-Control-Max-Age` on CORS Preflight — `wafctl/main.go:332-338`

No `Max-Age` header. Browsers send preflight for every cross-origin request.

- [x] Add `Access-Control-Max-Age: 86400` to CORS preflight response

#### CR-12: Inconsistent Error Status Codes — `handlers_lists.go:41` vs `handlers_exclusions.go:116`

Managed list creation returns 400 for all failures (including disk I/O). Exclusion
creation returns 500. Should distinguish validation (400) from server errors (500).

- [x] Return 500 for store persistence failures in `handlers_lists.go`

#### CR-13: `handleUpdateRLRule` Requires Full Object — `wafctl/handlers_ratelimit.go:49-70`

Unlike exclusions (partial JSON merge), RL rules require full object. Inconsistent API.

- [x] Add JSON merge partial update for RL rules (match exclusion pattern)

#### CR-14: `handleDeployRLRules` Claims `Reloaded: true` Without Verification — `wafctl/handlers_ratelimit.go:140`

Assumes plugin hot-reload polling is active. No verification.

- [x] Document assumption in response or add health check

#### CR-15: Deep Copy via JSON Round-Trip — `wafctl/csp.go:367-382`

`CSPStore.deepCopy()` uses `json.Marshal/Unmarshal` for every `Get()`. Expensive.

- [x] Consider manual clone for hot path (low priority)

#### CR-16: Unbounded `io.ReadAll` on Error — `wafctl/deploy.go:207`

No `LimitReader` on Caddy admin error response body.

- [x] Add `io.LimitReader(resp.Body, 1024)` to error body read in deploy.go

#### CR-17: `dorny/paths-filter@v3` Not SHA-Pinned — `.github/workflows/build.yml:41`

Mutable tag while all other third-party actions are SHA-pinned.

- [x] Pin `dorny/paths-filter` to SHA

#### CR-18: `caddy-reload` Makefile Target Incomplete — `Makefile:231-234`

Deploys WAF config and rate rules but skips CSP and security headers.

- [x] Add CSP and security headers deploy to `caddy-reload` target

#### CR-19: Timer Leaks in Frontend (4 components)

`SecurityHeadersPanel.tsx:105`, `RulesPanel.tsx:181`, `policy/TagInputs.tsx:28`,
`csp/PreviewPanel.tsx:175` — bare `setTimeout` without cleanup on unmount.

- [x] Add ref-based timer cleanup to all 4 components

#### CR-20: `exclusions.ts:182` — `||` vs `??` for Paranoia Level

`||` treats `0` as falsy. Should use `??`.

- [x] Change to `??` operator

#### CR-21: `default-rules.ts:88,95,99` — Missing `encodeURIComponent`

URL-interpolated IDs not encoded.

- [x] Add `encodeURIComponent(id)` to all 3 functions

#### CR-22: Missing `role="button"` on Expandable Rows — `EventsTable.tsx:393`

Clickable `<tr>` elements lacked keyboard accessibility.

- [x] Add `role="button"`, `tabIndex={0}`, `aria-expanded`, `onKeyDown`

### LOW

#### CR-23: `itoa` Reimplements `strconv.Itoa` — `wafctl/backup.go:194`

Custom implementation despite `strconv` already linked in the binary.

- [x] Replace with `strconv.Itoa`

#### CR-24: Duplicated Event Type Routing Logic — `wafctl/handlers_events.go:79-106,428-452`

WAF/RL type routing maps duplicated between `handleSummary` and `handleEvents`.

- [x] Extract to shared helper function

#### CR-25: `parseHours` Inconsistent Upper Bound — `wafctl/query_helpers.go:23`

No upper bound vs 720 cap in `handleExclusionHits`.

- [x] Add consistent upper bound across all endpoints

#### CR-26: `softprops/action-gh-release@v2` Mutable Tag — `.github/workflows/release.yml:49`

Has `contents: write` permission. Should be SHA-pinned.

- [x] Pin to SHA

#### CR-27: wafctl Memory Limit 128M — `compose.yaml:131`

With 90-day event retention + MMDB + access log stores, may be tight under load.

- [ ] Monitor and document sizing guidance

---

## Design Spec: Unified Policy Pipeline (allow/skip Refactor)

### Motivation

The current policy engine has a flat 4-pass evaluation model: block → allow → detect → rate_limit.
The `allow` action only bypasses CRS detect rules — it does NOT bypass block rules below it or
rate limit rules. This differs from Cloudflare's model where the **Skip** action can selectively
bypass any downstream phase (remaining custom rules, rate limiting, managed rules, or all).

Real-world use cases require more granular control:
- "This IP is my monitoring service — skip ALL security" (full bypass)
- "This API path is a health check — skip CRS and rate limits, but still honor block rules"
- "This partner's API key — skip rate limits only"
- "Skip specific CRS rules for this path" (selective rule exception)

### Cloudflare's Model (Reference)

Cloudflare evaluates security in sequential **phases**. Terminating actions stop the request:

```
DDoS (L7) → Custom Rules (block/skip) → Rate Limiting → Managed Rules (CRS) → SBFM
```

Their **Skip** action (replacement for old Allow + Bypass) can selectively bypass:
1. All remaining custom rules
2. Entire rate limiting phase
3. Entire managed rules phase
4. Specific managed ruleset rules
5. Any combination of the above

### New Model

Two new semantics replacing the current `allow`:

| Action | Behavior | CF Equivalent |
|--------|----------|---------------|
| `allow` | **Full bypass** — terminates evaluation immediately. No blocks, CRS, or rate limits below it fire. "I trust this traffic completely." | Skip (all remaining + all phases) |
| `skip` | **Selective bypass** — carries a `skip_targets` field specifying what to skip. Non-terminating (evaluation continues for non-skipped rule types). | Skip (selective phases/rules) |
| `block` | Terminates with 403 (unchanged) | Block |
| `honeypot` | Terminates with 403 + honeypot tag (unchanged) | Block (custom) |
| `detect` | Anomaly scoring accumulation (unchanged) | N/A (managed rules) |
| `rate_limit` | Sliding window counter (unchanged) | Rate Limiting Rules |

### Priority Bands (New)

```
allow  = 50-99     ← Full bypass, evaluated FIRST (terminates on match)
block  = 100-199   ← Deny list (terminates on match)
skip   = 200-299   ← Selective bypass (non-terminating, sets skip flags)
rate_limit = 300-399   ← Rate limiting (skippable via skip_targets)
detect = 400-499   ← CRS anomaly scoring (skippable via skip_targets)
```

This mirrors CF: skip-all rules at the top of custom rules, then blocks, then selective
exceptions, then rate limiting, then managed rules.

### `skip` Rule Data Model

```json
{
  "id": "skip-health-check",
  "name": "Skip CRS for health checks",
  "type": "skip",
  "conditions": [
    { "field": "path", "operator": "eq", "value": "/health" }
  ],
  "group_op": "and",
  "skip_targets": {
    "rules": ["932120", "941100"],
    "phases": ["detect", "rate_limit"],
    "all_remaining": false
  },
  "enabled": true,
  "priority": 200,
  "tags": ["health-check"]
}
```

**`skip_targets` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `rules` | `[]string` | Specific rule IDs to skip (detect rules by CRS ID, RL rules by ID, block rules by ID) |
| `phases` | `[]string` | Entire phases to skip: `"detect"`, `"rate_limit"`, `"block"` (remaining blocks) |
| `all_remaining` | `bool` | Skip everything below this rule (equivalent to CF "Skip all remaining custom rules + all phases") |

If `all_remaining` is true, `rules` and `phases` are ignored (everything is skipped).

### Plugin Evaluation Loop (New 5-Pass)

```
for each rule (sorted by priority):
  Pass 1 — Allow (priority 50-99):
    If conditions match → set allow vars, RETURN (terminate, full bypass)

  Pass 2 — Block/Honeypot (priority 100-199):
    If skipAllRemaining → skip
    If this rule's ID is in skipRuleIDs → skip
    If "block" phase is in skipPhases → skip
    If conditions match → set block vars, RETURN 403

  Pass 3 — Skip (priority 200-299):
    If conditions match → merge skip_targets into running skip state:
      - Add rule IDs to skipRuleIDs set
      - Add phases to skipPhases set
      - Set skipAllRemaining flag if all_remaining=true
    Continue (non-terminating)

  Pass 4 — Rate Limit (priority 300-399):
    If skipAllRemaining → skip
    If this rule's ID is in skipRuleIDs → skip
    If "rate_limit" phase is in skipPhases → skip
    Evaluate normally (counters tick, 429 if exceeded)

  Pass 5 — Detect (priority 400-499):
    If skipAllRemaining → skip
    If this rule's ID is in skipRuleIDs → skip
    If "detect" phase is in skipPhases → skip
    Evaluate normally (accumulate score)

Post-loop: anomaly threshold check (unchanged, but respects skip flags)
```

### Backward Compatibility

The current `allow` action (skips detect only) maps to the new `skip` with
`skip_targets: { phases: ["detect"] }`. Migration:

1. On plugin upgrade, existing rules with `type: "allow"` that were generated by wafctl
   keep working because wafctl regenerates `policy-rules.json` on every deploy.
2. wafctl migration: existing exclusions with `type: "allow"` become `type: "skip"` with
   `skip_targets: { phases: ["detect"] }` (preserves current behavior).
3. New `allow` type is the full-bypass action (no existing rules use this semantic).

### UI Layout

**Policy Rules** (unified tab at `/policy`):
- Contains `allow`, `skip`, `block`, `honeypot`, and `rate_limit` rules in one ordered list.
- Users see the full evaluation pipeline and can drag-reorder within priority bands.
- When the user picks `rate_limit` as the action type, rate-limit-specific fields appear
  (window, events, key, action).
- When the user picks `skip`, skip_targets fields appear (rule picker, phase checkboxes,
  all_remaining toggle).
- When the user picks `allow`, no extra fields needed — it's a simple condition → full bypass.

**CRS Settings** (separate tab at `/rules/crs`):
- Global CRS configuration: paranoia level, thresholds, per-service overrides.
- CRS rule list with enable/disable, severity overrides, PL assignment.
- This is the "managed ruleset" — always evaluated last, configurable globally.
- Per-service CRS profiles (see below) allow running modified CRS variants per service.
- Only if a user wants a fully custom detect rule with arbitrary conditions would they
  create a `detect` rule in Policy Rules (rare — most users use CRS profiles).

### Per-Service CRS Profiles (Account Ruleset Model)

Cloudflare allows deploying the same managed ruleset (OWASP CRS) multiple times at the
account level with different per-zone overrides — each deployment can disable categories,
change rule actions, override severity, etc. Our equivalent: **per-service CRS profiles**
that override the global default-rules behavior.

#### Current State (Limited)

- Global `WAFConfig`: paranoia_level, inbound_threshold, outbound_threshold
- Per-service overrides: can only change PL and thresholds (3 numbers)
- Default rules (DefaultRuleStore): global enable/disable and severity overrides (apply to ALL services)
- No way to say "disable XSS rules for my API" or "use wordpress exclusion profile for my blog"

#### Use Cases Not Currently Possible

- "For my API service, disable all XSS rules (category `attack-xss`)"
- "For my WordPress service, apply the `wordpress` CRS exclusion profile and lower threshold to 5"
- "For my upload endpoint, disable request body rules (category `attack-rfi`) at PL2+"
- "For my admin panel, bump all SQLi rules to CRITICAL severity"
- "For my static site, only run PL1 rules with a high threshold (lenient)"

#### CRS Service Profile Data Model

```json
{
  "service": "api.example.com",
  "paranoia_level": 3,
  "inbound_threshold": 15,
  "rule_overrides": {
    "941100": { "enabled": false },
    "941110": { "enabled": false },
    "932120": { "severity": "CRITICAL" }
  },
  "category_overrides": {
    "attack-xss": { "enabled": false },
    "attack-sqli": { "severity": "CRITICAL" },
    "attack-rce": { "paranoia_level": 2 }
  },
  "crs_exclusions": ["wordpress"],
  "description": "API service — no XSS, strict SQLi, PL3"
}
```

**Field definitions:**

| Field | Type | Description |
|-------|------|-------------|
| `service` | `string` | Service name or FQDN (resolved via serviceMap like other rules) |
| `paranoia_level` | `int` | Override global PL for this service (0 = inherit global) |
| `inbound_threshold` | `int` | Override global threshold for this service (0 = inherit) |
| `rule_overrides` | `map[string]RuleOverride` | Per-rule overrides keyed by CRS rule ID |
| `category_overrides` | `map[string]CategoryOverride` | Per-category overrides keyed by CRS tag (e.g., `attack-xss`) |
| `crs_exclusions` | `[]string` | Named exclusion profiles: `wordpress`, `nextcloud`, `drupal`, etc. |
| `description` | `string` | Human-readable description of what this profile does |

**`RuleOverride` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `*bool` | nil = inherit, false = disable, true = force-enable |
| `severity` | `string` | Override severity: `CRITICAL`/`ERROR`/`WARNING`/`NOTICE` (empty = inherit) |
| `paranoia_level` | `int` | Override PL assignment (0 = inherit) |

**`CategoryOverride` fields:** Same as `RuleOverride`. Applied to all rules with the matching
CRS tag. Individual rule overrides take precedence over category overrides.

#### Three-Level Override Resolution

This is strictly more powerful than CF's model because we override at three specificity levels:

```
Layer 1: Plugin default rule (baked into default-rules.json at build time)
  ↓ merged with
Layer 2: Global override (DefaultRuleStore — applies to ALL services)
  ↓ merged with
Layer 3: Service profile override (CRS Service Profile — specific service only)
```

Resolution rules (CSS specificity model):
- Service profile `rule_overrides` beat category overrides beat global overrides beat defaults
- `nil`/zero values mean "inherit from layer above" — only non-nil values override
- `crs_exclusions` profiles are additive (service inherits global + adds its own)
- Per-service PL and threshold override the global WAFConfig per-service settings
  (single source of truth — migrate existing WAFConfig.Services into CRS profiles)

**Example resolution for rule 941100 on service `api.example.com`:**
```
Default:        enabled=true,  severity=WARNING, PL=1
Global override: (none for 941100)
Category override: attack-xss → enabled=false
Rule override:  (none for 941100)
→ Effective:    enabled=false  (XSS disabled for this service)
```

**Example resolution for rule 932120 on service `api.example.com`:**
```
Default:        enabled=true,  severity=WARNING, PL=2
Global override: severity=ERROR (someone bumped it globally)
Category override: (none for attack-rce)
Rule override:  severity=CRITICAL (service profile bumps it further)
→ Effective:    enabled=true, severity=CRITICAL, PL=2
```

#### Plugin Implementation

The plugin already has `WafConfig` with `PerService map[string]PolicyWafServiceConfig`
for PL/threshold. Extend to carry the full profile:

```go
// PolicyWafServiceConfig — extended for CRS profiles
type PolicyWafServiceConfig struct {
    ParanoiaLevel     int                        `json:"paranoia_level,omitempty"`
    InboundThreshold  int                        `json:"inbound_threshold,omitempty"`
    OutboundThreshold int                        `json:"outbound_threshold,omitempty"`
    RuleOverrides     map[string]RuleOverride    `json:"rule_overrides,omitempty"`
    CategoryOverrides map[string]CategoryOverride `json:"category_overrides,omitempty"`
    CRSExclusions     []string                   `json:"crs_exclusions,omitempty"`
}

type RuleOverride struct {
    Enabled       *bool  `json:"enabled,omitempty"`
    Severity      string `json:"severity,omitempty"`
    ParanoiaLevel int    `json:"paranoia_level,omitempty"`
}
type CategoryOverride = RuleOverride // same shape
```

**Compile-time resolution** (during rule load / hot-reload):
- For each service with a profile, pre-compute a `serviceRuleMask`:
  ```go
  type serviceRuleMask struct {
      disabledRules map[string]bool          // rule ID → disabled
      severityMap   map[string]string        // rule ID → effective severity
      plMap         map[string]int           // rule ID → effective PL
      pl            int                      // effective PL for this service
      threshold     int                      // effective threshold
  }
  ```
- Build once at compile time, stored in `map[string]*serviceRuleMask` keyed by hostname.
- At request time: `host := stripPort(r.Host)` → lookup mask → O(1) per-rule checks.
- If no mask exists for this host, fall back to global defaults (current behavior).

**Evaluation changes in `ServeHTTP`:**
```go
// Current (detect rule skip check):
if cr.rule.Type == "detect" && cr.rule.ParanoiaLevel > 0 && cr.rule.ParanoiaLevel > servicePL {
    continue
}
// New (also check service mask):
if cr.rule.Type == "detect" {
    if mask != nil && mask.disabledRules[cr.rule.ID] {
        continue // disabled for this service
    }
    if cr.rule.ParanoiaLevel > 0 && cr.rule.ParanoiaLevel > effectivePL {
        continue // above effective PL for this service
    }
    // Use effective severity for scoring (mask.severityMap overrides cr.score)
}
```

#### CRS Exclusion Profiles

CRS v4 ships named exclusion profiles (wordpress, nextcloud, drupal, etc.) that disable
specific rules known to cause false positives with those applications. Currently we support
these globally via `WAFConfig.CRSExclusions`. Per-service profiles extend this:

- Global `crs_exclusions: ["wordpress"]` → applies wordpress exclusions to all services
- Service profile `crs_exclusions: ["nextcloud"]` → adds nextcloud exclusions for that service only
- Profiles are additive: service gets `wordpress + nextcloud`
- The plugin resolves named profiles to rule ID sets at compile time using a built-in
  profile registry (same CRS exclusion data we already have in `crs_rules.go`)

#### UI Design (CRS Tab)

```
┌─────────────────────────────────────────────────────────┐
│  CRS Managed Rules                                       │
│                                                          │
│  Service: [▾ Global (all services)  ]   [Deploy]        │
│           │  Global (all services)  │                    │
│           │  api.example.com        │                    │
│           │  blog.example.com       │                    │
│           │  + Add service profile  │                    │
│           └─────────────────────────┘                    │
│                                                          │
│  Paranoia Level: [▾ 2 ]   Threshold: [▾ 10 ]           │
│  CRS Exclusions: [wordpress] [× ] [+ Add]               │
│                                                          │
│  ┌─ PL1 (Core Rules) ─────────── 87 rules ────────────┐ │
│  │ ☑ 920170  GET/HEAD with body   WARNING    PL1       │ │
│  │ ☑ 920270  Invalid character     WARNING    PL1       │ │
│  │ ☐ 941100  XSS via libinjection  WARNING●   PL1      │ │
│  │           ↑ overridden (disabled for this service)   │ │
│  │ ☑ 932120  RCE: Unix command     CRITICAL●  PL2      │ │
│  │           ↑ overridden (severity bumped)             │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌─ Category Overrides ────────────────────────────────┐ │
│  │ attack-xss:   Disabled ●                            │ │
│  │ attack-sqli:  Severity → CRITICAL ●                 │ │
│  │ [+ Add category override]                            │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                          │
│  [Reset to Global Defaults]                              │
└─────────────────────────────────────────────────────────┘
```

- **Service selector** at top — "Global" shows base config, selecting a service shows
  the effective merged state with override indicators (● dot on changed rules/categories).
- **Per-rule toggles** — clicking a rule in service view creates a service-specific override,
  not modifying the global. A "Reset to Global Defaults" button clears all service overrides.
- **Category overrides section** — bulk operations by CRS category tag.
- **Diff view** (optional) — "Show changes from global" toggle highlights only the deltas.

#### API Endpoints (New)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/crs/profiles` | List all service profiles |
| `GET` | `/api/crs/profiles/{service}` | Get profile for a service (returns effective merged state) |
| `PUT` | `/api/crs/profiles/{service}` | Create/update profile for a service |
| `DELETE` | `/api/crs/profiles/{service}` | Delete profile (revert to global defaults) |
| `GET` | `/api/crs/profiles/{service}/effective` | Get fully resolved rule list (all 3 layers merged) |
| `POST` | `/api/crs/profiles/deploy` | Deploy profiles to plugin (writes to policy-rules.json) |

#### Data Storage

- New `CRSProfileStore` (or extend `DefaultRuleStore` with `ServiceProfiles map[string]CRSProfile`)
- Persisted to `/data/crs-profiles.json` (env: `WAF_CRS_PROFILES_FILE`)
- On deploy, wafctl resolves all profiles and passes them to the plugin via the
  `waf_config.per_service` field in `policy-rules.json`
- The plugin never sees "profiles" directly — it gets pre-resolved `PolicyWafServiceConfig`
  objects with `RuleOverrides` already merged from category → rule specificity

#### Comparison to Cloudflare

| Feature | Cloudflare | Our Model |
|---------|------------|-----------|
| Deploy same ruleset multiple times | Yes (per-zone or per-expression) | Yes (per-service profiles) |
| Override individual rule action | Yes (action override) | Yes (enable/disable + severity) |
| Override rule category | Yes (category override) | Yes (category_overrides) |
| Named exclusion profiles | No (manual per-rule) | Yes (wordpress, nextcloud, etc.) |
| Per-zone paranoia level | No (global setting) | Yes (per-service PL) |
| Per-zone anomaly threshold | No (global setting) | Yes (per-service threshold) |
| Diff view (changes from base) | No | Yes (override indicators in UI) |
| Three-level specificity | Two (account + zone) | Three (default + global + service) |

### Event Type Taxonomy (New Model)

With the new allow/skip split, the event classification changes:

| Event Type | Source | HTTP Status | Description |
|------------|--------|-------------|-------------|
| `policy_allow` | Allow rule match | 200 (pass) | Full bypass — request fully trusted, all evaluation stopped |
| `policy_skip` | Skip rule match | 200 (pass) | Selective bypass — specific phases/rules skipped |
| `policy_block` | Block/honeypot rule match | 403 | Explicit deny — terminated by policy rule |
| `detect_block` | CRS anomaly score >= threshold | 403 | CRS blocked — accumulated score exceeded threshold |
| `logged` | CRS anomaly score > 0, < threshold | 200 (pass) | CRS detected but below threshold — informational |
| `rate_limited` | Rate limit counter exceeded | 429 | Rate limited — sliding window counter exceeded |

**`policy_skip` event details should include what was skipped** for observability:
- `skip_phases`: which phases were skipped (e.g., `["detect", "rate_limit"]`)
- `skip_rules`: which specific rules were skipped (e.g., `["941100", "rl-api-1"]`)
- `skip_all`: whether all_remaining was used

This enables the dashboard to show "this request skipped CRS and rate limiting because
it matched the health-check skip rule" in the event detail panel.

### Unified Store Design

Currently there are two separate stores:
- `ExclusionStore` — allow/block/detect rules (`exclusions.json`)
- `RateLimitRuleStore` — rate_limit rules (`ratelimit.json`)

**Option A: Merge into single store** (clean but breaking)
- All rule types in one `PolicyRuleStore` with one JSON file
- Simplifies ordering — one drag-reorder list
- Breaking: API endpoints change, migration needed

**Option B: Keep separate stores, virtual merge at render time** (non-breaking)
- Stores stay separate, existing APIs unchanged
- UI fetches both, interleaves by priority for display
- New `GET /api/policy/pipeline` endpoint returns merged view
- Deploy still merges both into `policy-rules.json` (current behavior)

**Recommended: Option B for Phase 2, Option A for Phase 3.**
Option B ships faster, doesn't break existing API consumers, and the UI can still show
a unified pipeline. The `skip` type goes into ExclusionStore alongside allow/block/detect.
Rate limit rules stay in their own store. The unified pipeline view is a read-only merge.

### wafctl Changes (Complete)

| File | Change | Effort |
|------|--------|--------|
| `models_exclusions.go` | Add `SkipTargets` struct: `Rules []string`, `Phases []string`, `AllRemaining bool`. Add to `RuleExclusion`. | Low |
| `models_exclusions.go` | Add `skip` to `validExclusionTypes`. Update `policyEngineTypes` map. | Low |
| `exclusions_validate.go` | Validate `skip_targets`: phases in `["detect", "rate_limit", "block"]`, rule IDs exist in default-rules or RL store, reject empty skip_targets. | Medium |
| `policy_generator.go` | New `policyTypePriority["allow"] = 50`, `policyTypePriority["skip"] = 200`. Convert skip_targets to `PolicyRule.SkipTargets`. | Medium |
| `policy_generator.go` | Exclusion migration: type `"allow"` → `"skip"` with `phases: ["detect"]` on store load. | Low |
| `handlers_exclusions.go` | Accept `skip_targets` in create/update JSON payloads. Return in GET responses. | Low |
| `handlers_events.go` | Handle new `policy_allow` (full bypass) vs `policy_skip` (selective) event classification. | Medium |
| `access_log_store.go` | Detect allow vs skip from `policy_engine.action` var: `"allow"` → `policy_allow`, `"skip"` → `policy_skip`. | Low |
| `waf_summary.go` | No change needed if allow/skip both map to non-terminating event types. The summary already splits policy_allow and policy_skip. | None |

**CRS Profiles (new files):**

| File | Description | Effort |
|------|-------------|--------|
| `crs_profiles.go` (~300 lines) | `CRSProfileStore`: CRUD, validation, persistence, merge resolution | Medium |
| `handlers_crs_profiles.go` (~200 lines) | HTTP handlers for `/api/crs/profiles` endpoints | Medium |
| `policy_generator.go` | Extend `PolicyWafConfig` generation to include resolved per-service profiles | Medium |

### Plugin Changes (caddy-policy-engine — Complete)

| File | Change | Effort |
|------|--------|--------|
| `policyengine.go` | Add `SkipTargets` to `PolicyRule` type: `Rules []string`, `Phases []string`, `AllRemaining bool` | Low |
| `policyengine.go` | Compile step: build skip target index (which rules can be skipped) | Low |
| `policyengine.go` | New 5-pass `ServeHTTP`: allow terminates, skip accumulates flags, block/RL/detect check flags | Medium |
| `policyengine.go` | `serviceRuleMask` compile-time resolution from `PolicyWafServiceConfig.RuleOverrides`/`CategoryOverrides` | Medium |
| `policyengine.go` | Effective severity lookup: `mask.severityMap[ruleID]` → override `cr.score` at eval time | Low |
| `policyengine_test.go` | Allow-terminates, skip-phases, skip-rules, skip-all-remaining tests | Medium |
| `policyengine_test.go` | Skip+block interaction (skip doesn't override blocks above it) | Low |
| `policyengine_test.go` | Skip+RL interaction (skipped RL counters don't tick) | Low |
| `policyengine_test.go` | Per-service rule mask tests (disabled rules, severity override, category override) | Medium |
| `policyengine_test.go` | Service profile + global override merge tests | Medium |

### Frontend Changes (Complete)

**Policy Rules page (`/policy`):**

| Component | Change | Effort |
|-----------|--------|--------|
| `PolicyEngine.tsx` | Add `skip` and `rate_limit` to rule type selector. Show RL-specific fields when rate_limit selected. Show skip_targets fields when skip selected. | High |
| `policy/PolicyForms.tsx` | Skip form: phase checkboxes (detect, rate_limit, block), rule ID multi-select, all_remaining toggle | Medium |
| `policy/PolicyForms.tsx` | Rate limit form: key selector, events, window, action (reuse from current `RuleForm.tsx`) | Medium |
| `policy/constants.ts` | Add `skip` type with color/label/description. Update priority band labels. | Low |
| `RateLimitsPanel.tsx` | Deprecate as standalone page OR keep as "RL-focused view" that filters the unified pipeline | TBD |

**CRS Settings page (`/rules/crs`):**

| Component | Change | Effort |
|-----------|--------|--------|
| `RulesPanel.tsx` | Add service selector dropdown at top. Fetch/display per-service profile. | Medium |
| `RulesPanel.tsx` | Override indicators (● dot) on rules/categories that differ from global. | Medium |
| `RulesPanel.tsx` | Category overrides section with bulk enable/disable/severity per category tag. | Medium |
| `RulesPanel.tsx` | "Reset to Global Defaults" button per service. | Low |
| `lib/api/config.ts` | New `fetchCRSProfiles`, `updateCRSProfile`, `deleteCRSProfile` API functions. | Medium |

### Edge Cases and Invariants

1. **Allow above block**: An `allow` rule at priority 50 fires before blocks at priority 100.
   If a request matches both the allow condition AND a block condition, allow wins (terminates
   first). This is intentional — it's the "trusted traffic" escape hatch. If the user wants
   blocks to still apply, they should use `skip` instead of `allow`.

2. **Multiple skip rules**: If two skip rules match the same request, their skip_targets are
   merged (union). Skip rule A skips `["detect"]`, skip rule B skips `["rate_limit"]` → both
   detect and rate_limit are skipped. This is non-terminating merge behavior.

3. **Skip targeting a rule that doesn't exist**: Validation warns but doesn't reject — rules
   may be added later, or IDs may reference default rules not yet loaded. At eval time,
   skipping a non-existent rule is a no-op.

4. **Skip + detect scoring**: If a skip rule says `skip_targets.rules: ["941100"]` and detect
   rule 941100 would have matched, it's skipped (score not accumulated). Other detect rules
   still fire. The post-loop threshold check uses the reduced score.

5. **Skip + RL counter ticking**: If a skip rule skips a rate_limit rule, the counter does NOT
   tick for that request. This is different from the current `allow` behavior where RL counters
   always tick. When you skip an RL rule, you're saying "this traffic is exempt."

6. **Service profile + skip interaction**: A skip rule that skips `phases: ["detect"]` bypasses
   ALL detect rules including those modified by service profiles. Service profiles only affect
   which detect rules are active and their severity — they don't override skip decisions.

7. **Drag-reorder in unified UI**: Users can reorder within their priority band but NOT across
   bands (allow rules can't be dragged below blocks). The UI enforces band boundaries visually
   with section headers and prevents cross-band drops.

8. **Backward compat for API consumers**: The existing `/api/exclusions` and `/api/rate-rules`
   endpoints continue to work unchanged. The unified pipeline view is a new read-only endpoint
   (`GET /api/policy/pipeline`) that merges both stores for display purposes.

### Migration Plan (Detailed)

**Step 1 — Plugin v0.7.0** (caddy-policy-engine):
- Add `SkipTargets` to `PolicyRule` type
- Add `skip` to action handler in `ServeHTTP` (accumulate flags, non-terminating)
- Change `allow` to terminate immediately (breaking change — but wafctl regenerates rules)
- Add skip flag checks to block/RL/detect evaluation
- Extend `PolicyWafServiceConfig` with `RuleOverrides`/`CategoryOverrides`
- Build `serviceRuleMask` at compile time
- All new tests

**Step 2 — wafctl + frontend** (caddy-compose):
- Add `skip` exclusion type to models + validation + handlers
- Store migration: existing `allow` exclusions → `skip` with `phases: ["detect"]`
- New `allow` type = full bypass (priority 50)
- `CRSProfileStore` + handlers + API endpoints
- Policy generator: emit new priority bands, include service profiles in waf_config
- Frontend: unified pipeline UI, CRS tab service selector

**Step 3 — RL store merge** (optional, Phase 3):
- Merge `RateLimitRuleStore` into `ExclusionStore` (or rename to `PolicyRuleStore`)
- Single ordered list, single JSON file
- Simplify deploy pipeline (one store → one generator call)

### Implementation Priority

This is a **Phase 2** feature — implement after the current deploy cycle. The current
detect_block split and existing code review fixes ship first. This design spec ensures
the architecture is documented before we start building.

Estimated effort: ~3-4 days for plugin + wafctl + frontend for the allow/skip refactor
(Steps 1-2 without CRS profiles). CRS profiles add ~2-3 days. RL store merge is Phase 3.

---

## Design Spec: Rate Limiting Algorithm Improvements

### Current State

The plugin uses **fixed-window interpolation** (sliding window counter), the same algorithm
used by nginx, envoy, and Cloudflare:

```
effectiveCount = prevCount × (1 - elapsed/window) + currCount
```

State per key: two counters + two timestamps (32 bytes). 16-shard concurrent map for
lock contention reduction. Sweep goroutine evicts expired counters.

**Strengths:**
- O(1) per-request (no timestamp lists, no sorted sets)
- Minimal memory (32 bytes per key vs token bucket's ~24 or GCRA's ~16)
- Smooth interpolation — no hard window boundary spikes
- Counter preservation across hot-reloads (zone config unchanged → keep counters)
- Well-understood — same algorithm as the major CDNs

**Weaknesses:**
- No burst allowance — can't express "100/min with burst of 20"
- No graduated response — hard cliff from "allowed" to "denied"
- No response-aware counting — can't count only errors (e.g., "10 failed logins/5min")
- No compound keys with independent limits — can't say "100/IP/min AND 1000/path/min"
- No backoff escalation — repeat offenders get the same Retry-After every time
- Slight over-counting at interpolation boundaries (ceil rounds up)
- No penalty box / timeout — once the window slides past, offender is immediately back

### Algorithm Improvements

#### 1. Token Bucket Mode (Burst Support)

**Problem:** The sliding window treats all traffic uniformly. APIs often need to allow
short bursts (e.g., a batch of requests on page load) while still enforcing a sustained
rate. Currently, a client sending 10 requests in 1 second hits the limit even if the
rule allows 100/min — the window hasn't accumulated enough capacity.

**Solution:** Add a token bucket mode alongside the existing sliding window. Users choose
per-rule which algorithm to use.

```go
type counter struct {
    // Sliding window fields (existing)
    prevCount int64
    prevStart int64
    currCount int64
    currStart int64

    // Token bucket fields (new)
    tokens     float64  // current tokens available
    lastRefill int64    // last refill timestamp (unix nanos)
}
```

**Token bucket algorithm:**
```
On each request:
  1. elapsed = now - lastRefill
  2. tokens = min(tokens + elapsed × refillRate, burst)
  3. lastRefill = now
  4. if tokens >= 1.0: tokens -= 1.0; ALLOW
     else: DENY
```

Where: `refillRate = events / window` (tokens per nanosecond), `burst` = configurable
maximum token accumulation (defaults to `events` if not set).

**Data model extension:**

```json
{
  "rate_limit": {
    "key": "client_ip",
    "events": 100,
    "window": "1m",
    "burst": 20,
    "algorithm": "token_bucket",
    "action": "deny"
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `algorithm` | `string` | `"sliding_window"` | `"sliding_window"` or `"token_bucket"` |
| `burst` | `int` | `events` | Max burst size (token bucket only). Must be >= 1 and <= events. |

When `algorithm` is omitted or `"sliding_window"`, existing behavior is unchanged.
When `"token_bucket"`, the counter uses token bucket logic. Both share the same `zone`
infrastructure, `shard` map, and sweep goroutine.

**Memory:** Token bucket is actually smaller per key — `float64 + int64` = 16 bytes vs
sliding window's 32 bytes. Both fit in the same `counter` struct (union-style, fields
unused by the other algorithm are zero).

#### 2. Response-Aware Counting

**Problem:** Rate limiting counts all requests equally. For login endpoints, you want
to count only failed attempts (4xx responses), not successful ones. For APIs, you might
want to count only 5xx responses to detect backend overload.

**Solution:** Add optional `count_on` field that filters which responses increment
the counter. This requires a response-phase hook — the counter increments after the
upstream responds, not on request receipt.

```json
{
  "rate_limit": {
    "key": "client_ip",
    "events": 5,
    "window": "15m",
    "count_on": "response_status:4xx",
    "action": "deny"
  }
}
```

**`count_on` values:**

| Value | Counts When |
|-------|-------------|
| (empty/omitted) | Every request (current behavior) |
| `response_status:4xx` | Response status 400-499 |
| `response_status:5xx` | Response status 500-599 |
| `response_status:401,403` | Response status exactly 401 or 403 |
| `response_status:!2xx` | Response status NOT 200-299 |

**Implementation:** This requires the plugin to wrap `next.ServeHTTP()` with a
`ResponseRecorder` to capture the status code, then conditionally increment the counter.
The deny check still happens on request receipt (using the current count), but the
increment happens after the response:

```go
// Pseudo-code for response-aware counting
if rl.countOn != "" {
    // Don't increment on request — just check current count
    if !z.check(key, now) {  // check without increment
        return 429
    }
    // Wrap next handler to capture response status
    recorder := newResponseRecorder(w)
    err := next.ServeHTTP(recorder, r)
    recorder.Flush()
    if matchesCountOn(recorder.Status(), rl.countOn) {
        z.increment(key, now)  // only count matching responses
    }
    return err
} else {
    // Current behavior — count on request
    allowed, count, limit := z.allow(key, now)
    ...
}
```

**Caveat:** Response-aware counting adds latency (must buffer response to check status)
and memory (ResponseRecorder). Only enable when `count_on` is configured. The `zone.allow`
method splits into `zone.check` (read-only) and `zone.increment` (write) for this mode.

#### 3. Penalty Box / Timeout Escalation

**Problem:** Repeat offenders get the same treatment on every window. A scanner that
triggers rate limits every 60 seconds just waits 60 seconds and tries again. There's no
escalation or cooling-off period.

**Solution:** Add an optional penalty box that extends the deny duration for repeat
offenders using exponential backoff.

```json
{
  "rate_limit": {
    "key": "client_ip",
    "events": 100,
    "window": "1m",
    "action": "deny",
    "penalty": {
      "enabled": true,
      "initial_timeout": "1m",
      "max_timeout": "1h",
      "multiplier": 2.0,
      "decay_after": "10m"
    }
  }
}
```

**Penalty algorithm:**
```
On rate limit exceeded:
  1. Look up penalty state for this key
  2. If no penalty state or expired: timeout = initial_timeout, strikes = 1
  3. If existing penalty: timeout = min(prev_timeout × multiplier, max_timeout), strikes++
  4. Deny until: now + timeout
  5. Set Retry-After header to timeout seconds
  6. If no requests for decay_after duration: reset penalty state

On request within penalty period:
  1. Deny immediately (don't even check counter)
  2. DO NOT reset the penalty timer (prevent reset attacks)
```

**State per key:** Add to `counter`:
```go
type counter struct {
    // ... existing fields ...

    // Penalty box fields
    penaltyUntil int64   // unix nanos — deny all requests before this time
    penaltyLevel int     // current escalation level (0 = none, 1 = first strike, ...)
    lastDenied   int64   // last time a deny was issued (for decay)
}
```

**Memory impact:** +24 bytes per key. Only populated for keys that exceed the rate limit.
Swept alongside normal counter expiry.

**Interaction with skip rules:** A `skip` rule that skips a rate_limit rule also skips
its penalty box. Penalty state is per-zone, not global — different RL rules have
independent penalty tracking.

#### 4. Compound Rate Limits (Multi-Key)

**Problem:** Can't express "100 requests per IP per minute AND 1000 requests per path per
minute." Currently each rule has one key. To achieve multi-dimensional limiting, you need
multiple rules, and they're evaluated independently (no AND relationship).

**Solution:** Add `compound_keys` field — an array of key specs that must ALL be under
their respective limits for the request to pass.

```json
{
  "rate_limit": {
    "key": "compound",
    "compound_keys": [
      { "key": "client_ip", "events": 100, "window": "1m" },
      { "key": "path", "events": 1000, "window": "1m" }
    ],
    "action": "deny"
  }
}
```

**Evaluation:** Each compound key gets its own zone (sub-zone). ALL must allow for the
request to pass. If ANY denies, the request is denied. Counter increment happens only if
all allow (atomic-style — either all tick or none tick, preventing one dimension from
unfairly counting requests that the other dimension blocked).

**Implementation:** The `zone` struct gets an optional `subZones` slice. The `allow` method
iterates all sub-zones, checks all, then increments all if all passed.

```go
func (z *zone) allowCompound(keys []string, now time.Time) (bool, int64, int) {
    // Phase 1: check all sub-zones (read-only)
    for i, sub := range z.subZones {
        if !sub.check(keys[i], now) {
            return false, 0, sub.events
        }
    }
    // Phase 2: all passed — increment all
    for i, sub := range z.subZones {
        sub.increment(keys[i], now)
    }
    return true, 0, 0
}
```

**Use cases:**
- Per-IP + per-path: prevent one IP from hammering one endpoint, AND prevent any endpoint
  from being overwhelmed regardless of IP distribution (DDoS with many IPs)
- Per-IP + per-API-key: shared API key shouldn't allow unlimited IPs
- Per-IP + global: individual limit + total capacity limit

#### 5. Graduated Response (Soft → Hard)

**Problem:** Rate limiting is binary — you're either allowed or denied. No middle ground.
Many APIs benefit from graduated degradation: warn the client they're approaching the limit,
then throttle (add delay), then deny.

**Solution:** Add `thresholds` array with escalating actions:

```json
{
  "rate_limit": {
    "key": "client_ip",
    "events": 100,
    "window": "1m",
    "thresholds": [
      { "at": 80, "action": "warn" },
      { "at": 95, "action": "throttle", "delay_ms": 500 },
      { "at": 100, "action": "deny" }
    ]
  }
}
```

**Threshold actions:**

| Action | Behavior | Headers |
|--------|----------|---------|
| `warn` | Allow but add warning headers | `X-RateLimit-Warning: approaching limit` |
| `throttle` | Allow after artificial delay | `X-RateLimit-Throttled: 500ms` |
| `deny` | Block with 429 (current behavior) | Standard rate limit headers |
| `challenge` | Return 429 with captcha hint | `X-RateLimit-Challenge: true` (future) |

**Implementation:** After computing `effective` count, walk thresholds in reverse order
(highest first) to find the applicable action. The `throttle` action uses `time.Sleep()`
before calling `next.ServeHTTP()` — simple but effective for small delays.

```go
if effective >= threshold.at {
    switch threshold.action {
    case "warn":
        w.Header().Set("X-RateLimit-Warning", "approaching limit")
        // allow through
    case "throttle":
        time.Sleep(time.Duration(threshold.delayMs) * time.Millisecond)
        // allow through (after delay)
    case "deny":
        return 429
    }
    break // only apply highest matching threshold
}
```

**Caveat:** `throttle` holds a goroutine for the delay duration. Under attack, this could
exhaust goroutines. Add a max-concurrent-throttles limit (e.g., 1000) — if exceeded, escalate
to deny. This prevents throttle from becoming a resource exhaustion vector.

#### 6. Adaptive Rate Limiting (Backend Health)

**Problem:** Static rate limits don't account for backend health. If the origin server is
struggling (high latency, error rate), the rate limit should tighten automatically. If the
backend is healthy, limits can be relaxed.

**Solution:** Monitor upstream response latency and error rate, adjust effective rate limit
dynamically within a configured range.

```json
{
  "rate_limit": {
    "key": "client_ip",
    "events": 100,
    "window": "1m",
    "adaptive": {
      "enabled": true,
      "min_events": 20,
      "max_events": 200,
      "latency_target_ms": 200,
      "error_rate_target": 0.05,
      "adjustment_interval": "10s"
    }
  }
}
```

**Algorithm (AIMD — Additive Increase, Multiplicative Decrease):**
```
Every adjustment_interval:
  1. Sample upstream P95 latency and error rate over the interval
  2. If latency > target OR error_rate > target:
     effective_events = max(effective_events × 0.75, min_events)   ← multiplicative decrease
  3. Else if latency < target × 0.5 AND error_rate < target × 0.5:
     effective_events = min(effective_events + 5, max_events)       ← additive increase
  4. Otherwise: hold steady
```

**Implementation complexity:** High. Requires:
- Response latency sampling (wrap `next.ServeHTTP()` with timer)
- Error rate tracking (count 5xx responses)
- Per-service health metrics aggregation
- Thread-safe effective_events updates
- Hysteresis to prevent oscillation

**This is a Phase 3+ feature.** The sliding window and token bucket improvements should
ship first. Adaptive RL is a significant subsystem addition.

#### 7. Distributed Rate Limiting (Multi-Instance)

**Problem:** In a multi-instance deployment (e.g., Kubernetes with multiple Caddy pods),
each instance maintains independent counters. A client sending requests round-robin across
N instances effectively gets N× the rate limit.

**Current state:** The plugin has `RateLimitGlobalConfig` with `read_interval` and
`write_interval` fields that were designed for distributed sync but are not implemented.

**Solution options:**

| Approach | Complexity | Accuracy | Latency Impact |
|----------|------------|----------|----------------|
| Redis backend | Medium | High | +1-2ms per request (network hop) |
| Gossip protocol (Serf/memberlist) | High | Medium | +0-1ms (async) |
| Shared volume counter files | Low | Low | ~seconds delay |
| Accept over-counting (document it) | None | Low | None |

**Recommended: Redis backend (Phase 3+)**

```json
{
  "rate_limit_config": {
    "distributed": {
      "backend": "redis",
      "url": "redis://redis:6379/0",
      "key_prefix": "rl:",
      "sync_mode": "full"
    }
  }
}
```

Two sync modes:
- `full`: Every allow/deny check hits Redis (accurate, +latency)
- `approximate`: Local counter + periodic sync to Redis (fast, eventual consistency)

The approximate mode uses the same sliding window algorithm locally but periodically
(every `write_interval`) flushes local counts to Redis and reads the global count. The
effective limit is `events / num_instances` locally, with periodic global reconciliation.

**This is Phase 3+.** Single-instance deployment (current) works fine with local counters.

### Priority and Phasing

| Feature | Phase | Effort | Value |
|---------|-------|--------|-------|
| Token bucket mode (burst) | **Phase 2** | Medium | High — burst support is the most requested RL feature |
| Response-aware counting | **Phase 2** | Medium | High — login brute-force protection needs this |
| Penalty box / timeout | **Phase 2** | Low-Medium | Medium — scanner deterrence |
| Compound keys | **Phase 3** | Medium | Medium — DDoS scenarios need multi-dimensional limits |
| Graduated response | **Phase 3** | Medium | Medium — better UX for API rate limiting |
| Adaptive RL | **Phase 3+** | High | Medium — nice-to-have for auto-scaling scenarios |
| Distributed RL | **Phase 3+** | High | High for multi-instance, N/A for single-instance |

### Data Model Summary (All Features)

```json
{
  "rate_limit": {
    "key": "client_ip",
    "events": 100,
    "window": "1m",
    "action": "deny",
    "algorithm": "sliding_window",
    "burst": 20,
    "count_on": "response_status:4xx",
    "penalty": {
      "enabled": true,
      "initial_timeout": "1m",
      "max_timeout": "1h",
      "multiplier": 2.0,
      "decay_after": "10m"
    },
    "compound_keys": [
      { "key": "client_ip", "events": 100, "window": "1m" },
      { "key": "path", "events": 1000, "window": "1m" }
    ],
    "thresholds": [
      { "at": 80, "action": "warn" },
      { "at": 95, "action": "throttle", "delay_ms": 500 },
      { "at": 100, "action": "deny" }
    ]
  }
}
```

All new fields are optional with backward-compatible defaults. Existing rules continue
to work unchanged. New features are orthogonal — can be combined (e.g., token bucket +
penalty + response-aware).

---

### Deploy-time Actions (First Coraza-Free Deploy)

On first production deploy after Coraza removal, manually clean up on the remote host:

```bash
# Delete legacy JSONL event files (events will rebuild from fresh access logs)
rm -f /data/events.jsonl /data/access-events.jsonl
rm -f /data/.audit-log-offset /data/.access-log-offset
rm -f /var/log/waf-audit.log*

# Delete legacy .caddy rate limit files (policy engine handles RL now)
rm -f /data/caddy/rl/*_rl*.caddy

# Delete legacy Coraza config files if present
rm -f /data/coraza/*.conf
```

These files contain legacy event formats (rl- prefix IDs, Coraza transaction IDs,
old event types like `ipsum_blocked`, `honeypot`, `scanner`). Starting fresh ensures
all events use Caddy request UUIDs and the new event classification.
