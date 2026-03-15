# PLAN.md — Policy Engine Roadmap

## Current State (v2.32.0 / caddy 3.31.0 / plugin v0.16.0)

Fully operational WAF with custom policy engine, CRS 4.24.1 (313 rules: 254 inbound +
59 outbound, auto-converted at Docker build time), 5-pass evaluation (allow → block →
skip → rate_limit → detect), outbound anomaly scoring (response headers + body),
per-service category masks with frontend UI, 6 negated operators, managed lists, IPsum
blocklist (8 levels, 618K IPs), unified /policy page (WAF rules + rate limits tabs),
unified rule store (`/api/rules` + `/api/deploy`), and e2e CI pipeline
(106 e2e tests, 500 Go unit tests, 326 frontend tests).

---

## Deployed (v2.26.0 → v2.31.0)

### Operator & Condition Builder
- [x] Method pills (MethodMultiSelect single mode for eq/neq)
- [x] Host multi-select (HostMultiSelect with search, scroll, custom entry)
- [x] Comprehensive operator alignment (all string fields: 16 ops, enum: 6, IP: 8)
- [x] Condition builder: preserve value on operator change, previous value pill on field change
- [x] 275 Go + 23 frontend operator validation tests

### Performance
- [x] Remove Caddy reload from deploy (hot-reload via mtime polling)
- [x] Cache BuildServiceFQDNMap with mtime invalidation (26x faster)
- [x] Summary cache TTL 3s→10s, events early-exit pagination
- [x] matchIntField (zero-alloc status code filter), 16 Go benchmarks

### Policy Page UX
- [x] 25/page, clickable order numbers, move-to-position, multi-drag, bulk move
- [x] Back-to-events link, Skip type filter, per-page count in all pagination
- [x] UI unification: WAF Rules + Rate Limits merged into /policy with tabs

### Event & Log Detail
- [x] 2-column grid layout, TruncatedCode for long values, CopyBtn on all fields
- [x] Inline skipped rule pills, URI/User-Agent truncation with expand

### CRS & Rules
- [x] CRS CI automation: crs-rules Dockerfile stage, CRS_VERSION build arg
- [x] Dynamic CRS version from default-rules.json (was hardcoded)
- [x] Response-phase CRS categories (Leakage, SQL Leak, Web Shell, etc.)
- [x] Outbound threshold UI in WAF Engine Settings
- [x] Settings badge: "PL2 · In 15 · Out 10"
- [x] Dead config cleanup: disabled_groups removed, mode validation removed

### Response-Phase Detection (plugin v0.15.0 + v0.16.0)
- [x] Phase A: response_status, response_header, response_content_type fields
- [x] Phase B: response body buffering via Caddy ResponseRecorder, can block 403
- [x] Phase C: CRS converter emits 59 outbound rules (313 total)
- [x] Per-service category masks (disabled_categories) — plugin v0.16.0
- [x] E2E smoke tested: SQL error leakage blocked, category masks verified

### Infrastructure
- [x] Cache SSD migration (/mnt/cache/caddy/), event logs on array
- [x] Sidebar footer sticky, exclusion hits scanning ALS
- [x] Fix events "All (-1)" display

---

## Deployed (v2.31.0 → v2.32.0)

### Per-Service Category Masks — Complete
- [x] Plugin v0.16.0: `disabled_categories` globally and per-service in `waf_config`
- [x] wafctl: `DisabledCategories` in `WAFServiceSettings`, deep copy, validation (3-4 digit numeric)
- [x] Policy generator: `DisabledCategories` in `PolicyWafConfig`/`PolicyWafServiceConfig`
- [x] Frontend `CategoryToggles` component (inbound/outbound grid, enable all, per-service compact)
- [x] Global disabled categories in WAF Engine Settings card
- [x] Per-service disabled categories in `ServiceSettingsCard`
- [x] Badge indicators: "N cat off" in WAF Engine Settings + per-service headers
- [x] Removed dead `categories?: unknown` prop from `ServiceSettingsCard`

### E2E Test Suite — Fixed & Expanded
- [x] Fixed 11 e2e failures (0 remaining, 4 skipped for known plugin limitations)
- [x] Fixed TestDeployPipeline — accept reloaded=false (mtime hot-reload)
- [x] Fixed TestWAFBlocking — config isolation via `ensureDefaultConfig`, browser headers
- [x] Fixed TestWebSocketThroughWAF — canary block rule for reliable deploy propagation
- [x] Fixed TestDefaultRulesBulkBehavior — `waitForCondition` for threshold propagation
- [x] Fixed TestLoggedEventsCollected — polling wait replaces fixed sleep
- [x] Fixed TestDetectBlockSummarySplit — accept total=-1 for filtered queries
- [x] Added 3 new category mask tests: validation, deploy persistence, per-service persistence
- [x] Total: 106 e2e tests (15 in outbound/categories file), 26 e2e test files

---

## Known Plugin Limitations (v0.16.0)

These features are wired in wafctl and generated into policy-rules.json, but the
Caddy plugin does not yet implement them. E2E tests are skipped with markers.

- [ ] `negate` field on conditions — condition inversion ignored by plugin
- [ ] `multi_match` — evaluates only final transform stage, not at each stage
- [ ] `not_in` operator — treats as always-true (blocks all instead of non-matching)
- [ ] `not_in_list` operator — negated list membership check ignored

When the plugin implements these, remove the `t.Skip()` calls in:
  `21_condition_features_test.go` (multi_match, negate),
  `23_skip_negated_test.go` (not_in),
  `10_policy_lists_test.go` (not_in_list).

---

## Next Up — Unified Policy Engine (v3.0)

The goal: make `policy-rules.json` the **single control plane** for all
request/response processing. Everything hot-reloads via mtime polling — no
Caddy restart. Rate limits, CSP, security headers, caching, CORS, and custom
header manipulation all become policy-engine concerns, managed through one
unified API and UI.

### Architecture Context

Today the deploy pipeline already reads all 6 config stores (ExclusionStore,
RateLimitRuleStore, ConfigStore, CSPStore, SecurityHeaderStore, DefaultRuleStore)
and writes one `policy-rules.json`. There are 4 identical deploy endpoints
(`/api/config/deploy`, `/api/rate-rules/deploy`, `/api/csp/deploy`,
`/api/security-headers/deploy`) that all do the same thing. The fragmentation
is purely at the API/UI level — the data is already unified at the file level.

### Phase 1: Quick Wins (pre-unification cleanup) — DONE

- [x] `SecurityHeaderStore.deepCopy` — field-by-field copy via `copyStringMap`
- [x] `IPLookupPanel` — split 893→7 files under `ip-lookup/`, recharts isolated
- [x] `operatorChip()` — investigated, not a bug (FilterOp matches events API)
- [ ] Mode field removal — deferred to Phase 2h (40+ test touchpoints, zero impact)

### Phase 2: Rule Store Unification (Backend) — DONE

`RuleExclusion` is now the unified type for all rule types. `ExclusionStore` is
the single rule store. `/api/rules` is the canonical CRUD endpoint; `/api/deploy`
is the single deploy endpoint. Old endpoints (`/api/exclusions`, `/api/config/deploy`)
kept as aliases.

**Unified RuleExclusion (superset — `models_exclusions.go`):**
```
type RuleExclusion struct {
    // Common fields (all types)
    ID, Name, Description, Type string   // Type: allow|block|skip|detect|rate_limit
    Conditions    []Condition
    GroupOp       string                 // "and"|"or"
    Tags          []string
    Enabled       bool
    Service       string                 // hostname or "*" for per-service scoping
    Priority      int                    // explicit ordering within type band
    CreatedAt, UpdatedAt time.Time

    // skip-only
    SkipTargets   *SkipTargets

    // detect-only
    Severity            string           // CRITICAL|ERROR|WARNING|NOTICE
    DetectParanoiaLevel int              // 1-4

    // rate_limit-only
    RateLimit     *RateLimitConfig       // key, events, window, action
}
```

**Completed:**
- [x] `RuleExclusion` extended as superset (Service, Priority, RateLimitKey/Events/Window/Action)
- [x] `rate_limit` added to `validExclusionTypes` and `policyEngineTypes`
- [x] `validateExclusion()` handles rate_limit (key, events, window, action, priority, service)
- [x] Policy generator emits rate_limit config from unified exclusion rules
- [x] Per-service scoping (`Service` field) for all rule types
- [x] `RateLimitGlobal` added to `WAFConfig`
- [x] `/api/rules` CRUD + `/api/deploy` registered in main.go
- [x] Frontend: `ExclusionType` includes `rate_limit`, interfaces updated
- [x] `deployConfig()` uses unified `/api/deploy`
- [x] Old endpoints (`/api/exclusions/*`, `/api/config/deploy`) kept as aliases

**Cleanup completed:**
- [x] Deleted `rl_rules.go` (491 lines), `rl_rules_test.go` (739), `rl_handlers_test.go` (342)
      — net -1,913 lines across 25 files
- [x] Removed all `/api/rate-rules` CRUD routes; kept analytics endpoints (hits, advisor)
- [x] Deploy reads `RateLimitGlobal` from `ConfigStore` (not deleted RL store)
- [x] Policy generator no longer takes `rlRules` param; unified loop handles all types
- [x] Mode field deprecated (`json:"mode,omitempty"`), no longer set by defaults
- [x] Backup includes `default_rule_overrides`; restore gracefully handles them
- [x] All e2e tests updated to `/api/rules` with `type: "rate_limit"` payloads
- [x] Full suite: 529 Go unit tests, 348 frontend tests, 106 e2e tests — all pass

### Phase 3: Response-Phase Policy Rules

Enable all rule types (allow, block, skip, detect, rate_limit) to operate on
response-phase fields, not just inbound. This makes rate limits and custom
rules work on response data (status codes, headers, body).

**Plugin (caddy-policy-engine):**
- [ ] Extend rule evaluation to response phase for all types (currently only detect)
- [ ] `phase: "outbound"` on any rule type triggers response-phase evaluation
- [ ] Rate limit rules with `phase: "outbound"` — count responses by status code, etc.
- [ ] Block rules on response_status/response_header — reject before client sees response

**wafctl:**
- [ ] Remove `validPolicyEngineFields` restriction on response_status/response_header
      for non-detect types (currently rejected for allow/block/skip/rate_limit)
- [ ] UI: phase selector (inbound/outbound) in rule editor for all types
- [ ] Condition builder: show response-phase fields when phase=outbound

### Phase 4: Header & Caching Policies (Plugin-Managed)

Move header manipulation and caching rules from Caddyfile snippets into
`policy-rules.json` so they hot-reload without Caddy restart.

**New policy-rules.json sections:**
```json
{
  "response_headers": {
    "csp": { ... },             // Already exists
    "security": { ... },        // Already exists
    "custom": {                  // NEW: arbitrary per-service headers
      "global": { "set": {}, "add": {}, "remove": [] },
      "per_service": { "svc": { "set": {}, "add": {}, "remove": [] } }
    },
    "cors": {                    // NEW: replaces (cors) Caddyfile snippet
      "allowed_origins": [],
      "allowed_methods": [],
      "allowed_headers": [],
      "exposed_headers": [],
      "max_age": 3600,
      "per_service": {}
    }
  },
  "request_headers": {           // NEW: request-phase header manipulation
    "global": { "set": {}, "add": {}, "remove": [] },
    "per_service": {}
  },
  "cache_control": {             // NEW: replaces (static_cache) snippet
    "rules": [
      { "path_match": "/_astro/*", "value": "public, max-age=31536000, immutable" },
      { "path_match": "*.{css,js,woff2}", "value": "public, max-age=604800" }
    ],
    "per_service": {}
  }
}
```

**wafctl stores:**
- [ ] `CustomHeaderStore` — request/response header manipulation per-service
- [ ] `CORSStore` — CORS config per-service (or fold into CustomHeaderStore)
- [ ] `CacheStore` — path-based Cache-Control rules per-service
- [ ] All feed into `BuildPolicyResponseHeaders()` → `policy-rules.json`

**Plugin:**
- [ ] Parse and apply `custom` response headers (set/add/remove)
- [ ] Parse and apply `cors` config (preflight handling, origin validation)
- [ ] Parse and apply `request_headers` (set/add/remove before proxying)
- [ ] Parse and apply `cache_control` rules (path matching → Cache-Control header)

**Frontend:**
- [ ] Custom headers UI (global + per-service set/add/remove)
- [ ] CORS config UI (origins, methods, headers, max-age)
- [ ] Cache rules UI (path patterns, Cache-Control values)

**Caddyfile cleanup:**
- [ ] Remove `(static_cache)` snippet after plugin handles it
- [ ] Remove `(cors)` snippet after plugin handles it
- [ ] Remove individual `header` directives that duplicate plugin functionality

### Phase 5: Rate Limits Parity (UI)

After backend unification, the RL tab in `/policy` gets full parity with the
WAF rules tab. This is simpler post-unification since both share the same API.

- [ ] Bulk select, move-to-edge, inline position editing in RL tab
- [ ] Multi-drag reorder (already works for WAF rules)
- [ ] Per-page count selector
- [ ] Import/export rate limit rules

### Phase 6: CRS Automation

- [ ] GitHub Actions workflow to check latest CRS release
- [ ] Auto-open PR bumping `CRS_VERSION` in Dockerfile
- [ ] Run CRS test suite against policy engine for accuracy validation

---

## Future Items

### Performance
- [ ] Incremental summary computation — running counters on Store, O(1) reads

### Features
- [ ] Custom rulesets — native policy-engine rule format for user-created detect rules
- [ ] CRS accuracy evaluation against CRS test suite
- [ ] Outbound score display in event detail panel
- [ ] Filter events by inbound/outbound phase

### Operational
- [ ] Audit each service's built-in auth and document decisions
- [ ] Add forward_auth to dockge at minimum
- [ ] Monitor and document sizing guidance for event stores
