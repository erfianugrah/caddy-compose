# PLAN.md — Policy Engine Roadmap

## Current State (v2.31.0 / caddy 3.30.0 / plugin v0.16.0)

Fully operational WAF with custom policy engine, CRS 4.24.1 (313 rules: 254 inbound +
59 outbound, auto-converted at Docker build time), 5-pass evaluation (allow → block →
skip → rate_limit → detect), outbound anomaly scoring (response headers + body),
per-service category masks, 6 negated operators, managed lists, IPsum blocklist
(8 levels, 597K IPs), unified /policy page (WAF rules + rate limits tabs), and
e2e CI pipeline.

---

## Deployed (this session: v2.26.0 → v2.31.0)

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

## In Progress — Uncommitted Work

### Per-Service Category Masks (wafctl + frontend wiring)

**Plugin side: DONE** (v0.16.0 tagged + pushed). Plugin supports `disabled_categories`
globally and per-service in `waf_config`. Smoke tested with xcaddy.

**wafctl side: IN PROGRESS** (uncommitted changes):
- `wafctl/models_exclusions.go` — added `DisabledCategories []string` to `WAFServiceSettings`
- `wafctl/policy_generator.go` — added `Phase` to `PolicyRule`, `DisabledCategories`
  to `PolicyWafConfig`/`PolicyWafServiceConfig`, wired through `BuildPolicyWafConfig`
- `wafctl/config.go` — deep copy for `DisabledCategories`, validation (3-4 digit numeric prefix)
- `waf-dashboard/src/lib/api/config.ts` — added `disabled_categories?: string[]`
- `Dockerfile` — updated to plugin v0.16.0
- `test/e2e/24_outbound_categories_test.go` — 14 new e2e tests

**What remains to complete:**
1. Fix e2e test failures — many existing tests are failing after plugin v0.16.0 upgrade
   (likely from outbound scoring affecting existing detect rule behavior, or category mask
   inheritance changing default behavior). Need to investigate each failure.
2. Frontend UI for disabled_categories in per-service override cards (category toggle checkboxes)
3. Commit, bump tags (3.31.0 / 2.32.0), deploy

### E2E Test Suite Expansion

New test file `24_outbound_categories_test.go` covers:
- Outbound threshold config (global + per-service)
- CRS version dynamic (from health endpoint)
- Default rules have outbound phase
- Deploy returns reloaded=false (hot-reload)
- Exclusion hits endpoint
- Events pagination limit
- Unified policy page loads
- Rate limits redirect to /policy
- Cache-Control on hashed assets
- Deploy speed (FQDN cache)
- Disabled categories config

**Status:** Tests compile and vet clean. Some failures in e2e environment due to
image rebuild needed + some existing tests broken by plugin behavioral changes.

---

## Next Up (Priority Order)

### 1. Complete Per-Service Category Masks
- Fix e2e test failures from plugin v0.16.0
- Add frontend category toggle UI in per-service override cards
- Commit, test end-to-end, deploy

### 2. Rate Limits Parity
- Add bulk select, move-to-edge, inline position editing to RL tab
- Match PolicyEngine feature set for consistent UX

### 3. Rate Limits → Policy Engine Unification (Backend)
Currently RL rules use separate API (`/api/rate-rules/*`) and separate Go stores.
The deeper unification would merge them into the exclusion store with `type: "rate_limit"`,
single priority ordering, single deploy endpoint. This is a significant backend refactor.

**Scope:**
- Migrate `RateLimitRuleStore` data into `ExclusionStore`
- Unify CRUD APIs
- Single `POST /api/config/deploy` for all rule types
- Migration path for existing rate-limits.json → exclusions.json

### 4. CRS Update Checker Workflow
Scheduled CI workflow to check latest CRS release, open PR bumping CRS_VERSION.

---

## Future Items

### Performance
- [ ] Incremental summary computation — running counters on Store, O(1) reads
- [ ] TopCountriesPanel 397KB bundle — lazy-load IPLookupPanel or Vite manualChunks
- [ ] enrichAccessEvents O(events × rules) — cache sortRulesByPriority result
- [ ] SecurityHeaderStore.deepCopy — field-by-field copy instead of JSON round-trip

### Features
- [ ] Custom rulesets — native policy-engine rule format for user-created detect rules
- [ ] CRS accuracy evaluation against CRS test suite
- [ ] Outbound score display in event detail panel
- [ ] Filter events by inbound/outbound phase

### Design Decisions
- [ ] Mode field: currently preserved for backward compat but ignored. Remove entirely
  when all production configs have been migrated (or add a one-time migration to strip it).

### Operational
- [ ] Audit each service's built-in auth and document decisions
- [ ] Add forward_auth to dockge at minimum
- [ ] Monitor and document sizing guidance for event stores

### Low Priority
- [ ] operatorChip() for negated operators in DashboardFilterBar
- [ ] Compare detection rates: regex-only vs regex+libinjection
