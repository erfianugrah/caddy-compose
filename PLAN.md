# PLAN.md — Policy Engine Roadmap

## Current State (v2.32.0 / caddy 3.31.0 / plugin v0.16.0)

Fully operational WAF with custom policy engine, CRS 4.24.1 (313 rules: 254 inbound +
59 outbound, auto-converted at Docker build time), 5-pass evaluation (allow → block →
skip → rate_limit → detect), outbound anomaly scoring (response headers + body),
per-service category masks with frontend UI, 6 negated operators, managed lists, IPsum
blocklist (8 levels, 618K IPs), unified /policy page (WAF rules + rate limits tabs),
and e2e CI pipeline (106 e2e tests, 529 Go unit tests, 327 frontend tests).

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

## Next Up (Priority Order)

### 1. Rate Limits Parity
- Add bulk select, move-to-edge, inline position editing to RL tab
- Match PolicyEngine feature set for consistent UX

### 2. Rate Limits → Policy Engine Unification (Backend)
Currently RL rules use separate API (`/api/rate-rules/*`) and separate Go stores.
The deeper unification would merge them into the exclusion store with `type: "rate_limit"`,
single priority ordering, single deploy endpoint. This is a significant backend refactor.

**Scope:**
- Migrate `RateLimitRuleStore` data into `ExclusionStore`
- Unify CRUD APIs
- Single `POST /api/config/deploy` for all rule types
- Migration path for existing rate-limits.json → exclusions.json

### 3. CRS Update Checker Workflow
Scheduled CI workflow to check latest CRS release, open PR bumping CRS_VERSION.

---

## Future Items

### Performance
- [ ] SecurityHeaderStore.deepCopy — field-by-field copy instead of JSON round-trip
      (`security_headers.go:347-362` still uses json.Marshal/Unmarshal)
- [ ] IPLookupPanel 893-line single file — split sub-components, lazy-load recharts
- [ ] Incremental summary computation — running counters on Store, O(1) reads

### Features
- [ ] Custom rulesets — native policy-engine rule format for user-created detect rules
- [ ] CRS accuracy evaluation against CRS test suite
- [ ] Outbound score display in event detail panel
- [ ] Filter events by inbound/outbound phase
- [ ] Dashboard filter bar: expand `operatorChip()` beyond 5 operators (eq/neq/contains/
      in/regex) — other operators (begins_with, ip_match, gt, etc.) fallback to "="

### Design Decisions
- [ ] Mode field: preserved for backward compat but ignored (`models_exclusions.go:55-57`).
      Remove entirely when all production configs have migrated (or add a one-time migration).

### Operational
- [ ] Audit each service's built-in auth and document decisions
- [ ] Add forward_auth to dockge at minimum
- [ ] Monitor and document sizing guidance for event stores
