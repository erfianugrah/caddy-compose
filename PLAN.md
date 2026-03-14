# PLAN.md — Policy Engine Roadmap

## Current State (v2.28.0 / caddy 3.27.0 / plugin v0.14.1)

Fully operational WAF with custom policy engine, CRS 4.24.1 (254 default rules),
5-pass evaluation (allow → block → skip → rate_limit → detect), 6 negated operators,
managed lists, IPsum blocklist (8 levels, 597K IPs), per-service skip rule management,
logged event collection (tuning mode visibility), and e2e CI pipeline.

---

## Completed This Session (v2.26.0→v2.28.0)

- [x] **AGENTS.md** — trimmed from 1057→171 lines, focused on agent-actionable info
- [x] **Method pills** — `MethodMultiSelect` for all method operators (single mode for eq/neq)
- [x] **Host multi-select** — `HostMultiSelect` with search, max-height scroll, custom entry
- [x] **Operator alignment** — all string fields get 16 operators, enum fields get 6, IP gets 8
  - Go backend `validOperatorsForField` map aligned
  - Frontend `CONDITION_FIELDS` constants aligned
  - `TestValidateOperatorsPerField` (275 subtests) + 23 frontend tests added
  - Fix: method validation skips `in_list`/`not_in_list` (list name ≠ HTTP method)
- [x] **Perf: deploy** — removed `reloadCaddy()` from `handleDeploy` and `deployAll`
  (policy engine plugin hot-reloads via mtime polling, no Caddy restart needed)
- [x] **Perf: FQDN cache** — `BuildServiceFQDNMap` cached with mtime invalidation (26x faster)
- [x] **Perf: summary cache** — TTL increased from 3s to 10s
- [x] **Perf: events pagination** — early-exit for non-export (stop after full page collected)
- [x] **Perf: matchIntField** — avoid `strconv.Itoa` per event in status_code filter
- [x] **Perf: ui_server** — `Cache-Control: immutable` for `/_astro/*` (defense in depth)
- [x] **Perf: benchmarks** — 16 benchmarks for summary, events, filters, FQDN map, UI server
- [x] **Fix: exclusion hits** — endpoint now scans access log store for policy events
- [x] **Fix: events page** — `All (-1)` → `All` when total unknown from early-exit
- [x] **Policy UX: pagination** — 15→25 per page
- [x] **Policy UX: position reorder** — clickable order number opens inline input
- [x] **Policy UX: handleMoveToPosition** + `handleBulkMoveToPosition` handlers added
- [x] **Policy UX: back to events** — "Back to Events" link in success banner after event→policy flow

---

## Recently Completed

- [x] **Event detail: blank gap** — replaced 2-column grid with stacked layout (both panels)
- [x] **Event detail: long values** — TruncatedCode for URI, User-Agent, Variable, Full Value, matched_data
- [x] **Event detail: copy buttons** — CopyBtn on all fields (Event ID, Request ID, URI, IP, etc.)
- [x] **General Logs: same fixes** — TruncatedCode, CopyBtn, stacked layout
- [x] **Condition builder: preserve value** — operator changes keep value (clear only for exists/list/phrase)
- [x] **Condition builder: previous value pill** — dismissible pill after field change
- [x] **Policy page: bulk move-to-position** — "Move to #" input in bulk toolbar
- [x] **Policy page: type filter** — added missing "Skip" type
- [x] **Policy page: multi-drag** — drag selected rows as a group
- [x] **Policy page: per-page count** — all pagination shows "N per page"
- [x] **Infra: cache SSD migration** — Caddy + wafctl config on /mnt/cache/caddy/, logs on array

## CRS Audit (v2.29.0)

**All settings verified working end-to-end:**

| Setting | Status | Implementation |
|---------|--------|----------------|
| Paranoia Level | Working | Plugin skips rules where `rule.PL > servicePL` at runtime |
| Inbound Threshold | Working | Cumulative severity scores (CRIT=5, ERR=4, WARN=3, NOTICE=2); block when >= threshold |
| Per-Service Overrides | Working | Plugin resolves PL+threshold per Host header via `waf_config.per_service` |
| Individual Rule Disable | Working | User overrides stored separately, disabled rules excluded at generation time |

**CRS update process: fully manual** — no auto-update mechanism exists.
Pipeline: CRS repo → `tools/crs-converter` CLI → `waf/default-rules.json` → git commit → Docker build.
Currently at CRS v4.24.1 (254 rules). Converter supports ModSecurity SecRule syntax only.
**Should be automated** — run converter in CI build pipeline (see Open Items).

**`mode` field**: persisted but ignored by plugin — detection-only mode not implemented.
**`disabled_groups`**: persisted but ignored — group-level disabling not implemented.

---

## Open Items (Future Sessions)

### Major Features

#### 1. Policy UI Unification — Merge Rate Limits into `/policy`

Unified rule table showing all rule types (allow, block, skip, detect, rate_limit)
on a single `/policy` page. Currently rate limits are on a separate `/rate-limits` page.

**Scope:**
- Merge `RateLimitsPanel` into `PolicyEngine` as a unified table
- Unified create/edit dialog that handles all 5 rule types
- Single priority ordering across all rule types
- Remove `/rate-limits` page

#### 2. CRS Auto-Update in CI

Automate CRS rule conversion in the Docker build pipeline so updating
CRS is just a version bump in a single variable.

**Scope:**
- Add a build stage to `Dockerfile` that clones the CRS repo at a pinned tag
- Run `tools/crs-converter` in a Go builder stage to produce `default-rules.json`
- Remove the committed `waf/default-rules.json` — it becomes a build artifact
- Add `CRS_VERSION` env var to `.github/workflows/build.yml` alongside `CADDY_VERSION`
- Optional: scheduled workflow to check for new CRS releases and open a PR

#### 3. Per-Service CRS Profiles — Plugin Rule Masks

Allow different CRS rule sets per service at the plugin level, not just
skip rules with host conditions. Would enable: "authelia runs PL1 with
only protocol rules, httpbun runs PL2 with full CRS."

**Scope:**
- Plugin: per-service rule masks in wafConfig
- wafctl: new store for per-service CRS profiles
- Frontend: profile selector on per-service override card

#### 3. Response-Phase Detection (Phase 2)

Outbound anomaly scoring — inspect response bodies after `next.ServeHTTP()`.
Would enable ~100+ CRS outbound rules (response body inspection).

**Scope:**
- Plugin: response body buffering + inspection
- Plugin: outbound anomaly scoring with separate threshold
- wafctl: wire `outbound_threshold` through `BuildPolicyWafConfig()`
- CRS converter: port outbound rule categories

### Performance (Future)

- [ ] **Incremental summary computation** — maintain running counters on Store,
  update on insert/evict instead of O(N) full scan per request
- [ ] **TopCountriesPanel 397KB bundle** — recharts leaks into this chunk via shared
  code splitting. Lazy-load IPLookupPanel or configure Vite `manualChunks`
- [ ] **enrichAccessEvents O(events × rules)** — cache `sortRulesByPriority` result
- [ ] **SecurityHeaderStore.deepCopy** — replace JSON round-trip with field-by-field copy

### Design Decisions Pending

- [ ] **Mode field**: Either implement detection-only mode in the plugin
  (detect but don't block on threshold) or remove `mode` from `WAFConfig` entirely.
  Currently `mode` is persisted but ignored by the policy engine.

- [ ] **CRS Rule Group disabling**: Either implement in the policy generator
  (filter `default-rules.json` by tag at generation time) or remove
  `disabled_groups` from WAFConfig. Currently persisted but ignored.

### Operational

- [ ] Audit each service's built-in auth and document decisions
- [ ] Add `forward_auth` to dockge at minimum
- [ ] Monitor and document sizing guidance for event stores

### Low Priority / Deferred

- [ ] CRS accuracy evaluation against CRS test suite
- [ ] Compare detection rates: regex-only vs regex+libinjection
- [ ] `operatorChip()` for negated operators in DashboardFilterBar
