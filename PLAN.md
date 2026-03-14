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

## In Progress — Remaining Items

### 1. Event Detail Panel Fixes (EventDetailPanel.tsx)

- [ ] **Blank gap** between Request Details and Matched Rules sections
  - The 2-column grid creates a large gap when right column (Rule Match) is shorter
  - Fix: either collapse to single column or ensure min-height parity

- [ ] **Long values overflow** — Variable, Full Value, matched_data fields overflow horizontally
  - TruncatedCode exists but isn't used consistently
  - Fix: apply `max-w-full overflow-hidden` + expand/collapse toggle to all long value fields
  - Ensure export JSON always contains full untruncated values

- [ ] **Copy buttons** — add per-field copy button for:
  - Event ID, Request ID, Method, URI, Client IP, Status
  - Variable, Matched data, Full Value in matched rules
  - User-Agent
  - Use existing `CopyButton` from `TagInputs.tsx` or inline clipboard icon

### 2. Condition Builder UX (ConditionBuilder.tsx)

- [ ] **Preserve value on operator change** — don't clear when switching operators
  - Currently `value: ""` is set on every operator change (line 220)
  - Fix: keep `condition.value` when switching between compatible operators
  - Only clear when switching to/from structurally different ops (e.g., to `exists`, to `phrase_match`)

- [ ] **Previous value pill on field change** — when field changes:
  - Clear the value (current behavior)
  - Show a small dismissible pill with the old value below the input
  - Clicking the pill re-applies it; clicking × dismisses it
  - Requires new state: `previousValue` per condition row

### 3. Policy Page: Bulk Move-to-Position (PolicyEngine.tsx)

- [ ] Add "Move to #" input in the bulk action toolbar (alongside Enable/Disable/Delete)
  - Small number input + "Move" button
  - Calls `handleBulkMoveToPosition(position)` (handler already implemented)
  - Only visible when selection is non-empty and not filtered/sorted

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

#### 2. Per-Service CRS Profiles — Plugin Rule Masks

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
