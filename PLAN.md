# PLAN.md — Policy Engine Roadmap

## Current State (v2.31.0 / caddy 3.30.0 / plugin v0.15.0)

Fully operational WAF with custom policy engine, CRS 4.24.1 (254 default rules,
auto-converted at Docker build time), 5-pass evaluation (allow → block → skip →
rate_limit → detect), 6 negated operators, managed lists, IPsum blocklist (8 levels,
597K IPs), per-service skip rule management, logged event collection (tuning mode),
unified /policy page (WAF rules + rate limits), and e2e CI pipeline.

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
- [x] **CRS CI automation** — `crs-rules` Dockerfile stage converts CRS at build time
- [x] **UI unification** — WAF Rules + Rate Limits merged into `/policy` with tabs
- [x] **Response-phase Phase A** — plugin outbound scoring: Phase field, responseContext,
  extractResponseField (response_status, response_header, response_content_type),
  outboundThreshold per-service, post-ServeHTTP evaluation (10 new plugin tests)
- [x] **Response-phase Phase B** — response body buffering via Caddy ResponseRecorder,
  shouldBufferResponse Content-Type filter, can block 403 before response sent,
  bufPool for memory reuse (6 new plugin tests, live smoke test: SQL leak blocked)
- [x] **Response-phase Phase C** — CRS converter emits outbound rules (59 new rules),
  fix RESPONSE_HEADERS -> response_header mapping, 313 total rules (254+59)
- [x] **Infra: cache SSD migration** — Caddy + wafctl config on /mnt/cache/caddy/, logs on array

## CRS Audit (v2.30.0)

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

#### 1. Response-Phase Detection — DONE (v0.15.0, deployed)

Outbound anomaly scoring — all 3 phases complete. 59 CRS outbound rules.
Plugin v0.15.0: response_status, response_header, response_body fields,
ResponseRecorder body buffering, per-service outbound threshold, Content-Type
filtering. E2E tested: SQL error leakage blocked (score 9 >= threshold 5 → 403).

**Phased approach (recommended):**

**Phase A — Response headers only (no body buffering):**
- Plugin: add `response_status`, `response_headers`, `response_content_type` to `extractField()`
- Plugin: wrap response writer to capture status + headers
- Plugin: outbound score accumulation + threshold check
- Plugin: wire `OutboundThreshold` through `resolveWafConfig` (field already exists, currently unused)
- Converter: remove phase 3/4 skip for header-only rules (~20 rules)
- Impact: ~30% of CRS outbound rules. Zero memory overhead.

**Phase B — Response body buffering:**
- Plugin: `caddyhttp.NewResponseRecorder` with `shouldBuffer` callback
- Plugin: only buffer text/json/xml responses under configurable max size (default 1MB)
- Plugin: skip SSE, WebSocket, binary, large responses (zero overhead for streaming)
- Plugin: `sync.Pool` for buffers, `response_body_max_size` Caddyfile option
- Plugin: add `response_body` to `extractField()`
- Converter: enable remaining response-phase rules (~50 more rules)
- Impact: full CRS outbound coverage.

**Phase C — Integration:**
- wafctl: phase-aware rule model, outbound threshold in config generator
- Frontend: outbound score in event details, filter by inbound/outbound
- Tests: ~20 plugin tests (buffering, streaming bypass, threshold, edge cases)

**Key risks:**
- Response body buffering breaks streaming if not filtered correctly
- Memory pressure from large buffered responses
- Caddy's `ResponseRecorder` API compatibility across versions

**Files changed (total across phases):**
- Plugin: ~300 lines new code (buffering, field extraction, scoring)
- Converter: ~10 lines (remove phase skip)
- wafctl: ~50 lines (config wiring, model updates)
- Frontend: ~100 lines (event display, config UI)
- Tests: ~200 lines

**Complexity:** High (Phase A: Medium, Phase B: High, Phase C: Medium).

---

### Other Open Items

#### Per-Service CRS Profiles — Plugin Rule Masks

Allow different CRS rule sets per service. Would enable: "authelia runs PL1 with
only protocol rules, httpbun runs PL2 with full CRS." Currently PL filtering is
global; this would add per-service category masks.

**Scope:** Plugin per-service rule masks in wafConfig, wafctl store, frontend profile selector.
**Complexity:** Medium. Blocked on UI unification (per-service card redesign).

#### Performance

- [ ] **Incremental summary computation** — running counters on Store, O(1) reads
- [ ] **TopCountriesPanel 397KB bundle** — lazy-load IPLookupPanel or Vite manualChunks
- [ ] **enrichAccessEvents O(events × rules)** — cache sortRulesByPriority result
- [ ] **SecurityHeaderStore.deepCopy** — field-by-field copy instead of JSON round-trip

#### Design Decisions

- [ ] **Mode field**: implement detection-only in plugin or remove from WAFConfig
- [ ] **CRS Rule Group disabling**: implement in generator or remove disabled_groups
- [ ] **Custom rulesets**: define a native policy-engine rule format for user-created
  detect rules that bypass the CRS converter. Could enable importing other WAF
  rulesets (Trustwave, custom) directly.

#### Operational

- [ ] Audit each service's built-in auth and document decisions
- [ ] Add `forward_auth` to dockge at minimum
- [ ] Monitor and document sizing guidance for event stores

#### CI / Automation

- [ ] **CRS update checker** — optional `crs-update.yml` scheduled workflow that checks
  the latest CRS release tag via GitHub API and opens a PR bumping `CRS_VERSION`
- [ ] **Rate limits parity** — add bulk select, move-to-edge, inline position editing
  to Rate Limits tab (matching PolicyEngine features)

#### Low Priority

- [ ] CRS accuracy evaluation against CRS test suite
- [ ] Compare detection rates: regex-only vs regex+libinjection
- [ ] `operatorChip()` for negated operators in DashboardFilterBar
