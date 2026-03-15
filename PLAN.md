# PLAN.md — Policy Engine Roadmap

## Current State (v2.32.0 / caddy 3.31.0 / plugin v0.17.0)

Fully operational WAF with custom policy engine, CRS 4.24.1 (313 rules: 254 inbound +
59 outbound, auto-converted at Docker build time), 5-pass evaluation (allow → block →
skip → rate_limit → detect), outbound anomaly scoring, per-service category masks,
unified rule store (`/api/rules` + `/api/deploy`), response-phase support for all
rule types (including outbound rate limiting), managed lists, IPsum blocklist
(8 levels, 618K IPs), CRS auto-update, `response_header` rule type, structured CORS,
rule templates, incremental summary counters (per-hour buckets), mode field fully
removed, Caddyfile cleaned (CORS/cache snippets removed), move-to-edge + inline
position editing, outbound score display, blocked_by filtering, all plugin
limitations resolved (v0.17.0), and e2e CI pipeline (116 e2e tests,
500 Go unit tests, 326 frontend tests).

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
- [x] Total: 114 e2e tests (15 in outbound/categories, 8 in unified API), 26 e2e test files

---

## Plugin v0.17.0 + UI Improvements

### Plugin (caddy-policy-engine v0.17.0)
- [x] `response_header` rule type: set/add/remove/default headers
- [x] Fixed outbound negate/multiMatch: `matchConditionResponse()` replaces direct `evalOperator()`
- [x] Outbound evaluation extended to all rule types (was detect-only)
- [x] Outbound rate limiting: count responses (e.g., RL on 401s) → 429
- [x] Multiple response_header rules all fire (applied inline, not returned)
- [x] All 4 previously-skipped e2e tests unskipped and pass

### UI Improvements
- [x] Header "check all" checkbox in PolicyEngine table (select all on page)
- [x] Header "check all" checkbox in RulesPanel (CRS rules) table
- [x] Shift-click range selection in PolicyEngine (via lastSelectedRef + shiftKey)
- [x] Shift-click range selection in RulesPanel (via rangeSelect callbacks)
- [x] Indeterminate state on header checkbox when partially selected
- [x] Total item counts added: Services, Managed Lists, Overview pagination,
      CSP service overrides, Security Headers service overrides

---

## Known Plugin Limitations — ALL RESOLVED (v0.17.0)

All 4 previously-skipped features now work and are e2e tested:
- [x] `negate` field — inversion works for inbound and outbound (v0.17.0 fixed outbound)
- [x] `multi_match` — raw-stage matching works (evaluates at each transform stage)
- [x] `not_in` operator — two-layer negate design works correctly
- [x] `not_in_list` operator — list resolution + negate works

E2e tests unskipped and pass (had timing issues, fixed with `waitForCondition` polling).
Fix for test isolation: `not_contains` rule scoped to test prefix to avoid blocking others.

---

## Next Up — Unified Policy Engine (v3.0)

The goal: make `policy-rules.json` the **single control plane** for all
request/response processing. Everything hot-reloads via mtime polling — no
Caddy restart. Rate limits, CSP, security headers, caching, CORS, and custom
header manipulation all become policy-engine concerns, managed through one
unified API and UI.

### Architecture Context (pre-unification — for historical reference)

Before Phase 2, the deploy pipeline read 6 separate config stores
(ExclusionStore, RateLimitRuleStore, ConfigStore, CSPStore, SecurityHeaderStore,
DefaultRuleStore) and wrote one `policy-rules.json`. There were 4 identical
deploy endpoints. **After unification**: RateLimitRuleStore is deleted, rules
are managed via a single ExclusionStore, `/api/rules` + `/api/deploy` are the
canonical endpoints. CSPStore and SecurityHeaderStore remain (will migrate to
response-phase rules in Phase 4).

### Phase 1: Quick Wins (pre-unification cleanup) — DONE

- [x] `SecurityHeaderStore.deepCopy` — field-by-field copy via `copyStringMap`
- [x] `IPLookupPanel` — split 893→8 files under `ip-lookup/`, recharts isolated
- [x] `operatorChip()` — investigated, not a bug (FilterOp matches events API)
- [x] Mode field fully removed from WAFServiceSettings + all tests + frontend

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
- [x] Full suite: 500 Go unit tests, 326 frontend tests, 113 e2e tests — all pass

### Phase 3: Response-Phase Policy Rules

Enable all rule types (allow, block, skip, detect, rate_limit) to operate on
response-phase fields, not just inbound. This makes rate limits and custom
rules work on response data (status codes, headers, body).

**Plugin (caddy-policy-engine — DONE):**
- [x] Extend rule evaluation to response phase for ALL types (was detect-only)
- [x] `phase: "outbound"` on any rule type triggers response-phase evaluation
- [x] Block rules on response_status/response_header — reject before client sees response
- [x] Fixed outbound negate/multiMatch bug: `evaluateOutbound()` now uses
      `matchConditionResponse()` instead of calling `evalOperator()` directly
- [x] `matchRuleResponse()` + `matchConditionResponse()` — proper AND/OR, negate,
      transforms, absent-field semantics for outbound rules
- [x] Rate limit rules with `phase: "outbound"` — count responses by status code (plugin v0.17.0)

**wafctl (DONE):**
- [x] `Phase` field on `RuleExclusion` ("inbound"/"outbound"), validated + wired to PolicyRule
- [x] `validOutboundFields` (response_header, response_status, response_content_type)
- [x] Outbound phase merges response fields into allowed condition field set
- [x] Phase selector (inbound/outbound toggle) in AdvancedBuilderForm
- [x] Condition builder shows response-phase fields when phase=outbound
- [x] `INBOUND_FIELD_DEFS` / `OUTBOUND_FIELD_DEFS` filtered field sets

### Phase 4: Response-Phase Policies (Architectural Pivot)

**Key insight: CORS, CSP, security headers, cache-control, and custom header
manipulation are all response-phase policies.** They should NOT be separate
config stores — they should be expressible as response-phase rules in the
unified store, or as a new `response_header` rule type in the policy engine.

**Architecture decision:** CSP, security headers, and CORS are **structured config** (not
`response_header` rules). They need rich UX (CSP directive composition, security profiles,
CORS origin validation + preflight). The `response_header` rule type is for ad-hoc headers
(Cache-Control overrides, custom headers). Cache-control rules can also use response_header.

**CORS: DONE as structured config (like CSP/SecurityHeaders):**
- [x] Plugin: `CORSConfig` section in `ResponseHeaderConfig` with per-service config
- [x] Plugin: preflight handling (OPTIONS + Origin + ACRM → 204) before WAF evaluation
- [x] Plugin: origin validation (exact match + regex patterns), credentials, max-age
- [x] Plugin: CORS headers on normal responses via `applyResponseHeaders()`
- [x] wafctl: `CORSStore` with `GET/PUT /api/cors`, deploy wiring, FQDN resolution
- [x] Frontend: `cors.ts` API module
- [x] E2E: TestCORSStoreAPI (get, update, deploy)

**response_header rule type: DONE**
- [x] Plugin: evaluate conditions on response, set/add/remove/default headers
- [x] Plugin: `applyRuleHeaders()` applied inline (multiple rules fire)
- [x] Plugin: outbound evaluation handles detect/block/response_header/rate_limit/allow
- [x] wafctl: model, validation, policy generator, frontend types, e2e tests

**wafctl (DONE):**
- [x] `response_header` added to validExclusionTypes + policyEngineTypes
- [x] Header action fields: `header_set`, `header_add`, `header_remove`, `header_default`
- [x] Validation: at least one action, no newlines, phase must be outbound
- [x] Policy generator: priority band 500-599, auto-outbound phase, fields wired
- [x] Frontend types updated (ExclusionType, Exclusion, ExclusionCreateData, mappings)
- [x] E2E: TestResponseHeaderRuleCRUD (7 subtests)

**Rule Templates (DONE):**
- [x] `GET /api/rules/templates` — list builtin templates
- [x] `POST /api/rules/templates/{id}/apply` — one-click create rules from template
- [x] Templates: cache-static-assets, cache-immutable-hashed, security-headers-baseline,
      remove-server-headers
- [x] Frontend: `templates.ts` API module
- [x] E2E: TestRuleTemplatesAPI

**UI Pages (DONE):**
- [x] CORS config page (`/cors`): global settings, per-service overrides, save/deploy
- [x] Template browser page (`/templates`): card grid by category, preview, one-click apply
- [x] Nav entries in Security section sidebar

**Caddyfile cleanup (plugin v0.17.0 — DONE):**
- [x] E2E Caddyfile: removed `(cors)` and `(static_cache)` snippets
- [x] Production Caddyfile: removed `(cors)` snippet
- [x] Production Caddyfile: removed `(static_cache)` snippet
- [x] Production Caddyfile: removed `header_down -Access-Control-*` from `(proxy_headers)`
- [x] Configure CORS via `PUT /api/cors` — setup script at `scripts/setup-cors.sh`

### Phase 5: Rate Limits Parity — ASSESSED, KEPT SEPARATE

Analysis concluded `RateLimitsPanel` should remain a separate component.
It has domain-specific UI that PolicyEngine lacks: RL key selector (9 options
with parameterized types), events/window presets, Rate Advisor (587 lines),
Global Settings panel. The compat wrappers in `rate-limits.ts` correctly
translate to `/api/rules` with `type: "rate_limit"` filtering.

- [x] Assessed merge vs keep-separate — keeping separate (17-22h merge vs 2-3h fix)
- [x] Fixed `reorderRLRules` to preserve non-RL rules in unified store
- [x] Bulk selection: checkboxes, header checkbox, shift-click range select
- [x] Bulk actions: enable, disable, delete with auto-deploy
- [x] Move-to-edge + inline position editing in RateLimitsPanel

### Phase 6: CRS Automation — DONE

- [x] `crs-update.yml` workflow: weekly check against coreruleset/coreruleset
- [x] Fetches latest release, compares with CRS_VERSION in build.yml
- [x] Auto-opens PR with version bump + changelog link
- [x] Duplicate PR detection, manual trigger support

---

## Future Items

### WebSocket + Stream Deep Inspection (Long-Term / Major Feature)

Deep packet inspection of WebSocket frames and streaming connections.
Currently the plugin only inspects the HTTP upgrade handshake — once
a WebSocket is established or an SSE stream starts, data flows through
uninspected. This would add per-frame/per-event inspection.

**Current state:** WebSocket upgrades work (Hijack delegation), SSE streams
work (Flush delegation), gRPC works (HTTP/2, no hijack needed). The plugin
has no visibility into post-handshake data.

**Prior art (from research):**
- RFC 6455 §5.2: WebSocket base framing — FIN/RSV/opcode/mask/payload length
  fields. Client→server frames MUST be masked (4-byte XOR). Fragmentation via
  continuation frames (opcode 0x0). Control frames (close/ping/pong) max 125 bytes.
- Caddy `reverse_proxy/streaming.go`: `handleUpgradeResponse()` hijacks both
  client and backend connections, bidirectional copy via `io.Copy` goroutine pair.
  No frame awareness — raw TCP relay.
- `tailscale/tailscale` `k8s-operator/sessionrecording/ws/conn.go`: wraps hijacked
  net.Conn to record `kubectl exec` WebSocket sessions. Parses WS frames, extracts
  SPDY-over-WS payloads for session recording. Demonstrates the hijack-and-wrap pattern.
- `elazarl/goproxy` `websocket.go`: detects WS upgrades via `isWebSocketHandshake()`,
  hijacks client conn, dials backend separately, bidirectional `io.Copy`. No frame
  parsing — raw relay. Shows the MITM proxy pattern.
- Kubernetes `apiserver/pkg/util/proxy/streamtunnel.go`: `TunnelingHandler` wraps
  WS connections to tunnel SPDY. Full frame-level access for protocol translation.

**Architecture: MITM proxy with frame-level hooks**

```
Client ←→ [Policy Engine WS Proxy] ←→ Upstream
               ↓
          Per-frame inspection:
          - Read frame (RFC 6455 §5.2)
          - Unmask (client→server)
          - Reassemble fragments
          - Run text payload through compiled rules
          - Forward or block
```

Two operating modes:
- **Blocking (proxy):** Hold frame until inspection passes. Can drop individual
  frames or close the connection. Adds ~1-5µs per text frame for rule evaluation.
- **Tap (async):** Forward frame immediately, copy payload to inspection goroutine.
  Can only tear down connection after detection, not block individual frames.

**WebSocket proxy implementation:**
- Detect Upgrade in `ServeHTTP()` before `next.ServeHTTP()`
- Hijack client connection (per RFC 6455 §4.2)
- Dial upstream separately (reuse Caddy's upstream resolution)
- Two goroutines: client→upstream pump + upstream→client pump
- Frame parser: 2-byte header, extended payload length (16/64-bit),
  masking key (4 bytes, client→server only), payload
- Reassemble continuation frames into complete messages before inspection
- Text frames (opcode 0x1): extract UTF-8 payload, run through policy rules
- Binary frames (opcode 0x2): optionally skip or size-limit inspect
- Control frames (close 0x8, ping 0x9, pong 0xA): forward immediately, no inspection
- Backpressure: per-connection frame rate limiting
- Max message size: configurable (default 1 MiB), close connection on exceed

**SSE event inspection:**
- Wrap `io.Writer` on response after `next.ServeHTTP()` starts streaming
- Buffer lines until `\n\n` delimiter (complete SSE event)
- Parse: `data:`, `event:`, `id:`, `retry:` fields
- Run event payload through compiled rules
- `Flush()` after each inspected event to preserve real-time delivery
- Simpler than WS — unidirectional, text-only, line-delimited

**gRPC stream inspection:**
- Not planned — requires protobuf schema for meaningful payload inspection
- Could monitor frame sizes/rates for anomaly detection without decoding

**Rule model:**
- New condition fields: `ws_message`, `ws_opcode`, `sse_event`, `sse_event_type`
- Existing operators work on these fields (contains, regex, phrase_match, etc.)
- `phase: "stream"` for stream-phase rules (distinct from inbound/outbound)
- Rate limiting: `rate_limit_key: "ws_connection"` counts frames per connection
- Per-connection anomaly scoring: accumulate scores across frames

**Performance budget:**
- Per text frame: ~1-5µs (compiled regex/Aho-Corasick match)
- Memory: one frame buffer per active WebSocket (~128KB default)
- Goroutines: 2 per active WebSocket (Go handles thousands easily)
- Binary frames: skip by default (configurable)
- Connection teardown: <1ms (send close frame 1008 Policy Violation)

**Implementation phases (estimated effort):**
1. WebSocket frame parser: read/write RFC 6455 frames, masking, fragmentation (~2 days)
2. MITM proxy mode: intercept upgrade, dial upstream, bidirectional pump (~3 days)
3. Frame inspection: extract payload, run against compiled conditions (~1 day)
4. SSE wrapper: intercept Writer, parse events, inspect (~1 day)
5. Connection-level rate limiting: frames/sec per connection (~1 day)
6. wafctl: `ws_message`, `sse_event` condition fields, `phase: "stream"` UI (~2 days)
7. E2E tests: WS frame inspection, SSE event inspection (~1 day)

### Performance
- [x] Incremental summary computation — per-hour buckets, O(hours) reads (summary_counters.go)

### Features
- [x] Custom rulesets — users create detect rules via /api/rules, templates via /api/rules/templates
- [ ] CRS accuracy evaluation via CRS regression test suite (opt-in, set CRS_REGRESSION=1)
- [x] Outbound score display — already in EventDetailPanel + EventsTable Score column
- [x] Filter events by blocked_by (anomaly_inbound/outbound/direct) in DashboardFilterBar

### Operational
- [x] Event store sizing documented in README (disk estimates, memory, tuning)
