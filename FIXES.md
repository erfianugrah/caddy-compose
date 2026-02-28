# Code Review Fixes

Tracking file for issues found during comprehensive codebase review.
Branch: `fix/code-review-issues`

---

## CRITICAL

- [x] **F1 — RateLimitRuleStore.Export() deadlock** (`wafctl/rl_rules.go:320-327`): `Export()` acquires `RLock`, then calls `s.List()` which also acquires `RLock`. Go's `sync.RWMutex` is not re-entrant — if a writer is waiting between the two `RLock()` calls, the second `RLock` blocks, causing deadlock. Fix: inline the copy logic or extract an unexported `listLocked()`.

## HIGH

- [x] **F2 — Regex compiled per-event** (`wafctl/rl_analytics.go:870`): `regexp.Compile()` called on every event match for `regex` operator conditions. Pre-compile and cache regex patterns.
- [x] **F3 — CI tests don't gate image builds** (`.github/workflows/build.yml`): `caddy` and `wafctl` build jobs depend only on `changes`, not on `test-go`/`test-frontend`. Broken tests still produce signed images pushed to Docker Hub.
- [x] **F4 — Unpinned security-critical GitHub Actions** (`.github/workflows/build.yml`): `trivy-action@master`, `cosign-installer@main` use branch refs instead of SHA pins. Supply chain risk.

## MEDIUM

- [x] **F5 — Tiered CSP security headers** (`Caddyfile:107-110`): Blanket `unsafe-inline unsafe-eval` CSP for all services. Create tiered snippets: strict (no eval), moderate (unsafe-inline only), relaxed (current). Assign per service based on compatibility.
- [x] **F6 — Scanner UAs: convert drop to anomaly scoring** (`coraza/pre-crs.conf:9100032`, `coraza/scanner-useragents.txt`): Split list into two tiers — known attack tools keep `drop`, generic libraries (`python-requests`, `go-http-client`, `curl/`, `wget`) move to anomaly scoring (+3). Smarter than blanket blocking.
- [x] **F7 — Runtime CF IP refresh** (`Dockerfile:28-37`, `Caddyfile:36`): CF IP ranges baked at build time. Add a `CFProxyStore` mirroring the ipsum blocklist refresh pattern: download, validate, atomic write, Caddy reload. Add API endpoints and scheduled refresh.
- [x] **F8 — Event log IP lookup + auto-query race condition**: EventsTable has no IP lookup action. AnalyticsDashboard's `IPLookupPanel` has a race: `initialIP` arrives after `query` state is initialized to `""`, so `handleSearch()` early-returns on empty string. Fix both.
- [x] **F9 — API layer cleanup** (`waf-dashboard/src/lib/api.ts`): (a) Extract shared `applyFilterParams()` helper from 3 duplicated blocks. (b) Fix unsafe `undefined as unknown as T` for 204 responses. (c) Use `postJSON` in `refreshBlocklist` for consistency.
- [x] **F10 — Export endpoint unbounded data** (`wafctl/main.go:710`): `export=true` sets limit to 100k with no streaming or pagination. Cap and add streaming headers.

## LOW

- [x] **F11 — Jellyfin waf/blocklist import order** (`Caddyfile:459-460`): `import waf` before `import ipsum_blocklist` wastes WAF processing on blocked IPs. Swap order.

## UI FIXES

- [x] **F12 — Deduplicate buttons in EventDetailModal** (`EventsTable.tsx`, `EventDetailModal.tsx`): `EventDetailModal` embeds `EventDetailPanel` which has its own action buttons (Create Exception, IP Lookup, Export JSON), then the modal renders its own copy of the same buttons — causing duplicates. Added `hideActions` prop to `EventDetailPanel`; modal passes `hideActions` and keeps its own button row.
- [x] **F13 — IP Lookup URL consistency** (`EventDetailModal.tsx`): Modal's IP Lookup button linked to `/analytics?q=<ip>` without `tab=ip`. Added `tab=ip` for consistency with EventsTable links (param is harmless since analytics page is exclusively IP Lookup).
- [x] **F14 — Clickable client IPs everywhere** (`EventsTable.tsx`, `OverviewDashboard.tsx`): Client IPs rendered as plain text in (a) EventsTable row cells, (b) OverviewDashboard recent events feed, (c) EventDetailPanel request details section. Wrapped all in `<a>` links to `/analytics?q=<ip>` with `text-neon-cyan` styling and `stopPropagation()` where rows are clickable.

- [x] **F15 — Honeypot rule editing shows blank form** (`PolicyEngine.tsx`, `PolicyForms.tsx`): Clicking edit on a honeypot rule opened the Honeypot tab but rendered a blank create form — `HoneypotForm` had no `initial` prop. Added `initial`, `onCancel`, `submitLabel` props to `HoneypotForm`, added `isEditingHoneypot` routing in `PolicyEngine.tsx`, and wired the Honeypot `TabsContent` to conditionally render edit mode with pre-populated data.

---

## Performance Optimizations

- [x] **P1 — Binary search for time-based queries** (`wafctl/logparser.go`): `SnapshotSince`/`SnapshotRange` scanned all events O(N). Added `searchCutoff()`/`searchEnd()` binary search on chronologically-ordered events — O(log N) to find the starting index. Same for `AccessLogStore` via `searchCutoffRL()`/`searchEndRL()`.
- [x] **P2 — Direct range copy under RLock** (`wafctl/logparser.go`): After binary search finds bounds, copy only the matching slice directly instead of copying all events then filtering. Eliminates unnecessary allocation of full event slice.
- [x] **P3 — Eliminate double WAF event fetch in handleSummary** (`wafctl/logparser.go`, `wafctl/main.go`): `handleSummary` fetched WAF events twice — once for summary, once for unique client/service counts. Introduced `summarizeEventsWithSets()` returning `summaryResult` with `clientSet`/`serviceSet` maps built in a single pass.
- [x] **P4 — Reverse-merge pre-sorted arrays in handleEvents** (`wafctl/main.go`): Replaced append-then-sort O(N log N) with reverse merge of two pre-sorted (by time) event slices with inline filtering — O(N) single pass producing newest-first output.
- [x] **P5 — Pre-lowercase filter values at parse time** (`wafctl/main.go`): `fieldFilter.matchField()` called `strings.ToLower()` on every comparison. Added `valueLower` field computed once at parse time; `ins` slice values also pre-lowered.
- [x] **P6 — Atomic counter for ephemeral event IDs** (`wafctl/rl_analytics.go`): `rateLimitEventToEvent()` called `generateUUIDv7()` (crypto/rand) for each RL→WAF event conversion. Replaced with `ephemeralID()` using `atomic.Uint64` counter — zero allocation, no syscall.
- [x] **P7 — Inline TopCountries counting in summary loop** (`wafctl/logparser.go`): `handleTopCountries` triggered a separate `TopCountries()` call re-iterating all events. Folded country counting into `summarizeEventsWithSets` via `countryMap` parameter, eliminating the redundant pass.
- [x] **P8 — Generation-keyed response cache** (`wafctl/cache.go`, `wafctl/main.go`): Added `responseCache` with generation-based invalidation (Store + AccessLogStore generation counters) and 3s TTL. Applied to `handleSummary`, `handleServices`, `handleTopBlockedIPs`, `handleTopTargetedURIs`, `handleTopCountries`.

---

## Review-Round Bug Fixes

- [x] **R1 — JSONL stripping removed** (`wafctl/logparser.go`): `appendEventsToJSONL` and `compactEventFileLocked` stripped `RequestHeaders`, `RequestBody`, `RequestArgs` when persisting to JSONL. After container restarts, events loaded from JSONL lacked these fields, causing the "Request Context" expandable section to disappear. Stripping removed entirely — all fields now preserved. Tests updated: `TestStoreEventFileStripsLargeFields` → `TestStoreEventFilePreservesAllFields`.
- [x] **R2 — Stale comment in logparser.go** (`wafctl/logparser.go:338`): Comment referenced old stripping behavior. Updated to reflect current pass-through behavior.
- [x] **R3 — refreshBlocklist error handling** (`waf-dashboard/src/lib/api.ts`): Reverted `refreshBlocklist` from `fetchJSON` back to manual fetch to preserve clean error message extraction from JSON error bodies.
- [x] **R4 — CSP tiers were byte-identical** (`Caddyfile`): `security_headers` and `security_headers_relaxed` were identical. Differentiated: relaxed now adds `data:` to script-src/connect-src and `https:` to form-action.
- [x] **R5 — P4 nil slice → JSON null** (`wafctl/main.go`): `filtered` variable in reverse-merge was nil when no events matched, serializing as JSON `null` instead of `[]`. Fixed with `make([]Event, 0)`.
- [x] **R6 — URI title attributes on truncated cells** (`EventsTable.tsx`, `OverviewDashboard.tsx`, `EventDetailModal.tsx`, `AnalyticsDashboard.tsx`, `ServicesList.tsx`): Truncated URI cells across all pages lacked `title` attributes for hover-to-see-full-value. Added `title={uri}` everywhere.
- [x] **R7 — gofmt formatting** (`wafctl/crs_rules_test.go`, `wafctl/geoip_test.go`): Fixed formatting inconsistencies.

---

## Phase 4: UI/UX — Event Detail Deep-Linking

- [x] **U1 — Inline expandable rows in Overview Dashboard** (`OverviewDashboard.tsx`): Replaced modal-based event detail with inline expandable rows (Fragment, chevrons, collapse button) matching the Events tab pattern. Removed `EventDetailModal` import from Overview.
- [x] **U2 — "View in Events" deep-link button** (`EventsTable.tsx`, `OverviewDashboard.tsx`): Added `viewInEventsHref` prop to `EventDetailPanel`. Overview builds a deep-link URL with `event_id`, ±5min time window, and comprehensive filters (service, type, ip, method). Events tab reads URL params, does ID-first lookup, auto-expands and scrolls to matching row.
- [x] **U3 — Backend event ID fast-path** (`wafctl/main.go`, `wafctl/logparser.go`): Added `?id=` query param to `handleEvents` — reverse linear scan of WAF Store by persistent UUID, returns single event. Added `Store.EventByID(id)` method. Falls through to normal filter path for ephemeral RL/ipsum IDs.
- [x] **U4 — Event ID shown in detail panel** (`EventsTable.tsx`): Added Event ID field to the Request Details section of `EventDetailPanel`.
- [x] **U5 — Event ID filter chip on deep-link** (`DashboardFilterBar.tsx`, `EventsTable.tsx`): Added `event_id` as a `FilterField` (eq only, not in dropdown — programmatic only). When ID fast-path succeeds, sets `event_id` filter chip + absolute time range in state. Uses `skipNextLoadRef` to prevent double fetch from state change re-render.

---

## Deferred

- [ ] **CSP implementation** — Tiered CSP snippets created (F5) but disabled across the board pending proper research (RFC/spec analysis, Radix UI `unsafe-eval` necessity, nonce-based alternatives). Will revisit in a separate workflow.

---

## Verification

- [x] All 829 Go tests pass (817 original + 12 new cfproxy tests)
- [x] All 279 frontend tests pass
- [x] Astro build succeeds (8 pages)
- [x] No new TypeScript errors
