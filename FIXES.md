# Code Review Fixes

Tracking document for fixes from the comprehensive code review.
Branch: `fix/code-review-findings`

## Results

- Go: **493 tests passing**, builds clean, `gofmt` clean
- Frontend: **229 tests passing**, `astro build` clean
- 3 test updates required (analytics endpoint error propagation)

## Critical / High

| # | File | Issue | Status |
|---|------|-------|--------|
| 1 | `wafctl/rl_analytics.go` | Data race: `AccessLogStore.offset` changed from `int64` to `atomic.Int64`, all access sites updated | [x] |
| 2 | `wafctl/exclusions.go` | Slice aliasing: `Delete()` rollback now deep-copies before modifying | [x] |
| 3 | `wafctl/cli.go` | CLI `--limit` flag now sends `limit` param (was `per_page`) | [x] |

## Medium

| # | File | Issue | Status |
|---|------|-------|--------|
| 9 | `wafctl/main.go` + `logparser.go` | `handleTopCountries`, `handleTopBlockedIPs`, `handleTopTargetedURIs` all use `parseTimeRange()` + `getWAFEvents`; extracted `topBlockedIPs()`/`topTargetedURIs()` free functions | [x] |
| 10 | `wafctl/main.go` | Event type filter optimization: `wafTypes` map includes all WAF-origin types (`blocked`, `logged`, `policy_skip`, `policy_allow`, `policy_block`, `honeypot`, `scanner`) in both `handleSummary` and `handleEvents` | [x] |
| 11 | `wafctl/main.go` | Double-fetch avoided: WAF events only re-fetched when RL events exist | [x] |
| 12 | `wafctl/logparser.go` + `rl_analytics.go` | `s.geoIP` snapshotted under RLock before parsing loop in both stores | [x] |
| 14 | `waf-dashboard/.../PolicyEngine.tsx` | Import handler now supports both array and `{ exclusions: [...] }` formats | [x] |
| 15 | `waf-dashboard/.../api.ts` | 204 response: `undefined as unknown as T` (two-step cast) | [x] |

## Low

| # | File | Issue | Status |
|---|------|-------|--------|
| 22 | `wafctl/logparser.go` + `rl_analytics.go` | `saveOffset` now uses `atomicWriteFile` instead of `os.WriteFile` | [x] |
| 23 | `wafctl/geoip.go` | `readLeft`/`readRight` bounds check: returns 0 on corrupt MMDB | [x] |
| 25 | `waf-dashboard/.../*.tsx` | All `catch (err: any)` → `catch (err: unknown)` with `instanceof Error` | [x] |
| 26 | `waf-dashboard/.../*.tsx` | `showSuccess` timers stored in `useRef`, cleared on unmount | [x] |
| 27 | `waf-dashboard/.../OverviewDashboard.tsx` | `serviceBreakdown` wrapped in `useMemo` with `[data]` dep | [x] |
| 28 | `waf-dashboard/.../EventsTable.tsx` | Export All: React state (`exportingAll`) replaces DOM manipulation; `disabled` prop + conditional render preserves `<Download>` icon | [x] |

## Also updated

| File | Change |
|------|--------|
| `waf-dashboard/src/lib/api.ts` | Removed try/catch wrappers from `fetchTopBlockedIPs`, `fetchTopTargetedURIs`, `fetchTopCountries` — endpoints exist, errors should propagate |
| `waf-dashboard/src/lib/api.test.ts` | 3 tests updated: "returns empty on error" → "throws on error" |

## Not addressed (infra/config — separate scope)

These findings from the review are valid but are configuration/infra changes, not code fixes:
- #5: Raw SecRule injection (design trade-off, needs auth layer)
- #6: CI GitHub Actions pinned to `@master`/`@main`
- #7: Unpinned xcaddy plugin versions
- #8: Overly permissive CSP
- #13: No auth on mutating endpoints (mitigated by Authelia)
- #17: cosign verify wildcard matchers
- #19: Services missing forward_auth
- #20: Short brute-force ban time
