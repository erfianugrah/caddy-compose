# FIXES.md — Known Issues & Resolved Fixes

## Services Page: "No URI data" / "No rule data"

**Status:** RESOLVED.

**Symptom:** Expanding a service row on the Services page (`/services`) showed
"No URI data" and "No rule data" for most services, despite those services
having thousands of events.

**Root cause:** The `TopURIs` and `TopRules` fields in the `/api/services`
response were populated from the legacy WAF event store (`logparser.go:Store`),
not from the access log store (`access_log_store.go:AccessLogStore`) where
the majority of security events now live.

**Fix:** Added `ServiceTopURIs()` and `ServiceTopRules()` methods to
`AccessLogStore` (in `rl_analytics.go`). The `handleServices` handler now
falls back to the AccessLogStore when the legacy store returns empty data.

**Files changed:**
- `wafctl/rl_analytics.go`: New `ServiceTopURIs()` and `ServiceTopRules()` methods
- `wafctl/handlers_events.go`: Fall back to AccessLogStore in `handleServices()`

---

## Summary Timeline: Challenge Events Not in Counters

**Status:** RESOLVED.

**Symptom:** Challenge events (`challenge_issued`, `challenge_passed`, etc.)
appeared in the event table with badges but were not counted in the summary
timeline or overview dashboard counters.

**Fix:** Added challenge counters to the full summary pipeline:
- `hourBucket`: added `ChallengeIssued`, `ChallengePassed`, `ChallengeFailed`
- `classifyRLIntoBucket()`: added challenge cases
- `buildSummary()`: accumulates and populates challenge totals
- `mergeSummaryResponses()`: merges challenge fields from both stores
- `rleEventType()` / `rleIsBlocked()`: recognize challenge sources

Model changes:
- `SummaryResponse`: +3 challenge fields
- `HourCount`: +3 challenge fields

Frontend changes:
- `TimelinePoint`: +3 challenge fields
- `SummaryData`: +3 challenge fields
- `analytics.ts`: map challenge fields in timeline transformation
- `analytics.test.ts`: updated test fixtures and assertions

**Files changed:**
- `wafctl/query_helpers.go`: `rleEventType()`, `rleIsBlocked()`
- `wafctl/summary_counters.go`: `hourBucket`, `classifyRLIntoBucket()`, `buildSummary()`, `mergeSummaryResponses()`
- `wafctl/models.go`: `SummaryResponse`, `HourCount`
- `waf-dashboard/src/lib/api/waf-events.ts`: `TimelinePoint`, `SummaryData`
- `waf-dashboard/src/lib/api/analytics.ts`: timeline mapping
- `waf-dashboard/src/lib/api/analytics.test.ts`: test fixtures
