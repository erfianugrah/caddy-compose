# FIXES.md — Known Issues & Pending Fixes

## Services Page: "No URI data" / "No rule data"

**Status:** Known issue, pre-existing (not related to the challenge feature).

**Symptom:** Expanding a service row on the Services page (`/services`) shows
"No URI data" and "No rule data" for most services, despite those services
having thousands of events.

**Root cause:** The `TopURIs` and `TopRules` fields in the `/api/services`
response are populated from the legacy WAF event store (`logparser.go:Store`),
not from the access log store (`access_log_store.go:AccessLogStore`) where
the majority of security events now live.

The legacy store (`Store`) was the original event store from the Coraza WAF era.
It parsed Coraza-format audit logs and extracted per-rule match details with
URI attribution. When the policy engine replaced Coraza, most event ingestion
moved to the `AccessLogStore` (which tails Caddy's `combined-access.log`),
but the URI/rule aggregation was never migrated.

**Code path:**

```
handleServices (handlers_events.go:541)
  → store.Services(hours)          // Legacy WAF store — usually empty
  → als.FastSummary(hours)         // Access log store — has all the events
  → merged summary used for counts // Counts are correct
  → TopURIs/TopRules from legacy   // Empty because legacy store is empty
```

The per-service event counts (Total, Blocked, Logged, etc.) are correct
because they come from the merged `FastSummary` of both stores. Only the
drill-down URI/rule data is missing.

**Fix approach:** Add `TopURIs()` and `TopRules()` methods to `AccessLogStore`
that aggregate URIs and rule names from `RateLimitEvent` data. The handler
already merges data from both stores for counts — extend it to also merge
URI/rule data.

Estimated effort: ~2-3 hours. The aggregation logic exists in the legacy
store's `Services()` method (`logparser.go`) and can be adapted for
`RateLimitEvent` fields.

**Files to change:**
- `access_log_store.go`: Add `ServiceTopURIs(service, hours, n)` and
  `ServiceTopRules(service, hours, n)` methods
- `handlers_events.go:541-591`: Merge TopURIs/TopRules from AccessLogStore
  when legacy store returns empty data
- No frontend changes needed — the response shape is unchanged

---

## Summary Timeline: Challenge Events Not in Counters

**Status:** Known limitation of the initial challenge implementation.

**Symptom:** Challenge events (`challenge_issued`, `challenge_passed`, etc.)
appear correctly in the event table with badges, but are not counted in the
summary timeline or overview dashboard counters.

**Root cause:** The `summaryCounters` system (`summary_counters.go`) has
hardcoded switch cases for each event type (18 switch cases across 6
functions). Adding challenge counters requires touching all of them plus the
`SummaryResponse`, `TimelinePoint`, `ServiceCount`, and `ClientCount` models.

**Fix approach:** Add `ChallengeIssued`, `ChallengePassed`, `ChallengeFailed`,
`ChallengeTotal` counters to the summary models and all switch cases. Also
add corresponding fields to the frontend `TimelinePoint` and `SummaryData`
types, and wire into the overview dashboard charts.

Estimated effort: ~3-4 hours. Mechanical but touches many files.

**Files to change:**
- `models.go`: Add challenge fields to `SummaryResponse`, `TimelinePoint`,
  `ServiceCount`, `ServiceDetail`
- `summary_counters.go`: Add challenge cases to `incrementRLEvent`,
  `decrementRLEvent`, `buildSummary`, and all per-type switch blocks
- `waf-dashboard/src/lib/api/analytics.ts`: Add challenge fields to
  `TimelinePoint` TypeScript interface
- `waf-dashboard/src/components/OverviewDashboard.tsx`: Add challenge
  series to timeline chart
