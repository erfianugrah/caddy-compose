# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

Docker Compose infrastructure for a Caddy reverse proxy with a custom policy engine WAF,
Authelia 2FA forward auth, and a WAF management sidecar. Two codebases:

- **wafctl/** — Go HTTP service + CLI tool (stdlib only, zero external deps, Go 1.26+)
- **waf-dashboard/** — Astro 6 + React 19 + TypeScript 5.7 frontend (shadcn/ui, Tailwind CSS 4)
- Root level: Caddyfile, Dockerfile (4-stage multi-stage), compose.yaml, Makefile

## Build Commands

```bash
make build              # Build all Docker images
make build-caddy        # Build the main Caddy image only
make build-wafctl       # Build the standalone wafctl image only
```

### Go (wafctl)

```bash
cd wafctl && CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=2.83.0" -o wafctl .
```

Version injected via `-ldflags "-X main.version=..."`. Fallback: `var version = "dev"` in `main.go`.

### Frontend (waf-dashboard)

```bash
cd waf-dashboard && npm ci && npm run build
```

## Test Commands

```bash
make test               # Run ALL tests (Go + converter + frontend)
make test-go            # wafctl Go tests (~1555 test functions)
make test-crs-converter # CRS converter tests (~51 test functions)
make test-frontend      # Frontend Vitest (19 test files, ~355 tests)
make test-e2e           # E2E smoke tests (requires Docker, ~119 tests)
make test-crs-e2e       # CRS regression tests (requires Docker, 4566 tests)
```

### Running a single test

```bash
# Go — run from wafctl/:
cd wafctl && go test -run TestFunctionName -count=1 -timeout 60s ./...

# Converter — run from tools/crs-converter/:
cd tools/crs-converter && go test -run TestName -count=1 -timeout 60s ./...

# Frontend — run from waf-dashboard/:
cd waf-dashboard && npx vitest run -t "test description substring"

# E2E — run from test/e2e/:
cd test/e2e && go test -v -count=1 -timeout 60s -run TestName ./...

# CRS E2E — run from test/crs/ (requires Docker stack):
cd test/crs && go test -v -count=1 -timeout 600s ./...
```

### CRS Rules

```bash
make generate-rules            # Regenerate default-rules.json from CRS
make test-crs-e2e              # Run CRS regression tests (requires Docker)
make test-crs-e2e-update       # Run + update baseline (fast, status-code only)
```

## Lint / Format

No linters or formatters are configured. Use `gofmt` for Go.
TypeScript strict mode enforced via `astro/tsconfigs/strict`.

## Secrets

- `.env` is SOPS-encrypted (age). **Never commit unencrypted secrets.**
- A pre-commit hook blocks unencrypted `.env`, `.tfvars`, `.tfstate` files.

## Code Style — Go (wafctl/)

### Imports & Structure

- Standard library only — zero external dependencies. Single import block, alphabetically sorted.
- One cohesive module per `.go` file, split by domain responsibility.
- Section headers: `// --- Section Name ---` or `// ─── Section Name ──────────`
- Shared utilities in `util.go`; `envOr()` in `main.go`.

### Naming

- Types: `PascalCase` — `Store`, `WAFConfig`, `RuleExclusion`
- Exported functions: `PascalCase` — `NewStore`, `LoadConfig`
- Unexported functions: `camelCase` — `parseEvent`, `headerValue`, `envOr`
- Variables/constants: `camelCase` — `exclusionStore`, `validWAFModes`
- Files: lowercase with underscores — `rl_analytics.go`, `crs_rules.go`

### Error Handling

- Return errors as last value: `func (s *Store) Update(cfg WAFConfig) (WAFConfig, error)`
- Rollback-on-error pattern for store mutations — save old state, apply new, revert on failure.
- `log.Printf` for warnings; `log.Fatalf` only in `main()`.
- HTTP errors via `writeJSON(w, statusCode, ErrorResponse{Error: "...", Details: err.Error()})`.

### HTTP Handlers

- Go 1.22+ route patterns: `mux.HandleFunc("GET /api/health", handleHealth)`
- Closure pattern for DI: `handleSummary(store, als) http.HandlerFunc`
- All JSON responses via `writeJSON()` helper; request bodies via `decodeJSON()` (5 MB limit).
- Query filters: `fieldFilter` with `parseFieldFilter(value, op)` and `matchField(target)`.
  Operators: `eq` (default), `neq`, `contains`, `in`, `regex`. Param format: `field=val&field_op=op`.

### Concurrency

- `sync.RWMutex` on all stores; `RLock` for reads, `Lock` for mutations.
- `atomic.Int64` for offset tracking; `atomic.Bool` for guard flags.
- `atomic.Pointer` for CRS catalog (`defaultCRSCatalog`) and CRS metadata (`defaultCRSMetadata`).
- Return deep copies from getters to prevent concurrent modification.

### File Operations

- Atomic writes via `atomicWriteFile()` in `util.go` — write to temp, fsync, rename.
- All stores use JSON file persistence with `sync.RWMutex` protection.

### Input Validation

- `validateExclusion()` rejects newlines in all string fields, validates operators/fields against allowlists.
- `validateConditions()` — shared validation for WAF exclusions and rate limit rules.
- Tags: lowercase alphanumeric + hyphens (`^[a-z0-9][a-z0-9-]*$`), max 10 per rule, max 50 chars each.
- Condition operators validated per-field via `validOperatorsForField` map.
  Numeric operators (gt, ge, lt, le) accepted on any field.

## Code Style — TypeScript/React (waf-dashboard/)

### Imports & Naming

- Framework imports first (`react`, `vitest`), then local imports. Path alias: `@/` → `./src/`.
- Interfaces/types: `PascalCase` — `SummaryData`, `WAFEvent`, `TimelinePoint`
- Components: `PascalCase` filenames — `OverviewDashboard.tsx`, `PolicyEngine.tsx`
- API functions: `camelCase` — `fetchSummary`, `fetchEvents`, `lookupIP`

### API Layer

- Domain modules under `src/lib/api/` with barrel export via `index.ts`.
- Both Go JSON and TypeScript interfaces use `snake_case` field names (1:1 identity).
  A few fields are renamed between `Raw*` and public interfaces for clarity
  (e.g., `is_blocked` → `blocked`, `logged_events` → `logged`).
- When adding endpoints, update the Go handler AND the matching API module.

### UI Patterns

- shadcn/ui components in `src/components/ui/`; `cn()` for className composition.
- Components over ~500 lines split into feature subdirectories (e.g., `policy/`, `ratelimits/`, `csp/`).
- Astro static MPA (not SPA) — file-based routing, pre-rendered HTML pages.
- SSR/Hydration caveat: read URL params in `useEffect` (client-only), never in `useState` initializer.
- Cross-page links use native `<a href>` anchors, not SPA navigation.

## Test Patterns

### Go

- All `package main` (whitebox). Table-driven tests with `t.Run()` subtests.
- `httptest.NewRequest` + `httptest.NewRecorder` for handler tests.
- `httptest.NewServer` to mock the Caddy admin API.
- Temp file helpers in `testhelpers_test.go`: `writeTempLog`, `newTestExclusionStore`, etc.

### Frontend

- Vitest with `vi.fn()` mock fetch, `describe`/`it` blocks.
- `beforeEach`/`afterEach` for setup/teardown.
- API tests split by domain in `src/lib/api/`, component tests alongside components.

## Checklists

### Adding a New Event Type (e.g., `challenge_issued`)

Every new event type must be wired through the full stack. Missing any layer
causes the event to be invisible in parts of the UI.

**Plugin (caddy-policy-engine):**
- [ ] `caddyhttp.SetVar()` — set `policy_engine.action` to the new type in `ServeHTTP`
- [ ] `captureRequestContext(r, pb)` — call in the new event's case block so request headers/body are logged

**Caddyfile:**
- [ ] `log_append` — ensure `policy_action` field captures the new value (already generic)

**wafctl data pipeline:**
- [ ] `access_log_store.go` — add classification in `Load()` (`isChallenge`, etc.)
- [ ] `access_log_store.go` — set `evt.Source` to the new type in event builder
- [ ] `access_log_store.go` — propagate any new fields to `RateLimitEvent`
- [ ] `access_log_store.go` `RateLimitEventToEvent()` — add `case` for new source → event type + status
- [ ] `access_log_store.go` `RateLimitEventToEvent()` — update `nonBlocking` map if non-blocking
- [ ] `access_log_store.go` `RateLimitEventToEvent()` — set `evt.RuleMsg` for the new event type (display in event detail)
- [ ] `handlers_exclusions.go` `handleExclusionHits()` — add event type prefix to hits scan filter
- [ ] `query_helpers.go` `rlEventTypes` map — add the new event type(s) so filtering works
- [ ] `query_helpers.go` `wafEventTypes` map — add if the event type appears in the WAF store
- [ ] `query_helpers.go` `rleEventType()` — add `case` returning the event type string
- [ ] `query_helpers.go` `rleIsBlocked()` — add to non-blocking list if applicable
- [ ] `query_helpers.go` `rleResponseStatus()` — add `case` if HTTP status differs from default 429
- [ ] `query_helpers.go` `rleBlockedBy()` — add `case` if blocked by a specific component
- [ ] `query_helpers.go` `enrichSingleRLE()` — add tag enrichment `case` for the new source
- [ ] `query_helpers.go` `rleTags()` — add tag lookup `case` for the new source
- [ ] `summary_counters.go` `hourBucket` — add counter field
- [ ] `summary_counters.go` `classifyRLIntoBucket()` — add `case` incrementing the counter
- [ ] `summary_counters.go` `classifyEventIntoBucket()` — add `case` for fallback Event-based path
- [ ] `summary_counters.go` `buildSummary()` — accumulate total + populate in `SummaryResponse`
- [ ] `summary_counters.go` `buildSummary()` logged derivation — subtract new type if non-blocking
- [ ] `summary_counters.go` `mergeSummaryResponses()` — merge the new field
- [ ] `summary_counters.go` `hourBucket` — add per-service/per-client breakdown maps for new type
- [ ] `summary_counters.go` `incrementEvent()`/`decrementEvent()` — add service + client action breakdown cases
- [ ] `summary_counters.go` `incrementRLEvent()`/`decrementRLEvent()` — same for RLE-based path
- [ ] `summary_counters.go` `buildSummary()` `svcMap`/`clientMap` — expand tuple + aggregate new field
- [ ] `models.go` `SummaryResponse` — add field
- [ ] `models.go` `HourCount` — add field
- [ ] `models.go` `ServiceCount` — add counter field
- [ ] `models.go` `ClientCount` — add counter field
- [ ] `models.go` `ServiceDetail` — add counter field
- [ ] `models.go` `Event` — add any new per-event fields (e.g., `ja4`, `bot_score`)
- [ ] `models_general_logs.go` `GeneralLogEvent` — add field if visible on all requests

**Frontend API layer:**
- [ ] `waf-events.ts` `EventType` union — add the new type
- [ ] `waf-events.ts` `validEventTypes` array in `mapEvent()` — add the new type
- [ ] `waf-events.ts` `SummaryData` — add counter field
- [ ] `waf-events.ts` `TimelinePoint` — add counter field
- [ ] `waf-events.ts` `RawSummary` — add counter fields (top-level scalars)
- [ ] `waf-events.ts` `RawSummary.events_by_hour` — add counter fields to inline type
- [ ] `waf-events.ts` `RawSummary.top_services` — add counter fields to inline type
- [ ] `waf-events.ts` `RawSummary.top_clients` — add counter fields to inline type
- [ ] `waf-events.ts` `RawSummary.service_breakdown` — add counter fields to inline type
- [ ] `waf-events.ts` `fetchSummary()` — map scalar counter fields from raw response
- [ ] `waf-events.ts` `fetchSummary()` timeline mapper — map counter fields from `events_by_hour`
- [ ] `waf-events.ts` `fetchSummary()` top_services mapper — map counter fields
- [ ] `waf-events.ts` `fetchSummary()` top_clients mapper — map counter fields
- [ ] `waf-events.ts` `fetchSummary()` service_breakdown mapper — map counter fields
- [ ] `waf-events.ts` `ServiceStat` interface — add counter field
- [ ] `waf-events.ts` `ClientStat` interface — add counter field
- [ ] `waf-events.ts` `ServiceBreakdown` interface — add counter field
- [ ] `waf-events.ts` `WAFEvent` — add any new per-event fields
- [ ] `waf-events.ts` `RawEvent` — add matching fields
- [ ] `waf-events.ts` `mapEvent()` — propagate new fields
- [ ] `analytics.ts` — add fields to timeline mapping + raw type
- [ ] `analytics.test.ts` — update test fixtures
- [ ] `general-logs.ts` `GeneralLogEvent` — add field if applicable

**Frontend UI:**
- [ ] `utils.ts` `ACTION_LABELS` — add human-readable label
- [ ] `utils.ts` `ACTION_BADGE_CLASSES` — add badge styling
- [ ] `utils.ts` `ACTION_COLORS` — add chart color
- [ ] `filters/constants.ts` `EVENT_TYPE_OPTIONS` — add filter option
- [ ] `OverviewDashboard.tsx` `STAT_CARD_DEFS` — add stat card (auto-hidden if zero)
- [ ] `OverviewDashboard.tsx` timeline chart — add gradient + `<Area>` series
- [ ] `OverviewDashboard.tsx` pie chart breakdown — add slice
- [ ] `OverviewDashboard.tsx` logged computation — subtract new type if non-blocking
- [ ] `OverviewDashboard.tsx` Top Clients bar chart logged computation — subtract new non-blocking type
- [ ] `OverviewDashboard.tsx` stacked bar charts — add `<Bar>` if needed
- [ ] `EventDetailPanel.tsx` — add type-specific rendering branch in detail panel
- [ ] `EventDetailPanel.tsx` — display `user_agent` field (from request context headers)
- [ ] `EventDetailPanel.tsx` — add request context section (headers, body) if applicable
- [ ] `LogDetailPanel.tsx` — add fields to general log detail if applicable
- [ ] `EventTypeBadge.tsx` — already generic (reads from `ACTION_LABELS`), no change needed

**Tests:**
- [ ] `constants.test.ts` — update type/option counts
- [ ] `DashboardFilterBar.test.ts` — update event_type option count
- [ ] `waf-events.test.ts` — update timeline fixture, service_breakdown fixture, event type coverage
- [ ] `analytics.test.ts` — update timeline fixture fields

### Adding a New Rule Type (e.g., `challenge`)

**wafctl model + validation:**
- [ ] `models_exclusions.go` `validExclusionTypes` — add type
- [ ] `models_exclusions.go` `RuleExclusion` struct — add type-specific fields
- [ ] `exclusions_validate.go` `switch e.Type` — add validation case
- [ ] `exclusions_validate.go` `validSkipPhases` — add if skippable
- [ ] `models_ratelimit.go` `validRLKeyPattern` — add if new RL key type

**wafctl generator + deploy:**
- [ ] `policy_generator.go` `policyEngineTypes` — add type
- [ ] `policy_generator.go` `policyTypePriority` — add priority band
- [ ] `policy_generator.go` `PolicyRule` struct — add type-specific fields
- [ ] `policy_generator.go` `GeneratePolicyRulesWithRL()` — add conversion block
- [ ] `deploy.go` `DeployConfig` — add any new config fields (e.g., HMAC key)
- [ ] `main.go` — read env vars for new config, pass to `DeployConfig`

**Plugin (caddy-policy-engine):**
- [ ] `policyengine.go` `validRuleTypes` — add type
- [ ] `policyengine.go` `validSkipPhases` — add if skippable
- [ ] `policyengine.go` `compileRule()` — add compilation block
- [ ] `policyengine.go` `ServeHTTP` switch — add `case` for the type
- [ ] `policyengine.go` skip flag variable + skip check in loop
- [ ] `policyengine.go` service matching — add type to service-scoped list if applicable
- [ ] `policyengine.go` `compiledRule` struct — add type-specific compiled config
- [ ] `policyengine.go` `compiledSkipTargets` — add skip flag field if skippable
- [ ] `policyengine.go` `compileSkipTargets()` — add `case` for new phase
- [ ] `PolicyRulesFile` struct — add global config if needed

**Dashboard types:**
- [ ] `exclusions.ts` `ExclusionType` — add type
- [ ] `exclusions.ts` `Exclusion` interface — add type-specific fields
- [ ] `exclusions.ts` `ExclusionCreateData` — no change needed (derived from `Exclusion` automatically)
- [ ] `exclusions.ts` `typeToGo` / `typeFromGo` — add mapping
- [ ] `exclusions.ts` `mapExclusionFromGo()` — add type-specific fields from API response
- [ ] `exclusions.ts` `mapExclusionToGo()` — no change needed (generic key loop)
- [ ] `exclusions.ts` `RawExclusion` interface — add type-specific fields

**Dashboard UI:**
- [ ] `constants.ts` `ALL_EXCLUSION_TYPES` — add entry
- [ ] `constants.ts` `QUICK_ACTIONS` — add if quick-access (with icon)
- [ ] `constants.ts` `AdvancedFormState` + `emptyAdvancedForm` — add fields
- [ ] `PolicyForms.tsx` — add form section for type-specific fields
- [ ] `PolicyForms.tsx` `handleTypeChange` — add field resets
- [ ] `PolicyForms.tsx` `handleSubmit` — add data serialization
- [ ] `PolicyForms.tsx` `isValid` — add validation if needed
- [ ] `PolicyForms.tsx` imports — add icon if new quick action
- [ ] `PolicyForms.tsx` `QUICK_ACTION_ICONS` — add icon mapping
- [ ] `PolicyEngine.tsx` `editFormState` — populate type-specific fields

**Tests:**
- [ ] `constants.test.ts` — update QUICK_ACTIONS count
- [ ] `constants.test.ts` — update ALL_EXCLUSION_TYPES count
- [ ] `exclusions_test.go` — add validation tests for new type
- [ ] `policy_generator_test.go` — add generator tests (priority, conversion, defaults)

### Adding a New Condition Field (e.g., `ja4`)

- [ ] Plugin `policyengine.go` `extractFieldValue()` — add `case`
- [ ] Plugin `policyengine.go` `extractMultiField()` — add `case` if multi-value
- [ ] Plugin `policyengine.go` `extractMultiFieldKeyed()` — add `case` if multi-value
- [ ] Plugin `policyengine.go` `bodyFields` — add if field requires body read
- [ ] Plugin `policyengine.go` `multiFields` — add if field is multi-value
- [ ] Plugin `policyengine.go` `needsBodyField()` — add if field requires body read
- [ ] Plugin `policyengine.go` `fieldAbsent()` — add `case` if field can be absent
- [ ] Plugin `policyengine.go` `singleFieldVarName()` — add CRS variable name mapping
- [ ] Converter `mapper.go` `variableMap` — add CRS variable → plugin field mapping
- [ ] Converter `mapper.go` `pluginSupportedFields` — add the new field
- [ ] Converter `mapper.go` `multiFields` — add if multi-value (for count: support)
- [ ] wafctl `models_exclusions.go` `validPolicyEngineFields` — add field
- [ ] wafctl `models_exclusions.go` `validOutboundFields` — add if response-phase
- [ ] wafctl `models_exclusions.go` `validAggregateFields` — add if multi-value
- [ ] wafctl `models_exclusions.go` `validOperatorsForField` — add operator set
- [ ] Dashboard `exclusions.ts` `ConditionField` type — add value
- [ ] Dashboard `constants.ts` `CONDITION_FIELDS` — add field definition with operators

## Key Architecture Notes

- Deploy pipeline: generate config → write `policy-rules.json` → plugin detects mtime change → hot-reload.
- On startup, `generateOnBoot()` regenerates all config from stored JSON state.
- Version tags must stay in sync across: `Makefile`, `compose.yaml`, `README.md`, `.github/workflows/build.yml`.
- **Unified rule store**: `ExclusionStore` handles ALL rule types
  (allow/block/challenge/skip/detect/rate_limit/response_header).
  `RuleExclusion` is the single model. `/api/rules` is the canonical CRUD endpoint.
  `/api/deploy` is the single deploy endpoint. Old `/api/exclusions` kept as alias.
- Policy engine handles all rule evaluation with a **7-pass evaluation pipeline**:
  Allow (50-99) → Block (100-149) → Challenge (150-199) → Skip (200-299) →
  Rate Limit (300-399) → Detect (400-499) → Response Header (500-599).
  Coraza has been removed.
- **Challenge rules**: Proof-of-work interstitial (Anubis-inspired). SHA-256 hashcash
  with configurable difficulty (leading hex zeros), per-service HMAC-signed cookies,
  stateless design. Plugin serves embedded HTML/JS interstitial, verifies PoW at
  `/.well-known/policy-challenge/verify`. Cookie bypass on subsequent requests.
  HMAC key auto-generated by wafctl, injected into `policy-rules.json` at deploy.
  6-layer bot scoring: JA4 TLS, HTTP headers, JS probes (13 signals), behavioral
  (5 signals), spatial inconsistency, session behavioral tracking. Score >= 70
  rejects even with valid PoW.
  Cryptographic cookie IDs (jti), 1-hour default TTL, `challenge_cookie` RL key.
  Challenge hardening (v3.66.0): three enhancements to the PoW system:
  - **Adaptive difficulty**: `challenge_min_difficulty`/`challenge_max_difficulty` fields
    on rules. Server runs `preSignalScore()` (L1/L2/partial-L5 — JA4, HTTP headers, UA
    spatial checks) at interstitial-serve time and maps linearly to [min, max] range.
    Score 0 → min, score >= 70 → max. When unset, both default to `challenge_difficulty`.
  - **JA4 token binding**: `challenge_bind_ja4` field (default true). JA4 fingerprint is
    HMAC'd into the challenge payload and stored in the cookie's `ja4` field. Cookie
    validation rejects if the current connection's JA4 doesn't match. Prevents cookie
    replay from a different TLS stack (e.g., solve in browser, replay from curl).
  - **Timing validation**: Server parses `elapsed_ms` (already submitted by client,
    previously ignored) and `cores` from JS signals. `minSolveMs(difficulty, cores)` =
    `2^(difficulty*4) / (cores * 50) * 0.3`. Hard reject if elapsed < floor/3 (impossible
    timing). Soft penalty (+40 bot score) if elapsed < floor.
  Challenge field relationships:
  - **`challenge_difficulty`** (1-16, default 4): Static difficulty — used when adaptive
    min/max are both 0. Ignored when adaptive range is active.
  - **`challenge_min_difficulty`** / **`challenge_max_difficulty`** (1-16, 0=disabled):
    Adaptive range. When both > 0, the server picks difficulty per-request based on
    `preSignalScore()`. Clean browsers get min, suspicious TLS/headers get max.
    Overrides `challenge_difficulty` entirely when active.
  - **`challenge_algorithm`** ("fast"/"slow"): Orthogonal to difficulty. "slow" adds 10ms
    delay per hash iteration — applies to ALL clients regardless of their adaptive
    difficulty. Useful as a blanket punishment but be cautious: slow + difficulty > 2
    causes multi-minute solve times for real users. Expected solve times (8 cores):
    fast d4=~0.04ms, slow d4=~41s, slow d5=~11min, slow d6=~3h. Algorithm is enriched
    onto security events via rule lookup (not in access log) and shown in event detail
    with expected-vs-actual solve time comparison.
  - **`challenge_bind_ip`** (default true): Invalidates cookie if client IP changes.
  - **`challenge_bind_ja4`** (default true): Invalidates cookie if JA4 TLS fingerprint
    changes. Prevents cookie replay from a different TLS stack.
  - **`challenge_ttl`** ("1h"/"24h"/"7d"): Cookie lifetime before re-challenge.
  Challenge analytics: `/api/challenge/stats?hours=24&service=x&client=y` returns funnel
  (issued/passed/failed/bypassed), bot score histogram, hourly timeline, per-algorithm
  breakdown (fast/slow with avg solve time and avg difficulty), expected solve time
  reference table (all difficulty × algorithm × core permutations), top clients
  (with unique token counts and avg/max bot scores), top services (with fail rates),
  and top JA4 fingerprints. Dashboard at `/challenge`.
  Challenge data pipeline: plugin sets `policy_engine.challenge_difficulty`,
  `policy_engine.challenge_elapsed_ms`, `policy_engine.challenge_pre_score` as Caddy
  variables. These flow to access log via `log_append` and are parsed by wafctl into
  `RateLimitEvent` and `Event` structs. Analytics show avg solve time and avg difficulty.
  Challenge reputation: `/api/challenge/reputation?hours=24&service=x` returns JA4
  verdicts (trusted/suspicious/hostile from fail rates + avg bot scores), per-IP
  challenge history with flags (repeat_failure, cookie_harvesting, ja4_rotation),
  and severity-ranked alerts. Dashboard Reputation tab with quick-action Block/Challenge.
  Endpoint discovery: `/api/discovery/endpoints?hours=24&service=x` aggregates traffic
  by (service, method, path) with path normalization (UUIDs/numeric IDs collapsed).
  Per-endpoint: request count, unique IPs/JA4s/UAs, non-browser %, challenge/rate-limit
  coverage check. Dashboard Endpoint Discovery tab with coverage shields and
  quick-action "Create Challenge Rule" links.
  Challenge condition field: `challenge_history` — returns "passed" (valid cookie),
  "expired" (invalid cookie), or "none" (no cookie). Enables rules that enforce
  challenge requirements on specific paths. Escalation template available at
  `/api/rules/templates` (challenge-escalation: block unchallenged + block expired).
- **JA4 TLS fingerprinting**: `caddy.ListenerWrapper` module (`caddy.listeners.ja4`)
  between L4 DDoS and TLS in the listener chain. Hand-rolled ClientHello binary parser
  (zero deps). Full FoxIO JA4 spec. Available as `ja4` condition field and
  `policy_engine.ja4` Caddy variable. Enriches both security events and general logs.
- Service FQDN resolution: `BuildServiceFQDNMap()` parses Caddyfile to map short names → FQDNs.
  `mapServiceBoth` generic helper maps both short name and FQDN in all config builders.
- **CRS metadata**: Category taxonomy, valid prefixes, and severity levels are loaded from
  `crs-metadata.json` at startup (generated by `tools/crs-converter/` at Docker build time).
  Required — `main()` fatals if missing (no fallback). Tests load from `testdata/crs-metadata.json`
  via `TestMain`. `crs_metadata.go` holds the loader, `atomic.Pointer[CRSMetadata]` for
  thread-safe access. `normalizeCRSCategory()` and `IsValidPrefix()` read from loaded metadata.
- **CRS converter** (`tools/crs-converter/`): Converts CRS 4.x SecRule `.conf` files into
  `default-rules.json` for the policy engine plugin. 342 rules from CRS 4.25.0.
  Key features: RE2 regex validation with PCRE→RE2 auto-fix, per-field OR group
  conditions (preserves exact CRS variable scope), `Excludes` distribution to sub-conditions,
  TX variable capture chain flattening (bakes in CRS default allowlists for content-type,
  charset, restricted extensions, restricted headers), MATCHED_VARS→tx:0 conversion,
  special-case handling for rules 920450/920451/920540/931130, `pluginSupportedFields`
  filtering to prevent unsupported field conditions. Run with `make generate-rules`.
  Only 5 CRS detection rules skipped: 911100/920430 (handled natively by plugin
  `enforceProtocolLimits()`), 920190/942130/942131 (TX-to-TX comparison unsupported).
  294 flow-control rules correctly excluded (non-detection).
  CRS regression test fidelity at PL4: **97.9%** (4421/4514 testable, official CRS 4.25.0 suite).
  93 real failures. 603 cross-rule passes resolved via severity-aware events API batch check.
  Backend: albedo (CRS official test backend). Reload interval 2s.
  Key plugin fixes: multiFieldAbsent (detect path), parseQueryAmpOnly (semicolons).
  Tests auto-download from GitHub via sparse checkout (`make test-crs-e2e`).
- **CRS regression testing** (`test/crs/`): Runs the official OWASP CRS regression test
  suite (4566 YAML test cases) against the live Docker stack. PL4 with threshold=5
  (all rules enabled). Two-phase evaluation: (1) status-code fast path for clear
  pass/fail, (2) batch rule-level resolution via events API for ambiguous results
  (rules that scored below threshold but still matched, cross-rule interference
  where OTHER rules caused the block). Baseline tracking catches regressions.
  Run with `make test-crs-e2e` (check) or `make test-crs-e2e-update` (update baseline).
  Host header set via `req.Host` (Go net/http ignores `req.Header["Host"]`).
- **CRS remaining gaps** (93 real failures).
  - **603 cross-rule passes** resolved via severity-aware events API batch check
    (blocked by OTHER rules, tested rule's score alone below threshold).
- **DDoS mitigator**: `caddy-ddos-mitigator` plugin (separate repo: `ergo/caddy-ddos-mitigator`).
  Compiled into Caddy via xcaddy. Three-layer detection architecture (v0.17.0+):
  - **L1 — Global rate gate**: per-IP sustained req/s across ALL services (60s sliding window
    via ring buffer in `hostTracker`). Configurable `global_rate_threshold` (0=disabled).
  - **L2 — Per-service behavioral**: tracker keyed on `(IP, host)` — each service gets its
    own `ipProfile` with path diversity scoring. `AnomalyScore(uniqueHosts, recentRate)`.
  - **L3 — Host diversity exculpation**: `hostTracker` counts unique hosts per IP. At jail
    decision: `effectiveScore = rawScore / log2(uniqueHosts + 1)`. 8 services → ÷3.17.
    `min_host_exculpation` (default 2) gates when dampening activates.
  Enforces via 4 layers: L3 nftables kernel drop (primary), L4 TCP RST, L7 HTTP 403, eBPF/XDP NIC drop.
  Immediate nftables sync on jail (v0.14.0+) — zero propagation window between L7 jail and kernel drop.
  CIDR /24 promotion now visible in jail.json and kernel-dropped via nftables interval sets (v0.15.0).
  L4 handler configurable via Caddyfile listener_wrappers (v0.15.0).
  Shares IP jail with wafctl via `/data/waf/jail.json` (bidirectional file sync).
  Jail reasons: `auto:rate` (L1), `auto:behavioral` (L2+L3), `manual`.
  - wafctl stores: `JailStore`, `DosConfigStore`, `SpikeDetector`, `SpikeReporter`
  - API: `/api/dos/status`, `/api/dos/jail`, `/api/dos/config`, `/api/dos/reports`, `/api/dos/profiles`
  - `DosConfig` fields: `threshold`, `global_rate_threshold`, `min_host_exculpation`, `profile_ttl`,
    `base_penalty`, `max_penalty`, `eps_trigger`, `eps_cooldown`, `cooldown_delay`, `whitelist`,
    `kernel_drop`, `strategy`
  - `DosStatus` fields: `rate_jail_count`, `behav_jail_count` (L1/L2 breakdown)
  - `JailEntry` fields: `anomaly_score`, `host_count` (enrichment at jail time)
  - Dashboard: `/dos` page (`DDoSPanel.tsx`) with tabs: IP Jail, Profiles, Spike Reports, Configuration;
    frontend API in `src/lib/api/dos.ts`
  - Log fields: `ddos_action`, `ddos_fingerprint`, `ddos_z_score`, `ddos_spike_mode`
  - Handler ordering: `order log_append first`, `order ddos_mitigator after log_append`
  - L4 listener wrapper: `servers { listener_wrappers { layer4 { route { ddos_mitigator { ... } } } } }`
  - `SpikeDetector` thresholds updateable at runtime via `PUT /api/dos/config`.
- **Session behavioral tracking**: Layer 6 of bot scoring. Plugin embeds `session-sw.js`
  (service worker) and `session-collector.js` which track per-session behavioral signals
  (mouse movement, scroll patterns, keystroke cadence, focus/blur, navigation timing) and
  report back via `/.well-known/policy-challenge/session-report`. Sessions are keyed by
  cryptographic cookie ID (jti). `challenge_fail_reason` is now set natively by the plugin
  (not inferred by wafctl). PoW progress bar is time-based (not iteration-based).
  - wafctl stores: `SessionStore` — manages session data, scores, and alerts.
  - File sync: `jti-denylist.json` shared between wafctl and plugin (bidirectional).
    wafctl writes denied JTIs; plugin reads and rejects cookies with denied JTIs.
  - Config: `WAF_SESSION_FILE` (session data path), `WAF_SESSION_CONFIG_FILE` (scoring config).
  - Auto-escalation: suspicious sessions (high bot scores, anomalous behavior patterns)
    trigger automatic creation of temporary block rules via the exclusion store.
    Rules have `ExpiresAt` set from `auto_escalate_ttl` config and auto-deploy to plugin.
    Expired rules are cleaned up every 60s with automatic redeploy.
  - API: `/api/sessions/stats`, `/api/sessions/list`, `/api/sessions/{jti}`,
    `/api/sessions/alerts`, `/api/sessions/config`
  - Dashboard: `/sessions` page (`sessions.astro` + `SessionsPanel.tsx`);
    frontend API in `src/lib/api/sessions.ts`
  - 17 dashboard pages total, 155 mux routes, 19 frontend API modules.

## Downstream WAF behaviour notes (for callers)

The custom policy engine in front of `composer.erfi.io` blocks the default `curl` User-Agent on **`PUT` and `POST`** requests to its API (cross-referenced from `~/servarr-compose/AGENTS.md`). `GET` works without extra headers. Callers must send:

```
-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ...'
-H 'Origin: https://composer.erfi.io'
-H 'Referer: https://composer.erfi.io/<page>'
```

Same pattern applies to any other downstream that goes through this WAF and accepts state-changing verbs — if you see a `403` page with a reference ID on a `PUT`/`POST` and not on `GET`, this is the cause. Check policy-engine event logs by reference ID to confirm the exact rule that triggered.
