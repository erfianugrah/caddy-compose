# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

Docker Compose infrastructure for a Caddy reverse proxy with a custom policy engine WAF
(replacing Coraza), Authelia 2FA forward auth, and a WAF management sidecar. Two codebases live here:

- **wafctl/** — Go HTTP service + CLI tool (stdlib only, zero external deps, Go 1.24+)
- **waf-dashboard/** — Astro 5 + React 19 + TypeScript 5.7 frontend (shadcn/ui, Tailwind CSS 4)
- Root level: Caddyfile, Dockerfile (5-stage multi-stage), compose.yaml, Makefile

## Build Commands

```bash
make build              # Build all Docker images
make build-caddy        # Build the main Caddy image only
make build-wafctl      # Build the standalone wafctl image only
make push               # Push images to Docker Hub
make deploy             # Full pipeline: build + push + SCP + restart
```

### Go (wafctl)

```bash
cd wafctl && CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=1.2.1" -o wafctl .
```

Version is injected at build time via `-ldflags "-X main.version=..."`. The
`var version = "dev"` in `main.go` is the fallback for local builds. The
Dockerfile and Makefile both pass `--build-arg VERSION=` which feeds the ldflags.

### Frontend (waf-dashboard)

```bash
cd waf-dashboard && npm ci        # Install deps
cd waf-dashboard && npm run build  # Astro static build
```

## Test Commands

```bash
make test               # Run ALL tests (Go + frontend)
make test-go            # Go tests only
make test-frontend      # Frontend (Vitest) tests only
```

### Running a single test

```bash
# Go:
cd wafctl && go test -run TestFunctionName -count=1 -timeout 60s ./...
# Frontend:
cd waf-dashboard && npx vitest run -t "test description substring"
```

## Lint / Format

No linters or formatters are configured. Use `gofmt` for Go.
TypeScript strict mode is enforced via `astro/tsconfigs/strict`.

## Version Management

Image tags live in **four places** that must stay in sync:
- `Makefile` (lines 17-18: `CADDY_IMAGE`, `WAFCTL_IMAGE`)
- `compose.yaml` (lines 3 and 119: image fields)
- `README.md` (badge/reference)
- `.github/workflows/build.yml` (env block: `CADDY_TAG`, `WAFCTL_VERSION`)

Caddy tag format: `<project-version>-<caddy-version>` (e.g. `3.1.0-2.11.1`).
wafctl tag format: simple semver (e.g. `2.1.0`).

## Secrets and Encryption

- `.env` is SOPS-encrypted (age). Never commit unencrypted secrets.
- `authelia/users_database.yml` is also SOPS-encrypted.
- `.env.mk` (gitignored) holds local Makefile overrides like `REMOTE=host`.
- A **pre-commit hook** blocks unencrypted `.env`, `.tfvars`, `.tfstate` files.
  It checks YAML/JSON for secret-like patterns and verifies SOPS `ENC[AES256_GCM,...]`
  markers are present. Supports `.allow-unencrypted` (skip all) and
  `.allow-unencrypted-paths` (per-file glob exemptions).

## Code Style — Go (wafctl/)

### Imports

- Standard library only — no external dependencies
- Single import block, alphabetically sorted
- Common: `encoding/json`, `fmt`, `log`, `net/http`, `os`, `path/filepath`, `regexp`, `sort`, `strings`, `sync`, `sync/atomic`, `time`

### Naming

- Types: `PascalCase` — `Store`, `WAFConfig`, `RuleExclusion`, `DeployConfig`
- Exported functions: `PascalCase` — `NewStore`, `LoadConfig`
- Unexported functions: `camelCase` — `parseEvent`, `headerValue`, `envOr`
- Variables: `camelCase` — `exclusionStore`, `configStore`
- Constants as map-sets: `camelCase` — `validWAFModes`, `validHours`
- Files: lowercase with underscores — `rl_analytics.go`, `crs_rules.go`

### Error Handling

- Return errors as last value: `func (s *ConfigStore) Update(cfg WAFConfig) (WAFConfig, error)`
- Rollback-on-error pattern for store mutations — save old state, apply new, revert on failure
- `log.Printf` for non-fatal warnings; `log.Fatalf` only in `main()`
- HTTP errors via `writeJSON(w, statusCode, ErrorResponse{Error: "...", Details: err.Error()})`

### HTTP Handlers

- Go 1.22+ route patterns: `mux.HandleFunc("GET /api/health", handleHealth)`
- Closure pattern for dependency injection: `handleSummary(store, als) http.HandlerFunc`
- All JSON responses via `writeJSON()` helper (sets Content-Type, disables HTML escaping)
- All JSON request bodies decoded via `decodeJSON()` helper (`MaxBytesReader` 5 MB limit, structured error on failure)
- `PUT /api/exclusions/{id}` supports partial updates via JSON merge — decodes incoming fields into `map[string]json.RawMessage`, overlays onto the existing exclusion's JSON, then decodes the merged result. This enables toggling `enabled` without sending the full exclusion object.
- Server timeouts: `ReadTimeout: 10s`, `WriteTimeout: 150s`, `IdleTimeout: 60s`
- Caddy reload client timeout: `120s` (accounts for WAF rule initialization)
- Makefile deploy wget timeout: `120s` (`-T 120`)

### Query Filter System

- `fieldFilter` type with `parseFieldFilter(value, op)` and `matchField(target)` method
- Operators: `eq` (default), `neq`, `contains`, `in` (comma-separated), `regex` (Go RE2)
- Query param format: `<field>=<value>&<field>_op=<operator>` — backward compatible (no `_op` = `eq`)
- Used by `handleSummary` and `handleEvents` for: `service`, `client`, `method`, `event_type`, `rule_name`, `uri`, `status_code`, `country`
- When any filter is active on `/api/summary`, all events (WAF + RL) are collected, filtered, then re-summarized via `summarizeEvents()`

### Concurrency

- `sync.RWMutex` on all stores; `RLock` for reads, `Lock` for mutations
- `atomic.Int64` for lock-free offset tracking (`Store.offset` in logparser.go)
- `atomic.Bool` for lock-free guard flags (`BlocklistStore.refreshing`)
- Return deep copies from getters to prevent concurrent modification

### Input Validation

- Input validation regexps in `exclusions.go`: `ruleTagRe` (CRS tag format), `namedFieldNameRe` (header/cookie/args names)
- `validateExclusion()` rejects newlines in all string fields, validates condition operators/fields against allowlists
- `validateConditions()` — shared condition validation function used by both WAF exclusions and RL rules

### File Operations and Code Organization

- Atomic writes via `atomicWriteFile()` — write to temp, fsync, rename
- Incremental file reading with offset tracking and rotation detection
- Section headers: `// --- Section Name ---` or `// ─── Section Name ──────────`
- One cohesive module per `.go` file, split by domain responsibility
- **Entry point & routing**: `main.go` (~370 lines) — server setup, CORS middleware, `envOr()`, route registration
- **JSON/query helpers**: `json_helpers.go` — `writeJSON`, `decodeJSON`, `queryInt`; `query_helpers.go` — `parseHours`, `parseTimeRange`, `fieldFilter`, `matchField`
- **Handler files** (split from main.go): `handlers_events.go` (health/summary/events/services), `handlers_analytics.go` (top IPs/URIs/countries, IP lookup), `handlers_exclusions.go` (exclusion CRUD), `handlers_config.go` (CRS catalog, WAF config, deploy), `handlers_ratelimit.go` (RL rule CRUD + analytics), `handlers_lists.go` (managed lists CRUD + deploy)
- **Log parser**: `logparser.go` — Store struct, JSONL persistence, eviction; `event_parser.go` — `parseEvent`, anomaly score extraction; `waf_summary.go` — `summarizeEvents`; `waf_analytics.go` — services/IP/top-N analytics
- **Models** (split by domain): `models.go` — summary/analytics types; `models_exclusions.go` — Condition, RuleExclusion, WAFConfig; `models_ratelimit.go` — rate limit types; `models_general_logs.go` — general log types
- **Config generation**: `waf_settings_generator.go` — WAF settings generation (SecRule generators removed — policy engine handles all rules)
- **Access log store**: `access_log_store.go` (~623 lines) — AccessLogStore struct, persistence, Load, snapshots (split from rl_analytics.go)
- **Rate limit analytics**: `rl_analytics.go` (~373 lines) — regex cache, summary, filtered events, rule hits, condition matching
- **Rate limit advisor**: `rl_advisor.go` (~364 lines) — algorithm/computation, recommendations; `rl_advisor_stats.go` (~449 lines) — MAD/IQR/Fano statistical functions, distribution analysis; `rl_advisor_types.go` — types, models, cache
- **General logs**: `general_logs.go` (~505 lines) — store code; `general_logs_handlers.go` (~515 lines) — handlers + aggregation
- **IP intelligence**: `ip_intel.go` (~247 lines) — BGP routing, RPKI validation, orchestration; `ip_intel_sources.go` (~403 lines) — external API clients (Shodan, reputation, BGP); `tls_helpers.go` (38 lines) — TLS version/cipher suite name helpers
- **GeoIP**: `geoip.go` (~499 lines) — GeoIPStore, API/header/cache resolution; `geoip_mmdb.go` (~403 lines) — pure MMDB binary reader (zero-dependency)
- **Exclusions**: `exclusions.go` (~366 lines) — ExclusionStore CRUD, persistence; `exclusions_validate.go` (~257 lines) — validation, condition checks, regex patterns
- **CLI**: `cli.go` (~333 lines) — CLI framework, serve/config/deploy commands; `cli_rules.go` (~348 lines) — rules/exclusions/health subcommands; `cli_extras.go` (~310 lines) — ratelimit/csp/blocklist/events subcommands; `cli_managed_lists.go` (~116 lines) — managed lists subcommands
- **Shared utilities**: `util.go` (~85 lines) — `envOr()`, `atomicWriteFile()` (shared across stores)
- **Policy engine generator**: `policy_generator.go` (~339 lines) — PolicyRulesFile/PolicyRule/PolicyCondition types, PolicyRateLimitConfig/PolicyRateLimitGlobalConfig, `GeneratePolicyRules()`, `GeneratePolicyRulesWithRL()`, `IsPolicyEngineType()`, `SplitHoneypotPaths()`, `BuildServiceFQDNMap()`, `resolveServiceName()`
- **Managed lists**: `managed_lists.go` (~582 lines) — ManagedListStore CRUD, persistence, validation; `models_lists.go` (~69 lines) — ManagedList types; `handlers_lists.go` (~160 lines) — HTTP handlers
- **Security headers**: `security_headers.go` (~370 lines) — SecurityHeaderStore, 4 profiles (strict/default/relaxed/api), per-service overrides with profile inheritance, resolution, validation, HTTP handlers
- **Backup/Restore**: `backup.go` (~210 lines) — FullBackup envelope, handleBackup/handleRestore for all 6 config stores
- **Domain stores**: `rl_rules.go` (564), `csp.go` (~700 lines, includes functions moved from deleted `csp_generator.go`), `blocklist.go` (372), `validate.go` (447), `deploy.go`, `config.go`, `cache.go`, `cfproxy.go`, `crs_rules.go`

## WAF Config Defaults

- Mode: `enabled` (blocking), Paranoia level: `2`
- Inbound anomaly threshold: `10`, Outbound: `10`
- Request body limit: `13 MB`, action: `ProcessPartial` (inspect first 13 MB, pass the rest — allows large uploads like S3/MinIO)
- Per-service overrides stored in `WAFConfig.Services` map

### CRS v4 Extended Settings

All fields use `omitempty` — zero values mean "use CRS defaults". Per-service overrides
inherit from global defaults; only non-zero fields are emitted as `setvar` directives.

| Field | tx.* Variable | Type | Range / Values |
|-------|---------------|------|----------------|
| `blocking_paranoia_level` | `blocking_paranoia_level` | int | 1–4 (defaults to `paranoia_level`) |
| `detection_paranoia_level` | `detection_paranoia_level` | int | 1–4 (defaults to `paranoia_level`) |
| `sampling_percentage` | `sampling_percentage` | int | 0–100 |
| `reporting_level` | `reporting_level` | int | 1–5 |
| `early_blocking` | `early_blocking` | *bool | true/false (uses `*bool` to distinguish false from unset) |
| `enforce_bodyproc_urlencoded` | `enforce_bodyproc_urlencoded` | *bool | true/false |
| `allowed_methods` | `allowed_methods` | string | Space-separated HTTP methods |
| `allowed_request_content_type` | `allowed_request_content_type` | string | Pipe-separated MIME types |
| `max_num_args` | `max_num_args` | int | 0+ |
| `arg_name_length` | `arg_name_length` | int | 0+ |
| `arg_length` | `arg_length` | int | 0+ |
| `total_arg_length` | `total_arg_length` | int | 0+ |
| `max_file_size` | `max_file_size` | int | 0+ |
| `combined_file_sizes` | `combined_file_sizes` | int | 0+ |
| `restricted_extensions` | `restricted_extensions` | string | Space-separated (e.g., `.bak .sql`) |
| `allowed_http_versions` | `allowed_http_versions` | string | Space-separated (e.g., `HTTP/1.1 HTTP/2`) |
| `restricted_headers` | `restricted_headers` | string | Pipe-separated header names |
| `crs_exclusions` | (CRS exclusion profiles) | []string | `wordpress`, `nextcloud`, `drupal`, `cpanel`, `dokuwiki`, `phpmyadmin`, etc. |

Generator resolves BPL/DPL independently: if `blocking_paranoia_level` is set explicitly
it is used; otherwise it defaults to `paranoia_level`. Same for `detection_paranoia_level`.
`collectExtendedSetvars()` helper only emits directives for non-zero/non-default values.

## Policy Engine Exclusion Types

| Type | Action | Notes |
|------|--------|-------|
| `allow` | Policy Engine allow | Full WAF bypass for matching requests |
| `block` | Policy Engine block (403) | Deny matching requests. Honeypot paths use `block` + `["honeypot"]` tag |
| `detect` | Policy Engine detect | CRS-style anomaly scoring with configurable severity and PL |

### Condition Fields

| Field | Operators |
|-------|-----------|
| `ip` | `eq`, `neq`, `ip_match`, `not_ip_match`, `in_list`, `not_in_list` |
| `path` | `eq`, `neq`, `contains`, `begins_with`, `ends_with`, `regex`, `in`, `in_list`, `not_in_list` |
| `host` | `eq`, `neq`, `contains` |
| `method` | `eq`, `neq`, `in` |
| `user_agent` | `eq`, `contains`, `regex` |
| `header` | `eq`, `contains`, `regex` |
| `query` | `contains`, `regex` |
| `country` | `eq`, `neq`, `in` |
| `cookie` | `eq`, `neq`, `contains`, `regex` |
| `body` | `eq`, `contains`, `begins_with`, `ends_with`, `regex` |
| `body_json` | `eq`, `contains`, `regex`, `exists` |
| `body_form` | `eq`, `contains`, `regex` |
| `args` | `eq`, `neq`, `contains`, `regex` |
| `uri_path` | `eq`, `neq`, `contains`, `begins_with`, `ends_with`, `regex` |
| `referer` | `eq`, `neq`, `contains`, `regex` |
| `response_header` | `eq`, `contains`, `regex` |
| `response_status` | `eq`, `neq`, `in` |
| `http_version` | `eq`, `neq` |

Named fields (`header`, `cookie`, `args`, `response_header`, `body_form`) use `Name:value` format
in the value field — the name before `:` becomes the variable suffix, the value after `:` is
the match target. Without `:`, the entire collection is matched.
`body_json` uses `dotpath:value` format (e.g., `.user.role:admin`) — the dot-path
before `:` navigates the JSON document, the value after `:` is the match target.

### GeoIP Three-tier Resolution

```
Priority 1: Cf-Ipcountry header (free, zero latency, present when behind CF)
Priority 2: Local MMDB database lookup (sub-microsecond, offline)
Priority 3: Online API fallback (configurable via WAF_GEOIP_API_URL)
```

The online API supports IPinfo.io, ip-api.com, and similar services. Results are
cached in the shared 24h/100k in-memory cache. Supports `%s` URL placeholder for
IP or path-append. API key sent as Bearer token via `WAF_GEOIP_API_KEY`.

## Rate Limit Policy Engine

Condition-based rate limiting system that mirrors the WAF Policy Engine architecture.
Each rule targets a service and can optionally specify request-phase conditions for
fine-grained per-path, per-method, or per-header rate limiting.

### Architecture

- **Store**: `rl_rules.go` — `RateLimitRuleStore` with `sync.RWMutex`, CRUD, validation, v1 migration from flat zones, Caddyfile auto-discovery
- **Analytics**: `rl_analytics.go` — condition-based inference to attribute 429 events to specific rules
- **Advisor**: `rl_advisor.go` — traffic analysis, anomaly detection, client classification, recommendations with impact curves and time-of-day baselines
- **Handlers**: 12 HTTP endpoints under `/api/rate-rules` (CRUD, deploy, global config, export/import, hits, advisor)
- **CLI**: `wafctl ratelimit` / `wafctl rl` subcommands (list, get, create, delete, deploy, global)
- **Frontend**: `RateLimitsPanel.tsx` (rules CRUD + global settings), `RateAdvisorPanel.tsx` (advisor UI), `AdvisorCharts.tsx` (visualization components)
- **Frontend subdir**: `ratelimits/` — `constants`, `helpers`, `RuleForm`, `GlobalSettingsPanel`, `advisorConstants`, `AdvisorClientTable`, `AdvisorRecommendations`

### Rule Model

```
RateLimitRule {
  id, name, description, service, conditions[], group_operator,
  key, events, window, action, priority, tags[], enabled, created_at, updated_at
}
```

Tags follow the same constraints as exclusion tags: max 10 per rule, max 50 chars each,
lowercase alphanumeric + hyphens only (`^[a-z0-9][a-z0-9-]*$`). When a 429 event is
converted to the unified `Event` type, the matched rule's tags are propagated via
`matchEventToRuleTags()` in `rl_analytics.go`. This enables tag-based filtering and
`tag_counts` aggregation in the summary API for rate-limited events.

### Rate Limit Keys

| Key | Caddy Placeholder | Description |
|-----|-------------------|-------------|
| `client_ip` | `{http.request.remote.host}` | Per client IP (default) |
| `path` | `{http.request.uri.path}` | Per request path |
| `static` | `static` | Single global counter |
| `client_ip+path` | `{http.request.remote.host}_{http.request.uri.path}` | Per IP+path combo |
| `client_ip+method` | `{http.request.remote.host}_{http.request.method}` | Per IP+method combo |
| `header:<Name>` | `{http.request.header.<Name>}` | Per header value (e.g., API key) |
| `cookie:<Name>` | `{http.request.cookie.<Name>}` | Per cookie value |
| `body_json:<DotPath>` | `{http.vars.body_json.<DotPath>}` | Per JSON body field (e.g., API key in body) |
| `body_form:<Field>` | `{http.vars.body_form.<Field>}` | Per form-encoded field value |

### Rate Limit Actions

| Action | Behavior |
|--------|----------|
| `deny` | Return 429 when rate exceeded (default) |
| `log_only` | Set `X-RateLimit-Monitor` header instead of blocking — uses Caddy named matcher + header directive, NOT a `rate_limit` block |

### RL Condition Fields (subset of WAF fields)

Request-phase only: `ip`, `path`, `host`, `method`, `user_agent`, `header`, `query`,
`country`, `cookie`, `body`, `body_json`, `body_form`, `uri_path`, `referer`, `http_version`.
Response-phase fields (`args`, `response_header`, `response_status`) are excluded.
Body fields use the `caddy-body-matcher` plugin for Caddy-side matching.

`http_version` uses Caddy's `protocol` matcher. Values are normalized: `HTTP/2.0` → `http/2`,
but `HTTP/1.0` and `HTTP/1.1` keep their minor version (→ `http/1.0`, `http/1.1`).

### Global Config

`RateLimitGlobalConfig` controls jitter, sweep interval, and distributed RL settings
(read/write intervals, purge age). Stored alongside rules in the same JSON file.

### v1 Migration

Old flat zone format (`RateLimitZone`: name/events/window/enabled) is automatically
migrated to the new rule format on first load. Zones become rules with `key: "client_ip"`,
`action: "deny"`, `service` set from the zone name.

### Rate Limit Advisor

CF-style traffic analysis tool that scans access logs and recommends rate limit rules.
The advisor analyzes request patterns, detects anomalous clients using statistical methods,
and generates one-click rule creation from recommendations.

**Statistical Algorithms**:
- **MAD (Median Absolute Deviation)** — robust outlier detection resistant to skew; threshold at `median + 3×MAD`
- **Fano Factor** — burstiness detection via variance-to-mean ratio; values >1 indicate bursty traffic
- **IQR (Interquartile Range)** — fallback when MAD=0 (uniform-ish distributions); threshold at `Q3 + 1.5×IQR`
- **Composite Anomaly Score** — weighted combination: `0.4×volume + 0.3×burstiness + 0.3×concentration`
- **Cohen's d** — effect size measurement comparing client rate vs population mean
- **Client Classification** — categorizes clients as `normal`, `elevated`, `suspicious`, or `abusive` based on composite score thresholds

**Features**:
- Normalized rates (`RequestsPerSec`) for cross-window comparisons
- `NormalizedPercentiles` (P50/P75/P90/P95/P99 in req/s) on response
- Impact curve: simulated block rates at various threshold levels
- Distribution histogram: request count frequency distribution
- Time-of-day baselines: per-hour median/P95 RPS computed when ≥2 distinct hours of data present
- 30-second TTL cache keyed by `"window|service|path|method|limit"`, max 50 entries with expired-first eviction

**Query params**: `window` (`1m`/`5m`/`10m`/`1h`), `service`, `path`, `method`, `limit` (max clients, default 100)

**Frontend**: `RateAdvisorPanel.tsx` handles the form, client table with req/s columns, and recommendation cards. `AdvisorCharts.tsx` contains `ClassificationBadge`, `ConfidenceBadge`, `DistributionHistogram`, `ImpactCurve`, and `TimeOfDayChart` visualization components. Subcomponents: `ratelimits/AdvisorClientTable.tsx` (sortable client table with expandable rows), `ratelimits/AdvisorRecommendations.tsx` (recommendation cards with threshold slider).

## Code Style — TypeScript/React (waf-dashboard/)

### Imports

- Framework imports first (`react`, `vitest`), then local imports
- Path alias: `@/` maps to `./src/`

### Naming

- Interfaces/types: `PascalCase` — `SummaryData`, `WAFEvent`, `TimelinePoint`
- Components: `PascalCase` filenames — `OverviewDashboard.tsx`, `PolicyEngine.tsx`
- API functions: `camelCase` — `fetchSummary`, `fetchEvents`, `lookupIP`
- API base: `const API_BASE = "/api"`

### API Layer

- API client split into domain modules under `src/lib/api/`:
  - `shared.ts` — HTTP helpers (`fetchJSON`, `postJSON`, `putJSON`, `deleteJSON`), `FilterOp`, `SummaryParams`, `applyFilterParams`
  - `waf-events.ts` — Summary/overview types, WAFEvent, EventsParams, fetchSummary, fetchEvents, fetchServices
  - `analytics.ts` — IP lookup, top IPs/URIs/countries
  - `exclusions.ts` — Exclusion types, CRS types, type mapping (frontend ModSecurity names ↔ Go internal), CRUD
  - `config.ts` — WAFConfig, WAFServiceSettings, presets
  - `rate-limits.ts` — Rate limit rule types, CRUD, global config, analytics, advisor
  - `blocklist.ts` — Blocklist types and functions
  - `csp.ts` — CSP types and functions
  - `general-logs.ts` — General log types and functions
  - `managed-lists.ts` — Managed list types, CRUD
  - `index.ts` — barrel re-export (all components import from `@/lib/api`)
- Go returns `snake_case` JSON; the api modules map to `camelCase`
- Type-safe interfaces for all API responses
- When adding API endpoints, update the relevant Go handler and the matching api module
- `FilterOp` type: `"eq" | "neq" | "contains" | "in" | "regex"` — maps to backend `_op` query params
- `SummaryParams` and `EventsParams` include `_op` variants for all filter fields

### UI Patterns

- shadcn/ui components in `src/components/ui/` (button, card, badge, dialog, etc.)
- Tailwind CSS 4.0 for styling
- `cn()` utility (clsx + tailwind-merge) for className composition
- **Tag/chip pill pattern** — used for multi-value inputs (neon-cyan bg, font-mono, `x` to remove):
  - `RuleIdTagInput` — space-separated rule IDs (Enter/comma/space to add)
  - `PipeTagInput` — pipe-separated values for `in` operator (Enter/comma/pipe to add)
  - `MethodMultiSelect` — pill chips + popover picker for HTTP methods with `in` operator
- `ConditionRow` value input branching: `host` → `HostValueInput` (service dropdown), `method` + `in` → `MethodMultiSelect`, other + `in` → `PipeTagInput`, default → plain `<Input>`

### Shared Components

- `EventTypeBadge` — shared color-coded event type badge
- `EventDetailModal` — reusable Dialog wrapping EventDetailPanel with actions
- `TimeRangePicker` — Grafana-style time range picker with quick ranges, custom from/to, auto-refresh
- `DashboardFilterBar` — CF-style filter bar with wide 3-step popover (Field→Operator→Value, `w-96`), service and rule_name `in` multi-select with checkbox list + search + custom text entry, filter chips with operator symbols, `in` operator renders individual pills per value with `×` buttons. Dynamic searchable dropdowns for `service` (from API) and `rule_name` (from exclusions). Exports: `parseFiltersFromURL`, `filtersToSummaryParams`, `filtersToEventsParams`, `filterDisplayValue`, `operatorChip`, `FILTER_FIELDS`, `DashboardFilter`, `FilterField`
- `RateAdvisorPanel` — rate limit advisor UI: service/path/method/window form, client table with anomaly scores and req/s, recommendation cards with one-click rule creation
- `AdvisorCharts` — visualization components for the advisor: `ClassificationBadge`, `ConfidenceBadge`, `DistributionHistogram`, `ImpactCurve`, `TimeOfDayChart`
- `Sparkline` — shared SVG sparkline chart (used by PolicyEngine, RateLimitsPanel)
- `SortableTableRow` — dnd-kit sortable table row (used by PolicyEngine, RateLimitsPanel)
- `StatCard` — animated stat card with `useCountUp` hook (used by OverviewDashboard)
- `SecurityHeadersPanel` — security headers management: profile selector (strict/default/relaxed/api/custom), per-service overrides with profile inheritance, editable headers table, preview dialog, export/import

### Component Subdirectories

Components over ~500 lines are split into feature subdirectories following the `policy/` pattern:

- `analytics/` — `CountryLabel`, `IPLookupPanel`, `TopBlockedIPsPanel`, `TopTargetedURIsPanel`, `TopCountriesPanel`
- `csp/` — `constants`, `CSPSourceInput`, `DirectiveEditor`, `PreviewPanel`
- `events/` — `helpers`, `EventDetailPanel`
- `filters/` — `types`, `constants`, `filterUtils`
- `logs/` — `helpers`, `LogDetailPanel`, `LogStreamTab`, `SummaryTab`, `HeaderComplianceTab`
- `overview/` — `helpers` (chart formatting, tick renderers, deep-link builders)
- `policy/` — `ConditionBuilder`, `CRSRulePicker`, `PolicyForms`, `TagInputs`, `constants`, `eventPrefill`, `exclusionHelpers`
- `ratelimits/` — `constants`, `helpers`, `RuleForm`, `GlobalSettingsPanel`, `advisorConstants`, `AdvisorClientTable`, `AdvisorRecommendations`
- `settings/` — `constants`, `SettingsFormSections`, `AdvancedSettings`, `ServiceSettingsCard`

### Cross-Page Navigation

- **Overview → Events**: Stat cards link to `/events?type=<filter>`, service bar labels link to `/events?service=<name>`, client IPs link to `/analytics?tab=ip&q=<ip>`
- **Events ← URL params**: Reads `?type=`, `?service=`, `?status=`, `?method=`, `?ip=`, `?rule_name=` on mount, applies as initial filters, clears URL via `history.replaceState`
- **Investigate ← URL params**: Reads `?tab=` and `?q=` for tab selection and auto IP lookup
- **Events → Policy**: "Create Exception" stores event in sessionStorage, navigates to `/policy?from_event=1`
- **Events → Policy**: Policy rule events (9500000-9599999) link to `/policy?rule=<name>`
- **Policy → Overview**: Sparkline hit counts link to `/?rule_name=<name>`
- All cross-page links use native `<a href>` anchors (Astro static pages, not SPA)
- **SSR/Hydration caveat**: Read URL params in `useEffect` (client-only), never in `useState` initializer — causes React error #418

### Dashboard Pages (file-based routing)

`/` · `/analytics` · `/csp` · `/events` · `/headers` · `/lists` · `/logs` · `/policy` · `/rate-limits` · `/rules` · `/rules/crs` · `/services`

### Static MPA Routing

The dashboard is an Astro `output: "static"` multi-page application (MPA), **not** an SPA.
Each page is a pre-rendered HTML file (`<route>/index.html`). The dashboard is served by
wafctl's `uiFileServer` (`ui_server.go`) which implements try_files semantics:

1. Serve the exact file if it exists (e.g. `/_astro/foo.js`)
2. Try `path/index.html` for directory-style routes (e.g. `/events` → `events/index.html`)
3. Return `404.html` with a 404 status for anything else

Caddy reverse-proxies all non-API paths to wafctl, which handles both API and UI serving.

There is intentionally **no** `/index.html` catch-all fallback — that is an SPA pattern
and would cause Web Cache Deception vulnerabilities (e.g., `/blocklist;test.png` would
serve authenticated HTML with `.png` cache headers).

A custom `src/pages/404.astro` generates `dist/404.html` for proper 404 responses.

## Content Security Policy (CSP) Management

Per-service CSP header management system. Follows the same pattern as rate limiting:
JSON store → Caddy config generator → file deploy → Caddy reload.

### Architecture

- **Store**: `csp.go` (~700 lines) — `CSPStore` with `sync.RWMutex`, CRUD, validation, header builder, merge logic, service discovery via `discoverCaddyfileServices()`, CSP deploy (policy engine only)
- **Handlers**: 4 HTTP endpoints under `/api/csp` (get, update, deploy, preview)
- **CLI**: `wafctl csp` subcommands (get, set, deploy, preview)
- **Frontend**: `CSPPanel.tsx` (~420 lines) orchestrator + `csp/` subdir (constants, CSPSourceInput, DirectiveEditor, PreviewPanel)

### Data Model

```
CSPConfig {
  enabled *bool           // nil = true; global kill switch
  global_defaults CSPPolicy
  services map[string]CSPServiceConfig
}

CSPServiceConfig {
  mode string             // "set", "default", "none"
  report_only bool        // Content-Security-Policy-Report-Only
  inherit bool            // merge on top of global_defaults
  policy CSPPolicy
}

CSPPolicy {
  default_src, script_src, style_src, img_src, font_src, connect_src,
  media_src, frame_src, worker_src, object_src, child_src, manifest_src,
  base_uri, form_action, frame_ancestors []string
  upgrade_insecure_requests bool
  raw_directives string   // verbatim escape hatch
}
```

### CSP Modes

| Mode | Caddy Syntax | Behavior |
|------|-------------|----------|
| `set` | `header Content-Security-Policy "..."` | Always set (overwrite upstream) |
| `default` | `header ?Content-Security-Policy "..."` | Only set if upstream didn't send one |
| `none` | Comment-only file | No CSP header emitted for this service |

### Global Enable/Disable

`CSPConfig.Enabled` is a `*bool` (nil = true for backward compatibility). When `false`:
- Generator writes comment-only placeholder files for all services
- Preview endpoint returns empty services map
- Config is preserved — re-enabling restores all policies
- Does NOT affect CSP headers set by upstream applications themselves

### FQDN Propagation

Each Caddyfile service block has two CSP import lines (short name + FQDN):
```
import /data/caddy/csp/httpbun_csp*.caddy
import /data/caddy/csp/httpbun.erfi.io_csp*.caddy
```

When a service has an explicit override (e.g., `httpbun`), the generator propagates
it to the FQDN variant (`httpbun.erfi.io`) via `findParentServiceConfig()`. Without
this, the FQDN file would get global defaults and overwrite the short-name override
(Caddy processes imports sequentially).

### Merge Behavior (inherit: true)

Non-empty override directive slices replace the base; empty slices keep the base.
`upgrade_insecure_requests` is sticky (true in base or override → true in result).

### Directory Layout

| Aspect | Pattern |
|--------|---------|
| Store file | `/data/csp-config.json` (`WAF_CSP_FILE`) |
| Delivery | Policy engine plugin `response_headers.csp` (no `.caddy` files) |
| Deploy | `POST /api/csp/deploy` writes to `policy-rules.json` |

### Nonce Limitations

Nonces are not supported — Caddy reverse proxy doesn't control HTML body. `style-src 'unsafe-inline'`
is unavoidable (Radix UI injects `<style>` tags). `script-src 'unsafe-inline'` needed for most
proxied apps and Astro hydration.

## Managed Lists

Reusable named lists of values (IPs, paths, user agents, etc.) that can be referenced
by WAF exclusion and rate limit conditions via `in_list` / `not_in_list` operators.
Follows the same store → generator → deploy pattern as other subsystems.

### Architecture

- **Store**: `managed_lists.go` — `ManagedListStore` with `sync.RWMutex`, CRUD, validation, persistence
- **Models**: `models_lists.go` — `ManagedList` type (id, name, description, type, items, tags, enabled, timestamps)
- **Handlers**: `handlers_lists.go` — 5 HTTP endpoints under `/api/lists` (CRUD)
- **CLI**: `wafctl lists` subcommands (list, get, create, delete)
- **Frontend**: `ManagedListsPanel.tsx` — full CRUD UI with search, inline editing, import/export
- **Generator integration**: `policy_generator.go` resolves `in_list`/`not_in_list` references at generation time

### Data Model

```
ManagedList {
  id, name, description, type, items[], tags[], enabled, created_at, updated_at
}
```

List types: `ip`, `path`, `user_agent`, `header`, `country`, `generic`.
Items are validated per type (e.g., CIDR validation for `ip` lists).

### Condition Integration

The `in_list` and `not_in_list` operators reference a list by ID. The value field
contains the list ID. At generation time:
- **Policy engine plugin**: `resolveListConditions()` (v0.3.0+) expands list items into `in` operator conditions

### Directory Layout

| Aspect | Pattern |
|--------|---------|
| Store file | `/data/lists.json` (`WAF_MANAGED_LISTS_FILE`) |
| Output dir | `/data/lists/` (`WAF_MANAGED_LISTS_DIR`) |
| File naming | `<list-id>.list` (one file per list, items newline-separated) |

## Event Tags & Classification

Events use a tag-based classification system instead of hardcoded event types.
The `Event.Tags` field (string array) enables flexible, extensible categorization.

### Event Types

| Type | Description |
|------|-------------|
| `detect_block` | CRS anomaly threshold exceeded (policy engine detect action) |
| `logged` | CRS detected but below threshold (detection-only mode) |
| `rate_limited` | Rate limited (429) or blocklist-blocked |
| `policy_skip` | Policy engine skipped specific CRS rules |
| `policy_allow` | Policy engine allowed (WAF bypassed) |
| `policy_block` | Policy engine blocked (403 from plugin) |

### Policy Event Breakdown (Summary API)

The `/api/summary` response splits policy events into three granular sub-types instead
of a single aggregate. This applies to all aggregation levels:

| Go Field | JSON Key | Frontend Field | Description |
|----------|----------|----------------|-------------|
| `PolicyBlocked` | `policy_blocked` | `policyBlocked` | Top-level count of policy engine blocks |
| `PolicyAllowed` | `policy_allowed` | `policyAllowed` | Top-level count of policy engine allows |
| `PolicySkipped` | `policy_skipped` | `policySkipped` | Top-level count of policy engine skips |
| `PolicyBlock` | `policy_block` | `policyBlock` | Per-hour/service/client breakdown |
| `PolicyAllow` | `policy_allow` | `policyAllow` | Per-hour/service/client breakdown |
| `PolicySkip` | `policy_skip` | `policySkip` | Per-hour/service/client breakdown |

Affected Go types: `SummaryResponse`, `HourCount`, `ServiceCount`, `ClientCount`, `ServiceDetail`.
Frontend types: `TimelinePoint`, `ServiceStat`, `ClientStat`, `ServiceBreakdown`, `ServiceDetail`,
`SummaryData`. Color mapping: `policy_block` (rose-500), `policy_allow` (emerald-500),
`policy_skip` (emerald-400).

### Tag Conventions

Tags are lowercase alphanumeric + hyphens (`^[a-z0-9][a-z0-9-]*$`), max 10 per rule/event,
max 50 chars each. Common tags:
- `honeypot` — honeypot path traps (on `block` type exclusions)
- `scanner`, `bot-detection` — scanner UA detection rules
- `bot-signal`, `protocol`, `generic-ua` — heuristic bot signal rules
- `blocklist`, `ipsum` — IPsum blocklist blocks

### Summary Tag Counts

The `/api/summary` response includes a `tag_counts` array with `{tag, count}` pairs
aggregated across all events in the time window. The dashboard renders tag-based stat
cards dynamically instead of hardcoded honeypot/scanner/ipsum counters.

### Store Migrations

All exclusion store migrations (v0→v6) have been removed — production is at v6, fresh
installs start empty. No migration code remains.

## API Endpoints (wafctl)

| Group | Routes |
|-------|--------|
| Core | `GET /api/health`, `GET /api/summary`, `GET /api/events`, `GET /api/services` |
| Analytics | `GET /api/analytics/top-ips`, `GET /api/analytics/top-uris`, `GET /api/analytics/top-countries` |
| IP Lookup | `GET /api/lookup/{ip}` |
| Exclusions | `GET\|POST /api/exclusions`, `GET\|PUT\|DELETE /api/exclusions/{id}` |
| Exclusion ops | `GET /api/exclusions/export`, `POST /api/exclusions/import`, `POST /api/exclusions/generate`, `GET /api/exclusions/hits`, `PUT /api/exclusions/reorder` |
| CRS | `GET /api/crs/rules` |
| Config | `GET\|PUT /api/config`, `POST /api/config/generate`, `POST /api/config/validate`, `POST /api/config/deploy` |
| RL Rules | `GET\|POST /api/rate-rules`, `GET\|PUT\|DELETE /api/rate-rules/{id}` |
| RL Rule ops | `POST /api/rate-rules/deploy`, `GET\|PUT /api/rate-rules/global`, `GET /api/rate-rules/export`, `POST /api/rate-rules/import`, `GET /api/rate-rules/hits`, `PUT /api/rate-rules/reorder` |
| RL Advisor | `GET /api/rate-rules/advisor?window=&service=&path=&method=&limit=` |
| RL Analytics | `GET /api/rate-limits/summary`, `GET /api/rate-limits/events` |
| Managed Lists | `GET\|POST /api/lists`, `GET\|PUT\|DELETE /api/lists/{id}` |
| CSP | `GET\|PUT /api/csp`, `POST /api/csp/deploy`, `GET /api/csp/preview` |
| Security Headers | `GET\|PUT /api/security-headers`, `POST /api/security-headers/deploy`, `GET /api/security-headers/preview`, `GET /api/security-headers/profiles` |
| General Logs | `GET /api/logs`, `GET /api/logs/summary` |
| CF Proxy | `GET /api/cfproxy/stats`, `POST /api/cfproxy/refresh` |
| Blocklist | `GET /api/blocklist/stats`, `GET /api/blocklist/check/{ip}`, `POST /api/blocklist/refresh` |

## Caddy Body Matcher Plugin (github.com/erfianugrah/caddy-body-matcher)

Custom Caddy HTTP request body plugin with two modules:
- **Matcher** — `http.matchers.body`: inspects request body for matching
- **Handler** — `http.handlers.body_vars`: extracts body field values as Caddy placeholders

Zero external dependencies beyond Caddy itself.

### Match Types (http.matchers.body)

| Category | Caddyfile Syntax | Description |
|----------|-----------------|-------------|
| Raw contains | `body contains "string"` | Substring match |
| Raw equals | `body eq "string"` | Exact match |
| Raw prefix | `body starts_with "string"` | Prefix match |
| Raw suffix | `body ends_with "string"` | Suffix match |
| Raw regex | `body regex "pattern"` | RE2 regex match |
| JSON field eq | `body json .path "value"` | JSON dot-path exact match |
| JSON field contains | `body json_contains .path "value"` | JSON dot-path substring match |
| JSON field regex | `body json_regex .path "pattern"` | JSON dot-path regex match |
| JSON field exists | `body json_exists .path` | JSON field presence check |
| Form field eq | `body form field "value"` | URL-encoded form field exact match |
| Form field contains | `body form_contains field "value"` | Form field substring match |
| Form field regex | `body form_regex field "pattern"` | Form field regex match |

### Body Vars Handler (http.handlers.body_vars)

Middleware handler that reads the request body, extracts configured JSON and form
field values, and exposes them as Caddy variables (placeholders). Enables body field
values to be used as rate limit keys, in log templates, policy engine conditions, or any
Caddy directive that supports placeholders.

**Exposed placeholders:**
- `{http.vars.body_json.<dotpath>}` — value from a JSON body field
- `{http.vars.body_form.<field>}` — value from a form-encoded field

**Caddyfile syntax:**
```
body_vars {
    json .user.api_key
    json .tenant.id
    form action
    form token
    max_size 13mb
}
```

**Single-field shorthand:**
```
body_vars json .user.api_key
body_vars form action
```

**Auto-generated by wafctl:** When a rate limit rule uses a `body_json:` or `body_form:` key,
`policy_generator.go` emits the corresponding body field conditions in the policy rule.
The policy engine plugin reads the request body lazily when conditions require it.

### Design

- **One match type per instance** — compose multiple via Caddy named matcher blocks
- **Body buffering** — reads once via `io.LimitReader`, re-wraps `r.Body` with `io.MultiReader` so downstream handlers still see the full body
- **Default max_size: 13 MiB** — configurable via `max_size` directive
- **JSON path resolution** — dot-notation via `encoding/json` → `map[string]interface{}`, array indices as numeric segments (e.g., `.items.0.type`)
- **Block syntax** for max_size override:
  ```
  body {
      max_size 13mb
      contains "search term"
  }
  ```
- **External GitHub repo** — fetched by xcaddy via `--with github.com/erfianugrah/caddy-body-matcher@v0.1.0`; tagged releases

## Caddy Policy Engine Plugin (github.com/erfianugrah/caddy-policy-engine)

Custom Caddy HTTP middleware that evaluates allow/block/honeypot/rate_limit rules with
correct matching semantics. The `in` operator uses `map[string]bool` hash sets for O(1) exact
lookup, preventing substring false positives (e.g., `/admin` does not match `/administrator`).

Also provides sliding window rate limiting (v0.5.0+) as a `rate_limit` rule type,
eliminating the need for Caddyfile generation + Caddy reload for rate limit changes.
Counter state is preserved across hot-reloads.

Zero external dependencies beyond Caddy itself. Registered as `http.handlers.policy_engine`.

### Architecture

- **Rules file**: JSON file (`policy-rules.json`) containing an array of `PolicyRule` objects
- **Hot reload**: Polls rules file mtime at configurable interval (default 5s); reloads on change
- **Graceful degradation**: Missing file at startup = empty rules (pass-through); invalid JSON on reload keeps old rules; file deletion clears rules
- **Concurrency**: `sync.RWMutex` for rule access; `*sync.RWMutex` stored as pointer to avoid `go vet` copy warning on `CaddyModule()` value receiver
- **Caddy integration**: Implements `Module`, `Provisioner`, `Validator`, `CleanerUpper`, `MiddlewareHandler`, `Unmarshaler`

### Actions

| Action | Behavior | Caddy Variables/Headers |
|--------|----------|------------------------|
| `allow` | Set vars, pass to next handler | `{http.vars.policy_engine.action}=allow`, `{http.vars.policy_engine.rule_id}`, `{http.vars.policy_engine.rule_name}` |
| `block` | Set vars, return 403 via `caddyhttp.Error` | `{http.vars.policy_engine.action}=block`, `{http.vars.policy_engine.rule_id}`, `{http.vars.policy_engine.rule_name}`, `{http.vars.policy_engine.tags}`, `X-Blocked-By: policy-engine`, `X-Blocked-Rule: <name>` |
| `honeypot` | Set vars, return 403 via `caddyhttp.Error` | `{http.vars.policy_engine.action}=honeypot`, `{http.vars.policy_engine.rule_id}`, `{http.vars.policy_engine.rule_name}`, `{http.vars.policy_engine.tags}`, `X-Blocked-By: policy-engine`, `X-Blocked-Rule: <name>` |
| `rate_limit` | Sliding window counter, 429 when exceeded | `{http.vars.policy_engine.action}=rate_limit`, `X-RateLimit-Limit/Remaining/Reset/Policy`, `Retry-After` |
| `rate_limit` (log_only) | Monitor mode, set headers but don't block | `{http.vars.policy_engine.action}=rate_limit_monitor`, `X-RateLimit-Monitor: <name>` |

### Rate Limiting (v0.5.0+)

Sliding window counter rate limiting using fixed-window interpolation (same algorithm
as nginx/envoy/cloudflare): `effectiveCount = prevCount × (1 - elapsed/window) + currCount`.

- **Counter storage**: 16-shard concurrent map (reduces lock contention)
- **Key resolution**: Direct from `http.Request` — `client_ip`, `path`, `static`, compound keys (`client_ip+path`, `client_ip+method`), `header:<Name>`, `cookie:<Name>`, `body_json:<DotPath>`, `body_form:<Field>`
- **Counter preservation**: Zones with unchanged config (same events+window) keep counters across hot-reload
- **Sweep goroutine**: Evicts expired counters at configurable interval (default 30s)
- **Service matching**: Via `service` field (matches Host header; `""` or `"*"` matches all)
- **Actions**: `deny` (429 + Retry-After with jitter) or `log_only` (headers only, no block)
- **Global config**: `rate_limit_config` in `PolicyRulesFile` for `sweep_interval` and `jitter`

### Condition Matching

Supports all request-phase fields: `ip`, `path`, `uri_path`, `host`, `method`, `user_agent`,
`header`, `cookie`, `args`, `query`, `country`, `referer`, `http_version`, `body`, `body_json`,
`body_form`.

All operators: `eq`, `neq`, `contains`, `begins_with`, `ends_with`, `regex`, `ip_match`,
`not_ip_match`, `in`, `exists`. Named fields use `Name:value` format (same as wafctl conventions).

**Critical security fix**: `in` operator uses `map[string]bool` hash set for O(1) exact
lookup instead of substring matching.

### Body Field Support

- **Lazy body reading**: Only reads request body when a rule needs it (`needsBody` flag set at compile time)
- **Body re-wrap**: Uses `io.LimitReader` + `io.MultiReader` so downstream handlers still see the full body
- **Default max size**: 13 MiB (matches WAF `request_body_limit`), configurable via `body_max_size`
- **`body`**: Raw request body matching (eq, contains, begins_with, ends_with, regex)
- **`body_json`**: JSON dot-path resolution via `resolveJSONPath()` — walks nested objects/arrays (e.g., `.user.roles.0`). Supports `exists` operator for field presence checks
- **`body_form`**: URL-encoded form field extraction via `url.ParseQuery()` — first value for multi-valued fields
- **`exists` operator**: Checks JSON field presence without value comparison (`extractFieldExists()`)
- `jsonValueToString()` handles all JSON types: strings, floats (integers render without decimals), bools, null, arrays/objects
- **Multi-reader memory impact**: If a request hits the policy engine (body condition) and a rate limit rule (body matcher), the body is read and buffered twice. Each reader re-wraps `r.Body` with `io.MultiReader` so downstream handlers can re-read. Memory: one copy per reader, up to 13 MiB each.

### Caddyfile Integration

```
order policy_engine first
```

The `(waf)` snippet runs the policy engine as the sole WAF:
```
policy_engine {
    rules_file /data/caddy/policy-rules.json
    reload_interval 5s
    body_max_size 13mb
}
```

The policy engine handles all rule evaluation — allow, block, detect (CRS anomaly scoring),
and rate limiting. Coraza has been removed entirely.

### wafctl Integration

- `policy_generator.go` generates `policy-rules.json` from exclusions (allow/block/detect) and rate limit rules
- `GeneratePolicyRulesWithRL()` merges WAF exclusions + RL rules into a single rules array with priority bands: block(100) < allow(200) < rate_limit(300). Accepts a `serviceMap` parameter for FQDN resolution.
- `IsPolicyEngineType()` checks if an exclusion type is handled by the plugin
- `splitHoneypotPaths()` expands honeypot rules (which consolidate multiple paths) into individual path conditions (unexported, test-only)
- Both `generateOnBoot()` and `handleDeploy()` call the policy generator, including RL rules
- `handleDeployRLRules()` writes to `policy-rules.json` (no Caddy restart needed — plugin hot-reloads)
- `validPolicyEngineFields` map in `models_exclusions.go` — same as RL fields + `args`, excludes `response_header` and `response_status`

### Service FQDN Resolution

The policy engine plugin's `matchService()` compares the rule's `service` field against
`r.Host` (the HTTP Host header, stripped of port) using `strings.EqualFold`. In production,
Host headers are FQDNs (e.g., `httpbun.erfi.io`), but exclusions and rate limit rules store
short service names (e.g., `httpbun`). Without resolution, rules would never match.

- `BuildServiceFQDNMap(caddyfilePath string) map[string]string` — parses the Caddyfile to
  build a `shortname → fqdn` mapping. Uses `siteBlockPattern` regex to extract the site block
  label (e.g., `httpbun.erfi.io`) and the `site_log` directive argument (e.g., `httpbun`).
  Maps both directions: `httpbun → httpbun.erfi.io` and `httpbun.erfi.io → httpbun.erfi.io`.
- `resolveServiceName(service string, serviceMap map[string]string) string` — looks up a
  service name in the map. Returns the FQDN if found, or the original name if not (safe
  pass-through for services not in the Caddyfile or already FQDNs).
- Called at 5 sites: `generateOnBoot()`, `handleDeploy()` (WAF deploy), `handleDeploy()`
  (config deploy), `handleDeployRLRules()`, and inline in `handleConfigDeploy()`.
- Each call site builds the map fresh from `WAF_CADDYFILE_PATH` before passing to
  `GeneratePolicyRulesWithRL()`. This ensures changes to the Caddyfile are picked up
  without restarting wafctl.

### Plugin Test Suite (396 tests)

In the plugin repo (`/home/erfi/caddy-policy-engine`):
- Condition matching tests for every operator and field type
- `TestCondition_In_NotSubstring` — verifies the core security fix
- Rule evaluation: AND/OR groups, disabled rules, priority ordering
- Action tests: block headers, allow vars, honeypot behavior
- Hot reload: file change detection, invalid JSON recovery, file deletion
- Concurrent reads under `sync.RWMutex`
- Body field tests: body, body_json (dot-path, exists, nested), body_form
- `needsBody` flag compilation, `readBody` re-wrap, `parseSize` helper
- `resolveJSONPath` edge cases, `jsonValueToString` type handling
- Rate limit tests: sliding window, key resolution, config compilation, window parsing, zone management, service matching, ServeHTTP integration (deny/log_only/conditions/tags), hot reload with RL rules, block+rate_limit coexistence

## Test Patterns

### Go (1082 tests across 25 files)
- Tests split into domain-specific files: `logparser_test.go`, `exclusions_test.go`, `config_test.go`, `deploy_test.go`, `geoip_test.go`, `blocklist_test.go`, `rl_analytics_test.go`, `rl_advisor_test.go`, `rl_rules_test.go`, `rl_handlers_test.go`, `crs_rules_test.go`, `csp_test.go`, `handlers_test.go`, `cli_test.go`, `cfproxy_test.go`, `default_rules_test.go`, `general_logs_test.go`, `ip_intel_test.go`, `tls_helpers_test.go`, `policy_generator_test.go`, `managed_lists_test.go`, `security_headers_test.go`, `backup_test.go`, `ui_server_test.go`, `testhelpers_test.go`
- All `package main` (whitebox)
- Table-driven tests with `t.Run()` subtests
- `httptest.NewRequest` + `httptest.NewRecorder` for handler tests
- `httptest.NewServer` to mock the Caddy admin API
- Temp file helpers in `testhelpers_test.go`: `writeTempLog`, `newTestExclusionStore`, `newTestConfigStore`, `emptyAccessLogStore`, `writeTempAccessLog`
- `handlers_test.go` covers operator-aware filtering (`fieldFilter`/`matchField` unit tests + handler integration tests)

### Frontend (322 tests across 17 files)
- Vitest with `vi.fn()` mock fetch, `describe`/`it` blocks
- `beforeEach`/`afterEach` for setup/teardown
- API tests split by domain in `src/lib/api/`: `waf-events.test.ts` (33), `rate-limits.test.ts` (31), `default-rules.test.ts` (17), `managed-lists.test.ts` (14), `general-logs.test.ts` (13), `exclusions.test.ts` (13), `analytics.test.ts` (13), `security-headers.test.ts` (11), `config.test.ts` (9), `backup.test.ts` (9), `blocklist.test.ts` (6), `shared.test.ts` (3)
- Component tests: `DashboardFilterBar.test.ts` (63)
- Policy sub-module tests in `components/policy/`: `constants.test.ts` (33), `exclusionHelpers.test.ts` (38), `eventPrefill.test.ts` (24), `TagInputs.test.ts` (19)

### Error Pages

The `(waf)` snippet includes `handle_errors 400 403 429` which serves `errors/error.html`
via Caddy's `templates` + `file_server`. The `(error_pages)` snippet catches remaining
error codes (404, 500, 502, etc.). The template uses `{placeholder "http.error.status_code"}`
for conditional content (different messages per status code). `file_server` inside
`handle_errors` preserves the error's HTTP status code via `statusOverrideResponseWriter`.

## Key Architecture Notes

- The wafctl sidecar reads Caddy access logs incrementally (Coraza audit logs removed)
- Policy engine rules are written to `policy-rules.json` and hot-reloaded by the plugin (no Caddy restart)
- Deploy pipeline: generate config → write `policy-rules.json` → plugin detects mtime change → reload rules
- Caddy reload uses `Cache-Control: must-revalidate` header to force re-provision even
  when the Caddyfile-adapted JSON is byte-identical (Caddy strips comments during
  adaptation, so the fingerprint comment alone cannot force a reload)
- `.env` contains secrets (`CF_API_TOKEN`, `EMAIL`) — never commit this file unencrypted
- Makefile supports `.env.mk` overrides and `REMOTE=host` inline overrides
- Two deploy modes in Makefile: `dockge` (via dockge container) or `compose` (direct)

### Dynamic vs Baked-in Config

Files baked into the Caddy image at build time (in `/etc/caddy/`):
- `cf_trusted_proxies.caddy` — Cloudflare IP ranges
- `errors/error.html` — custom error page template

Files baked into the wafctl image at build time:
- `/app/waf-ui/` — dashboard static files (Astro MPA build output)
- `/etc/caddy/waf/default-rules.json` — CRS default rules

Files written at runtime by wafctl (in `/data/caddy/` volumes):
- `policy-rules.json` — policy engine plugin rules (WAF exclusions + rate limits + CSP + security headers)
- `<list-id>.list` — managed list files (one per list, newline-separated items)

### Startup Behavior (generate-on-boot)

On startup, wafctl calls `generateOnBoot()` which regenerates all config files
from stored JSON state (WAF config, exclusions, rate limit rules, CSP). This ensures a
stack restart always picks up the latest generator output without requiring a
manual `POST /api/config/deploy`. No Caddy reload is performed — Caddy reads
the files fresh on its own startup.

The blocklist store calls `loadFromLists()` on boot to populate its in-memory IP set
from the ipsum managed lists. IPsum blocking is handled by the policy engine plugin
via 8 per-level block rules (seeded by v2→v3 exclusion migration).

### JSONL Event Persistence

Parsed events are persisted to JSONL files so they survive wafctl restarts
without re-parsing the raw audit/access logs. On startup, `SetEventFile()`
restores events from JSONL before tailing begins.

- WAF events: `/data/events.jsonl` — large payload fields (`RequestHeaders`,
  `RequestBody`, `RequestArgs`) are stripped when persisting to keep the file compact
- Access log events: `/data/access-events.jsonl` — rate limit and policy engine block events
- Compaction runs synchronously after eviction via `compactEventFileLocked()` (caller holds lock); `compactEventFile()` wrapper acquires its own lock for external callers
- At ~400 WAF events/day and 90-day retention: ~36,000 events, ~36MB on disk

### Access Log Event Classification

The `AccessLogStore` (`access_log_store.go`) parses Caddy access logs for security events:
- 429 responses → `rate_limited` events
- 403 responses with policy engine vars → `policy_block` events
- Policy engine detect actions with score above threshold → `detect_block` events
- Policy engine detect actions below threshold → `logged` events

**Policy engine block detection** uses a two-tier approach for HTTP/2 compatibility:

1. **Primary**: Read `policy_action` and `policy_rule` fields from Caddy `log_append` directives (case-safe, set as Caddy variables by the plugin v0.4.1+)
2. **Fallback**: Case-insensitive header lookup for `X-Blocked-By: policy-engine` and `X-Blocked-Rule` (defense in depth for older plugin versions)

This two-tier approach was necessary because HTTP/2 lowercases all header names on the wire,
causing exact map lookups like `headers["X-Blocked-By"]` to silently fail when the actual key
is `"x-blocked-by"`. The `log_append` fields are set from Caddy variables (not headers) and
are always case-consistent.

**Policy engine rate limit detection** (v0.5.0+) uses the same two-tier approach:

1. **Primary**: `policy_action == "rate_limit"` from `log_append` field
2. **Fallback**: `X-RateLimit-Policy` response header presence (set by policy engine)

Rate limit events from the policy engine carry direct rule name attribution via
`policy_rule` field (or `X-RateLimit-Policy` header name extraction), eliminating
the need for heuristic condition-based matching (`matchEventToRuleTags`).

**Access log flow**: `AccessLogEntry` → classify as `isRateLimit` (429) or `isPolicy` (403 + policy detection) → further classify 429s as `isPolicyRateLimit` → `RateLimitEvent{Source: "policy_rl"|"policy"|""}` → `enrichAccessEvents()` (tag lookup from RL rules for `policy_rl`, exclusion store for `policy`, heuristic for legacy) → `RateLimitEventToEvent()` → unified `Event`

**Event sources**:
| Source | Status | EventType | Tag Enrichment |
|--------|--------|-----------|----------------|
| `""` | 429 | `rate_limited` | Heuristic `matchEventToRuleTags()` |
| `"policy_rl"` | 429 | `rate_limited` | Direct RL rule name lookup |
| `"policy"` | 403 | `policy_block` | Exclusion store name lookup |

**Helper functions**: `headerValuesCI()` / `headerValueCI()` for case-insensitive header lookups, `isPolicyBlocked(entry)` for block detection, `isPolicyRateLimit(entry)` for RL detection, `policyBlockedRuleName(entry)` / `policyRateLimitRuleName(entry)` for rule name extraction.

### Blocklist Refresh

`POST /api/blocklist/refresh` downloads a fresh IPsum list from GitHub, parses
IPs by threat score, syncs 8 per-level managed lists (`ipsum-level-1` through
`ipsum-level-8`) via the `onRefresh` callback, then calls `deployAll()` via the
`onDeploy` callback to regenerate policy engine rules and reload Caddy. The
in-memory IP set is rebuilt from the managed lists after sync.

### wafctl Environment Variables

All configurable via `envOr()` with sensible defaults:
- `WAFCTL_PORT` (default `8080`), `WAF_CORS_ORIGINS` (default `*`)
- `WAF_COMBINED_ACCESS_LOG` — log file path
- `WAF_EXCLUSIONS_FILE`, `WAF_CONFIG_FILE`, `WAF_RATELIMIT_FILE` — JSON store paths
- `WAF_CADDY_ADMIN_URL` (default `http://caddy:2019`) — Caddy admin API endpoint
- `WAF_AUDIT_OFFSET_FILE` (default `/data/.audit-log-offset`) — persists audit log read offset across restarts
- `WAF_ACCESS_OFFSET_FILE` (default `/data/.access-log-offset`) — persists access log read offset across restarts
- `WAF_EVENT_FILE` (default `/data/events.jsonl`) — JSONL persistence for WAF events
- `WAF_ACCESS_EVENT_FILE` (default `/data/access-events.jsonl`) — JSONL persistence for access log events
- `WAF_EVENT_MAX_AGE` (default `2160h`), `WAF_TAIL_INTERVAL` (default `5s`)
- `WAF_GEOIP_DB` (default `/data/geoip/country.mmdb`) — path to DB-IP/MaxMind MMDB file
- `WAF_GEOIP_API_URL` (default empty = disabled) — online GeoIP API URL (e.g., `https://ipinfo.io/%s/json`); `%s` is replaced with IP, or IP is appended as path segment
- `WAF_GEOIP_API_KEY` (default empty) — API key sent as Bearer token for online GeoIP lookups
- `WAF_CADDYFILE_PATH` (default `/data/Caddyfile`) — path to the Caddyfile used for RL auto-discovery
- `WAF_CSP_FILE` (default `/data/csp-config.json`) — CSP configuration store path
- `WAF_CSP_DIR` (default `/data/csp/`) — output directory for generated CSP config files
- `WAF_GENERAL_LOG_FILE` (default `/data/general-events.jsonl`) — JSONL persistence for general log events
- `WAF_GENERAL_LOG_OFFSET_FILE` (default `/data/.general-log-offset`) — persists general log read offset across restarts
- `WAF_GENERAL_LOG_MAX_AGE` (default `168h`) — retention period for general log events (shorter than WAF events due to higher volume)
- `WAF_BLOCKLIST_REFRESH_HOUR` (default `6`) — UTC hour (0–23) for daily IPsum blocklist refresh
- `WAF_MANAGED_LISTS_FILE` (default `/data/lists.json`) — managed lists store path
- `WAF_MANAGED_LISTS_DIR` (default `/data/lists`) — output directory for managed list files (one `.list` file per list)
- `WAF_SECURITY_HEADERS_FILE` (default `/data/security-headers.json`) — security headers configuration store path
- `WAF_POLICY_RULES_FILE` (default `/data/coraza/policy-rules.json`) — output path for the policy engine plugin's rules JSON file

### CLI Subcommands

wafctl is both an HTTP server and a CLI tool. When run without arguments (or
with `serve`), it starts the API server. All other commands are CLI clients
that talk to a running wafctl instance via HTTP.

```
wafctl              # Start HTTP server (default)
wafctl serve        # Same as above
wafctl version      # Print version
wafctl health       # Check server health
wafctl config get   # Show WAF configuration
wafctl config set   # Update config (JSON on stdin or --file)
wafctl rules list   # List policy exclusion rules
wafctl rules get ID # Get rule by ID
wafctl rules create # Create rule (JSON on stdin or --file)
wafctl rules delete ID
wafctl deploy       # Deploy WAF config to Caddy
wafctl events       # List events (--hours, --limit, --service, --type, --client, --method, --rule)
wafctl ratelimit list       # List all rate limit rules (alias: rl)
wafctl ratelimit get ID     # Get a rate limit rule by ID
wafctl ratelimit create     # Create rule (JSON on stdin or --file)
wafctl ratelimit delete ID  # Delete a rate limit rule
wafctl ratelimit deploy     # Deploy rate limit configs to Caddy
wafctl ratelimit global     # Show global rate limit settings
wafctl csp get              # Show CSP configuration
wafctl csp set              # Update config (JSON on stdin or --file)
wafctl csp deploy           # Deploy CSP configs to Caddy
wafctl csp preview          # Preview rendered CSP headers per service
wafctl lists list            # List all managed lists (alias: ls)
wafctl lists get ID          # Get a managed list by ID
wafctl lists create          # Create list (JSON on stdin or --file)
wafctl lists delete ID       # Delete a managed list
wafctl blocklist stats
wafctl blocklist check IP
wafctl blocklist refresh
```

Global flags: `--addr` (API address, default from `WAFCTL_ADDR` or `http://localhost:$WAFCTL_PORT`), `--json` (raw JSON output), `--file`/`-f` (read input from file instead of stdin).

### Related projects

A parallel implementation of the same security concepts exists as a Traefik middleware
plugin for Kubernetes (heuristic bot scoring, expression-based firewall rules, IPsum
CronJob, Go SSR dashboard). Both projects share architectural patterns: `envOr()`,
`sync.RWMutex` stores, section header style, atomic file ops, scanner UA lists,
honeypot path concept, IP resolution from proxy headers.
