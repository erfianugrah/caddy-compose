# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

Docker Compose infrastructure for a Caddy reverse proxy with Coraza WAF (OWASP CRS),
Authelia 2FA forward auth, and a custom WAF management sidecar. Two codebases live here:

- **wafctl/** — Go HTTP service + CLI tool (stdlib only, zero external deps, Go 1.24+)
- **waf-dashboard/** — Astro 5 + React 19 + TypeScript 5.7 frontend (shadcn/ui, Tailwind CSS 4)
- Root level: Caddyfile, Dockerfile (6-stage multi-stage), compose.yaml, Makefile

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
cd wafctl && CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=1.2.0" -o wafctl .
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

Image tags live in **five places** that must stay in sync:
- `Makefile` (lines 17-18: `CADDY_IMAGE`, `WAFCTL_IMAGE`)
- `compose.yaml` (lines 3 and 117: image fields)
- `README.md` (badge/reference)
- `test/docker-compose.test.yml` (line 3: caddy image field)
- `.github/workflows/build.yml` (env block: `CADDY_TAG`, `WAFCTL_VERSION`)

Caddy tag format: `<project-version>-<caddy-version>` (e.g. `2.2.0-2.11.1`).
wafctl tag format: simple semver (e.g. `1.2.0`).

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
- Server timeouts: `ReadTimeout: 10s`, `WriteTimeout: 150s`, `IdleTimeout: 60s`
- Caddy reload client timeout: `120s` (accounts for WAF rule initialization)
- Makefile deploy wget timeout: `120s` (`-T 120`)

### Query Filter System

- `fieldFilter` type with `parseFieldFilter(value, op)` and `matchField(target)` method
- Operators: `eq` (default), `neq`, `contains`, `in` (comma-separated), `regex` (Go RE2)
- Query param format: `<field>=<value>&<field>_op=<operator>` — backward compatible (no `_op` = `eq`)
- Used by `handleSummary` and `handleEvents` for: `service`, `client`, `method`, `event_type`, `rule_name`
- When any filter is active on `/api/summary`, all events (WAF + RL) are collected, filtered, then re-summarized via `summarizeEvents()`

### Concurrency

- `sync.RWMutex` on all stores; `RLock` for reads, `Lock` for mutations
- `atomic.Int64` for lock-free offset tracking (`Store.offset` in logparser.go)
- `atomic.Bool` for lock-free guard flags (`BlocklistStore.refreshing`)
- Return deep copies from getters to prevent concurrent modification

### SecRule Injection Hardening

- `escapeSecRuleValue()` — escapes `\`, `"`, `'`, strips `\n`/`\r` for SecRule pattern/action values
- `sanitizeComment()` — replaces newlines with spaces for `msg:` and comment fields
- Input validation regexps in `exclusions.go`: `ruleTagRe` (CRS tag format), `variableRe` (SecRule variable names), `namedFieldNameRe` (header/cookie/args names)
- `validateExclusion()` rejects newlines in all string fields, validates condition operators/fields against allowlists
- `validateConditions()` — shared condition validation function used by both WAF exclusions and RL rules

### File Operations and Code Organization

- Atomic writes via `atomicWriteFile()` — write to temp, fsync, rename
- Incremental file reading with offset tracking and rotation detection
- Section headers: `// --- Section Name ---` or `// ─── Section Name ──────────`
- One cohesive module per `.go` file (logparser, generator, deploy, config, exclusions, geoip, blocklist, etc.)
- All data models in `models.go`; most HTTP handlers in `main.go`, domain-specific handlers co-located with their store (e.g. `blocklist.go` has `handleBlocklistStats`, `handleBlocklistRefresh`)
- `geoip.go` — pure-Go MMDB reader (ported from k3s Sentinel), GeoIP store with in-memory cache, CF header parser, online API fallback (configurable via `WAF_GEOIP_API_URL`)
- `blocklist.go` — IPsum blocklist file parser with `# Updated:` comment extraction and mtime fallback, cached stats/check, on-demand refresh (download + filter + atomic write + Caddy reload)
- `rl_rules.go` — Rate limit rule store with CRUD, validation, v1 migration, Caddyfile auto-discovery
- `rl_generator.go` — Rate limit Caddy config generator, condition→matcher translation, file writer
- `rl_analytics.go` — Rate limit analytics, condition-based rule attribution for 429 events
- `rl_advisor.go` — Rate limit advisor: traffic analysis, statistical anomaly detection (MAD, Fano factor, IQR), client classification, time-of-day baselines, 30s TTL caching

## Coraza Rule ID Namespaces

When adding custom SecRules, use the correct ID range:
- `9100001–9100006` — pre-CRS rules (baked in `coraza/pre-crs.conf`)
- `9100010–9100019` — post-CRS custom detection rules (baked in `coraza/post-crs.conf`)
- `9100020–9100029` — honeypot path rules (fully dynamic via Policy Engine; `9100021` generated in `custom-pre-crs.conf`)
- `9100030–9100039` — heuristic bot signal rules (baked in `coraza/pre-crs.conf`, scanner UAs in `coraza/scanner-useragents.txt`)
- `9100050–9100059` — GeoIP blocking rules (reserved; country blocking uses Policy Engine `95xxxxx` IDs via `REQUEST_HEADERS:Cf-Ipcountry`)
- `95xxxxx` — generated exclusion rules (from Policy Engine, `generator.go`)
- `97xxxxx` — generated WAF settings overrides (`generator.go`)
- CRS inbound: `910000–949999`, outbound: `950000–979999`
- Evaluation rules `949110`, `959100`, `980170` are excluded from scoring

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
| `allow` | `ctl:ruleEngine=Off` | Full WAF bypass for matching requests |
| `block` | `deny,status:403` | Deny matching requests |
| `skip_rule` | `ctl:ruleRemoveById` / `ByTag` | Skip specific CRS rules |
| `honeypot` | `deny,status:403` (consolidated `@pm`) | Dynamic honeypot path groups; all paths merged into one rule ID `9100021` |
| `raw` | Verbatim SecRule | Free-form SecRule directive |
| `remove_by_id`, `remove_by_tag` | Post-CRS removal | Configure-time exclusions |
| `update_target_by_id`, `update_target_by_tag` | Post-CRS target update | Exclude specific variables |
| `runtime_remove_by_id` | `ctl:ruleRemoveById` | Remove entire rule for matching requests |
| `runtime_remove_by_tag` | `ctl:ruleRemoveByTag` | Remove rule category for matching requests |
| `runtime_remove_target_by_id` | `ctl:ruleRemoveTargetById` | Exclude variable from specific rule for matching requests |
| `runtime_remove_target_by_tag` | `ctl:ruleRemoveTargetByTag` | Surgical: exclude variable from tag category for matching requests |

### Condition Fields

| Field | SecRule Variable | Operators |
|-------|-----------------|-----------|
| `ip` | `REMOTE_ADDR` | `eq`, `neq`, `ip_match`, `not_ip_match` |
| `path` | `REQUEST_URI` | `eq`, `neq`, `contains`, `begins_with`, `ends_with`, `regex`, `in` |
| `host` | `SERVER_NAME` | `eq`, `neq`, `contains` |
| `method` | `REQUEST_METHOD` | `eq`, `neq`, `in` |
| `user_agent` | `REQUEST_HEADERS:User-Agent` | `eq`, `contains`, `regex` |
| `header` | `REQUEST_HEADERS:<Name>` | `eq`, `contains`, `regex` |
| `query` | `QUERY_STRING` | `contains`, `regex` |
| `country` | `REQUEST_HEADERS:Cf-Ipcountry` | `eq`, `neq`, `in` |
| `cookie` | `REQUEST_COOKIES:<Name>` | `eq`, `neq`, `contains`, `regex` |
| `body` | `REQUEST_BODY` | `contains`, `regex` |
| `args` | `ARGS:<Name>` | `eq`, `neq`, `contains`, `regex` |
| `uri_path` | `REQUEST_FILENAME` | `eq`, `neq`, `contains`, `begins_with`, `ends_with`, `regex` |
| `referer` | `REQUEST_HEADERS:Referer` | `eq`, `neq`, `contains`, `regex` |
| `response_header` | `RESPONSE_HEADERS:<Name>` | `eq`, `contains`, `regex` |
| `response_status` | `RESPONSE_STATUS` | `eq`, `neq`, `in` |
| `http_version` | `REQUEST_PROTOCOL` | `eq`, `neq` |

Named fields (`header`, `cookie`, `args`, `response_header`) use `Name:value` format
in the value field — the name before `:` becomes the SecRule variable suffix, the
value after `:` is the match target. Without `:`, the entire collection is matched.

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
- **Generator**: `rl_generator.go` — translates rules into Caddy `rate_limit` plugin configs with named matchers
- **Analytics**: `rl_analytics.go` — condition-based inference to attribute 429 events to specific rules
- **Advisor**: `rl_advisor.go` — traffic analysis, anomaly detection, client classification, recommendations with impact curves and time-of-day baselines
- **Handlers**: 12 HTTP endpoints under `/api/rate-rules` (CRUD, deploy, global config, export/import, hits, advisor)
- **CLI**: `wafctl ratelimit` / `wafctl rl` subcommands (list, get, create, delete, deploy, global)
- **Frontend**: `RateLimitsPanel.tsx` (rules CRUD + global settings), `RateAdvisorPanel.tsx` (advisor UI), `AdvisorCharts.tsx` (visualization components)

### Rule Model

```
RateLimitRule {
  id, name, description, service, conditions[], group_operator,
  key, events, window, action, priority, enabled, created_at, updated_at
}
```

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

### Rate Limit Actions

| Action | Behavior |
|--------|----------|
| `deny` | Return 429 when rate exceeded (default) |
| `log_only` | Set `X-RateLimit-Monitor` header instead of blocking — uses Caddy named matcher + header directive, NOT a `rate_limit` block |

### RL Condition Fields (subset of WAF fields)

Request-phase only: `ip`, `path`, `host`, `method`, `user_agent`, `header`, `query`,
`country`, `cookie`, `uri_path`, `referer`, `http_version`. Response-phase fields
(`body`, `args`, `response_header`, `response_status`) are excluded.

`http_version` uses Caddy's `protocol` matcher. Values are normalized: `HTTP/2.0` → `http/2`,
but `HTTP/1.0` and `HTTP/1.1` keep their minor version (→ `http/1.0`, `http/1.1`).

### Global Config

`RateLimitGlobalConfig` controls jitter, sweep interval, and distributed RL settings
(read/write intervals, purge age). Stored alongside rules in the same JSON file.

### Caddyfile Generation

Each enabled rule generates a `<service>_rate_limit.caddy` file containing:
- Named matcher (`@rl_<zone>`) with conditions translated to Caddy matcher syntax
- `rate_limit` block with the configured key, events, window, and global settings
- For `log_only` rules: matcher + `header_up X-RateLimit-Monitor` instead of `rate_limit`
- Disabled rules generate comment-only files (no-op)
- Stale files for removed services are automatically cleaned up

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

**Frontend**: `RateAdvisorPanel.tsx` handles the form, client table with req/s columns, and recommendation cards. `AdvisorCharts.tsx` contains `ClassificationBadge`, `ConfidenceBadge`, `DistributionHistogram`, `ImpactCurve`, and `TimeOfDayChart` visualization components.

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

- Go returns `snake_case` JSON; the frontend `api.ts` maps it to `camelCase`
- Type-safe interfaces for all API responses
- When adding API endpoints, update both Go handler (`main.go`) and frontend client (`api.ts`)
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

`/` · `/analytics` · `/blocklist` · `/events` · `/policy` · `/rate-limits` · `/services` · `/settings`

## API Endpoints (wafctl)

| Group | Routes |
|-------|--------|
| Core | `GET /api/health`, `GET /api/summary`, `GET /api/events`, `GET /api/services` |
| Analytics | `GET /api/analytics/top-ips`, `GET /api/analytics/top-uris`, `GET /api/analytics/top-countries` |
| IP Lookup | `GET /api/lookup/{ip}` |
| Exclusions | `GET\|POST /api/exclusions`, `GET\|PUT\|DELETE /api/exclusions/{id}` |
| Exclusion ops | `GET /api/exclusions/export`, `POST /api/exclusions/import`, `POST /api/exclusions/generate`, `GET /api/exclusions/hits` |
| CRS | `GET /api/crs/rules`, `GET /api/crs/autocomplete` |
| Config | `GET\|PUT /api/config`, `POST /api/config/generate`, `POST /api/config/deploy` |
| RL Rules | `GET\|POST /api/rate-rules`, `GET\|PUT\|DELETE /api/rate-rules/{id}` |
| RL Rule ops | `POST /api/rate-rules/deploy`, `GET\|PUT /api/rate-rules/global`, `GET /api/rate-rules/export`, `POST /api/rate-rules/import`, `GET /api/rate-rules/hits` |
| RL Advisor | `GET /api/rate-rules/advisor?window=&service=&path=&method=&limit=` |
| RL Analytics | `GET /api/rate-limits/summary`, `GET /api/rate-limits/events` |
| Blocklist | `GET /api/blocklist/stats`, `GET /api/blocklist/check/{ip}`, `POST /api/blocklist/refresh` |

## Test Patterns

### Go (744 tests across 16 files)
- Tests split into domain-specific files: `logparser_test.go`, `exclusions_test.go`, `generator_test.go`, `config_test.go`, `deploy_test.go`, `geoip_test.go`, `blocklist_test.go`, `rl_analytics_test.go`, `rl_advisor_test.go`, `rl_rules_test.go`, `rl_generator_test.go`, `rl_handlers_test.go`, `crs_rules_test.go`, `handlers_test.go`, `cli_test.go`, `testhelpers_test.go`
- All `package main` (whitebox)
- Table-driven tests with `t.Run()` subtests
- `httptest.NewRequest` + `httptest.NewRecorder` for handler tests
- `httptest.NewServer` to mock the Caddy admin API
- Temp file helpers in `testhelpers_test.go`: `writeTempLog`, `newTestExclusionStore`, `newTestConfigStore`, `emptyAccessLogStore`, `writeTempAccessLog`, `writeTempBlocklist`
- `handlers_test.go` covers operator-aware filtering (`fieldFilter`/`matchField` unit tests + handler integration tests)

### Frontend (265 tests across 6 files)
- Vitest with `vi.fn()` mock fetch, `describe`/`it` blocks
- `beforeEach`/`afterEach` for setup/teardown
- Tests live alongside source: `api.test.ts` next to `api.ts`, `DashboardFilterBar.test.ts` next to component
- Policy sub-module tests in `components/policy/`: `constants.test.ts`, `eventPrefill.test.ts`, `exclusionHelpers.test.ts`, `TagInputs.test.ts`

## Key Architecture Notes

- The wafctl sidecar reads Coraza audit logs and Caddy access logs incrementally
- SecRule `.conf` files are generated and deployed to Caddy via its admin API
- Deploy pipeline: generate config → SHA-256 fingerprint → POST to Caddy admin → reload
- `.env` contains secrets (`CF_API_TOKEN`, `EMAIL`) — never commit this file unencrypted
- Makefile supports `.env.mk` overrides and `REMOTE=host` inline overrides
- Two deploy modes in Makefile: `dockge` (via dockge container) or `compose` (direct)

### Dynamic vs Baked-in Config

Files baked into the image at build time (in `/etc/caddy/`):
- `coraza/pre-crs.conf`, `coraza/post-crs.conf` — static WAF rules
- `ipsum_block.caddy` — IPsum blocklist snapshot (seeded to runtime volume on first boot or when `# Updated:` header is missing)
- `cf_trusted_proxies.caddy` — Cloudflare IP ranges
- `waf-ui/` — dashboard static files, `errors/error.html`

Files written at runtime by wafctl (in `/data/coraza/` and `/data/rl/` volumes):
- `custom-waf-settings.conf` — SecRuleEngine mode, paranoia levels, thresholds
- `custom-pre-crs.conf`, `custom-post-crs.conf` — policy engine exclusions
- `ipsum_block.caddy` — updated daily by cron at 02:00, or on-demand via `POST /api/blocklist/refresh`
- `<service>_rate_limit.caddy` — rate limit rule configs (condition-based)

### Startup Behavior (generate-on-boot)

On startup, wafctl calls `generateOnBoot()` which regenerates all config files
from stored JSON state (WAF config, exclusions, rate limit rules). This ensures a
stack restart always picks up the latest generator output without requiring a
manual `POST /api/config/deploy`. No Caddy reload is performed — Caddy reads
the files fresh on its own startup.

The entrypoint (`scripts/entrypoint.sh`) also re-seeds the ipsum blocklist from
the build-time snapshot if the runtime file is missing OR lacks the `# Updated:`
header (which older builds didn't include).

### Audit Log Rotation

Coraza writes directly to `/var/log/coraza-audit.log` with no built-in rotation.
A cron job (`rotate-audit-log.sh`) runs hourly and uses copytruncate to rotate
when the file exceeds 256MB. Settings: `roll_size=256MB`, `roll_keep=5`,
`roll_keep_for=2160h` (90 days). wafctl's offset tracking detects the size
shrink and resets automatically. On copytruncate, in-memory events are preserved
(not cleared) — they age out naturally via maxAge eviction.

### JSONL Event Persistence

Parsed events are persisted to JSONL files so they survive wafctl restarts
without re-parsing the raw audit/access logs. On startup, `SetEventFile()`
restores events from JSONL before tailing begins.

- WAF events: `/data/events.jsonl` — large payload fields (`RequestHeaders`,
  `RequestBody`, `RequestArgs`) are stripped when persisting to keep the file compact
- Access log events: `/data/access-events.jsonl` — rate limit and ipsum events
- Compaction runs synchronously after eviction via `compactEventFileLocked()` (caller holds lock); `compactEventFile()` wrapper acquires its own lock for external callers
- At ~400 WAF events/day and 90-day retention: ~36,000 events, ~36MB on disk

### Blocklist Refresh

`POST /api/blocklist/refresh` downloads a fresh IPsum list from GitHub, filters
by min_score, generates the Caddy snippet, atomically writes it, reloads the
in-memory cache, and reloads Caddy. The Go `BlocklistStore.parseFile()` uses
the file's mtime as a fallback when the `# Updated:` comment is missing.

### wafctl Environment Variables

All configurable via `envOr()` with sensible defaults:
- `WAFCTL_PORT` (default `8080`), `WAF_CORS_ORIGINS` (default `*`)
- `WAF_AUDIT_LOG`, `WAF_COMBINED_ACCESS_LOG` — log file paths
- `WAF_EXCLUSIONS_FILE`, `WAF_CONFIG_FILE`, `WAF_RATELIMIT_FILE` — JSON store paths
- `WAF_CORAZA_DIR`, `WAF_RATELIMIT_DIR` — output directories for generated configs
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
