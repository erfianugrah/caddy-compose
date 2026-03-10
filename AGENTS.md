# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

Docker Compose infrastructure for a Caddy reverse proxy with Coraza WAF (OWASP CRS),
Authelia 2FA forward auth, and a custom WAF management sidecar. Two codebases live here:

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

Image tags live in **five places** that must stay in sync:
- `Makefile` (lines 17-18: `CADDY_IMAGE`, `WAFCTL_IMAGE`)
- `compose.yaml` (lines 3 and 119: image fields)
- `README.md` (badge/reference)
- `test/docker-compose.test.yml` (line 3: caddy image field)
- `.github/workflows/build.yml` (env block: `CADDY_TAG`, `WAFCTL_VERSION`)

Caddy tag format: `<project-version>-<caddy-version>` (e.g. `2.10.1-2.11.1`).
wafctl tag format: simple semver (e.g. `1.10.1`).

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

### SecRule Injection Hardening

- `escapeSecRuleValue()` — escapes `\`, `"`, `'`, strips `\n`/`\r` for SecRule pattern/action values
- `escapeSecRuleMsgValue()` — calls `escapeSecRuleValue()` then replaces commas with semicolons (commas in `msg:'...'` fields cause Coraza's seclang parser to silently stop loading subsequent rules)
- `sanitizeComment()` — replaces newlines with spaces for `msg:` and comment fields
- Input validation regexps in `exclusions.go`: `ruleTagRe` (CRS tag format), `variableRe` (SecRule variable names), `namedFieldNameRe` (header/cookie/args names)
- `validateExclusion()` rejects newlines in all string fields, validates condition operators/fields against allowlists
- `validateConditions()` — shared condition validation function used by both WAF exclusions and RL rules

### SecRule Chain Generation

- `writeChainedRule()` generates chained SecRules for multi-condition exclusions
- `splitCTLActions()` separates `ctl:` actions from other action parts (pass, log, msg, etc.)
- **Critical Coraza quirk**: `ctl:` actions (ruleRemoveById, ruleEngine=Off, etc.) must be placed on the **last** rule of a chain. Coraza silently ignores `ctl:` actions on the first rule of a chain — they parse without error but never execute. Disruptive actions (`pass`, `deny`) and logging (`log`, `msg:`) stay on the first rule as normal.
- Single-condition rules (no chain) are unaffected — `ctl:` on the only rule works fine
- `conditionAction()` builds the full action string; `buildSkipRuleAction()` handles multi-ID `ctl:ruleRemoveById` with self-reference prevention

### File Operations and Code Organization

- Atomic writes via `atomicWriteFile()` — write to temp, fsync, rename
- Incremental file reading with offset tracking and rotation detection
- Section headers: `// --- Section Name ---` or `// ─── Section Name ──────────`
- One cohesive module per `.go` file, split by domain responsibility
- **Entry point & routing**: `main.go` (~370 lines) — server setup, CORS middleware, `envOr()`, route registration
- **JSON/query helpers**: `json_helpers.go` — `writeJSON`, `decodeJSON`, `queryInt`; `query_helpers.go` — `parseHours`, `parseTimeRange`, `fieldFilter`, `matchField`
- **Handler files** (split from main.go): `handlers_events.go` (health/summary/events/services), `handlers_analytics.go` (top IPs/URIs/countries, IP lookup), `handlers_exclusions.go` (exclusion CRUD), `handlers_config.go` (CRS catalog, WAF config, deploy), `handlers_ratelimit.go` (RL rule CRUD + analytics), `handlers_lists.go` (managed lists CRUD + deploy)
- **Log parser**: `logparser.go` (~592 lines) — Store struct, offset/JSONL persistence, Load, eviction, tailing; `event_parser.go` — `parseEvent`, anomaly score extraction; `waf_summary.go` — `summarizeEvents`; `waf_analytics.go` — services/IP/top-N analytics
- **Models** (split by domain): `models.go` (~454 lines) — CRS scoring, audit log types, summary/analytics types; `models_exclusions.go` — Condition, RuleExclusion, WAFConfig; `models_ratelimit.go` — rate limit types; `models_general_logs.go` — general log types
- **Config generation**: `generator.go` (~458 lines) — SecRule exclusion generation; `generator_helpers.go` (~187 lines) — condition-to-SecRule mapping, escape utilities; `waf_settings_generator.go` — WAF settings generation
- **Access log store**: `access_log_store.go` (~623 lines) — AccessLogStore struct, persistence, Load, snapshots (split from rl_analytics.go)
- **Rate limit analytics**: `rl_analytics.go` (~373 lines) — regex cache, summary, filtered events, rule hits, condition matching
- **Rate limit advisor**: `rl_advisor.go` (~364 lines) — algorithm/computation, recommendations; `rl_advisor_stats.go` (~449 lines) — MAD/IQR/Fano statistical functions, distribution analysis; `rl_advisor_types.go` — types, models, cache
- **Rate limit generator**: `rl_generator.go` (~321 lines) — Caddyfile generation for RL rules; `rl_matchers.go` (~301 lines) — Caddy matcher syntax generation from conditions
- **General logs**: `general_logs.go` (~505 lines) — store code; `general_logs_handlers.go` (~515 lines) — handlers + aggregation
- **IP intelligence**: `ip_intel.go` (~247 lines) — BGP routing, RPKI validation, orchestration; `ip_intel_sources.go` (~403 lines) — external API clients (Shodan, reputation, BGP); `tls_helpers.go` (38 lines) — TLS version/cipher suite name helpers
- **GeoIP**: `geoip.go` (~499 lines) — GeoIPStore, API/header/cache resolution; `geoip_mmdb.go` (~403 lines) — pure MMDB binary reader (zero-dependency)
- **Exclusions**: `exclusions.go` (~366 lines) — ExclusionStore CRUD, persistence; `exclusions_validate.go` (~257 lines) — validation, condition checks, regex patterns
- **CLI**: `cli.go` (~333 lines) — CLI framework, serve/config/deploy commands; `cli_rules.go` (~324 lines) — rules/exclusions subcommands; `cli_extras.go` (~310 lines) — ratelimit/csp/blocklist/events subcommands; `cli_managed_lists.go` (~116 lines) — managed lists subcommands
- **Shared utilities**: `util.go` (~85 lines) — `envOr()`, `atomicWriteFile()` (shared across stores)
- **Policy engine generator**: `policy_generator.go` (~260 lines) — PolicyRulesFile/PolicyRule/PolicyCondition types, PolicyRateLimitConfig/PolicyRateLimitGlobalConfig, `GeneratePolicyRules()`, `GeneratePolicyRulesWithRL()`, `FilterSecRuleExclusions()`, `IsPolicyEngineType()`, `SplitHoneypotPaths()`
- **Managed lists**: `managed_lists.go` (~582 lines) — ManagedListStore CRUD, persistence, validation; `models_lists.go` (~69 lines) — ManagedList types; `handlers_lists.go` (~160 lines) — HTTP handlers
- **Domain stores**: `rl_rules.go` (564), `csp.go` (558), `csp_generator.go`, `blocklist.go` (372), `validate.go` (447), `deploy.go`, `config.go`, `cache.go`, `cfproxy.go`, `crs_rules.go`

## Coraza Rule ID Namespaces

When adding custom SecRules, use the correct ID range:
- `9100001–9100006` — pre-CRS rules (baked in `coraza/pre-crs.conf`)
- `9100010–9100019` — post-CRS custom detection rules (baked in `coraza/post-crs.conf`)
- `9100020–9100029` — honeypot path rules (fully dynamic via Policy Engine; `9100021` generated in `custom-pre-crs.conf`)
- `9100030–9100039` — heuristic bot signal rules (baked in `coraza/pre-crs.conf`, scanner UAs in `coraza/scanner-useragents.txt`). Rule 9100032 uses `drop` action (treated as `deny,status:403` by our coraza-caddy fork)
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
| `allow` | `ctl:ruleEngine=Off` / Policy Engine allow | Full WAF bypass for matching requests |
| `block` | `deny,status:403` / Policy Engine block | Deny matching requests. Honeypot paths use `block` + `["honeypot"]` tag |
| `skip_rule` | `ctl:ruleRemoveById` / `ByTag` | Skip specific CRS rules |
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
| `ip` | `REMOTE_ADDR` | `eq`, `neq`, `ip_match`, `not_ip_match`, `in_list`, `not_in_list` |
| `path` | `REQUEST_URI` | `eq`, `neq`, `contains`, `begins_with`, `ends_with`, `regex`, `in`, `in_list`, `not_in_list` |
| `host` | `SERVER_NAME` | `eq`, `neq`, `contains` |
| `method` | `REQUEST_METHOD` | `eq`, `neq`, `in` |
| `user_agent` | `REQUEST_HEADERS:User-Agent` | `eq`, `contains`, `regex` |
| `header` | `REQUEST_HEADERS:<Name>` | `eq`, `contains`, `regex` |
| `query` | `QUERY_STRING` | `contains`, `regex` |
| `country` | `REQUEST_HEADERS:Cf-Ipcountry` | `eq`, `neq`, `in` |
| `cookie` | `REQUEST_COOKIES:<Name>` | `eq`, `neq`, `contains`, `regex` |
| `body` | `REQUEST_BODY` | `eq`, `contains`, `begins_with`, `ends_with`, `regex` |
| `body_json` | `REQUEST_BODY` | `eq`, `contains`, `regex`, `exists` |
| `body_form` | `ARGS:<Name>` | `eq`, `contains`, `regex` |
| `args` | `ARGS:<Name>` | `eq`, `neq`, `contains`, `regex` |
| `uri_path` | `REQUEST_FILENAME` | `eq`, `neq`, `contains`, `begins_with`, `ends_with`, `regex` |
| `referer` | `REQUEST_HEADERS:Referer` | `eq`, `neq`, `contains`, `regex` |
| `response_header` | `RESPONSE_HEADERS:<Name>` | `eq`, `contains`, `regex` |
| `response_status` | `RESPONSE_STATUS` | `eq`, `neq`, `in` |
| `http_version` | `REQUEST_PROTOCOL` | `eq`, `neq` |

Named fields (`header`, `cookie`, `args`, `response_header`, `body_form`) use `Name:value` format
in the value field — the name before `:` becomes the SecRule variable suffix, the
value after `:` is the match target. Without `:`, the entire collection is matched.
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
- **Generator**: `rl_generator.go` — translates rules into Caddy `rate_limit` plugin configs with named matchers
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

### Caddyfile Generation (legacy, `WAF_POLICY_ENGINE_ENABLED=false` only)

**Note:** In production, rate limiting is handled entirely by the policy engine plugin
via `policy-rules.json` hot-reload. The `caddy-ratelimit` Caddy plugin has been removed
from the Dockerfile and all `import /data/caddy/rl/*_rl*.caddy` lines removed from the
Caddyfile. The legacy generator code remains as a fallback for `WAF_POLICY_ENGINE_ENABLED=false`.

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

`/` · `/analytics` · `/csp` · `/events` · `/lists` · `/logs` · `/policy` · `/rate-limits` · `/services` · `/settings`

### Static MPA Routing

The dashboard is an Astro `output: "static"` multi-page application (MPA), **not** an SPA.
Each page is a pre-rendered HTML file (`<route>/index.html`). Caddy serves these via:

```
try_files {path} {path}/index.html
```

There is intentionally **no** `/index.html` catch-all fallback — that is an SPA pattern
and would cause Web Cache Deception vulnerabilities (e.g., `/blocklist;test.png` would
serve authenticated HTML with `.png` cache headers). Unknown paths fall through to
Caddy's `handle_errors` which serves the custom `404.html` page.

A custom `src/pages/404.astro` generates `dist/404.html` for proper 404 responses.

## Content Security Policy (CSP) Management

Per-service CSP header management system. Follows the same pattern as rate limiting:
JSON store → Caddy config generator → file deploy → Caddy reload.

### Architecture

- **Store**: `csp.go` — `CSPStore` with `sync.RWMutex`, CRUD, validation, header builder, merge logic
- **Generator**: `csp_generator.go` — translates config into per-service `header` directives in `.caddy` files
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
| Output dir (wafctl) | `/data/csp/` (`WAF_CSP_DIR`) |
| Output dir (Caddy) | `/data/caddy/csp/` |
| File naming | `<service>_csp.caddy` |
| Caddyfile import | `import /data/caddy/csp/<svc>_csp*.caddy` |
| Import position | After `security_headers`, before rate limit imports |

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
- **Generator integration**: Both `generator.go` (SecRule) and `rl_generator.go` (Caddy matchers) resolve `in_list`/`not_in_list` references at generation time

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
- **SecRule generator**: `resolveSecRuleListConditions()` expands list items into `@pmFromFile` or `@ipMatchFromFile` directives
- **RL generator**: `resolveRLListConditions()` expands into Caddy matcher syntax
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
| `blocked` | WAF blocked (Coraza anomaly threshold exceeded) |
| `logged` | WAF logged only (below threshold or detection-only mode) |
| `rate_limited` | Rate limited (429) or blocklist-blocked |
| `policy_skip` | Policy engine skipped specific CRS rules |
| `policy_allow` | Policy engine allowed (WAF bypassed) |
| `policy_block` | Policy engine blocked (403 from plugin) |

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

- **Exclusion store v1→v2**: Auto-migrates on load. Adds `tags` to seeded rules, converts
  `honeypot` type exclusions to `block` + `["honeypot"]` tag. Creates `.v1.bak` backup.
- **Exclusion store v2→v3**: Seeds 8 per-level IPsum block rules (`type: "block"`,
  condition `ip in_list ipsum-level-N`, tags `["blocklist", "ipsum", "ipsum-level-N"]`).
  Idempotent — checks if any `block` rule with `ipsum` tag already exists before seeding.
- **JSONL event backfill**: On load, remaps legacy event types:
  `honeypot`→`policy_block`, `scanner`→`policy_block`, `ipsum_blocked`→`rate_limited`.
  Backfills appropriate tags. Compacts JSONL file after migration.

## API Endpoints (wafctl)

| Group | Routes |
|-------|--------|
| Core | `GET /api/health`, `GET /api/summary`, `GET /api/events`, `GET /api/services` |
| Analytics | `GET /api/analytics/top-ips`, `GET /api/analytics/top-uris`, `GET /api/analytics/top-countries` |
| IP Lookup | `GET /api/lookup/{ip}` |
| Exclusions | `GET\|POST /api/exclusions`, `GET\|PUT\|DELETE /api/exclusions/{id}` |
| Exclusion ops | `GET /api/exclusions/export`, `POST /api/exclusions/import`, `POST /api/exclusions/generate`, `GET /api/exclusions/hits`, `PUT /api/exclusions/reorder` |
| CRS | `GET /api/crs/rules`, `GET /api/crs/autocomplete` |
| Config | `GET\|PUT /api/config`, `POST /api/config/generate`, `POST /api/config/validate`, `POST /api/config/deploy` |
| RL Rules | `GET\|POST /api/rate-rules`, `GET\|PUT\|DELETE /api/rate-rules/{id}` |
| RL Rule ops | `POST /api/rate-rules/deploy`, `GET\|PUT /api/rate-rules/global`, `GET /api/rate-rules/export`, `POST /api/rate-rules/import`, `GET /api/rate-rules/hits`, `PUT /api/rate-rules/reorder` |
| RL Advisor | `GET /api/rate-rules/advisor?window=&service=&path=&method=&limit=` |
| RL Analytics | `GET /api/rate-limits/summary`, `GET /api/rate-limits/events` |
| Managed Lists | `GET\|POST /api/lists`, `GET\|PUT\|DELETE /api/lists/{id}` |
| CSP | `GET\|PUT /api/csp`, `POST /api/csp/deploy`, `GET /api/csp/preview` |
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
values to be used as rate limit keys, in log templates, SecRule conditions, or any
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
`rl_generator.go` automatically emits a `body_vars { ... }` block before the `rate_limit`
directive. The handler must run first so placeholders are populated for bucket keying.

### Design

- **One match type per instance** — compose multiple via Caddy named matcher blocks
- **Body buffering** — reads once via `io.LimitReader`, re-wraps `r.Body` with `io.MultiReader` so downstream handlers still see the full body
- **Default max_size: 13 MiB** — matches Coraza WAF `request_body_limit`; configurable via `max_size` directive
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
correct matching semantics. Fixes the core security bug where the `in` operator in Coraza
SecRule generation uses `@pm` (Aho-Corasick substring match), causing `/admin` to
match `/administrator`. The plugin uses `map[string]bool` hash sets for exact matching.

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
lookup instead of Coraza's `@pm` substring match.

### Body Field Support

- **Lazy body reading**: Only reads request body when a rule needs it (`needsBody` flag set at compile time)
- **Body re-wrap**: Uses `io.LimitReader` + `io.MultiReader` so downstream handlers still see the full body
- **Default max size**: 13 MiB (matches Coraza WAF `request_body_limit`), configurable via `body_max_size`
- **`body`**: Raw request body matching (eq, contains, begins_with, ends_with, regex)
- **`body_json`**: JSON dot-path resolution via `resolveJSONPath()` — walks nested objects/arrays (e.g., `.user.roles.0`). Supports `exists` operator for field presence checks
- **`body_form`**: URL-encoded form field extraction via `url.ParseQuery()` — first value for multi-valued fields
- **`exists` operator**: Checks JSON field presence without value comparison (`extractFieldExists()`)
- `jsonValueToString()` handles all JSON types: strings, floats (integers render without decimals), bools, null, arrays/objects

### Caddyfile Integration

```
order policy_engine first
order coraza_waf after policy_engine
```

The `(waf)` snippet chains policy_engine before coraza_waf:
```
policy_engine {
    rules_file /data/coraza/policy-rules.json
    reload_interval 5s
    body_max_size 13mb
}
@needs_waf {
    not vars {http.vars.policy_engine.action} allow
}
route @needs_waf {
    coraza_waf { ... }
}
```

Allow action sets a Caddy var; the `@needs_waf` inverted matcher skips Coraza WAF
for allowed requests. Block/honeypot return 403 before Coraza runs.

### wafctl Integration

- `policy_generator.go` generates `policy-rules.json` from exclusions (allow/block) and rate limit rules
- `GeneratePolicyRulesWithRL()` merges WAF exclusions + RL rules into a single rules array with priority bands: block(100) < allow(200) < rate_limit(300)
- `FilterSecRuleExclusions()` removes policy-engine types from the SecRule generator input
- `IsPolicyEngineType()` checks if an exclusion type is handled by the plugin
- `splitHoneypotPaths()` expands honeypot rules (which consolidate multiple paths) into individual path conditions (unexported, test-only)
- Behind `WAF_POLICY_ENGINE_ENABLED` env var (default `false`) — when disabled, all exclusions use Coraza SecRules and RL rules generate `.caddy` files as before
- Both `generateOnBoot()` and `handleDeploy()` call the policy generator when enabled, including RL rules
- `handleDeployRLRules()` writes to `policy-rules.json` when enabled (no Caddy restart), falls back to `.caddy` files when disabled
- On boot with policy engine enabled, stale `*_rl.caddy` files are cleared to prevent double rate limiting
- `validPolicyEngineFields` map in `models_exclusions.go` — same as RL fields + `args`, excludes `response_header` and `response_status`
- `validateExclusion()` uses `IsPolicyEngineType()` to select the right condition field set (policy engine fields for allow/block/honeypot, all fields for SecRule types)

### Plugin Test Suite (143 tests)

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

### Go (1357 tests across 24 files)
- Tests split into domain-specific files: `logparser_test.go`, `exclusions_test.go`, `generator_test.go`, `config_test.go`, `deploy_test.go`, `geoip_test.go`, `blocklist_test.go`, `rl_analytics_test.go`, `rl_advisor_test.go`, `rl_rules_test.go`, `rl_generator_test.go`, `rl_handlers_test.go`, `crs_rules_test.go`, `csp_test.go`, `handlers_test.go`, `cli_test.go`, `cfproxy_test.go`, `validate_test.go`, `general_logs_test.go`, `ip_intel_test.go`, `tls_helpers_test.go`, `policy_generator_test.go`, `managed_lists_test.go`, `testhelpers_test.go`
- All `package main` (whitebox)
- Table-driven tests with `t.Run()` subtests
- `httptest.NewRequest` + `httptest.NewRecorder` for handler tests
- `httptest.NewServer` to mock the Caddy admin API
- Temp file helpers in `testhelpers_test.go`: `writeTempLog`, `newTestExclusionStore`, `newTestConfigStore`, `emptyAccessLogStore`, `writeTempAccessLog`
- `handlers_test.go` covers operator-aware filtering (`fieldFilter`/`matchField` unit tests + handler integration tests)

### Frontend (312 tests across 14 files)
- Vitest with `vi.fn()` mock fetch, `describe`/`it` blocks
- `beforeEach`/`afterEach` for setup/teardown
- API tests split by domain in `src/lib/api/`: `waf-events.test.ts` (33), `rate-limits.test.ts` (31), `managed-lists.test.ts` (14), `general-logs.test.ts` (13), `exclusions.test.ts` (13), `analytics.test.ts` (13), `config.test.ts` (9), `blocklist.test.ts` (6), `shared.test.ts` (3)
- Component tests: `DashboardFilterBar.test.ts` (63)
- Policy sub-module tests in `components/policy/`: `constants.test.ts` (33), `exclusionHelpers.test.ts` (38), `eventPrefill.test.ts` (24), `TagInputs.test.ts` (19)

## Coraza-Caddy Fork

The Dockerfile uses a fork of coraza-caddy (`github.com/erfianugrah/coraza-caddy/v2`)
pinned by commit hash. The fork contains two fixes over upstream:

1. **WebSocket hijack tracking** — prevents response writes on upgraded connections
   that would panic or log "WriteHeader on hijacked connection". The `rwInterceptor`
   tracks hijack state via a `hijackTracker` wrapper and skips response processing
   when the connection has been taken over. ([upstream PR #259](https://github.com/corazawaf/coraza-caddy/pull/259))

2. **`drop` action status code fix** — upstream's `obtainStatusCodeFromInterruptionOrDefault()`
   only handles `action == "deny"`, causing `drop` to fall through to `defaultStatusCode`
   (200). Since coraza-caddy operates as HTTP middleware and cannot perform TCP-level
   FIN/RST, `drop` is now treated identically to `deny` — uses the rule's `status:`
   field or defaults to 403. This ensures Caddy's `handle_errors` serves error pages
   with the correct HTTP status code.

### WebSocket Bypass

The fork's hijack tracking prevents panics on upgraded connections, but a
Caddyfile-level `@not_websocket` bypass is **still required**. Without it,
WebSocket connections fail with `NS_ERROR_WEBSOCKET_CONNECTION_REFUSED`.
The `(waf)` snippet wraps the entire `coraza_waf` block in
`route @not_websocket { ... }` so WebSocket traffic bypasses WAF entirely.
The initial HTTP upgrade request is NOT inspected — this is intentional to
avoid breaking the upgrade handshake.

### Error Pages

The `(waf)` snippet includes `handle_errors 400 403 429` which serves `errors/error.html`
via Caddy's `templates` + `file_server`. The `(error_pages)` snippet catches remaining
error codes (404, 500, 502, etc.). The template uses `{placeholder "http.error.status_code"}`
for conditional content (different messages per status code). `file_server` inside
`handle_errors` preserves the error's HTTP status code via `statusOverrideResponseWriter`.

## Key Architecture Notes

- The wafctl sidecar reads Coraza audit logs and Caddy access logs incrementally
- SecRule `.conf` files are generated and deployed to Caddy via its admin API
- Deploy pipeline: generate config → SHA-256 fingerprint → POST to Caddy admin → reload
- Caddy reload uses `Cache-Control: must-revalidate` header to force re-provision even
  when the Caddyfile-adapted JSON is byte-identical (Caddy strips comments during
  adaptation, so the fingerprint comment alone cannot force a reload)
- `.env` contains secrets (`CF_API_TOKEN`, `EMAIL`) — never commit this file unencrypted
- Makefile supports `.env.mk` overrides and `REMOTE=host` inline overrides
- Two deploy modes in Makefile: `dockge` (via dockge container) or `compose` (direct)

### Dynamic vs Baked-in Config

Files baked into the image at build time (in `/etc/caddy/`):
- `coraza/pre-crs.conf`, `coraza/post-crs.conf` — static WAF rules
- `cf_trusted_proxies.caddy` — Cloudflare IP ranges
- `waf-ui/` — dashboard static files, `errors/error.html`

Files written at runtime by wafctl (in `/data/coraza/` volumes):
- `custom-waf-settings.conf` — SecRuleEngine mode, paranoia levels, thresholds
- `custom-pre-crs.conf`, `custom-post-crs.conf` — policy engine exclusions
- `<service>_csp.caddy` — CSP header configs (per-service)
- `<list-id>.list` — managed list files (one per list, newline-separated items)
- `policy-rules.json` — policy engine plugin rules including rate limits (in `/data/coraza/`, when `WAF_POLICY_ENGINE_ENABLED=true`)

### Startup Behavior (generate-on-boot)

On startup, wafctl calls `generateOnBoot()` which regenerates all config files
from stored JSON state (WAF config, exclusions, rate limit rules, CSP). This ensures a
stack restart always picks up the latest generator output without requiring a
manual `POST /api/config/deploy`. No Caddy reload is performed — Caddy reads
the files fresh on its own startup.

The blocklist store calls `loadFromLists()` on boot to populate its in-memory IP set
from the ipsum managed lists. IPsum blocking is handled by the policy engine plugin
via 8 per-level block rules (seeded by v2→v3 exclusion migration).

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
- Access log events: `/data/access-events.jsonl` — rate limit and policy engine block events
- Compaction runs synchronously after eviction via `compactEventFileLocked()` (caller holds lock); `compactEventFile()` wrapper acquires its own lock for external callers
- At ~400 WAF events/day and 90-day retention: ~36,000 events, ~36MB on disk

### Access Log Event Classification

Two event stores feed into the unified `Event` type:
- **WAF Audit Log Store** (`Store` in `logparser.go`) — parses Coraza audit log, classifies by rule IDs and `is_interrupted`
- **Access Log Store** (`AccessLogStore` in `access_log_store.go`) — parses Caddy access log for 429s (rate limit) and 403s (policy engine blocks)

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
- `WAF_CSP_FILE` (default `/data/csp-config.json`) — CSP configuration store path
- `WAF_CSP_DIR` (default `/data/csp/`) — output directory for generated CSP config files
- `WAF_GENERAL_LOG_FILE` (default `/data/general-events.jsonl`) — JSONL persistence for general log events
- `WAF_GENERAL_LOG_OFFSET_FILE` (default `/data/.general-log-offset`) — persists general log read offset across restarts
- `WAF_GENERAL_LOG_MAX_AGE` (default `168h`) — retention period for general log events (shorter than WAF events due to higher volume)
- `WAF_BLOCKLIST_REFRESH_HOUR` (default `6`) — UTC hour (0–23) for daily IPsum blocklist refresh
- `WAF_MANAGED_LISTS_FILE` (default `/data/lists.json`) — managed lists store path
- `WAF_MANAGED_LISTS_DIR` (default `/data/lists`) — output directory for managed list files (one `.list` file per list)
- `WAF_POLICY_ENGINE_ENABLED` (default `false`) — enables policy engine plugin integration; when `true`, `allow`/`block`/`honeypot` exclusions are routed to the Caddy plugin instead of Coraza SecRules
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
