# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

Docker Compose infrastructure for a Caddy reverse proxy with Coraza WAF (OWASP CRS),
Authelia 2FA forward auth, and a custom WAF management sidecar. Two codebases live here:

- **waf-api/** — Go HTTP service (stdlib only, zero external deps, Go 1.23+)
- **waf-dashboard/** — Astro 5 + React 19 + TypeScript 5.7 frontend (shadcn/ui, Tailwind CSS 4)
- Root level: Caddyfile, Dockerfile (6-stage multi-stage), compose.yaml, Makefile

## Build Commands

```bash
make build              # Build all Docker images
make build-caddy        # Build the main Caddy image only
make build-waf-api      # Build the standalone waf-api image only
make push               # Push images to Docker Hub
make deploy             # Full pipeline: build + push + SCP + restart
```

### Go (waf-api)

```bash
cd waf-api && CGO_ENABLED=0 go build -ldflags="-s -w" -o waf-api .
```

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
cd waf-api && go test -run TestFunctionName -count=1 -timeout 60s ./...
# Frontend:
cd waf-dashboard && npx vitest run -t "test description substring"
```

## Lint / Format

No linters or formatters are configured. Use `gofmt` for Go.
TypeScript strict mode is enforced via `astro/tsconfigs/strict`.

## Version Management

Image tags live in **four places** that must stay in sync:
- `Makefile` (lines 17-18: `CADDY_IMAGE`, `WAF_API_IMAGE`)
- `compose.yaml` (lines 3 and 117: image fields)
- `README.md` (badge/reference)
- `test/docker-compose.test.yml` (line 3: caddy image field)

Caddy tag format: `<project-version>-<caddy-version>` (e.g. `1.15.0-2.10.2`).
waf-api tag format: simple semver (e.g. `0.10.0`).

## Secrets and Encryption

- `.env` is SOPS-encrypted (age). Never commit unencrypted secrets.
- `authelia/users_database.yml` is also SOPS-encrypted.
- `.env.mk` (gitignored) holds local Makefile overrides like `REMOTE=host`.
- A **pre-commit hook** blocks unencrypted `.env`, `.tfvars`, `.tfstate` files.
  It checks YAML/JSON for secret-like patterns and verifies SOPS `ENC[AES256_GCM,...]`
  markers are present. Supports `.allow-unencrypted` (skip all) and
  `.allow-unencrypted-paths` (per-file glob exemptions).

## Code Style — Go (waf-api/)

### Imports

- Standard library only — no external dependencies
- Single import block, alphabetically sorted
- Common: `encoding/json`, `fmt`, `log`, `net/http`, `os`, `path/filepath`, `sort`, `strings`, `sync`, `time`

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
- Server timeouts: `ReadTimeout: 10s`, `WriteTimeout: 150s`, `IdleTimeout: 60s`
- Caddy reload client timeout: `120s` (accounts for WAF rule initialization)
- Makefile deploy wget timeout: `120s` (`-T 120`)

### Concurrency

- `sync.RWMutex` on all stores; `RLock` for reads, `Lock` for mutations
- Return deep copies from getters to prevent concurrent modification

### File Operations and Code Organization

- Atomic writes via `atomicWriteFile()` — write to temp, fsync, rename
- Incremental file reading with offset tracking and rotation detection
- Section headers: `// --- Section Name ---` or `// ─── Section Name ──────────`
- One cohesive module per `.go` file (logparser, generator, deploy, config, exclusions, geoip, blocklist, etc.)
- All data models in `models.go`; most HTTP handlers in `main.go`, domain-specific handlers co-located with their store (e.g. `blocklist.go` has `handleBlocklistStats`, `handleBlocklistRefresh`)
- `geoip.go` — pure-Go MMDB reader (ported from k3s Sentinel), GeoIP store with in-memory cache, CF header parser, online API fallback (configurable via `WAF_GEOIP_API_URL`)
- `blocklist.go` — IPsum blocklist file parser with `# Updated:` comment extraction and mtime fallback, cached stats/check, on-demand refresh (download + filter + atomic write + Caddy reload)

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

### UI Patterns

- shadcn/ui components in `src/components/ui/` (button, card, badge, dialog, etc.)
- Tailwind CSS 4.0 for styling
- `cn()` utility (clsx + tailwind-merge) for className composition

### Dashboard Pages (file-based routing)

`/` · `/analytics` · `/blocklist` · `/events` · `/policy` · `/rate-limits` · `/services` · `/settings`

## API Endpoints (waf-api)

| Group | Routes |
|-------|--------|
| Core | `GET /api/health`, `GET /api/summary`, `GET /api/events`, `GET /api/services` |
| Analytics | `GET /api/analytics/top-ips`, `GET /api/analytics/top-uris`, `GET /api/analytics/top-countries` |
| IP Lookup | `GET /api/lookup/{ip}` |
| Exclusions | `GET\|POST /api/exclusions`, `GET\|PUT\|DELETE /api/exclusions/{id}` |
| Exclusion ops | `GET /api/exclusions/export`, `POST /api/exclusions/import`, `POST /api/exclusions/generate` |
| CRS | `GET /api/crs/rules`, `GET /api/crs/autocomplete` |
| Config | `GET\|PUT /api/config`, `POST /api/config/generate`, `POST /api/config/deploy` |
| Rate Limits | `GET\|PUT /api/rate-limits`, `POST /api/rate-limits/deploy` |
| RL Analytics | `GET /api/rate-limits/summary`, `GET /api/rate-limits/events` |
| Blocklist | `GET /api/blocklist/stats`, `GET /api/blocklist/check/{ip}`, `POST /api/blocklist/refresh` |

## Test Patterns

### Go
- All tests in `main_test.go`, `package main` (whitebox)
- Table-driven tests with `t.Run()` subtests
- `httptest.NewRequest` + `httptest.NewRecorder` for handler tests
- `httptest.NewServer` to mock the Caddy admin API
- Temp file helpers: `writeTempLog`, `newTestExclusionStore`, `newTestConfigStore`

### Frontend
- Vitest with `vi.fn()` mock fetch, `describe`/`it` blocks
- `beforeEach`/`afterEach` for setup/teardown
- Tests live alongside source: `api.test.ts` next to `api.ts`

## Key Architecture Notes

- The waf-api sidecar reads Coraza audit logs and Caddy access logs incrementally
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

Files written at runtime by waf-api (in `/data/coraza/` and `/data/rl/` volumes):
- `custom-waf-settings.conf` — SecRuleEngine mode, paranoia levels, thresholds
- `custom-pre-crs.conf`, `custom-post-crs.conf` — policy engine exclusions
- `ipsum_block.caddy` — updated daily by cron at 02:00, or on-demand via `POST /api/blocklist/refresh`
- `<service>_rate_limit.caddy` — rate limit zone configs

### Startup Behavior (generate-on-boot)

On startup, waf-api calls `generateOnBoot()` which regenerates all config files
from stored JSON state (WAF config, exclusions, rate limit zones). This ensures a
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
`roll_keep_for=2160h` (90 days). waf-api's offset tracking detects the size
shrink and resets automatically. On copytruncate, in-memory events are preserved
(not cleared) — they age out naturally via maxAge eviction.

### JSONL Event Persistence

Parsed events are persisted to JSONL files so they survive waf-api restarts
without re-parsing the raw audit/access logs. On startup, `SetEventFile()`
restores events from JSONL before tailing begins.

- WAF events: `/data/events.jsonl` — large payload fields (`RequestHeaders`,
  `RequestBody`, `RequestArgs`) are stripped when persisting to keep the file compact
- Access log events: `/data/access-events.jsonl` — rate limit and ipsum events
- Compaction runs automatically after eviction (removes events older than maxAge)
- At ~400 WAF events/day and 90-day retention: ~36,000 events, ~36MB on disk

### Blocklist Refresh

`POST /api/blocklist/refresh` downloads a fresh IPsum list from GitHub, filters
by min_score, generates the Caddy snippet, atomically writes it, reloads the
in-memory cache, and reloads Caddy. The Go `BlocklistStore.parseFile()` uses
the file's mtime as a fallback when the `# Updated:` comment is missing.

### waf-api Environment Variables

All configurable via `envOr()` with sensible defaults:
- `WAF_API_PORT` (default `8080`), `WAF_CORS_ORIGINS` (default `*`)
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

### Relationship to k3s Sentinel

A parallel implementation of the same security concepts exists in `/home/erfi/k3s/`:
- `k3s/middleware/sentinel.go` — inline Traefik middleware plugin (heuristic bot scoring, expression-based firewall rules)
- `k3s/services/sentinel/` — IPsum CronJob for Kubernetes
- `k3s/services/security-dashboard/` — Go SSR dashboard (same author, same stdlib-only style)
- Both repos share: `envOr()` pattern, `sync.RWMutex` stores, section header style, atomic file ops, scanner UA lists, honeypot paths, IP resolution from proxy headers
