# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

Docker Compose infrastructure for a Caddy reverse proxy with a custom policy engine WAF,
Authelia 2FA forward auth, and a WAF management sidecar. Two codebases:

- **wafctl/** — Go HTTP service + CLI tool (stdlib only, zero external deps, Go 1.24+)
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
cd wafctl && CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=1.2.1" -o wafctl .
```

Version injected via `-ldflags "-X main.version=..."`. Fallback: `var version = "dev"` in `main.go`.

### Frontend (waf-dashboard)

```bash
cd waf-dashboard && npm ci && npm run build
```

## Test Commands

```bash
make test               # Run ALL tests (Go + frontend)
make test-go            # Go tests only (24 test files, 500 tests)
make test-frontend      # Frontend Vitest only (17 test files, 326 tests)
make test-e2e           # E2E smoke tests (requires Docker, 117 tests)
```

### Running a single test

```bash
# Go — run from wafctl/:
cd wafctl && go test -run TestFunctionName -count=1 -timeout 60s ./...

# Frontend — run from waf-dashboard/:
cd waf-dashboard && npx vitest run -t "test description substring"

# E2E — run from test/e2e/:
cd test/e2e && go test -v -count=1 -timeout 60s -run TestName ./...
```

## Lint / Format

No linters or formatters are configured. Use `gofmt` for Go.
TypeScript strict mode enforced via `astro/tsconfigs/strict`.

## Secrets

- `.env` is SOPS-encrypted (age). **Never commit unencrypted secrets.**
- A pre-commit hook blocks unencrypted `.env`, `.tfvars`, `.tfstate` files.

## Code Style — Go (wafctl/)

### Imports

- Standard library only — zero external dependencies.
- Single import block, alphabetically sorted.

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
- All JSON responses via `writeJSON()` helper (sets Content-Type, disables HTML escaping).
- All JSON request bodies via `decodeJSON()` helper (`MaxBytesReader` 5 MB limit).
- Query filters: `fieldFilter` type with `parseFieldFilter(value, op)` and `matchField(target)`.
  Operators: `eq` (default), `neq`, `contains`, `in`, `regex`. Param format: `field=val&field_op=op`.

### Concurrency

- `sync.RWMutex` on all stores; `RLock` for reads, `Lock` for mutations.
- `atomic.Int64` for offset tracking; `atomic.Bool` for guard flags.
- Return deep copies from getters to prevent concurrent modification.

### File Operations & Structure

- Atomic writes via `atomicWriteFile()` in `util.go` — write to temp, fsync, rename.
- `envOr()` helper in `main.go`; shared utilities in `util.go`.
- Section headers: `// --- Section Name ---` or `// ─── Section Name ──────────`
- One cohesive module per `.go` file, split by domain responsibility.

### Input Validation

- `validateExclusion()` rejects newlines in all string fields, validates operators/fields against allowlists.
- `validateConditions()` — shared validation used by both WAF exclusions and rate limit rules.
- Tags: lowercase alphanumeric + hyphens (`^[a-z0-9][a-z0-9-]*$`), max 10 per rule, max 50 chars each.
- Condition operators validated per-field via `validOperatorsForField` map:
  - **String fields** (host, path, uri_path, user_agent, header, query, cookie, body, body_json, body_form,
    args, referer, response_header): 16-operator set. `body_json` also supports `exists`.
  - **Enum fields** (method, country, response_status, http_version): eq, neq, in, not_in, in_list, not_in_list.
  - **IP field**: eq, neq, in, not_in, ip_match, not_ip_match, in_list, not_in_list.
  - Numeric operators (gt, ge, lt, le) bypass per-field map — accepted on any field.

## Code Style — TypeScript/React (waf-dashboard/)

### Imports

- Framework imports first (`react`, `vitest`), then local imports.
- Path alias: `@/` maps to `./src/`.

### Naming

- Interfaces/types: `PascalCase` — `SummaryData`, `WAFEvent`, `TimelinePoint`
- Components: `PascalCase` filenames — `OverviewDashboard.tsx`, `PolicyEngine.tsx`
- API functions: `camelCase` — `fetchSummary`, `fetchEvents`, `lookupIP`
- API base: `const API_BASE = "/api"`

### API Layer

- Domain modules under `src/lib/api/` — `shared.ts` (HTTP helpers), `waf-events.ts`, `analytics.ts`,
  `exclusions.ts`, `config.ts`, `rate-limits.ts` (compat wrappers → `/api/rules`), `blocklist.ts`,
  `csp.ts`, `general-logs.ts`, `managed-lists.ts`, `backup.ts`, `default-rules.ts`,
  `security-headers.ts`, `index.ts` (barrel).
- Go returns `snake_case` JSON; API modules map to `camelCase` TypeScript interfaces.
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

## Key Architecture Notes

- Deploy pipeline: generate config → write `policy-rules.json` → plugin detects mtime change → hot-reload.
- On startup, `generateOnBoot()` regenerates all config from stored JSON state.
- All stores use JSON file persistence with `sync.RWMutex` protection.
- Version tags must stay in sync across: `Makefile`, `compose.yaml`, `README.md`, `.github/workflows/build.yml`.
- **Unified rule store**: `ExclusionStore` handles ALL rule types (allow/block/skip/detect/rate_limit).
  `RuleExclusion` is the single model. `/api/rules` is the canonical CRUD endpoint.
  `/api/deploy` is the single deploy endpoint. Old `/api/exclusions` kept as alias.
  `RateLimitRuleStore` has been removed — rate limit rules use `type: "rate_limit"` on `RuleExclusion`.
- Policy engine handles all rule evaluation (allow/block/skip/detect/rate_limit). Coraza has been removed.
- Service FQDN resolution: `BuildServiceFQDNMap()` parses Caddyfile to map short names → FQDNs.
- **DDoS mitigator**: `caddy-ddos-mitigator` plugin v0.7.3 (separate repo: `ergo/caddy-ddos-mitigator`).
  Compiled into Caddy via xcaddy. Registers as `http.handlers.ddos_mitigator` (L7) and
  `layer4.handlers.ddos_mitigator` (L4). Runs after `log_append` but before `policy_engine`.
  Uses behavioral IP profiling (path diversity scoring) instead of raw frequency z-score.
  Enforces via 4 layers: L7 403, L4 TCP RST, nftables kernel drop, eBPF/XDP NIC drop.
  CIDR aggregation promotes /24 prefix when 5+ IPs from same subnet are jailed.
  All detection parameters configurable via Caddyfile (threshold, warmup, CIDR thresholds, etc.).
  Profile reset on unjail (prevents re-jail from stale behavioral data).
  Shares IP jail with wafctl via `/data/waf/jail.json` (bidirectional file sync).
  - wafctl DDoS stores: `JailStore`, `DosConfigStore`, `SpikeDetector`, `SpikeReporter`
  - wafctl DDoS API: `/api/dos/status` (EPS from access log, sparkline, ddos_events count),
    `/api/dos/jail` (CRUD), `/api/dos/config` (CRUD),
    `/api/dos/reports` (spike forensics) in `handlers_dos.go`
  - Dashboard: `/dos` page (`DDoSPanel.tsx`) with StatusBanner (EPS sparkline, poll indicator),
    StatCards, JailTable (CRUD), SpikeReports, ConfigPanel
  - Overview: DDoS Blocked stat card (purple), DDoS series in timeline/donut/bar charts
  - Security Events: purple `DDOS BLOCKED` / `DDOS JAILED` badges via EventTypeBadge
  - Access Logs: optional DDoS column showing ddos_action with purple badge
  - General Logs: ddos_action, ddos_fingerprint, ddos_z_score fields passed through
  - Frontend API module: `src/lib/api/dos.ts`
  - Log fields: `ddos_action`, `ddos_fingerprint`, `ddos_z_score`, `ddos_spike_mode`
  - Handler ordering: `order log_append first`, `order ddos_mitigator after log_append`
  - k6 load tests: `test/k6/stress.js` (baseline + flood + sustain, 300 VUs)
