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
cd wafctl && CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=2.62.0" -o wafctl .
```

Version injected via `-ldflags "-X main.version=..."`. Fallback: `var version = "dev"` in `main.go`.

### Frontend (waf-dashboard)

```bash
cd waf-dashboard && npm ci && npm run build
```

## Test Commands

```bash
make test               # Run ALL tests (Go + frontend)
make test-go            # Go tests only (29 test files, ~530 tests)
make test-frontend      # Frontend Vitest only (18 test files, ~334 tests)
make test-e2e           # E2E smoke tests (requires Docker, ~118 tests)
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
- Version tags must stay in sync across: `Makefile`, `compose.yaml`, `README.md`, `.github/workflows/build.yml`.
- **Unified rule store**: `ExclusionStore` handles ALL rule types (allow/block/skip/detect/rate_limit).
  `RuleExclusion` is the single model. `/api/rules` is the canonical CRUD endpoint.
  `/api/deploy` is the single deploy endpoint. Old `/api/exclusions` kept as alias.
- Policy engine handles all rule evaluation. Coraza has been removed.
- Service FQDN resolution: `BuildServiceFQDNMap()` parses Caddyfile to map short names → FQDNs.
  `mapServiceBoth` generic helper maps both short name and FQDN in all config builders.
- **CRS metadata**: Category taxonomy, valid prefixes, and severity levels are loaded from
  `crs-metadata.json` at startup (generated by `tools/crs-converter/` at Docker build time).
  Required — `main()` fatals if missing (no fallback). Tests load from `testdata/crs-metadata.json`
  via `TestMain`. `crs_metadata.go` holds the loader, `atomic.Pointer[CRSMetadata]` for
  thread-safe access. `normalizeCRSCategory()` and `IsValidPrefix()` read from loaded metadata.
- **DDoS mitigator**: `caddy-ddos-mitigator` plugin (separate repo: `ergo/caddy-ddos-mitigator`).
  Compiled into Caddy via xcaddy. Uses behavioral IP profiling (path diversity scoring).
  Enforces via 4 layers: L3 nftables kernel drop (primary), L4 TCP RST, L7 HTTP 403, eBPF/XDP NIC drop.
  Immediate nftables sync on jail (v0.14.0+) — zero propagation window between L7 jail and kernel drop.
  CIDR /24 promotion now visible in jail.json and kernel-dropped via nftables interval sets (v0.15.0).
  L4 handler configurable via Caddyfile listener_wrappers (v0.15.0).
  Shares IP jail with wafctl via `/data/waf/jail.json` (bidirectional file sync).
  - wafctl stores: `JailStore`, `DosConfigStore`, `SpikeDetector`, `SpikeReporter`
  - API: `/api/dos/status`, `/api/dos/jail`, `/api/dos/config`, `/api/dos/reports`
  - Dashboard: `/dos` page (`DDoSPanel.tsx`); frontend API in `src/lib/api/dos.ts`
  - Log fields: `ddos_action`, `ddos_fingerprint`, `ddos_z_score`, `ddos_spike_mode`
  - Handler ordering: `order log_append first`, `order ddos_mitigator after log_append`
  - L4 listener wrapper: `servers { listener_wrappers { layer4 { route { ddos_mitigator { ... } } } } }`
  - `SpikeDetector` thresholds updateable at runtime via `PUT /api/dos/config`.
