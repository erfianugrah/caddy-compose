# PLAN.md — WAF Platform Roadmap

## Table of Contents

1. [Current State](#current-state)
2. [Near-Term](#near-term)
3. [Storage Migration: PostgreSQL + Valkey](#storage-migration-postgresql--valkey)
   - [Motivation & Constraints](#motivation--constraints)
   - [What Must NOT Move](#what-must-not-move)
   - [Phase 0: Interface Extraction](#phase-0-interface-extraction-prerequisite)
   - [Phase 1: Config Stores to PostgreSQL](#phase-1-config-stores-to-postgresql-8-stores)
   - [Phase 2: Event Stores to PostgreSQL](#phase-2-event-stores-to-postgresql-3-stores)
   - [Phase 3: IP Jail to Valkey](#phase-3-ip-jail-to-valkey)
   - [Phase 4: Rate Limit Counters to Valkey (Optional)](#phase-4-rate-limit-counters-to-valkey-optional)
   - [Infrastructure Changes](#infrastructure-changes)
   - [Data Migration Strategy](#data-migration-strategy)
   - [Operational Concerns](#operational-concerns)
4. [WebSocket + Stream Deep Inspection](#websocket--stream-deep-inspection)
5. [Edge Caching & Request Coalescing](#edge-caching--request-coalescing)
6. [Proof-of-Work Challenge Action](#proof-of-work-challenge-action)
   - [Motivation](#motivation)
   - [Evaluation Order: 7-Pass Pipeline](#evaluation-order-7-pass-pipeline)
   - [Data Model Changes](#data-model-changes)
   - [Plugin Implementation](#plugin-implementation-caddy-policy-engine)
   - [wafctl Implementation](#wafctl-implementation)
   - [Dashboard Implementation](#dashboard-implementation-waf-dashboard)
   - [Example Rules](#example-rules)
   - [Interaction with Existing Rule Types](#interaction-with-existing-rule-types)
   - [Interaction with Existing Roadmap](#interaction-with-existing-roadmap)
   - [Security Considerations](#security-considerations)
   - [Implementation Phases](#implementation-phases-1)
7. [CRS Converter Fidelity](#crs-converter-fidelity)
8. [Cross-Cutting: Sequencing, Effort & Risk](#cross-cutting-sequencing-effort--risk)
9. [Completed (changelog)](#completed-changelog)

---

## Current State

**v2.83.0 / caddy 3.79.0-2.11.2 / body-matcher v0.2.1 / policy-engine v0.35.0 / ddos-mitigator v0.16.0**

Fully operational WAF with custom policy engine, CRS 4.24.1 (342 rules: 283 inbound +
59 outbound, per-field condition groups), 7-pass evaluation (allow → block → challenge → skip → rate_limit → detect →
response_header), proof-of-work challenge with 5-layer bot scoring (JA4 TLS, HTTP headers,
JS probes, behavioral, spatial inconsistency), JA4 TLS fingerprinting via listener wrapper,
unified rule store (`/api/rules` + `/api/deploy`), response-phase
support for all rule types, structured CORS (preflight + origin validation), rule
templates, per-service category masks, outbound anomaly scoring + rate limiting,
incremental summary (O(hours)), managed lists, IPsum blocklist (571K IPs), CRS
metadata driven by converter (`crs-metadata.json`), auto-update workflow, and e2e CI
pipeline.

DDoS mitigator: behavioral IP profiling, 4-layer enforcement (L3 nftables kernel drop,
L4 TCP RST via caddy-l4 listener wrapper, L7 HTTP 403, eBPF/XDP NIC drop), immediate
nftables sync on jail (zero propagation window), 64-shard IP jail shared with wafctl
via `jail.json` bidirectional file sync + flock, CMS, CIDR /24 aggregation with promoted
prefixes visible in jail API and kernel-dropped via nftables interval sets. L4 handler
configurable via Caddyfile `listener_wrappers`. ~90ns/req hot path. Load tested at
30K RPS from loopback: 0.97% CPU, zero goroutine leaks, instant recovery.

### Codebase

| Area | Files | Tests | Notes |
|---|---|---|---|
| **wafctl** (Go) | 57 source + 29 test | ~1555 test functions, 17 benchmarks | Zero external deps (stdlib only), `package main`, 40K LoC + 20K test LoC |
| **waf-dashboard** (Astro/React) | 38 components + 16 API modules | ~355 tests across 19 files | Astro 6, React 19, TypeScript 5.7, shadcn/ui, Tailwind CSS 4 |
| **e2e** | 16 test files + helpers | ~148 subtests across 67 functions | Go + Docker, stdlib + `gopkg.in/yaml.v3` only |
| **crs-converter** | 13 files | 3 test files, ~51 test functions | Standalone Go tool, zero deps |
| **crs-e2e** | 1 test file + baseline | 4526 tests (baseline-driven) | Go + Docker, official CRS YAML test cases |

### Per-Repo Storage Map

| Repo | Storage Mechanism | Data Volume | Hot Path? |
|---|---|---|---|
| **caddy-body-matcher** | None. Stateless, request-scoped. | 0 | Yes |
| **caddy-policy-engine** | In-memory compiled rules + 16-shard rate-limit counters. Config loaded from JSON file via mtime polling (`policyengine.go:3562-3630`). | ~100K RL keys | Yes |
| **caddy-ddos-mitigator** | 6 in-memory structures (64-shard jail, 4×8192 CMS, Welford stats, 64-shard IP profiles, CIDR aggregator, whitelist) + bidirectional `jail.json` file sync with flock (`mitigator.go:580-672`). | ~100K IPs, 256KB CMS | Yes |
| **caddy-compose/wafctl** | 18 stores: 8 JSON config + 3 JSONL event + jail file + 6 in-memory/specialized. Zero external dependencies. 70 handler functions across 16 files, 82 mux routes. | ~250K events, ~50-200 rules | No |

### wafctl Store Inventory (18 stores)

| # | Store | File | Backing | Public Methods |
|---|---|---|---|---|
| 1 | ExclusionStore | `exclusions.go:25` | `exclusions.json` | 13 |
| 2 | ConfigStore | `config.go:12` | `waf-config.json` | 2 |
| 3 | CSPStore | `csp.go:275` | `csp-config.json` | 5 |
| 4 | SecurityHeaderStore | `security_headers.go:269` | `security-headers.json` | 4 |
| 5 | CORSStore | `cors_store.go:67` | `cors.json` | 3 |
| 6 | ManagedListStore | `managed_lists.go:32` | `lists.json` + `.txt` files | 10 |
| 7 | DefaultRuleStore | `default_rules.go:38` | `default-rules.json` + overrides | 11 |
| 8 | DosConfigStore | `dos_mitigation.go:334` | `dos-config.json` | 2 |
| 9 | JailStore | `dos_mitigation.go:47` | `jail.json` (shared with ddos-mitigator) | 5 |
| 10 | Store (WAF events) | `logparser.go:20` | `events.jsonl` | 22 (across 3 files) |
| 11 | AccessLogStore | `access_log_store.go:195` | `access-events.jsonl` + offset file | 17 (across 3 files) |
| 12 | GeneralLogStore | `general_logs.go:24` | `general-events.jsonl` + offset file | 10 |
| 13 | BlocklistStore | `blocklist.go:28` | In-memory (loads from ManagedListStore) | 6 |
| 14 | SpikeDetector | `spike_detector.go:20` | In-memory (60s sliding window) | 6 |
| 15 | SpikeReporter | `spike_reporter.go:37` | `/data/spike-reports/*.json` files | 4 |
| 16 | IPIntelStore | `ip_intel.go:21` | In-memory cache + external API calls | 1 |
| 17 | GeoIPStore | `geoip.go:31` | MMDB file + in-memory cache | 5 |
| 18 | CFProxyStore | `cfproxy.go:23` | `cf_trusted_proxies.caddy` file | 3 |
| | **Total** | | | **129** |

### Architecture Constraints

**Zero interfaces.** Every handler function accepts concrete `*Store` pointers. There
are no Go interfaces anywhere in wafctl. All ~554 test functions construct real
file-backed stores using `t.TempDir()`. `handleHealth` alone takes 13 concrete store
parameters (`handlers_events.go:18`).

**Zero external deps.** `go.mod` has no `require` block. The entire 40K-line codebase
uses only the Go standard library. This is a deliberate design choice affecting build
times, Docker image size, dependency surface, and testing story.

**Single-package design.** Everything is `package main`, enabling white-box testing but
meaning any interface extraction affects all files in the same compilation unit.

---

## Near-Term

### Production Deployment

- [x] Run `scripts/setup-cors.sh` to configure production CORS origins
- [x] Apply cache-static-assets template via `/api/rules/templates/cache-static-assets/apply`
- [x] Verify CORS preflight + origin validation in production
- [x] Monitor event store disk/memory usage (access: 97K/89MB, general: 49K/89MB — healthy)

---

## Storage Migration: PostgreSQL + Valkey

Migrate wafctl's file-based storage to PostgreSQL (config + events) and Valkey (IP jail),
while keeping all Caddy plugin hot paths in-memory. This eliminates flock-based file
coordination, hand-rolled indexing/filtering code (~1260 lines), and manual rollback
logic (~200 lines), replacing them with transactions, SQL indexes, and a pub/sub channel.

### Motivation & Constraints

#### 1. Hot-Path Latency

The two Caddy plugins (`policy-engine`, `ddos-mitigator`) run inline on every HTTP
request. Current in-memory lookups are sub-microsecond. A network round-trip to Valkey
adds ~0.1-0.5ms; PostgreSQL adds ~0.5-2ms. On a box doing 50K req/s, that is the
difference between no overhead and 25-100 seconds of added latency per second.

**Implication:** Plugin hot paths must stay in-memory. Any Valkey/PG integration must be
async background sync, mirroring the existing file-sync pattern. The plugins already
follow this architecture:
- Policy engine: mtime polling (`policyengine.go:3562-3574`)
- DDoS mitigator: `runFileSync` goroutine (`mitigator.go:580-672`)

#### 2. Zero Interfaces in wafctl

Every handler function accepts concrete `*Store` pointers. There are no Go interfaces
anywhere in the codebase. All ~554 test functions across 29 test files construct real
file-backed stores. You cannot swap a PG-backed implementation without first refactoring
every store and every handler signature.

This is the single largest cost in the migration.

#### 3. The `policy-rules.json` File Contract Is Permanent

The policy-engine plugin reads config from a JSON file via mtime polling (`checkReload()`
at `policyengine.go:3576-3630`). Even with PG as wafctl's source of truth, `deployAll()`
(`deploy.go:107-123`) must still generate and atomically write `policy-rules.json`. The
plugin side does not change at all.

The only plugin-side file that could move to Valkey is `jail.json`, since it is
bidirectionally shared between two separate processes.

#### 4. Breaking Zero External Deps

Adding `pgx` (or `lib/pq`) and a Valkey client breaks wafctl's design principle. Concrete
impacts:
- Docker image size: alpine + wafctl binary goes from ~20MB to ~25-30MB
- Build time: dependency resolution + compilation adds ~10-15s
- Test infrastructure: PG tests need either `testcontainers-go` (~30s CI setup),
  embedded PG, or the file-backed implementation as test double
- Dependency audit surface: `pgx` alone pulls in ~15 transitive deps

This is a one-way door. The benefit must justify the cost.

### What Must NOT Move

| Component | Location | Reason |
|---|---|---|
| **caddy-body-matcher** (entire repo) | `caddy-body-matcher/` | Zero state. Nothing to migrate. |
| **Compiled rules, regex, AC automata** | `policyengine.go:67-114` | Must be in-process for sub-microsecond matching. Read-only after compilation. |
| **Rate limit shards + counters** (hot path) | `ratelimit.go:48-84` | 16-shard in-memory sliding window. Per-request `allow()` must be lock-free within shard. |
| **CMS, adaptive stats, IP profiles** | `cms.go`, `stats.go`, `profile.go` | Ephemeral hot-path structures. CMS decays every 30s. Profiles are LRU-evicted. All restart cleanly. |
| **parsedBody, scoreAccumulator, sync.Pool** | `policyengine.go:362-378` | Request-scoped stack allocations and goroutine-local pools. |
| **nftables/XDP kernel state** | `nftables.go`, `xdp.go` | Kernel data structures. Cannot be externalized. |
| **GeoIP MMDB** | `geoip.go:31` | Binary format read by MaxMind library. Stays as file. |
| **`policy-rules.json` file generation** | `deploy.go:107-123` | Plugin reads this file. Even with PG as source of truth, wafctl still writes it. |
| **Whitelist** | `util.go:94-165` (ddos-mitigator) | Immutable after `Provision()`. `atomic.Pointer` swap. No persistence needed. |
| **CIDR aggregator** | `cidr.go` | Ephemeral counters rebuilt from jail state. |
| **BlocklistStore** | `blocklist.go:28` | In-memory, loaded from ManagedListStore. No persistence. |
| **SpikeDetector** | `spike_detector.go:20` | In-memory 60s sliding window. Ephemeral by design. |
| **IPIntelStore** | `ip_intel.go:21` | In-memory cache + external API calls. No persistence. |
| **CFProxyStore** | `cfproxy.go:23` | Reads Caddy-generated `cf_trusted_proxies.caddy` file. Stays file-based. |

---

### Phase 0: Interface Extraction (Prerequisite)

Pure refactoring with no behavior change. Every test should pass identically afterward.
This unblocks all subsequent phases and improves testability regardless of whether the
PG migration proceeds.

#### Interface Definitions

```go
// interfaces.go — new file in wafctl/

// --- Config Stores ---

type RuleStore interface {
    Version() int
    Count() int
    TagsByName() map[string][]string
    List() []RuleExclusion
    Get(id string) (RuleExclusion, bool)
    Create(e RuleExclusion) (RuleExclusion, error)
    Update(id string, updated RuleExclusion) (RuleExclusion, bool, error)
    Delete(id string) (bool, error)
    Reorder(ids []string) error
    Import(exclusions []RuleExclusion) error
    Export() ExclusionExport
    BulkUpdate(ids []string, action string) (int, error)
    EnabledExclusions() []RuleExclusion
}

type WAFConfigStore interface {
    Get() WAFConfig
    Update(cfg WAFConfig) (WAFConfig, error)
}

type CSPStorer interface {
    Get() CSPConfig
    Update(cfg CSPConfig) (CSPConfig, error)
    ServiceNames() []string
    ResolvePolicy(service string) (CSPPolicy, CSPServiceConfig)
    StoreInfo() map[string]any
}

type SecurityHeaderStorer interface {
    Get() SecurityHeaderConfig
    Update(cfg SecurityHeaderConfig) (SecurityHeaderConfig, error)
    Resolve(service string) ResolvedSecurityHeaders
    StoreInfo() map[string]any
}

type CORSStorer interface {
    Get() CORSConfig
    Update(cfg CORSConfig) (CORSConfig, error)
    StoreInfo() map[string]any
}

type ListStore interface {
    List() []ManagedList
    Get(id string) (ManagedList, bool)
    GetByName(name string) (ManagedList, bool)
    Create(l ManagedList) (ManagedList, error)
    Update(id string, updated ManagedList) (ManagedList, bool, error)
    Delete(id string) (bool, error)
    Import(lists []ManagedList) error
    Export() ManagedListExport
    RefreshURL(id string) (ManagedList, error)
    SyncIPsum(ipsByScore map[int][]string)
}

type DefaultRuleStorer interface {
    CRSVersion() string
    List() []DefaultRuleResponse
    Get(id string) (DefaultRuleResponse, bool)
    SetOverride(id string, override json.RawMessage) error
    RemoveOverride(id string) (bool, error)
    GetOverriddenRules() []PolicyRule
    GetDisabledIDs() []string
    GetOverrides() map[string]json.RawMessage
    ReplaceOverrides(overrides map[string]json.RawMessage) error
    BulkOverride(ids []string, override json.RawMessage) (int, error)
    BulkReset(ids []string) (int, error)
}

type DosConfigStorer interface {
    Get() DosConfig
    Update(cfg DosConfig) error
}

// --- Event Stores ---

type WAFEventStore interface {
    EventCount() int
    Stats() map[string]any
    Snapshot() []Event
    EventByID(id string) *Event
    SnapshotSince(hours int) []Event
    SnapshotRange(start, end time.Time) []Event
    Summary(hours int) SummaryResponse
    FastSummary(hours int) SummaryResponse
    SummaryRange(start, end time.Time) SummaryResponse
    FilteredEvents(service, client, method string, blocked *bool, limit, offset, hours int) EventsResponse
    Services(hours int) ServicesResponse
    ServicesRange(start, end time.Time) ServicesResponse
    IPLookup(ip string, hours, limit, offset int, extraEvents []Event) IPLookupResponse
    IPLookupRange(ip string, tr timeRange, hours, limit, offset int, extraEvents []Event) IPLookupResponse
    IPLookupRangeRaw(ip string, tr timeRange, hours, limit, offset int, rlRaw []RateLimitEvent, lookup *enrichmentLookup) IPLookupResponse
    TopBlockedIPs(hours, n int) []TopBlockedIP
    TopTargetedURIs(hours, n int) []TopTargetedURI
}

type AccessEventStore interface {
    EventCount() int
    Stats() map[string]any
    FastSummary(hours int) SummaryResponse
    SnapshotAsEvents(hours int, rules []RateLimitRule) []Event
    SnapshotAsEventsRange(start, end time.Time, rules []RateLimitRule) []Event
    Summary(hours int) RLSummaryResponse
    FilteredEvents(service, client, method string, limit, offset, hours int) RLEventsResponse
    RuleHits(rules []RateLimitRule, hours int) map[string]RLRuleHitStats
    ScanRates(req RateAdvisorRequest) RateAdvisorResponse
}

type GeneralEventStore interface {
    EventCount() int
    Stats() map[string]any
}

// --- Specialized Stores ---

type JailStorer interface {
    Reload()
    List() []JailEntry
    Count() int
    Add(ip, ttlStr, reason string) error
    Remove(ip string) error
}

type BlocklistStorer interface {
    Stats() BlocklistStatsResponse
    Check(ip string) BlocklistCheckResponse
    Refresh() BlocklistRefreshResponse
}

type SpikeDetecting interface {
    Status() DosStatus
    Mode() string
    EPS() float64
}

type SpikeReporting interface {
    List() []SpikeReport
    Get(id string) *SpikeReport
    Count() int
}

type IPIntel interface {
    Lookup(ip string) *IPIntelligence
}

type GeoResolver interface {
    HasDB() bool
    LookupIP(ip string) string
    Resolve(ip, cfCountry string) string
    HasAPI() bool
    LookupFull(ip, cfCountry string) *GeoIPInfo
}

type CFProxyStorer interface {
    Stats() CFProxyStatsResponse
    Refresh(deployCfg DeployConfig) CFProxyRefreshResponse
}
```

#### Handler Signature Changes

Every handler changes from concrete to interface types. The highest-parameter handlers:

| Handler | File:Line | Current Params | After |
|---|---|---|---|
| `handleHealth` | `handlers_events.go:18` | 13 concrete `*Store` params | 13 interface params |
| `handleDeploy` | `handlers_config.go:64` | `*ConfigStore, *ExclusionStore, *ManagedListStore, *CSPStore, *SecurityHeaderStore, *CORSStore, *DefaultRuleStore, DeployConfig` | `WAFConfigStore, RuleStore, ListStore, CSPStorer, SecurityHeaderStorer, CORSStorer, DefaultRuleStorer, DeployConfig` |
| `handleBackup` | `backup.go:37` | `*ConfigStore, *CSPStore, *SecurityHeaderStore, *ExclusionStore, *ManagedListStore, *DefaultRuleStore` | `WAFConfigStore, CSPStorer, SecurityHeaderStorer, RuleStore, ListStore, DefaultRuleStorer` |
| `generatePolicyData` | `deploy.go:62` | 7 stores + `DeployConfig` | 7 interfaces + `DeployConfig` |

All 70 handlers follow the same transformation. The `main.go` wiring at lines 260-397
changes the constructor calls but route registrations stay identical.

#### Files Changed

| File | Changes |
|---|---|
| `interfaces.go` (new) | ~180 lines of interface definitions |
| `main.go:260-397` | Handler registrations: types in closure args change |
| 16 handler files | 70 handler function signatures |
| `deploy.go` | `generatePolicyData`, `deployAll` params |
| `policy_generator.go` | Functions that accept store pointers |
| 29 test files | Store construction patterns unchanged (concrete types satisfy interfaces) |

#### Test Strategy

Tests currently construct real stores:
```go
// testhelpers_test.go
func newTestExclusionStore(t *testing.T) *ExclusionStore {
    dir := t.TempDir()
    path := filepath.Join(dir, "exclusions.json")
    os.WriteFile(path, []byte(`{"version":6,"exclusions":[]}`), 0644)
    return NewExclusionStore(path)
}
```

After Phase 0, these helpers still work because `*ExclusionStore` satisfies `RuleStore`.
No test logic changes — only handler call sites that explicitly reference the concrete
type in their function signatures need updating. The `handleHealth` test helper
(`testhelpers_test.go:71-87`) will pass the same 13 stores; they just satisfy interfaces
now.

#### Effort: 1-2 weeks. Risk: Low.

Pure refactoring, large diff (~3000+ lines touched across 45+ files), no behavior change.
Run `go vet ./...` and full test suite after every file batch.

---

### Phase 1: Config Stores to PostgreSQL (8 stores)

#### Stores Moving

| Store | Current Backing | Rows | Writes/day | Mutation Methods |
|---|---|---|---|---|
| ExclusionStore | `exclusions.json` | ~50-200 | ~10 | Create, Update, Delete, Reorder, Import, BulkUpdate |
| ConfigStore | `waf-config.json` | 1 + per-service | ~2 | Update |
| CSPStore | `csp-config.json` | ~5-20 services | ~2 | Update |
| SecurityHeaderStore | `security-headers.json` | ~5-20 services | ~2 | Update |
| CORSStore | `cors.json` | ~5-20 services | ~2 | Update |
| ManagedListStore | `lists.json` + `.txt` | ~10 lists, up to 100K items | ~1 | Create, Update, Delete, Import, RefreshURL, SyncIPsum |
| DefaultRuleStore | 2 JSON files | ~300 CRS + overrides | ~5 | SetOverride, RemoveOverride, ReplaceOverrides, BulkOverride, BulkReset |
| DosConfigStore | `dos-config.json` | 1 | Rare | Update |

Also moving: **SpikeReporter** (currently writes individual JSON files to
`/data/spike-reports/*.json`). Low volume, simple schema.

#### Current Mutation Pattern (identical across all 8 stores)

```
1. Acquire s.mu.Lock()
2. old := s.field       // snapshot for rollback
3. s.field = newValue   // apply mutation in-memory
4. err := s.save()      // json.Marshal -> atomicWriteFile
5. if err != nil {
       s.field = old    // rollback in-memory state
       return err
   }
6. return nil
```

Concrete examples with line numbers:
- `ExclusionStore.Create` (`exclusions.go:178-193`): append, save, on error truncate
- `ExclusionStore.Delete` (`exclusions.go:221-238`): full slice copy, splice, save, on error restore
- `ExclusionStore.Reorder` (`exclusions.go:242-277`): save old, rebuild, save, on error restore
- `ConfigStore.Update` (`config.go:205-220`): `old := s.config`, save, on error restore

Every mutation follows this pattern. With PG transactions, the ~200 lines of rollback
logic across all stores disappears. The `atomicWriteFile` function (`util.go`) is no
longer needed for config stores.

#### Schema

```sql
-- ============================================================
-- Config Stores
-- ============================================================

-- ExclusionStore (unified rules)
CREATE TABLE exclusions (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL CHECK (type IN (
        'allow', 'block', 'skip', 'detect',
        'rate_limit', 'response_header', 'honeypot'
    )),
    conditions      JSONB NOT NULL DEFAULT '[]',
    group_operator  TEXT NOT NULL DEFAULT 'and' CHECK (group_operator IN ('and', 'or')),
    service         TEXT DEFAULT '',
    priority        INT NOT NULL DEFAULT 0,
    tags            TEXT[] DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    -- Type-specific fields stored as JSONB to avoid sparse columns
    type_config     JSONB DEFAULT '{}',
    sort_order      INT NOT NULL DEFAULT 0,
    version         INT NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_exclusions_type ON exclusions (type);
CREATE INDEX idx_exclusions_enabled ON exclusions (enabled) WHERE enabled = true;
CREATE INDEX idx_exclusions_sort ON exclusions (sort_order ASC);

-- Versioning table (tracks store-level version counter for export/import)
CREATE TABLE exclusion_store_meta (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    version         INT NOT NULL DEFAULT 6,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ConfigStore (WAF global config + per-service overrides)
CREATE TABLE waf_config (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    defaults        JSONB NOT NULL DEFAULT '{}',
    services        JSONB NOT NULL DEFAULT '{}',
    rate_limit_global JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CSPStore
CREATE TABLE csp_config (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    config          JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- SecurityHeaderStore
CREATE TABLE security_header_config (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    config          JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CORSStore
CREATE TABLE cors_config (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    config          JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ManagedListStore (metadata)
CREATE TABLE managed_lists (
    id              UUID PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('ip', 'uri', 'ua', 'header', 'body', 'custom')),
    source          TEXT DEFAULT '',
    source_url      TEXT DEFAULT '',
    description     TEXT DEFAULT '',
    auto_refresh    BOOLEAN DEFAULT false,
    refresh_hours   INT DEFAULT 0,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ManagedListStore (items — separate table for large lists up to 100K entries)
CREATE TABLE managed_list_items (
    list_id         UUID NOT NULL REFERENCES managed_lists(id) ON DELETE CASCADE,
    item            TEXT NOT NULL,
    PRIMARY KEY (list_id, item)
);

CREATE INDEX idx_list_items_list ON managed_list_items (list_id);

-- DefaultRuleStore (overrides only; base rules are baked into the image)
CREATE TABLE default_rule_overrides (
    rule_id         TEXT PRIMARY KEY,
    override        JSONB NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- DosConfigStore
CREATE TABLE dos_config (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    config          JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- SpikeReporter (replaces individual JSON files in /data/spike-reports/)
CREATE TABLE spike_reports (
    id              TEXT PRIMARY KEY,
    spike_start     TIMESTAMPTZ NOT NULL,
    spike_end       TIMESTAMPTZ NOT NULL,
    peak_eps        DOUBLE PRECISION NOT NULL,
    total_events    BIGINT NOT NULL,
    jail_count      INT NOT NULL DEFAULT 0,
    report          JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

#### Method-by-Method Migration: ExclusionStore (representative)

This is the most complex config store. All others follow the same pattern but simpler.

| Method | Current | PG |
|---|---|---|
| `List()` | `RLock`, copy slice, `RUnlock` | `SELECT * FROM exclusions ORDER BY sort_order` |
| `Get(id)` | Linear scan `for _, e := range s.exclusions` | `SELECT * FROM exclusions WHERE id = $1` |
| `Create(e)` | Append + save + rollback | `INSERT INTO exclusions (...) VALUES (...)` in tx |
| `Update(id, e)` | Find + replace + save + rollback | `UPDATE exclusions SET ... WHERE id = $1` in tx |
| `Delete(id)` | Find + splice + save + rollback | `DELETE FROM exclusions WHERE id = $1` in tx |
| `Reorder(ids)` | Rebuild slice + save + rollback | `UPDATE exclusions SET sort_order = $2 WHERE id = $1` batch |
| `Import(exclusions)` | Replace all + save + rollback | `TRUNCATE exclusions; INSERT INTO ...` in tx |
| `Export()` | `RLock`, copy + version | `SELECT * FROM exclusions; SELECT version FROM exclusion_store_meta` |
| `BulkUpdate(ids, action)` | Full copy + mutate + save + rollback | `UPDATE exclusions SET enabled = $2 WHERE id = ANY($1)` |
| `EnabledExclusions()` | Filter + copy | `SELECT * FROM exclusions WHERE enabled = true ORDER BY sort_order` |

The single-row config stores (ConfigStore, CSPStore, SecurityHeaderStore, CORSStore,
DosConfigStore) are trivial: `Get()` → `SELECT config FROM table WHERE id = 1`,
`Update()` → `UPDATE table SET config = $1 WHERE id = 1`.

#### Deploy Pipeline Impact

`deployAll()` (`deploy.go:107-123`) currently:
1. Acquires `deployMu.Lock()`
2. Calls `generatePolicyData()` which reads from 7 stores via getter methods
3. Writes `policy-rules.json` via `atomicWriteFile`

With PG: Step 2 executes `SELECT` queries instead of reading in-memory state. Step 3
stays unchanged (the plugin reads this file). `deployMu` still serializes deploys.

#### Test Impact

~200 tests across 15 files create file-backed stores. With Phase 0 interfaces:
- **Handler logic tests (~140):** Use existing file-backed stores (they satisfy the
  interfaces). Zero changes needed.
- **Persistence round-trip tests (~60):** Need either:
  - (a) `testcontainers-go` for real PG (recommended for CI)
  - (b) Keep file-backed implementation as test double (fastest)
  - (c) Both: file-backed for unit tests, testcontainers for integration

Recommendation: **(c)**. File-backed stores remain the default test double. A small
`pgstore_test.go` integration test file runs against testcontainers only when
`-tags=integration` is passed. CI runs both.

#### Effort: 2-3 weeks (after Phase 0). Risk: Low.

Mechanical but repetitive. Each store is independent — migrate one at a time. The
`atomicWriteFile` + rollback pattern (~200 lines) is replaced by PG transactions.

---

### Phase 2: Event Stores to PostgreSQL (3 stores)

This is the largest and riskiest phase. ~1260 lines of hand-rolled indexing, filtering,
compaction, and aggregation code are replaced by SQL queries and indexes.

#### Store Characteristics

| Store | Max Rows | Writes/sec | Secondary Indexes | Summary Strategy |
|---|---|---|---|---|
| Store (WAF) | 100K | Bursty | `idIndex map[string]int` | `summaryCounters` (per-hour buckets) |
| AccessLogStore | 100K | ~10-100/s | `idxSource`, `idxClient`, `idxService` | `summaryCounters` (per-hour buckets) |
| GeneralLogStore | 50K | ~100-1000/s (sampled) | None | Full scan in `summarizeGeneralLogs()` |

#### Current Ingestion Pipeline

```
Caddy writes combined-access.log (JSON lines, Caddyfile log directive)
    |
    |-- AccessLogStore.Load() (access_log_store.go:600)
    |     Tails from atomic.Int64 offset
    |     Rotation detection: file_size < offset => reset to 0
    |     Parses JSON, classifies (429/policy/detect/ddos/skip)
    |     Enriches with GeoIP + exclusion tags
    |     Appends to in-memory []RateLimitEvent + 3 secondary indexes
    |     Appends to access-events.jsonl (O_APPEND, fsync)
    |     Updates summaryCounters
    |     Runs eviction (time 90d + count 100K cap at 80%)
    |
    |-- GeneralLogStore.Load() (general_logs.go:238)
    |     Same tailing pattern, separate offset
    |     2xx sampling (configurable rate)
    |     No secondary indexes, no summary counters
    |     Appends to general-events.jsonl
    |
    |-- SpikeDetector.tailLog() (spike_detector.go)
         Same log, third separate offset
         Counts ddos_action events in 1-second sliding window
```

#### New Ingestion Pipeline

```
Caddy writes combined-access.log (unchanged)
    |
    |-- AccessLogStore.Load()
    |     Same tailing + parsing + enrichment
    |     Batch INSERT via pgx.CopyFrom (replaces slice append + JSONL)
    |     summaryCounters: keep in-memory, seed from PG on startup
    |
    |-- GeneralLogStore.Load()
    |     Same tailing + parsing + sampling
    |     Batch INSERT via pgx.CopyFrom
    |
    |-- SpikeDetector (unchanged — in-memory only, never persisted)
```

**Log tailing remains** — Caddy still writes to a file. The tailing, JSON parsing,
classification, and GeoIP enrichment code stays. What changes is the storage target
(PG instead of in-memory slices + JSONL files) and the query path (SQL instead of
hand-rolled filtering).

#### Schema

```sql
-- ============================================================
-- Event Stores
-- ============================================================

-- WAF security events (Store from logparser.go)
CREATE TABLE waf_events (
    id              TEXT PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    client_ip       INET NOT NULL,
    service         TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT '',
    uri             TEXT NOT NULL DEFAULT '',
    status          INT NOT NULL DEFAULT 0,
    protocol        TEXT DEFAULT '',
    user_agent      TEXT DEFAULT '',
    event_type      TEXT NOT NULL DEFAULT '',
    is_blocked      BOOLEAN NOT NULL DEFAULT false,
    blocked_by      TEXT DEFAULT '',
    rule_id         TEXT DEFAULT '',
    rule_name       TEXT DEFAULT '',
    rule_msg        TEXT DEFAULT '',
    tags            TEXT[] DEFAULT '{}',
    anomaly_score   INT DEFAULT 0,
    matched_rules   JSONB DEFAULT '[]',
    country         TEXT DEFAULT '',
    request_headers TEXT DEFAULT '',
    request_body    TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_waf_ts ON waf_events USING BRIN (timestamp);
CREATE INDEX idx_waf_client ON waf_events (client_ip);
CREATE INDEX idx_waf_service ON waf_events (service);
CREATE INDEX idx_waf_type ON waf_events (event_type);
CREATE INDEX idx_waf_rule ON waf_events (rule_id) WHERE rule_id != '';
CREATE INDEX idx_waf_blocked ON waf_events (is_blocked) WHERE is_blocked = true;

-- Access log events (AccessLogStore)
CREATE TABLE access_events (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    client_ip       INET NOT NULL,
    service         TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT '',
    uri             TEXT NOT NULL DEFAULT '',
    status          INT NOT NULL DEFAULT 0,
    protocol        TEXT DEFAULT '',
    user_agent      TEXT DEFAULT '',
    request_id      TEXT DEFAULT '',
    rule_id         TEXT DEFAULT '',
    rule_name       TEXT DEFAULT '',
    anomaly_score   INT DEFAULT 0,
    tags            TEXT[] DEFAULT '{}',
    inline_tags     TEXT[] DEFAULT '{}',
    country         TEXT DEFAULT '',
    request_headers TEXT DEFAULT '',
    request_body    TEXT DEFAULT '',
    ddos_fingerprint TEXT DEFAULT '',
    ddos_z_score    DOUBLE PRECISION DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_access_ts ON access_events USING BRIN (timestamp);
CREATE INDEX idx_access_source ON access_events (source, timestamp DESC);
CREATE INDEX idx_access_client ON access_events (client_ip, timestamp DESC);
CREATE INDEX idx_access_service ON access_events (service, timestamp DESC);
CREATE INDEX idx_access_rule ON access_events (rule_name) WHERE rule_name != '';

-- General log events (partitioned by week for efficient retention)
CREATE TABLE general_events (
    id              BIGINT GENERATED ALWAYS AS IDENTITY,
    timestamp       TIMESTAMPTZ NOT NULL,
    client_ip       INET NOT NULL,
    service         TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT '',
    uri             TEXT NOT NULL DEFAULT '',
    status          INT NOT NULL DEFAULT 0,
    protocol        TEXT DEFAULT '',
    user_agent      TEXT DEFAULT '',
    request_id      TEXT DEFAULT '',
    duration        DOUBLE PRECISION DEFAULT 0,
    tls_version     TEXT DEFAULT '',
    tls_cipher      TEXT DEFAULT '',
    has_csp         BOOLEAN DEFAULT false,
    has_hsts        BOOLEAN DEFAULT false,
    has_xcto        BOOLEAN DEFAULT false,
    has_xfo         BOOLEAN DEFAULT false,
    has_referrer    BOOLEAN DEFAULT false,
    has_cors        BOOLEAN DEFAULT false,
    has_permissions BOOLEAN DEFAULT false,
    ddos_action     TEXT DEFAULT '',
    ddos_z_score    DOUBLE PRECISION DEFAULT 0,
    country         TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Auto-create weekly partitions via pg_partman or application cron.
-- Example manual partitions:
-- CREATE TABLE general_events_w1 PARTITION OF general_events
--     FOR VALUES FROM ('2026-03-16') TO ('2026-03-23');

CREATE INDEX idx_general_ts ON general_events USING BRIN (timestamp);
CREATE INDEX idx_general_service ON general_events (service, timestamp DESC);
CREATE INDEX idx_general_status ON general_events (status, timestamp DESC);
CREATE INDEX idx_general_client ON general_events (client_ip);

-- ============================================================
-- Retention
-- ============================================================

-- Run via pg_cron or application goroutine every hour:
--   DELETE FROM waf_events WHERE timestamp < NOW() - INTERVAL '90 days';
--   DELETE FROM access_events WHERE timestamp < NOW() - INTERVAL '90 days';
--   DROP TABLE IF EXISTS general_events_<old_partition>;  -- instant for partitions
```

#### Summary Aggregation Strategy

The current `summaryCounters` provide O(1) `FastSummary()` — precomputed per-hour buckets
updated incrementally on each event ingestion/eviction. Moving to PG requires a decision:

**Recommended: Hybrid approach.** Keep in-memory `summaryCounters` for the current
session (fast dashboard reads), but seed them from PG on startup and periodically
reconcile. This preserves the existing O(1) read performance while gaining PG durability.

For cold queries (time ranges not in the current counters), fall back to a materialized
view:

```sql
CREATE MATERIALIZED VIEW hourly_summary AS
SELECT
    date_trunc('hour', timestamp) AS hour,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE is_blocked) AS blocked,
    COUNT(*) FILTER (WHERE event_type = 'rate_limited') AS rate_limited,
    COUNT(*) FILTER (WHERE event_type = 'policy_block') AS policy_block,
    COUNT(*) FILTER (WHERE event_type = 'detect_block') AS detect_block,
    COUNT(DISTINCT client_ip) AS unique_clients,
    COUNT(DISTINCT service) AS unique_services
FROM (
    SELECT timestamp, is_blocked, event_type, client_ip, service FROM waf_events
    UNION ALL
    SELECT timestamp, false, source, client_ip, service FROM access_events
) combined
GROUP BY 1;

CREATE UNIQUE INDEX ON hourly_summary (hour);

-- Refresh every 60s via application goroutine:
-- REFRESH MATERIALIZED VIEW CONCURRENTLY hourly_summary;
```

**Behavioral note:** With the materialized view, cold queries (startup, ranges beyond
in-memory window) are up to 60s stale. Hot queries (current session) remain O(1) via
in-memory counters. This is a regression from the current all-in-memory model where
everything is always current. Document this for dashboard users.

#### Query Pattern Translations

The 3 event stores expose ~40 query methods. Five distinct SQL patterns cover them all:

**Pattern 1 — Time-Range Snapshot:**
```sql
SELECT * FROM access_events
WHERE ($1 <= 0 OR timestamp >= NOW() - make_interval(hours => $1))
ORDER BY timestamp ASC;
```

**Pattern 2 — Filtered Pagination** (replaces ~400 lines of in-memory merge-filter):

| wafctl Operator | SQL Equivalent |
|---|---|
| `eq` | `LOWER(field) = LOWER($1)` |
| `neq` | `LOWER(field) != LOWER($1)` |
| `contains` | `field ILIKE '%' \|\| $1 \|\| '%'` |
| `in` | `LOWER(field) = ANY(LOWER_ARRAY($1))` |
| `regex` | `field ~ $1` |

```sql
SELECT * FROM waf_events
WHERE timestamp >= NOW() - make_interval(hours => $1)
  AND ($2 = '' OR LOWER(service) = LOWER($2))
  AND ($3 = '' OR client_ip = $3::inet)
  AND ($4 = '' OR event_type = $4)
ORDER BY timestamp DESC
LIMIT $limit OFFSET $offset;
```

**Pattern 3 — Top-N Analytics:**
```sql
SELECT client_ip, MIN(country) FILTER (WHERE country != '') AS country,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE is_blocked) AS total_blocked,
    MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
FROM waf_events
WHERE timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY client_ip
HAVING COUNT(*) FILTER (WHERE is_blocked) > 0
ORDER BY total_blocked DESC LIMIT 50;
```

**Pattern 4 — General Log Summary with Percentiles:**
```sql
SELECT COUNT(*) AS total,
    AVG(duration) AS avg_duration,
    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY duration) AS p50,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration) AS p95,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration) AS p99,
    COUNT(*) FILTER (WHERE status BETWEEN 200 AND 299) AS status_2xx,
    COUNT(*) FILTER (WHERE status BETWEEN 400 AND 499) AS status_4xx,
    COUNT(*) FILTER (WHERE status >= 500) AS status_5xx
FROM general_events
WHERE timestamp >= NOW() - make_interval(hours => $1);
```

**Pattern 5 — Header Compliance per Service:**
```sql
SELECT service, COUNT(*) AS count,
    AVG(has_csp::int)::numeric(3,2) AS csp_rate,
    AVG(has_hsts::int)::numeric(3,2) AS hsts_rate
FROM general_events
WHERE timestamp >= NOW() - make_interval(hours => $1)
GROUP BY service ORDER BY count DESC LIMIT 20;
```

#### Code Eliminated vs. Retained

**Eliminated (~1260 lines):**

| Code | Lines | Replaced By |
|---|---|---|
| `summaryCounters` + `hourBucket` + `incrementRLEvent` + `decrementRLEvent` + `buildSummary` | ~400 | Materialized view + in-memory cache for hot reads |
| `idxSource`, `idxClient`, `idxService` maps + `rebuildIndexes` + `indexEvent` | ~120 | PG B-tree indexes |
| `searchCutoffRL` + `searchCutoffGeneral` (binary search) | ~60 | `WHERE timestamp >= $1` on BRIN index |
| JSONL append + compaction + smart eviction | ~200 | `INSERT` + partition drop or `DELETE` |
| `fieldFilter` + `matchField` + `matchTags` + operator dispatch | ~400 | SQL `WHERE` clauses |
| Offset tracking + rotation detection | ~80 | Stays (still tailing a log file) |

**Retained:**
- Log tailing (`Load()` method) — Caddy still writes to a file
- JSON line parsing and classification
- GeoIP enrichment
- SpikeDetector (in-memory sliding window, not an event store)
- In-memory `summaryCounters` for hot reads (seeded from PG on startup)

#### ~20 API Handlers Affected

| Handler | File | Change |
|---|---|---|
| `handleSummary` | `handlers_events.go` | Read from in-memory counters (hot) or materialized view (cold) |
| `handleEvents` | `handlers_events.go` | SQL query builder replaces ~300 lines of in-memory merge-filter-paginate |
| `handleServices` | `handlers_events.go` | `GROUP BY service` query |
| `handleTopBlockedIPs` | `handlers_analytics.go` | `GROUP BY client_ip HAVING blocked > 0` |
| `handleTopTargetedURIs` | `handlers_analytics.go` | `GROUP BY uri` |
| `handleTopCountries` | `handlers_analytics.go` | `GROUP BY country` |
| `handleIPLookup` | `handlers_analytics.go` | `WHERE client_ip = $1` + aggregation |
| `handleRLSummary` | `handlers_ratelimit.go` | `GROUP BY` on access_events |
| `handleRLEvents` | `handlers_ratelimit.go` | SQL query builder |
| `handleRLRuleHits` | `handlers_ratelimit.go` | `GROUP BY rule_name` |
| `handleRLAdvisor` | `handlers_ratelimit.go` | SQL query + response cache |
| `handleExclusionHits` | `handlers_exclusions.go` | `GROUP BY rule_id JOIN exclusions` |
| `handleGeneralLogs` | `general_logs_handlers.go` | SQL query builder |
| `handleGeneralLogsSummary` | `general_logs_handlers.go` | SQL aggregation |

#### Query Builder Design

The `handleEvents` handler is the most complex — it currently does ~300 lines of
in-memory merge-filter-paginate across both WAF and access event stores. The SQL
replacement needs a query builder that:

1. Accepts the same filter parameters (`service`, `client`, `method`, `blocked`, `event_type`, plus operator variants)
2. Builds parameterized SQL (never string interpolation)
3. Handles the UNION ALL across `waf_events` and `access_events` with schema mapping
4. Supports all 5 filter operators (`eq`, `neq`, `contains`, `in`, `regex`)
5. Returns paginated results with total count

Recommend a simple builder pattern — not a full ORM. Something like:

```go
type queryBuilder struct {
    table   string
    where   []string
    args    []any
    orderBy string
    limit   int
    offset  int
}

func (qb *queryBuilder) addFilter(field, value, op string) {
    if value == "" { return }
    qb.args = append(qb.args, value)
    p := fmt.Sprintf("$%d", len(qb.args))
    switch op {
    case "eq":       qb.where = append(qb.where, fmt.Sprintf("LOWER(%s) = LOWER(%s)", field, p))
    case "neq":      qb.where = append(qb.where, fmt.Sprintf("LOWER(%s) != LOWER(%s)", field, p))
    case "contains": qb.where = append(qb.where, fmt.Sprintf("%s ILIKE '%%' || %s || '%%'", field, p))
    case "regex":    qb.where = append(qb.where, fmt.Sprintf("%s ~ %s", field, p))
    }
}
```

This keeps wafctl's stdlib-ish style (no ORM dep) while the actual PG driver (`pgx`)
handles connection pooling and parameterization.

#### Effort: 5-7 weeks (after Phase 0). Risk: Medium-High.

The original estimate of 4-5 weeks is optimistic. The complexity is in:
1. The `handleEvents` query builder (~300 lines of logic to replicate in SQL)
2. The UNION ALL schema mapping between `waf_events` and `access_events`
3. Batch insert pipeline with `pgx.CopyFrom` (backpressure, error handling, retry)
4. Materialized view tuning without degrading `/api/summary` latency
5. Rewriting ~80 tests that inject events directly under lock
6. The `summaryCounters` hybrid (in-memory + PG seed) requires careful startup sequencing

---

### Phase 3: IP Jail to Valkey

Replace the `jail.json` bidirectional file sync + flock with Valkey. This is the highest
architectural payoff: eliminates flock coordination between two separate processes,
replaces polling with pub/sub for near-instant propagation, and uses native TTL for
automatic expiration.

#### Current Bidirectional Sync

The plugin and wafctl share jail state via `jail.json` with flock-based coordination:

**Plugin side** (`mitigator.go:580-672`, runs every 2s under flock):
1. Snapshot current jail state before read
2. Read file, merge new entries (file entries don't overwrite existing jail entries)
3. Detect unjails: if IP was in snapshot, predates file write, but absent from file → wafctl removed it
4. Write file if dirty flag set

**wafctl side** (`dos_mitigation.go:47`): reads/writes the same file with flock.

**Struct definitions are byte-identical between processes:**

| Plugin (`util.go:221-226`) | wafctl (`dos_mitigation.go`) |
|---|---|
| `jailFileEntry` | `jailFileEntry` (same fields) |
| `jailFileFormat` | `jailFile` (same fields, different name) |

#### Valkey Key Schema

```
# Per-IP jail entry (hash with native TTL)
HSET jail:{ip} expires_at {RFC3339} infractions {int} reason {string} jailed_at {RFC3339}
EXPIREAT jail:{ip} {unix_seconds}

# Jail membership set (for efficient SMEMBERS / diff operations)
SADD jail:ips {ip}

# Pub/sub channel for instant propagation (replaces 2s file polling)
PUBLISH jail:changes '{"action":"add","ip":"192.168.1.100","ttl":3600}'
PUBLISH jail:changes '{"action":"remove","ip":"192.168.1.100"}'

# Metadata
SET jail:version 1
```

#### New Sync Flow: Plugin Side

Replace `runFileSync` (`mitigator.go:580-672`) with `runValkeySync`:

```
runValkeySync (every 5s + pub/sub listener):

1. beforeSync := m.jail.Snapshot()

2. valkeyIPs := SMEMBERS jail:ips
   For each IP in valkeyIPs:
     If !jail.IsJailed(ip):
       entry := HGETALL jail:{ip}
       If not expired:
         jail.Add(ip, ttl, entry.reason, entry.infractions)

3. For each IP in beforeSync:
   a. If !jail.IsJailed(ip):           // expired naturally
      SREM jail:ips {ip}
      DEL jail:{ip}
      tracker.Reset(ip)
   b. If jail.IsJailed(ip) && ip NOT in valkeyIPs:
      jail.Remove(ip)                   // wafctl removed it
      cidr.DecrementPrefix(ip)
      tracker.Reset(ip)

4. For each newly jailed IP (dirty):
   HSET jail:{ip} ...
   EXPIREAT jail:{ip} ...
   SADD jail:ips {ip}
   PUBLISH jail:changes {"action":"add","ip":...}
```

The pub/sub listener runs in a separate goroutine, handling `add`/`remove` messages
for near-instant propagation (replaces the 2s file poll interval).

#### New Flow: wafctl Side

Replace `JailStore` file I/O (`dos_mitigation.go:47-190`) with Valkey client:

| Method | Current | Valkey |
|---|---|---|
| `Reload()` | Read file under flock | `SMEMBERS jail:ips` → `HGETALL` for each |
| `List()` | Read file, filter expired | `SMEMBERS` → `HGETALL`, filter expired |
| `Add(ip, ttl, reason)` | Write file under flock | `HSET` + `EXPIREAT` + `SADD` + `PUBLISH` |
| `Remove(ip)` | Write file under flock | `DEL` + `SREM` + `PUBLISH` |
| `Count()` | `len(entries)` | `SCARD jail:ips` |

#### Files Changed

| File | Current | New |
|---|---|---|
| `ddos-mitigator/util.go:80-92` | `withFileLock()` (flock) | Remove entirely |
| `ddos-mitigator/util.go:172-202` | `atomicWriteFile()` for jail | Remove (keep for non-jail uses) |
| `ddos-mitigator/util.go:207-338` | `jailFileFormat`, `writeJailFile`, `readJailFileIPs` | Replace with `valkey_sync.go` |
| `ddos-mitigator/mitigator.go:580-672` | `runFileSync()` | Replace with `runValkeySync()` |
| `ddos-mitigator/mitigator.go:254-263` | Jail file load at startup | Valkey `SMEMBERS` + `HGETALL` |
| `ddos-mitigator/go.mod` | 5 direct deps | +1: `github.com/valkey-io/valkey-go` |
| `wafctl/dos_mitigation.go:47-190` | `JailStore` with file I/O + flock | `JailStore` with Valkey client |
| `compose.yaml` | No Valkey service | Add Valkey service on `waf` network |
| `Caddyfile` | `jail_file /data/waf/jail.json` | `jail_valkey valkey://172.19.98.4:6379` |

#### Race Condition: Concurrent Jail Additions

With file-based sync, flock serializes all writes. With Valkey, both the plugin and
wafctl can `HSET` the same IP simultaneously with different `infractions` counts. The
last write wins. This is acceptable — jail semantics are "at least once" and the
infraction count is used only for exponential backoff TTL calculation. The worst case
is a slightly shorter or longer TTL on the second jailing, which self-corrects on the
next infraction.

If this becomes a problem, use `WATCH`/`MULTI`/`EXEC` (optimistic locking) on the
per-IP hash. But don't add this complexity upfront.

#### Graceful Degradation

| Scenario | Current (file) | New (Valkey) |
|---|---|---|
| Missing at startup | Empty jail, module starts | Empty jail, module starts |
| Unavailable during sync | Log warning, skip cycle | Log warning, skip cycle |
| Connection lost mid-operation | N/A (atomic file I/O) | Retry with backoff, fall back to in-memory |
| Write failure | Restore dirty flag, retry next cycle | Retry next cycle |

**The plugin must never block on Valkey.** All Valkey operations use `context.WithTimeout`
(500ms). On any error, the plugin continues with in-memory state. The jail is
authoritative in-memory; Valkey is the coordination channel.

#### Effort: 2-3 weeks. Risk: Medium.

The `runFileSync` logic (92 lines) is well-isolated. The flock + atomicWriteFile
machinery (~170 lines in `util.go`) is eliminated. The bigger work is adding the Valkey
client to both repos, handling connection lifecycle, and adding the `jail_valkey`
Caddyfile directive to the ddos-mitigator plugin.

---

### Phase 4: Rate Limit Counters to Valkey (Optional)

#### Current

In-process 16-shard sliding window counters in `caddy-policy-engine/ratelimit.go:48-84`.
~100K keys max per zone. Swept every 30s. Zones preserved across hot-reloads if config
unchanged (`ratelimit.go:205-236`).

```go
type counter struct {
    prevCount int64
    prevStart int64    // unix nanoseconds
    currCount int64
    currStart int64
}
// Effective count = prevCount * (1 - elapsed/window) + currCount
```

#### When This Is Needed

Multi-instance Caddy deployment only. Currently, `compose.yaml` uses `network_mode: host`
with a single Caddy instance — two instances would have independent rate limit state,
allowing an attacker to split traffic and get double the allowed rate.

#### Approach: Background Sync Only

```
Hot path (zone.allow, ratelimit.go:111-170):
  UNCHANGED — in-memory shard lookup + increment

Background goroutine (every 10s):
  For each zone, for each shard, for each counter with currCount > 0:
    INCRBY rl:{zone_id}:{rate_key} currCount
    EXPIRE key {2 * window}

Startup:
  SCAN rl:{zone_id}:*
  Seed in-memory counters from Valkey values
```

Distributed counters are inherently approximate. With two instances:
- Each maintains local counters (current behavior)
- Background sync exports deltas to Valkey via `INCRBY`
- Global count = Valkey value (sum of all instances)
- Each instance periodically reads global count; if it exceeds limit: preemptive rate limit

Eventually consistent with ~10s window. Acceptable for rate limiting.

#### Effort: 3-4 weeks. Risk: Medium.

Requires `go.mod` change in policy-engine, Valkey client integration, sync protocol,
and graceful degradation. **Skip unless running multiple Caddy instances.**

---

### Infrastructure Changes

#### compose.yaml Additions

```yaml
services:
  postgres:
    image: postgres:17-alpine
    container_name: postgres
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    deploy:
      resources:
        limits: { cpus: "2", memory: 512M }
        reservations: { cpus: "0.5", memory: 128M }
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U waf"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      waf:
        ipv4_address: 172.19.98.3
    volumes:
      - /mnt/user/data/postgres:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init.sql:ro
    tmpfs:
      - /tmp:size=64M
      - /run/postgresql:size=16M
    environment:
      POSTGRES_USER: waf
      POSTGRES_PASSWORD_FILE: /run/secrets/pg_password
      POSTGRES_DB: wafctl
      TZ: Asia/Singapore

  valkey:
    image: valkey/valkey:8-alpine
    container_name: valkey
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    deploy:
      resources:
        limits: { cpus: "1", memory: 256M }
        reservations: { cpus: "0.25", memory: 64M }
    healthcheck:
      test: ["CMD", "valkey-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    networks:
      waf:
        ipv4_address: 172.19.98.4
    volumes:
      - /mnt/cache/valkey/data:/data
    tmpfs:
      - /tmp:size=32M
    environment:
      TZ: Asia/Singapore
```

#### Updated Dependency Chain

```
postgres (healthy) + valkey (healthy)
    -> authelia (healthy)
        -> caddy (healthy)
            -> wafctl
```

#### wafctl Environment Additions

```yaml
environment:
  WAF_DATABASE_URL: "postgres://waf:${PG_PASSWORD}@172.19.98.3:5432/wafctl?sslmode=disable"
  WAF_VALKEY_URL: "valkey://172.19.98.4:6379"
  WAF_STORAGE_BACKEND: "postgres+valkey"  # or "file" for rollback
```

#### Volume Changes After Full Migration

| Volume | Before | After |
|---|---|---|
| `/mnt/cache/caddy/waf/policy-rules.json` | wafctl writes, caddy reads | **Unchanged** |
| `/mnt/cache/caddy/waf/jail.json` | Bidirectional file sync + flock | **Eliminated** |
| `/mnt/cache/caddy/waf/jail.json.lock` | flock coordination | **Eliminated** |
| `/mnt/cache/caddy/wafctl/config/*.json` | 8 JSON config stores | **Eliminated** |
| `/mnt/user/data/wafctl/events/*.jsonl` | 3 JSONL event stores + offsets | **Eliminated** |
| `/mnt/cache/caddy/log/combined-access.log` | caddy writes, wafctl tails | **Unchanged** |

#### Makefile Targets

```makefile
db-migrate:           ## Run PG schema migrations
db-seed:              ## One-time: seed PG from existing JSON files
db-reset:             ## Drop and recreate PG schema (destructive)
db-backup:            ## pg_dump to compressed file
db-restore:           ## pg_restore from dump
db-shell:             ## Interactive psql
valkey-shell:         ## Interactive valkey-cli
```

---

### Data Migration Strategy

#### Migration Tool: `wafctl migrate-to-pg`

New CLI subcommand that reads existing JSON/JSONL files and populates PG:

```
wafctl migrate-to-pg [--database-url postgres://...] [--dry-run]

Steps:
 1. Read exclusions.json         -> INSERT INTO exclusions
 2. Read waf-config.json         -> INSERT INTO waf_config
 3. Read csp-config.json         -> INSERT INTO csp_config
 4. Read security-headers.json   -> INSERT INTO security_header_config
 5. Read cors.json               -> INSERT INTO cors_config
 6. Read lists.json + *.txt      -> INSERT INTO managed_lists + managed_list_items
 7. Read default-rule-overrides  -> INSERT INTO default_rule_overrides
 8. Read dos-config.json         -> INSERT INTO dos_config
 9. Read events.jsonl            -> COPY INTO waf_events        (pgx.CopyFrom)
10. Read access-events.jsonl     -> COPY INTO access_events     (pgx.CopyFrom)
11. Read general-events.jsonl    -> COPY INTO general_events    (pgx.CopyFrom)
12. Read spike-reports/*.json    -> INSERT INTO spike_reports
```

Steps 9-11 use `pgx.CopyFrom` for bulk loading — orders of magnitude faster than
individual INSERTs for 100K+ rows.

#### Feature Flag: `WAF_STORAGE_BACKEND`

```
file              — current behavior (default)
postgres          — PG for config + event stores, file for jail
postgres+valkey   — PG + Valkey (full migration)
```

Deploy new code with `file` first. Run `migrate-to-pg`. Switch to `postgres` with a
container restart. Rollback is switching back to `file`.

#### Rollback Plan

JSON files are never deleted during migration. If PG fails:
1. Set `WAF_STORAGE_BACKEND=file`
2. Restart wafctl
3. wafctl reads from JSON files as before

For the jail (Phase 3), if Valkey fails:
1. The plugin automatically degrades to in-memory-only (500ms context timeout)
2. wafctl falls back to file-based JailStore via the same feature flag

#### Schema Evolution

Use embedded SQL migration files (not an external tool like golang-migrate, to minimize
deps). Pattern:

```go
//go:embed migrations/*.sql
var migrationsFS embed.FS

func runMigrations(pool *pgxpool.Pool) error {
    // Read applied versions from schema_migrations table
    // Apply any unapplied .sql files in order
}
```

Migration files named `001_initial_schema.sql`, `002_add_index.sql`, etc. Each runs in
a transaction. `schema_migrations` table tracks applied versions.

---

### Operational Concerns

#### Connection Pooling

wafctl needs `pgxpool` (not raw `pgx.Conn`). Sizing:

- 70 HTTP handlers × concurrent requests (bounded by container CPU limit of 2 cores)
- 3 log tailing goroutines doing batch inserts
- 1 materialized view refresh goroutine
- 1 retention cleanup goroutine

Recommended pool config:
```go
poolConfig.MaxConns = 20              // sufficient for 2-core container
poolConfig.MinConns = 4               // keep warm for handler latency
poolConfig.MaxConnLifetime = 30 * time.Minute
poolConfig.MaxConnIdleTime = 5 * time.Minute
poolConfig.HealthCheckPeriod = 30 * time.Second
```

PG side: `max_connections = 50` (default 100 is fine; 20 from wafctl, leave headroom
for psql sessions, migrations, monitoring).

#### Partition Maintenance

`general_events` is partitioned by week. Partitions must be created ahead of time.
If partition creation fails, inserts into the missing range fail silently or error.

Options:
1. **pg_partman extension** — auto-creates partitions. Requires the extension to be installed.
2. **Application cron** — a goroutine in wafctl creates next week's partition every Monday.
3. **Pre-create 12 weeks ahead** — manual, low maintenance for a single deployment.

Recommend **(2)** for self-contained operation. The goroutine runs at startup and daily,
creating partitions up to 4 weeks ahead. On failure, log an error and retry next cycle.

#### Backup & Restore

PG backup replaces the current JSON file backup (`/api/backup` endpoint):

- **Daily automated:** `pg_dump -Fc` via a cron job or compose sidecar
- **On-demand:** `make db-backup` / `make db-restore`
- **The existing `/api/backup` endpoint** continues to work — it reads from the store
  interfaces, which now return data from PG. The export format (JSON) stays identical
  for user-facing backups.

Valkey does not need backup — jail state is ephemeral (all entries have TTLs) and is
reconstructed from the plugin's in-memory jail on the next sync cycle.

#### Monitoring & Alerting

Neither PG nor Valkey will have monitoring initially. Add these when the migration
stabilizes:

**Must-have (wafctl application-level):**
- PG connection pool stats: active/idle/total connections, wait count, wait duration
  (`pgxpool.Stat()` — expose via `/api/health` response)
- Query latency: track P50/P95/P99 for the 5 most-called queries (summary, events,
  top-N, deploy, batch insert)
- Valkey latency: round-trip time for `SMEMBERS` + `HGETALL` during jail sync
- Materialized view freshness: `last_refresh_at` timestamp in `/api/health`

**Nice-to-have (infrastructure-level, can add later):**
- `pg_stat_statements` for query-level performance
- PG disk usage per table (`pg_total_relation_size`)
- Valkey `INFO memory` / `INFO keyspace`
- Prometheus metrics endpoint (new, not currently in stack)

#### Graceful Degradation Matrix

| Component Down | Impact | Mitigation |
|---|---|---|
| **PG down at startup** | wafctl cannot start | Fail fast with clear error. Compose `depends_on: postgres: condition: service_healthy` prevents this. |
| **PG down during operation** | Config reads fail, event inserts fail | Return cached in-memory state for reads (stale but available). Buffer events in memory (bounded ring buffer, ~10K events). Retry PG connection with exponential backoff. Log warnings. |
| **PG slow (>2s queries)** | Dashboard latency degrades | Connection pool timeout (5s). Handler-level context timeout (10s). `/api/health` reports degraded status. |
| **Valkey down at startup** | Jail starts empty | Plugin continues with in-memory jail. First sync cycle will populate from Valkey when it recovers. |
| **Valkey down during operation** | Jail sync fails, no pub/sub | Plugin and wafctl continue with in-memory state. Jail changes aren't coordinated until Valkey recovers. 500ms context timeout prevents blocking. |
| **Valkey slow** | Jail sync delays | Same 500ms timeout. Skip cycle, retry next interval. |

#### Security

- PG password via Docker secret (`POSTGRES_PASSWORD_FILE`), not environment variable
- PG listens only on `172.19.98.3` (waf network), not exposed to host
- Valkey has no auth by default; add `requirepass` via config volume if needed
- Both services are `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`
- `sslmode=disable` is acceptable on a Docker bridge network with no external exposure

---

## WebSocket + Stream Deep Inspection

MITM proxy for WebSocket frame inspection and SSE event inspection. The policy engine
currently evaluates the HTTP upgrade request but hands off the raw TCP connection after
101 Switching Protocols — zero visibility into frame-level traffic. The
`responseHeaderWriter` in the plugin already implements `http.Hijacker`, which is the
extension point for intercepting the connection handoff.

### Architecture

```
Client ←TCP→ [Caddy] ←hijack→ [Policy Engine MITM Proxy] ←TCP→ Upstream
                                    ↓
                              Frame Parser (RFC 6455)
                                    ↓
                              Condition Evaluator
                              (ws_payload, ws_opcode, sse_data, sse_event_type)
                                    ↓
                         ┌──────────┴──────────┐
                         │                     │
                    Action: tap            Action: block
                    (log + forward)        (close + emit event)
                         │                     │
                         ↓                     ↓
                    wafctl API             Close frame 1008
                    (POST /api/stream/events)  (Policy Violation)
```

**Two modes per rule:**
- **tap** (default) — log the frame/event, forward to upstream. Visibility without risk.
- **block** — close the connection with status 1008 (Policy Violation), emit event.

**SSE path** — different mechanism: wrap the `http.ResponseWriter` before calling
`next.ServeHTTP()`. Detect `Content-Type: text/event-stream`, intercept `Write()` calls,
parse SSE field boundaries (`data:`, `event:`, `id:`, `retry:`), run conditions against
parsed fields.

### Data Model Changes

**New phase: `"stream"`** — added to `validPhases`. Stream-phase rules only evaluate
during WebSocket frame or SSE event processing, never during HTTP request/response.

**New condition fields:**

| Field | Type | Description | Available in |
|-------|------|-------------|-------------|
| `ws_payload` | string | Text frame payload (UTF-8) | WebSocket |
| `ws_opcode` | string | Frame opcode: `"text"`, `"binary"`, `"ping"`, `"pong"` | WebSocket |
| `ws_direction` | string | `"client_to_server"` or `"server_to_client"` | WebSocket |
| `ws_size` | numeric | Payload byte length | WebSocket |
| `sse_data` | string | SSE `data:` field content | SSE |
| `sse_event_type` | string | SSE `event:` field value | SSE |
| `sse_id` | string | SSE `id:` field value | SSE |
| `connection_id` | string | Unique per-WS/SSE connection (UUID) | Both |

All existing inbound fields (`ip`, `path`, `host`, `user_agent`, etc.) remain available
in stream-phase rules — captured from the original upgrade request and attached to the
connection context.

**New event types:** `ws_blocked`, `ws_tapped`, `sse_blocked`, `sse_tapped`

**New Event struct fields:**

```go
ConnectionID   string `json:"connection_id,omitempty"`
StreamType     string `json:"stream_type,omitempty"`      // "websocket" or "sse"
FrameDirection string `json:"frame_direction,omitempty"`
FrameOpcode    string `json:"frame_opcode,omitempty"`
FramePayload   string `json:"frame_payload,omitempty"`    // truncated to 4KB
FrameSize      int    `json:"frame_size,omitempty"`
SSEEventType   string `json:"sse_event_type,omitempty"`
SSEData        string `json:"sse_data,omitempty"`         // truncated to 4KB
```

### Connection-Level Rate Limiting

New rate limit rule subtype for `phase: "stream"`:

```json
{
  "type": "rate_limit",
  "phase": "stream",
  "service": "dockge.erfi.io",
  "stream_rate": {
    "frames_per_second": 100,
    "bytes_per_second": 1048576,
    "window": "1s",
    "action": "block"
  },
  "conditions": [
    { "field": "ws_direction", "operator": "eq", "value": "client_to_server" }
  ]
}
```

Rate counters are per-connection (keyed by `connection_id`), not per-IP. Prevents a
single chatty connection from consuming resources while allowing many connections from
the same IP.

### Plugin Changes (caddy-policy-engine)

All frame parsing and MITM logic lives in the plugin. wafctl is not in the hot path.

| New File | Purpose |
|----------|---------|
| `ws_frame.go` | RFC 6455 frame reader/writer: masking, fragmentation reassembly, control frame handling, max frame size (configurable, default 1MB) |
| `ws_proxy.go` | MITM proxy: hijack, dial upstream, bidirectional pump with frame-boundary awareness |
| `ws_inspect.go` | Field extraction, compiled condition evaluation, tap/block action dispatch |
| `sse_wrapper.go` | `ResponseWriter` wrapper: detect `text/event-stream`, buffer to SSE field boundaries, parse, inspect |
| `stream_rate.go` | Per-connection token bucket: frames/sec and bytes/sec. Connection map with cleanup on close. |

**Caddyfile directive:**

```caddyfile
policy_engine {
    rules_file /data/waf/policy-rules.json
    stream_inspection {
        enabled true
        max_frame_size 1MB
        max_payload_log 4KB
        connection_timeout 24h
    }
}
```

Event emission: the plugin POSTs batched frame events to wafctl via
`POST /api/stream/events` (max 100 events/sec), same fire-and-forget pattern as the
DDoS mitigator's jail sync.

### SSE Wrapper: Partial Field Edge Case

SSE fields can span multiple `Write()` calls from the upstream. The wrapper must handle:

1. **Partial field:** Upstream flushes `data:hello ` in one `Write()` and `world\n\n` in
   the next. The wrapper must buffer until it sees `\n\n` (end of event) before inspecting.
2. **Write-through guarantee:** Every `Write()` call must be forwarded to the underlying
   `ResponseWriter` immediately for streaming. The wrapper inspects a copy, not the
   original bytes.
3. **Buffer bounds:** Cap the SSE field buffer at 64KB per connection. If an SSE event
   exceeds this, flush without inspection and log a warning.

Implementation: ring buffer per connection, scan for `\n\n` boundaries on each `Write()`.
Completed events are dispatched to the condition evaluator. The original bytes pass through
unconditionally — blocking happens by closing the response, not by withholding data.

### wafctl Changes

**New API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/stream/events` | Receive batched stream events from plugin |
| `GET` | `/api/stream/connections` | List active WS/SSE connections |
| `GET` | `/api/stream/connections/{id}` | Connection detail + recent frames |
| `GET` | `/api/stream/stats` | Aggregate: connections/sec, frames/sec, top talkers |

**Validation changes:**
- `validPhases`: add `"stream"`
- `validConditionFields`: add all stream fields
- `validStreamFields` (new): fields only valid when `phase: "stream"`
- `wafEventTypes`: add `ws_blocked`, `ws_tapped`, `sse_blocked`, `sse_tapped`

**Stream event store:** Separate from the main event store (high-volume, short-lived).
Ring buffer, 100K events max, 1-hour TTL. If PG is available (Phase 2), optionally
persist to a `stream_events` table with aggressive retention (24h).

### Frontend Changes (waf-dashboard)

**New page: `/streams`** (`StreamsPanel.tsx`):
- Connection list: table with connection_id, service, path, client IP, type (WS/SSE),
  duration, frames, status (active/closed/blocked)
- Connection detail: frame timeline (last 50 frames), direction arrows, matched rules
- Stream stats cards: active connections, frames/sec, tapped/sec, blocked/sec
- Stream rules: filtered view of `phase: "stream"` rules, reuses existing CRUD components

**Existing page updates:**
- Overview dashboard: stream event counts in timeline
- Event log: stream events with `ws_blocked`/`sse_tapped` badges, filterable
- Policy engine: stream-phase rules in rule list, condition builder with stream fields

### Implementation Phases

```
Phase 1 ──→ Phase 2 ──→ Phase 3 ──┬──→ Phase 5 ──→ Phase 7
                                   │
                        Phase 4 ───┘
                                   │
                        Phase 6 ───┘ (can start after Phase 3 API exists)
```

| Phase | Scope | Est. |
|-------|-------|------|
| 1. WS frame parser | `ws_frame.go`: RFC 6455 read/write, masking, fragmentation, control frames, max size | ~2 days |
| 2. MITM proxy | `ws_proxy.go`: hijack, dial upstream, bidirectional pump, graceful shutdown | ~2 days |
| 3. Frame inspection + tap/block | `ws_inspect.go` + wafctl `POST /api/stream/events` + validation + E2E | ~2.5 days |
| 4. SSE inspection | `sse_wrapper.go`: ResponseWriter wrapper, field parser, partial field buffering | ~2 days |
| 5. Connection rate limiting | `stream_rate.go`: per-connection token bucket, connection map with TTL | ~1.5 days |
| 6. Dashboard | `/streams` page, stats cards, stream rule CRUD, event badges | ~2 days |
| 7. Integration + hardening | Caddyfile wiring, hot-reload, memory bounds, metrics, full E2E | ~1.5 days |

**Total: ~13.5 days** (revised up from 12 — SSE partial field buffering and the E2E
scope in Phase 3 are underestimated in the original plan).

### Risk Assessment

| Risk | Mitigation |
|------|-----------|
| MITM adds latency to every WS frame | Inspect only when stream rules exist; bypass when no rules match |
| High-volume connections overwhelm event store | Ring buffer 100K cap + 1h TTL; batch emission (100/sec max) |
| Binary WS frames (protobuf, msgpack) | `ws_payload` only for text frames; binary inspectable via `ws_size`/`ws_opcode` only |
| SSE wrapper breaks streaming | Write-through: forward immediately, inspect a copy. Buffer only to SSE field boundaries. |
| SSE partial fields across Write() calls | Ring buffer with 64KB cap, `\n\n` boundary scanning, flush without inspection on overflow |
| Plugin upgrade requires Caddy restart | Stream rules hot-reload via `policy-rules.json`; plugin code changes need xcaddy rebuild |
| Reconnection storms | Per-IP connection rate limit (separate from per-connection frame rate limit) |

---

## Edge Caching & Request Coalescing

Run Caddy as a full edge server with HTTP response caching, request coalescing
(thundering herd protection), and stale-while-revalidate — replacing the need for a
separate Varnish/Nginx caching layer.

### RFC Foundations

**RFC 9111 (HTTP Caching):**
- Section 4 ¶7 — Request collapsing is explicitly permitted (MAY)
- Section 2 — Cache key: minimum `method + target URI`, must incorporate `Vary` headers
- Section 4.2.1 — Freshness precedence: `s-maxage` > `max-age` > `Expires` > heuristic
- Section 4.2.4 — Shared caches MUST NOT serve stale unless permitted by RFC 5861
- Section 5.2.2.7 — `private` responses: shared caches MUST NOT store
- Section 5.2.2.10 — `s-maxage` overrides `max-age`, implies `proxy-revalidate`

**RFC 5861 (Stale Content Extensions):**
- `stale-while-revalidate` — serve stale instantly, one async revalidation. Zero latency
  for N-1 clients. The single most effective thundering herd defense.
- `stale-if-error` — on 500/502/503/504, serve stale instead of cascading retries.

**RFC 8246** — `Cache-Control: immutable`. Skip conditional revalidation while fresh.
Ideal for versioned/fingerprinted static assets.

**RFC 9211** — `Cache-Status` structured header for hit/miss/revalidated reporting.

### CDN Implementation Survey

| Capability | Varnish | Nginx | Caddy + Souin |
|---|---|---|---|
| Coalescing | Automatic + per-req toggle | `proxy_cache_lock` + timeout/age | `singleflight` (no timeout) |
| Grace / SWR | Mature, per-request override | `background_update` + `use_stale` | `stale` directive |
| Hit-for-pass | Native | Lock timeout as bypass | **Not documented** |
| Coalescing timeout | Backend timeouts | `lock_timeout` / `lock_age` | **None — hung origin blocks all** |
| Streaming cache | `beresp.do_stream` | Inherent in proxy_cache | **Not supported** (full buffer) |
| Negative caching | VCL configurable | `proxy_cache_valid 404 1m` | Via Cache-Control headers |
| Cache warming | varnishadm | N/A | **Not supported** |
| Observability | varnishstat/varnishlog (rich) | Log variables | Prometheus counters (basic) |
| Auto-HTTPS | Requires proxy | Manual certs | **Best-in-class** (ACME) |
| Maturity | 15+ years | 10+ years | ~3-4 years (Souin) |
| Maintainer bus factor | Varnish Software | F5/Nginx Inc. | Single maintainer (@darkweak) |

### Caddy's Current Caching State

Caddy has **no built-in HTTP response cache**. The plugin ecosystem:

- **`github.com/caddyserver/cache-handler`** (v0.16.0) — under `caddyserver` org, built
  on Souin. Semi-official. 9 storage backends (Badger, Otter, NutsDB, Redis, etc.).
  Tag-based invalidation, surrogate key purge, ESI, Prometheus metrics.

- **`github.com/darkweak/souin`** (~950 stars) — upstream development repo. Single
  primary maintainer. MIT license.

### Critical Design Decisions

Five decisions that determine whether a coalescing cache works in production:

**1. Cache key computation.** Minimum: `method + host + path + sorted query +
Vary-nominated headers`. Normalize `Accept-Encoding` to reduce variants. Souin
handles this well.

**2. Coalescing timeout.** A hung origin with no timeout blocks ALL collapsed requests
forever. Souin uses bare `singleflight.Do()` with no timeout — **this is a gap**.
Fix: `singleflight.DoChan()` + `select { case <-ch: ... case <-time.After(timeout): }`.

**3. Hit-for-pass.** When origin returns uncacheable (`private`, `no-store`, `Set-Cookie`),
store a short-lived marker (2-5 min TTL) that bypasses coalescing. Without this,
uncacheable responses cause serial queue drain. Fastly documents "extreme response times
of several minutes." **Souin does not implement this — this is the most dangerous gap.**

**4. Stale-while-revalidate.** First request triggers background revalidation, all
subsequent get stale instantly. Zero client latency, one origin request. Souin supports
this via the `stale` directive.

**5. Stale-if-error.** On 5xx, serve stale to collapsed waiters. Prevents cascading
failures. Combined with SWR, makes the cache resilient to transient origin errors.

**Defense-in-depth ordering** (most to least effective):
1. `stale-while-revalidate` — zero latency
2. Request coalescing — adds origin-RTT latency
3. Tiered cache / origin shield — second coalescing layer
4. Hit-for-pass — bypass coalescing for known-uncacheable resources
5. Coalescing timeout — fail fast rather than queue indefinitely

### Implementation Plan

**Phase 1 — Evaluate Souin/cache-handler:**
- [ ] Build Caddy with `cache-handler` + Otter storage (in-memory)
- [ ] Configure per-route caching: static assets (immutable, long TTL), API responses
      (short TTL, Vary-aware), uncacheable paths (bypass)
- [ ] Verify `singleflight` coalescing under load (k6 stampede test)
- [ ] Measure SWR behavior — confirm only one revalidation fires per stale key
- [ ] Test `Cache-Status` header output
- [ ] Benchmark: response times, origin request reduction, memory usage

**Phase 2 — Address critical gaps (contribute upstream or fork):**
- [ ] Add coalescing timeout (`DoChan` + `select` with deadline)
- [ ] Implement hit-for-pass: on uncacheable response, store negative marker (2-5 min TTL)
- [ ] Add `stale-if-error` support if not working end-to-end
- [ ] Add per-route coalescing toggle (disable for auth endpoints)

**Fork vs. upstream decision framework:** If the fix is <200 LoC and well-scoped
(coalescing timeout is ~30 lines), submit upstream PR. If rejected or no response in
2 weeks, fork. Hit-for-pass is architecturally significant (~500 LoC) — if upstream
isn't receptive, evaluate whether to fork or build a minimal purpose-built cache
middleware instead (the coalescing + SWR + hit-for-pass core is ~1500 LoC without the
9 storage backends).

**Phase 3 — Integration with WAF stack:**
- [ ] Handler ordering: `ddos_mitigator` → `cache` → `policy_engine` → `reverse_proxy`
      (cached responses skip WAF evaluation)
- [ ] Cache invalidation on WAF deploy: when `response_header` rules change, purge
      affected cache entries. Strategy: tag cached responses with a `waf-version`
      surrogate key; on deploy, purge all entries with the old version tag.
- [ ] Jail integration: jailed IPs bypass cache (serve 403 directly)
- [ ] Dashboard: cache hit/miss/SWR metrics on overview page (via Prometheus counters
      from Souin, or `Cache-Status` header parsing in access log)

**Phase 4 — Tiered caching (optional, multi-node):**
- [ ] Redis or Olric as shared storage backend
- [ ] Origin shield: designate one Caddy as shield, others as edge
- [ ] Surrogate key purge propagation across nodes

---

## Proof-of-Work Challenge Action

Add a new `challenge` rule type to the policy engine, inspired by
[Anubis](https://github.com/TecharoHQ/anubis). When a `challenge` rule matches an
incoming request, the plugin serves an interstitial HTML page that requires the client
to complete a proof-of-work (PoW) computation before proceeding to the upstream service.
Legitimate browsers solve the challenge in seconds; headless scrapers and AI crawlers
that lack JavaScript execution are permanently blocked.

This is a native integration — not an external reverse proxy. The challenge lives inside
the caddy-policy-engine plugin, shares the same condition evaluator as all other rule
types, and flows through the same `policy-rules.json` config file.

### Motivation

AI crawler traffic is a growing problem. Current defenses in this stack:

- **Block rules** deny known-bad user agents (403), but sophisticated crawlers rotate UAs.
- **Rate limit rules** throttle volume, but crawlers can slow-drip below thresholds.
- **DDoS mitigator** catches behavioral anomalies, but low-and-slow crawlers avoid it.
- **Detect rules** (CRS) catch attack payloads, not benign-looking scrape requests.

A challenge rule fills the gap: it forces clients to prove they are a real browser
with JavaScript execution and CPU resources, without denying them outright. This is the
same approach Anubis uses to protect ~17K+ sites from AI scraping.

### How It Works

```
Client → Caddy → policy_engine
                     ↓
              ┌── challenge rule matches? ──┐
              │                             │
              │ YES                         │ NO
              ↓                             ↓
        Valid cookie?                  Continue to
              │                        next pass
        ┌─────┴─────┐
        │           │
        YES         NO
        ↓           ↓
   Continue      Serve interstitial
   (pass 4+)    ┌────────────────────────────┐
                │ "Verifying your connection" │
                │ [SHA-256 PoW computation]   │
                │ [Progress spinner]          │
                └──────────┬─────────────────┘
                           ↓
                POST /.well-known/policy-challenge/verify
                           ↓
                   PoW valid? ─── NO → 403 + log challenge_failed
                           │
                          YES
                           ↓
                   Set signed cookie
                   302 → original URL
                           ↓
                   Cookie present on retry
                   → continue to pass 4+
```

### Evaluation Order: 7-Pass Pipeline

The `challenge` type slots between `block` and `skip` at priority band 150-199:

```
Pass 1 — Allow           (50-99):   full bypass, terminates immediately
Pass 2 — Block           (100-149): deny list, terminates on match (403)
Pass 3 — Challenge       (150-199): proof-of-work interstitial          ← NEW
Pass 4 — Skip            (200-299): selective bypass, non-terminating
Pass 5 — Rate Limit      (300-399): sliding window counters
Pass 6 — Detect          (400-499): CRS anomaly scoring
Pass 7 — Response Header (500-599): set/add/remove/default response headers
```

**Why this position:**

- After `allow`: allowed traffic should never be challenged.
- After `block`: known-bad traffic should be denied (403), not given a chance to solve.
- Before `skip`: skip rules can exempt specific paths from challenges (e.g., API
  endpoints, webhooks).
- Before `rate_limit`/`detect`: challenged requests that pass should still be evaluated
  by CRS and rate limiting — the challenge proves browser capability, not benign intent.

### Data Model Changes

#### New Fields on `RuleExclusion`

```go
// ─── challenge-only ─────────────────────────────────────────
ChallengeDifficulty int    `json:"challenge_difficulty,omitempty"` // PoW leading zero bits (1-32, default 4)
ChallengeAlgorithm  string `json:"challenge_algorithm,omitempty"` // "fast" (default) or "slow"
ChallengeTTL        string `json:"challenge_ttl,omitempty"`       // cookie lifetime: "7d" (default), "24h", "1h"
```

| Field | Type | Default | Description |
|---|---|---|---|
| `challenge_difficulty` | int | 4 | Number of leading zero bits in SHA-256 hash. 4 = ~0.5s on modern hardware. 8 = ~5-10s. 16 = effectively impossible (anti-bot punishment). |
| `challenge_algorithm` | string | `"fast"` | `"fast"`: WebCrypto API SHA-256, optimized. `"slow"`: deliberate delay loop per iteration, intentionally wastes CPU time. |
| `challenge_ttl` | string | `"7d"` | Duration before the challenge cookie expires and the client must re-solve. Parsed as Go duration with day/hour shorthand. |

#### New `PolicyRule` Fields

```go
type PolicyChallengeConfig struct {
    Difficulty int    `json:"difficulty"`          // PoW leading zeros (1-32)
    Algorithm  string `json:"algorithm"`           // "fast" or "slow"
    TTLSeconds int    `json:"ttl_seconds"`         // cookie lifetime in seconds
    CookieName string `json:"cookie_name"`         // per-service cookie name
    HMACKey    string `json:"hmac_key"`            // injected at deploy time
}
```

Added to `PolicyRule`:

```go
ChallengeConfig *PolicyChallengeConfig `json:"challenge,omitempty"`
```

#### New Event Types

| Event Type | Description |
|---|---|
| `challenge_issued` | Challenge interstitial served to client |
| `challenge_passed` | Client solved PoW, cookie issued |
| `challenge_failed` | Client submitted invalid PoW solution |
| `challenge_bypassed` | Valid cookie present, challenge skipped |

#### New Log Fields (via `log_append`)

| Field | Description |
|---|---|
| `policy_challenge_difficulty` | PoW difficulty for this request |
| `policy_challenge_algorithm` | Algorithm used |
| `policy_challenge_duration_ms` | Time client spent solving (from timestamp in payload) |

### Plugin Implementation (caddy-policy-engine)

All challenge logic lives in the plugin. The hot path (cookie validation) is sub-microsecond.
The slow path (interstitial serving + PoW verification) only fires on first visit or
cookie expiry.

#### New Files

| File | Purpose | Est. Lines |
|---|---|---|
| `challenge.go` | Cookie validation, PoW verification, HMAC signing, interstitial handler | ~400 |
| `challenge_page.go` | `//go:embed` HTML template with inline CSS/JS | ~50 |
| `challenge.js` | Client-side SHA-256 PoW worker (WebCrypto API) | ~150 |
| `challenge.html` | Interstitial page template | ~80 |
| `challenge_test.go` | Unit tests for HMAC, cookie, PoW verification | ~300 |

**Total plugin addition: ~980 lines.**

#### Cookie Design

```
Cookie name:  __policy_challenge_{sha256(service_hostname)[:8]}
Domain:       {service_hostname}
Path:         /
HttpOnly:     true
Secure:       true
SameSite:     Lax
Max-Age:      {ttl_seconds}
Value:        base64url(header.payload.signature)
```

The cookie value is a compact signed token (not full JWT to avoid the dependency):

```
payload = {
    "iss": "policy-engine",
    "sub": client_ip,
    "aud": service_hostname,
    "exp": unix_timestamp,
    "iat": unix_timestamp,
    "dif": difficulty,           // difficulty solved at
    "alg": "fast"                // algorithm used
}

signature = HMAC-SHA256(hmac_key, base64url(payload))
token     = base64url(payload) + "." + base64url(signature)
```

The `sub` field binds the cookie to the client IP. If the client's IP changes, they
must re-solve. This prevents cookie sharing/replay across different origins.

IP binding is optional (configurable via `challenge_bind_ip` field, default `true`).
Disable for mobile clients that frequently change IPs.

#### Proof-of-Work Protocol

**Challenge issuance (GET, challenge rule matches, no valid cookie):**

```
1. Generate random 32-byte nonce
2. payload = JSON({ nonce, timestamp, difficulty, service, algorithm })
3. hmac = HMAC-SHA256(hmac_key, payload)
4. Serve interstitial HTML with embedded payload + hmac
```

**Client-side computation (`challenge.js`):**

```javascript
// "fast" algorithm — WebCrypto API, single-threaded
async function solve(payload, difficulty) {
    const target = BigInt(1) << BigInt(256 - difficulty);
    for (let counter = 0; ; counter++) {
        const data = new TextEncoder().encode(payload + counter);
        const hash = await crypto.subtle.digest('SHA-256', data);
        const value = BigInt('0x' + hex(hash));
        if (value < target) {
            return { counter, hash: hex(hash) };
        }
    }
}

// "slow" algorithm — deliberate delay per iteration
async function solveSlow(payload, difficulty) {
    // Same as fast, but with:
    await new Promise(r => setTimeout(r, 10)); // 10ms delay per iteration
}
```

**Verification (POST `/.well-known/policy-challenge/verify`):**

```
1. Parse { payload, hmac, counter, hash } from POST body
2. Verify HMAC (prevents payload tampering)
3. Verify timestamp (reject if > 5 minutes old)
4. Recompute SHA-256(payload + counter)
5. Verify leading zeros >= difficulty
6. Issue signed cookie
7. 302 redirect to original URL (from Referer or payload)
```

#### Interstitial Page

Minimal, accessible, no external dependencies:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Verifying your connection</title>
    <style>/* inline: centered spinner, progress bar, dark/light theme */</style>
</head>
<body>
    <div id="challenge">
        <h1>Verifying your connection</h1>
        <p>Please wait while we verify your browser.</p>
        <div class="spinner"></div>
        <noscript>
            <p>JavaScript is required to access this site. This is necessary
            because automated scrapers have changed the economics of web hosting.</p>
        </noscript>
    </div>
    <script>/* inline: challenge.js PoW solver */</script>
</body>
</html>
```

The page is embedded in the plugin binary via `//go:embed`. No external CSS/JS/font
requests. Total size: ~5KB gzipped.

#### Reserved Path

`/.well-known/policy-challenge/*` is reserved for the verification endpoint. The plugin
registers an implicit allow rule for this path prefix at priority 0 (before all user
rules) so the verification POST is never itself challenged, blocked, or rate-limited.

This path follows the [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) well-known URI
convention and will not conflict with upstream application routes.

#### Caddyfile Configuration

```caddyfile
policy_engine {
    rules_file /data/waf/policy-rules.json
    challenge {
        hmac_key {env.CHALLENGE_HMAC_KEY}    # or auto-generated on first run
        cookie_prefix __policy_challenge_
        bind_ip true                          # bind cookies to client IP
    }
}
```

The `hmac_key` can be provided via environment variable or auto-generated. Auto-generated
keys are persisted to `{data_dir}/challenge-hmac.key` so they survive Caddy restarts
without invalidating outstanding cookies. If no key is provided and no persisted key
exists, a random 32-byte key is generated and saved.

### wafctl Implementation

#### Validation (`exclusions_validate.go`)

```go
case "challenge":
    if len(e.Conditions) == 0 {
        errs = append(errs, "challenge rules require at least one condition")
    }
    if e.ChallengeDifficulty < 0 || e.ChallengeDifficulty > 32 {
        errs = append(errs, "challenge_difficulty must be 0-32 (0 = use default)")
    }
    if e.ChallengeAlgorithm != "" && e.ChallengeAlgorithm != "fast" && e.ChallengeAlgorithm != "slow" {
        errs = append(errs, "challenge_algorithm must be 'fast' or 'slow'")
    }
    if e.ChallengeTTL != "" {
        if _, err := parseDurationExtended(e.ChallengeTTL); err != nil {
            errs = append(errs, "invalid challenge_ttl: "+err.Error())
        }
    }
```

#### Policy Generator (`policy_generator.go`)

```go
var policyTypePriority = map[string]int{
    "allow":           50,
    "block":           100,
    "challenge":       150,   // ← NEW
    "skip":            200,
    "rate_limit":      300,
    "detect":          400,
    "response_header": 500,
}
```

Challenge rules are converted to `PolicyRule` with a populated `ChallengeConfig`:

```go
if e.Type == "challenge" {
    rule.ChallengeConfig = &PolicyChallengeConfig{
        Difficulty: defaultIfZero(e.ChallengeDifficulty, 4),
        Algorithm:  defaultIfEmpty(e.ChallengeAlgorithm, "fast"),
        TTLSeconds: parseTTLSeconds(e.ChallengeTTL, 7*24*3600),
        CookieName: challengeCookieName(resolvedService),
        HMACKey:    deployCfg.ChallengeHMACKey,
    }
}
```

The HMAC key is injected at deploy time from `DeployConfig.ChallengeHMACKey`, which
reads from `CHALLENGE_HMAC_KEY` environment variable or generates a random key on first
boot and persists it to `{data_dir}/challenge-hmac.key`.

#### Files Changed in wafctl

| File | Changes |
|---|---|
| `models_exclusions.go` | Add `challenge` to `validExclusionTypes`; add 3 fields to `RuleExclusion` |
| `exclusions_validate.go` | Add `case "challenge"` block (~15 lines) |
| `policy_generator.go` | Add `"challenge": 150` to priority map; add `PolicyChallengeConfig` struct; add conversion block in `GeneratePolicyRulesWithRL()` (~30 lines) |
| `deploy.go` | Read/generate HMAC key; add to `DeployConfig` struct (~20 lines) |
| `main.go` | Read `CHALLENGE_HMAC_KEY` env; pass to `DeployConfig` (~5 lines) |

**Total wafctl addition: ~120 lines** (excluding tests).

#### Test Changes in wafctl

| File | Changes |
|---|---|
| `exclusions_test.go` | CRUD tests for challenge rules (~40 lines) |
| `exclusions_validate_test.go` | Validation edge cases: difficulty bounds, algorithm values, TTL parsing (~60 lines) |
| `policy_generator_test.go` | Challenge rule → PolicyRule conversion; priority ordering with challenge in band (~50 lines) |
| `deploy_test.go` | HMAC key injection into generated output (~30 lines) |

**Total wafctl test addition: ~180 lines.**

### Dashboard Implementation (waf-dashboard)

#### TypeScript Interface Update (`src/lib/api/exclusions.ts`)

```typescript
export interface Exclusion {
    // ... existing fields ...

    // challenge-only
    challenge_difficulty?: number;
    challenge_algorithm?: 'fast' | 'slow';
    challenge_ttl?: string;
}
```

#### Policy Form Update (`src/components/policy/PolicyForms.tsx`)

Add a "Challenge Settings" section when `type === "challenge"`:

- **Difficulty slider** (1-16 range, default 4) with descriptive labels:
  "Easy (~0.5s)" / "Medium (~5s)" / "Hard (~30s)" / "Extreme (~5min)"
- **Algorithm dropdown**: "Fast (WebCrypto)" / "Slow (CPU-intensive)"
- **TTL input**: duration input (reuse existing `duration-input.tsx` component)

#### Event Badge Update (`src/components/events/helpers.tsx`)

```typescript
case 'challenge_issued':   return { label: 'Challenge', variant: 'warning' };
case 'challenge_passed':   return { label: 'Challenge OK', variant: 'success' };
case 'challenge_failed':   return { label: 'Challenge Fail', variant: 'destructive' };
case 'challenge_bypassed': return { label: 'Challenge Skip', variant: 'secondary' };
```

#### Constants Update (`src/components/policy/constants.ts`)

```typescript
export const RULE_TYPES = [
    'allow', 'block', 'challenge', 'skip', 'detect', 'rate_limit', 'response_header'
] as const;
```

#### New Components

None. All challenge UI is handled by extending existing form sections and badge helpers.
The overview dashboard will automatically pick up challenge events through the existing
event type aggregation.

### Example Rules

#### Challenge all browser-like traffic

```json
{
    "name": "challenge-browsers",
    "type": "challenge",
    "conditions": [
        { "field": "user_agent", "operator": "contains", "value": "Mozilla" }
    ],
    "challenge_difficulty": 4,
    "challenge_algorithm": "fast",
    "challenge_ttl": "7d",
    "enabled": true
}
```

#### Hard challenge for suspected AI crawlers

```json
{
    "name": "punish-ai-crawlers",
    "type": "challenge",
    "conditions": [
        {
            "field": "user_agent",
            "operator": "regex",
            "value": "(?i)(GPTBot|ChatGPT|Claude|Anthropic|CCBot|Bytespider|PetalBot)"
        }
    ],
    "challenge_difficulty": 16,
    "challenge_algorithm": "slow",
    "challenge_ttl": "1h",
    "tags": ["ai-crawler"],
    "enabled": true
}
```

#### Per-service challenge for public-facing sites only

```json
{
    "name": "challenge-httpbun",
    "type": "challenge",
    "service": "httpbun.erfi.io",
    "conditions": [
        { "field": "path", "operator": "regex", "value": "^/(?!api/).*" }
    ],
    "challenge_difficulty": 4,
    "challenge_algorithm": "fast",
    "challenge_ttl": "24h",
    "enabled": true
}
```

#### Skip challenges for known-good paths

Combine with a `skip` rule (evaluated after challenge, but skip targets can include
the `challenge` phase):

```json
{
    "name": "skip-challenge-for-well-known",
    "type": "skip",
    "conditions": [
        { "field": "path", "operator": "regex", "value": "^/\\.well-known/.*" }
    ],
    "skip_targets": { "phases": ["challenge"] },
    "enabled": true
}
```

Note: skip rules evaluate at priority 200-299, after challenge (150-199). For paths
that must never see a challenge, use an `allow` rule (priority 50-99) instead — allow
rules terminate evaluation before the challenge pass is reached.

### Interaction with Existing Rule Types

| Existing Type | Interaction |
|---|---|
| **allow** | Allow rules (pass 1) terminate before challenge. Allowed requests are never challenged. Use for API endpoints, webhooks, health checks. |
| **block** | Block rules (pass 2) terminate before challenge. Known-bad traffic is denied, not given a chance to solve. |
| **skip** | Skip rules can target `"phases": ["challenge"]` to exempt specific conditions from challenge. But skip evaluates *after* challenge (pass 4 vs pass 3), so it only suppresses challenges on future requests if the skip sets a cookie/flag. For pre-challenge exemption, use `allow` instead. |
| **rate_limit** | Rate limiting (pass 5) applies after challenge. A client that passes the challenge is still rate-limited. Challenge failures can be counted as rate limit events (configurable). |
| **detect** | CRS detection (pass 6) applies after challenge. Challenge pass proves browser capability, not benign intent. SQLi/XSS payloads from a browser that solved a challenge are still detected. |
| **response_header** | No interaction. Challenge responses are generated by the plugin, not proxied from upstream. Response header rules only apply to proxied responses. |
| **DDoS mitigator** | DDoS mitigator evaluates before the policy engine (`order ddos_mitigator after log_append`, `order policy_engine after ddos_mitigator`). Jailed IPs never reach the challenge. Challenge failures can trigger jail additions via a new `challenge_jail_after` config (default: 5 failures → jail for 1h). |

### Interaction with Existing Roadmap

| Roadmap Item | Impact |
|---|---|
| **Phase 0 (interfaces)** | Not a prerequisite. `challenge` is stored in `ExclusionStore` like all other types. When interfaces are extracted, it's just another type in the union. |
| **Storage migration (Phases 1-3)** | No impact. Challenge rules are regular rows in the exclusions table. Challenge cookies are stateless (signed tokens), requiring zero server-side storage. |
| **WebSocket/SSE inspection** | Independent. Stream-phase rules never have `challenge` type. Challenges are inherently HTTP request/response. |
| **Edge caching** | Challenge responses must NOT be cached. The interstitial includes a unique nonce per request. The plugin sets `Cache-Control: no-store, no-cache, must-revalidate` and `Pragma: no-cache` on all challenge responses. The cache handler (if integrated) must respect this. |

### Security Considerations

| Concern | Mitigation |
|---|---|
| **HMAC key compromise** | Attacker can forge cookies. Mitigation: key stored only in plugin memory + on-disk file (not in policy-rules.json after reconsideration — injected via env). Rotate via `CHALLENGE_HMAC_KEY` env change + Caddy restart. |
| **Cookie replay** | Cookies bound to client IP (default) + service hostname. Replay from a different IP fails validation. IP binding can be disabled for mobile-heavy services. |
| **PoW precomputation** | Nonce is random per challenge issuance. Precomputation is impossible without the nonce. Timestamp in payload prevents replay of old solutions (5-minute validity window). |
| **Challenge page XSS** | No user input reflected in the challenge page. All dynamic values (nonce, difficulty) are injected as `data-*` attributes, never into script context. CSP: `script-src 'self' 'unsafe-inline'` (inline script is the PoW solver). |
| **Denial of service via challenge flood** | Challenge issuance is cheap (generate nonce + HMAC + serve static page). Verification is cheap (one SHA-256 computation). The client does the expensive work. DDoS mitigator handles volume. |
| **Accessibility** | `<noscript>` fallback explains why JS is required. Consider adding a CAPTCHA fallback in a future iteration for JS-disabled clients that need access. |

### Implementation Phases

```
Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 4 ──→ Phase 5
```

| Phase | Scope | Est. |
|---|---|---|
| 1. wafctl model + validation | `RuleExclusion` fields, validation, generator, deploy HMAC | ~1.5 days |
| 2. Plugin PoW engine | Cookie validation, HMAC signing, nonce generation, PoW verification | ~3 days |
| 3. Interstitial + client JS | HTML template, CSS, `challenge.js` PoW solver, `//go:embed` | ~2 days |
| 4. Dashboard integration | Form fields, event badges, constants update | ~1.5 days |
| 5. E2E tests + hardening | Challenge issued/passed/failed scenarios, cookie expiry, IP binding, skip interaction | ~2.5 days |

**Total: ~10.5 days.**

### Risk Assessment

| Risk | Impact | Probability | Mitigation |
|---|---|---|---|
| Challenge blocks legitimate users without JS | Accessibility regression | Low (JS is ubiquitous) | `<noscript>` message; future CAPTCHA fallback |
| Challenge latency adds to TTFB | UX degradation on first visit | Medium | Challenge page is <5KB; PoW at difficulty 4 takes <1s |
| HMAC key management complexity | Operational burden | Low | Auto-generation with on-disk persistence; env override |
| Challenge pages confuse users | Support burden | Medium | Clear, branded messaging; configurable explanation text |
| Sophisticated bots solve PoW via headless Chrome | Bypass | Medium | Difficulty escalation; future: behavioral fingerprinting, CAPTCHA |
| Cookie size adds overhead to every request | Performance | Low | Token is ~120 bytes base64; negligible vs typical headers |

---

## CRS Converter Fidelity

Converter coverage: 341 rules from CRS 4.24.1. 5 detection rules skipped
(TX-to-TX comparison, protocol limits handled natively by plugin). 294 flow-control
rules correctly excluded. Test suite runs at PL4 with threshold=5.

CRS E2E fidelity: **97.9%** (4381/4476 testable at PL4, official CRS 4.24.1 suite).
95 real failures: 79 FN (rule should detect but didn't) + 16 FP (rule shouldn't fire but did).
744 cross-rule passes resolved via severity-aware events API batch check.

**Completed:**
- [x] Per-field OR condition groups (replaced request_combined — 201 rules)
- [x] SecRuleUpdateTargetById processing (55 cookie/arg exclusions)
- [x] Catch-all chain skip (920450/920451)
- [x] Custom rule deduplication (7 duplicates removed)
- [x] Standalone CRS E2E test suite with baseline (PL4, auto-download from GitHub)
- [x] `validate_byte_range` / `validate_url_encoding` / `validate_utf8_encoding` operators
- [x] Mixed MATCHED_VARS + non-TX chain variable merge (tx:0 + real fields)
- [x] body/xml deduplication (removes body from OR groups with xml)
- [x] `multiFieldAbsent()` (negated files/xml conditions on wrong content type)
- [x] Host header fix in test runner (Go `req.Host` vs `req.Header`)
- [x] CRS extended settings (allowed_methods, arg limits via PolicyWafConfig)
- [x] Plugin-side enforcement of method/version/arg limits

**Remaining 28 PL1 test failures (requires plugin or converter changes):**
- [ ] XML element/attribute name exclusion from `xml` field (944100 — 4 tests)
- [ ] `not_ends_with_field` operator for dynamic Referer/Host comparison (943110 — 4 tests)
- [ ] Cookie header exclusion from `all_headers` (941120 — 1 test)
- [ ] Cookie name regex filtering (921250 — 1 test)
- [ ] Multipart `name` vs `filename` scoping for FILES field (933110 — 1 test)
- [ ] TX:1 capture + phrase_match chain evaluation (920480 — 1 test)
- [ ] Short command regex boundary with cmdLine transform (932340 — 4 tests)
- [ ] LDAP injection regex precision (921200 — 3 tests, may be CRS issue)
- [ ] Various regex/transform edge cases (9 tests across 932/933/934/941)

---

## Cross-Cutting: Sequencing, Effort & Risk

### Store Dependency Graph (Migration Ordering)

```
GeoIPStore (standalone, stays file-based — MMDB)
    |
    +---> Store (WAF events) ................. Phase 2
    +---> AccessLogStore ..................... Phase 2
    |         +---> ExclusionStore ........... Phase 1
    +---> GeneralLogStore .................... Phase 2

ExclusionStore (standalone) .................. Phase 1
ConfigStore (standalone) ..................... Phase 1
CSPStore (standalone) ........................ Phase 1
SecurityHeaderStore (standalone) ............. Phase 1
CORSStore (standalone) ....................... Phase 1
ManagedListStore (standalone) ................ Phase 1
DefaultRuleStore (standalone) ................ Phase 1
DosConfigStore (standalone) .................. Phase 1

BlocklistStore --callback--> ManagedListStore (SyncIPsum)
               --callback--> deployAll --> 7 config stores
               <--- IPIntelStore

JailStore ...................................... Phase 3 (Valkey)
    +---> SpikeReporter

SpikeDetector <--- DosConfigStore (reads at construction)
```

Safe migration order:
1. All 8 config stores (Phase 1) — no cross-dependencies
2. Event stores (Phase 2) — AccessLogStore depends on ExclusionStore for tag enrichment
3. JailStore (Phase 3) — standalone, can run in parallel with Phases 1-2

### Recommended Execution Order

```
Phase 0 (interfaces) ........................... 1-2 weeks
  |
  +-> Phase 1 (config stores to PG) ........... 2-3 weeks
  |     |
  |     +-> Infra (compose + PG + Valkey) ...... 1-2 weeks (overlaps with Phase 1)
  |           |
  |           +-> Phase 3 (jail to Valkey) ..... 2-3 weeks (can overlap with Phase 1)
  |                 |
  |                 +-> Phase 2 (event stores) . 5-7 weeks
  |                       |
  |                       +-> Phase 4 (RL, optional) ... 3-4 weeks
  |
  +-> WebSocket inspection ..................... ~14 days (independent, can run anytime)
  |
  +-> PoW challenge action ..................... ~10.5 days (independent, can run anytime)
  |
  +-> Edge caching evaluation .................. 4-8 weeks (independent)
```

**Rationale:**
- Phase 0 unblocks everything in wafctl and improves testability regardless of migration
- Phase 1 is the lowest-risk PG migration and validates PG infrastructure
- Phase 3 is independent of PG and gives the highest architectural payoff (eliminates
  flock + bidirectional file sync between two processes)
- Phase 2 is the largest and riskiest — do it last when PG is proven
- Phase 4 only if multi-instance Caddy is needed
- WebSocket is fully independent of storage migration
- PoW challenge is fully independent of all other workstreams — no new dependencies,
  no storage requirements (stateless cookies), slots into existing rule type system
- Edge caching is exploratory and independent

### Effort Summary

| Phase | Component | Effort | Risk | Breaks Zero-Deps? |
|---|---|---|---|---|
| **0** | Interface extraction | **1-2 weeks** | Low | No |
| **1** | Config stores → PG | **2-3 weeks** | Low | Yes (`pgx`) |
| **2** | Event stores → PG | **5-7 weeks** | Medium-High | Yes |
| **3** | Jail → Valkey | **2-3 weeks** | Medium | Yes (both repos) |
| **4** | RL counters → Valkey (opt.) | **3-4 weeks** | Medium | Yes (policy-engine) |
| **Infra** | compose + schema + migration tool | **1-2 weeks** | Low | N/A |
| **WS** | WebSocket + SSE inspection | **~14 days** | Medium | No (plugin only) |
| **PoW** | Proof-of-work challenge action | ~~10.5 days~~ **DONE** | Low-Medium | No (plugin + wafctl) |
| **Cache** | Edge caching evaluation + integration | **4-8 weeks** | Medium | No (plugin only) |

**Storage migration total: 14-21 weeks** for Phases 0-3 + Infra (Phase 4 adds 3-4 weeks).

**All workstreams total: ~6-9 months** (storage + WebSocket + challenge + caching, with parallelism).

### Lines of Code Impact

| Category | Added | Removed | Net |
|---|---|---|---|
| Phase 0: interfaces + handler signatures | ~500 | ~200 | +300 |
| Phase 1: PG store implementations | ~1200 | ~800 | +400 |
| Phase 2: PG event stores + query builders | ~1800 | ~1260 | +540 |
| Phase 3: Valkey jail sync | ~300 | ~280 | +20 |
| Infra: compose + schema + migration tool | ~600 | ~0 | +600 |
| WebSocket: plugin + wafctl + dashboard | ~3000 | ~0 | +3000 |
| PoW challenge: plugin + wafctl + dashboard | ~1280 | ~0 | +1280 |
| **Total (excl. caching)** | **~8680** | **~2540** | **+6140** |

### CI Pipeline Impact

- Phase 0: no CI change (same tests, different signatures)
- Phase 1-2: add `testcontainers-go` for PG integration tests. Adds ~30s to CI for
  container startup. Run behind `-tags=integration` to keep unit tests fast.
- Phase 3: Valkey testcontainer for jail sync tests. Same ~30s overhead (can share
  startup with PG container).
- WebSocket: new e2e tests using the existing `13_websocket_test.go` pattern (raw TCP,
  no external deps). Minor CI time increase.
- PoW challenge: new e2e tests for challenge issuance, PoW verification, cookie
  validation, and skip interaction. Uses `net/http` client with cookie jar — no
  external deps. Adds ~5-10s to e2e suite. wafctl unit tests for validation and
  generator are zero-cost (same pattern as existing rule type tests).

---

## Completed (changelog)

### v2.83.0 / caddy 3.79.0-2.11.2

- **CRS converter overhaul**: Per-field OR condition groups replace `request_combined`
  (201 rules). Eliminates false positives from over-broad field consolidation
  (Accept-Encoding, Cf-Visitor, Accept headers no longer checked by RCE/SQLi rules).
  SecRuleUpdateTargetById processing (55 cookie/arg exclusions). Catch-all chain skip
  (920450/920451). Custom rule deduplication (7 duplicates removed). SortRules uses
  stable sort. 342 rules total, 0 `request_combined`, 0 duplicates.
- **CRS protocol enforcement** (policy-engine v0.35.0): Plugin-native enforcement of
  allowed_methods (911100), allowed_http_versions (920430), max_num_args (920380),
  arg_name_length (920360), arg_length (920370), total_arg_length (920390). Configurable
  via CRS v4 settings panel. Per-service overrides supported. Violations produce
  synthetic detect matches with CRITICAL severity for anomaly scoring.
- **CRS E2E test suite**: Standalone test/crs/ module — 4526 tests from official CRS
  YAML test cases, baseline-driven regression detection, hybrid status-code + events
  API checking, fast baseline generation (CRS_STATUS_ONLY mode). 79.9% status-code
  fidelity (3578/4480 testable).
- **Pipeline improvements**: Converter tests in CI. Makefile targets (generate-rules,
  test-crs-converter, test-crs-e2e). crs-update.yml regenerates default-rules.json in
  bump PRs. Custom rules: 920450 updated (10 items), 920451 added (extended list).
- **Code quality**: 8 fixes (deprecated strings.Title, dead categoryMap field, frontend
  prefix extraction, singleton retry, misplaced test, no-op ReplaceAll, RESPONSE-956
  category, non-deterministic field fallback).

### v2.66.0 / caddy 3.62.0-2.11.2

- **Proof-of-work challenge action** (policy-engine v0.24.0-v0.25.2): New `challenge`
  rule type — SHA-256 hashcash PoW interstitial. Multi-threaded Web Worker solver with
  pure-JS fallback. 7-pass evaluation pipeline (was 6-pass). Per-service HMAC-signed
  cookies with cryptographic token IDs (jti), 1-hour default TTL, IP binding.
  `challenge_cookie` rate limit key for post-challenge abuse prevention.
- **5-layer bot signal scoring**: JS environment probes (17 signals: webdriver, plugins,
  WebGL SwiftShader, canvas, speech voices, permissions timing, chrome.runtime, languages),
  behavioral signals (5: mouse, keyboard, scroll, focus, worker timing variance),
  JA4 TLS fingerprint scoring (ALPN, version), HTTP header analysis (Sec-Fetch-*,
  Client Hints, Accept-Language), spatial inconsistency detection (mobile UA + desktop
  signals, Chrome UA + non-browser JA4). Deep WebGL probes (MAX_TEXTURE_SIZE catches
  stealth scripts that patch renderer string). Audio fingerprinting via OfflineAudioContext.
  Score >= 70 → reject even with valid PoW.
- **JA4 TLS fingerprinting** (policy-engine v0.25.0): Hand-rolled ClientHello binary
  parser (zero deps). `caddy.ListenerWrapper` module between L4 DDoS and TLS. Full
  FoxIO JA4 spec: 3-section format, GREASE filtered, sorted ciphers/extensions. `ja4`
  condition field for policy rules. Caddy variable `policy_engine.ja4` in access log.
- **Full data pipeline**: JA4, bot score, challenge JTI flow through
  Caddy log_append → AccessLogStore → RateLimitEvent → Event → API → Dashboard.
  General logs enriched with JA4 and policy action on every request.
- **Dashboard**: Challenge in Quick Actions (ShieldQuestion), challenge form
  (difficulty/algorithm/TTL/bind-IP), 4 event badges, JA4 + bot score + JTI in
  event detail, JA4 in general log TLS section, `challenge_cookie` in RL key picker,
  challenge counters in summary timeline.
- **Services TopURIs/TopRules**: Fixed pre-existing issue — now sourced from
  AccessLogStore when legacy WAF store is empty.
- **Production deployment**: CORS configured (*.erfi.io), cache-static-assets template
  applied (fonts/images/CSS/JS/media), Caddy 2.11.2 (CVE-2026-33186 mitigation).
- **Test coverage**: 81 Go e2e tests, 11 Playwright browser tests (including AI
  crawler detection: raw headless blocked, spoofed UA blocked, partial stealth blocked,
  full stealth demonstrates detection limit), 334 frontend tests, ~1479 wafctl tests.

### v2.62.0 / caddy 3.58.0

- **DDoS mitigator v0.15.0**: CIDR promotion visibility — promoted /24 and /64 prefixes
  now written to `jail.json` (`promoted_prefixes` section) so wafctl can display them on
  the dashboard. nftables sets upgraded to interval mode — promoted CIDR prefixes are
  kernel-dropped alongside individually-jailed IPs (previously only individual IPs were
  dropped, leaving promoted prefixes L7-only). Dirty flag now set on jail sweep removals
  and CIDR promotions/expirations.
- **L4 Caddyfile support**: `DDOSMitigatorL4` implements `caddyfile.Unmarshaler` for use
  in caddy-l4 `listener_wrappers` blocks. Drops jailed IPs with TCP RST before TLS
  handshake, sharing jail state via registry. Caddyfile: `servers { listener_wrappers {
  layer4 { route { ddos_mitigator { jail_file /data/waf/jail.json } } } } }`
- **New e2e tests**: L4 listener wrapper registration, L4 module loaded, L4 clean traffic
  passthrough, CIDR promotion visibility via jail API, jail file format validation.

### v2.60.0 / caddy 3.56.0

- **CRS metadata cleanup**: Removed all remaining hardcoded CRS data. `fallbackMetadata()`
  deleted from `crs_metadata.go` — `init()` seeds empty-but-safe instance, `main()` now
  fatals if `crs-metadata.json` is missing. Tests load from `testdata/crs-metadata.json`
  via `TestMain`.
- **Frontend CRS categories wired to API**: `useCRSCategories()` hook fetches from
  `/api/crs/rules` on first mount (singleton). `getCRSCategories()` getter replaces
  direct export. `CategoryToggles.tsx` inbound/outbound split uses `phase` field from
  CRS metadata via `useMemo`.
- **CRSCategory.Phase field**: Added `phase` ("inbound"/"outbound") to Go `CRSCategory`
  struct and TypeScript `RuleCategory` interface.

### v2.59.0 / caddy 3.55.0

- **DDoS mitigator v0.14.0**: Immediate nftables sync on jail — zero propagation window
  between L7 behavioral jail and L3 kernel drop. Load tested: 30K RPS loopback → 0.97%
  Caddy CPU, instant recovery, zero goroutine leak.
- **CRS metadata (converter-driven)**: `crs-converter` now emits `crs-metadata.json` at
  Docker build time. All hardcoded category maps removed. `atomic.Pointer[CRSMetadata]`
  for thread-safe access.
- **E2E fixes**: All 3 pre-existing failures resolved.
- **Go 1.26.1**: Fixes CVE-2026-25679.

### v2.57.0 / caddy 3.53.0

- **Code review sweep (31 fixes)**: Critical bug fixes, test coverage, and design
  improvements across CRS, policy engine, DDoS mitigation, and E2E test suite.
- **Critical fixes**: `response_content_type` field usable, rate limit priority cap,
  `JailStore.SetWhitelist` double-lock race eliminated, `SpikeDetector` thresholds
  updateable at runtime.
- **DDoS improvements**: `SpikeReport.TotalEvents` tracks cumulative spike events, log
  tailing uses actual timestamps, `JailStore.Count()` O(n) count-only.
- **Policy engine**: `mapServiceBoth` generic helper, `ResetFQDNCache()` exported,
  `defaultCRSCatalog` uses `atomic.Pointer`.
- **New test coverage**: `handlers_dos_test.go`, `spike_reporter_test.go`,
  `response_header` rule generation tests, `IsPolicyEngineType` test.

### v2.53.0 / caddy 3.49.0

- **Cross-repo audit**: Fixed unjail-via-wafctl for long-TTL entries, aligned
  `withFileLock` error handling, fixed stale endpoints, removed dead env vars.
- Plugin bumps: body-matcher v0.2.1, policy-engine v0.20.1, ddos-mitigator v0.9.0.

### v2.52.0 / caddy 3.48.0

- `fetchAllEvents` returns `ExportResult` with `totalEmitted`/`truncated`.
- Extracted shared rule table infrastructure from PolicyEngine and RateLimitsPanel.

### v2.51.0 / caddy 3.47.0

- Full-stack performance audit (30+ items): deferred enrichment, response caches,
  O(1) event index, streaming export, JSONL single-syscall writes, frontend
  AbortController/visibility API/memoization, Makefile parallel build.

### v2.50.0 and earlier

- DDoS mitigator: 7-phase implementation.
- CRS converter: variable exclusions, isExcluded() filtering, nested condition groups.
