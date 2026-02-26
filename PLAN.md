# Rate-Limit Policy Engine — Implementation Plan

## Status: DRAFT

**Branch:** `feature/rate-limit-policy-engine`
**Author:** AI-assisted design
**Date:** 2026-02-26

---

## 1. Problem Statement

The current rate-limiting system is a flat zone table (`RateLimitZone`: name, events, window, enabled) that maps 1:1 to services via Caddyfile import globs. It exposes only 2 of the 8+ parameters that Caddy's `caddy-ratelimit` plugin supports. Meanwhile, the WAF policy engine already has a rich condition-based rule system with 16 fields, 9 operators, AND/OR grouping, per-rule CRUD, analytics tracking, and a sophisticated UI.

### Current Limitations (12)

1. **No per-path/endpoint rate limiting** — all requests to a service share one counter
2. **Hardcoded key** — always `{http.request.remote.host}`; can't key by API key, path, etc.
3. **No request matchers** — only the WebSocket exclusion; Caddy supports full matcher sets
4. **No per-zone analytics** — all 429s for a service are counted together
5. **Stale `.caddy` file cleanup missing** — deleted zones continue to be enforced
6. **No jitter** — Caddy supports `jitter` to prevent thundering herd
7. **No multi-zone-per-service** — can't layer burst + sustained limits
8. **No distributed RL** — Caddy's cross-instance sync entirely unused
9. **Simple equality filters only** on `/api/rate-limits/events`
10. **No CLI subcommands** for rate limit management
11. **Time range limitations** — only `?hours=` with a fixed allowlist
12. **IPsum events conflated** — share `RateLimitEvent` struct with actual 429s

---

## 2. Design Goals

- **Unify** the rate-limit model with the policy engine's condition pattern
- **Reuse** existing `Condition` type, validation, and UI components
- **Expose** Caddy's full `rate_limit` capabilities (matchers, keys, jitter)
- **Per-rule analytics** with zone attribution via response headers
- **Backward-compatible migration** from `RateLimitZone` to `RateLimitRule`
- **Same CRUD pattern** as `ExclusionStore` (UUID, timestamps, rollback-on-error)
- **Same deploy pattern** as WAF policy (generate → write → reload)

---

## 3. Data Model

### 3.1 New Model: `RateLimitRule`

**File:** `wafctl/models.go` (append after `RateLimitConfig`, ~line 547)

```go
// RateLimitRule is a single rate-limiting policy with conditions and key config.
// Analogous to RuleExclusion for the WAF policy engine.
type RateLimitRule struct {
    ID          string      `json:"id"`
    Name        string      `json:"name"`
    Description string      `json:"description,omitempty"`
    Service     string      `json:"service"`                  // hostname or "*" for all services
    Conditions  []Condition `json:"conditions,omitempty"`      // Reuse existing Condition type
    GroupOp     string      `json:"group_operator,omitempty"`  // "and" (default) or "or"
    Key         string      `json:"key"`                       // "client_ip", "header:X-API-Key", "client_ip+path", "static"
    Events      int         `json:"events"`                    // Max events in window
    Window      string      `json:"window"`                    // Duration string: "1m", "30s", "1h"
    Action      string      `json:"action,omitempty"`          // "deny" (default 429) or "log_only"
    Priority    int         `json:"priority,omitempty"`        // Lower = evaluated first (0 = default)
    Enabled     bool        `json:"enabled"`
    CreatedAt   time.Time   `json:"created_at"`
    UpdatedAt   time.Time   `json:"updated_at"`
}

// RateLimitRuleConfig wraps the list of rules plus global settings.
type RateLimitRuleConfig struct {
    Rules   []RateLimitRule       `json:"rules"`
    Global  RateLimitGlobalConfig `json:"global,omitempty"`
}

// RateLimitGlobalConfig holds settings applied to all generated rate_limit blocks.
type RateLimitGlobalConfig struct {
    Jitter        float64 `json:"jitter,omitempty"`         // 0.0-1.0, randomize Retry-After
    SweepInterval string  `json:"sweep_interval,omitempty"` // e.g. "1m" (default)
    Distributed   bool    `json:"distributed,omitempty"`    // Enable cross-instance RL
}
```

### 3.2 Key Format Specification

The `Key` field is a human-readable descriptor that the generator translates to Caddy placeholders:

| Key value | Caddy placeholder | Description |
|---|---|---|
| `client_ip` (default) | `{http.request.remote.host}` | Per client IP |
| `header:<Name>` | `{http.request.header.<Name>}` | Per header value (e.g., `header:X-API-Key`) |
| `path` | `{http.request.uri.path}` | Per URI path |
| `client_ip+path` | `{http.request.remote.host}{http.request.uri.path}` | Compound: per IP per path |
| `client_ip+method` | `{http.request.remote.host}{http.request.method}` | Compound: per IP per method |
| `static` | `static` | Global rate limit (one counter for all requests) |
| `cookie:<Name>` | `{http.request.cookie.<Name>}` | Per cookie value |

Validation regex: `^(client_ip|path|static|client_ip\+path|client_ip\+method|header:[A-Za-z0-9_-]+|cookie:[A-Za-z0-9_-]+)$`

### 3.3 Condition → Caddy Matcher Mapping

Conditions reuse the existing `Condition` struct and are translated to Caddy request matchers inside the `rate_limit` zone's `match { }` block:

| Condition Field | Caddy Matcher | Example |
|---|---|---|
| `path` (begins_with) | `path /api/*` | Match all API routes |
| `path` (eq) | `path /login` | Exact path |
| `path` (regex) | `path_regexp .*\.json$` | Regex path |
| `method` (eq) | `method POST` | Single method |
| `method` (in) | `method POST PUT DELETE` | Multiple methods |
| `header` (eq) | `header X-Custom value` | Header match |
| `header` (contains) | `header_regexp X-Custom .*value.*` | Header regex |
| `ip` (eq/ip_match) | `remote_ip <CIDR>` | Client IP match |
| `query` (contains) | `query key=*value*` | Query string |

When `GroupOp = "and"`: all matchers go inside one `match { }` block (AND logic).
When `GroupOp = "or"`: each condition gets its own `match { }` block (OR — Caddy evaluates multiple match blocks as OR).

The WebSocket exclusion (`not header Connection *Upgrade*`) is **always** prepended to every zone's matcher unless a future toggle disables it.

### 3.4 Migration from `RateLimitZone`

```go
func migrateZonesToRules(zones []RateLimitZone) []RateLimitRule {
    rules := make([]RateLimitRule, len(zones))
    for i, z := range zones {
        rules[i] = RateLimitRule{
            ID:        generateUUID(),
            Name:      z.Name,
            Service:   z.Name,  // zone name was always the service name
            Key:       "client_ip",
            Events:    z.Events,
            Window:    z.Window,
            Enabled:   z.Enabled,
            CreatedAt: time.Now().UTC(),
            UpdatedAt: time.Now().UTC(),
            // No conditions = match all requests (same as current behavior)
        }
    }
    return rules
}
```

Auto-migration runs on startup if the old `rate-limits.json` has `{"zones":[...]}` format (detected by presence of `"zones"` key). The new format has `{"rules":[...], "global":{...}}`. Old file is backed up to `rate-limits.json.v1.bak`.

---

## 4. Backend Implementation

### 4.1 New File: `wafctl/rl_rules.go` — Rule Store

Mirrors `exclusions.go` pattern. ~300 lines estimated.

```go
type RateLimitRuleStore struct {
    mu       sync.RWMutex
    config   RateLimitRuleConfig
    filePath string
}

func NewRateLimitRuleStore(filePath string) *RateLimitRuleStore
func (s *RateLimitRuleStore) load()
func (s *RateLimitRuleStore) save() error
func (s *RateLimitRuleStore) List() []RateLimitRule             // Deep copy
func (s *RateLimitRuleStore) Get(id string) *RateLimitRule      // Deep copy or nil
func (s *RateLimitRuleStore) Create(rule RateLimitRule) (RateLimitRule, error)
func (s *RateLimitRuleStore) Update(id string, rule RateLimitRule) (RateLimitRule, error)
func (s *RateLimitRuleStore) Delete(id string) error
func (s *RateLimitRuleStore) GetGlobal() RateLimitGlobalConfig
func (s *RateLimitRuleStore) UpdateGlobal(cfg RateLimitGlobalConfig) error
func (s *RateLimitRuleStore) ListByService(host string) []RateLimitRule
func (s *RateLimitRuleStore) EnabledRules() []RateLimitRule
func (s *RateLimitRuleStore) Export() RateLimitRuleExport
func (s *RateLimitRuleStore) Import(rules []RateLimitRule) error

// Migration
func (s *RateLimitRuleStore) migrateFromV1(filePath string) error
```

**Concurrency:** `sync.RWMutex` — `RLock` for reads, `Lock` for mutations.
**Persistence:** Atomic writes via `atomicWriteFile()`.
**Rollback:** Every mutation saves old state, reverts on save failure.
**UUID:** Generated via `generateUUID()` (same helper as exclusions).

### 4.2 Validation: `validateRateLimitRule()`

**File:** `wafctl/rl_rules.go` (within the same file)

```go
func validateRateLimitRule(rule RateLimitRule) error
```

Validates:
- `Name`: required, no newlines (same as exclusion name validation)
- `Service`: required (hostname or `"*"`), no newlines
- `Key`: required, must match the key format regex
- `Events`: 1–100,000
- `Window`: must match `^\d+[smh]$`
- `Action`: `""` (default = deny), `"deny"`, or `"log_only"`
- `Priority`: 0–999
- `Conditions`: reuse `validateCondition()` from `exclusions.go` — extract it into a shared function
- `GroupOp`: must be `""`, `"and"`, or `"or"` (reuse `validGroupOperators`)

Config-level validation:
- No duplicate rule names within the same service
- Zone name uniqueness (generated names must not collide)

### 4.3 New File: `wafctl/rl_generator.go` — Config Generator

Generates Caddy rate_limit snippets from rules. ~250 lines estimated.

```go
// GenerateRateLimitConfigs produces per-service .caddy files from the rule set.
// Returns a map of filename → content.
func GenerateRateLimitConfigs(config RateLimitRuleConfig, caddyfilePath string) map[string]string

// generateServiceRL generates the rate_limit block for a single service.
func generateServiceRL(service string, rules []RateLimitRule, global RateLimitGlobalConfig) string

// rlZoneName generates a unique Caddy zone name from service + rule ID.
// Format: <service>_<first8charsOfID> (e.g. "sonarr_a1b2c3d4")
func rlZoneName(service string, ruleID string) string

// rlConditionToMatcher translates a Condition to a Caddy matcher line.
func rlConditionToMatcher(c Condition) string

// rlKeyToPlaceholder translates the Key field to a Caddy placeholder string.
func rlKeyToPlaceholder(key string) string
```

**Generated file format** (per service, e.g. `sonarr_rl.caddy`):

```caddy
# Managed by wafctl Rate Limit Policy Engine
# Service: sonarr | Rules: 2 | Updated: 2026-02-26T12:00:00Z

rate_limit {
    # Rule: "API Write Protection" (a1b2c3d4)
    zone sonarr_a1b2c3d4 {
        match {
            not header Connection *Upgrade*
            path /api/*
            method POST PUT DELETE
        }
        key {http.request.remote.host}
        events 50
        window 1m
    }

    # Rule: "Standard Limit" (e5f6g7h8)
    zone sonarr_e5f6g7h8 {
        match {
            not header Connection *Upgrade*
        }
        key {http.request.remote.host}
        events 300
        window 1m
    }

    jitter 0.2
}

# Zone response headers
header X-RateLimit-Limit "300"
header X-RateLimit-Policy "sonarr"
```

**Disabled rules:** Omitted from generation entirely (not emitted as comments).
**Empty service (no enabled rules):** Produces comment-only file (no-op import).
**Stale file cleanup:** `writeRLFiles()` deletes `.caddy` files in the RL dir that are NOT in the generated set.

### 4.4 Zone Attribution for Analytics

Each generated zone emits a `X-RateLimit-Zone` header with the **rule name**:

```caddy
zone sonarr_a1b2c3d4 {
    ...
}
# After the rate_limit block, but within the service block:
# (Can't add per-zone headers inside rate_limit — add as response header via Caddy handle)
```

**Implementation approach:** Since Caddy's `rate_limit` plugin sets `Retry-After` and returns 429, but doesn't set a custom zone-identifying header natively, we use the `X-RateLimit-Policy` header which already includes the zone name. The `AccessLogStore` parser will extract the zone name from this header on 429 responses.

Update `rl_analytics.go` `Load()`:
```go
// Extract zone name from X-RateLimit-Policy header on 429 responses
// Format: "50;w=1m;name=\"sonarr_a1b2c3d4\""
// Parse the name= portion to get the zone, then map back to rule name
```

### 4.5 Handler Changes: `wafctl/main.go`

**New endpoints** (add at ~line 150):

```go
// Rate Limit Rules (new policy engine)
mux.HandleFunc("GET /api/rate-rules", handleListRLRules(rlRuleStore))
mux.HandleFunc("POST /api/rate-rules", handleCreateRLRule(rlRuleStore))
mux.HandleFunc("GET /api/rate-rules/{id}", handleGetRLRule(rlRuleStore))
mux.HandleFunc("PUT /api/rate-rules/{id}", handleUpdateRLRule(rlRuleStore))
mux.HandleFunc("DELETE /api/rate-rules/{id}", handleDeleteRLRule(rlRuleStore))
mux.HandleFunc("POST /api/rate-rules/deploy", handleDeployRLRules(rlRuleStore, deployCfg))
mux.HandleFunc("GET /api/rate-rules/hits", handleRLRuleHits(accessLogStore, rlRuleStore))
mux.HandleFunc("GET /api/rate-rules/export", handleExportRLRules(rlRuleStore))
mux.HandleFunc("POST /api/rate-rules/import", handleImportRLRules(rlRuleStore))
mux.HandleFunc("GET /api/rate-rules/global", handleGetRLGlobal(rlRuleStore))
mux.HandleFunc("PUT /api/rate-rules/global", handleUpdateRLGlobal(rlRuleStore))
```

**Deprecation of old endpoints:** The existing endpoints at `/api/rate-limits` remain functional during migration but log a deprecation warning. They proxy to the new store internally.

**Handler pattern:** Same closure injection pattern as `handleCreateExclusion(es)`:

```go
func handleCreateRLRule(rs *RateLimitRuleStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var rule RateLimitRule
        if err := decodeJSON(r, &rule); err != nil { ... }
        if err := validateRateLimitRule(rule); err != nil { ... }
        created, err := rs.Create(rule)
        if err != nil { ... }
        writeJSON(w, http.StatusCreated, created)
    }
}
```

### 4.6 Deploy Pipeline Changes: `wafctl/deploy.go`

Update `generateOnBoot()` (~line 78):
```go
// Replace: rs.MergeCaddyfileZones(deployCfg.CaddyfilePath)
// With:    rlrs.MergeCaddyfileServices(deployCfg.CaddyfilePath)
// Then:    writeRLFiles(deployCfg.RateLimitDir, GenerateRateLimitConfigs(...))
```

Update `handleDeploy()` (WAF deploy, ~line 1199):
```go
// Replace: syncCaddyfileZones(rs, deployCfg)
// With:    syncCaddyfileServices(rlrs, deployCfg)
```

`MergeCaddyfileServices()` replaces `MergeCaddyfileZones()` — uses the same `rlImportPattern` regex to discover services from Caddyfile imports, then creates default rules (instead of default zones) for any new services.

### 4.7 CLI Subcommands: `wafctl/cli.go`

Add new subcommand group (after `blocklist` commands, ~line 400):

```go
case "ratelimit", "rl":
    if len(args) < 2 { usage(); os.Exit(1) }
    switch args[1] {
    case "list":    cliRateLimitList(addr, jsonOut)
    case "get":     cliRateLimitGet(addr, args[2], jsonOut)
    case "create":  cliRateLimitCreate(addr, inputFile, jsonOut)
    case "delete":  cliRateLimitDelete(addr, args[2], jsonOut)
    case "deploy":  cliRateLimitDeploy(addr, jsonOut)
    case "summary": cliRateLimitSummary(addr, jsonOut)
    case "events":  cliRateLimitEvents(addr, jsonOut)
    }
```

Each function follows the existing CLI pattern: build HTTP request → send to wafctl API → format output.

### 4.8 Analytics Enhancement: `wafctl/rl_analytics.go`

**Per-rule hit tracking** (new function):

```go
// RLRuleHits returns per-rule hit counts with sparklines, analogous to handleExclusionHits.
func (als *AccessLogStore) RuleHits(rules []RateLimitRule, hours int) map[string]HitStats
```

Implementation:
1. Scan 429 events
2. Extract zone name from `X-RateLimit-Policy` response header (the `name="..."` portion)
3. Map zone name back to rule name via a lookup table (zone name → rule ID → rule name)
4. Aggregate counts + sparkline buckets per rule

**HitStats** struct (reuse from exclusion hits or define shared):
```go
type HitStats struct {
    Total     int   `json:"total"`
    Sparkline []int `json:"sparkline"` // Hourly buckets, oldest-first
}
```

---

## 5. Frontend Implementation

### 5.1 API Client: `waf-dashboard/src/lib/api.ts`

**New types** (append after `RLEventsData`, ~line 1034):

```typescript
export interface RateLimitRule {
  id: string;
  name: string;
  description?: string;
  service: string;
  conditions?: Condition[];      // Reuse existing Condition interface
  group_operator?: string;
  key: string;                   // "client_ip", "header:X-API-Key", etc.
  events: number;
  window: string;
  action?: string;               // "deny" or "log_only"
  priority?: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface RateLimitRuleConfig {
  rules: RateLimitRule[];
  global?: RateLimitGlobalConfig;
}

export interface RateLimitGlobalConfig {
  jitter?: number;
  sweep_interval?: string;
  distributed?: boolean;
}

export interface RLRuleHitsResponse {
  [ruleName: string]: { total: number; sparkline: number[] };
}
```

**New API functions:**

```typescript
export async function getRLRules(): Promise<RateLimitRule[]>
export async function createRLRule(rule: Partial<RateLimitRule>): Promise<RateLimitRule>
export async function updateRLRule(id: string, rule: Partial<RateLimitRule>): Promise<RateLimitRule>
export async function deleteRLRule(id: string): Promise<void>
export async function deployRLRules(): Promise<RateLimitDeployResult>
export async function getRLRuleHits(hours?: number): Promise<RLRuleHitsResponse>
export async function exportRLRules(): Promise<RateLimitRule[]>
export async function importRLRules(rules: RateLimitRule[]): Promise<void>
export async function getRLGlobal(): Promise<RateLimitGlobalConfig>
export async function updateRLGlobal(config: RateLimitGlobalConfig): Promise<void>
```

### 5.2 Rate Limits Page: Rewrite `RateLimitsPanel.tsx`

The current 644-line flat zone table is replaced with a policy engine-style interface. The new component reuses existing sub-components:

**Reused from policy engine:**
- `ConditionBuilder.tsx` / `ConditionRow` — same condition field/operator/value builder
- `HostValueInput` — service selector dropdown
- Tag input components for multi-value fields
- `exclusionHelpers.ts` patterns (adapted for RL rules)

**New sub-components** (in `waf-dashboard/src/components/rate-limits/`):

| Component | Purpose | Estimated Lines |
|---|---|---|
| `RateLimitRuleList.tsx` | Main rule list with search, filter, pagination, sparklines | ~400 |
| `RateLimitRuleForm.tsx` | Create/edit dialog with conditions, key picker, presets | ~350 |
| `RateLimitKeyPicker.tsx` | Dropdown for key type with dynamic sub-fields | ~100 |
| `RateLimitGlobalSettings.tsx` | Jitter, sweep interval, distributed toggle | ~80 |
| `constants.ts` | Key types, presets, field definitions | ~80 |

**UI Layout:**

```
┌────────────────────────────────────────────────────────┐
│ Rate Limit Rules                    [+ New Rule] [⚙]  │
│ ┌─────────────────────────────────────────────────────┐│
│ │ 🔍 Search rules...          [Service ▼] [All ▼]    ││
│ └─────────────────────────────────────────────────────┘│
│                                                        │
│ ┌──────┬──────────┬──────────┬────┬────┬────┬───┬───┐ │
│ │ Name │ Service  │ Match    │Key │Rate│Hits│ ⚡│ 🗑│ │
│ ├──────┼──────────┼──────────┼────┼────┼────┼───┼───┤ │
│ │ API  │ sonarr   │ POST     │ IP │50/ │ ▁▃│ ✓ │ × │ │
│ │ Write│          │ /api/*   │    │ 1m │ ▅▇│   │   │ │
│ ├──────┼──────────┼──────────┼────┼────┼────┼───┼───┤ │
│ │ Std  │ sonarr   │ (all)    │ IP │300/│ ▂▂│ ✓ │ × │ │
│ │ Limit│          │          │    │ 1m │ ▃▃│   │   │ │
│ └──────┴──────────┴──────────┴────┴────┴────┴───┴───┘ │
│                                                        │
│ ┌─ Global Settings ─────────────────────────────────┐  │
│ │ Jitter: 20%    Sweep: 1m    Distributed: Off      │  │
│ └───────────────────────────────────────────────────┘  │
│                                          [Deploy]      │
└────────────────────────────────────────────────────────┘
```

**Preset Templates** (in create dialog):

| Preset | Service | Conditions | Key | Rate |
|---|---|---|---|---|
| Standard Service | (selected) | (none) | client_ip | 300/1m |
| API Login Protection | (selected) | path begins_with `/api/login`, method in `POST` | client_ip | 10/1m |
| Upload Limit | (selected) | path begins_with `/upload`, method eq `POST` | client_ip | 5/1m |
| Admin Protection | (selected) | path begins_with `/admin` | client_ip | 100/1m |
| API Key Limit | (selected) | (none) | header:X-API-Key | 1000/1h |
| Global Burst | (selected) | (none) | static | 10000/1s |

### 5.3 Cross-Page Navigation

- **Overview → Rate Limits**: Rate-limited stat card links to `/events?type=rate_limited`
- **Events → Rate Limits**: "Create Rate Limit Rule" button on 429 events stores event in sessionStorage, navigates to `/rate-limits?from_event=1`
- **Rate Limits → Overview**: Sparkline hit counts link to `/?rule_name=<name>`

---

## 6. File Inventory

### Files to Create

| File | Purpose | Est. Lines |
|---|---|---|
| `wafctl/rl_rules.go` | Rule store (CRUD, validation, migration) | ~400 |
| `wafctl/rl_rules_test.go` | Tests for rule store | ~600 |
| `wafctl/rl_generator.go` | Caddy config generator for RL rules | ~300 |
| `wafctl/rl_generator_test.go` | Tests for RL generator | ~500 |
| `waf-dashboard/src/components/rate-limits/RateLimitRuleList.tsx` | Rule list component | ~400 |
| `waf-dashboard/src/components/rate-limits/RateLimitRuleForm.tsx` | Create/edit dialog | ~350 |
| `waf-dashboard/src/components/rate-limits/RateLimitKeyPicker.tsx` | Key type selector | ~100 |
| `waf-dashboard/src/components/rate-limits/RateLimitGlobalSettings.tsx` | Global settings | ~80 |
| `waf-dashboard/src/components/rate-limits/constants.ts` | Constants and presets | ~80 |

### Files to Modify

| File | Changes |
|---|---|
| `wafctl/models.go` | Add `RateLimitRule`, `RateLimitRuleConfig`, `RateLimitGlobalConfig` structs; add validation maps for key format, RL action |
| `wafctl/main.go` | Add new route registrations (~12 endpoints), new handlers, wire `RateLimitRuleStore`, update startup to use new store |
| `wafctl/deploy.go` | Update `generateOnBoot()` to use new store, add `writeRLFiles()` with stale file cleanup |
| `wafctl/rl_analytics.go` | Add zone-to-rule name mapping in `Load()`, add `RuleHits()` method |
| `wafctl/cli.go` | Add `ratelimit`/`rl` subcommand group with list/get/create/delete/deploy/summary/events |
| `wafctl/exclusions.go` | Extract `validateCondition()` into a shared function (used by both exclusions and RL rules) |
| `wafctl/ratelimit.go` | Deprecate `RateLimitStore`, add migration helper. Eventually remove. |
| `waf-dashboard/src/lib/api.ts` | Add new types and API functions for RL rules |
| `waf-dashboard/src/components/RateLimitsPanel.tsx` | Rewrite to use new rule-based components |
| `waf-dashboard/src/pages/rate-limits.astro` | Update imports if component names change |

### Files to Eventually Remove (post-migration)

| File | Reason |
|---|---|
| `wafctl/ratelimit.go` | Replaced by `rl_rules.go` + `rl_generator.go` |
| `wafctl/ratelimit_test.go` | Replaced by `rl_rules_test.go` + `rl_generator_test.go` |

---

## 7. Test Plan

### 7.1 Go Tests

**`rl_rules_test.go`** (~600 lines):

| Test | Description |
|---|---|
| `TestRLRuleStoreStartsEmpty` | Fresh store has 0 rules |
| `TestRLRuleStoreCreate` | Create rule, verify UUID/timestamps assigned |
| `TestRLRuleStoreUpdate` | Update rule, verify immutable fields preserved |
| `TestRLRuleStoreDelete` | Delete rule, verify removed from list |
| `TestRLRuleStoreGet` | Get by ID, returns deep copy |
| `TestRLRuleStoreListByService` | Filter rules by service hostname |
| `TestRLRuleStoreEnabledRules` | Filter to enabled-only |
| `TestRLRuleStorePersistence` | Save to disk, reload, verify state |
| `TestRLRuleStoreRollback` | Mutation failure reverts to previous state |
| `TestRLRuleStoreImportExport` | Round-trip import/export |
| `TestRLRuleValidation` | Table-driven: valid rule, missing name, invalid key, bad events, bad window, invalid action, invalid priority, invalid conditions, duplicate names per service |
| `TestRLRuleMigrationFromV1` | Old `{"zones":[...]}` format auto-migrated to rules |
| `TestRLRuleKeyValidation` | All key formats validated |
| `TestRLRuleConditionValidation` | Reuses condition validation from exclusions |
| `TestRLRuleStoreDeepCopy` | Modifying returned rule doesn't affect store |

**`rl_generator_test.go`** (~500 lines):

| Test | Description |
|---|---|
| `TestGenerateServiceRL_SingleRule` | One rule, no conditions → basic zone with matcher |
| `TestGenerateServiceRL_MultipleRules` | Multiple rules sorted by priority |
| `TestGenerateServiceRL_WithConditions` | Path + method conditions → correct Caddy matchers |
| `TestGenerateServiceRL_DisabledRules` | Disabled rules omitted entirely |
| `TestGenerateServiceRL_AllDisabled` | All disabled → comment-only file |
| `TestGenerateServiceRL_Jitter` | Global jitter setting emitted |
| `TestGenerateServiceRL_CustomKey` | header:X-API-Key → correct placeholder |
| `TestGenerateServiceRL_CompoundKey` | client_ip+path → concatenated placeholders |
| `TestGenerateServiceRL_StaticKey` | static key → literal "static" |
| `TestGenerateServiceRL_ORConditions` | OR grouping → multiple match blocks |
| `TestGenerateServiceRL_ANDConditions` | AND grouping → single match block |
| `TestRLZoneName` | Zone name generation from service + rule ID |
| `TestRLConditionToMatcher` | Each condition field/operator → correct Caddy matcher |
| `TestRLKeyToPlaceholder` | Each key format → correct Caddy placeholder |
| `TestWriteRLFiles_StaleCleanup` | Old files for deleted rules are removed |
| `TestGenerateRateLimitConfigs_MultiService` | Multiple services → separate files |

**Handler tests** (added to `handlers_test.go`):

| Test | Description |
|---|---|
| `TestRLRuleCRUDEndpoints` | GET/POST/PUT/DELETE round-trip |
| `TestRLRuleDeployEndpoint` | Mock Caddy admin, verify files written + reload |
| `TestRLRuleHitsEndpoint` | Per-rule hit counts from 429 events |
| `TestRLRuleValidationErrors` | HTTP 400 on invalid input |

**CLI tests** (added to `cli_test.go`):

| Test | Description |
|---|---|
| `TestCLIRateLimitList` | `wafctl rl list` output |
| `TestCLIRateLimitCreate` | `wafctl rl create` with JSON input |
| `TestCLIRateLimitDelete` | `wafctl rl delete <id>` |
| `TestCLIRateLimitDeploy` | `wafctl rl deploy` |

### 7.2 Frontend Tests

**New test files:**

| File | Tests |
|---|---|
| `api.test.ts` (extend) | New RL rule API functions: CRUD, deploy, hits, export, import |
| `rate-limits/constants.test.ts` | Key format validation, preset definitions |

### 7.3 Integration Tests

| Test | Description |
|---|---|
| `TestGenerateOnBootWithRLRules` | Boot generates RL files from stored rules |
| `TestWAFDeploySyncsRLRules` | WAF deploy also ensures RL files exist |
| `TestMigrationE2E` | Start with old zones JSON, verify auto-migration + file generation |

---

## 8. Implementation Phases

### Phase 1: Backend Core (Est. 2-3 days)
1. Add data models to `models.go`
2. Create `rl_rules.go` (store + validation)
3. Create `rl_rules_test.go`
4. Extract shared condition validation from `exclusions.go`

### Phase 2: Generator (Est. 1-2 days)
1. Create `rl_generator.go`
2. Create `rl_generator_test.go`
3. Update `deploy.go` for new generate + write + cleanup flow

### Phase 3: API Handlers (Est. 1 day)
1. Add CRUD handlers to `main.go`
2. Wire new store in startup
3. Add to `handlers_test.go`
4. Migration logic for old → new format

### Phase 4: Analytics (Est. 1 day)
1. Update `rl_analytics.go` for zone attribution
2. Add `RuleHits()` method
3. Add hits endpoint handler

### Phase 5: CLI (Est. 0.5 day)
1. Add `ratelimit`/`rl` subcommands to `cli.go`
2. Add CLI tests

### Phase 6: Frontend (Est. 2-3 days)
1. Add types + API functions to `api.ts`
2. Create rule list, form, key picker, global settings components
3. Rewrite `RateLimitsPanel.tsx`
4. Add frontend tests

### Phase 7: Migration & Cleanup (Est. 0.5 day)
1. Auto-migration from v1 format on startup
2. Remove old `ratelimit.go`, `ratelimit_test.go`, old handlers from `main.go`
3. Update AGENTS.md, README.md

---

## 9. Backward Compatibility

- **Old API endpoints removed** — `/api/rate-limits`, `/api/rate-limits/summary`, `/api/rate-limits/events` are deleted. New endpoints at `/api/rate-rules/*`. RL analytics served via unified `/api/summary` and `/api/events`.
- **Old JSON format** (`{"zones":[...]}`) auto-migrated on first startup to `{"rules":[...], "global":{}}`. Backup saved to `rate-limits.json.v1.bak`.
- **Caddyfile import pattern** unchanged — same `import /data/caddy/rl/<zone>_rl*.caddy` globs
- **Generated file naming** — new rules still produce `<service>_rl.caddy` files (one per service, containing all zones for that service)
- **Environment variables** — `WAF_RATELIMIT_FILE`, `WAF_RATELIMIT_DIR` paths unchanged

---

## 10. Version Sync Checklist

When merging, update version in:
- [ ] `Makefile` (lines 17-18)
- [ ] `compose.yaml` (lines 3, 116)
- [ ] `README.md` (badges)
- [ ] `test/docker-compose.test.yml` (line 3)
- [ ] AGENTS.md (API endpoints table, model docs)

---

## 11. Design Decisions (Resolved)

1. **Old `/api/rate-limits` endpoints: Remove immediately.**
   No deprecation shim. The old `RateLimitStore`, its handlers, and the flat zone model
   are replaced outright by the new `RateLimitRuleStore` and `/api/rate-rules` endpoints.
   The old `ratelimit.go` is deleted. Analytics endpoints (`/api/rate-limits/summary`,
   `/api/rate-limits/events`) are also removed — analytics are served through the
   unified `/api/summary` and `/api/events` with `event_type=rate_limited`.

2. **`log_only` action: Separate logging path.**
   When `action = "log_only"`, the generator produces a Caddy `log` directive block
   that records matching requests to a structured log *without* the `rate_limit` plugin.
   This provides accurate monitoring without false 429s or inflated thresholds.
   Implementation: generate a `@rl_monitor_<zone>` named matcher + `log` directive
   that writes to the combined access log with an `X-RateLimit-Monitor: <rule_name>`
   header. The `AccessLogStore` recognizes this header to count "monitored" events.

3. **Distributed RL: Full UI in v1.**
   The Global Settings panel includes: distributed toggle (on/off), read interval,
   write interval, purge age. All wired to `RateLimitGlobalConfig` and emitted in
   the generated `rate_limit { distributed { ... } }` block.

4. **Zone attribution: Condition-based inference.**
   When a 429 is received, the `AccessLogStore` matches the request's path, method,
   IP, and headers against stored `RateLimitRule` conditions to infer which rule
   triggered. The `AccessLogStore` receives a reference to `RateLimitRuleStore` to
   perform this lookup. For multi-zone services, rules are evaluated in priority
   order (lower priority number = checked first); the first matching rule is
   attributed. If no rule matches, the event is attributed to the service generically.
