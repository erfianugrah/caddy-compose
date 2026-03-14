# PLAN.md — Policy Engine Roadmap

## Current State (v2.26.0 / caddy 3.25.0 / plugin v0.14.1)

Fully operational WAF with custom policy engine, CRS 4.24.1 (254 default rules),
5-pass evaluation (allow → block → skip → rate_limit → detect), 6 negated operators,
managed lists, IPsum blocklist (8 levels, 597K IPs), per-service skip rule management,
logged event collection (tuning mode visibility), and e2e CI pipeline.

### Completed Milestones

| Version | Feature |
|---------|---------|
| v0.6.1 | Client IP fix |
| v0.7.0 | Response phase: CSP & security headers |
| v0.8.0 | Anomaly scoring engine (detect rules) |
| v0.8.1 | Transform functions (17 transforms) |
| v0.9.0 | Multi-variable inspection + Aho-Corasick phrase match |
| v0.10.x | Default rules loading, CRS 920/930/941/942/943 categories |
| v0.11.x | CRS LFI/protocol/session fixation, RE2 regex fix |
| v0.14.0 | Skip action (5-pass), 6 negated operators |
| v0.14.1 | Below-threshold detect_rules/tags emission |

### Completed This Session

- Skip action type: plugin 5-pass eval, wafctl validation/generation, frontend UI
- 6 negated operators: not_contains, not_begins_with, not_ends_with, not_regex, not_in, not_phrase_match
- Dead settings removed from `/rules` page (Mode, CRS groups, Advanced CRS v4)
- Logged event collection from access logs (tuning/log-only mode)
- policy_skip event collection from access logs
- Skip prefill from events (logged → skip with rule IDs)
- Inline CRS rule picker per service (searchable dropdown + pills)
- Transform UI: Select-style dropdown + numbered pills below
- CRS breadcrumb navigation, policy dialog refresh
- CORS Origin allowlist (regex validation instead of Host reflection)
- CRS PL section headers (Active/Inactive badge + threshold)
- RawRateLimitRule type safety
- E2E CI job, image existence check, 14 new e2e tests
- Policy table: Tags column, column alignment fix
- Skipped events show rule ID pills in detail
- View in General Logs link fixed (request_id param)
- useStaleSafeRequest hook extracted

---

## Open Items

### Major Features (Future Sessions)

#### 1. Policy UI Unification — Merge Rate Limits into `/policy`

Unified rule table showing all rule types (allow, block, skip, detect, rate_limit)
on a single `/policy` page. Currently rate limits are on a separate `/rate-limits` page.

**Scope:**
- Merge `RateLimitsPanel` into `PolicyEngine` as a unified table
- Unified create/edit dialog that handles all 5 rule types
- Single priority ordering across all rule types
- Remove `/rate-limits` page

#### 2. Per-Service CRS Profiles — Plugin Rule Masks

Allow different CRS rule sets per service at the plugin level, not just
skip rules with host conditions. Would enable: "authelia runs PL1 with
only protocol rules, httpbun runs PL2 with full CRS."

**Scope:**
- Plugin: per-service rule masks in wafConfig
- wafctl: new store for per-service CRS profiles
- Frontend: profile selector on per-service override card

#### 3. Response-Phase Detection (Phase 2)

Outbound anomaly scoring — inspect response bodies after `next.ServeHTTP()`.
Would enable ~100+ CRS outbound rules (response body inspection).

**Scope:**
- Plugin: response body buffering + inspection
- Plugin: outbound anomaly scoring with separate threshold
- wafctl: wire `outbound_threshold` through `BuildPolicyWafConfig()`
- CRS converter: port outbound rule categories

### Design Decisions Pending

- [ ] **Mode field**: Either implement detection-only mode in the plugin
  (detect but don't block on threshold) or remove `mode` from `WAFConfig` entirely.
  Currently `mode` is persisted but ignored by the policy engine.

- [ ] **CRS Rule Group disabling**: Either implement in the policy generator
  (filter `default-rules.json` by tag at generation time) or remove
  `disabled_groups` from WAFConfig. Currently persisted but ignored.

### Operational

- [ ] Audit each service's built-in auth and document decisions
- [ ] Add `forward_auth` to dockge at minimum
- [ ] Monitor and document sizing guidance for event stores

### Low Priority / Deferred

- [ ] CRS accuracy evaluation against CRS test suite
- [ ] Compare detection rates: regex-only vs regex+libinjection
- [ ] `operatorChip()` for negated operators in DashboardFilterBar
  (deferred — negated operators only used in condition builder, not filter bar)
