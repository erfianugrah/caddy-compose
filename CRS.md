# CRS.md — CRS Converter Fidelity & Implementation Fixes

Tracking file for CRS converter accuracy improvements and code quality fixes.
Branch: `fix/crs-improvements`

---

## Context

CRS implementation spans 4 layers: build-time converter (`tools/crs-converter/`),
runtime metadata + catalog (`wafctl/crs_metadata.go`, `wafctl/crs_rules.go`),
API (`GET /api/crs/rules`), and frontend (`useCRSCategories`, `CRSRulePicker`,
`CategoryToggles`).

Current fidelity: **90.8% (216/238 rules)**. 22 failures:
- 9 Go HTTP client limitations (can't send malformed HTTP — not fixable)
- 13 false positives from converter deficiencies (fixable)

Target: **95%+** — fixing the converter issues below eliminates the 13 false positives.

---

## Converter Fidelity — Production False Positives

Observed in production: a simple `GET /` from a normal client (US IP, standard
browser headers) blocked with anomaly score 32. Seven rules matched — six are
false positives caused by three systemic converter bugs.

### Observed False Positives

| Rule | Name | Matched | Full Value | Root Cause |
|------|------|---------|------------|------------|
| 920450 | HTTP header restricted by policy | `cf-ray` | `Cf-Ray` | F1: chain-drop — matches every header |
| 920451 | HTTP header restricted by policy | `cf-ray` | `Cf-Ray` | F1: chain-drop — matches every header |
| 932236 | Unix Command Injection | `gzip,` | `gzip, br` | F2: over-consolidation — checks Accept-Encoding |
| 932260 | Direct Unix Command Execution | `gzip,` | `gzip, br` | F2: over-consolidation — checks Accept-Encoding |
| 942340 | SQL auth bypass 3/3 | `"scheme":` | `{"scheme":"https"}` | F2: over-consolidation — checks Cf-Visitor |
| 942440 | SQL Comment Sequence | `*/` | `*/*` | F2: over-consolidation — checks Accept header |

### F1. Chain Link TX-Variable Drop (920450, 920451)

**Files:** `tools/crs-converter/converter.go:341-354`

**The original CRS rule is a two-part chain:**
1. Head: `REQUEST_HEADERS_NAMES @rx ^.*$` — captures every header name into TX vars
2. Chain: `TX:/^header_name_920450_/ @within %{tx.restricted_headers_basic}` — checks
   if the captured header name is in a restricted list (proxy, lock-token, etc.)

**What the converter does:** In `convertChain()` at line 349, the chain link's
variables are mapped. `TX` maps to `""` in `variableMap` (`mapper.go:72`), so
`mapVariablesToConditions()` returns zero fields. `skipThisLink` becomes `true`
(line 350). The chain condition is silently dropped.

**Result:** Only the head rule survives: `all_headers_names @rx ^.*$` — matches
every header name on every request. Score +5 per match. A request with 10
headers accumulates +50 anomaly score from a single rule.

**The `@within %{tx.restricted_headers_basic}` operator also fails independently:**
At `converter.go:254`, `@within` with TX variable references returns an error, which
would cause the entire rule to be skipped. But the chain link path at line 380 sets
`skipThisLink = true` instead of erroring, so the head survives without its filter.

**Duplicate ID problem:** `waf/default-rules.json` contains TWO rules with ID 920450:
- Index 39: manually-written custom rule — `phrase_match` against 5 restricted headers
  (correct behavior)
- Index 40: CRS-converted rule — `regex ^.*$` against all headers (broken)

Both fire because `DefaultRuleStore` loads all rules into `ds.defaults` slice at
`default_rules.go:72`. The `defaultsByID` map (line 75) does last-write-wins, but
the full slice is what gets deployed to `policy-rules.json`.

**7 duplicate IDs total** in `default-rules.json`: 920180, 920300, 920311, 920440,
920450, 932180, 943120. Each has a correct custom version and a broken CRS version.

**Fix — two parts:**

1. **Converter**: Detect the "capture-all + TX-variable chain" pattern and skip the
   rule entirely (it can't be converted without TX variable support). The custom
   rules already provide the correct replacement. Add to `shouldSkipRule()` in
   `converter.go`: if a rule's chain link uses `@within %{tx.*}`, skip the entire
   rule rather than emitting a broken head-only version.

2. **Deduplication**: The converter or the build pipeline must deduplicate rules. When
   custom rules and CRS-converted rules share an ID, the custom rule should win.
   Options: (a) converter skips IDs that exist in custom-rules.json, (b) build script
   merges with custom-first priority, (c) `DefaultRuleStore` deduplicates on load.

### F2. Over-Aggressive `consolidateFields()` (932236, 932260, 942340, 942440)

**File:** `tools/crs-converter/mapper.go:306-376`

**The core problem:** `consolidateFields()` collapses multiple fields into
`request_combined` when 4+ "categories" are present (args, cookies, headers, body).
But the category detection is too coarse:

```go
hasHeaders := set["all_headers"] || set["all_headers_names"]  // line 323
```

This checks for the aggregate `all_headers` field. Named header shortcuts like
`user_agent` and `referer` (from `headerShortcuts` at mapper.go:87-94) are individual
fields and don't set `hasHeaders`. So how does `request_combined` get triggered?

**The actual trigger path — field count, not category count:**

When a CRS rule targets `ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|
REQUEST_BODY|REQUEST_FILENAME|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|
XML:/*`, `mapVariablesToConditions()` produces fields:
- `all_args_values`, `all_args_names` (hasArgs = true)
- `all_cookies`, `all_cookies_names` (hasCookies = true)
- `body` (hasBody = true, via `uri_path` or `request_basename`)
- `user_agent`, `referer` (individual fields — NOT hasHeaders)
- `xml` (unmapped or mapped to a specific field)

With `REQUEST_FILENAME` → `request_basename` or `uri_path`, `hasBody` includes those
(line 324: `set["uri_path"] || set["request_basename"]`). If `XML` maps to a field
that triggers another category, or if the set includes enough misc fields, the
4-category threshold fires.

**But even without hitting 4 categories**, the 2-category fast path at line 346-349
triggers when args AND cookies are fully present:
```go
if set["all_args_values"] && set["all_args_names"] &&
    set["all_cookies"] && set["all_cookies_names"] {
    return "request_combined"
}
```

This alone would produce `request_combined` for rules 942340/942440 which target
args + cookies + body (no headers). And `request_combined` in the plugin evaluates
ALL request sources including ALL headers.

**Why this is wrong for each rule:**

- **932236/932260** (RCE): Original CRS targets args, cookies, body, and ONLY
  `User-Agent` + `Referer` headers. Converted to `request_combined` which also checks
  `Accept-Encoding: gzip, br` → comma triggers RCE regex.
- **942340** (SQLi PL2): Original CRS targets args, cookies, body. NO headers.
  Converted to `request_combined` which checks `Cf-Visitor: {"scheme":"https"}` →
  `"scheme":` triggers SQLi regex.
- **942440** (SQL comment): Same as 942340. `Accept: */*` contains `*/` which
  matches the SQL comment-close regex.

**Fix — condition groups instead of field consolidation:**

Instead of collapsing to a single `request_combined`, emit an OR-group of per-field
conditions. The `PolicyCondition.Group` / `GroupOp` fields already exist in
`types.go:91-92` but are never used by `convertRule()`.

For a rule targeting args + cookies + body + user_agent + referer:
```json
{
  "group": [
    {"field": "all_args_values", "operator": "regex", "value": "..."},
    {"field": "all_args_names",  "operator": "regex", "value": "..."},
    {"field": "all_cookies",     "operator": "regex", "value": "..."},
    {"field": "all_cookies_names","operator": "regex", "value": "..."},
    {"field": "body",            "operator": "regex", "value": "..."},
    {"field": "user_agent",      "operator": "regex", "value": "..."},
    {"field": "referer",         "operator": "regex", "value": "..."}
  ],
  "group_op": "or"
}
```

This preserves the original CRS variable scope exactly — each field is checked
individually, and the rule matches if ANY field matches (OR semantics, matching
CRS behavior).

**Implementation:**

1. Replace `consolidateFields()` with `buildFieldConditions()` that returns either
   a single `PolicyCondition` (when there's only one field) or a group condition
   (when there are multiple fields). Remove the `request_combined` consolidation
   path entirely.

2. In `convertRule()` at line 283-292, instead of:
   ```go
   field := consolidateFields(fields)
   cond := PolicyCondition{Field: field, Operator: opName, ...}
   ```
   Generate:
   ```go
   cond := buildFieldCondition(fields, opName, operatorValue, ...)
   // returns grouped condition when len(fields) > 1
   ```

3. Same change in `convertChain()` at line 353.

4. Verify the plugin correctly evaluates nested OR groups with detection operators
   (`detect_sqli`, `detect_xss`, `regex`, `phrase_match`). The group infrastructure
   exists in the plugin but may not have been exercised with all operator types.

**Scope:** This fix affects ~100+ CRS rules that currently use `request_combined`.
All of them become more precise (narrower scope = fewer false positives). Some
may lose detections that relied on `request_combined`'s broader scope, but those
detections were never intended by the CRS rule authors.

### F3. `SecRuleUpdateTargetById` Not Processed

**File:** `tools/crs-converter/parser.go:37`

**Problem:** The parser explicitly skips `SecRuleUpdateTargetById` directives:
```go
strings.HasPrefix(text, "SecRuleUpdateTargetById") ||
```

CRS uses this to retroactively add variable exclusions to rules:
```
SecRuleUpdateTargetById 932240 "!REQUEST_COOKIES:/^_ga(?:\w+)?$/"
```

This means "rule 932240 should skip cookies matching `_ga*`." Without this, the
rule checks Google Analytics cookies and produces false positives.

**Fix:**

1. **Parse**: Instead of skipping, parse into a new `SecRuleUpdate` struct:
   `{TargetRuleID: "932240", Variables: "!REQUEST_COOKIES:/^_ga.../"}`.
2. **Two-pass processing**: `SecRuleUpdateTargetById` can appear in a later `.conf`
   file than the rule it modifies. Collect all updates in pass 1, apply them to
   the parsed rule AST in pass 2 before conversion.
3. The negation variables (`!REQUEST_COOKIES:pattern`) already flow through
   `mapVariablesToConditions()` → `excludeVars` → condition `excludes`. The
   pipeline handles them correctly once they're in the AST.

**Estimated complexity:** Medium (~100-150 lines). Independent of F1/F2.

### F4. CRS `ctl:ruleRemoveByTag` Translation

**File:** `tools/crs-converter/converter.go` (no handling exists)

**Problem:** CRS uses `ctl:ruleRemoveByTag=<tag>` as a runtime directive to disable
all rules with a matching tag for the current request. Example:

```
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json" \
    "id:900100,pass,nolog,ctl:ruleRemoveByTag=attack-sqli"
```

"If Content-Type is application/json, disable all SQLi detection." This suppresses
false positives from JSON payloads that contain SQL-like syntax. The converter has
zero awareness of `ctl:` actions — they're parsed (`parser.go:400-437`) but never
consumed.

These suppression rules have `pass,nolog` and no `msg`/`severity`, so they're
dropped by the "data-extraction helper" skip at `converter.go:160-172`.

**Fix — static expansion at conversion time (no plugin changes):**

1. When the converter encounters a rule with `ctl:ruleRemoveByTag=<tag>` action,
   don't skip it as a data-extraction helper.
2. Look up all converted rules with that tag in the current rule set.
3. Generate a `type: "skip"` rule with `skip_targets.rules` populated from the
   tag→ruleIDs index.
4. Conditions come from the original rule's variables/operators (the "when to
   suppress" logic).

**Estimated complexity:** High (~200-300 lines). Partially depends on F3 (some
`ctl:` rules appear in `SecRuleUpdateTargetById` contexts). This fix directly
addresses 13 of the 22 regression failures — it's the highest-impact item.

### Fidelity Fix Execution Order

Dependencies: F2 is independent. F1 is independent. F3 is independent. F4
partially depends on F3 (some `ctl:` directives come via `SecRuleUpdateTargetById`).

Recommended order by impact:

```
F2 (consolidateFields) ─── highest impact, systemic, independent
  ↓
F1 (chain-drop + dedup) ── high impact, independent
  ↓
F4 (ctl:ruleRemoveByTag) ─ 13 of 22 failures, depends partially on F3
  ↓
F3 (SecRuleUpdateTargetById) ── unlocks more exclusions for F4
```

| Fix | Impact | Estimated LOC | Effort |
|-----|--------|---------------|--------|
| F2 | ~100+ rules become precise | ~150-200 | 1-2 days |
| F1 | Eliminates match-everything rules + dedup | ~80-100 | 0.5-1 day |
| F3 | Adds cookie/arg exclusions | ~100-150 | 1 day |
| F4 | Eliminates 13 FP failures | ~200-300 | 1.5-2 days |
| **Total** | | **~530-750** | **~4-6 days** |

### F5. Duplicate Rule IDs in `default-rules.json` (Build pipeline)

**Files:** `tools/crs-converter/main.go:93-105`, `waf/default-rules.json`

**Problem:** The converter merges custom rules by appending them AFTER CRS-converted
rules (`main.go:103`), then sorts by ID (`main.go:108`). `SortRules` uses
`sort.Slice` which is NOT stable — for duplicate IDs, the ordering between the
custom rule and CRS-converted rule is non-deterministic across builds.

7 duplicate IDs currently exist in `default-rules.json`:

| ID | Custom rule (correct) | CRS-converted (broken) |
|----|-----------------------|----------------------|
| 920180 | POST missing Content-Type | POST without Content-Length and Transfer-Encoding |
| 920300 | Max number of request arguments | Request Missing an Accept Header |
| 920311 | Argument value too long | Request Has an Empty Accept Header |
| 920440 | URL file extension restricted | URL file extension is restricted |
| 920450 | HTTP header restricted (phrase_match, 5 items) | HTTP header restricted (regex `^.*$`, matches everything) |
| 932180 | Restricted File Upload Attempt | Restricted file upload attempt |
| 943120 | Session fixation — session ID parameter | Possible Session Fixation Attack |

Both versions of each rule are deployed to the plugin. The plugin has merge-by-ID
logic for overrides (`ApplyDefaultRuleOverrides` at `policy_generator.go:377`), but
these aren't overrides — they're duplicate baked defaults. Both fire.

**Fix:** The converter must deduplicate. When merging custom rules, skip any CRS rule
whose ID already exists in the custom rules set. Custom rules are the curated
corrections — they should always win:

```go
// After CRS conversion, before merge:
customIDs := make(map[string]bool)
for _, r := range custom {
    customIDs[r.ID] = true
}
var deduped []PolicyRule
for _, r := range allRules {
    if !customIDs[r.ID] {
        deduped = append(deduped, r)
    }
}
allRules = append(deduped, custom...)
```

Also switch `SortRules` to `sort.SliceStable` for deterministic output.

---

## CI/Build Pipeline Analysis

### Pipeline Flow

```
.github/workflows/build.yml          (CI trigger: push to main)
    ↓
Dockerfile (4-stage multi-stage)
    ↓
Stage 2: crs-rules
    1. Build tools/crs-converter/
    2. git clone --depth 1 --branch ${CRS_VERSION} coreruleset/coreruleset
    3. Run crs-converter:
         -crs-dir /crs/rules
         -crs-version ${CRS_VERSION#v}
         -custom-rules /build/custom-rules.json
         -output /build/default-rules.json
         -metadata-output /build/crs-metadata.json
    ↓
Stage 4: final image
    COPY default-rules.json → /etc/caddy/waf/default-rules.json
    COPY crs-metadata.json  → /etc/caddy/waf/crs-metadata.json
```

### Source of Truth

- **CRS version**: Pinned as `CRS_VERSION: "v4.24.1"` in `build.yml:26` and
  `Dockerfile:2`. The Dockerfile `git clone --branch ${CRS_VERSION}` pulls exactly
  that tag from `coreruleset/coreruleset`.

- **Local clone**: `tools/coreruleset/` is a shallow git clone at v4.24.1 (tracked
  in `.gitignore` — not committed). This is for local development/reference only.
  Docker builds do a fresh clone.

- **Custom rules**: `waf/custom-rules.json` (24 rules, committed to git). These are
  manually-written replacements for CRS rules the converter handles badly.

- **Generated output**: `waf/default-rules.json` (349 rules, committed to git).
  Generated: 2026-03-17. This is the baked artifact — the Docker build regenerates
  it but the committed copy is used for local testing and as a reference.

### Auto-Update Workflow

`.github/workflows/crs-update.yml`:
- Runs weekly (Monday 08:00 UTC) + manual trigger
- Compares `CRS_VERSION` in `build.yml` against latest GitHub release
- If newer: bumps version in `build.yml` + `Dockerfile`, creates PR
- PR checklist includes "Verify default-rules.json regeneration"
- **Does NOT regenerate `default-rules.json` in the PR** — relies on the Docker
  build to do it. The committed copy may be stale after the version bump PR merges.

### CRS Regression Tests — NOT USED

The CRS repo at `tools/coreruleset/tests/regression/tests/` contains official YAML
test cases for every CRS rule (e.g., `932236.yaml` has 1786 lines of test vectors).
These are designed for [go-ftw](https://github.com/coreruleset/go-ftw), the official
CRS test framework.

**These tests are not integrated into the CI pipeline.** No Makefile target, no
workflow step, no Go test file references them. The "90.8% (216/238)" fidelity
number from PLAN.md was likely from a manual run.

The E2E tests (`test/e2e/`) are aware of CRS but intentionally **disable it** for
most tests to avoid interference:
- `helpers_test.go:774`: `allCRSCategories` list used to disable all CRS categories
- `helpers_test.go:777`: `wafDefaults` sets `disabled_categories` to all CRS prefixes
- `01_infra_test.go:15-16`: "Default threshold is 0 = blocking disabled. CRS
  evaluates and logs but never blocks."
- Only `TestCRSRulesCatalog` (`03_exclusions_test.go:73`) tests the CRS API endpoint

### Pipeline Gaps

#### P1. Standalone CRS E2E Test Suite

The official CRS YAML test cases exist locally at `tools/coreruleset/tests/regression/`
(316 YAML files, 4634 test cases covering true positives via `expect_ids` and false
positive checks via `no_expect_ids`). None of these are run anywhere in the pipeline.

The existing E2E suite (`test/e2e/`) intentionally disables all CRS categories
(`helpers_test.go:774`) to test custom rules in isolation. CRS detection tests
cannot be mixed into that suite — they need CRS enabled with a blocking threshold,
which would break every other E2E test.

**Fix: Build a standalone CRS E2E test suite at `test/crs/`.**

This is a separate Go test module with its own Docker Compose stack, its own
Makefile target, and its own CI job. It runs the official CRS YAML test vectors
against the live policy engine with CRS fully enabled.

**Architecture:**

```
test/crs/
    docker-compose.crs.yml     — Caddy + wafctl + httpbun (CRS enabled, threshold=5)
    Caddyfile.crs              — Minimal Caddyfile for CRS testing
    go.mod                     — module test/crs (deps: gopkg.in/yaml.v3)
    runner_test.go             — YAML parser + HTTP test runner
    baseline.json              — Known pass/fail/skip for each rule ID
    README.md                  — How to run, update baseline, triage failures
```

**How it works:**

1. `docker-compose.crs.yml` starts a stack identical to the E2E stack but with
   a WAF config that enables CRS blocking (threshold=5, no disabled categories).
   Uses the same `caddy-e2e:local` and `wafctl-e2e:local` images.

2. `runner_test.go` walks `tools/coreruleset/tests/regression/tests/` and parses
   each YAML file. For each test case:
   - Builds an HTTP request from the `input` spec (method, URI, headers, data)
   - Sends it to the Caddy proxy
   - Queries the wafctl events API for matched rule IDs
   - Compares against `expect_ids` (must be present) or `no_expect_ids` (must
     be absent)

3. `baseline.json` records the expected outcome per rule ID:
   ```json
   {
     "920100": {"status": "pass", "note": ""},
     "920450": {"status": "fail", "note": "F1: chain-drop, custom rule covers it"},
     "932236": {"status": "fail", "note": "F2: over-consolidation"},
     "941100": {"status": "skip", "note": "Go HTTP client limitation"}
   }
   ```
   Tests compare actual results against the baseline. New failures (rule was passing,
   now failing) cause the test to fail. Known failures matching the baseline pass.
   This prevents regressions while allowing known issues to be tracked.

4. Test output:
   ```
   === CRS Fidelity Report ===
   Total rules:  238 (testable)
   Passing:      216 (90.8%)
   Known fail:    13 (baselined)
   New fail:       0 (REGRESSION — test fails if > 0)
   Skipped:        9 (Go HTTP client limitations)
   ```

**Why not go-ftw:**

go-ftw is designed for ModSecurity/Coraza backends that emit Apache-format logs
with rule IDs in `SecAuditLog`. The policy engine emits structured JSON events
via wafctl, not ModSecurity audit logs. A custom runner that queries the wafctl
API (`GET /api/events`) is simpler and more reliable than adapting go-ftw's log
parser.

go-ftw also adds a heavy dependency (`gopkg.in/yaml.v3` + the go-ftw module
itself). The custom runner only needs `gopkg.in/yaml.v3` for YAML parsing.

**Test runner design (`runner_test.go`):**

```go
// TestCRSRegression walks the CRS YAML test directory and runs each test case.
func TestCRSRegression(t *testing.T) {
    baseline := loadBaseline(t, "baseline.json")
    yamlDir := "../../tools/coreruleset/tests/regression/tests"

    var stats Stats
    filepath.WalkDir(yamlDir, func(path string, d fs.DirEntry, err error) error {
        if !strings.HasSuffix(path, ".yaml") { return nil }
        suite := parseYAML(t, path)

        for _, tc := range suite.Tests {
            t.Run(fmt.Sprintf("%s/%d", suite.RuleID, tc.TestID), func(t *testing.T) {
                input := tc.Stages[0].Input
                req := buildRequest(input)
                resp := sendRequest(t, req)

                // Wait for event ingestion, then query matched rules
                matchedIDs := queryMatchedRules(t, resp)

                // Check expect_ids (true positive tests)
                for _, id := range tc.Stages[0].Output.Log.ExpectIDs {
                    if !contains(matchedIDs, id) {
                        recordResult(&stats, suite.RuleID, tc.TestID, "miss", baseline)
                    }
                }
                // Check no_expect_ids (false positive tests)
                for _, id := range tc.Stages[0].Output.Log.NoExpectIDs {
                    if contains(matchedIDs, id) {
                        recordResult(&stats, suite.RuleID, tc.TestID, "false_positive", baseline)
                    }
                }
            })
        }
        return nil
    })
    stats.Report(t)
    if stats.NewFailures > 0 {
        t.Fatalf("%d new regressions detected (not in baseline)", stats.NewFailures)
    }
}
```

**Detecting matched rules:** Two options:
- (a) Check HTTP response status (403 = blocked, 200 = passed). Simple but loses
  rule ID granularity — only tells you "something blocked" not "which rule."
- (b) Query `GET /api/events?hours=1&limit=1&client=<test-ip>` after each request.
  Slower (needs ingestion delay) but gives full matched rule IDs.
- (c) Use a unique marker per test (e.g., custom header `X-CRS-Test-ID: 942440-1`)
  and query events by that marker. Most reliable.

**Recommended:** Option (a) for speed + option (b) for a spot-check sample of
rules where rule ID verification matters. Most CRS tests just need "was it
blocked or not" — the YAML `expect_ids` implies the request should be blocked.

**CI integration:**

```yaml
# .github/workflows/build.yml — new job
test-crs:
  needs: [test-e2e]        # reuses the built images
  runs-on: ubuntu-latest
  timeout-minutes: 30
  steps:
    - uses: actions/checkout@v6
    - uses: actions/setup-go@v6
      with:
        go-version: '1.26'
        cache-dependency-path: test/crs/go.sum
    - name: Start CRS test stack
      run: |
        docker compose -f test/crs/docker-compose.crs.yml up -d
        for i in $(seq 1 60); do
          curl -sf http://localhost:19082/api/health > /dev/null 2>&1 && break
          sleep 2
        done
    - name: Run CRS regression tests
      run: go test -v -count=1 -timeout 600s ./...
      working-directory: test/crs
    - name: Tear down
      if: always()
      run: docker compose -f test/crs/docker-compose.crs.yml down -v
```

**Makefile:**
```makefile
test-crs-e2e:          ## Run standalone CRS E2E regression tests (requires Docker)
    docker compose -f test/crs/docker-compose.crs.yml up -d --wait
    cd test/crs && go test -v -count=1 -timeout 600s ./...
    docker compose -f test/crs/docker-compose.crs.yml down -v
```

**Effort:** 2-3 days for initial implementation (YAML parser, HTTP runner, baseline
generation, CI wiring). Ongoing: update baseline when fidelity fixes land.

**Scope:** Start with the REQUEST-9xx categories (inbound detection rules) which
are the most common source of false positives. RESPONSE-9xx (outbound) can be
added later. Skip 911 (method enforcement) and 949 (blocking evaluation) which
are control-flow rules, not detection rules.

#### P2. `waf/default-rules.json` committed but stale-prone

The generated file is committed to git, but the CI workflow regenerates it during
Docker build (not in the PR). After a CRS version bump PR merges:
1. The committed `default-rules.json` still has the old version
2. The Docker build generates a fresh one from the new CRS
3. The committed copy is never updated

This means local `make test-go` runs use the stale committed copy, while the
Docker image uses the freshly generated one. If the converter changes behavior,
the committed copy may not match what's actually deployed.

**Fix:** Either:
- (a) Don't commit `default-rules.json` — generate it as a build step, add to
  `.gitignore`. Tests would need a build step or use a fixture.
- (b) Add a CI step that regenerates it and commits the result. The CRS update
  workflow could do this in the bump PR.
- (c) Add a Makefile target `make generate-rules` that runs the converter locally
  using `tools/coreruleset/rules/` and updates `waf/default-rules.json`.

**Recommended:** Option (c) — adds `make generate-rules` for local dev, and option
(b) for CI to keep the committed copy fresh.

#### P3. No Makefile target for running the converter locally

There's no `make generate-rules` or `make crs-convert` target. To regenerate
`default-rules.json` locally, you'd need to manually:
1. `cd tools/crs-converter && go build -o crs-converter .`
2. `./crs-converter -crs-dir ../coreruleset/rules -custom-rules ../../waf/custom-rules.json ...`

**Fix:** Add Makefile targets:
```makefile
generate-rules:        ## Regenerate default-rules.json from CRS
    cd tools/crs-converter && go build -o /tmp/crs-converter .
    /tmp/crs-converter \
        -crs-dir tools/coreruleset/rules \
        -crs-version "$$(cd tools/coreruleset && git describe --tags)" \
        -custom-rules waf/custom-rules.json \
        -output waf/default-rules.json \
        -metadata-output waf/crs-metadata.json

test-crs:              ## Run CRS converter tests
    cd tools/crs-converter && go test -count=1 -timeout 60s ./...
```

#### P4. Converter tests not run in CI

The `test-go` job in `build.yml:70` runs `go test ./...` in `wafctl/` only. The
converter tests at `tools/crs-converter/` (3 test files, parser + converter +
metadata) are never run in CI.

**Fix:** Add to the `test-go` job:
```yaml
- name: Run converter tests
  run: go test -count=1 -timeout 60s ./...
  working-directory: tools/crs-converter
```

---

## Code Quality Fixes

### 1. Non-deterministic `consolidateFields` fallback (Bug)

**File:** `tools/crs-converter/mapper.go`
**Problem:** When multiple fields don't match any consolidation pattern, the fallback
returns `fields[0]` — but `fields` is built by iterating a `map[string]bool`. Go map
iteration order is non-deterministic, so the same CRS input can produce different
`default-rules.json` output across builds. This breaks build reproducibility.
**Fix:** Sort the fields slice before falling back to `fields[0]`.
**Risk:** Low — only affects unusual variable combinations not matching standard CRS
patterns, but correctness matters for reproducible builds.
**Status:** [ ] TODO

### 2. Deprecated `strings.Title` usage (Warning)

**File:** `tools/crs-converter/metadata.go:172`
**Problem:** `strings.Title()` deprecated since Go 1.18. Produces compiler warnings.
Safe for ASCII CRS category names today but technically incorrect for Unicode.
**Fix:** Replace with a simple `titleCase()` helper (capitalize first letter of each
word, lowercase the rest). Avoids adding `golang.org/x/text` dependency to maintain
the zero-deps constraint.
**Risk:** None — cosmetic fix.
**Status:** [ ] TODO

### 3. Dead `categoryMap` field in `CRSMetadata` (Dead code)

**File:** `wafctl/crs_metadata.go`
**Problem:** Unexported `categoryMap` field duplicates exported `CategoryMap`. The
`buildIndexes()` method copies the reference but `NormalizeCategory()` reads from the
exported field directly. The unexported field is never read.
**Fix:** Remove the `categoryMap` field and the copy in `buildIndexes()`.
**Risk:** None — dead code removal.
**Status:** [ ] TODO

### 4. Fragile frontend prefix extraction from `rule_range` (Latent bug)

**File:** `waf-dashboard/src/lib/api/default-rules.ts:129`
**Problem:** `c.rule_range?.replace(/000-.*$/, "") ?? ""` assumes all CRS ranges
follow the `NNN000-NNN999` pattern. Custom rule ranges like `"9100030-9100036"`
(bot-detection) produce `"91"` instead of `"9100"`. The compile-time fallback has
the correct prefix, masking the bug — but if the API refresh succeeds, the
dynamically-computed prefix will be wrong for bot-detection.
**Fix:** Use a `prefix` field from the API response (already available in
`CRSMetadataCategory`) instead of deriving it from `rule_range`. The Go
`CRSCategory` struct already has all fields needed — just needs to include
`prefix` in the JSON response so the frontend can use it directly.
**Risk:** Low-medium — currently masked by compile-time fallback, but would surface
if the fallback is ever removed or if new non-standard categories are added.
**Status:** [ ] TODO

### 5. Missing RESPONSE-956 in converter `categoryNameMap` (Data gap)

**File:** `tools/crs-converter/metadata.go`
**Problem:** `categoryNameMap` covers RESPONSE-950 through RESPONSE-955 but not
RESPONSE-956 (Ruby Data Leakages). The `autoCategory()` fallback handles it and
happens to produce the correct ID, but without a curated description or tag.
**Fix:** Add the RESPONSE-956 entry to `categoryNameMap`.
**Risk:** None — data completeness.
**Status:** [ ] TODO

### 6. No-op `strings.ReplaceAll` in `autoCategory` (Dead code)

**File:** `tools/crs-converter/metadata.go:171,184`
**Problem:** `strings.ReplaceAll(short, "-", "-")` replaces dashes with dashes —
literal no-op. Both `id` and `tag` are computed identically.
**Fix:** Remove the no-op `ReplaceAll`. If `id` and `tag` should differ, fix the
replacement. If intentionally identical, simplify to a single computation.
**Risk:** None — cosmetic fix.
**Status:** [ ] TODO

### 7. Singleton CRS fetch never retries on failure (Frontend)

**File:** `waf-dashboard/src/hooks/useCRSCategories.ts`
**Problem:** `_refreshPromise` is set once at module level. If the first fetch fails,
the `catch` block silently swallows the error and `_refreshPromise` is never reset.
All subsequent component mounts reuse the failed promise and fall back to stale
compile-time data permanently (until full page reload).
**Fix:** Reset `_refreshPromise = undefined` in the `catch` block so the next
component mount retries the fetch.
**Risk:** None — improves resilience on flaky networks.
**Status:** [ ] TODO

### 8. `TestValidateExclusion_DetectAction` in wrong test file (Test organization)

**File:** `wafctl/crs_rules_test.go:303`
**Problem:** This test validates exclusion detect actions, not CRS rules. It was
likely added to `crs_rules_test.go` during a session that had the file open.
**Fix:** Move to `exclusions_validate_test.go` or `exclusions_test.go`.
**Risk:** None — test organization only, no behavior change.
**Status:** [ ] TODO

---

## Test Gaps (Not blocking, but worth addressing)

### T1. `handleCRSRules` endpoint test is shallow

**File:** `wafctl/crs_rules_test.go:14`
**Problem:** Only asserts non-zero totals. Doesn't verify specific rule content,
category assignments, or response structure beyond top-level fields.
**Improvement:** Add assertions for at least one known rule (ID, description,
category) and verify categories list structure.

### T2. `buildIndexes` edge cases untested

**File:** `wafctl/crs_metadata.go`
**Problem:** No tests for empty `ValidPrefixes`, empty `CategoryMap`, or malformed
JSON input to `LoadCRSMetadata`.
**Improvement:** Add table-driven edge case tests.

### T3. No frontend component test for CRS pages

**Problem:** `/rules/crs` page and `CRSRulePicker` component have zero component-level
tests. Only the API layer (`fetchCRSRules`) is tested.
**Improvement:** Add basic rendering tests with mock API data.

### T4. Store-vs-fallback priority for duplicate rule IDs untested

**File:** `wafctl/crs_rules.go`
**Problem:** `GetCatalog` uses a `seen` map to deduplicate, but no test verifies
that store rules take priority over `customRulesFallback` when both have the same ID.
**Improvement:** Add a test that creates a store rule with the same ID as a fallback
rule and verifies the store version wins.

---

## Overall Execution Plan

### Phase 1: Stop the bleeding (immediate)

| Item | Type | Effort |
|------|------|--------|
| F5. Converter dedup (custom wins over CRS) | Converter bug | 1 hour |
| P4. Add converter tests to CI | Pipeline gap | 30 min |
| P3. Add `make generate-rules` / `make test-crs` | Pipeline gap | 30 min |

### Phase 2: Fix production false positives (high priority)

| Item | Type | Effort |
|------|------|--------|
| F2. Replace `consolidateFields` with condition groups | Converter rewrite | 1-2 days |
| F1. Skip unconvertible chain rules (920450 etc.) | Converter fix | 0.5-1 day |
| Regenerate `default-rules.json`, verify in e2e | Validation | 2 hours |

### Phase 3: Improve fidelity to 95%+ (medium priority)

| Item | Type | Effort |
|------|------|--------|
| F3. `SecRuleUpdateTargetById` processing | Converter feature | 1 day |
| F4. `ctl:ruleRemoveByTag` translation | Converter feature | 1.5-2 days |
| P1. Standalone CRS E2E test suite (`test/crs/`) | New test suite | 2-3 days |
| P2. Keep `default-rules.json` fresh in CI | Pipeline fix | 2 hours |

### Phase 4: Code quality cleanup (low priority)

| Item | Type | Effort |
|------|------|--------|
| #1. Non-deterministic consolidateFields fallback | Code quality | 15 min |
| #2. Deprecated strings.Title | Code quality | 15 min |
| #3. Dead categoryMap field | Code quality | 15 min |
| #4. Frontend prefix extraction | Latent bug | 1 hour |
| #5. Missing RESPONSE-956 | Data gap | 15 min |
| #6. No-op ReplaceAll | Code quality | 10 min |
| #7. Singleton fetch retry | Frontend fix | 15 min |
| #8. Misplaced test | Organization | 15 min |

**Total estimated effort:** ~10-14 days across all phases.
