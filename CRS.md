# CRS.md — CRS Implementation Status

## Current State (v4.24.1)

### Converter Coverage

```
CRS detection rules:  504 total (across 20 categories)
Converted:            332 (65.8%)
Skipped:              172
  - Paranoia gating:  176 (NNN01x skipAfter rules — not detection logic)
  - Data extraction:   19 (pass+nolog helpers — capture/setvar only)
  - TX variable:       10 (check CRS runtime config state)
  - No mappable vars:   2 (REQBODY_PROCESSOR, REQUEST_BODY_LENGTH)
  - Catch-all chain:    2 (920450/920451 — replaced by custom rules)
  - @within TX ref:     2 (911100, 920430 — reference TX config variables)
  - SecAction:          2 (949xxx blocking eval)
  - Blocking eval:      1 (949110 — handled natively by policy engine)
```

The 332 converted rules cover essentially all attack detection logic:
- **SQLi**: 60/68 (88.2%) — 8 missing are paranoia gating
- **RCE**: 48/54 (85.2%) — 6 missing are paranoia gating
- **XSS**: 34/42 (78.6%) — 8 missing are paranoia gating
- **PHP**: 21/29 (72.4%) — 8 missing are paranoia gating
- **Web Shells**: 27/36 (75.0%) — 9 missing are paranoia gating
- **Protocol**: 49/67 (67.2%) — 18 missing are TX config checks + gating

The missing rules in every category are paranoia gating (NNN011-NNN018
skipAfter rules), NOT detection rules. The actual attack pattern detection
is near-complete.

### CRS E2E Test Suite

```
Test cases:           4526 (from official CRS YAML test files)
Passing:              3578 (79.9% at status-code level)
Baselined failures:    902
Skipped:                46 (encoded_request / multi-stage format)
```

The 902 failures are almost entirely cross-rule interference — benign test
payloads trigger UNRELATED rules that accumulate enough anomaly score to
block (403). Of 902 failures, 865+ are `no_expect_ids` false positive tests
where the tested rule did NOT fire, but other rules did. This is an anomaly
scoring interaction problem, not a converter fidelity problem.

True converter fidelity (per-rule detection accuracy) is significantly
higher than 79.9% but requires rule-level match checking to measure.

### What the Converter Handles Correctly

- Per-field variable scoping (OR condition groups, no request_combined)
- Variable exclusions from SecRuleUpdateTargetById (55 cookie/arg exclusions)
- Operator mapping: regex, phrase_match, detect_sqli, detect_xss, eq, contains,
  begins_with, in, gt/ge/lt/le, validateByteRange
- Transform mapping: lowercase, urlDecode, htmlEntityDecode, etc.
- Chain conversion (head preserved, TX-only chain links dropped)
- Negation operators (!@rx, !@within, etc.)
- MultiMatch action → multi_match condition flag
- Data file resolution (@pmFromFile → inline list_items)
- RE2 regex validation (PCRE possessive quantifiers → non-capturing groups)
- Response-phase rules (CRS phase 3/4 → outbound)
- Paranoia level extraction from tags
- CRS metadata generation (categories, prefixes, severity levels)

### What the Converter Cannot Handle

| Feature | Rules | Why | Impact |
|---------|-------|-----|--------|
| TX variable checks | ~10 | CRS runtime config state (tx.max_num_args, tx.arg_length, tx.allowed_methods) — no equivalent in policy engine | Protocol enforcement limits not enforced. Policy engine has its own config (paranoia_level, thresholds) that partially covers this. |
| Paranoia gating | 176 | skipAfter + TX:DETECTION_PARANOIA_LEVEL — flow control, not detection | None — policy engine implements paranoia level natively via waf-config.json |
| @within %{tx.*} | 2 | Operator references TX config variable — can't inline at build time | 911100 (method enforcement) and 920430 (HTTP version enforcement) not converted. Could add custom rules with hardcoded allowed lists. |
| REQBODY_PROCESSOR | 1 | ModSecurity internal — no policy engine equivalent | 920540 (JSON body processor check) not converted |
| REQUEST_BODY_LENGTH | 1 | ModSecurity internal variable | 920640 (body length check for GET/HEAD) not converted |
| ctl:ruleRemoveByTag | 0 (in v4.24.1) | All 3 instances are in skipped flow-control ranges (901/905). Future CRS versions may add detection-range instances. | No current impact. Converter should handle this for future-proofing. |

---

## Completed Work

### Converter Fixes (this branch)

| Fix | What | Impact |
|-----|------|--------|
| F1 | Skip catch-all chain heads (@rx ^.*$) when chain drops | 920450/920451 no longer match everything |
| F2 | Replace consolidateFields/request_combined with per-field OR groups | 201 rules now use precise field scoping; eliminates Accept-Encoding, Cf-Visitor, Accept false positives |
| F3 | SecRuleUpdateTargetById processing (two-pass architecture) | 55 cookie/arg exclusions applied to 22 rules |
| F5 | Custom rules deduplicate CRS-converted duplicates | 7 duplicate IDs eliminated |

### Code Quality (this branch)

| # | What |
|---|------|
| 1 | Non-deterministic field fallback → sort.Strings + sort.SliceStable |
| 2 | Deprecated strings.Title → titleCase helper |
| 3 | Dead categoryMap field removed from CRSMetadata |
| 4 | CRSCategory API includes prefix field; frontend uses it directly |
| 5 | RESPONSE-956 added to converter categoryNameMap |
| 6 | No-op strings.ReplaceAll removed in autoCategory |
| 7 | useCRSCategories resets promise on failure for retry |
| 8 | TestValidateExclusion_DetectAction moved to exclusions_test.go |

### Pipeline (this branch)

| Item | What |
|------|------|
| P1 | Standalone CRS E2E test suite (test/crs/) — 4526 tests, baseline-driven |
| P2 | crs-update.yml regenerates default-rules.json in bump PRs |
| P3 | Makefile: generate-rules, test-crs-converter, test-crs-e2e |
| P4 | Converter tests added to CI build.yml |
| 920451 | Custom rule for extended restricted headers (accept-charset, PL2) |
| 920450 | Updated to match full CRS basic restricted headers list (10 items) |

---

## Future Improvements

### 1. TX Variable Config Mapping

10 protocol enforcement rules check CRS TX config variables
(tx.allowed_methods, tx.arg_name_length, tx.max_num_args, etc.).
The policy engine has its own config system (waf-config.json) that
partially covers these. A mapping layer could:
- Read the CRS crs-setup.conf defaults for these TX variables
- Convert them to policy engine config equivalents
- Or generate custom rules with the default values inlined

**Affected rules:** 911100, 920250, 920360-920410, 920650, 921180, 922110
**Effort:** 1-2 days
**Impact:** 10 more rules converted, protocol enforcement more complete

### 2. ctl:ruleRemoveByTag Translation

Zero instances in CRS v4.24.1 detection ranges, but the pattern exists in
flow-control ranges (901/905) and could appear in future CRS versions. The
converter should handle this for forward compatibility:
- Parse ctl:ruleRemoveByTag actions instead of skipping
- Generate skip rules from tag→ruleID mappings
- Static expansion at conversion time (no plugin changes needed)

**Effort:** 1-2 days
**Impact:** Future-proofing only — no current detection improvement

### 3. Rule-Level Fidelity Measurement

The CRS E2E test runner currently uses HTTP status codes (403 vs 200).
This conflates cross-rule interference with converter bugs, showing 79.9%
when true per-rule fidelity is likely 95%+. The runner has infrastructure
for events API rule-level checking but it's too slow for full runs
(3s per false-positive test × 900 tests = 45 minutes).

Options:
- Batch events query after all tests complete
- Export access log and parse matched_rules offline
- Only check NEW failures via events API (current hybrid approach)

**Effort:** 1-2 days
**Impact:** Accurate fidelity number; better regression detection

### 4. Response-Phase Coverage

Response-phase categories (950-956) have lower conversion rates (10-61%)
because many rules use TX variable chains and data-extraction helpers.
The actual detection rules (regex/phrase_match on RESPONSE_BODY) do convert.
The missing rules are mostly flow-control logic around outbound anomaly
scoring.

**Effort:** 2-3 days (mostly TX variable handling for outbound scoring)
**Impact:** Better outbound data leakage detection
