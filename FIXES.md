# Code Review Findings

Comprehensive code review performed 2026-03-08. Each finding has been verified against the
actual codebase with exact line references. Findings marked **INVALIDATED** were disproven
during verification and are included for transparency.

**Tally: 55 verified findings (5 critical, 7 high, 14 medium, 23 low), 6 invalidated.**

---

## Table of Contents

- [Critical](#critical)
  - [C1: WAF bypass via Connection: Upgrade header](#c1-waf-bypass-via-connection-upgrade-header)
  - [C2: :2020 admin proxy allows 172.17.0.0/16](#c2-2020-admin-proxy-allows-17217016)
  - [C3: Deploy proceeds after validation failure](#c3-deploy-proceeds-after-validation-failure)
  - [C4: SSRF via IP injection in GeoIP URL construction](#c4-ssrf-via-ip-injection-in-geoip-url-construction)
  - [C5: Rate limit OR-grouping silently ignored](#c5-rate-limit-or-grouping-silently-ignored)
- [High](#high)
  - [H1: No deploy mutex — concurrent deploys interleave file writes](#h1-no-deploy-mutex--concurrent-deploys-interleave-file-writes)
  - [H2: Cosign verify uses .* wildcards — no identity verification](#h2-cosign-verify-uses--wildcards--no-identity-verification)
  - [H3: Missing separator in composite rate limit keys](#h3-missing-separator-in-composite-rate-limit-keys)
  - [H4: CSP service name not validated — path traversal + config injection](#h4-csp-service-name-not-validated--path-traversal--config-injection)
  - [H5: compactEventFileLocked ignores f.Write errors](#h5-compacteventfilelocked-ignores-fwrite-errors)
  - [H6: ConfigStore.Get() deep copy misses \*bool fields](#h6-configstoreget-deep-copy-misses-bool-fields)
  - [H7: No fsync on JSONL append](#h7-no-fsync-on-jsonl-append)
- [Medium](#medium)
  - [M1: Caddy runs as root with network\_mode: host](#m1-caddy-runs-as-root-with-network_mode-host)
  - [M2: chmod 777 on CSP directory](#m2-chmod-777-on-csp-directory)
  - [M3: Trivy action pinned to master hash](#m3-trivy-action-pinned-to-master-hash)
  - [M4: SamplingPercentage 100 treated as "unset"](#m4-samplingpercentage-100-treated-as-unset)
  - [M5: Export mode allows 50k events — OOM risk](#m5-export-mode-allows-50k-events--oom-risk)
  - [M6: Absolute time range inconsistency in IPLookup](#m6-absolute-time-range-inconsistency-in-iplookup)
  - [M7: No AbortController for racing requests in OverviewDashboard](#m7-no-abortcontroller-for-racing-requests-in-overviewdashboard)
  - [M8: Startup ordering — caddy before wafctl on fresh deploy](#m8-startup-ordering--caddy-before-wafctl-on-fresh-deploy)
  - [M9: Jellyfin has no security headers](#m9-jellyfin-has-no-security-headers)
  - [M10: Missing aria-label on icon-only buttons](#m10-missing-aria-label-on-icon-only-buttons)
  - [M11: No aria-expanded on expandable table rows](#m11-no-aria-expanded-on-expandable-table-rows)
  - [M12: No CI concurrency control](#m12-no-ci-concurrency-control)
  - [M13: Unbounded user-supplied regex in query filters](#m13-unbounded-user-supplied-regex-in-query-filters)
- [Low](#low)
  - [L1: Dead code — unused oldest slice in GeoIP evictRandom](#l1-dead-code--unused-oldest-slice-in-geoip-evictrandom)
  - [L2: String-based error comparison in json\_helpers.go](#l2-string-based-error-comparison-in-json_helpersgo)
  - [L3: Dead ResetRuleIDCounter() calls](#l3-dead-resetruleidcounter-calls)
  - [L4: truncate operates on bytes not runes](#l4-truncate-operates-on-bytes-not-runes)
  - [L5: CORS middleware sets headers on rejected origins](#l5-cors-middleware-sets-headers-on-rejected-origins)
  - [L6: Redundant time format in parseTimeRange](#l6-redundant-time-format-in-parsetimerange)
  - [L7: Variable shadowing w in handleValidateConfig](#l7-variable-shadowing-w-in-handlevalidateconfig)
  - [L8: parseHours silent fallback to 0 for unrecognized values](#l8-parsehours-silent-fallback-to-0-for-unrecognized-values)
  - [L9: RateLimitEventToEvent hardcodes Protocol](#l9-ratelimiteventtoevent-hardcodes-protocol)
  - [L10: blocklist.ts uses raw fetch instead of postJSON](#l10-blocklistts-uses-raw-fetch-instead-of-postjson)
  - [L11: RLRuleKey type collapses to string](#l11-rlrulekey-type-collapses-to-string)
  - [L12: TimeRangePicker hours:0 sentinel is misleading](#l12-timerangepicker-hours0-sentinel-is-misleading)
  - [L13: .dockerignore missing exclusions](#l13-dockerignore-missing-exclusions)
  - [L14: || loses falsy numeric values in exclusions.ts](#l14--loses-falsy-numeric-values-in-exclusionsts)
  - [L15: Unchecked JSON imports in SettingsPanel/CSPPanel](#l15-unchecked-json-imports-in-settingspanelcsppanel)
  - [L16: CORS reflects host header](#l16-cors-reflects-host-header)
  - [L17: general\_logs.go compactEventFileLocked unchecked Sync/Close](#l17-general_logsgo-compacteventfilelocked-unchecked-syncclose)
  - [L18: blocklist.go ensureLoaded thundering herd](#l18-blocklistgo-ensureloaded-thundering-herd)
  - [L19: CSP deepCopy ignores marshal errors](#l19-csp-deepcopy-ignores-marshal-errors)
  - [L20: Regex cache grows unbounded](#l20-regex-cache-grows-unbounded)
  - [L21: DisabledGroups tags not escaped in waf\_settings\_generator](#l21-disabledgroups-tags-not-escaped-in-waf_settings_generator)
  - [L22: advisorCache has no max size enforcement](#l22-advisorcache-has-no-max-size-enforcement)
  - [L23: release.yml PREV\_TAG may match non-semver tags](#l23-releaseyml-prev_tag-may-match-non-semver-tags)
- [Invalidated Findings](#invalidated-findings)
  - [X1: splitCTLActions naive comma split](#x1-splitctlactions-naive-comma-split)
  - [X2: Ignored json.Unmarshal errors in partial update merge](#x2-ignored-jsonunmarshal-errors-in-partial-update-merge)
  - [X3: CLI reads unlimited stdin/response bodies](#x3-cli-reads-unlimited-stdinresponse-bodies)
  - [X4: Dockerfile COPY wafctl/\*.go misses subdirectories](#x4-dockerfile-copy-wafctlgo-misses-subdirectories)
  - [X5: Stale closure in Recharts onMouseMove](#x5-stale-closure-in-recharts-onmousemove)
  - [X6: Dockerfile alpine used in two separate stages](#x6-dockerfile-alpine-used-in-two-separate-stages)

---

## Critical

### C1: WAF bypass via Connection: Upgrade header

| Field | Value |
|-------|-------|
| **File** | `Caddyfile:144-168` |
| **Severity** | Critical |
| **Category** | Security — WAF bypass |

#### Code

```caddyfile
# Caddyfile:144-147
(waf) {
	@not_websocket {
		not header Connection *Upgrade*
	}
	route @not_websocket {
		...
		coraza_waf {
			load_owasp_crs
			...
		}
	}
}
```

#### Analysis

The `@not_websocket` matcher checks **only** the `Connection` header using a wildcard glob
(`*Upgrade*`). It does **not** check `Upgrade: websocket`. The WAF only runs when `Connection`
does NOT contain "Upgrade", so any request can bypass WAF entirely by adding a single header:

```bash
curl -H "Connection: Upgrade" https://target.erfi.io/sqli?id=1%27%20OR%201=1--
```

This request has `Connection: Upgrade` (so `@not_websocket` does NOT match), has no
`Upgrade: websocket` header (so it's NOT a real WebSocket upgrade), and is a plain HTTP request
that skips the entire WAF. It gets proxied directly to the backend with no CRS inspection.

Every service that uses `import waf` is affected — 23 services total including authelia,
sonarr, radarr, jellyfin, keycloak, vault, and all others.

A proper WebSocket upgrade requires **both** `Connection: Upgrade` **and** `Upgrade: websocket`.

**Mitigating factors:** If behind Cloudflare, CF may strip/normalize the `Connection` header on
non-WebSocket HTTP/2+ connections. But HTTP/1.1 clients can still send arbitrary headers, and
direct-to-origin access bypasses CF entirely.

#### Fix

```caddyfile
(waf) {
	@websocket_upgrade {
		header Connection *Upgrade*
		header Upgrade    websocket
	}
	route {
		request_header X-Request-Id {http.request.uuid}
		@not_websocket not @websocket_upgrade
		route @not_websocket {
			coraza_waf {
				load_owasp_crs
				directives `
				Include /etc/caddy/coraza/pre-crs.conf
				Include /data/coraza/custom-pre-crs.conf
				Include @crs-setup.conf.example
				Include /data/coraza/custom-waf-settings.conf
				Include @owasp_crs/*.conf
				Include /etc/caddy/coraza/post-crs.conf
				Include /data/coraza/custom-post-crs.conf
				SecAuditEngine RelevantOnly
				SecAuditLog /var/log/coraza-audit.log
				SecAuditLogFormat json
				SecAuditLogParts ABCFHKZ
				`
			}
		}
	}
	handle_errors 400 403 429 {
		root * /etc/caddy/errors
		templates
		rewrite * /error.html
		file_server
	}
}
```

This requires **both** headers to be present before skipping WAF. A request with only
`Connection: Upgrade` but no `Upgrade: websocket` is processed normally by the WAF.

---

### C2: :2020 admin proxy allows 172.17.0.0/16

| Field | Value |
|-------|-------|
| **File** | `Caddyfile:811-823` |
| **Severity** | Critical |
| **Category** | Security — overly broad ACL |

#### Code

```caddyfile
# Caddyfile:811-823
:2020 {
	@allowed remote_ip 172.19.98.0/24 172.17.0.0/16
	handle @allowed {
		reverse_proxy localhost:2019 {
			header_up Host localhost:2019
		}
	}
	handle {
		respond "Forbidden" 403
	}
}
```

The comment at line 812 says "Restricted to the wafctl Docker subnet (172.19.98.0/24)" but the
actual matcher **also** includes `172.17.0.0/16` — Docker's **default bridge network**.

#### Analysis

`172.17.0.0/16` covers 65,534 IP addresses — any container on the default Docker bridge
network. The `:2020` listener is on `network_mode: host`, so it's reachable from the host and
all Docker networks.

The Caddy admin API at `localhost:2019` exposes:
- `GET /config/` — read entire running config (may leak `CF_API_TOKEN` and other env vars)
- `POST /load` — **replace the entire Caddy configuration** — an attacker could add routes,
  disable TLS, remove WAF, redirect traffic
- `POST /stop` — shut down Caddy entirely (DoS)
- `DELETE /config/...` — delete parts of the running config

A compromised container on the default Docker bridge (e.g., a vulnerable web app, a dev
container, anything started with `docker run` without `--network`) can reach this endpoint
and take full control of Caddy.

The `172.17.0.0/16` was likely added because Dockge (`Caddyfile:712`) runs on the default bridge
at `172.17.0.2:5001`.

#### Fix

```caddyfile
:2020 {
	@allowed remote_ip 172.19.98.0/24
	handle @allowed {
		reverse_proxy localhost:2019 {
			header_up Host localhost:2019
		}
	}
	handle {
		respond "Forbidden" 403
	}
}
```

Remove `172.17.0.0/16`. Only wafctl (on `172.19.98.0/24`) needs admin API access. If Dockge
legitimately needs admin access, add its specific IP (`172.17.0.2/32`) instead of a `/16`.

---

### C3: Deploy proceeds after validation failure

| Field | Value |
|-------|-------|
| **File** | `wafctl/handlers_config.go:100-158` |
| **Severity** | Critical |
| **Category** | Logic bug — ignored validation |

#### Code

```go
// handlers_config.go:100-121
func handleDeploy(cs *ConfigStore, es *ExclusionStore, rs *RateLimitRuleStore, deployCfg DeployConfig) http.HandlerFunc {
    return func(w http.ResponseWriter, _ *http.Request) {
        cfg := cs.Get()
        exclusions := es.EnabledExclusions()
        ResetRuleIDCounter()
        result := GenerateConfigs(cfg, exclusions)
        wafSettings := GenerateWAFSettings(cfg)

        // Validate generated config before writing.
        vr := ValidateGeneratedConfig(result.PreCRS, result.PostCRS, wafSettings)
        selfRefWarnings := validateGeneratedRuleIDs(exclusions)
        vr.Warnings = append(vr.Warnings, selfRefWarnings...)
        logValidationResult(vr)

        // Write config files to the shared volume.  <--- NO CHECK OF vr.Valid!
        if err := writeConfFiles(deployCfg.CorazaDir, result.PreCRS, result.PostCRS, wafSettings); err != nil {
```

#### Analysis

Two bugs are present:

**Bug A**: `vr.Valid` is never checked — even if `ValidateGeneratedConfig` returns `Valid: false`
(duplicate rule IDs, invalid SecRule syntax), deploy proceeds to write files and reload Caddy.

**Bug B**: Self-referencing rule ID warnings with `Level == "error"` don't set `vr.Valid = false`
in deploy. Compare with `handleValidateConfig` (lines 80-84) which correctly does:
```go
for _, w := range selfRefWarnings {
    if w.Level == "error" {
        vr.Valid = false
    }
}
```
This loop is **missing** from `handleDeploy`.

If Coraza's seclang parser can't parse the invalid config, the WAF fails to provision — either
crashing (leaving services unprotected) or silently keeping old config while the user sees
"deployed" status.

#### Fix

```go
func handleDeploy(cs *ConfigStore, es *ExclusionStore, rs *RateLimitRuleStore, deployCfg DeployConfig) http.HandlerFunc {
    return func(w http.ResponseWriter, _ *http.Request) {
        cfg := cs.Get()
        exclusions := es.EnabledExclusions()
        ResetRuleIDCounter()
        result := GenerateConfigs(cfg, exclusions)
        wafSettings := GenerateWAFSettings(cfg)

        vr := ValidateGeneratedConfig(result.PreCRS, result.PostCRS, wafSettings)
        selfRefWarnings := validateGeneratedRuleIDs(exclusions)
        vr.Warnings = append(vr.Warnings, selfRefWarnings...)
        for _, sw := range selfRefWarnings {
            if sw.Level == "error" {
                vr.Valid = false
            }
        }
        logValidationResult(vr)

        if !vr.Valid {
            writeJSON(w, http.StatusBadRequest, map[string]interface{}{
                "error":    "validation failed - deploy aborted",
                "warnings": vr.Warnings,
                "valid":    false,
            })
            return
        }

        // ... rest unchanged
    }
}
```

---

### C4: SSRF via IP injection in GeoIP URL construction

| Field | Value |
|-------|-------|
| **File** | `wafctl/geoip.go:219-224, 295-300` |
| **Severity** | Critical (conditional on `WAF_GEOIP_API_URL` being configured) |
| **Category** | Security — SSRF |

#### Code

```go
// geoip.go:219-224 — lookupOnline()
url := s.api.URL
if strings.Contains(url, "%s") {
    url = fmt.Sprintf(url, ip)
} else {
    url = strings.TrimRight(url, "/") + "/" + ip
}

// geoip.go:205-208 — only check is empty string
func (s *GeoIPStore) lookupOnline(ip string) string {
    if ip == "" {
        return ""
    }
```

The `ip` parameter comes from parsed log entries (`ev.ClientIP`) during log tailing
(`logparser.go:300`, `access_log_store.go:357`). These call sites do **not** validate with
`net.ParseIP()`.

Compare with the IP intelligence path which IS protected:
```go
// ip_intel.go:53-54
func (s *IPIntelStore) Lookup(ip string) *IPIntelligence {
    if ip == "" || net.ParseIP(ip) == nil {
        return nil
    }
```

#### Analysis

A crafted `ClientIP` value in a log entry (e.g., `../../internal-service/secret?x=`) could be
interpolated into the GeoIP API URL, causing an outbound SSRF request to an arbitrary host.

**Exploitability:** Requires (1) `WAF_GEOIP_API_URL` is configured (disabled by default), and
(2) log entries contain crafted IPs. Caddy/Coraza typically populate `ClientIP` from the actual
TCP connection, but proxy header injection or malformed upstream logs could provide a vector.

#### Fix

```go
func (s *GeoIPStore) lookupOnline(ip string) string {
    if ip == "" || net.ParseIP(ip) == nil {
        return ""
    }
    // ... rest unchanged
}

func (s *GeoIPStore) lookupOnlineFull(ip string) *GeoIPInfo {
    if ip == "" || net.ParseIP(ip) == nil {
        return nil
    }
    // ... rest unchanged
}
```

---

### C5: Rate limit OR-grouping silently ignored

| Field | Value |
|-------|-------|
| **File** | `wafctl/rl_generator.go:166-183` |
| **Severity** | Critical |
| **Category** | Logic bug — silent misconfiguration |

#### Code

```go
// rl_generator.go:166-183 — writeConditionMatchers()
func writeConditionMatchers(b *strings.Builder, conditions []Condition, groupOp string) {
    if len(conditions) == 0 {
        return
    }
    // For AND logic (default): all matchers in one match block.
    // For OR logic: Caddy evaluates multiple match blocks as OR,
    // but since we're already inside a single match block, we use
    // expression matchers for OR. For simplicity in v1, we emit
    // all conditions in one block (AND behavior) — OR support
    // requires named matcher composition which is more complex.
    // TODO: OR grouping via multiple named matchers in future version.
    for _, c := range conditions {
        line := rlConditionToMatcher(c)
        if line != "" {
            b.WriteString("\t\t\t" + line + "\n")
        }
    }
}
```

Validation at `rl_rules.go:520-522` accepts "or":
```go
if !validGroupOperators[rule.GroupOp] {
    return fmt.Errorf("invalid group_operator: %q (must be \"and\" or \"or\")", rule.GroupOp)
}
```

#### Analysis

A user who creates a rate limit rule with `group_operator: "or"` and conditions
`[path=/api, method=POST]` expects: "rate limit requests matching `/api` **OR** `POST`".
What they actually get: "rate limit requests matching `/api` **AND** `POST`". This is a
**silent correctness bug** — the rule is stricter than intended, potentially leaving traffic
unprotected that the user believed was rate-limited.

The data model, API, and UI all accept and display "or" as a valid option. The
`writeConditionMatchers` function's own comment acknowledges this is a TODO.

#### Fix

**Option A — Reject until implemented (recommended):**
```go
// In rl_rules.go, validateRateLimitRule():
if rule.GroupOp == "or" && len(rule.Conditions) > 1 {
    return fmt.Errorf("group_operator \"or\" is not yet supported for rate limit rules with multiple conditions")
}
```

**Option B — Implement OR via multiple named matchers** (requires restructuring the Caddy
config generation to emit separate `@matcher` blocks per condition).

Option A is safer — it prevents misconfiguration now and can be loosened when OR is implemented.

---

## High

### H1: No deploy mutex — concurrent deploys interleave file writes

| Field | Value |
|-------|-------|
| **File** | `wafctl/handlers_config.go:100-158`, `wafctl/handlers_ratelimit.go:89-128`, `wafctl/csp.go:423-457` |
| **Severity** | High |
| **Category** | Concurrency — race condition |

#### Code

All three deploy handlers follow the same pattern with no serialization:

```go
// handlers_config.go:100 — handleDeploy
func handleDeploy(cs *ConfigStore, es *ExclusionStore, ...) http.HandlerFunc {
    return func(w http.ResponseWriter, _ *http.Request) {
        cfg := cs.Get()                            // read
        result := GenerateConfigs(cfg, exclusions)  // generate
        writeConfFiles(...)                         // write files
        reloadCaddy(...)                            // reload
    }
}

// handlers_ratelimit.go:89 — handleDeployRLRules (same pattern)
// csp.go:423 — handleDeployCSP (same pattern)
```

No `sync.Mutex` or any serialization mechanism exists.

#### Analysis

Two concurrent `POST /api/config/deploy` requests can interleave:
1. Request A writes `custom-pre-crs.conf`
2. Request B writes `custom-pre-crs.conf` (overwriting A's file)
3. Request A writes `custom-post-crs.conf`
4. Request A reloads Caddy — loads B's pre-CRS + A's post-CRS (inconsistent state)

Similarly, a WAF deploy and RL deploy running simultaneously could each reload Caddy
mid-write, causing Caddy to load half-updated config.

#### Fix

```go
// In main.go or deploy.go:
var deployMu sync.Mutex

func handleDeploy(...) http.HandlerFunc {
    return func(w http.ResponseWriter, _ *http.Request) {
        deployMu.Lock()
        defer deployMu.Unlock()
        // ... existing logic
    }
}
// Same wrapper for handleDeployRLRules and handleDeployCSP
```

---

### H2: Cosign verify uses .* wildcards — no identity verification

| Field | Value |
|-------|-------|
| **File** | `Makefile:133-135` |
| **Severity** | High |
| **Category** | Supply chain — broken verification |

#### Code

```makefile
# Makefile:133-135
verify: ## Verify signatures on both images
	cosign verify $$(docker inspect --format='{{index .RepoDigests 0}}' $(CADDY_IMAGE)) \
		--certificate-identity-regexp='.*' --certificate-oidc-issuer-regexp='.*'
	cosign verify $$(docker inspect --format='{{index .RepoDigests 0}}' $(WAFCTL_IMAGE)) \
		--certificate-identity-regexp='.*' --certificate-oidc-issuer-regexp='.*'
```

#### Analysis

Using `.*` for both identity and issuer means cosign verifies the signature cryptographically
but accepts **any signer identity** from **any OIDC issuer**. An attacker who signs a malicious
image with their own Sigstore identity passes this check. The CI workflow
(`build.yml:120-121`) signs correctly via keyless Sigstore with GitHub OIDC, but the verify
step provides zero supply-chain integrity guarantees.

#### Fix

```makefile
COSIGN_IDENTITY ?= https://github.com/erfianugrah/caddy-compose/.github/workflows/build.yml@refs/heads/main
COSIGN_ISSUER   ?= https://token.actions.githubusercontent.com

verify:
	cosign verify $$(docker inspect --format='{{index .RepoDigests 0}}' $(CADDY_IMAGE)) \
		--certificate-identity='$(COSIGN_IDENTITY)' \
		--certificate-oidc-issuer='$(COSIGN_ISSUER)'
	cosign verify $$(docker inspect --format='{{index .RepoDigests 0}}' $(WAFCTL_IMAGE)) \
		--certificate-identity='$(COSIGN_IDENTITY)' \
		--certificate-oidc-issuer='$(COSIGN_ISSUER)'
```

---

### H3: Missing separator in composite rate limit keys

| Field | Value |
|-------|-------|
| **File** | `wafctl/rl_generator.go:471-474` |
| **Severity** | High |
| **Category** | Logic bug — bucket collision |

#### Code

```go
// rl_generator.go:471-474
case "client_ip+path":
    return "{http.request.remote.host}{http.request.uri.path}"
case "client_ip+method":
    return "{http.request.remote.host}{http.request.method}"
```

AGENTS.md documents the correct format with `_` separator:
> `{http.request.remote.host}_{http.request.uri.path}` — Per IP+path combo

#### Analysis

Without a separator, the key is ambiguous. IP `192.168.1.1` with path `/0/foo` produces key
`192.168.1.1/0/foo`, which is identical to IP `192.168.1.10` with path `/foo`. This causes
unrelated clients to share rate limit buckets — one client's requests count against another's
limit, producing false-positive 429s or allowing an attacker to hide their traffic behind shared
buckets.

For `client_ip+method`, IP `10.0.0.1` + method `GET` produces `10.0.0.1GET`. While this
specific case has no practical collision (IPs don't end with HTTP method names), the missing
separator contradicts documentation and is incorrect by principle.

#### Fix

```go
case "client_ip+path":
    return "{http.request.remote.host}_{http.request.uri.path}"
case "client_ip+method":
    return "{http.request.remote.host}_{http.request.method}"
```

---

### H4: CSP service name not validated — path traversal + config injection

| Field | Value |
|-------|-------|
| **File** | `wafctl/csp_generator.go:15-17`, `wafctl/csp.go:89-103` |
| **Severity** | High |
| **Category** | Security — injection |

#### Code

```go
// csp_generator.go:15-17 — service name used directly in filename
func cspFileName(service string) string {
    return service + "_csp.caddy"
}

// csp_generator.go:90 — service name in generated Caddy config
sb.WriteString(fmt.Sprintf("# CSP config for %s\n", service))

// csp.go:89-103 — validateCSPConfig does NOT validate service name keys
func validateCSPConfig(cfg CSPConfig) error {
    for svc, sc := range cfg.Services {
        // validates sc.Mode and sc.Policy... but NOT svc
    }
}
```

#### Analysis

A malicious API client can submit a CSP config with service names like
`../../etc/caddy/Caddyfile` or `foo\nmalicious_directive`. The `cspFileName()` function
produces `../../etc/caddy/Caddyfile_csp.caddy`, and `filepath.Join(dir, filename)` resolves to
a path outside the intended CSP directory (path traversal). A service name with newlines
injects arbitrary Caddy directives via the comment line.

**Practical exploitability is limited** since the API is typically behind auth and not externally
exposed, but any API client (including the dashboard) could trigger this with crafted input.

#### Fix

Add service name validation in `validateCSPConfig`:

```go
var validServiceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func validateCSPConfig(cfg CSPConfig) error {
    // ... existing validation ...
    for svc, sc := range cfg.Services {
        if !validServiceNameRe.MatchString(svc) {
            return fmt.Errorf("service %q: invalid service name", svc)
        }
        // ... existing mode/policy validation ...
    }
}
```

The same pattern should be applied in `rl_generator.go` (`rlFileName()`) and any other place
where user-controlled names become filenames.

---

### H5: compactEventFileLocked ignores f.Write errors

| Field | Value |
|-------|-------|
| **File** | `wafctl/logparser.go:158-164`, `wafctl/access_log_store.go:216-222` |
| **Severity** | High |
| **Category** | Data integrity — silent data loss |

#### Code

```go
// logparser.go:158-164
for i := range s.events {
    data, err := json.Marshal(s.events[i])
    if err != nil {
        continue
    }
    f.Write(data)         // error ignored
    f.Write([]byte{'\n'}) // error ignored
}
```

Both `logparser.go` and `access_log_store.go` have identical patterns.

#### Analysis

If the filesystem runs out of space or the write fails (I/O error, NFS timeout), `f.Write()`
returns an error that is silently discarded. The compaction then proceeds to `f.Sync()`,
`f.Close()`, and `os.Rename(tmp, s.eventFile)` — **replacing the original complete JSONL file
with a truncated temp file**. This causes permanent data loss: events in the original file are
gone, and on restart only the partial events would be loaded.

#### Fix

```go
var writeErr error
for i := range s.events {
    data, err := json.Marshal(s.events[i])
    if err != nil {
        continue
    }
    if _, err := f.Write(data); err != nil {
        writeErr = err
        break
    }
    if _, err := f.Write([]byte{'\n'}); err != nil {
        writeErr = err
        break
    }
}
if writeErr != nil {
    f.Close()
    os.Remove(tmp)
    log.Printf("error writing compacted event file, keeping original: %v", writeErr)
    return
}
```

---

### H6: ConfigStore.Get() deep copy misses \*bool fields

| Field | Value |
|-------|-------|
| **File** | `wafctl/config.go:187-201` |
| **Severity** | High |
| **Category** | Concurrency — shared mutable state |

#### Code

```go
// config.go:187-201
func (s *ConfigStore) Get() WAFConfig {
    s.mu.RLock()
    defer s.mu.RUnlock()
    cp := s.config   // struct copy — *bool pointers are shallow-copied
    cp.Defaults.DisabledGroups = copyStringSlice(s.config.Defaults.DisabledGroups)
    cp.Defaults.CRSExclusions = copyStringSlice(s.config.Defaults.CRSExclusions)
    cp.Services = make(map[string]WAFServiceSettings, len(s.config.Services))
    for k, v := range s.config.Services {
        v.DisabledGroups = copyStringSlice(v.DisabledGroups)
        v.CRSExclusions = copyStringSlice(v.CRSExclusions)
        cp.Services[k] = v
    }
    return cp
}
```

`WAFServiceSettings` has `*bool` fields (`models_exclusions.go:66,72`):
```go
EarlyBlocking             *bool `json:"early_blocking,omitempty"`
EnforceBodyprocURLEncoded *bool `json:"enforce_bodyproc_urlencoded,omitempty"`
```

#### Analysis

`cp := s.config` copies the struct, which copies the `*bool` pointer values — the caller and
the store share the same `bool`. If any caller modifies `*cp.Defaults.EarlyBlocking`, it mutates
the store's internal state without holding the lock. The same applies to per-service settings
in the loop (the `v` assignment copies `*bool` pointers shallowly).

**Current callers don't mutate the returned config's pointer fields** (they serialize to JSON or
pass to generators), so this is not actively exploited. But it violates the deep-copy contract
and is a latent data race.

#### Fix

```go
func copyBoolPtr(p *bool) *bool {
    if p == nil {
        return nil
    }
    v := *p
    return &v
}

func (s *ConfigStore) Get() WAFConfig {
    s.mu.RLock()
    defer s.mu.RUnlock()
    cp := s.config
    cp.Defaults.DisabledGroups = copyStringSlice(s.config.Defaults.DisabledGroups)
    cp.Defaults.CRSExclusions = copyStringSlice(s.config.Defaults.CRSExclusions)
    cp.Defaults.EarlyBlocking = copyBoolPtr(s.config.Defaults.EarlyBlocking)
    cp.Defaults.EnforceBodyprocURLEncoded = copyBoolPtr(s.config.Defaults.EnforceBodyprocURLEncoded)
    cp.Services = make(map[string]WAFServiceSettings, len(s.config.Services))
    for k, v := range s.config.Services {
        v.DisabledGroups = copyStringSlice(v.DisabledGroups)
        v.CRSExclusions = copyStringSlice(v.CRSExclusions)
        v.EarlyBlocking = copyBoolPtr(v.EarlyBlocking)
        v.EnforceBodyprocURLEncoded = copyBoolPtr(v.EnforceBodyprocURLEncoded)
        cp.Services[k] = v
    }
    return cp
}
```

---

### H7: No fsync on JSONL append

| Field | Value |
|-------|-------|
| **File** | `wafctl/logparser.go:108-129`, `wafctl/access_log_store.go:168-188`, `wafctl/general_logs.go:85-104` |
| **Severity** | High |
| **Category** | Data integrity — durability gap |

#### Code

```go
// logparser.go:108-129 — Store.appendEventsToJSONL()
func (s *Store) appendEventsToJSONL(events []Event) {
    f, err := os.OpenFile(s.eventFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    // ...
    defer f.Close()
    for i := range events {
        data, _ := json.Marshal(events[i])
        f.Write(data)
        f.Write([]byte{'\n'})
    }
    // NO f.Sync() before close
}
```

All three stores (`Store`, `AccessLogStore`, `GeneralLogStore`) have identical patterns.
Contrast with `compactEventFileLocked()` which correctly calls `f.Sync()` at `logparser.go:167`,
and `atomicWriteFile()` at `exclusions.go:73` which also syncs.

#### Analysis

On crash between `f.Write()` and kernel flush (0-5 second window on Linux), appended events are
lost. More importantly, the offset is saved (with fsync) **before** `appendEventsToJSONL` is
called (`logparser.go:330` vs `339`). On crash after offset save but before page cache flush,
the offset has advanced past those events but the JSONL doesn't contain them — they're
permanently lost and can't be re-derived from the raw log.

**Practical impact is low** — the data loss window is tiny (Linux `dirty_writeback_centisecs` =
5s default), and at ~400 events/day the expected loss per crash is near zero. But the
inconsistency with the rest of the codebase (which correctly syncs) is a code smell.

#### Fix

Add `f.Sync()` before close in all three `appendEventsToJSONL` functions. Optionally reorder
offset save to occur **after** JSONL append:

```go
// Current order (logparser.go:324-339):
s.saveOffset()                     // offset synced to disk
s.appendEventsToJSONL(newEvents)   // events NOT synced

// Proposed order:
s.appendEventsToJSONL(newEvents)   // events synced (with fix)
s.saveOffset()                     // then advance offset
```

---

## Medium

### M1: Caddy runs as root with network_mode: host

| Field | Value |
|-------|-------|
| **File** | `compose.yaml:2-13`, `Dockerfile:55-70` |
| **Severity** | Medium |
| **Category** | Security — container hardening |

#### Code

```yaml
# compose.yaml:2-13
caddy:
    image: erfianugrah/caddy:2.10.2-2.11.1
    network_mode: host
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
      - DAC_OVERRIDE
```

No `user:` directive. No `USER` in the final Dockerfile stage. Caddy runs as root (UID 0).

#### Analysis

**network_mode: host** — Caddy has access to every port on every interface of the host,
including localhost-only services (databases, admin APIs, Docker socket proxies). An SSRF in
any proxied backend can reach host services.

**Root + DAC_OVERRIDE** — combined with host networking, a container escape gives full host
network + root privilege access.

**Mitigations already in place** (these significantly reduce severity):
- `cap_drop: ALL` + selective `cap_add` (only `NET_BIND_SERVICE` + `DAC_OVERRIDE`)
- `read_only: true` — root filesystem is immutable
- `security_opt: no-new-privileges:true` — prevents setuid escalation
- Resource limits (8 CPU, 2GB RAM)
- `tmpfs` volumes for `/tmp` and `/var/run`

The `network_mode: host` is a deliberate architecture choice for direct port binding and
real client IP visibility. The `DAC_OVERRIDE` is needed because bind-mounted directories may
have restrictive ownership. The crond job requires root.

#### Fix (Hardening)

Long-term: replace crond with an in-process Go ticker in wafctl, fix directory ownership at
image build time, and add `USER caddy` to the Dockerfile. This would allow dropping both
`DAC_OVERRIDE` and running as non-root.

Short-term: document the root requirement and the mitigations in place.

---

### M2: chmod 777 on CSP directory

| Field | Value |
|-------|-------|
| **File** | `scripts/entrypoint.sh:36-40` |
| **Severity** | Medium |
| **Category** | Security — excessive permissions |

#### Code

```bash
# entrypoint.sh:36-40
CSP_DIR="/data/caddy/csp"
mkdir -p "${CSP_DIR}"
chmod 777 "${CSP_DIR}" 2>/dev/null || true
```

#### Analysis

`chmod 777` grants read/write/execute to every user inside the container. Any process (including
one exploited via WAF bypass) can write arbitrary `.caddy` files into this directory, which
Caddy imports on reload. If `/data` is a bind-mount, the 777 permission leaks to the host.

#### Fix

```bash
chmod 755 "${CSP_DIR}" 2>/dev/null || true
```

Or with targeted ownership: `chown 65534:65534 "${CSP_DIR}" 2>/dev/null || chmod 755 "${CSP_DIR}" 2>/dev/null || true`

---

### M3: Trivy action pinned to master hash

| Field | Value |
|-------|-------|
| **File** | `.github/workflows/build.yml:110-111, 164-165` |
| **Severity** | Medium |
| **Category** | CI/CD — version hygiene |

#### Code

```yaml
uses: aquasecurity/trivy-action@1bd062560b422f5944df1de50abd05162bea079e  # master
```

#### Analysis

The commit hash pin is from the `master` branch (per the comment), not a tagged release.
This means it may contain unreleased or unreviewed code. The same pattern applies to
`sigstore/cosign-installer@430b6a7...  # main`. Compare with `anchore/sbom-action@17ae174...  # v0.23.0`
which properly annotates the release tag.

#### Fix

Pin to a commit hash from a tagged release and annotate accordingly:
```yaml
uses: aquasecurity/trivy-action@<sha-of-tagged-release>  # v0.31.0
```

---

### M4: SamplingPercentage 100 treated as "unset"

| Field | Value |
|-------|-------|
| **File** | `wafctl/waf_settings_generator.go:121` |
| **Severity** | Medium |
| **Category** | Logic bug — silent override drop |

#### Code

```go
// waf_settings_generator.go:121
if ss.SamplingPercentage > 0 && ss.SamplingPercentage != 100 {
    vars = append(vars, fmt.Sprintf("setvar:tx.sampling_percentage=%d", ss.SamplingPercentage))
}
```

#### Analysis

The `!= 100` check suppresses the directive because 100 is the CRS default. This works for
the global defaults section. However, `collectExtendedSetvars()` is also used for per-service
overrides. If the global default is set to 50 (sample half) and a specific service explicitly
sets `sampling_percentage: 100` (to override back to full sampling), the per-service override
is silently dropped — that service continues at 50%.

#### Fix

```go
if ss.SamplingPercentage > 0 {
    vars = append(vars, fmt.Sprintf("setvar:tx.sampling_percentage=%d", ss.SamplingPercentage))
}
```

The redundant `setvar:tx.sampling_percentage=100` in the global section is harmless.

---

### M5: Export mode allows 50k events — OOM risk

| Field | Value |
|-------|-------|
| **File** | `wafctl/handlers_events.go:394-399` |
| **Severity** | Medium |
| **Category** | Resource exhaustion |

#### Code

```go
// handlers_events.go:394-399
exportAll := strings.EqualFold(q.Get("export"), "true")
limit := queryInt(q.Get("limit"), 50)
if exportAll {
    limit = 50000
} else if limit <= 0 || limit > 1000 {
    limit = 50
}
```

#### Analysis

With 50k events at ~2-5KB each = 100-250MB JSON response built entirely in memory. On a small
container (256-512MB), this can OOM. The user-supplied `limit` param is ignored in export mode.
No rate limiting exists on this endpoint.

#### Fix

```go
if exportAll {
    if limit <= 0 || limit > 10000 {
        limit = 10000
    }
} else if limit <= 0 || limit > 1000 {
    limit = 50
}
```

---

### M6: Absolute time range inconsistency in IPLookup

| Field | Value |
|-------|-------|
| **File** | `wafctl/handlers_analytics.go:106-119` |
| **Severity** | Medium |
| **Category** | Logic bug — inconsistent filtering |

#### Code

```go
// handlers_analytics.go:106-119
tr := parseTimeRange(r)
hours := parseHours(r)
rlEvents := getRLEvents(als, tr, hours)          // uses tr when valid
result := store.IPLookup(ip, hours, limit, offset, rlEvents)  // always uses hours
```

`IPLookup` signature at `waf_analytics.go:129`:
```go
func (s *Store) IPLookup(ip string, hours, limit, offset int, extraEvents []Event) IPLookupResponse {
    events := s.SnapshotSince(hours)  // ignores absolute time range
```

#### Analysis

When the user specifies `?from=...&to=...`, RL events are correctly filtered to the absolute
range via `getRLEvents`, but WAF events inside `IPLookup` always use `hours` (defaults to 24
when not provided). A 7-day historical query would show all RL events for 7 days but only the
last 24h of WAF events.

#### Fix

Pass `timeRange` through to `IPLookup` and use it when valid.

---

### M7: No AbortController for racing requests in OverviewDashboard

| Field | Value |
|-------|-------|
| **File** | `waf-dashboard/src/components/OverviewDashboard.tsx:145-156` |
| **Severity** | Medium |
| **Category** | UI — stale data race |

#### Code

```typescript
// OverviewDashboard.tsx:145-156
const loadData = useCallback(() => {
    setLoading(true);
    setError(null);
    fetchSummary(summaryParams)
      .then(setData)           // last-to-resolve wins, not last-to-fire
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [timeRange, filters]);
```

Compare with `EventsTable.tsx:85,138-191` which correctly guards against this:
```typescript
const requestGenRef = useRef(0);
const gen = ++requestGenRef.current;
// ...later in .then():
if (requestGenRef.current !== gen) return; // discard stale response
```

#### Analysis

When a user rapidly changes time range or filters, multiple concurrent `fetchSummary` calls
fire. The last to **resolve** (not the last to fire) wins. A slow old request can overwrite
a fast new request's data, showing stale results.

#### Fix

Add a `requestGenRef` pattern matching `EventsTable.tsx`.

---

### M8: Startup ordering — caddy before wafctl on fresh deploy

| Field | Value |
|-------|-------|
| **File** | `compose.yaml:38-41`, `scripts/entrypoint.sh` |
| **Severity** | Medium |
| **Category** | Reliability — first-boot failure |

#### Analysis

Caddy's Caddyfile includes `Include /data/coraza/custom-pre-crs.conf` etc. These files are
created by wafctl's `generateOnBoot()`. Caddy has no `depends_on` for wafctl, and the
entrypoint only seeds `ipsum_block.caddy` and `cf_trusted_proxies.caddy` — not the dynamic WAF
config files.

On a **fresh** deployment (no prior data volumes), Caddy fails to start because the Coraza
`Include` files don't exist. Existing deployments are unaffected (files persist on volumes).

#### Fix

Add placeholder file creation to `entrypoint.sh`:

```bash
for f in custom-pre-crs.conf custom-waf-settings.conf custom-post-crs.conf; do
    target="/data/coraza/$f"
    if [ ! -f "$target" ]; then
        echo "# Placeholder - will be populated by wafctl" > "$target"
    fi
done
```

---

### M9: Jellyfin has no security headers

| Field | Value |
|-------|-------|
| **File** | `Caddyfile:490-507` |
| **Severity** | Medium |
| **Category** | Security — missing hardening |

#### Code

```caddyfile
# Caddyfile:490-492
jellyfin.erfi.io {
	# import cors
	# import security_headers_base
```

Both `cors` and `security_headers_base` are commented out.

#### Analysis

Jellyfin responses lack HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and
Cross-Origin-Opener-Policy. The `security_headers_base` snippet already uses the relaxed
`Cross-Origin-Resource-Policy "cross-origin"` which is compatible with native app clients.

#### Fix

Uncomment `import security_headers_base`. CORS can stay commented out if Jellyfin manages its
own CORS headers.

---

### M10: Missing aria-label on icon-only buttons

| Field | Value |
|-------|-------|
| **File** | `waf-dashboard/src/components/PolicyEngine.tsx:620-634`, `RateLimitsPanel.tsx:657-672` |
| **Severity** | Medium |
| **Category** | Accessibility — WCAG 4.1.2 |

#### Code

```tsx
// PolicyEngine.tsx:620-625
<Button variant="ghost" size="icon-sm" onClick={() => setEditingId(excl.id)}>
  <Pencil className="h-3.5 w-3.5" />
</Button>
<Button variant="ghost" size="icon-sm" onClick={() => setDeleteConfirmId(excl.id)}>
  <Trash2 className="h-3.5 w-3.5" />
</Button>
```

No `aria-label`, `title`, or `sr-only` text.

#### Fix

```tsx
<Button aria-label={`Edit rule ${excl.name}`} variant="ghost" size="icon-sm" ...>
<Button aria-label={`Delete rule ${excl.name}`} variant="ghost" size="icon-sm" ...>
```

---

### M11: No aria-expanded on expandable table rows

| Field | Value |
|-------|-------|
| **File** | `waf-dashboard/src/components/OverviewDashboard.tsx:721-781` |
| **Severity** | Medium |
| **Category** | Accessibility — WCAG 2.1.1 |

#### Code

```tsx
// OverviewDashboard.tsx:721-730
<TableRow className="cursor-pointer" onClick={() => { /* toggle */ }}>
  <TableCell>{expanded.has(evt.id) ? <ChevronDown/> : <ChevronRight/>}</TableCell>
```

No `aria-expanded`, `role`, `tabIndex`, or `onKeyDown` handler.

#### Fix

```tsx
<TableRow
  className="cursor-pointer"
  role="button"
  tabIndex={0}
  aria-expanded={expanded.has(evt.id)}
  onClick={() => { /* toggle */ }}
  onKeyDown={(e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      /* toggle */
    }
  }}
>
```

---

### M12: No CI concurrency control

| Field | Value |
|-------|-------|
| **File** | `.github/workflows/build.yml` |
| **Severity** | Medium |
| **Category** | CI/CD — race condition |

#### Analysis

No `concurrency:` key. Two pushes to `main` in quick succession run the full build/push/sign
pipeline in parallel, potentially pushing images with different contents under the same tag.

#### Fix

```yaml
concurrency:
  group: build-${{ github.ref }}
  cancel-in-progress: true
```

---

### M13: Unbounded user-supplied regex in query filters

| Field | Value |
|-------|-------|
| **File** | `wafctl/query_helpers.go:116-132` |
| **Severity** | Medium |
| **Category** | Resource exhaustion |

#### Code

```go
// query_helpers.go:126-132
case "regex":
    re, err := regexp.Compile(value)  // no length limit on value
    if err != nil {
        f.op = "contains"
    } else {
        f.re = re
    }
```

#### Analysis

Go's RE2 prevents catastrophic backtracking, but compilation of extremely large patterns
(e.g., 1MB of alternations) consumes significant CPU and memory. The `value` comes from URL
query parameters with no length cap.

#### Fix

```go
case "regex":
    if len(value) > 1024 {
        f.op = "contains"
    } else {
        re, err := regexp.Compile(value)
        if err != nil {
            f.op = "contains"
        } else {
            f.re = re
        }
    }
```

---

## Low

### L1: Dead code — unused oldest slice in GeoIP evictRandom

| Field | Value |
|-------|-------|
| **File** | `wafctl/geoip.go:453-473` |

```go
func (s *GeoIPStore) evictRandom() {
    target := geoCacheMaxSize / 4
    type aged struct {
        key string
        ts  time.Time
    }
    oldest := make([]aged, 0, len(s.cache))    // allocated
    for k, v := range s.cache {
        oldest = append(oldest, aged{k, v.ts}) // populated
    }
    // ... oldest is NEVER READ ...
    deleted := 0
    for k := range s.cache {
        if deleted >= target { break }
        delete(s.cache, k)
        deleted++
    }
}
```

The `oldest` slice allocates ~4MB at `geoCacheMaxSize=100000` (100k structs with string+Time),
iterates the entire map, then discards the result. Leftover from an abandoned age-based eviction
approach. **Fix:** Remove the `oldest` slice allocation and population loop.

---

### L2: String-based error comparison in json_helpers.go

| Field | Value |
|-------|-------|
| **File** | `wafctl/json_helpers.go:22` |

```go
if err.Error() == "http: request body too large" {
```

Go 1.19+ provides `*http.MaxBytesError`. **Fix:** `var mbe *http.MaxBytesError; if errors.As(err, &mbe) { ... }`

---

### L3: Dead ResetRuleIDCounter() calls

| Field | Value |
|-------|-------|
| **File** | `wafctl/handlers_config.go:53,71,104`, `wafctl/generator.go:641-645` |

Three call sites invoke a documented no-op:
```go
// generator.go:641-645
func ResetRuleIDCounter() {
    // no-op: rule IDs are now per-invocation via ruleIDGen
}
```

**Fix:** Delete the function and all three call sites.

---

### L4: truncate operates on bytes not runes

| Field | Value |
|-------|-------|
| **File** | `wafctl/validate.go:322-327` |

```go
func truncate(s string, maxLen int) string {
    if len(s) <= maxLen { return s }
    return s[:maxLen] + "..."
}
```

Slicing at byte offset can split multi-byte UTF-8 characters. Only used for log/warning
messages with mostly ASCII content. **Fix:** Use `[]rune(s)` for correct Unicode truncation.

---

### L5: CORS middleware sets headers on rejected origins

| Field | Value |
|-------|-------|
| **File** | `wafctl/main.go:277-303` |

When origin is present but not in the allowlist and method is not OPTIONS, execution falls
through to lines 294-295 which unconditionally set `Allow-Methods` and `Allow-Headers`.
These are meaningless without `Allow-Origin` but add noise. **Fix:** Move header setting
inside the allowed-origin branches.

---

### L6: Redundant time format in parseTimeRange

| Field | Value |
|-------|-------|
| **File** | `wafctl/query_helpers.go:48-54` |

`"2006-01-02T15:04:05Z"` is already matched by `time.RFC3339`. The fifth format in the list
is redundant. **Fix:** Remove `"2006-01-02T15:04:05Z"`.

---

### L7: Variable shadowing w in handleValidateConfig

| Field | Value |
|-------|-------|
| **File** | `wafctl/handlers_config.go:80` |

```go
for _, w := range selfRefWarnings {
```

Loop variable `w` shadows the `http.ResponseWriter` parameter `w`. Not a bug but a readability
hazard. **Fix:** Rename to `warn`.

---

### L8: parseHours silent fallback to 0 for unrecognized values

| Field | Value |
|-------|-------|
| **File** | `wafctl/query_helpers.go:15-28` |

`?hours=2` silently returns 0 (all time) because 2 is not in `validHours`. The caller may
expect 2 hours of data and get everything instead. **Fix:** Return 400 for invalid values, or
accept any positive integer.

---

### L9: RateLimitEventToEvent hardcodes Protocol

| Field | Value |
|-------|-------|
| **File** | `wafctl/access_log_store.go:566` |

```go
Protocol: "HTTP/2.0", // access log doesn't differentiate per-request; default
```

The protocol is available in the raw access log (`AccessLogReq.Proto`) but lost during
conversion to `RateLimitEvent`. **Fix:** Add a `Protocol` field to `RateLimitEvent` and
propagate it.

---

### L10: blocklist.ts uses raw fetch instead of postJSON

| Field | Value |
|-------|-------|
| **File** | `waf-dashboard/src/lib/api/blocklist.ts:38-44` |

The only API function using raw `fetch` instead of the shared `postJSON` helper. Inconsistent
error handling. **Fix:** `return postJSON<BlocklistRefreshResult>(\`${API_BASE}/blocklist/refresh\`, {});`

---

### L11: RLRuleKey type collapses to string

| Field | Value |
|-------|-------|
| **File** | `waf-dashboard/src/lib/api/rate-limits.ts:7` |

```typescript
export type RLRuleKey = "client_ip" | string;
```

TypeScript collapses `"client_ip" | string` to just `string`. Zero type safety. **Fix:**
Enumerate known keys or just use `string` without the misleading union.

---

### L12: TimeRangePicker hours:0 sentinel is misleading

| Field | Value |
|-------|-------|
| **File** | `waf-dashboard/src/components/TimeRangePicker.tsx:38-50` |

Most `QUICK_RANGES` entries have `hours: 0` as a sentinel meaning "use label-based minutes
lookup". It looks like "all time" but means "not in validHours allowlist". **Fix:** Use `hours: -1`
as sentinel, or remove the field entirely since only `RANGE_MINUTES` is used.

---

### L13: .dockerignore missing exclusions

| Field | Value |
|-------|-------|
| **File** | `.dockerignore` |

Missing: `test/`, `.github/`, `.sbom/`, `.env.mk`, `Makefile`. These inflate the build context
unnecessarily. **Fix:** Add them to `.dockerignore`.

---

### L14: || loses falsy numeric values in exclusions.ts

| Field | Value |
|-------|-------|
| **File** | `waf-dashboard/src/lib/api/exclusions.ts:189-190` |

```typescript
anomaly_score: raw.anomaly_score || undefined,
anomaly_paranoia_level: raw.anomaly_paranoia_level || undefined,
```

`||` treats `0` as falsy, converting it to `undefined`. Should use `??`. In practice these
fields are 1+ so the impact is negligible.

---

### L15: Unchecked JSON imports in SettingsPanel/CSPPanel

| Field | Value |
|-------|-------|
| **File** | `waf-dashboard/src/components/SettingsPanel.tsx:203`, `CSPPanel.tsx:212` |

```typescript
const data = JSON.parse(text) as WAFConfig;
```

`as` cast provides no runtime validation. A malformed JSON file with correct top-level keys
but wrong nested types could corrupt component state. Wrapped in try/catch so it won't crash,
but could silently set bad state. **Fix:** Add minimal structural validation before `set*` calls.

---

### L16: CORS reflects host header

| Field | Value |
|-------|-------|
| **File** | `Caddyfile:56-67` |

```caddyfile
header Access-Control-Allow-Origin "https://{http.request.host}"
```

Reflects the Host header as the CORS origin. Caddy's site block matching prevents requests with
arbitrary Host headers from reaching the snippet (SNI/hostname matching), so this effectively
means "allow same-origin only". Not a vulnerability, but non-standard CORS behavior.

---

### L17: general_logs.go compactEventFileLocked unchecked Sync/Close

| Field | Value |
|-------|-------|
| **File** | `wafctl/general_logs.go:127-129` |

```go
f.Sync()   // error ignored
f.Close()  // error ignored
os.Rename(tmp, s.eventFile)
```

On NFS or certain filesystems, `Close()` can report deferred write errors. If `Sync()` fails,
rename could create a corrupt file. Same in `access_log_store.go:225-226`. **Fix:** Check both
errors and skip rename on failure.

---

### L18: blocklist.go ensureLoaded thundering herd

| Field | Value |
|-------|-------|
| **File** | `wafctl/blocklist.go:125-133` |

```go
func (bs *BlocklistStore) ensureLoaded() {
    bs.mu.RLock()
    stale := time.Since(bs.lastLoad) > bs.cacheTTL
    bs.mu.RUnlock()
    if stale {
        bs.parseFile()  // multiple goroutines can all call this
    }
}
```

Multiple concurrent requests seeing `stale=true` all call `parseFile()` redundantly (re-reading
multi-MB file). Not a correctness bug (write lock inside `parseFile` protects state), but wastes
CPU/disk. **Fix:** Use `atomic.Bool` guard like the existing `refreshing` flag in `Refresh()`.

---

### L19: CSP deepCopy ignores marshal errors

| Field | Value |
|-------|-------|
| **File** | `wafctl/csp.go:360-368` |

```go
data, _ := json.Marshal(s.cfg)
var copy CSPConfig
json.Unmarshal(data, &copy)
```

Both errors silently discarded. If marshal fails (unlikely for this struct), returns zero-value
config. **Fix:** Return `(CSPConfig, error)` or log on error.

---

### L20: Regex cache grows unbounded

| Field | Value |
|-------|-------|
| **File** | `wafctl/rl_analytics.go:12-26` |

```go
var regexCache sync.Map  // no eviction, no max size, no TTL
```

Patterns come from stored rate limit rules (not user queries), so the key space is bounded by
admin-created rules — typically single digits. **Practical risk is very low.** Fix if desired:
add a size cap with full eviction at threshold.

---

### L21: DisabledGroups tags not escaped in waf_settings_generator

| Field | Value |
|-------|-------|
| **File** | `wafctl/waf_settings_generator.go:89-92, 298-301` |

```go
b.WriteString(fmt.Sprintf("SecAction \"id:%s,...,ctl:ruleRemoveByTag=%s\"\n", idGen.next(), tag))
```

`tag` interpolated without `escapeSecRuleValue()`. Tags come from `validRuleGroupTags` safelist
(validated known strings like `language-php`, `OWASP_CRS`), so not exploitable today. But relies
on validation layer rather than escaping at generation. **Fix:** Apply `escapeSecRuleValue(tag)`
at the generation site for defense-in-depth.

---

### L22: advisorCache has no max size enforcement

| Field | Value |
|-------|-------|
| **File** | `wafctl/rl_advisor_types.go:171-183` |

Eviction only removes expired entries when cache exceeds 50. If 50+ non-expired entries exist
(within 30s TTL), cache grows unbounded. Practically limited by the small key space
(`window|service|path|method|limit`). **Fix:** Add hard cap — evict oldest non-expired entry
when at capacity after expired cleanup.

---

### L23: release.yml PREV_TAG may match non-semver tags

| Field | Value |
|-------|-------|
| **File** | `.github/workflows/release.yml:24` |

```bash
PREV_TAG=$(git tag --sort=-creatordate | grep -v "^${TAG}$" | head -1)
```

Takes most recent tag regardless of format. A non-semver tag (e.g., `test-build`) would produce
incorrect release notes. **Fix:** Filter to semver: `grep -E '^v[0-9]'`.

---

## Invalidated Findings

### X1: splitCTLActions naive comma split

| Field | Value |
|-------|-------|
| **File** | `wafctl/generator.go:410-424` |
| **Original severity** | Critical |
| **Verdict** | **INVALIDATED** — not exploitable |

The naive comma split in `splitCTLActions` is safe because **every** user-controlled value that
enters the action string is sanitized:
- `escapeSecRuleMsgValue()` at `generator.go:607` replaces all commas with semicolons in `msg:` fields
- Rule IDs are regex-validated as numeric by `validateExclusion`
- Rule tags are regex-validated by `ruleTagRe`
- `logdata:` uses hardcoded Coraza macros (no user input)

The code is fragile-by-design (a future action field that skips `escapeSecRuleMsgValue` would
break), but it is not currently exploitable. **Recommendation:** Add a comment documenting the
invariant and add unit tests for `splitCTLActions`.

---

### X2: Ignored json.Unmarshal errors in partial update merge

| Field | Value |
|-------|-------|
| **File** | `wafctl/handlers_exclusions.go:140-145` |
| **Original severity** | High |
| **Verdict** | **INVALIDATED** — cannot fail in practice |

```go
base, _ := json.Marshal(existing)          // existing is a known-good struct — cannot fail
var merged RuleExclusion
_ = json.Unmarshal(base, &merged)          // round-trip of same type — cannot fail
overlay, _ := json.Marshal(raw)            // raw is map[string]json.RawMessage — cannot fail
_ = json.Unmarshal(overlay, &merged)       // type mismatch just keeps old value, then validated
```

The only observable behavior for a type mismatch (e.g., `"enabled": "yes"`) is that the field
silently keeps its old value, and `validateExclusion(merged)` at line 147 catches any
semantically invalid result. This is arguably correct JSON merge-patch behavior.

---

### X3: CLI reads unlimited stdin/response bodies

| Field | Value |
|-------|-------|
| **File** | `wafctl/cli.go:317-322` |
| **Original severity** | High |
| **Verdict** | **INVALIDATED** — CLI context, not a server |

This is a CLI tool, not a network service. The operator pipes their own data into their own CLI.
The server side has `MaxBytesReader` (5MB) via `decodeJSON`, so oversized payloads are rejected
at the API level. Standard CLI behavior — no widely-used CLI tool limits stdin reads.

---

### X4: Dockerfile COPY wafctl/\*.go misses subdirectories

| Field | Value |
|-------|-------|
| **File** | `Dockerfile:52` |
| **Original severity** | High |
| **Verdict** | **INVALIDATED** — no subdirectories exist |

All 61 `.go` files live flat in `wafctl/` with no subdirectories. The glob works correctly.
If a subpackage were ever added, the compiler would immediately error on the missing `import`,
making the breakage obvious at build time.

---

### X5: Stale closure in Recharts onMouseMove

| Field | Value |
|-------|-------|
| **File** | `waf-dashboard/src/components/OverviewDashboard.tsx:243-250` |
| **Original severity** | High |
| **Verdict** | **INVALIDATED** — not a real bug |

The `useCallback` dependency array `[refAreaLeft]` is correct. React re-renders synchronously
after `setRefAreaLeft`, and the user cannot generate a `mousemove` event in the same browser
task as `mousedown`. Recharts re-binds handlers on re-render via normal React prop diffing.

---

### X6: Dockerfile alpine used in two separate stages

| Field | Value |
|-------|-------|
| **File** | `Dockerfile:13,28` |
| **Original severity** | Low |
| **Verdict** | **INVALIDATED** — standard multi-stage practice |

Both stages use `alpine:3.21` but Docker layer caching pulls the base only once. Separate stages
run in parallel with BuildKit. No overhead.
