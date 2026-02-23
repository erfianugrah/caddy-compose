# PLAN.md — Sentinel-Inspired Security Enhancements

Porting inline security features from k3s Sentinel to the Caddy/Coraza WAF stack.
All features are implemented as SecRules evaluated by Coraza inline (every request),
managed through the existing waf-api Policy Engine and deploy pipeline.

Branch: `feature/sentinel-inspired-security`

---

## 1. Honeypot Paths

**Status:** Done (Phase A — static rules)
**Difficulty:** Low
**Files:** `coraza/post-crs.conf`, optionally `waf-api/generator.go` + `models.go`

### What

Add SecRules that detect requests to known-bad paths (admin panels, dotfiles,
PHP endpoints that don't exist in this stack). Instant deny or high anomaly score.

### Why

CRS catches some of these via LFI/scanner rules, but a dedicated honeypot that
fires on exact paths is faster (phase 1, no regex) and assigns heavier penalties.
Sentinel scores these at +50 per hit, which is half the blocking threshold.

### Implementation

**Phase A — Static rules in `post-crs.conf` (baked into image):**

```apache
# --- Honeypot: dotfile probes ---
SecRule REQUEST_URI "@pmFromFile /etc/caddy/coraza/honeypot-paths.txt" \
    "id:9100020,\
    phase:1,\
    deny,\
    status:403,\
    log,\
    msg:'Honeypot: known-bad path probe',\
    tag:'honeypot',\
    tag:'custom-rules',\
    severity:'CRITICAL'"
```

`honeypot-paths.txt` (one path per line):
```
/.env
/.git/config
/.git/HEAD
/.aws/credentials
/.ssh/id_rsa
/wp-login.php
/wp-admin/
/xmlrpc.php
/wp-content/
/administrator/
/phpmyadmin
/pma/
/.htaccess
/.htpasswd
/server-status
/server-info
/cgi-bin/
/.well-known/security.txt
/autodiscover/autodiscover.xml
/ecp/
/owa/
/telescope/requests
/debug/vars
/actuator
```

**Phase B — Dynamic honeypot paths via Policy Engine (optional):**

Add a new exclusion type `honeypot` to the Policy Engine, allowing users to
add/remove honeypot paths through the dashboard without rebuilding the image.
- New exclusion type in `models.go`: `"honeypot": true`
- Generator in `generator.go`: produces `@pmFromFile` or `@pm` rules
- Dashboard UI: simple path list editor in PolicyEngine.tsx

### Rule ID allocation

`9100020–9100029` — honeypot rules in `post-crs.conf`

### Testing

- Go tests: generate honeypot exclusions, verify SecRule output
- Manual: `curl -I https://example.com/.env` should return 403

---

## 2. Heuristic Bot Signals

**Status:** Done (static rules in pre-crs.conf)
**Difficulty:** Medium
**Files:** `coraza/pre-crs.conf` or generated via `generator.go`

### What

SecRules that detect suspicious request characteristics and contribute to the
CRS anomaly score (via `setvar:tx.anomaly_score_pl1`), rather than blocking
outright. Multiple weak signals combine to breach the threshold.

### Why

A single missing header won't trigger CRS, but a request with no Accept header +
no Referer + HTTP/1.0 + scanner-like path pattern is almost certainly automated.
Sentinel uses 9 signals for this; we can implement the most effective ones as
SecRules that feed into CRS's existing anomaly scoring.

### Signals to implement

| Signal | SecRule variable | Operator | Score | Notes |
|--------|-----------------|----------|-------|-------|
| Missing Accept header | `&REQUEST_HEADERS:Accept` | `@eq 0` | +2 | Phase 1. Exclude health checks, Caddy internal. |
| Missing Referer on non-API GET | `&REQUEST_HEADERS:Referer` | `@eq 0` | +1 | Phase 1. Chain: method=GET AND path != /api/*. |
| HTTP/1.0 protocol | `REQUEST_PROTOCOL` | `@streq HTTP/1.0` | +2 | Phase 1. Most modern clients use 1.1+. |
| Empty/missing User-Agent | `&REQUEST_HEADERS:User-Agent` | `@eq 0` | +3 | Phase 1. Already partially covered by CRS 920320. |
| Known scanner UA substring | `REQUEST_HEADERS:User-Agent` | `@pm` | +5 | Phase 1. sqlmap, nikto, nuclei, gobuster, etc. |

### Implementation

```apache
# --- Heuristic: missing Accept header ---
SecRule &REQUEST_HEADERS:Accept "@eq 0" \
    "id:9100030,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.anomaly_score_pl1=+2',\
    msg:'Heuristic: missing Accept header',\
    tag:'heuristic',\
    tag:'custom-rules'"

# --- Heuristic: HTTP/1.0 protocol ---
SecRule REQUEST_PROTOCOL "@streq HTTP/1.0" \
    "id:9100031,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.anomaly_score_pl1=+2',\
    msg:'Heuristic: HTTP/1.0 protocol',\
    tag:'heuristic',\
    tag:'custom-rules'"

# --- Heuristic: known scanner User-Agent ---
SecRule REQUEST_HEADERS:User-Agent \
    "@pm sqlmap nikto nuclei gobuster dirbuster ffuf wfuzz nmap masscan zgrab \
    censys shodan netcraft qualys nessus burp zap arachni acunetix whatweb \
    httprobe subfinder amass" \
    "id:9100032,\
    phase:1,\
    deny,\
    status:403,\
    log,\
    msg:'Heuristic: known scanner User-Agent',\
    tag:'heuristic',\
    tag:'scanner',\
    tag:'custom-rules',\
    severity:'CRITICAL'"
```

Note: scanner UA rule uses `deny` (instant block) rather than score increment,
since any client identifying as a scanner is not a false positive.

### Rule ID allocation

`9100030–9100049` — heuristic signal rules

### Open questions

- Should heuristic scores be configurable via the dashboard (like paranoia level)?
- Should health check paths (`/api/health`) be excluded from missing-header rules?
  Yes — add a chained `SecRule REQUEST_URI "!@beginsWith /api/health"` condition.

### Testing

- Go tests: table-driven tests for each signal generating correct SecRule syntax
- Manual: `curl -H "User-Agent: sqlmap/1.0" https://example.com/` → 403
- Manual: `curl --http1.0 -H "Accept:" https://example.com/` → higher anomaly score

---

## 3. Tarpitting

**Status:** Done (Option D — `drop` for scanners via rule 9100032)
**Difficulty:** Medium-High
**Files:** Caddyfile (new handler), possibly a small Caddy plugin or `respond` delay

### What

Intentionally delay responses to suspicious clients to waste scanner time and
slow down automated attacks.

### Why

Blocking is binary — the scanner immediately knows it's blocked and moves on.
Tarpitting forces the scanner to wait, consuming its resources. Sentinel
implements this as a configurable delay on flagged requests.

### Coraza limitation

**Coraza does NOT support `pause:N`.** The ModSecurity `pause` action was never
implemented. The full list of Coraza disruptive actions is:
`allow`, `deny`, `drop`, `pass`, `redirect`, `block`.

### Alternative approaches

**Option A — Caddy `respond` with deliberate slow body (preferred):**

Use Caddy's `respond` directive with a matcher for flagged requests. Coraza can
set a request header or variable when anomaly score is elevated but below the
blocking threshold, and a Caddy handler can match on that to inject delay.

However, Coraza-Caddy does not currently expose transaction variables to
downstream Caddy handlers. This would require a custom Caddy module or a
coraza-caddy enhancement.

**Option B — Caddy rate limiting with very low limits:**

Use `caddy-ratelimit` with a per-IP zone that has extremely low throughput
(e.g., 1 request per 10 seconds) applied only to flagged IPs. The rate limiter
queues requests, effectively tarpitting.

**Option C — Reverse proxy to a tarpit service:**

Route flagged requests to a dedicated tarpit endpoint (a trivial Go HTTP handler
that sleeps before responding). The flag could be set via the IPsum blocklist
matcher or a custom Caddy matcher.

**Option D — `drop` action in Coraza:**

Coraza supports `drop` which closes the connection immediately without a response.
This isn't tarpitting (no delay) but is more hostile than `deny` — the client
gets a connection reset instead of a clean 403. Useful against aggressive scanners.

### Recommendation

Start with **Option D (`drop`)** for known scanners — it's zero-effort since
Coraza already supports it. Defer true tarpitting to a future enhancement since
all options require work outside the Coraza SecRule layer.

For the scanner UA rule in section 2, use `drop` instead of `deny`:
```apache
SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto ..." \
    "id:9100032,...,drop,..."
```

### Implementation plan

1. Use `drop` for scanner UAs and honeypot paths (immediate, no new code)
2. Investigate coraza-caddy variable export for Option A (future PR)
3. Consider Option C tarpit service if there's demand (future PR)

---

## 4. IP Allowlist

**Status:** Done (generator already emits `ctl:ruleEngine=Off` for allow-type exclusions)
**Difficulty:** Low
**Files:** `waf-api/generator.go`, `waf-api/models.go`, `waf-api/exclusions.go`,
`waf-dashboard/src/components/PolicyEngine.tsx`, `waf-dashboard/src/lib/api.ts`

### What

A dedicated allowlist that bypasses ALL WAF checks for trusted IPs (monitoring
systems, CI runners, the operator's own IP, internal services).

### Current state

The Policy Engine already supports `type: "allow"` exclusions with `ip_match`
conditions. These generate:
```apache
SecRule REMOTE_ADDR "@ipMatch 1.2.3.4" \
    "id:95xxxxx,phase:1,allow,nolog"
```

However, `allow` stops rule evaluation for the current phase only. The canonical
pattern for full WAF bypass is `pass` + `ctl:ruleEngine=Off`:
```apache
SecRule REMOTE_ADDR "@ipMatch 1.2.3.4" \
    "id:95xxxxx,phase:1,pass,nolog,ctl:ruleEngine=Off"
```

### Implementation

**Change the `allow` type generator** in `generator.go` to emit
`pass,nolog,ctl:ruleEngine=Off` instead of `allow,nolog` when the only
condition is an `ip_match`. This is more thorough — it disables the engine
for ALL subsequent rules in the transaction, not just the current phase.

Coraza confirms support:
- `@ipMatch` — supports IPv4, IPv6, CIDR notation
- `@ipMatchFromFile` — load from file, one IP/CIDR per line, `#` comments
- `ctl:ruleEngine=Off` — fully supported, disables engine for remaining rules

### Changes needed

1. `generator.go` — update `generateAllowRule()` to use `pass,nolog,ctl:ruleEngine=Off`
2. Tests in `main_test.go` — update expected output for allow-type exclusions
3. No frontend changes needed — the existing "Allow" type in Policy Engine
   already supports IP conditions

### Optional enhancement

Add a dedicated "Allowlist" page in the dashboard (separate from Policy Engine)
for a simpler UX — just an IP/CIDR list with add/remove, no condition builder.
This would be a thin wrapper around the exclusion store with `type: "allow"`.

### Testing

- Update existing `TestGenerateAllowExclusion*` tests for new output
- Add test: allow with IP → `ctl:ruleEngine=Off` in output
- Manual: allowlisted IP should trigger zero WAF rules (check audit log)

---

## 5. GeoIP Analytics and Blocking

**Status:** Done (Phase 5A — analytics with MMDB reader + CF header + dashboard; Phase 6 — country condition in Policy Engine via Cf-Ipcountry)
**Difficulty:** Medium-High
**Files:** `waf-api/` (new `geoip.go`), `waf-api/logparser.go`, `waf-api/models.go`,
`waf-api/main.go`, `waf-dashboard/src/lib/api.ts`,
`waf-dashboard/src/components/AnalyticsDashboard.tsx`

### What

Country-level geolocation for every request, surfaced in analytics dashboards
and available for SecRule-based blocking/scoring.

### Design: Three-tier resolution

The implementation must work with and without Cloudflare, and with and without
a local MMDB database.

```
Priority 1: Cf-Ipcountry header (free, zero latency, present when behind CF)
Priority 2: Local MMDB database lookup (free, sub-microsecond, offline)
Priority 3: Online API fallback (for deployments without CF or MMDB)
```

### Tier 1 — Cloudflare header (inline via Coraza)

When behind Cloudflare, every request has a `Cf-Ipcountry` header. Coraza can
match this directly:

```apache
# Block requests from specific countries
SecRule REQUEST_HEADERS:Cf-Ipcountry "@pm CN RU" \
    "id:9100050,phase:1,deny,status:403,log,\
    msg:'GeoIP: blocked country',tag:'geoip',tag:'custom-rules',severity:'WARNING'"
```

This is the simplest and most efficient path — no Go code needed for blocking.
The waf-api dashboard can expose a country blocklist that generates these rules.

For analytics, the `Cf-Ipcountry` value needs to be parsed from Caddy access
logs (it's already logged as a request header).

### Tier 2 — Local MMDB database (waf-api side)

For deployments without Cloudflare, or for enriching analytics regardless:

**MMDB reader approach:** Port the pure-Go MMDB reader from k3s Sentinel
(`/home/erfi/k3s/middleware/sentinel.go:1983-2380`). This is a ~400-line
stdlib-only implementation that reads DB-IP or MaxMind GeoLite2 MMDB files.
It extracts only `country.iso_code`, which is all we need.

**Database options:**

| Database | Signup | License | Update frequency |
|----------|--------|---------|-----------------|
| DB-IP Lite Country | None needed | CC BY 4.0 (attribution) | Monthly |
| MaxMind GeoLite2 Country | Free account + key | GeoLite2 EULA | Twice weekly |

**Recommendation:** DB-IP Lite — no signup, no API key, just download the MMDB.
Same format, same reader code. Sentinel already uses this in production.

**New files:**
- `waf-api/geoip.go` — MMDB reader (ported from Sentinel), GeoIP store with
  in-memory cache, `Cf-Ipcountry` header parser, online API fallback
- MMDB file mounted as a volume: `/data/geoip/country.mmdb`

**Environment variables:**
- `WAF_GEOIP_DB` — path to MMDB file (default: `/data/geoip/country.mmdb`)
- `WAF_GEOIP_API_URL` — online fallback API URL (default: empty = disabled)
- `WAF_GEOIP_API_KEY` — API key for online fallback (default: empty)

### Tier 3 — Online API fallback

When no MMDB is available and no CF header is present, fall back to an online API.

**Recommended: IPinfo.io Lite**
- Free tier: unlimited requests, country + continent + ASN
- Requires free API key (signup at ipinfo.io)
- HTTPS, commercial use allowed with attribution
- Response: `{"ip":"1.2.3.4","country":"US","continent":"NA",...}`

**Implementation:**
- HTTP client with configurable timeout (default 2s)
- In-memory LRU cache (avoid repeated lookups for same IP)
- Cache TTL: 24 hours (country doesn't change often)
- Graceful degradation: if API is down, country = "XX" (unknown)

### Analytics integration

**Access log parsing** (`logparser.go` / `rl_analytics.go`):
- Extract `Cf-Ipcountry` from logged request headers when present
- For IPs without CF header, do MMDB lookup on first occurrence, cache result
- Add `Country string` field to `WAFEvent` and `AccessLogEvent` models

**New API endpoints:**
- `GET /api/analytics/top-countries` — top countries by request count
- Add `country` field to existing `/api/events` response

**Dashboard:**
- New "Countries" chart in AnalyticsDashboard.tsx (bar chart or table)
- Country column in EventsTable.tsx
- Country filter in event search

### GeoIP-based SecRule generation

Add a new exclusion condition type for country matching:

```go
// In models.go — new condition field value
{Field: "country", Operator: "eq", Value: "CN"}
{Field: "country", Operator: "in", Value: "CN,RU,KP"}
```

Generator produces:
```apache
# When behind Cloudflare
SecRule REQUEST_HEADERS:Cf-Ipcountry "@pm CN RU KP" \
    "id:95xxxxx,phase:1,deny,status:403,log,..."

# When not behind Cloudflare (requires X-Country header set by waf-api or Caddy)
# This is more complex — either:
# a) A Caddy handler that does MMDB lookup and sets a header before Coraza
# b) Coraza @geoLookup operator (not available in coraza-caddy)
```

**Note:** Inline MMDB lookup during Coraza rule evaluation is NOT possible
without a Caddy plugin that resolves country before Coraza processes the request.
For non-CF deployments, geo-blocking would need to be implemented as either:
- A custom Caddy middleware that sets an `X-Geo-Country` header before Coraza
- A waf-api-generated IPsum-style blocklist file (resolve countries offline,
  generate IP block lists per country)

For the initial implementation, focus on CF-header-based blocking (inline) and
MMDB-based analytics (waf-api side). Non-CF inline geo-blocking is a future item.

### Rule ID allocation

`9100050–9100059` — GeoIP blocking rules

### Testing

- Go tests: MMDB reader with test database, country lookup, cache behavior
- Go tests: Cf-Ipcountry header parsing from access log lines
- Go tests: GeoIP SecRule generation for country conditions
- Manual: verify country appears in dashboard analytics

---

## Implementation Order

| Phase | Feature | Effort | Impact | Status |
|-------|---------|--------|--------|--------|
| 1 | Honeypot paths (static rules) | 1-2 hours | High — immediate scanner protection | **Done** |
| 2 | IP allowlist fix (`ctl:ruleEngine=Off`) | 1 hour | Medium — correctness fix | **Done** |
| 3 | Heuristic bot signals (static rules) | 2-3 hours | High — catches what CRS misses | **Done** |
| 4 | Tarpitting via `drop` action | 30 min | Low — quick win for scanners | **Done** |
| 5 | GeoIP analytics (MMDB reader + dashboard) | 1-2 days | High — visibility | **Done** |
| 6 | GeoIP blocking (CF header SecRules) | 2-3 hours | Medium — only works behind CF | **Done** |
| 7 | Honeypot paths (dynamic via Policy Engine) | 3-4 hours | Medium — dashboard management | Not started |
| 8 | GeoIP online API fallback | 3-4 hours | Low — edge case for non-CF, non-MMDB | Not started |

Total estimated effort: ~3-4 days

---

## Rule ID Allocation Summary

| Range | Purpose |
|-------|---------|
| `9100001–9100006` | Pre-CRS static rules (existing, `pre-crs.conf`) |
| `9100010–9100019` | Post-CRS static rules (existing, `post-crs.conf`) |
| `9100020–9100029` | Honeypot path rules (new) |
| `9100030–9100049` | Heuristic bot signal rules (new) |
| `9100050–9100059` | GeoIP blocking rules (new) |
| `95xxxxx` | Generated exclusion rules (existing, Policy Engine) |
| `97xxxxx` | Generated WAF settings overrides (existing) |
