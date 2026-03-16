# FIXES.md — Security & Architecture Review

Comprehensive code review of the ergo ecosystem (`caddy-compose`, `caddy-policy-engine`,
`caddy-ddos-mitigator`, `caddy-body-matcher`) from the perspective of a network engineer,
reverse proxy engineer, and white hat hacker.

Reviewed: March 2026

---

## Table of Contents

- [Critical Findings](#critical-findings)
- [High Severity Findings](#high-severity-findings)
- [Medium Severity Findings](#medium-severity-findings)
- [Low Severity Findings](#low-severity-findings)
- [Positive Security Controls](#positive-security-controls)
- [Top Recommendations](#top-recommendations)

---

## Critical Findings

### C-1. wafctl API has zero authentication

**Status: FIXED** — Bearer token auth middleware added via WAF_AUTH_TOKEN env var. Health endpoint exempt. CORS default restricted when auth enabled.

**Component:** wafctl
**Files:** `wafctl/main.go:242-370`, `wafctl/main.go:382-384`

Every endpoint is completely unauthenticated, including destructive operations:

- `POST /api/deploy` — deploys WAF rules to the live Caddy policy engine
- `POST /api/backup/restore` — replaces ALL configuration stores
- `POST /api/dos/jail` — jails arbitrary IPs
- `DELETE /api/dos/jail/{ip}` — unjails IPs
- `PUT /api/config` — changes WAF paranoia levels and thresholds
- `POST /api/exclusions` — creates allow/block rules (could whitelist attacker IPs)
- `POST /api/blocklist/refresh` — triggers external HTTP fetch
- `PUT /api/dos/config` — modifies DDoS mitigation settings

The default CORS policy is `Access-Control-Allow-Origin: *`:

```go
corsOrigins := envOr("WAF_CORS_ORIGINS", "*")
```

Any entity that can reach port 8080 has full WAF administrative control. Combined with
wildcard CORS, any webpage visited by an admin on the same network can make cross-origin
requests to the wafctl API via the browser.

**Current mitigation:** Authelia forward-auth at the Caddy layer for `waf.erfi.io`, and
wafctl is on an isolated Docker bridge (172.19.98.0/24). But wafctl binds `0.0.0.0:8080`
(`":" + port`, main.go:388) — any container on that network, or any misconfiguration
opening port 8080, exposes the entire management plane. There is no defense-in-depth.

**Recommendation:**
- Add a bearer token (via environment variable) checked in middleware.
- Restrict default CORS to the dashboard origin, not `*`.
- Consider binding to `172.19.98.2:8080` instead of `0.0.0.0`.

---

### C-2. Rate limit bypass via absent header/cookie key

**Status: FIXED** (in caddy-policy-engine) — Empty rate-limit key now falls back to client IP.

**Component:** caddy-policy-engine
**Files:** `ratelimit.go:320-330`, `ratelimit.go:724`

When a rate limit rule uses `key: "header:X-API-Key"` or `key: "cookie:session"`, and the
client omits that header/cookie, `extractKey()` returns `""`. The ServeHTTP loop then hits:

```go
if key == "" {
    continue
}
```

This **completely skips rate limiting** for that rule. Any rate limit keyed on an optional
client-controlled value is trivially bypassed by not sending it. The same applies to
`body_json:` and `body_form:` keys when the attacker sends a wrong Content-Type or empty body.

**Impact:** Critical for any rate limit rule keyed on optional/client-controlled headers
(API keys, session tokens, etc.). The `client_ip` key is safe since `clientIP()` always
returns a value.

**Recommendation:** Treat empty key as a fallback to `client_ip` instead of skipping:

```go
if key == "" {
    key = clientIP(r)  // fallback, don't skip
}
```

---

### C-3. DDoS behavioral scoring defeated with ~33 unique paths

**Status: OPEN** — Architectural change to scoring model. Deferred.

**Component:** caddy-ddos-mitigator
**Files:** `profile.go:55-72`, `profile.go:138-168`

The anomaly score is dominated by path diversity:

```go
pathScore = math.Exp(-pathDiv * 80.0)
```

An attacker rotating through just 33 unique URL paths maintains `pathDiv ≈ 33/N` which
keeps the score below the 0.65 threshold at any request volume. Worked example at 10,000
requests with 33 paths:

```
pathDiv = 33 / 10000 = 0.0033
pathScore = exp(-0.0033 * 80) = exp(-0.264) = 0.768
volumeConf = 1.0 (saturated at high volume)
rateBoost = 1.5 (pathDiv < 0.05)
finalScore = 0.768 * 1.0 * 1.5 = 1.15... wait, this exceeds threshold.
```

Correction — the rate boost only applies when pathDiv < 0.05 AND requests exceed a certain
count. But the `maxTrackedPaths` cap of 256 creates a worse problem: an attacker sends 256
random paths in the first burst (warm-up), then switches to flooding a single target. The
path set is frozen at 256, so `pathDiv = 256/N` slowly decreases as N grows but takes a
very long time to cross threshold:

```
At N=30000: pathDiv = 256/30000 = 0.0085
pathScore = exp(-0.0085 * 80) = exp(-0.68) = 0.507
score = 0.507 * 1.0 * 1.5 = 0.76  (just over 0.65 threshold)
```

The attacker gets 30,000 free requests before detection.

**Additional evasion vectors:**
- Profile TTL reset: flood for 9 minutes, pause for 10 minutes (profile expires), repeat
  with a clean slate indefinitely.
- The `maxTrackedPaths` cap means legitimate power users (>256 pages) appear MORE suspicious
  as their request count grows — false positive risk.

**Recommendation:**
- Use a **sliding window** for path diversity (not cumulative). A 60-second rolling window
  makes evasion require sustained path diversity, not just a warm-up burst.
- Incorporate **absolute request rate** as an independent signal, not just a multiplier on
  path diversity.
- Consider decaying the path set over time so stale paths don't permanently inflate diversity.

---

## High Severity Findings

### H-1. JailStore and DosConfigStore: lock released before save

**Status: FIXED** — JailStore.Add/Remove and DosConfigStore.Update now hold write lock through saveLocked().

**Component:** wafctl
**Files:** `dos_mitigation.go:129-157`, `dos_mitigation.go:259-269`

Both `JailStore.Add()` and `DosConfigStore.Update()` release `mu.Unlock()` before calling
`save()`, which re-acquires `RLock`. Between unlock and save, another goroutine (e.g., the
periodic `Reload()` at main.go:219) can mutate the data, causing the saved state to be
inconsistent:

```go
func (s *JailStore) Add(ip, ttlStr, reason string) error {
    s.mu.Lock()
    s.entries[ip] = entry
    s.mu.Unlock()       // Lock released here
    return s.save()     // save() acquires RLock — concurrent mutation possible
}
```

And `save()` itself acquires only an `RLock`:

```go
func (s *JailStore) save() error {
    s.mu.RLock()
    // ... read entries ...
    s.mu.RUnlock()
    // ... write to file ...
}
```

**Impact:** Jail entries can be silently lost. The on-disk state can diverge from in-memory
state. No rollback on failure (unlike `ConfigStore.Update` which properly rolls back).

**Recommendation:** Hold the write lock through the entire mutation+persist cycle:

```go
func (s *JailStore) Add(ip, ttlStr, reason string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.entries[ip] = entry
    return s.saveLocked()  // saveLocked() assumes lock is already held
}
```

---

### H-2. DDoS config update accepts arbitrary values with zero validation

**Status: FIXED** — validateDosConfig() validates strategy, thresholds, duration fields, and whitelist CIDRs.

**Component:** wafctl
**Files:** `handlers_dos.go:167-181`

`handleUpdateDosConfig` passes the decoded JSON directly to `store.Update()` with no
validation:

```go
func handleUpdateDosConfig(store *DosConfigStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var cfg DosConfig
        if _, failed := decodeJSON(w, r, &cfg); failed { return }
        if err := store.Update(cfg); err != nil { ... }
        writeJSON(w, http.StatusOK, cfg)
    }
}
```

An attacker with API access (see C-1) can:
- Set `Whitelist: ["0.0.0.0/0"]` → whitelist all IPv4 traffic
- Set `EPSTrigger: 999999999` → disable spike detection
- Set `Strategy` to an arbitrary string
- Set thresholds to extreme values that disable all mitigation

**Recommendation:** Add a `validateDosConfig()` function that validates:
- Whitelist entries are valid CIDRs (and not wildcard ranges)
- Numeric thresholds are within sane bounds
- Strategy is one of the known values

---

### H-3. Jail IP not validated

**Status: FIXED** — net.ParseIP() validation added to handleAddJail.

**Component:** wafctl
**Files:** `handlers_dos.go:103-131`, `dos_mitigation.go:129-148`

`handleAddJail` checks only that `req.IP != ""` but does NOT call `net.ParseIP()`:

```go
if req.IP == "" {
    writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "ip is required"})
    return
}
```

Malformed strings (containing newlines, path separators, JSON-breaking characters) are
stored in `jail.json`, which is shared with the Caddy DDoS mitigator plugin via
bidirectional file sync. This could corrupt the shared file or cause the plugin to
malfunction.

Contrast with `handleBlocklistCheck` and `handleIPLookup` which both validate with
`net.ParseIP()`.

**Recommendation:** Add IP validation:

```go
if net.ParseIP(req.IP) == nil {
    writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid IP address"})
    return
}
```

---

### H-4. Allow rules bypass rate limiting entirely

**Status: OPEN** — Requires caddy-policy-engine architectural change to evaluation order. Deferred.

**Component:** caddy-policy-engine
**Files:** `policyengine.go:540-544`, `policyengine.go:629`

When an allow rule matches, `return next.ServeHTTP(w, r)` fires immediately at line 629,
completely skipping all rate limit evaluation. The code at lines 540-544 has a `continue`
for `allowMatched` but this is unreachable since the allow return already happened.

**Impact:** An attacker whose requests match a broad allow rule (e.g., a trusted IP CIDR,
a known-good path pattern) gets unlimited request throughput with zero rate limiting.

**Recommendation:** Evaluate rate limit rules BEFORE returning for allow matches. The allow
rule should bypass block/detect phases but not rate limiting.

---

### H-5. IPv4-mapped-v6 whitelist bypass in DDoS mitigator

**Status: FIXED** (in caddy-ddos-mitigator) — .Unmap() added to clientAddr().

**Component:** caddy-ddos-mitigator
**Files:** `mitigator.go:431-451`, `mitigator_l4.go:141`, `util.go:39-46`

The L7 `clientAddr()` does NOT call `addr.Unmap()`, while the L4 handler's
`extractRemoteIP()` does call `.Unmap()` at mitigator_l4.go:141. The whitelist uses
`netip.Prefix.Contains()` which is family-sensitive.

If Caddy provides an IPv4-mapped IPv6 address like `::ffff:10.0.0.1`, the whitelist
entry `10.0.0.0/8` will **not match**. This causes whitelisted infrastructure IPs
(monitoring, health checks, upstream proxies) to be subjected to jail checks.

**This is a real bug with inconsistent behavior between L4 and L7 paths.**

**Recommendation:** One-line fix in `clientAddr()`:

```go
addr = addr.Unmap()  // normalize before returning
```

---

### H-6. Data race on profile pointer in DDoS mitigator

**Status: OPEN** — Requires tracker sharding refactor in caddy-ddos-mitigator. Deferred.

**Component:** caddy-ddos-mitigator
**Files:** `profile.go:206-219`

`Profile()` returns a mutable pointer to the actual `ipProfile` struct held in the shard
map. `AnomalyScore()` reads fields like `Requests`, `paths` (a map), `Methods` (a map)
without holding any lock, while concurrent requests call `Record()` which modifies these
same fields under the shard lock.

```go
func (t *Tracker) Profile(addr netip.Addr) *ipProfile {
    // ...
    return p  // raw pointer, no copy
}
```

`Score()` calls `Profile()` then `AnomalyScore()` which reads the maps:

```go
func (p *ipProfile) AnomalyScore() float64 {
    pathDiv := float64(len(p.paths)) / float64(p.Requests)  // concurrent read
    // ...
}
```

**Impact:** Under load, concurrent map read/write causes a Go runtime panic (`fatal error:
concurrent map read and map write`). This crashes the entire Caddy process.

**Recommendation:** Either return a deep copy from `Profile()`, or compute the score under
the shard lock:

```go
func (t *Tracker) Score(addr netip.Addr) float64 {
    s := t.shard(addr)
    s.mu.RLock()
    defer s.mu.RUnlock()
    p, ok := s.profiles[addr]
    if !ok { return 0 }
    return p.AnomalyScore()
}
```

---

### H-7. NET_ADMIN + host network mode on Caddy container

**Status: OPEN** — Architecturally required for kernel-level DDoS mitigation. Documented risk.

**Component:** caddy-compose
**Files:** `compose.yaml:7`, `compose.yaml:14`

Caddy runs with `network_mode: host` and `cap_add: NET_ADMIN`. This combination gives the
process:
- Full control over the host's routing tables
- Ability to manipulate nftables/iptables rules
- Access to all network interfaces
- Ability to bind any port
- Access to all Docker bridge networks via gateway interfaces
- Potential to sniff traffic (with raw socket access)

Combined with `DAC_OVERRIDE` (compose.yaml:13), the Caddy process can read/write any
accessible file regardless of permissions.

**Impact:** An RCE vulnerability in ANY Caddy plugin (policy engine, DDoS mitigator, body
matcher) grants host-level network control. These are custom plugins from
`github.com/erfianugrah/` — their security posture directly impacts the host.

**Current mitigations:** `cap_drop: ALL` (minimal baseline), `no-new-privileges: true`,
`read_only: true` root filesystem.

**Recommendation:** This is architecturally required for kernel-level DDoS mitigation (nftables,
eBPF/XDP). If that feature is not needed, remove `NET_ADMIN` and `network_mode: host`. If it IS
needed, consider running the nftables/XDP operations in a separate privileged sidecar that
communicates with Caddy via Unix socket, limiting the blast radius.

---

## Medium Severity Findings

### M-1. :2020 admin API proxy binds on 0.0.0.0

**Status: OPEN** — Caddyfile change requiring operator decision on bind address.

**Component:** caddy-compose
**Files:** `Caddyfile:577-590`

The internal Caddy admin API proxy listens on `:2020`. With `network_mode: host`, this binds
on ALL interfaces — reachable from the internet if port 2020 is not firewalled at the
host/cloud level. The `remote_ip 172.19.98.0/24` matcher provides application-layer
protection only.

```caddyfile
:2020 {
    @allowed remote_ip 172.19.98.0/24
    handle @allowed {
        reverse_proxy localhost:2019
    }
    handle {
        respond "Forbidden" 403
    }
}
```

No authentication beyond IP filtering. No TLS. Traffic traverses the Docker bridge in
plaintext.

**Recommendation:**
- Bind to specific interface: `172.19.98.1:2020` instead of `:2020`.
- Add host firewall rule dropping external traffic to port 2020.
- Consider using a Unix socket for the admin API instead of TCP.

---

### M-2. 17+ services lack Authelia forward-auth

**Status: OPEN** — Per-service deployment decision.

**Component:** caddy-compose
**Files:** `Caddyfile` (various site blocks)

Services with WAF but **no** `import forward_auth`:

| Service | Domain |
|---------|--------|
| sonarr | sonarr.erfi.io |
| radarr | radarr.erfi.io |
| bazarr | bazarr.erfi.io |
| tracearr | tracearr.erfi.io |
| vault | vault.erfi.io |
| prowlarr | prowlarr.erfi.io |
| jellyfin | jellyfin.erfi.io |
| qbit | qbit.erfi.io |
| seerr | seerr.erfi.io |
| keycloak | keycloak.erfi.io |
| joplin | joplin.erfi.io |
| navidrome | navidrome.erfi.io |
| sabnzbd | sabnzbd.erfi.io |
| immich | immich.erfi.io |
| copyparty | copyparty.erfi.io |
| dockge | dockge.erfi.io |
| httpbun/httpbin | httpbun.erfi.io / httpbin.erfi.io |
| atuin | atuin.erfi.io |

These rely entirely on their own application-level authentication. The Authelia
`access_control` rules only define `two_factor` for servarr, change, waf, and cdn.
Authelia will not protect the others because `forward_auth` is never invoked.

Additionally:
- `servarr.erfi.io` has a `/graphql` route that bypasses forward-auth (relies on Unraid's
  own x-api-key auth).
- `cdn.erfi.io` has S3 API routes that bypass forward-auth (relies on bucket policies).

**Recommendation:** Add `import forward_auth` to services that don't have robust built-in
authentication, or document the intentional reliance on app-level auth.

---

### M-3. Hot-reload config inconsistency in policy engine

**Status: FIXED** (in caddy-policy-engine) — Split RLock sections merged into single acquisition.

**Component:** caddy-policy-engine
**Files:** `policyengine.go:479-484`, `policyengine.go:509-511`

`rules` and `wafConfig` are read under **separate** `RLock` acquisitions:

```go
pe.mu.RLock()
rules := pe.rules
globalCfg := pe.rlGlobalConfig
respHeaders := pe.respHeaders
pe.mu.RUnlock()

// ... CORS preflight, other work ...

pe.mu.RLock()
wafCfg := pe.wafConfig
pe.mu.RUnlock()
```

If a hot-reload occurs between these two reads, `rules` is from the old config while
`wafCfg` is from the new config. This can cause:
- Detect rules evaluated with wrong paranoia level (too high = false positives, too low =
  missed detections)
- Wrong anomaly thresholds applied to the old rule set

**Recommendation:** Read all per-request state under a single `RLock` acquisition.

---

### M-4. SSRF via DNS rebinding in managed list refresh

**Status: FIXED** — Custom http.Transport with DialContext re-validates resolved IPs at connection time.

**Component:** wafctl
**Files:** `managed_lists.go:391-427`, `managed_lists.go:460-479`

`validateRefreshURL()` resolves the hostname and checks for private IPs:

```go
ips, err := net.LookupHost(hostname)
// ... check each IP for IsLoopback, IsPrivate, etc.
```

Classic TOCTOU DNS rebinding: the DNS resolution happens BEFORE the actual HTTP request
in `client.Get(listURL)`. An attacker sets up DNS that initially resolves to a public IP
(passes validation), then resolves to `127.0.0.1` (for the actual fetch), allowing SSRF
to internal services.

**Recommendation:**
- Use a custom `http.Transport` with a `DialContext` that re-validates the resolved IP
  at connection time:

```go
transport := &http.Transport{
    DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
        host, port, _ := net.SplitHostPort(addr)
        ips, err := net.DefaultResolver.LookupHost(ctx, host)
        // ... validate IPs are not private/loopback ...
        return net.Dial(network, net.JoinHostPort(ips[0], port))
    },
}
```

---

### M-5. Response header value CRLF injection

**Status: FIXED** — Header values validated for CR/LF in HeaderSet, HeaderAdd, HeaderDefault.

**Component:** wafctl
**Files:** `exclusions_validate.go:284-317`

Header keys in `header_set`, `header_add`, `header_default` are validated for newlines, but
header **values** are NOT:

```go
for k := range e.HeaderSet {
    if strings.ContainsAny(k, "\n\r") {
        return fmt.Errorf("header_set key must not contain newlines")
    }
}
// Values are NOT checked
```

If the Caddy policy engine passes these values through to HTTP response headers, CRLF
injection enables response splitting.

**Mitigation:** Go's `net/http` strips `\r` and `\n` from header values at the transport
layer since Go 1.21, providing a safety net. But this is not defense-in-depth.

**Recommendation:** Validate header values for `\r\n` in `validateExclusion()`.

---

### M-6. Jail file TOCTOU race between Caddy and wafctl

**Status: OPEN** — Requires coordinated flock between ddos-mitigator and wafctl. Deferred.

**Component:** caddy-ddos-mitigator / wafctl
**Files:** `caddy-ddos-mitigator/mitigator.go:485-518`, `caddy-ddos-mitigator/util.go:131-171`

Both processes do read-merge-write on `jail.json` without file locking:

1. Plugin takes a snapshot
2. Plugin reads the jail file and merges new entries
3. Plugin writes the jail back to the file

Meanwhile wafctl does the same in reverse. If both read simultaneously, then both write,
one side's additions are lost. The `readJailFile` "don't overwrite existing" semantics
prevent data corruption but not data loss.

**Impact:** Manual jail/unjail operations via wafctl may be transiently lost and need to be
re-applied. The 5-second sync interval limits the window.

**Recommendation:** Use file-level advisory locking (`flock`) or a Unix socket IPC mechanism.

---

### M-7. nftables/XDP sync creates brief drop gap

**Status: OPEN** — Requires double-buffer strategy. Deferred.

**Component:** caddy-ddos-mitigator
**Files:** `nftables.go:200-246`, `xdp.go:122-181`

`SyncJail()` flushes all nftables set entries then re-adds them. During the flush window
(potentially milliseconds, longer under kernel load), jailed IPs can establish TCP
connections:

```go
// nftables SyncJail():
c.FlushSet(m.setV4)   // all entries removed
c.FlushSet(m.setV6)   // all entries removed
// ... re-add entries ...
c.Flush()              // commit
```

Same pattern in XDP: delete all LPM trie keys, then re-add. Additionally, XDP trie
iteration under concurrent modification may miss keys in some kernel versions, leaving
stale entries.

**Mitigation:** The L7 jail check still blocks at the HTTP level during the gap.

**Recommendation:** Use a double-buffer strategy: populate a new set, swap the rule to
reference it, then flush the old set. This provides atomic switchover with zero gap.

---

### M-8. /24 CIDR promotion collateral damage

**Status: OPEN** — Requires design work for fractional thresholds. Deferred.

**Component:** caddy-ddos-mitigator
**Files:** `cidr.go:46-92`

With default `cidr_threshold_v4 = 5`, jailing 5 IPs from the same /24 blocks all 256 IPs:

| Scenario | IPs in /24 | Jailed | Blocked | Collateral |
|----------|-----------|--------|---------|------------|
| CGNAT provider | 100,000 | 5 | 100,000 | 99,995 |
| Shared hosting | 500 | 5 | 500 | 495 |
| Corporate NAT | 10,000 | 5 | 10,000 | 9,995 |

The TTL with exponential backoff can extend to 24 hours, during which all IPs in the
prefix are blocked.

**Recommendation:**
- Increase default threshold or require a fraction (e.g., 10% of observed IPs, not just 5
  absolute) before promoting.
- Expose a mechanism to whitelist known CGNAT/shared ranges from CIDR aggregation
  (separate from the general whitelist).

---

### M-9. cosign sign failures silently swallowed in CI

**Status: OPEN** — CI workflow change. Deferred.

**Component:** caddy-compose
**Files:** `.github/workflows/build.yml:171`, `.github/workflows/build.yml:230`

```yaml
cosign sign ... || true
```

If cosign signing fails, the pipeline continues and pushes an unsigned image. This silently
degrades the signing guarantee. Unsigned images reach the public registry without any alert.

**Recommendation:** Remove `|| true`. If signing is best-effort, add an explicit notification
step on failure rather than silent swallowing.

---

### M-10. Trivy scans run AFTER image push in CI

**Status: OPEN** — CI workflow change. Deferred.

**Component:** caddy-compose
**Files:** `.github/workflows/build.yml:160-166`, `.github/workflows/build.yml:219-225`

The image is already pushed to the registry before the vulnerability scan runs. If Trivy
finds CRITICAL/HIGH vulnerabilities, the vulnerable image is already public.

**Recommendation:** Build with `load: true` first, scan locally, push only on scan success.

---

### M-11. Shared /data/waf volume is bidirectional read-write

**Status: OPEN** — Docker architecture change. Deferred.

**Component:** caddy-compose
**Files:** `compose.yaml` (volume mounts)

Both Caddy and wafctl have full read-write access to `/data/waf`. A compromised wafctl can:
1. Write a permissive `policy-rules.json` that disables all WAF rules.
2. Clear `jail.json` to unjail all blocked IPs.
3. Modify `cf_trusted_proxies.caddy` to add attacker IPs as trusted proxies, enabling XFF
   spoofing and IP attribution bypass.

A compromised Caddy can modify wafctl's config inputs.

**Recommendation:** Use file ownership and more granular mounts. wafctl should have write
access to `policy-rules.json` and read access to `jail.json`. Caddy should have the inverse.
Consider separate mount paths with appropriate permissions.

---

### M-12. IP intelligence: unsanitized IP in external API URLs

**Status: FIXED** — URL construction uses url.PathEscape/url.QueryEscape.

**Component:** wafctl
**Files:** `ip_intel_sources.go:240`, `ip_intel_sources.go:302-303`, `ip_intel_sources.go:355-356`

IPs are used in URL construction via string concatenation:

```go
url := "https://api.greynoise.io/v3/community/" + ip
url := "https://api.stopforumspam.org/api?json&ip=" + ip
url := "https://internetdb.shodan.io/" + ip
```

While `net.ParseIP()` validation exists in `ip_intel.go:50`, it only runs at the
`Lookup()` entry point. If any code path reaches these URL builders with unvalidated IPs
(e.g., IPs parsed from log files), an attacker could inject path segments or query
parameters.

**Recommendation:** Validate IP at each URL construction site, or use `url.PathEscape()`.

---

### M-13. Condition value validation only rejects newlines

**Status: FIXED** — Rejects all ASCII control characters (0x00-0x1F except tab).

**Component:** wafctl
**Files:** `exclusions_validate.go:139-142`

```go
if strings.ContainsAny(c.Value, "\n\r") {
    return fmt.Errorf("condition[%d]: value must not contain newlines", i)
}
```

Only CR/LF are rejected. Null bytes, tabs, and other control characters are accepted.
Depending on how the Caddy policy engine evaluates these values, null bytes could cause
truncation or unexpected matching behavior in regex operations.

**Recommendation:** Reject all ASCII control characters (0x00-0x1F except tab if needed).

---

### M-14. Regex DoS potential in query filters

**Status: OPEN** — RE2 + 1024-char limit provides baseline protection. Context timeout deferred.

**Component:** wafctl
**Files:** `query_helpers.go:260-271`

User-supplied regex patterns in query filters are compiled and run against potentially every
event in the store:

```go
case "regex":
    if len(value) > 1024 {
        f.op = "contains"  // Fallback for large patterns
    } else if re, err := regexp.Compile(value); err != nil {
        f.op = "contains"
    } else {
        f.re = re
    }
```

While Go's RE2 engine provides linear-time guarantees, a complex pattern against hundreds of
thousands of events can still consume significant CPU. There is no timeout on the overall
query execution.

**Mitigation:** The 1024-char limit and RE2 help. The fallback to `contains` on invalid regex
is good.

**Recommendation:** Add a context timeout on event queries.

---

## Low Severity Findings

### L-1. Double URL encoding bypass in policy engine transforms

**Status: OPEN** — CRS-consistent behavior. Documentation only.

**Component:** caddy-policy-engine
**Files:** `transforms.go:93-117`

`transformURLDecode` performs a single pass of percent-decoding. Double encoding
(`%2527` → `%27` → `'`) evades rules that only apply `urlDecode` once. This is CRS-consistent
behavior (CRS also does single-pass `t:urlDecode`).

**Recommendation:** Rule authors must explicitly chain transforms: `["urlDecode", "urlDecode"]`.
Document this in rule-authoring guidelines.

---

### L-2. `compiledRegex` nil check missing in body matcher

**Status: FIXED** (in caddy-body-matcher) — Match() now checks `m.compiledRegex != nil`.

**Component:** caddy-body-matcher
**Files:** `bodymatcher.go:263` vs `bodymatcher.go:299`, `bodymatcher.go:401`

`compiledJSONRegex` and `compiledFormRegex` have nil guards; `compiledRegex` does not:

```go
// Line 263 -- NO nil check, will panic:
case m.Regex != "":
    return m.compiledRegex.Match(buf)

// Line 299 -- has nil check:
if m.compiledJSONRegex != nil { ... }

// Line 401 -- has nil check:
if m.compiledFormRegex != nil && ... { ... }
```

Caddy's lifecycle guarantees `Provision()` runs before `Match()`, so this is unreachable in
normal operation. But it panics if used as a library outside Caddy.

**Recommendation:** Add nil guard for consistency:

```go
case m.Regex != "" && m.compiledRegex != nil:
```

---

### L-3. No MaxSize upper bound in body matcher

**Status: FIXED** (in caddy-body-matcher) — MaxSize capped at 256 MiB.

**Component:** caddy-body-matcher
**Files:** `bodymatcher.go:158-160`, `bodymatcher.go:671-674`

`Validate()` only rejects `MaxSize < 0`. A config of `max_size 100gb` is accepted, causing
`io.ReadAll` to attempt a ~100 GiB heap allocation, OOM-killing Caddy. Additionally,
`parseSize` at line 608 has a silent integer overflow on multiplication for very large values.

**Recommendation:** Add an upper bound in `Validate()`:

```go
const absoluteMaxSize = 256 * 1024 * 1024  // 256 MiB
if m.MaxSize > absoluteMaxSize {
    return fmt.Errorf("max_size %d exceeds limit of %d", m.MaxSize, absoluteMaxSize)
}
```

---

### L-4. Invalid whitelist CIDRs silently ignored in DDoS mitigator

**Status: FIXED** (in caddy-ddos-mitigator) — newWhitelist() returns error.

**Component:** caddy-ddos-mitigator
**Files:** `util.go:26-36`

```go
func newWhitelist(cidrs []string) whitelist {
    var wl whitelist
    for _, s := range cidrs {
        p, err := netip.ParsePrefix(s)
        if err != nil {
            continue  // silently dropped
        }
        wl = append(wl, p)
    }
    return wl
}
```

Misconfigured entries (trailing spaces like `"10.0.0.0/8 "`, missing prefix length like
`"10.0.0.0"`) are silently dropped. Operators believe ranges are whitelisted when they are
not — monitoring, health checks, or upstream proxies could be jailed.

**Recommendation:** Log a warning for each unparseable CIDR. Better yet, fail `Provision()`
if any whitelist entry is invalid.

---

### L-5. Non-atomic backup restore in wafctl

**Status: OPEN** — Deferred.

**Component:** wafctl
**Files:** `backup.go:72-198`

The restore operation updates stores sequentially (WAF config, CSP, security headers,
exclusions, lists, default rules). If any store fails, previously restored stores retain the
new data — no all-or-nothing transaction:

```go
resp["warning"] = "Partial restore: some stores were updated before the failure."
```

A crafted backup with a valid WAFConfig (lowering paranoia to 1) but intentionally invalid
exclusions could cause a partial restore that weakens the WAF while appearing to fail.

**Recommendation:** Validate all stores before applying any. Apply in reverse-priority order
(least security-critical first).

---

### L-6. Error template XSS via Host header

**Status: OPEN** — Requires template change. Deferred.

**Component:** caddy-compose
**Files:** `errors/error.html`

`{{.Req.Host}}` renders the HTTP Host header into HTML (lines 6, 77). If Caddy's error
template engine uses `text/template` (not `html/template`) and a catch-all host block exists,
a crafted `Host: <script>alert(1)</script>` header achieves reflected XSS.

**Mitigation:** Caddy typically validates Host headers against configured site addresses. Most
browsers restrict characters in the Host header. HTTP/2 further restricts this.

**Recommendation:** Use explicit escaping: `{{html .Req.Host}}` or replace with a static
string.

---

### L-7. Remember-me cookie valid for 1 month

**Status: OPEN** — Config change. Deferred.

**Component:** caddy-compose
**Files:** `authelia/configuration.yml:82`

```yaml
remember_me: "1M"
```

Exfiltrated session cookies (via XSS on a subdomain, malicious browser extension, etc.)
remain valid for 30 days.

**Recommendation:** Reduce to 7-14 days.

---

### L-8. GitHub Actions not consistently SHA-pinned

**Status: OPEN** — CI change. Deferred.

**Component:** caddy-compose
**Files:** `.github/workflows/build.yml`, `.github/workflows/release.yml`

`dorny/paths-filter@v4` (third-party individual-maintained action) and several first-party
actions (`actions/checkout@v6`, `docker/build-push-action@v6`, etc.) use tag references.
Tags can be moved to point to different commits — vulnerable to tag hijacking.

Notably, `aquasecurity/trivy-action`, `sigstore/cosign-installer`, and `anchore/sbom-action`
ARE properly SHA-pinned. The inconsistency suggests incremental adoption.

**Recommendation:** SHA-pin all actions. Use Dependabot or Renovate to keep pins updated.

---

### L-9. Rules with zero conditions match all requests

**Status: OPEN** — Validated at wafctl layer. Engine guard deferred.

**Component:** caddy-policy-engine
**Files:** `policyengine.go:1196-1199`

```go
if len(cr.conditions) == 0 {
    return true
}
```

A rule with zero conditions matches every request unconditionally. If a misconfigured or
maliciously injected rule reaches the rule set, it bypasses all evaluation. Validated at the
wafctl layer, but the engine itself does not guard against it.

**Recommendation:** Reject zero-condition rules at compile time in the policy engine.

---

### L-10. Limited HTML entity coverage in transforms

**Status: FIXED** (in caddy-policy-engine) — 16 security-critical entities added.

**Component:** caddy-policy-engine
**Files:** `transforms.go:227-242`

Only 13 named HTML entities are supported. Entities like `&lpar;` (→ `(`), `&rpar;` (→ `)`),
`&tab;`, `&NewLine;` are not decoded. An attacker using obscure named entities could bypass
detection patterns matching parentheses or other characters.

ModSecurity's `htmlEntityDecode` handles a larger set.

---

### L-11. `cmdLine` transform does not strip backtick characters

**Status: FIXED** (in caddy-policy-engine) — Backtick added to deletion set.

**Component:** caddy-policy-engine
**Files:** `transforms.go:557-595`

The `cmdLine` transform strips `\`, `^`, `"`, `'` but NOT backtick (`` ` ``). In bash,
backticks are used for command substitution (`` `whoami` ``). Consistent with ModSecurity's
`t:cmdLine` but still a detection gap.

---

### L-12. `jsDecode` does not handle ES6 `\u{HHHHH}` escapes

**Status: OPEN** — Deferred.

**Component:** caddy-policy-engine
**Files:** `transforms.go:414-429`

ES6 introduced `\u{1F600}` syntax for Unicode code points beyond the BMP. Only `\uHHHH`
(4-digit) escapes are handled. Payloads using the extended notation are not decoded.

---

### L-13. Profile TTL reset enables cyclic DDoS evasion

**Status: OPEN** — Inherent to behavioral profiling design.

**Component:** caddy-ddos-mitigator
**Files:** `profile.go:214-218`

`Profile()` returns nil if `time.Since(LastSeen) > ttl` (default 10 minutes). An attacker
can flood for 9 minutes, pause for 10 minutes (profile expires), then resume with a clean
slate indefinitely. Even if jailed, `Reset()` on unjail guarantees a clean slate.

---

### L-14. CMS decay is not atomic in DDoS mitigator

**Status: FIXED** (in caddy-ddos-mitigator) — CompareAndSwap retry loop.

**Component:** caddy-ddos-mitigator
**Files:** `cms.go:99-109`

`Decay()` uses `Load()` then `Store()` per counter without locking. A concurrent
`Increment()` between Load and Store would have its value lost. Currently the CMS is not
used for decisions (see L-15), so impact is nil. If the CMS is re-activated, this becomes a
data correctness issue.

---

### L-15. CMS computed but never used for decisions

**Status: OPEN** — Architectural decision pending.

**Component:** caddy-ddos-mitigator
**Files:** `mitigator.go:351-353`

The Count-Min Sketch `Increment()` and `stats.Observe()` are executed every request but the
CMS frequency estimate is never checked against a threshold. The behavioral `tracker.Score()`
is the sole decision input. This is dead code that wastes CPU under DDoS conditions.

**Recommendation:** Remove the CMS path, or gate it behind a config flag if planned for
future use.

---

### L-16. Jail file world-readable (0644 permissions)

**Status: FIXED** (in caddy-ddos-mitigator) — Permissions tightened to 0660.

**Component:** caddy-ddos-mitigator
**Files:** `util.go:125`

The jail file is written with `0644`. Any process on the host can read jailed IPs. More
importantly, if another process can write to the jail file path, it can inject or remove
entries.

**Recommendation:** Use `0600`.

---

### L-17. XDP program not cleaned up on unclean shutdown

**Status: OPEN** — Deferred.

**Component:** caddy-ddos-mitigator
**Files:** `xdp.go:104-113`

If Caddy crashes without calling `Cleanup()`, the XDP program remains attached to the NIC.
On restart, the new program should replace it, but if the previous attachment used a
different mode (SKB vs. native), replacement may fail. A stale program with an empty jail
map passes all traffic (fail-open).

**Recommendation:** On startup, explicitly check for and detach any pre-existing XDP program
on the interface before attaching the new one.

---

### L-18. Snapshot under CIDR lock creates latency on hot path

**Status: OPEN** — Deferred.

**Component:** caddy-ddos-mitigator
**Files:** `cidr.go:70`

`Check()` calls `jail.Snapshot()` while holding `c.mu.Lock()`. `Snapshot()` iterates all 64
shards, acquiring each shard's RLock. This holds the CIDR mutex for the entire snapshot
duration, blocking all `IsPromoted()` checks. Since `IsPromoted()` is on the hot path
(every request), this creates latency spikes during promotion checks.

**Recommendation:** Take the snapshot before acquiring the CIDR lock, or use RLock for the
read path of `IsPromoted`.

---

### L-19. `extractMultiField` excludes silently ignored on args/headers

**Status: OPEN** — Deferred.

**Component:** caddy-policy-engine
**Files:** `policyengine.go:1598-1739`

The `excludes` check (`isExcluded`) is only applied to `all_cookies`, `all_cookies_names`,
and selectively to `request_combined`. It is NOT applied to `all_args`, `all_args_values`,
`all_args_names`, `all_headers`, or `all_headers_names`. If a rule author sets excludes
expecting them to work on these fields, the exclusions are silently ignored.

---

### L-20. CORS regex patterns not auto-anchored in policy engine

**Status: FIXED** (in caddy-policy-engine) — Auto-anchored with ^ and $.

**Component:** caddy-policy-engine
**Files:** `responseheaders.go:365`, `responseheaders.go:549-550`

CORS origin matching uses regex without enforcing `$` anchoring. A pattern like
`.*\.example\.com` matches `evil.example.com.attacker.com`. The regex compilation does not
add anchors automatically.

**Recommendation:** Auto-append `$` if the pattern does not already end with one, or document
this requirement prominently.

---

### L-21. `body_form` parsed regardless of Content-Type

**Status: OPEN** — By design.

**Component:** caddy-policy-engine
**Files:** `policyengine.go:375-387`

`getForm()` calls `url.ParseQuery(string(pb.raw))` unconditionally on the raw body bytes
without checking Content-Type. For non-form bodies (JSON, XML), this produces spurious
key-value pairs from content that happens to contain `=` and `&`. This can cause unexpected
detect rule firing (false positives, not bypasses).

---

### L-22. No rate limit zone counter cardinality limit

**Status: OPEN** — Deferred.

**Component:** caddy-policy-engine
**Files:** `ratelimit.go:108-114`

Each unique rate limit key creates a new `counter` struct. An attacker sending requests with
unique keys (e.g., unique cookie values) creates unbounded entries. The sweep goroutine only
cleans entries after 2 windows expire. For a 1-hour window with high-cardinality keys, memory
pressure is possible.

**Recommendation:** Add a maximum entries-per-zone limit with eviction.

---

### L-23. UI server path traversal check is simplistic

**Status: FIXED** — filepath.Clean() + prefix verification replaces simple string check.

**Component:** wafctl
**Files:** `ui_server.go:21-51`

```go
p := strings.TrimPrefix(r.URL.Path, "/")
if strings.Contains(p, "..") {
    http.Error(w, "invalid path", http.StatusBadRequest)
    return
}
```

Only checks for literal `..` in the URL-decoded path. Go's `http.ServeFile` has its own
protections, but using `filepath.Clean()` + prefix verification would be more robust as
defense-in-depth.

---

### L-24. UUID fallback to UnixNano

**Status: OPEN** — Extremely unlikely scenario.

**Component:** wafctl
**Files:** `util.go:94-103`

If `crypto/rand` fails (extremely unlikely), the fallback produces a predictable
timestamp-based ID. Could lead to ID collision or predictability.

---

### L-25. `fetchSpikeReport` missing `encodeURIComponent`

**Status: OPEN** — Frontend change. Deferred.

**Component:** waf-dashboard
**Files:** `src/lib/api/dos.ts:86`

```typescript
`${API_BASE}/dos/reports/${id}`
```

Inconsistent with the rest of the API layer which uses `encodeURIComponent()` for all
interpolated path segments.

---

### L-26. Unsanitized event ID in CSS selector

**Status: OPEN** — Frontend change. Deferred.

**Component:** waf-dashboard
**Files:** `src/components/EventsTable.tsx:219`

```typescript
document.querySelector(`[data-event-id="${expandId}"]`)
```

If an event ID contained CSS selector metacharacters (e.g., `"]`), querySelector would fail
or match unexpectedly. Event IDs are server-generated UUIDs so risk is minimal.

**Recommendation:** Use `CSS.escape(expandId)`.

---

### L-27. Caddy main Dockerfile runs as root

**Status: OPEN** — Required for NET_ADMIN.

**Component:** caddy-compose
**Files:** `Dockerfile` (no USER directive in final stage)

The main Caddy Dockerfile does not set a `USER` directive. The container runs as root. This
is standard for Caddy containers needing to bind ports 80/443 and manage nftables, but it
means a container escape inherits root privileges.

Note: The wafctl Dockerfile correctly uses `USER 65534:65534` (nobody).

---

### L-28. L4 handler lacks PROXY protocol awareness

**Status: OPEN** — Feature request.

**Component:** caddy-ddos-mitigator
**Files:** `mitigator_l4.go:84`, `mitigator_l4.go:136-155`

The L4 handler reads `cx.Conn.RemoteAddr()` directly. In a `LB → PROXY protocol → Caddy-L4`
deployment, all traffic appears from the LB IP. If the LB is not whitelisted, all clients
share one IP for jail purposes. If it IS whitelisted, all clients bypass jail.

---

### L-29. `RawDirectives` CSP field allows directive injection

**Status: FIXED** (in caddy-policy-engine) — RawDirectives validated at compile time.

**Component:** caddy-policy-engine
**Files:** `responseheaders.go:189-191`

```go
if p.RawDirectives != "" {
    parts = append(parts, strings.TrimSpace(p.RawDirectives))
}
```

A malicious admin could inject directive-separator semicolons to override earlier directives
(e.g., `; default-src *`). This is by design (escape hatch), but there is no warning.

---

### L-30. TagsByName returns shared slice references

**Status: FIXED** — TagsByName now returns deep-copied tag slices.

**Component:** wafctl
**Files:** `exclusions.go:115-125`

The returned tag slices are references into the store's data. If any caller inadvertently
appends to a tag slice, it corrupts the store. The `List()` method correctly deep-copies,
but `TagsByName()` does not.

---

## Positive Security Controls

These are **well-implemented** security measures across the ecosystem:

**Container Hardening:**
- All containers: `cap_drop: ALL`, `read_only: true`, `no-new-privileges: true`
- Authelia: non-root (UID 1000), zero capabilities
- wafctl: non-root (UID 65534/nobody), zero capabilities
- Resource limits on all containers (CPU/memory)
- tmpfs mounts for ephemeral data

**Network Architecture:**
- Authelia (172.19.99.0/24) and wafctl (172.19.98.0/24) on separate bridges, isolated from
  each other
- `strict_sni_host on` prevents SNI routing bypass
- Encrypted Client Hello (ECH) for SNI privacy
- `trusted_proxies_strict` with Cloudflare IPs, generated at build time and refreshed at
  runtime
- `X-Forwarded-For` set to `{client_ip}` (single-value replacement, not appended)

**Authentication:**
- Argon2id hashing (3 iterations, 64MB memory, parallelism 4)
- zxcvbn password policy at maximum strength (score 4)
- TOTP + WebAuthn/FIDO2 for 2FA
- Default deny policy in Authelia
- Secrets loaded from files (not environment variables)

**Frontend Security:**
- Zero `dangerouslySetInnerHTML` usage anywhere
- Consistent `encodeURIComponent()` on URL interpolation (one exception: L-25)
- React JSX auto-escaping for all user-supplied data
- Static MPA (no SSR) eliminates server-side template injection
- URL params read in `useEffect` (client-only), cleaned up after reading

**Request Handling:**
- 5MB `MaxBytesReader` on all JSON endpoints via `decodeJSON()`
- Go RE2 regex engine (no catastrophic backtracking)
- Atomic file writes (temp → fsync → rename) in `atomicWriteFile()`
- SOPS-encrypted `.env` with pre-commit hook blocking unencrypted secrets

**Supply Chain:**
- Cosign keyless signing via Sigstore
- Trivy vulnerability scanning
- SBOM generation (SPDX + CycloneDX)
- Multi-stage Docker builds (build tools not in final images)

**WAF Engine:**
- Priority-based rule evaluation with deterministic tie-breaking
- Hot-reload via mtime polling (no restart required)
- 16-shard concurrent rate limit counters
- Aho-Corasick multi-pattern matching for string operators
- CRS-compatible transform functions

---

## Top Recommendations (Prioritized by Risk × Effort)

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| 1 | **C-1:** Add bearer token auth to wafctl API | Low | Eliminates entire class of unauthenticated management attacks |
| 2 | **C-2:** Fix empty rate limit key → fallback to client_ip | Trivial | Closes critical bypass on all header/cookie-keyed rules |
| 3 | **H-5:** Call `addr.Unmap()` in L7 clientAddr() | Trivial | Fixes real bug causing whitelist bypass |
| 4 | **H-1:** Hold locks through save in JailStore/DosConfigStore | Low | Prevents data loss from concurrent operations |
| 5 | **H-6:** Return deep copy or compute score under lock | Low | Prevents crash under load from concurrent map access |
| 6 | **H-3:** Add `net.ParseIP()` validation to jail add | Trivial | Prevents shared file corruption |
| 7 | **H-2:** Add `validateDosConfig()` | Low | Prevents disabling DDoS mitigation via API |
| 8 | **M-1:** Bind :2020 to 172.19.98.1 | Trivial | Removes internet-facing admin API surface |
| 9 | **M-3:** Read all per-request state under single RLock | Low | Prevents mismatched rules/config after hot-reload |
| 10 | **C-3:** Sliding window path diversity scoring | Medium | Defeats trivial warm-up evasion strategy |
