# Challenge Action — Implementation Scope

Proof-of-work challenge rule type for the policy engine, inspired by
[Anubis](https://github.com/TecharoHQ/anubis). When a `challenge` rule matches,
the plugin serves an interstitial page requiring SHA-256 proof-of-work before
proxying to upstream. Legitimate browsers solve in <1s; headless scrapers without
JS execution are permanently blocked.

**Reference implementation:** Anubis v1.25.0 (cloned to `/home/erfi/anubis-ref/`).

---

## 1. caddy-policy-engine (bulk of the work)

All file:line references are against the current HEAD of `/home/erfi/ergo/caddy-policy-engine/`.

### 1a. New files

| File | Purpose | Est. Lines |
|---|---|---|
| `challenge.go` | HMAC signing, cookie validation, PoW verification, interstitial serving, verification endpoint handler | ~400 |
| `challenge.html` | Embedded interstitial template (inline CSS, noscript fallback) | ~80 |
| `challenge.js` | Client-side WebCrypto SHA-256 PoW solver (single-threaded, no build step) | ~100 |
| `challenge_test.go` | Unit tests: HMAC round-trip, cookie parse/validate, PoW verify, difficulty check, expiry | ~300 |

### 1b. Modifications to `policyengine.go`

#### Imports (line 13-35)

Add:
```go
"crypto/hmac"
"crypto/rand"
"crypto/sha256"
"embed"
"encoding/base64"
"encoding/hex"
```

No new external dependencies — all stdlib.

#### PolicyEngine struct (line 67-114)

Add fields for challenge state:
```go
// Challenge configuration (provisioned from Caddyfile or env)
challengeHMACKey []byte // 32-byte HMAC-SHA256 key for cookie signing
challengeEnabled bool   // true if any challenge rules exist
```

#### PolicyRulesFile struct (line 117-125)

Add global challenge config:
```go
ChallengeConfig *ChallengeGlobalConfig `json:"challenge_config,omitempty"`
```

Where:
```go
type ChallengeGlobalConfig struct {
    HMACKey string `json:"hmac_key,omitempty"` // hex-encoded 32-byte key (injected by wafctl at deploy)
}
```

#### PolicyRule struct (line 207-233)

Add challenge field:
```go
Challenge *ChallengeConfig `json:"challenge,omitempty"`
```

Where:
```go
type ChallengeConfig struct {
    Difficulty int    `json:"difficulty"`    // leading hex zeros in SHA-256 (1-16, default 4)
    Algorithm  string `json:"algorithm"`     // "fast" (default) or "slow"
    TTLSeconds int    `json:"ttl_seconds"`   // cookie lifetime (default 604800 = 7d)
    BindIP     bool   `json:"bind_ip"`       // bind cookie to client IP (default true)
}
```

#### compiledRule struct (line 268-277)

Add:
```go
challengeConfig *compiledChallengeConfig // non-nil for challenge rules
```

Where:
```go
type compiledChallengeConfig struct {
    difficulty int
    algorithm  string
    ttl        time.Duration
    bindIP     bool
    cookieName string // precomputed: __policy_challenge_{hash(service)}
}
```

#### Provision (line 436-496)

After rule loading, scan for challenge rules and provision HMAC key:
```go
// After pe.rules is populated:
pe.challengeEnabled = false
for _, cr := range pe.rules {
    if cr.rule.Type == "challenge" && cr.rule.Enabled {
        pe.challengeEnabled = true
        break
    }
}
if pe.challengeEnabled {
    pe.provisionChallengeKey() // reads from ChallengeGlobalConfig or generates
}
```

Key provisioning logic (in `challenge.go`):
1. If `ChallengeGlobalConfig.HMACKey` is set in policy-rules.json, hex-decode it.
2. Else if `CHALLENGE_HMAC_KEY` env var is set, hex-decode it.
3. Else generate 32 random bytes, persist to `{data_dir}/challenge-hmac.key`, log warning.

#### ServeHTTP — reserved path handler (line 522, after RLock but before CORS)

Insert at **line 530** (after `pe.mu.RUnlock()`, before CORS preflight):
```go
// ── Challenge verification endpoint ─────────────────────────
// Handle POST to /.well-known/policy-challenge/verify before any
// rule evaluation. This path is implicitly allowed — it must never
// be challenged, blocked, or rate-limited.
if pe.challengeEnabled && r.URL.Path == "/.well-known/policy-challenge/verify" && r.Method == http.MethodPost {
    return pe.handleChallengeVerify(w, r)
}
```

#### ServeHTTP — cookie check fast path (line 537, before rule loop)

Insert after the CORS preflight block (line 536), before the 6-pass comment (line 538):
```go
// ── Challenge cookie check ──────────────────────────────────
// If any challenge rules exist, check for a valid challenge cookie.
// Valid cookie → set context var, skip challenge rules in main loop.
var challengePassed bool
if pe.challengeEnabled {
    challengePassed = pe.validateChallengeCookie(r)
}
```

#### ServeHTTP — pass comment update (line 538-553)

Update the evaluation order comment to document 7 passes:
```
// Pass 1 — Allow     (50-99):   full bypass, terminates immediately.
// Pass 2 — Block     (100-149): deny list, terminates with 403. Skippable.
// Pass 3 — Challenge (150-199): PoW interstitial. Skippable. Cookie bypass.
// Pass 4 — Skip      (200-299): selective bypass, accumulates skip flags.
// Pass 5 — Rate limit(300-399): sliding window counters. Skippable.
// Pass 6 — Detect    (400-499): CRS anomaly scoring. Skippable.
// Pass 7 — Resp Hdr  (500-599): response header manipulation.
```

#### ServeHTTP — skip flag variables (line 560-565)

Add:
```go
var skipChallenge bool
```

#### ServeHTTP — service matching (line 578)

Add `"challenge"` to the service-scoped types:
```go
if (cr.rule.Type == "rate_limit" || cr.rule.Type == "detect" || cr.rule.Type == "skip" || cr.rule.Type == "challenge") && !matchService(cr.rule.Service, r) {
```

#### ServeHTTP — allow guard (line 585)

Challenge rules should also be skipped after allow match (already covered by `!= "rate_limit"`).
No change needed — challenge is not rate_limit, so it's already skipped.

#### ServeHTTP — skip flag checks (line 591-605)

Add challenge skip check after the block check (after line 595):
```go
if cr.rule.Type == "challenge" {
    if skipAllRemaining || skipChallenge || skipRuleIDs[cr.rule.ID] {
        continue
    }
}
```

#### ServeHTTP — switch case (line 652, between block and skip)

Insert `case "challenge":` at **line 696** (after `return caddyhttp.Error(http.StatusForbidden, nil)` from block, before `case "skip":`):

```go
case "challenge":
    // Pass 3: proof-of-work challenge — serve interstitial or validate cookie.
    if challengePassed {
        // Valid cookie — log bypass, continue evaluation.
        caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_bypassed")
        caddyhttp.SetVar(r.Context(), "policy_engine.rule_id", cr.rule.ID)
        caddyhttp.SetVar(r.Context(), "policy_engine.rule_name", cr.rule.Name)
        pe.logger.Debug("challenge bypassed (valid cookie)",
            zap.String("rule_id", cr.rule.ID),
            zap.String("rule_name", cr.rule.Name),
            zap.String("client_ip", clientIP(r)),
            zap.String("uri", r.RequestURI))
        continue
    }
    // No valid cookie — serve challenge interstitial (terminates).
    caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_issued")
    caddyhttp.SetVar(r.Context(), "policy_engine.rule_id", cr.rule.ID)
    caddyhttp.SetVar(r.Context(), "policy_engine.rule_name", cr.rule.Name)
    if len(cr.rule.Tags) > 0 {
        caddyhttp.SetVar(r.Context(), "policy_engine.tags", strings.Join(cr.rule.Tags, ","))
    }
    pe.logger.Info("challenge issued",
        zap.String("rule_id", cr.rule.ID),
        zap.String("rule_name", cr.rule.Name),
        zap.Int("difficulty", cr.challengeConfig.difficulty),
        zap.String("algorithm", cr.challengeConfig.algorithm),
        zap.String("client_ip", clientIP(r)),
        zap.String("uri", r.RequestURI))
    return pe.serveChallengeInterstitial(w, r, cr.challengeConfig)
```

#### validRuleTypes (line 2966-2974)

Add:
```go
"challenge": true,
```

#### validSkipPhases (line 2977-2981)

Add:
```go
"challenge": true,
```

#### compileRule (line 2992-3075)

**Zero-condition guard (line 3008):** Add `"challenge"` alongside `"allow", "block", "honeypot", "skip"`:
```go
case "allow", "block", "honeypot", "skip", "challenge":
```

**After the rate_limit compilation block (line 3035):** Add challenge compilation:
```go
// Compile challenge config.
if rule.Type == "challenge" {
    if rule.Challenge == nil {
        return cr, fmt.Errorf("challenge rules must have a challenge config")
    }
    diff := rule.Challenge.Difficulty
    if diff <= 0 { diff = 4 }
    if diff > 16 { diff = 16 }
    algo := rule.Challenge.Algorithm
    if algo == "" { algo = "fast" }
    ttl := time.Duration(rule.Challenge.TTLSeconds) * time.Second
    if ttl <= 0 { ttl = 7 * 24 * time.Hour }
    svc := rule.Service
    if svc == "" { svc = "_global" }
    cr.challengeConfig = &compiledChallengeConfig{
        difficulty: diff,
        algorithm:  algo,
        ttl:        ttl,
        bindIP:     rule.Challenge.BindIP,
        cookieName: challengeCookieName(svc),
    }
}
```

**Skip targets (line 3066):** Already handled by `validSkipPhases` addition above.

#### Caddyfile parsing (line 3754-3807)

Add new directive case before the `default:` fallback:
```go
case "challenge_hmac_key":
    if !d.NextArg() {
        return d.ArgErr()
    }
    key, err := hex.DecodeString(d.Val())
    if err != nil {
        return d.Errf("invalid challenge_hmac_key: %v", err)
    }
    pe.challengeHMACKey = key
```

### 1c. challenge.go — core implementation

Key functions:

```go
// challengeCookieName computes the per-service cookie name.
func challengeCookieName(service string) string {
    h := sha256.Sum256([]byte(service))
    return "__pc_" + hex.EncodeToString(h[:4]) // __pc_a1b2c3d4
}

// provisionChallengeKey loads or generates the HMAC key.
func (pe *PolicyEngine) provisionChallengeKey() { ... }

// validateChallengeCookie checks for a valid challenge cookie on the request.
// Returns true if the client has already solved a challenge for this service.
func (pe *PolicyEngine) validateChallengeCookie(r *http.Request) bool {
    // 1. Find cookie by name prefix __pc_
    // 2. Split token: payload.signature
    // 3. Verify HMAC-SHA256(key, payload) == signature
    // 4. Decode payload JSON: { sub, aud, exp, dif }
    // 5. Check exp > now
    // 6. If bind_ip: check sub == clientIP(r)
    // 7. Return true
}

// serveChallengeInterstitial writes the PoW interstitial page.
func (pe *PolicyEngine) serveChallengeInterstitial(w http.ResponseWriter, r *http.Request, cfg *compiledChallengeConfig) error {
    // 1. Generate 32-byte random nonce → hex
    // 2. Build challenge JSON: { nonce, difficulty, algorithm, timestamp, original_url }
    // 3. HMAC the challenge payload
    // 4. Inject into HTML template (data attributes or script tag)
    // 5. Set Cache-Control: no-store, no-cache, must-revalidate
    // 6. w.Header().Set("Content-Type", "text/html; charset=utf-8")
    // 7. w.WriteHeader(200) — return 200 like Anubis (fools status-checking bots)
    // 8. w.Write(page)
    // 9. return nil
}

// handleChallengeVerify handles POST /.well-known/policy-challenge/verify
func (pe *PolicyEngine) handleChallengeVerify(w http.ResponseWriter, r *http.Request) error {
    // 1. Parse form: nonce, response (hash), counter, payload_hmac, original_url
    // 2. Verify payload HMAC (prevents tampering)
    // 3. Check timestamp freshness (< 5 minutes)
    // 4. Recompute: SHA256(randomData + counter)
    // 5. Verify leading hex zeros >= difficulty
    // 6. Constant-time compare recomputed hash vs submitted hash
    // 7. Build cookie token: { sub: clientIP, aud: host, exp: now+ttl, dif: difficulty }
    // 8. Sign with HMAC-SHA256
    // 9. Set-Cookie with HttpOnly, Secure, SameSite=Lax, Max-Age=ttl
    // 10. 302 redirect to original URL
}
```

### 1d. PoW algorithm (matching Anubis exactly)

**Hash:** `SHA256(randomData + nonce)` where randomData is 64 bytes hex-encoded (128 chars) and nonce is an integer string-appended.

**Difficulty:** Number of leading zero **hex characters** in the hash output. Difficulty N means `strings.HasPrefix(hash, strings.Repeat("0", N))`. Each hex digit = 4 bits.

**Server verification** (from Anubis `proofofwork.go:69-79`):
```go
calcString := fmt.Sprintf("%s%d", challenge, nonce)
calculated := sha256hex(calcString)
if subtle.ConstantTimeCompare([]byte(response), []byte(calculated)) != 1 {
    // FAIL
}
if !strings.HasPrefix(response, strings.Repeat("0", difficulty)) {
    // FAIL
}
```

**Client-side** (from Anubis `sha256-webcrypto.ts:15-72`): WebCrypto `crypto.subtle.digest("SHA-256", data)` in a tight loop, checking leading zero bytes. Multi-threaded via Web Workers with interleaved nonce (thread N starts at nonce=N, increments by thread_count).

**Our simplification vs Anubis:**
- Single-threaded first (no Web Workers). Multi-thread is a follow-up.
- No templ dependency — plain HTML with `<script type="application/json">` for challenge data (same pattern Anubis uses: `web/index.templ:36-46`).
- No localization initially.
- No separate "slow" algorithm initially — just "fast". Add "slow" (deliberate delay loop per iteration) as a follow-up.
- No server-side challenge store (Anubis uses bbolt/Valkey for double-spend prevention). Instead, HMAC the challenge payload — the server doesn't store anything. Replay prevented by 5-minute timestamp window.

### 1e. Cookie format (simpler than Anubis JWT)

Anubis uses full JWT (Ed25519 or HS512, depends on `github.com/golang-jwt/jwt/v5`). We use a minimal HMAC-SHA256 signed token to avoid adding jwt as a dependency:

```
token = base64url(payload) + "." + base64url(hmac-sha256(key, base64url(payload)))

payload = {
    "sub": "192.168.1.1",     // client IP (if bind_ip)
    "aud": "httpbun.erfi.io", // service hostname
    "exp": 1742558400,        // unix timestamp
    "dif": 4                  // difficulty solved at
}
```

Verification: decode payload, verify HMAC, check exp > now, optionally check sub == client IP.

---

## 2. wafctl (caddy-compose)

### 2a. models_exclusions.go

**`validExclusionTypes` map (line 157-164):** Add `"challenge": true`.

**`RuleExclusion` struct (line 28-65):** Add after response_header fields:
```go
// ─── challenge-only ─────────────────────────────────────────
ChallengeDifficulty int    `json:"challenge_difficulty,omitempty"` // leading hex zeros (1-16, default 4)
ChallengeAlgorithm  string `json:"challenge_algorithm,omitempty"` // "fast" (default) or "slow"
ChallengeTTL        string `json:"challenge_ttl,omitempty"`       // cookie lifetime: "7d", "24h", "1h"
ChallengeBindIP     *bool  `json:"challenge_bind_ip,omitempty"`   // bind cookie to client IP (default true)
```

### 2b. exclusions_validate.go

**`switch e.Type` block (line 210-332):** Add before closing `}`:
```go
case "challenge":
    if len(e.Conditions) == 0 {
        return fmt.Errorf("challenge requires at least one condition")
    }
    if e.ChallengeDifficulty < 0 || e.ChallengeDifficulty > 16 {
        return fmt.Errorf("challenge_difficulty must be 0-16 (0 = default 4)")
    }
    if e.ChallengeAlgorithm != "" && e.ChallengeAlgorithm != "fast" && e.ChallengeAlgorithm != "slow" {
        return fmt.Errorf("challenge_algorithm must be 'fast' or 'slow'")
    }
    if e.ChallengeTTL != "" {
        if _, err := parseDurationExtended(e.ChallengeTTL); err != nil {
            return fmt.Errorf("invalid challenge_ttl: %v", err)
        }
    }
```

**`validSkipPhases` (line 338-341):** Add `"challenge": true`.

### 2c. policy_generator.go

**`policyEngineTypes` (line 124-131):** Add `"challenge": true`.

**`policyTypePriority` (line 142-149):** Add `"challenge": 150`.

**Update comment (line 133-141):** Document 7-pass order.

**`PolicyRule` struct (line 33-59):** Add:
```go
Challenge *PolicyChallengeConfig `json:"challenge,omitempty"`
```

**New struct:**
```go
type PolicyChallengeConfig struct {
    Difficulty int    `json:"difficulty"`
    Algorithm  string `json:"algorithm"`
    TTLSeconds int    `json:"ttl_seconds"`
    BindIP     bool   `json:"bind_ip"`
}
```

**`GeneratePolicyRulesWithRL` (line 174, inside the loop after line 264):** Add:
```go
// Challenge rules carry challenge config.
if e.Type == "challenge" {
    diff := e.ChallengeDifficulty
    if diff == 0 { diff = 4 }
    algo := e.ChallengeAlgorithm
    if algo == "" { algo = "fast" }
    ttlSec := 7 * 24 * 3600 // default 7 days
    if e.ChallengeTTL != "" {
        if d, err := parseDurationExtended(e.ChallengeTTL); err == nil {
            ttlSec = int(d.Seconds())
        }
    }
    bindIP := true
    if e.ChallengeBindIP != nil {
        bindIP = *e.ChallengeBindIP
    }
    pr.Challenge = &PolicyChallengeConfig{
        Difficulty: diff,
        Algorithm:  algo,
        TTLSeconds: ttlSec,
        BindIP:     bindIP,
    }
}
```

### 2d. deploy.go

**`DeployConfig` struct (line 20-36):** Add:
```go
ChallengeHMACKey string // hex-encoded 32-byte key (from env or auto-generated)
```

**`generatePolicyData` (line 62-83):** The HMAC key flows through the `PolicyRulesFile.ChallengeConfig` field. Add after `wafCfg` construction:
```go
// Include challenge HMAC key when challenge rules exist.
var challengeCfg *ChallengeGlobalConfig
hasChallengeRules := false
for _, e := range allExclusions {
    if e.Type == "challenge" {
        hasChallengeRules = true
        break
    }
}
if hasChallengeRules && deployCfg.ChallengeHMACKey != "" {
    challengeCfg = &ChallengeGlobalConfig{HMACKey: deployCfg.ChallengeHMACKey}
}
```

Then pass `challengeCfg` into `GeneratePolicyRulesWithRL` (requires adding a parameter or setting it on the returned `PolicyRulesFile`).

**`main.go`:** Read `CHALLENGE_HMAC_KEY` from env, or auto-generate and persist:
```go
challengeKey := envOr("CHALLENGE_HMAC_KEY", "")
if challengeKey == "" {
    challengeKey = loadOrGenerateChallengeKey(dataDir)
}
deployCfg.ChallengeHMACKey = challengeKey
```

---

## 3. waf-dashboard

### 3a. src/lib/api/exclusions.ts

**`ExclusionType` (line 30):** Add `"challenge"`:
```typescript
export type ExclusionType = "allow" | "block" | "challenge" | "skip" | "detect" | "rate_limit" | "response_header";
```

**`Exclusion` interface (line 97-124):** Add:
```typescript
// challenge fields
challenge_difficulty?: number;
challenge_algorithm?: 'fast' | 'slow';
challenge_ttl?: string;
challenge_bind_ip?: boolean;
```

**`ExclusionCreateData` (line 126-149):** Same 4 fields.

**`typeToGo` / `typeFromGo` (line 172-183):** Add `challenge: "challenge"`.

### 3b. src/components/policy/constants.ts

**`ALL_EXCLUSION_TYPES` (line 16-22):** Add:
```typescript
{ value: "challenge", label: "Challenge", description: "Proof-of-work verification for browser clients", group: "advanced" },
```

**`AdvancedFormState` (line 660-676):** Add:
```typescript
challenge_difficulty: number;
challenge_algorithm: string;
challenge_ttl: string;
challenge_bind_ip: boolean;
```

**`emptyAdvancedForm` (line 678-694):** Add defaults:
```typescript
challenge_difficulty: 4,
challenge_algorithm: "fast",
challenge_ttl: "7d",
challenge_bind_ip: true,
```

### 3c. src/components/policy/PolicyForms.tsx

Add a "Challenge Settings" section when `type === "challenge"`:
- Difficulty slider (1-16, labels: "Easy ~0.5s" / "Medium ~5s" / "Hard ~30s" / "Extreme")
- Algorithm select: "Fast (WebCrypto)" / "Slow (CPU-intensive)"
- TTL: reuse existing `duration-input` component
- Bind IP toggle

### 3d. Event badges

In `src/components/events/helpers.tsx` or `EventTypeBadge.tsx`, add badge variants:
```typescript
case "challenge_issued":   return { label: "Challenge", color: "warning" };
case "challenge_passed":   return { label: "Challenge OK", color: "success" };
case "challenge_failed":   return { label: "Challenge Fail", color: "destructive" };
case "challenge_bypassed": return { label: "Challenge Skip", color: "secondary" };
```

---

## 4. E2E tests

New file: `test/e2e/30_challenge_test.go`

| Test | Description |
|---|---|
| `TestChallengeRuleCRUD` | Create/read/update/delete a challenge rule via `/api/rules` |
| `TestChallengeValidation` | Validation: difficulty bounds, algorithm values, TTL parse, conditions required |
| `TestChallengePriorityBand` | Deploy and verify challenge rules sort into 150-199 band |
| `TestChallengeInPolicyRulesJSON` | Deploy and verify `challenge` config appears in policy-rules.json |
| `TestChallengeSkipInteraction` | Skip rule with `phases: ["challenge"]` suppresses challenge |
| `TestChallengeAllowInteraction` | Allow rule prevents challenge from firing |

Plugin-level e2e tests (require running Caddy with the plugin):
| Test | Description |
|---|---|
| `TestChallengeInterstitialServed` | Request matching challenge rule gets 200 + HTML with challenge data |
| `TestChallengeVerifyEndpoint` | POST to `/.well-known/policy-challenge/verify` with valid PoW → cookie + 302 |
| `TestChallengeCookieBypass` | Request with valid cookie skips challenge, reaches upstream |
| `TestChallengeExpiredCookie` | Expired cookie → challenge re-issued |
| `TestChallengeIPBinding` | Cookie from different IP is rejected |
| `TestChallengeInvalidPoW` | Wrong nonce/hash → 403 |

---

## 5. Work breakdown

| # | Task | Where | Est. | Depends |
|---|---|---|---|---|
| 1 | wafctl model + validation + generator | caddy-compose/wafctl | 1.5d | — |
| 2 | wafctl deploy pipeline (HMAC key) | caddy-compose/wafctl | 0.5d | 1 |
| 3 | Plugin structs + compileRule + validTypes | caddy-policy-engine | 0.5d | 1 |
| 4 | Plugin ServeHTTP integration (switch case, cookie check, skip flags) | caddy-policy-engine | 1d | 3 |
| 5 | Plugin challenge.go (HMAC, cookie, PoW verify, interstitial) | caddy-policy-engine | 2.5d | 3,4 |
| 6 | Client JS (SHA-256 WebCrypto PoW solver) | caddy-policy-engine | 1d | 5 |
| 7 | HTML interstitial template | caddy-policy-engine | 0.5d | 5,6 |
| 8 | Dashboard: types, forms, badges | caddy-compose/waf-dashboard | 1.5d | 1 |
| 9 | E2E tests (wafctl + plugin) | caddy-compose/test/e2e | 1.5d | 1-7 |

**Critical path:** 1 → 3 → 4 → 5 → 6 → 7 → 9 = **~7.5 days**
**Parallel:** Task 2 and 8 can run alongside 3-7.
**Total calendar time:** ~10.5 days with parallelism.

---

## 6. Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| PoW algorithm | SHA-256 hashcash (Anubis-compatible) | Proven, WebCrypto API support, no WASM needed |
| Difficulty unit | Leading hex zeros (not bits) | Matches Anubis exactly. Difficulty 4 = 16 bits = ~0.5s |
| Cookie format | HMAC-SHA256 signed JSON (not JWT) | No new dependency. JWT would require `golang-jwt/jwt` |
| Challenge state | Stateless (HMAC payload) | No server-side store, no double-spend tracking. Replay prevented by 5-min timestamp. Simpler than Anubis's bbolt/Valkey store. |
| Client JS | Single-threaded first | Web Workers are a follow-up. Single-thread is simpler and still fast enough at difficulty 4. |
| Interstitial embedding | `//go:embed` | Self-contained in plugin binary. No external fetches. |
| HTTP status for challenge | 200 | Matches Anubis: fools status-checking bots. Configurable later. |
| Reserved path | `/.well-known/policy-challenge/verify` | RFC 8615 compliant. Auto-allowed at priority 0. |
| IP binding | Default on, configurable off | Prevents cookie sharing. Disable for mobile-heavy services. |
| HMAC key management | wafctl generates, injects via policy-rules.json | Plugin reads from file. Rotation = new deploy + Caddy re-reads file. |
