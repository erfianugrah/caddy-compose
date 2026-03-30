# Challenge Platform Hardening Plan

Comparative analysis against Cloudflare Turnstile (decrypted by Buchodi, March 2026).
Goal: close gaps and extend advantages of the self-hosted challenge system.

---

## Current State

### What we have that Turnstile doesn't

| Capability | Detail |
|---|---|
| Raw TLS access (JA4) | `ja4_listener.go` parses ClientHello before TLS termination. Cookie binding to JA4 fingerprint prevents replay from different TLS stack. Impossible behind a CDN. |
| Adaptive difficulty | `preSignalScore()` runs L1/L2/partial-L5 at serve time, maps to `[min_difficulty, max_difficulty]`. Suspicious TLS/headers get harder PoW. Turnstile uses uniform random 400K-500K. |
| Slow algorithm | 10ms delay per hash iteration. Difficulty 4 fast = 0.04ms, slow = 41s. Targeted punishment mechanism. Turnstile has no equivalent. |
| Retrospective cookie invalidation | JTI denylist: wafctl writes suspicious JTIs, plugin rejects on next request. Forces re-challenge. Turnstile tokens are valid until expiry, no revocation. |
| Post-challenge session tracking | Service worker + page collector monitors browsing after challenge pass. Session scoring triggers auto-escalation to temporary block rules. Turnstile's Signal Orchestrator only runs during the challenge page. |
| Full tunability | Every threshold, weight, and scoring parameter is configurable. Turnstile is opaque. |
| Zero cost | No per-request pricing. Runs in-process. |

### Where Turnstile is ahead

| Gap | Detail |
|---|---|
| Application-state verification | Turnstile checks `__reactRouterContext`, `loaderData`, `clientBootstrap` — proves the React SPA fully rendered. We only prove "real browser", not "real browser running the actual app". |
| Signal obfuscation | Turnstile uses a bytecode VM (28 opcodes, randomized float registers, double-XOR encryption per request). Our `challenge.js` is static plaintext via `go:embed`. Bot author reads it once. |
| Fingerprint breadth | Turnstile: 55 browser properties + 36 behavioral + 25 PoW fields. Us: 13 JS signals + 5 behavioral. ~3x gap. |
| Font measurement | Turnstile creates hidden divs, sets fonts, measures rendered text bounding rects. We don't do this. |
| Storage quota probing | Turnstile calls `navigator.storage.estimate()` and writes to localStorage. We don't. |

---

## P1: Signal Obfuscation — Server-Side JS Mutation

**Priority:** High
**Status:** Not started
**Estimated effort:** ~200 lines Go, ~30 lines JS template changes

### Problem

`challenge.js` is embedded via `go:embed` and served identically on every request. A bot author reads the source once, identifies all 13 signal field names (`wd`, `cdc`, `cr`, `plg`, `lang`, `sv`, `wglr`, `wglMaxTex`, `audioHash`, `cores`, `mem`, `touch`, `plt`, `sw`, `sh`, `pt`), and writes targeted spoofs for each.

The string literals `"SwiftShader"`, `"cdc_"`, `"__puppeteer"` are directly greppable.

### Solution

Server-side JS mutation at serve time in `serveChallengeInterstitial()`.

#### 1a. Randomize signal field names

Generate a random mapping per request:

```
wd -> x7f3
cdc -> q2a1
cr -> m9k2
plg -> p3b8
...
```

In the mutated JS, `signals.wd = navigator.webdriver ? 1 : 0` becomes `signals.x7f3 = navigator.webdriver ? 1 : 0`.

The inverse mapping is JSON-serialized, encrypted with the challenge HMAC key (AES-GCM, 12-byte nonce), and embedded in `CHALLENGE_DATA` as `field_map_enc`. At verify time, `handleChallengeVerify` decrypts the field map and remaps signal keys before passing to `scoreBotSignals`.

#### 1b. Shuffle signal collection order

The 13 probes are independent. Randomize their execution order each request. Static analysis of "the first check is always webdriver" breaks.

Implementation: split `challenge.js` signal section into an array of probe blocks (delimited by comments). At serve time, `mutateJS()` shuffles the array and concatenates.

#### 1c. Insert dead-code probes

Add 5-10 fake property reads per request, drawn from a pool of ~30:

```js
signals.r4k2 = navigator.buildID || "";           // Firefox-only, always "" in Chrome
signals.j8m1 = window.__selenium_unwrapped || 0;  // old Selenium marker
signals.t3q9 = navigator.brave ? 1 : 0;           // Brave browser
signals.w2p5 = window.domAutomation || 0;          // old Chrome flag
signals.a6n3 = document.hasFocus() ? 1 : 0;       // always true in foreground
```

These contribute nothing to scoring. The server ignores any field not in the decrypted `field_map`. Forces bot authors to determine which signals matter through trial-and-error rather than code reading.

#### 1d. Obfuscate string literals

Replace greppable strings with per-request char-code arrays:

```js
// Before:
if (/^cdc_|^__puppeteer/.test(key)) return 1;

// After (per-request encoding):
const _m = [99,100,99,95]; // "cdc_"
const _p = [95,95,112,117,112,112,101,116,101,101,114]; // "__puppeteer"
const _ms = String.fromCharCode(..._m);
const _ps = String.fromCharCode(..._p);
if (key.startsWith(_ms) || key.startsWith(_ps)) return 1;
```

The char-code arrays can be XOR'd with a per-request byte for additional obfuscation.

### Implementation plan

**File: `challenge.go`**

1. Add `mutateJS(js string, hmacKey []byte) (mutatedJS string, fieldMapEnc string)`:
   - Parse signal field names from template markers in `challenge.js`
   - Generate random replacement names (4-char alphanum)
   - Pick 5-10 random dead-code probes from pool
   - Shuffle probe order
   - Obfuscate string literals with per-request XOR byte
   - Encrypt the `realName -> randomName` mapping with AES-GCM using first 16 bytes of HMAC key
   - Return mutated JS and encrypted field map (base64)

2. Update `serveChallengeInterstitial()`:
   - Call `mutateJS()` instead of using raw `challengeJS`
   - Add `field_map_enc` to `challengePayload` struct
   - Embed in `CHALLENGE_DATA` JSON

3. Update `handleChallengeVerify()`:
   - Decrypt `field_map_enc` from form data
   - Remap signal JSON keys before passing to `scoreBotSignals()`

**File: `challenge.js`**

4. Add template markers around each probe block:
   ```js
   // {{PROBE:wd}}
   signals.{{FLD:wd}} = navigator.webdriver ? 1 : 0;
   // {{/PROBE:wd}}
   ```

5. Replace hardcoded string literals with `{{STR:cdc_}}` markers that the mutator replaces with char-code arrays.

### Verification

- Existing challenge tests must pass (field remapping is transparent to scoring)
- New test: verify 100 mutations produce 100 different JS outputs
- New test: verify field map decrypt + remap recovers original field names
- Manual: inspect Network tab — signal JSON should have randomized keys

---

## P2: Application-State Verification

**Priority:** High
**Status:** Not started
**Estimated effort:** ~80 lines JS, ~60 lines Go, model changes

### Problem

A bot that passes all 13 browser probes but doesn't render the actual protected application will pass our challenge. Turnstile's strongest feature is checking `__reactRouterContext`, `loaderData`, and `clientBootstrap` — properties that only exist if the ChatGPT React app fully rendered and hydrated.

### Solution

Add configurable `challenge_app_checks` to challenge rules. The operator specifies which window properties, DOM selectors, or meta tags must be present.

#### Rule configuration

```json
{
  "type": "challenge",
  "challenge_difficulty": 4,
  "challenge_app_checks": [
    {"type": "window_prop", "path": "__nuxt"},
    {"type": "window_prop", "path": "__NEXT_DATA__.props"},
    {"type": "dom_selector", "selector": "#app[data-v-app]"},
    {"type": "dom_selector", "selector": "[data-reactroot]"},
    {"type": "meta_content", "name": "csrf-token"}
  ]
}
```

#### Client-side (challenge.js)

After PoW solve, before submission, execute the checks:

```js
const appState = {};
if (config.app_checks) {
  for (const check of config.app_checks) {
    const key = check.type + ":" + (check.path || check.selector || check.name);
    if (check.type === "window_prop") {
      appState[key] = typeof getNestedProp(window, check.path) !== "undefined";
    } else if (check.type === "dom_selector") {
      appState[key] = !!document.querySelector(check.selector);
    } else if (check.type === "meta_content") {
      const el = document.querySelector('meta[name="' + check.name + '"]');
      appState[key] = el ? !!el.content : false;
    }
  }
}
form.set("app_state", JSON.stringify(appState));
```

#### Server-side (challenge.go)

In `handleChallengeVerify()`:

1. Look up the matching challenge rule (already done for JA4/TTL/bindIP)
2. If `challenge_app_checks` is configured, parse the submitted `app_state` JSON
3. For each required check, verify the client reported `true`
4. If any check fails, reject with `challenge_fail_reason: app_state_missing`

#### Why this is better than Turnstile's approach

Turnstile hardcodes ChatGPT-specific properties. Ours is configurable per-rule per-service. Works for React, Vue, Nuxt, Next.js, Svelte, plain server-rendered HTML with specific meta tags, or any custom window global.

The operator knows their own application and specifies what to check. Zero framework assumptions in the plugin.

### Implementation plan

**Model changes:**

1. `challenge.go` — add `AppChecks []AppCheck` to `ChallengeConfig`
2. `challenge.go` — add `appChecks []AppCheck` to `compiledChallengeConfig`
3. Add `AppCheck` struct: `Type string, Path string, Selector string, Name string`

**wafctl model changes:**

4. `models_exclusions.go` — add `ChallengeAppChecks` field to `RuleExclusion`
5. `exclusions_validate.go` — validate check types (`window_prop`, `dom_selector`, `meta_content`)
6. `policy_generator.go` — serialize `challenge_app_checks` into `policy-rules.json`

**Plugin changes:**

7. `challenge.go` `serveChallengeInterstitial()` — include `app_checks` in `challengePayload`
8. `challenge.js` — add app-state collection block (after PoW, before submit)
9. `challenge.go` `handleChallengeVerify()` — validate `app_state` against rule config
10. `policyengine.go` `compileRule()` — compile `AppChecks` from config

**Frontend:**

11. `exclusions.ts` — add `challenge_app_checks` field
12. `PolicyForms.tsx` — add UI for configuring app checks (type dropdown + path/selector input)
13. `constants.ts` — add app check type options

### Important design note

The challenge interstitial is served *instead of* the actual page. The app hasn't loaded yet when the interstitial runs. Two approaches:

**Option A (iframe probe):** The interstitial creates a hidden iframe loading the actual page. After the iframe loads, the JS reaches into `iframe.contentWindow` to check for the expected properties. Then submits the PoW with the app-state results. Downside: doubles the page load during challenge, and CSP `frame-ancestors` may block it.

**Option B (two-phase):** After PoW verification succeeds, the server issues a *temporary* cookie (30-second TTL) that allows one page load without challenge. The JS redirects to the original URL. The page loads normally (app renders). A post-load script (injected via `sessionCollectorWriter`, same mechanism as `session-collector.js`) checks the app state and beacons it back. If app state is wrong, the temporary cookie is revoked via JTI denylist. Downside: adds one extra request, but architecturally cleaner.

**Option C (post-redirect check):** Same as current flow, but the `session-collector.js` (already injected into HTML responses for cookie holders) is extended to check app-state properties on first page load after challenge. If the properties are missing, it beacons a failure, and wafctl adds the JTI to the denylist. The client gets re-challenged on next request. This requires zero changes to the challenge interstitial itself — all logic goes into the existing session collector injection path.

**Recommendation: Option C.** It's the simplest, uses existing infrastructure (session collector injection + JTI denylist), and is architecturally consistent. The tradeoff is that the bot gets one free page load before detection, but since the session collector runs inline before the page is interactive, the window is small.

### Verification

- Test: challenge with `app_checks` configured, submit with all checks passing -> pass
- Test: challenge with `app_checks` configured, submit with one check failing -> reject
- Test: challenge with no `app_checks` -> existing behavior unchanged
- E2E: configure app check for a known DOM element on the test backend, verify bots without the element are caught

---

## P3: Expand Fingerprint Surface

**Priority:** Medium
**Status:** Not started
**Estimated effort:** ~60 lines JS, ~20 lines Go (new signal fields in `botSignals` struct)

### Current state

13 JS signals + 5 behavioral = 18 total.
Turnstile: 55 + 36 + 25 = 116 total.

### New probes to add

#### 3a. Font measurement (`fontHash`)

Create a hidden div, set specific fonts, measure rendered text bounding rects. Different OS/GPU/font configurations produce different measurements. Headless Chrome with `--no-sandbox` has different font metrics than desktop Chrome.

```js
signals.fontHash = (() => {
  try {
    const el = document.createElement("span");
    el.style.cssText = "position:absolute;visibility:hidden;font-size:72px";
    el.textContent = "mmmmmmmmmmlli";
    document.body.appendChild(el);
    const fonts = ["monospace", "serif", "sans-serif", "Arial", "Courier New"];
    let hash = 0;
    for (const f of fonts) {
      el.style.fontFamily = f;
      const r = el.getBoundingClientRect();
      hash = ((hash << 5) - hash + Math.round(r.width * 100) + Math.round(r.height * 100)) | 0;
    }
    document.body.removeChild(el);
    return hash;
  } catch { return 0; }
})();
```

**Scoring:** Don't score the hash value itself (too variable across legitimate browsers). Use it as a consistency check: if the font hash is 0, +10 (failed to render = headless). If the font hash is identical across multiple sessions from the same IP but different claimed UAs, flag in reputation scoring.

#### 3b. Storage quota (`storageQuota`)

```js
signals.storageQuota = await (async () => {
  try {
    const est = await navigator.storage.estimate();
    return est.quota || 0;
  } catch { return -1; }
})();
```

**Scoring:** Quota of 0 = headless/incognito with restricted storage. Not scored directly but contributes to the fingerprint hash for cross-session consistency.

#### 3c. Canvas fingerprint (`canvasHash`)

```js
signals.canvasHash = (() => {
  try {
    const c = document.createElement("canvas");
    c.width = 200; c.height = 50;
    const ctx = c.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("Cwm fjord veg", 2, 15);
    ctx.fillStyle = "rgba(102,204,0,0.7)";
    ctx.fillText("bank glyphs", 4, 35);
    const data = ctx.getImageData(0, 0, 200, 50).data;
    let hash = 0;
    for (let i = 0; i < data.length; i += 4) {
      hash = ((hash << 5) - hash + data[i] + data[i+1] + data[i+2]) | 0;
    }
    return hash;
  } catch { return 0; }
})();
```

**Scoring:** Canvas hash of 0 = canvas API blocked or headless. Cross-reference with WebGL renderer: if WebGL reports a real GPU but canvas hash is 0, +20 (inconsistent).

#### 3d. Media queries (`colorGamut`, `prefersRM`, `dynRange`)

```js
signals.colorGamut = matchMedia("(color-gamut: p3)").matches ? "p3" :
                     matchMedia("(color-gamut: srgb)").matches ? "srgb" : "none";
signals.prefersRM = matchMedia("(prefers-reduced-motion: reduce)").matches ? 1 : 0;
signals.dynRange = matchMedia("(dynamic-range: high)").matches ? 1 : 0;
```

**Scoring:** Not scored individually. Used for cross-session fingerprint consistency and spatial checks (e.g., mobile UA claiming P3 gamut on a device that doesn't support it).

#### 3e. Connection info (`connType`)

```js
signals.connType = navigator.connection ? navigator.connection.effectiveType || "" : "";
```

**Scoring:** `effectiveType` of "" (API absent) on Chrome UA = headless Chrome (real Chrome always has NetworkInformation API). +10.

### Go changes

Add fields to `botSignals` struct in `challenge.go`:

```go
FontHash     int    `json:"fontHash,omitempty"`
StorageQuota int64  `json:"storageQuota,omitempty"`
CanvasHash   int    `json:"canvasHash,omitempty"`
ColorGamut   string `json:"colorGamut,omitempty"`
PrefersRM    int    `json:"prefersRM,omitempty"`
DynRange     int    `json:"dynRange,omitempty"`
ConnType     string `json:"connType,omitempty"`
```

Add scoring rules in `scoreBotSignals()`:

```go
// Font measurement failed — likely headless
if sig.FontHash == 0 {
    score += 10
}
// Canvas API blocked/failed but WebGL works — inconsistent
if sig.CanvasHash == 0 && sig.WebGLRenderer != "" {
    score += 20
}
// Chrome UA but no NetworkInformation API
if isChromeLikeUA && sig.ConnType == "" {
    score += 10
}
```

### Verification

- Update `botSignals` struct and scoring in `challenge.go`
- Add new fields to `challenge.js` signal collection
- Run existing challenge tests — new fields are `omitempty`, old test fixtures still valid
- New test: verify canvas/font probes produce non-zero values in real browser (manual)

---

## P4: Encrypted Signal Transport

**Priority:** Medium
**Status:** Not started
**Estimated effort:** ~40 lines JS, ~30 lines Go

### Problem

Signals are submitted as plaintext JSON in `form.set("signals", JSON.stringify(signals))`. Visible in browser devtools Network tab. Easy to record and replay.

### Solution

At interstitial serve time, generate a per-challenge AES key (16 random bytes). Embed it in the JS payload. The JS encrypts the signals JSON with XOR (simple, no WebCrypto dependency for this) before submission. The key is also HMAC'd into the challenge payload so the server can recover it.

```js
// In challenge.js:
const encKey = config.signal_key; // 32 hex chars = 16 bytes
const raw = JSON.stringify(signals);
const enc = [];
for (let i = 0; i < raw.length; i++) {
  enc.push(raw.charCodeAt(i) ^ encKey.charCodeAt(i % encKey.length));
}
form.set("signals_enc", btoa(String.fromCharCode(...enc)));
```

Server-side: decrypt before parsing. The key is embedded in the HMAC'd challenge data, so it can't be tampered with.

### Why not AES-GCM in the browser?

WebCrypto's `subtle.encrypt` is async and adds complexity. XOR with a per-request key achieves the goal (prevent casual inspection) without adding failure modes. This is not cryptographic security — it's obfuscation of the transport layer. The real security is in the HMAC verification and bot scoring.

### Verification

- Test: signals encrypt/decrypt roundtrip
- Test: tampered signals_enc fails HMAC verification
- Manual: inspect Network tab — signals field should be base64 gibberish

---

## P5: Behavioral Signal Expansion

**Priority:** Medium
**Status:** Not started
**Estimated effort:** ~50 lines JS, ~40 lines Go

### Current state

5 behavioral signals during PoW: mouse event count, key event count, focus changes, scroll event count, first interaction time. Plus worker timing variance.

Turnstile's Signal Orchestrator: 36 `window.__oai_so_*` properties including keystroke timing, mouse velocity, scroll patterns, idle time, paste events.

### New behavioral signals

#### 5a. Mouse velocity histogram

```js
let lastMX = 0, lastMY = 0, lastMT = 0;
const velocities = [];
document.addEventListener("mousemove", (e) => {
  const now = Date.now();
  if (lastMT > 0) {
    const dt = now - lastMT;
    if (dt > 0 && dt < 500) {
      const dist = Math.sqrt((e.clientX - lastMX) ** 2 + (e.clientY - lastMY) ** 2);
      velocities.push(dist / dt);
    }
  }
  lastMX = e.clientX; lastMY = e.clientY; lastMT = now;
});
```

Submit as 3-bucket histogram: `{slow: <0.5, med: 0.5-2.0, fast: >2.0}`.

**Scoring:** If all velocities are in one bucket (zero variance), +15. Real human mouse movement has mixed velocities.

#### 5b. Mouse movement entropy

Compute Shannon entropy of movement directions (quantized to 8 compass directions).

**Scoring:** Entropy < 1.0 over 10+ events = scripted movement pattern. +20.

#### 5c. Page visibility at load

```js
behavior.hiddenAtStart = document.hidden ? 1 : 0;
```

**Scoring:** Challenge page loaded in background tab = +10. Bot farms often run headless tabs that are never visible.

#### 5d. requestAnimationFrame timing

```js
let rafTimes = [];
let rafCount = 0;
function rafProbe(ts) {
  rafTimes.push(ts);
  if (++rafCount < 30) requestAnimationFrame(rafProbe);
}
requestAnimationFrame(rafProbe);
```

Submit: stddev of inter-frame intervals.

**Scoring:** Stddev < 0.1ms over 30 frames = artificially precise timing (no OS scheduling jitter). +15.

#### 5e. Touch event on non-mobile

If the challenge page receives a `touchstart` event but `navigator.maxTouchPoints == 0`, it's a spoofed touch event. +25.

### Go changes

Add fields to `botBehavior` struct:

```go
MouseVelSlow   int     `json:"mvs,omitempty"`
MouseVelMed    int     `json:"mvm,omitempty"`
MouseVelFast   int     `json:"mvf,omitempty"`
MouseEntropy   float64 `json:"ment,omitempty"`
HiddenAtStart  int     `json:"has,omitempty"`
RAFVariance    float64 `json:"rafv,omitempty"`
FakeTouch      int     `json:"ft,omitempty"`
```

### Verification

- Test: behavioral signals parse correctly with new fields
- Test: single-bucket velocity histogram scores +15
- Test: hiddenAtStart=1 scores +10
- Manual: verify rAF stddev is > 1ms in real Chrome, < 0.1ms in headless

---

## P6: Canvas Fingerprinting (dedicated)

**Priority:** Low
**Status:** Not started
**Estimated effort:** Covered by P3 (3c)

This is included in P3 above. Listed separately because it deserves dedicated testing — canvas fingerprints are GPU/driver-dependent and need validation across multiple platforms to avoid false positives.

### Platforms to test

- Chrome/Windows (ANGLE/D3D11)
- Chrome/macOS (Metal)
- Chrome/Linux (Mesa/ANGLE)
- Firefox/all platforms (different canvas implementation)
- Safari/macOS (Core Graphics)
- Headless Chrome `--headless=new` (SwiftShader)
- Puppeteer default config

### Expected behavior

Each platform should produce a distinct, stable `canvasHash`. Headless Chrome with SwiftShader should produce a hash that differs from all desktop Chrome variants. If two different platforms produce the same hash, the probe is not useful for discrimination and should be downweighted.

---

## Implementation Order

| Phase | Items | Dependency |
|---|---|---|
| Phase 1 | P1 (obfuscation) + P2 (app-state) | None. Ship together — biggest impact. |
| Phase 2 | P3 (fingerprint surface) + P5 (behavioral) | None. Can start in parallel with Phase 1. |
| Phase 3 | P4 (encrypted transport) | Depends on P1 (field map encryption shares the same mechanism). |
| Phase 4 | P6 (canvas testing) | Depends on P3 (canvas probe already in P3). |

## Files to modify

### Plugin (`caddy-policy-engine/`)

| File | Changes |
|---|---|
| `challenge.go` | `mutateJS()`, field map encrypt/decrypt, app-state validation, new `botSignals`/`botBehavior` fields, new scoring rules |
| `challenge.js` | Template markers for probe blocks, app-state collection, new probes (font, canvas, storage, media queries, connection), new behavioral signals (velocity, entropy, rAF, visibility, touch), signal encryption |
| `challenge-worker.js` | No changes |
| `session-collector.js` | Option C app-state checks (if P2 uses Option C) |
| `session-sw.js` | No changes |
| `policyengine.go` | Compile `AppChecks` from rule config |

### wafctl (`wafctl/`)

| File | Changes |
|---|---|
| `models_exclusions.go` | `ChallengeAppChecks` field on `RuleExclusion` |
| `exclusions_validate.go` | Validate app check types and fields |
| `policy_generator.go` | Serialize `challenge_app_checks` to `policy-rules.json` |

### Frontend (`waf-dashboard/`)

| File | Changes |
|---|---|
| `src/lib/api/exclusions.ts` | `challenge_app_checks` field |
| `src/components/policy/PolicyForms.tsx` | UI for configuring app checks |
| `src/components/policy/constants.ts` | App check type options |

### Tests

| File | Changes |
|---|---|
| `challenge_test.go` (plugin) | Field map mutation, encrypt/decrypt roundtrip, app-state validation, new scoring rules |
| `exclusions_test.go` (wafctl) | App check validation |
| `policy_generator_test.go` (wafctl) | App check serialization |
| `exclusions.test.ts` (frontend) | App check field mapping |
