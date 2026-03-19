# BOTS.md — Advanced Bot Detection Beyond Proof-of-Work

## Problem Statement

The current challenge system (SHA-256 hashcash PoW) proves JavaScript execution
capability. It stops non-JS scrapers (curl, requests, scrapy, Go http.Client) but
does not stop headless Chrome, Puppeteer, Playwright, or residential proxy farms.
These clients have identical PoW-solving capability to real browsers.

This document describes a multi-layer detection system that scores browser
authenticity signals alongside the PoW, using the challenge page as the
collection point. The architecture follows the same weighted scoring model used
in the Forminator fraud detection system (`/home/erfi/fraud-detection/forminator/`)
but replaces Cloudflare-dependent signals with self-hosted equivalents.

**Design constraints:**
- No Cloudflare. TLS terminates directly in Caddy. No `request.cf` metadata.
- Zero external dependencies in the Go plugin (stdlib + existing deps only).
- All JS fingerprinting happens on the challenge interstitial page — no tracking
  scripts on upstream application pages.
- Scoring is server-side. The client submits signals alongside the PoW solution.
  The server decides accept/reject/escalate.
- Privacy: no persistent tracking. Signals are evaluated per-challenge, not stored
  beyond the challenge cookie lifetime.

---

## Detection Stack (4 layers)

```
Layer 1 — TLS Fingerprinting (JA4)          [before any HTTP]
Layer 2 — HTTP Header Fingerprinting         [before challenge page]
Layer 3 — JS Environment Probes              [during challenge page]
Layer 4 — Behavioral Signals                 [during PoW computation]
          ↓
    Weighted Risk Score (0-100)
          ↓
    Accept (score < 40) / Escalate (40-70) / Reject (≥ 70)
```

Each layer is independent. Layers 1-2 run before the challenge page is even
served. Layers 3-4 run client-side during the PoW and are submitted with the
solution. The server computes a composite score and decides the outcome.

---

## Layer 1: TLS Fingerprinting (JA4)

### What

Compute a JA4 fingerprint from the TLS ClientHello for every incoming connection.
JA4 identifies the TLS client implementation (browser version, HTTP library, bot
framework) before any HTTP data is exchanged.

### Why

- Python `requests` (JA4: `t13d...`), Go `net/http`, Node `undici`, curl — all
  have completely different TLS implementations from real browsers.
- Even `puppeteer-extra-plugin-stealth` cannot fake the TLS handshake — it
  happens at the OS/library level, not in JavaScript.
- Real headless Chrome has the same JA4 as real Chrome (same binary), so this
  layer catches non-browser clients, not headless browsers.

### How (hand-rolled, no external deps)

JA4 is computed from the TLS ClientHello message fields:

```
JA4 = TLSVersion_SNI_CipherCount_ExtensionCount_ALPNFirst_
      SHA256(SortedCiphers)_SHA256(SortedExtensions+SignatureAlgorithms+...)
```

Specifically (per FoxIO JA4 spec):
1. TLS version: `t` for TCP + version (`13` for TLS 1.3, `12` for 1.2, etc.)
2. SNI: `d` if SNI present, `i` if not
3. Cipher suite count (2-digit, zero-padded)
4. Extension count (2-digit, zero-padded)
5. ALPN first value: `h2` or `h1` or `00`
6. `_` separator
7. SHA-256 truncated hash of sorted cipher suites (12 hex chars)
8. `_` separator
9. SHA-256 truncated hash of sorted extensions + signature algorithms

**Implementation location:** `caddy-policy-engine/ja4.go` (new file, ~200 lines).

**Approach:** Caddy's `crypto/tls` exposes `tls.ConnectionState` on `r.TLS`, which
gives us `Version`, `CipherSuite`, `ServerName`, and `PeerCertificates`. However,
the full ClientHello (with extension list, cipher order, ALPN) is NOT available
from `ConnectionState` — Go's TLS library doesn't expose it post-handshake.

**Two options:**

**Option A: Custom TLS listener wrapper** (~300 lines Go)
Implement a `net.Listener` wrapper that intercepts the raw ClientHello bytes before
Go's TLS library processes them. Parse the ClientHello manually to extract:
- Cipher suites (2-byte IDs)
- Extensions (2-byte type + length + data)
- Supported groups (elliptic curves)
- Signature algorithms
- ALPN protocols

Store the parsed result in a connection-scoped context value that the policy engine
reads during `ServeHTTP`. This is the approach used by `caddy-ja3` and
`fingerproxy` — both open-source Caddy plugins with working implementations.

Reference: `github.com/rushiiMachine/caddy-ja3` (Apache-2.0) — intercepts
ClientHello via a custom `tls.Config.GetConfigForClient` callback, which receives
`*tls.ClientHelloInfo` containing all the fields we need.

**Option B: `GetConfigForClient` callback** (~150 lines Go)
Go's `tls.Config` has a `GetConfigForClient` callback that receives
`*tls.ClientHelloInfo` with:
- `CipherSuites []uint16`
- `SupportedVersions []uint16`
- `SupportedProtos []string` (ALPN)
- `ServerName string`

This gives us most JA4 fields except extensions and signature algorithms.
Sufficient for a "JA4-lite" that still distinguishes browsers from non-browsers.

**Recommendation:** Option B first (simpler, covers 90% of cases), upgrade to
Option A later for full JA4 fidelity.

**Storage:** The computed JA4 is stored as a Caddy variable
(`policy_engine.ja4_fingerprint`) accessible to rules as a condition field.

**New condition field in the policy engine:**
```json
{"field": "ja4", "operator": "eq", "value": "t13d1517h2_..."}
{"field": "ja4", "operator": "in_list", "value": "known-browser-ja4"}
{"field": "ja4", "operator": "not_in_list", "value": "known-browser-ja4"}
```

### JA4 Known-Good List

Maintain a managed list of known browser JA4 fingerprints. Seed from:
- Chrome (Windows, macOS, Linux) — 3-5 fingerprints per major version
- Firefox — 2-3 per major version
- Safari — 2-3 per major version
- Edge — shares Chrome's JA4

JA4 changes with browser updates but is stable across minor versions. A list of
~50 fingerprints covers 95%+ of real browser traffic. Update quarterly.

### Scoring

| Signal | Score | Weight |
|--------|-------|--------|
| JA4 not in known-browser list | 80 | 15% |
| JA4 matches known bot tool (curl, python-requests, go-http) | 100 | 15% |
| JA4 in known-browser list | 0 | 15% |

---

## Layer 2: HTTP Header Fingerprinting

### What

Compute a fingerprint from the HTTP header stack (names, order, values) of each
request. Different HTTP clients produce distinct header patterns even when
User-Agent is spoofed.

### How (adapted from Forminator)

**FNV-1a 64-bit hash** of normalized, sorted, non-volatile headers.

```go
// Exclude volatile/tracking headers
excluded := map[string]bool{
    "cookie": true, "authorization": true,
    "x-forwarded-for": true, "x-real-ip": true,
    "x-request-id": true, "cf-ray": true,
}

// Build canonical header string
var pairs []string
for name, values := range r.Header {
    lower := strings.ToLower(name)
    if excluded[lower] { continue }
    pairs = append(pairs, lower+":"+strings.Join(values, ","))
}
sort.Strings(pairs)
fingerprint := fnv1a64(strings.Join(pairs, "|"))
```

**Implementation:** Add to `challenge.go` — compute during challenge verification,
store in the challenge cookie for consistency checking on subsequent requests.

### Signals

| Signal | How detected | Score |
|--------|-------------|-------|
| Missing standard browser headers | Real browsers send Accept, Accept-Language, Accept-Encoding, Sec-Fetch-*, Sec-CH-UA-*. Automation tools often omit some. | 20-40 per missing header |
| Header order anomaly | Browsers send headers in a consistent order per engine. Custom HTTP clients often alphabetize or randomize. | 30 |
| Sec-Fetch-* metadata mismatch | `Sec-Fetch-Site: none` + `Sec-Fetch-Mode: navigate` is normal for direct navigation. Other combos from a challenge page are suspicious. | 40 |
| Client Hints present but inconsistent with UA | `Sec-CH-UA-Platform: "Windows"` but `User-Agent` says macOS. | 60 |

### Scoring

Header fingerprint contributes **10%** of total score.

---

## Layer 3: JS Environment Probes

### What

Collect browser environment signals client-side during the challenge page. These
probe for headless Chrome tells, automation markers, and device inconsistencies.

### Probes (collected in challenge.js, submitted with PoW solution)

#### 3a. Automation Markers

```javascript
const signals = {};

// navigator.webdriver — true in Selenium/Puppeteer automation mode.
// Easy to override via Object.defineProperty, but many bots don't bother.
// Score: 90 if true (strong signal), 0 if false.
signals.webdriver = !!navigator.webdriver;

// Chrome DevTools Protocol markers — ChromeDriver injects cdc_ variables.
// Puppeteer injects __puppeteer_evaluation_script__.
signals.cdcPresent = (() => {
  for (const key of Object.keys(document)) {
    if (key.match(/^cdc_|^__puppeteer/)) return true;
  }
  return false;
})();

// window.chrome.runtime — present in real Chrome, absent in headless.
// puppeteer-extra-plugin-stealth patches this, but many bots don't.
signals.hasChromeRuntime = !!(window.chrome && window.chrome.runtime && window.chrome.runtime.id !== undefined);
```

#### 3b. Plugin & Feature Presence

```javascript
// navigator.plugins — headless Chrome has 0 plugins.
// Real Chrome has PDF viewer + Chrome PDF Plugin (typically 2-5).
// The FP-Inconsistent paper found this is the #1 signal for BotD evasion.
signals.pluginCount = navigator.plugins.length;
signals.hasPlugins = navigator.plugins.length > 0;

// speechSynthesis voices — headless has 0 voices.
// Real Chrome/Firefox enumerate OS TTS voices.
signals.speechVoiceCount = window.speechSynthesis
  ? speechSynthesis.getVoices().length : -1;

// navigator.languages — headless often has empty or ["en"].
// Real browsers reflect OS language preferences (e.g., ["en-US", "en"]).
signals.languageCount = navigator.languages ? navigator.languages.length : 0;
```

#### 3c. WebGL Renderer (SwiftShader Detection)

```javascript
// WebGL renderer string reveals GPU.
// Headless Chrome uses SwiftShader (software renderer).
// Real Chrome uses actual GPU: "NVIDIA GeForce ...", "Intel Iris ...", etc.
// This single check catches most headless Chrome instances.
signals.webglRenderer = (() => {
  try {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!gl) return 'no-webgl';
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    if (!ext) return 'no-debug-ext';
    return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
  } catch { return 'error'; }
})();
signals.webglVendor = (() => {
  try {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!gl) return 'no-webgl';
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    if (!ext) return 'no-debug-ext';
    return gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
  } catch { return 'error'; }
})();
// SwiftShader check: "Google SwiftShader" = headless.
signals.isSwiftShader = signals.webglRenderer.includes('SwiftShader');
```

#### 3d. Hardware Consistency

```javascript
// Cross-reference claimed platform with actual hardware signals.
// iPhone claiming 0 touch points = inconsistent.
// "Windows" platform with macOS Canvas hash = inconsistent.
signals.hardwareConcurrency = navigator.hardwareConcurrency || 0;
signals.deviceMemory = navigator.deviceMemory || 0;
signals.maxTouchPoints = navigator.maxTouchPoints || 0;
signals.platform = navigator.platform;
signals.screenWidth = screen.width;
signals.screenHeight = screen.height;
signals.colorDepth = screen.colorDepth;
signals.pixelRatio = window.devicePixelRatio || 1;
```

#### 3e. Canvas Fingerprint

```javascript
// Draw text + shapes, hash the output. Differs per GPU/driver/OS/font.
// Headless Chrome with SwiftShader produces a known hash.
// Anti-detect browsers add noise — detectable by statistical analysis.
signals.canvasHash = (() => {
  try {
    const c = document.createElement('canvas');
    c.width = 280; c.height = 60;
    const ctx = c.getContext('2d');
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('policy-challenge-fp', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('policy-challenge-fp', 4, 45);
    return fnv1a32(c.toDataURL());
  } catch { return 'error'; }
})();

function fnv1a32(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}
```

#### 3f. Permissions API Timing

```javascript
// Real browsers take 1-50ms to resolve permissions queries (UI thread).
// Headless Chrome resolves in <0.1ms (no UI to consult).
// Reference: multiple anti-bot detection guides cite this as a reliable signal.
signals.permissionTiming = await (async () => {
  try {
    const t0 = performance.now();
    await navigator.permissions.query({ name: 'notifications' });
    return performance.now() - t0;
  } catch { return -1; }
})();
```

### Scoring

| Signal | Condition | Score |
|--------|-----------|-------|
| webdriver | true | 90 |
| cdcPresent | true | 95 |
| pluginCount | 0 (Chrome UA) | 50 |
| speechVoiceCount | 0 | 30 |
| isSwiftShader | true | 85 |
| canvasHash | matches known SwiftShader hash | 70 |
| maxTouchPoints | 0 but UA claims mobile | 60 |
| screenWidth/Height | impossible for claimed device | 50 |
| permissionTiming | < 0.5ms | 40 |
| hasChromeRuntime | false (Chrome UA) | 25 |
| languageCount | 0 or 1 | 15 |

JS environment contributes **50%** of total score (highest weight — this is where
the most discriminating signals live).

---

## Layer 4: Behavioral Signals

### What

Collect interaction and timing data during the PoW computation window (0.5-30
seconds depending on difficulty). Real users exhibit natural behavior. Bots
exhibit none or synthetic behavior.

### Signals

```javascript
const behavior = {
  // Mouse: did the user move the mouse at all?
  // Real users move the mouse while waiting. Bots don't unless scripted.
  mouseEvents: 0,
  mouseDistance: 0,
  
  // Keyboard: any keypress during the challenge?
  keyEvents: 0,
  
  // Focus: did the page lose/gain focus? (tab switching)
  // Real users might tab away while waiting. Bots keep the page focused.
  focusChanges: 0,
  
  // Scroll: any scroll events?
  scrollEvents: 0,
  
  // Timing: how long between page load and first interaction?
  // Bots interact at time 0 or never. Humans interact after 100-2000ms.
  firstInteractionMs: -1,
  
  // Worker timing: variance in Web Worker progress messages.
  // Real machines have OS scheduling jitter. Containers are more uniform.
  workerTimingVariance: 0,
};

// Listeners (added at page load, removed at submission)
document.addEventListener('mousemove', (e) => {
  behavior.mouseEvents++;
  // Accumulate distance
});
document.addEventListener('keydown', () => behavior.keyEvents++);
document.addEventListener('visibilitychange', () => behavior.focusChanges++);
document.addEventListener('scroll', () => behavior.scrollEvents++);
```

### Worker Timing Variance

The PoW Web Workers post progress every 1024 iterations. The timing between
these messages reflects CPU scheduling:

```javascript
const progressTimings = [];
let lastProgress = Date.now();

// In worker onmessage handler:
if (typeof event.data === 'number') {
  const now = Date.now();
  progressTimings.push(now - lastProgress);
  lastProgress = now;
}

// After PoW completes:
if (progressTimings.length >= 3) {
  const mean = progressTimings.reduce((a, b) => a + b, 0) / progressTimings.length;
  const variance = progressTimings.reduce((a, b) => a + (b - mean) ** 2, 0) / progressTimings.length;
  behavior.workerTimingVariance = Math.sqrt(variance);
}
```

Real machines have variance due to OS task scheduling, background processes, GC
pauses. Containers in bot farms have more uniform timing (dedicated CPU, no
background tasks).

### Scoring

| Signal | Condition | Score |
|--------|-----------|-------|
| mouseEvents | 0 after 2+ seconds of PoW | 25 |
| workerTimingVariance | < 1ms (unnaturally uniform) | 30 |
| firstInteractionMs | -1 (no interaction at all) | 15 |
| focusChanges + scrollEvents + keyEvents | all zero | 10 |

Behavioral signals contribute **15%** of total score. Lower weight because
behavioral signals are noisy (a user on mobile may not move a mouse) and
sophisticated bots can simulate basic interactions.

---

## Composite Risk Score

### Architecture (adapted from Forminator's scoring.ts)

```
Total = Σ (signal_score × signal_weight)
      + corroboration_bonus (if 3+ signals fire)
      + JA4_override (if known bot tool)
```

### Weights

| Layer | Weight | Rationale |
|-------|--------|-----------|
| TLS fingerprint (JA4) | 15% | Catches non-browser clients. Zero false positives. |
| HTTP header fingerprint | 10% | Catches basic automation. Low-entropy but useful. |
| JS environment probes | 50% | Highest-entropy signals. WebGL renderer alone catches most headless Chrome. |
| Behavioral signals | 15% | Noisy but additive. Catches lazy bots. |
| PoW completion | 10% | Baseline: did they solve it at all? Difficulty compliance. |

### Corroboration Bonus

When 3 or more independent signals score >= 30, add +15 to the total. This
captures the "everything is a little off" pattern that FP-Inconsistent identified
as the strongest detection heuristic.

### Weight Redistribution (from Forminator)

When some signals are unavailable (e.g., WebGL blocked by browser policy, JA4
not computed for HTTP/3), redistribute their weight to remaining signals.
Redistribution factor capped at 2.0× to prevent over-amplification.

### Decision Thresholds

| Score | Action |
|-------|--------|
| 0-39 | **Accept** — issue challenge cookie, redirect to original URL |
| 40-69 | **Escalate** — re-challenge at higher difficulty (×2) |
| 70-100 | **Reject** — return 403, log as `challenge_failed_bot` |

### Deterministic Overrides

Certain signals are so strong that they override the score:
- `navigator.webdriver === true` → force score ≥ 70 (block)
- `cdcPresent === true` → force score ≥ 70 (block)
- JA4 matches known bot tool → force score ≥ 70 (block)
- WebGL renderer is SwiftShader → force score ≥ 50 (escalate)

---

## Implementation Plan

### Phase 1: JS Environment Probes (Tier 1)

**Effort:** ~2-3 days. No Go changes. JS only + verify endpoint scoring.

1. Add signal collection to `challenge.js` (probes from Layer 3)
2. Add behavioral listeners to `challenge.js` (Layer 4)
3. Submit signals as additional form fields in the verify POST
4. In `challenge.go` `handleChallengeVerify`: parse signals, compute risk score
5. Accept/escalate/reject based on score thresholds
6. Log signals in Caddy variables for access log capture

**What this catches immediately:**
- `navigator.webdriver === true` (Selenium, unpatched Puppeteer)
- 0 plugins (headless Chrome default)
- SwiftShader WebGL renderer (headless Chrome)
- 0 speech voices (headless)
- Permission timing < 0.5ms (headless)
- No mouse/keyboard interaction during PoW

### Phase 2: JA4-Lite via GetConfigForClient

**Effort:** ~3-4 days. New Go code in the plugin.

1. Add `ja4.go` to caddy-policy-engine
2. Implement JA4-lite from `tls.ClientHelloInfo` fields (cipher suites, supported
   versions, ALPN, SNI)
3. Store as Caddy variable `policy_engine.ja4`
4. Add `ja4` as a condition field in rule matching
5. Add known-browser JA4 list to managed lists
6. Challenge rules can use `ja4` in conditions for pre-filtering

### Phase 3: Full JA4 + Header Fingerprinting

**Effort:** ~3-4 days.

1. Upgrade to full JA4 via ClientHello interception (extensions, signature
   algorithms)
2. Add HTTP header fingerprinting (FNV-1a hash of sorted header stack)
3. Add header consistency checks (missing Sec-Fetch-*, Client Hints mismatches)
4. Integrate into the composite risk score

### Phase 4: Spatial Inconsistency Detection

**Effort:** ~2-3 days.

Based on the FP-Inconsistent paper (UC Davis, 2024):
1. Cross-reference UA-claimed device with actual signals:
   - iPhone UA + 0 touch points = inconsistent
   - iPhone UA + non-iPhone screen resolution = inconsistent
   - Mobile UA + hardwareConcurrency > 16 = inconsistent
   - Windows UA + macOS Canvas hash = inconsistent
2. Cross-reference JA4 with UA (a Python requests JA4 with a Chrome UA = spoof)
3. Cross-reference timezone (from JS `Intl.DateTimeFormat`) with IP geolocation

---

## What This Does NOT Solve

- **Residential proxy farms with real browsers operated by humans.** These are
  real users being paid to browse. No technical detection can distinguish them
  from legitimate users because they ARE legitimate users. This is a business
  problem (pricing, ToS enforcement), not a technical one.

- **Anti-detect browsers (Multilogin, GoLogin, Kameleo)** with full GPU
  passthrough, real plugins, and consistent fingerprints. These are
  indistinguishable from real browsers at every layer. They cost $100+/month
  per profile, which is the economic defense — making scraping expensive.

- **Browser extensions that modify fingerprints** (Canvas Blocker, etc.) on
  real users' browsers. These will trigger false positives. The scoring system
  must be tuned to tolerate privacy-enhancing tools without blocking real users.
  The FP-Inconsistent paper found a 96.84% true negative rate on real user
  traffic — 3.16% false positive rate, mostly from UA spoofer extensions.

---

## References

### Academic Papers

- **FP-Inconsistent** (Venugopalan et al., UC Davis, 2024): "Detecting Evasive
  Bots using Browser Fingerprint Inconsistencies." 507K bot requests from 20 bot
  services. Found spatial inconsistencies reduce evasion by 44-48% with 96.84%
  true negative rate. Key insight: individual attributes are easy to spoof,
  consistency across attributes is hard.
  https://arxiv.org/html/2406.07647v3

- **BOTracle** (Kadel et al., Adobe + Hamburg, 2024): "A framework for
  Discriminating Bots and Humans." Compared network-level, fingerprint-based,
  and behavioral detection. Behavioral analysis had highest accuracy against
  sophisticated bots.
  https://arxiv.org/html/2412.02266v1

- **Vastel thesis** (2019): "Tracking Versus Security: Investigating the Two
  Facets of Browser Fingerprinting." Comprehensive taxonomy of fingerprinting
  techniques and their entropy contributions.
  https://theses.hal.science/tel-02343930

### Industry References

- **JA4 specification** (FoxIO): JA4+ network fingerprinting.
  https://github.com/FoxIO-LLC/ja4

- **Auth0 blog** (March 2026): "Strengthening Bot Detection with JA4 Signals."
  Describes using JA4 to defeat TLS spoofing.
  https://auth0.com/blog/strengthening-bot-detection-ja4-signals/

- **caddy-ja3** (Caddy plugin): JA3 fingerprinting via GetConfigForClient.
  Apache-2.0 license. Reference implementation for Caddy TLS fingerprinting.
  https://github.com/rushiiMachine/caddy-ja3

- **fingerproxy** (Go): JA3 + JA4 + HTTP/2 fingerprinting reverse proxy.
  Apache-2.0 license. Full ClientHello parsing implementation.
  https://github.com/0x4D31/fingerproxy

- **Forminator** (`/home/erfi/fraud-detection/forminator/`): Multi-signal
  weighted risk scoring with progressive timeouts, header fingerprinting
  (FNV-1a), TLS anomaly baselines, and JA4 session clustering. Architecture
  directly applicable to this system.

### Browser API Documentation

- `navigator.webdriver`: https://w3c.github.io/webdriver/#dom-navigator-webdriver
- `WEBGL_debug_renderer_info`: https://registry.khronos.org/webgl/extensions/WEBGL_debug_renderer_info/
- `navigator.permissions.query()`: https://w3c.github.io/permissions/#dom-permissions-query
- `navigator.plugins`: https://html.spec.whatwg.org/multipage/system-state.html#dom-navigator-plugins
- `speechSynthesis.getVoices()`: https://w3c.github.io/speech-api/#dom-speechsynthesis-getvoices
- Canvas fingerprinting: https://browserleaks.com/canvas (test tool)
- `Sec-Fetch-*` headers: https://w3c.github.io/webappsec-fetch-metadata/
- `Sec-CH-UA-*` Client Hints: https://wicg.github.io/ua-client-hints/

### Detection Evasion (know thy enemy)

- **puppeteer-extra-plugin-stealth**: Patches 11+ detection vectors in Puppeteer.
  Understanding what it patches informs what we DON'T rely on as sole signals.
  https://github.com/nicedayfor/puppeteer-extra-plugin-stealth

- **Patchright**: Playwright fork with anti-fingerprint hardening at the binary
  level. Demonstrates that JS-level patching is the floor, not the ceiling.
  https://github.com/nicedayfor/patchright
