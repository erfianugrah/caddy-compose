# Session Behavioral Tracking: Detecting Low-and-Slow Bots

## Problem Statement

A class of sophisticated bots evades all current defenses in the stack:

1. **Bot scoring passes** — they use full stealth-patched headless Chrome (webdriver=false,
   real plugins, patched WebGL, fake voices). Our 5-layer scoring gives them < 70.
2. **Rate limiting misses** — they make 1-5 requests per session, well below any threshold.
3. **PoW challenge passes** — they solve the challenge with a real browser engine. Turnstile
   and similar challenge-response systems are equally bypassed.
4. **DDoS mitigator ignores** — no burst, no path diversity anomaly, no behavioral trigger.

The pattern: bot lands on a page, idles 5-10 seconds (mimicking reading), clicks one link
or extracts content, then leaves. From a single-request perspective, it looks human. The
signal is only visible **across the session** — real humans browse multiple pages, vary
their dwell times, and don't follow a fixed arrival→extract→leave cycle.

This is the gap Scott Pearson identified in the Cloudflare internal thread. Cloudflare's
"Precursor" (2026Q2 roadmap, behind Access — not publicly documented) likely targets this
with network-layer session analysis. We need to solve it at the application layer.

## Prior Art & Research

### Academic Papers

**COSEC — Session Incoherence Detection** (IEEE S&P 2025)
Zhang et al., Georgia Tech + Microsoft. "Identifying Incoherent Search Sessions: Search
Click Fraud Remediation Under Real-World Constraints." Key insight: humans exhibit
*coherent* session behavior (focused on one topic, natural temporal progression), while
bots/fraudsters produce *incoherent* sessions (diverse/illogical sequence, uniform timing).
COSEC extracts literal semantic, temporal, and behavioral features from sessions, feeds
them into a Bi-LSTM classifier, and produces an "incoherence index" (0-1). Achieved
95.79% precision, 92.40% recall. Robust against concept drift (92.34% accuracy on data
3 months newer than training set).

Relevance: The incoherence-index concept maps directly to our problem. A scraper that
visits one page and leaves has maximum incoherence — no semantic progression, no
browsing flow, single-action sessions.

**Session2vec — Multi-Instance Learning for Web Robot Detection** (Electronics, 2025)
Zhang et al., Beijing University of Posts and Telecommunications. Models each web session
as a "bag" of request instances under the Multi-Instance Learning (MIL) paradigm. Instead
of classifying individual requests, the system learns session-level representations that
capture cross-request patterns. Outperformed traditional per-request methods on
camouflage attacks.

Relevance: Validates that session-level features (not individual request features) are
the correct abstraction for detecting sophisticated bots.

**BOTracle — Website Traversal Graphs** (ESORICS-W 2024, Adobe Research)
Kadel et al. Three-stage pipeline: heuristics → SGAN per-request analysis → DGCNN on
Website Traversal (WT) graphs. The WT graph stage is purely behavioral — no IP, no UA,
no window size. Constructs a graph where nodes = pages and edges = navigations, then
classifies via Deep Graph Convolutional Neural Network. 98%+ precision/recall on 50M
monthly visits e-commerce site. Key finding: bots are "unaware of average behavior on a
specific website" — their traversal graphs look structurally different from humans.

Relevance: The traversal graph concept is powerful but requires ML infrastructure we don't
have. However, the *features* they extract (page type distribution, session depth, edge
patterns) can be computed with simple statistics.

**CAWAL — Enriched Session Data for Anomaly Detection** (arXiv 2502.00413, submitted to
Knowledge-Based Systems, 2025) Canay & Kocabicak, Sakarya University. Integrates
application logs with web analytics for comprehensive session/pageview data. Gradient
Boosting and Random Forest on enriched datasets achieved 92%+ accuracy in predicting
user behavior and detecting anomalies. Session ID + user ID tracking, page load time,
time-on-page metrics. Deployed on a real web portal with 10 web servers and 1.2M sessions.

### Industry Approaches

**Cloudflare Bot Management** — Multi-layer: ML engine (supervised, trained on billions of
requests), JavaScript Detections (JSD — lightweight invisible JS injection), heuristics
engine (50+ heuristics on HTTP/2 fingerprints, Client Hello, etc.), anomaly detection
(per-zone traffic baseline), per-customer behavioral models (September 2025 announcement).
The `__cf_bm` cookie smooths bot scores across sessions. New "scraping behavioral
detections" caught 138M requests in 24 hours on 5 beta zones, with 34% not caught by
existing bot scoring alone.

**Cloudflare Post-Challenge Monitoring** (reported in evasion analysis literature, not
officially documented by Cloudflare) — Multiple evasion researchers report that even
after a Turnstile/Managed Challenge passes, Cloudflare may monitor post-challenge
behavioral telemetry and retrospectively flag clearance tokens as invalid if subsequent
interactions indicate bot-like traversal patterns. Source: Aggarwal (Medium, 2026-02-24)
and CloudBypass analysis (2026-03-19). Cloudflare's official docs confirm that the
`__cf_bm` cookie "measures a single user's request pattern and applies it to the machine
learning data to generate a reliable bot score for all of that user's requests" — which
implies ongoing session evaluation, though retrospective invalidation is not explicitly
documented. This is the pattern we want to replicate: challenge pass is not permanent trust.

**Arcjet Advanced Signals** — WebAssembly-based client-side signal collector, stores
results in `aj_signals` cookie, evaluated server-side. Runs continuously throughout user
sessions (not just at challenge time). Detects automation that mimics human behavior.

**GA4 Bot Detection** — Server-side behavioral heuristics: mouse movement velocity/
trajectory analysis, session duration clustering, navigation pattern coherence. Cross-
references browser consistency signals with behavioral telemetry.

### Web Platform Standards

**W3C Service Workers** (CRD 2026-03-12, https://www.w3.org/TR/service-workers/)
Service workers are event-driven workers registered against an origin and path. They
intercept `fetch` events for all in-scope navigations and subresource requests. Lifetime
is tied to event execution, not page lifecycle — they persist across navigations. Key
capability: a service worker registered during the challenge interstitial would
automatically intercept all subsequent navigations to the same origin, enabling cross-page
session tracking without per-page JavaScript injection.

- `install` event: triggered on first registration, can precache assets
- `activate` event: triggered when SW takes control, can enable navigation preload
- `fetch` event: fired for every request from controlled clients
- `NavigationPreloadManager`: allows parallel network fetch during SW bootup
- Scope: `./` relative to script URL by default. A SW at `/sw.js` has scope `/`.
  A SW at `/.well-known/policy-challenge/session-sw.js` would default to scope
  `/.well-known/policy-challenge/`. To control the entire origin, the server must
  set the `Service-Worker-Allowed` response header to `/` when serving the SW script,
  and the registration must specify `{scope: '/'}`.
- Update: browser checks for byte-diff on navigation; `registration.update()` for manual

**W3C Beacon API** (Candidate Recommendation Draft, 2022-08-03, https://www.w3.org/TR/beacon/)
`navigator.sendBeacon(url, data)` — asynchronous, non-blocking data delivery. Per the
spec (Section 3.1):
- "Beacon requests are guaranteed to be initiated before page is unloaded and are
  allowed to run to completion without requiring blocking requests"
- User agent MUST initiate fetch with `keepalive` flag set
- User agent MUST schedule immediate transmission when `visibilityState` transitions
  to `hidden` and MUST allow all such requests to run to completion
- Uses `POST` method only; no response callback; no custom headers
- Payload limited by keepalive quota (shared with `fetch(..., {keepalive: true})`)
- Returns `true` if queued successfully, `false` if over quota

Note: delivery is best-effort — network conditions may prevent delivery. The spec
explicitly states "reporting is not intended to be used as a reliable communications
channel." For our use case this is acceptable: missing a few beacons degrades scoring
accuracy but doesn't break security.

Alternative: `fetch()` with `keepalive: true` — same delivery mechanism under the
hood, but supports custom methods, headers, and response access. The Beacon API spec
notes: "Applications that require non-default settings for such requests should use
the [FETCH] API with keepalive set to true."

**W3C Navigation Timing Level 2** (WD 2022-01-17, https://www.w3.org/TR/navigation-timing-2/)
`PerformanceNavigationTiming` interface — high-resolution timing for document navigation:
- `unloadEventStart`/`unloadEventEnd`: previous document teardown
- `domInteractive`, `domContentLoadedEventStart/End`, `loadEventStart/End`
- `type`: navigate, reload, back_forward, prerender
- `redirectCount`: number of redirects

**W3C Reporting API** (WD 2025-06-11, https://www.w3.org/TR/reporting-1/)
Generic framework for delivering feature-specific reports to named endpoints.
`Reporting-Endpoints` header defines collection URLs. Reports delivered out-of-band,
best-effort. Can be observed via `ReportingObserver` JavaScript API. Useful for
server-side collection of deprecation/intervention/crash reports without polling.

**Page Visibility** (HTML Living Standard, Section 6.2)
Page Visibility is now defined in the HTML Living Standard (not a separate spec). A
`Document` has a `visibility state` which is "hidden" or "visible". The
`visibilitychange` event fires when the state changes (tab switch, minimize, screen
lock, app switch on mobile). The `VisibilityStateEntry` interface (Chrome 115+)
exposes visibility changes via `PerformanceObserver`. The Beacon API spec explicitly
notes that `visibilitychange` "is the only event that is guaranteed to fire on mobile
devices when the page transitions to background state."

Note: The older Page Visibility Level 2 (W3C CR 2022-06-23) is superseded by the
HTML Living Standard definition. The `"prerender"` visibility state was part of the
old spec but is no longer a `visibilityState` value in the current HTML spec.

**Page Lifecycle** (not a W3C standard — Chrome/Chromium implementation)
Chrome extends the visibility model with `freeze`/`resume` states and the `pagehide`
event. `pagehide` fires more reliably than `beforeunload` for cleanup.
`document.wasDiscarded` detects tab discard. These are Chromium-specific and not
available in all browsers. For cross-browser compatibility, `visibilitychange` is
the recommended event for triggering exit beacons.

## Design

### Architecture Overview

```
Challenge Pass
     ↓
Register Service Worker (/.well-known/policy-challenge/session-sw.js)
     ↓
SW intercepts all subsequent navigations
     ↓
On each navigation:
  ├── Record timestamp + path + referrer in IndexedDB/memory
  ├── Compute dwell time for previous page (via visibilitychange)
  ├── On visibilitychange→hidden: sendBeacon with accumulated session data
  └── On periodic interval (30s): sendBeacon heartbeat
     ↓
Server receives session beacons at /.well-known/policy-challenge/session
     ↓
wafctl SessionStore: per-JTI session accumulator
     ↓
Session scoring pipeline (runs on beacon receipt + periodic sweep)
     ↓
Score feeds into:
  ├── Cookie invalidation (retrospective: mark JTI as suspicious)
  ├── Reputation system (IP/JA4 flagging)
  └── Challenge re-issuance (force re-challenge on next request)
```

### Layer 1: Service Worker Session Tracker

Registered during the challenge interstitial (alongside the PoW solver). The SW persists
after the challenge is solved and controls all subsequent navigations to the origin.

**Important**: By default, a newly registered SW does not control the page that
registered it (per the SW spec: "a page's fetches won't go through a service worker
unless the page request itself went through a service worker"). The SW must call
`self.clients.claim()` in its `activate` handler to immediately take control of all
open pages. Without this, the first page after challenge redirect would NOT be tracked.
The `activate` handler should be:

```javascript
self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});
```

```javascript
// session-sw.js — served at /.well-known/policy-challenge/session-sw.js
// Registered with {scope: '/'} — requires Service-Worker-Allowed: / header
// on the SW script response (the plugin must set this header).

const SESSION_BEACON_URL = '/.well-known/policy-challenge/session';
const HEARTBEAT_INTERVAL_MS = 30000; // 30s
const MAX_BUFFER_SIZE = 50; // max navigations before forced flush

let sessionBuffer = [];
let lastNavTimestamp = 0;

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Only track navigations (not subresource fetches)
  if (event.request.mode !== 'navigate') return;

  // Skip our own beacon endpoint
  if (url.pathname.startsWith('/.well-known/policy-challenge/')) return;

  const now = Date.now();
  const dwellMs = lastNavTimestamp > 0 ? now - lastNavTimestamp : 0;

  sessionBuffer.push({
    ts: now,
    path: url.pathname,
    referrer: event.request.referrer || '',
    dwell_ms: dwellMs,
    type: 'navigate',
  });

  lastNavTimestamp = now;

  // Flush if buffer is large
  if (sessionBuffer.length >= MAX_BUFFER_SIZE) {
    flushBeacon();
  }
});

function flushBeacon() {
  if (sessionBuffer.length === 0) return;
  const payload = JSON.stringify(sessionBuffer);
  sessionBuffer = [];
  // fetch with keepalive ensures delivery even during SW termination
  fetch(SESSION_BEACON_URL, {
    method: 'POST',
    body: payload,
    keepalive: true,
    headers: { 'Content-Type': 'application/json' },
  }).catch(() => {}); // best-effort
}

// NOTE: setInterval is unreliable in service workers — the browser may terminate
// the SW between fetch events. Flushing on each navigation (above) and relying on
// the page-level collector's visibilitychange beacon is more reliable than timers.
// If periodic flush is needed, consider using the Periodic Background Sync API
// (requires user permission and is not widely supported).
```

The cookie JTI (already in the challenge cookie) serves as the session identifier. The
server correlates beacons to JTIs via the cookie sent with each fetch request.

### Layer 2: Page-Level Behavioral Collector

A lightweight inline script injected into every page served through the policy engine
(not just the interstitial). This captures page-level signals that the SW can't see:

- **Visible dwell time**: `visibilitychange` events to track actual viewing time
  (excluding hidden/minimized periods)
- **Scroll depth**: maximum scroll position as percentage of page height
- **Interaction events**: mouse click count, keyboard input presence (boolean, not content)
- **Exit beacon**: `visibilitychange → hidden` triggers final flush with accumulated
  page metrics. This is the cross-browser reliable event for page exit (the Beacon API
  spec specifically recommends this over `unload`/`beforeunload`/`pagehide`).

```javascript
// Injected as a small inline script via the policy engine's response filter
(function() {
  let visibleStart = Date.now();
  let totalVisible = 0;
  let maxScroll = 0;
  let clicks = 0;
  let typed = false;
  let sent = false;

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      totalVisible += Date.now() - visibleStart;
      // Flush on hidden — this is the recommended exit signal per Beacon API spec.
      // "visibilitychange is the only event that is guaranteed to fire on mobile
      // devices when the page transitions to background state" — W3C Beacon API §1
      if (!sent) {
        sent = true;
        navigator.sendBeacon('/.well-known/policy-challenge/session', JSON.stringify([{
          ts: Date.now(),
          path: location.pathname,
          type: 'page_metrics',
          visible_ms: totalVisible,
          scroll_pct: maxScroll,
          clicks: clicks,
          typed: typed ? 1 : 0,
        }]));
      }
    } else {
      visibleStart = Date.now();
      sent = false; // allow re-send if page becomes visible again then hidden
    }
  });

  window.addEventListener('scroll', () => {
    const pct = Math.round((window.scrollY + window.innerHeight) /
      document.documentElement.scrollHeight * 100);
    if (pct > maxScroll) maxScroll = pct;
  });

  document.addEventListener('click', () => clicks++);
  document.addEventListener('keydown', () => { typed = true; }, { once: true });
})();
```

**Size**: ~400 bytes minified. Injected only when a valid challenge cookie is present
(no overhead for unchallenged requests or first-time visitors seeing the interstitial).

### Layer 3: Server-Side Session Store (wafctl)

New `SessionStore` in wafctl, keyed by challenge cookie JTI.

```go
type SessionEntry struct {
    JTI         string        `json:"jti"`
    IP          string        `json:"ip"`
    JA4         string        `json:"ja4"`
    Service     string        `json:"service"`
    FirstSeen   time.Time     `json:"first_seen"`
    LastSeen    time.Time     `json:"last_seen"`
    Navigations []Navigation  `json:"navigations"`
    Score       float64       `json:"score"`       // 0-1, higher = more suspicious
    Flags       []string      `json:"flags"`       // e.g., "single_page", "uniform_dwell"
}

type Navigation struct {
    Timestamp  time.Time `json:"ts"`
    Path       string    `json:"path"`
    DwellMs    int       `json:"dwell_ms"`
    VisibleMs  int       `json:"visible_ms,omitempty"`  // from page metrics
    ScrollPct  int       `json:"scroll_pct,omitempty"`
    Clicks     int       `json:"clicks,omitempty"`
    Typed      bool      `json:"typed,omitempty"`
}
```

**Storage**: In-memory with periodic JSON persistence (same pattern as other stores).
Sessions expire after cookie TTL (default 1h). Bounded: max 10,000 active sessions,
LRU eviction. Each session entry is small (~500 bytes for 10 navigations).

**Memory budget**: 10,000 sessions × 500 bytes = ~5MB. Negligible.

### Layer 4: Session Scoring Pipeline

Runs on each beacon receipt and periodically (every 60s) for aging sessions.

#### Features Extracted

| Feature | Description | Human Range | Bot Signal |
|---|---|---|---|
| `page_count` | Total unique pages visited | 3-50+ | 1-2 |
| `session_duration_s` | Time from first to last navigation | 60-1800+ | 5-30 |
| `mean_dwell_ms` | Average time between navigations | 8000-60000 | 3000-10000 (uniform) |
| `dwell_cv` | Coefficient of variation of dwell times | 0.4-1.5 | < 0.2 (too uniform) |
| `visible_ratio` | visible_ms / dwell_ms (actually looking) | 0.7-1.0 | 0.0-0.3 (tab hidden) |
| `scroll_depth_mean` | Average scroll depth across pages | 30-80% | 0-10% (no scroll) |
| `interaction_rate` | Pages with clicks or typing / total pages | 0.3-0.8 | 0.0-0.1 |
| `path_diversity` | Unique path prefixes / total navigations | 0.3-0.9 | < 0.1 (same path pattern) |
| `referrer_coherence` | Fraction of navigations with internal referrer | 0.5-0.9 | 0.0-0.2 (direct entry) |
| `exit_after_extract` | Session has exactly: land → one content page → leave | rare | signature pattern |

#### Scoring Algorithm

Rule-based scoring with weighted indicators (no ML dependency — matches the project's
zero-external-dependency philosophy in wafctl):

```go
func scoreSession(s *SessionEntry) float64 {
    score := 0.0

    // Single-page session after challenge
    if len(s.Navigations) <= 1 && elapsed(s) > 10*time.Second {
        score += 0.4
    }

    // Very short session (< 30s) with content extraction pattern
    if elapsed(s) < 30*time.Second && len(s.Navigations) <= 3 {
        score += 0.2
    }

    // Uniform dwell time (CV < 0.2) across 3+ pages
    if len(s.Navigations) >= 3 && dwellCV(s) < 0.2 {
        score += 0.3
    }

    // No scroll engagement
    if meanScrollPct(s) < 10 && len(s.Navigations) >= 2 {
        score += 0.15
    }

    // No interaction (clicks/typing) across entire session
    if interactionRate(s) < 0.05 && len(s.Navigations) >= 2 {
        score += 0.15
    }

    // Low visible ratio (tab hidden most of the time)
    if meanVisibleRatio(s) < 0.3 {
        score += 0.2
    }

    // Positive: real browsing behavior reduces score
    if len(s.Navigations) >= 5 && dwellCV(s) > 0.5 && interactionRate(s) > 0.3 {
        score -= 0.3
    }

    return clamp(score, 0, 1)
}
```

Threshold: `score >= 0.6` → flag session as suspicious.

#### Actions on Suspicious Sessions

1. **Retrospective cookie invalidation**: Add JTI to a short-lived denylist
   (checked in `validateChallengeCookie()`). Next request forces re-challenge.
2. **Reputation update**: Increment suspicion counter for the IP and JA4 in the
   challenge reputation system. Repeated suspicious sessions from the same
   IP/JA4 → automatic block rule suggestion in the dashboard.
3. **Logging**: Emit `session_suspicious` event type with session details, visible
   in the challenge analytics dashboard.
4. **Optional: escalation**: If the same IP/JA4 produces 3+ suspicious sessions
   within 1 hour, automatically create a temporary block rule (configurable).

### Layer 5: Plugin Integration

The policy engine plugin needs minimal changes:

1. **Serve session-sw.js** at `/.well-known/policy-challenge/session-sw.js`
   (embedded, same as worker.js). Cached aggressively. Must include the header
   `Service-Worker-Allowed: /` in the response so the SW can be registered with
   origin-wide scope (per the Service Workers spec, a SW script can only control
   URLs at or below its own path unless this header is present).
2. **Register SW in interstitial**: Add
   `navigator.serviceWorker.register('/.well-known/policy-challenge/session-sw.js', {scope: '/'})`
   to the challenge interstitial page after PoW solve (or in the redirect handler).
   The `{scope: '/'}` is required because the script path is under `/.well-known/`.
3. **Accept session beacons**: New handler at `/.well-known/policy-challenge/session`
   (POST, returns 204). Parse beacon JSON, extract JTI from cookie, forward to
   wafctl via log_append or direct API call.
4. **Inject page collector**: Response filter that inserts the inline script into
   HTML responses when a valid challenge cookie is present. ~400 bytes, injected
   before `</body>`.
5. **Cookie denylist check**: Extend `validateChallengeCookie()` to check a JTI
   denylist (shared memory or file-based, same as jail sync pattern).

### Privacy Considerations

- **No content tracking**: The system tracks navigation paths and timing, never page
  content, form inputs, or personal data. Scroll depth is a percentage, not pixel position.
- **Typed boolean**: Records whether any typing occurred, not what was typed.
- **Session-scoped**: Data is tied to the challenge cookie JTI, which is a random token
  with no PII. Data expires when the cookie expires (default 1h).
- **No cross-origin tracking**: Service worker is scoped to the service's origin only.
- **Opt-in via challenge**: Only installed for users who triggered a challenge rule.
  Non-challenged traffic is completely unaffected.

## What This Catches

| Attack Pattern | Current Detection | With Session Tracking |
|---|---|---|
| Bot lands, idles 5-10s, clicks once, leaves | **Missed** — passes challenge, low volume | **Caught** — single-page session, no scroll/interaction |
| Slow scraper: one page per minute, different paths | **Missed** — below rate limit | **Caught** — uniform dwell, no scroll, no interaction |
| AI crawler with real Chrome: passes all JS probes | **Missed** — bot score < 70 | **Caught** — navigation graph anomaly (systematic path pattern) |
| Cookie harvesting: solve once, replay from curl | **Caught** — JA4/IP binding | Still caught (plus: no session beacons = JTI flagged) |
| Real user browsing normally | **Passes** | **Passes** — high page count, varied dwell, scroll, clicks |

## What This Does NOT Catch

- **Bots that perfectly mimic multi-page browsing** — if a bot visits 10+ pages with
  varied dwell times, scrolls, and clicks, session tracking won't flag it. This is
  the arms-race ceiling. Defense: the cost of mimicking a full session is high enough
  to make scraping uneconomical at scale.
- **API-only scraping** — if bots hit API endpoints directly (not HTML pages), the
  service worker and page collector never load. Defense: API endpoints should have
  their own rate limiting and authentication.
- **First-request extraction** — if the bot extracts everything it needs from the
  challenge interstitial response itself (before JS runs). Defense: the interstitial
  doesn't contain site content.

## Effort Estimate

| Component | Scope | Est. Lines | Est. Time |
|---|---|---|---|
| session-sw.js (embedded) | New file in plugin | ~80 | 0.5 days |
| Page-level collector (inline) | New template in plugin | ~40 | 0.5 days |
| SW registration + injection | Plugin: interstitial + response filter | ~100 | 1 day |
| Beacon endpoint handler | Plugin: new handler + log_append | ~60 | 0.5 days |
| SessionStore (wafctl) | New store + scoring pipeline | ~400 | 2 days |
| Session scoring algorithm | Rule-based scorer in wafctl | ~150 | 1 day |
| Cookie denylist + invalidation | Plugin + wafctl sync | ~100 | 1 day |
| API endpoints (session stats) | wafctl handlers | ~200 | 1 day |
| Dashboard: session analytics tab | React component | ~300 | 1.5 days |
| E2E + Playwright tests | Test both repos | ~300 | 1.5 days |
| **Total** | | **~1,730** | **~10.5 days** |

## Implementation Phases

```
Phase 1 (Foundation)     → Phase 2 (Scoring)      → Phase 3 (Actions)
SW + page collector         SessionStore + scoring     Cookie invalidation
Beacon endpoint             API endpoints              Reputation integration
Log pipeline                Dashboard tab              Auto-escalation
                                                       E2E tests
```

**Phase 1** (4 days): Get the data flowing. SW registration, page collector injection,
beacon endpoint, session data in access logs. No scoring yet — just observe.

**Phase 2** (3 days): Session scoring pipeline, API endpoints, dashboard analytics tab.
Review real-world session data to tune thresholds before enabling actions.

**Phase 3** (3.5 days): Cookie invalidation, reputation system integration,
auto-escalation rules, comprehensive tests.

## Open Questions

1. **SW registration timing**: Register during interstitial (before PoW solve) or
   after redirect (on the real page)? During interstitial is simpler but the SW
   scope might conflict with the interstitial path. After redirect requires an
   inline script on the first real page load.

2. **Response filter injection**: The page collector script must be injected into
   HTML responses. The policy engine already has response header modification —
   body injection is a new capability. Options: (a) Caddy's `templates` handler,
   (b) custom response writer that appends before `</body>`, (c) service worker
   injects via DOM manipulation (no server-side change needed).

3. **Beacon delivery to wafctl**: The beacon hits Caddy (plugin). Options:
   (a) Plugin writes to access log via `log_append`, wafctl reads from log
   (existing pipeline), (b) Plugin forwards to wafctl API directly (requires
   new inter-service communication), (c) Plugin writes to a shared file
   (same pattern as jail sync).

4. **JTI denylist propagation**: Cookie invalidation requires the plugin to know
   which JTIs are suspended. Options: (a) File-based denylist (same as jail.json),
   (b) Caddy admin API push from wafctl, (c) inline in policy-rules.json
   (problematic — changes on every invalidation).

5. **False positive threshold**: The scoring algorithm needs real-world calibration.
   Phase 2 should run in observe-only mode for at least a week before enabling
   Phase 3 actions.

6. **Service Worker lifetime and `setInterval`**: The SW spec states that "the
   lifetime of a service worker is tied to the execution lifetime of events and
   not references held by service worker clients." This means `setInterval` in
   a SW is unreliable — the browser may terminate the SW between `fetch` events.
   The heartbeat flush in the pseudocode uses `setInterval(flushBeacon, 30000)`
   which may not fire if the SW is terminated. Alternative: flush on every
   navigation `fetch` event instead of relying on timers, or use the page-level
   collector's `visibilitychange` beacon as the primary flush mechanism.

7. **`Service-Worker-Allowed` header**: The plugin must serve the session-sw.js
   with `Service-Worker-Allowed: /` header. Without this, registration with
   `{scope: '/'}` will be rejected by the browser because the script URL is
   under `/.well-known/policy-challenge/` which is more restrictive than `/`.

## References

### Academic

- Zhang, R. et al. "Identifying Incoherent Search Sessions: Search Click Fraud
  Remediation Under Real-World Constraints." IEEE S&P 2025.
  DOI: 10.1109/SP61157.2025.00111
- Zhang, J. et al. "Session2vec: Session Modeling with Multi-Instance Learning
  for Accurate Malicious Web Robot Detection." Electronics 2025, 14(10), 1945.
  DOI: 10.3390/electronics14101945
- Kadel, J. et al. "BOTracle: A Framework for Discriminating Bots and Humans."
  ESORICS-W 2024 (Adobe Research). arXiv: 2412.02266
- Lucz, G. & Forstner, B. "Weighted Transformer Classifier for User-Agent
  Progression Modeling, Bot Contamination Detection, and Traffic Trust Scoring."
  Mathematics 2025, 13(19), 3153.
- Canay, O. & Kocabicak, U. "Predictive Modeling and Anomaly Detection in Large-Scale
  Web Portals Through the CAWAL Framework." arXiv:2502.00413, 2025.
  (Submitted to Knowledge-Based Systems.)
- Gayathri, K. V. "User Behavior Tracking and Bot Detection Using Machine Learning."
  IJSREM 2025, 09(12). DOI: 10.55041/IJSREM55348
- Bolukonda, D. et al. "Anomaly Detection through Behavior Analysis: A Deep
  Learning Approach." ICITSM 2025. DOI: 10.4108/eai.28-4-2025.2357761

### Web Standards

- W3C Service Workers (CRD 2026-03-12): https://www.w3.org/TR/service-workers/
- W3C Beacon API (CRD 2022-08-03): https://www.w3.org/TR/beacon/
- W3C Navigation Timing Level 2 (WD 2022-01-17): https://www.w3.org/TR/navigation-timing-2/
- W3C Reporting API (WD 2025-06-11): https://www.w3.org/TR/reporting-1/
- HTML Living Standard, Section 6.2 "Page visibility":
  https://html.spec.whatwg.org/multipage/interaction.html#page-visibility
- W3C Page Visibility Level 2 (CR 2022-06-23, superseded by HTML Living Standard):
  https://www.w3.org/TR/page-visibility-2/

### Industry

- Cloudflare: "Building unique, per-customer defenses against advanced bot threats in
  the AI era." (2025-09-23) https://blog.cloudflare.com/per-customer-bot-defenses/
- Cloudflare: "Bot detection engines" (developer docs)
  https://developers.cloudflare.com/bots/concepts/bot-detection-engines
- Arcjet: "Advanced bot signals" (docs)
  https://docs.arcjet.com/bot-protection/advanced-signals
- Arcjet: "Detecting Bots, Scraping, and AI-driven Abuse at the Application Layer."
  (2026-02-10) https://blog.arcjet.com/detecting-bots-scraping-and-ai-driven-abuse-at-the-application-layer/
- Cloudflare: "Improved Bot Management flexibility and visibility with new
  high-precision heuristics." (2025-03-19)
  https://blog.cloudflare.com/bots-heuristics

### Evasion Analysis (Know Your Enemy)

- Aggarwal, A. "Advanced Evasion Techniques and Architecture Analysis of Cloudflare
  Bot Management Systems in 2026." Medium, 2026-02-24.
- Browserless: "Anti-Detection Techniques: 2026 Comprehensive Guide." 2026-03-13.
  https://www.browserless.io/blog/anti-detection-techniques-2026-guide
- Castle.io: "Bot detection 101: How to detect bots in 2025?" 2025-03-25.
  https://blog.castle.io/bot-detection-101-how-to-detect-bots-in-2025-2/

---

## Appendix: Existing Challenge Dashboard Bugs (Fix Alongside)

Two bugs in the current challenge analytics dashboard should be fixed as part of this
work, since we'll be touching the same code paths.

### Bug 1: "Unknown" Fail Reason in Breakdown

**Symptom**: The Fail Reason Breakdown shows a large "Unknown" bar alongside "Invalid
PoW Hash."

**Root Cause**: The plugin (`caddy-policy-engine`) never sets the Caddy variable
`policy_engine.challenge_fail_reason`. The Caddyfile captures it via `log_append`, but
the value is always empty in the access log. The wafctl side has `inferChallengeFailReason()`
as a heuristic fallback (runs during `AccessLogStore.Load()`), but the challenge analytics
endpoint (`challenge_analytics.go:287-291`) reads from events that may not have been
enriched yet, or where the inference returned `""`:

```go
// challenge_analytics.go:287-291
if e.ChallengeFailReason != "" {
    failReasons[e.ChallengeFailReason]++
} else {
    failReasons["unknown"]++  // ← this is what the dashboard shows
}
```

**Fix — two parts**:

1. **Plugin (caddy-policy-engine)**: Set `policy_engine.challenge_fail_reason` as a
   Caddy variable in `handleChallengeVerify()` at each rejection point. The plugin
   already knows the exact reason at the point of rejection:
   - Missing fields → `"missing_fields"`
   - Invalid difficulty/nonce → `"bad_input"`
   - Timestamp expired → `"payload_expired"`
   - HMAC mismatch → `"hmac_invalid"`
   - Hash mismatch → `"bad_pow"`
   - Insufficient leading zeros → `"bad_pow"`
   - Impossibly fast timing → `"timing_hard"`
   - Bot score >= 70 → `"bot_score"`

2. **wafctl (challenge_analytics.go)**: The `"unknown"` fallback should also run
   `inferChallengeFailReason()` inline rather than emitting "unknown":
   ```go
   if e.ChallengeFailReason != "" {
       failReasons[e.ChallengeFailReason]++
   } else {
       inferred := inferChallengeFailReason(rleFromEvent(e))
       failReasons[inferred]++
   }
   ```

### Bug 2: Challenge Timeline Squished to Thin Line

**Symptom**: The Challenge Timeline sparkline shows all data as a thin line at the bottom
of the chart, with no visible variation between bars.

**Root Cause**: In `ChallengeAnalytics.tsx`, the `Timeline` component (line 97-138) uses
a CSS percentage-height approach where the container is `h-24` (96px) and each bar's height
is `max(rawHeight, 15)%`. When all hours have similar low counts (e.g., 1-3 events/hour
for 24 hours), every bar hits the 15% minimum floor, producing a visually flat line at
~14px height with no visible differentiation.

The underlying issue: percentage-based heights don't work well when all values cluster
at the minimum. The chart needs either:
- A logarithmic scale for the height mapping
- Or a different minimum height strategy that preserves relative differences

**Fix**: Replace the current percentage-based height with a normalized approach that
uses the full chart height. When all values are similar, bars should fill more of the
chart and show relative differences:

```tsx
// Replace lines 113-114:
const rawHeight = (total / maxVal) * 100;
const height = total > 0 ? Math.max(rawHeight, 15) : 0;

// With:
const height = total > 0 ? Math.max((total / maxVal) * 100, 20) : 0;
```

Additionally, when `maxVal` is very small (< 10), normalize to a minimum max to spread
the bars:

```tsx
const effectiveMax = Math.max(maxVal, 5); // prevents all bars from being 100%
const height = total > 0 ? Math.max((total / effectiveMax) * 100, 20) : 0;
```

This ensures that even with low event counts, the chart shows meaningful height
variation. A maxVal of 5 when events are 1-3 would produce heights of 20%, 40%, 60%
instead of all being clamped at 15%.
