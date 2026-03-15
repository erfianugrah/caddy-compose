# PLAN.md — Policy Engine Roadmap

## Current State (v2.33.0 / caddy 3.32.0 / plugin v0.17.0)

Fully operational WAF with custom policy engine, CRS 4.24.1 (313 rules: 254 inbound +
59 outbound), 6-pass evaluation (allow → block → skip → rate_limit → detect →
response_header), unified rule store (`/api/rules` + `/api/deploy`), response-phase
support for all rule types, structured CORS (preflight + origin validation), rule
templates, per-service category masks, outbound anomaly scoring + rate limiting,
incremental summary (O(hours)), managed lists, IPsum blocklist (618K IPs), CRS
auto-update workflow, and e2e CI pipeline (116 e2e tests, 500 Go tests, 326 frontend).

---

## Pending Work

### CRS Converter Fidelity

CRS regression: 90.8% (216/238 rules). 22 failures:
- 9 Go http client limitations (can't send malformed HTTP)
- 9 correct detections with different status (403 vs expected 400)
- 13 false positives from CRS exclusion chains not translated by converter
- 1 genuine miss (920521)

Root cause: CRS uses chained rules with `ctl:ruleRemoveByTag` to suppress
false positives in specific contexts. The converter doesn't translate these chains,
causing 4 rules (932236, 932260, 941130, 942200) to over-match on `request_combined`.

**To improve:**
- [ ] Translate CRS exclusion chains (SecRule chain semantics)
- [ ] Per-variable evaluation instead of concatenated `request_combined` for rules
      that check fewer than the full variable set
- [ ] Target: 95%+ detection rate

### WebSocket + Stream Deep Inspection (Long-Term)

MITM proxy for WebSocket frame inspection and SSE event inspection. Design complete
(RFC 6455 frame parsing, hijack-and-wrap pattern, blocking/tap modes). See prior art
from tailscale, K8s streamtunnel, goproxy.

**Implementation phases (~11 days estimated):**
1. WebSocket frame parser (RFC 6455): read/write, masking, fragmentation
2. MITM proxy: intercept upgrade, dial upstream, bidirectional pump
3. Frame inspection: extract payload, run against compiled conditions
4. SSE wrapper: intercept Writer, parse events, inspect
5. Connection-level rate limiting: frames/sec per connection
6. wafctl: `ws_message`, `sse_event` fields, `phase: "stream"` UI
7. E2E tests

### Production Deployment

- [ ] Run `scripts/setup-cors.sh` to configure production CORS origins
- [ ] Apply cache-static-assets template via `/api/rules/templates/cache-static-assets/apply`
- [ ] Verify CORS preflight + origin validation in production
- [ ] Monitor event store disk/memory usage (see README sizing guide)
