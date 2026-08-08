# 2026-08-08 - edge TLS outage: ja4 listener accept-loop wedge

**Status**: fixed in caddy-policy-engine v0.42.2, image `erfianugrah/caddy:3.97.1-2.11.4`.
**Impact**: all TLS on the edge :443 hung for ~70 min; vault.erfi.io unreachable (bw unlock hung), plus every other edge-fronted service.

## Summary

A client opened a TCP connection to the edge :443 and sent nothing. The `ja4`
listener wrapper reads the ClientHello **synchronously inside `Accept()`** with
no read deadline, and Go's `net/http` accept loop is serial - so one silent
connection parked the accept loop and every TLS handshake behind it hung until
the caddy container was restarted.

The deadline that would normally bound this (caddy-l4's matching-phase read
deadline) is **cleared by caddy-l4 as soon as its route matches** - and the
production route (`ddos_mitigator`) has no byte matchers, so it matches
instantly. The ja4 peek therefore ran with no deadline at all.

## Timeline (SGT)

| Time | Event |
|---|---|
| ~05:55 | Last successful TLS request before the wedge (access log) |
| 06:35 | First symptom: `bw unlock` hangs after the master-password prompt (that's where it first talks to vault.erfi.io) |
| 06:53 | Second attempt fails with a local crypto error (wrong key material after the interrupted first attempt) |
| ~07:05 | Diagnosis: TCP connects fine (loopback, LAN, WAN), port 80 fine, only TLS hangs. pprof: **353 goroutines** stuck in `caddy-l4 pipeConnection` (listener.go:218, blocking send to `connChan`), 1 stuck in `ja4Listener.Accept -> readClientHello` (ja4.go:61, `io.ReadFull`) |
| 07:12 | `docker restart caddy` - immediate recovery |
| 07:20-07:35 | Wedge **reproduced deterministically** with the production image + production wrapper chain in a throwaway container: one silent conn -> real handshake times out; release -> instant recovery. Same pprof signature |
| 07:40-08:10 | Fix implemented under a self-correcting loop (sensor-gated, 1 iteration); runtime gate red at baseline, green after |
| 08:24-08:30 | Image build + push. Trivy gate caught `golang.org/x/text` v0.38.0 (CVE-2026-56852, HIGH) -> added `--replace golang.org/x/text@v0.39.0`. Pushed `3.97.1-2.11.4` |
| 08:46:35 | **Unrelated event**: i40e NIC (`enp2s0f0np0`, LAN trunk to the XikeStor switch) lost link and never regained it; site-wide LAN/internet loss. Router manually rebooted 08:48, link up 08:49:24. Probes prove this was NOT deploy-related - the deploy was done by ~08:30 and every 60s probe was green across the whole window |
| pending | `make sync restart REMOTE=nixos COMPOSER_CONTAINER=composer` (blocked on `COMPOSER_API_KEY`, which lives in the bw vault) |

## Root cause (mechanism)

Wrapper chain on :443 (deploy/edge/Caddyfile):

```
listener_wrappers {
    layer4 { route { ddos_mitigator { jail_file ... } } }   # no byte matchers
    ja4                                                      # synchronous ClientHello peek
    tls
}
```

1. `http.Server.Serve` accepts **serially**: `Accept -> tls -> ja4 -> layer4`.
2. caddy-l4 sets a read deadline for the matching phase, but `routes.go`
   clears it ("remove deadline after we matched") as soon as a route matches.
   The ddos route matches on IP metadata alone - instantly - so the deadline
   is gone before the conn reaches ja4.
3. `ja4Listener.Accept()` -> `readClientHello()` -> `io.ReadFull` with **no
   deadline of its own**. A silent or drip-feeding conn blocks here forever.
4. Every new conn piles up in caddy-l4's `connChan` (capacity GOMAXPROCS),
   then in `pipeConnection` goroutines (353 at diagnosis time). Port 80 is
   unaffected (ja4 fails fast on plaintext bytes).

The trigger connection is unidentifiable retroactively: that layer logs
nothing (l4 `connection stats` is Debug-level) and conntrack state died with
the restart. Trigger class: scanner/slowloris/half-open peer.

## Fix (caddy-policy-engine v0.42.2)

- `ja4_listener.go`: `clientHelloPeekTimeout = 2s`; `Accept` sets its own read
  deadline around the peek and clears it immediately after (a lingering
  deadline would kill slow-but-legitimate handshakes later). Timeout takes the
  existing fail-open path: rewind bytes read, pass conn through.
- `ja4.go`: `readClientHello` error returns now carry only bytes actually read
  (`hdr[:n]`, `payload[:m]`) - previously the fail-open rewind could inject
  zero padding into a live drip-fed stream and corrupt a valid late handshake.
- `TestJA4Listener_SilentConnDeadline`: silent conn must not park Accept >3s;
  post-timeout bytes arrive intact; valid ClientHello still fingerprints.
- `test/ja4-accept-deadline.sh`: runtime gate - builds caddy with the local
  plugin into the production image, parks a silent conn, requires a real
  handshake to complete. Red at baseline, green after the fix.
- `.pi/harness.json`: self-correcting-loop manifest (guards + both feature
  sensors) so the gate is repeatable.

**Rule going forward: any byte read in the accept path must carry its own
deadline. Never rely on deadline state leaking from another layer.**

## Follow-ups

- [ ] Deploy: `make sync restart REMOTE=nixos COMPOSER_CONTAINER=composer`
      (needs `COMPOSER_API_KEY` from the bw vault), then verify with the
      silent-conn probe against prod (worst case now: 2s delay, not a hang).
- [ ] Makefile `REMOTE ?= servarr` is stale - composer moved to the MS-01
      router; default should be `nixos`.
- [ ] 08:46 trunk event: `i40e ... NIC Link is Down` with no preceding driver
      error points at the far end (switch port/reboot), but the switch CLI was
      locked out (failMax) so uptime/port state is unverified.
- [ ] flint (iot VLAN, 10.0.72.2) did not come back after the trunk event -
      ARP FAILED, no kea lease. Needs switch port check or power cycle.
- [ ] Consider enabling l4 `connection stats` at info level (or a
      stuck-goroutine alert on the admin pprof) so the next wedge is
      attributable without a restart destroying the evidence.
