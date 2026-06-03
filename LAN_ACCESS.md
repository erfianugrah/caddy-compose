# LAN access to Caddy via public hostnames

Caddy on `servarr` (10.68.71.2) is reached from LAN clients via the
**public hostname** (e.g. `https://httpbun.erfi.io`) rather than the
internal IP. The redirect happens at the network layer on VyOS — Caddy
is unaware that the request came via NAT hairpin.

## Request path

```
LAN client (10.68.69.18, eth2)
   │
   │ 1. DNS: httpbun.erfi.io → 118.189.189.102  (Pi-hole answers truthfully;
   │                                              same as any public resolver)
   │
   ▼
118.189.189.102:443  (home WAN, but the packet never leaves the LAN)
   │
   │ 2. VyOS DNAT rule 15 (or 16/17/18/19, depending on ingress interface):
   │    dst=118.189.189.102:80,443 → dst=10.68.71.2 (port preserved)
   │
   ▼
Caddy on 10.68.71.2:443
   │
   │ 3. TLS handshake (incl. ECH), HTTP request handled normally
   │
   │ 4. Response: src=10.68.71.2 → dst=10.68.69.18
   │    But the client sent its SYN to 118.189.189.102 and expects the
   │    response source to match.
   │
   ▼
VyOS L3 gateway (cross-VLAN routing 10.68.71.0/24 → 10.68.69.0/24)
   │
   │ 5. Conntrack un-DNATs the source: src=10.68.71.2 → src=118.189.189.102
   │    (this works because VyOS routes between the two VLANs and sees
   │     the return packet)
   │
   ▼
Client receives response from 118.189.189.102 ✓ connection completes
```

## What Caddy sees

**Real client IPs.** No SNAT masquerade is in play. `X-Forwarded-For`,
`X-Real-IP`, and the connection's `RemoteAddr` all carry the actual
LAN IP of the client (10.68.69.x / 10.68.70.x / 10.68.73.x).

Practical consequences:

- WAF and `ddos-mitigator` plugins can rate-limit and ban specific LAN
  clients without false collateral damage on others.
- Authelia session cookies carry truthful client IPs for the session
  store.
- Caddy access logs are useful for forensics.
- `trusted_proxies` does NOT need to include VyOS interface IPs
  (10.68.71.1 etc.) — Caddy is the direct server on the hairpin path,
  not behind a reverse proxy. (Tailscale → composer → Caddy trust hops
  are a separate concern.)

## ECH compatibility

ECH (Encrypted Client Hello) — configured via `ech ech.erfi.io` in the
Caddyfile — works transparently through hairpin:

- The HTTPS RR (SVCB) for any erfi.io subdomain published at Knot
  includes the ECH config blob.
- LAN-side clients resolve to the same record as public clients
  (Pi-hole returns identical answers to 1.1.1.1 / 8.8.8.8 / public DoH).
- Clients fall back to A-record lookup → 118.189.189.102 → hairpin → Caddy
- TLS+ECH handshake proceeds normally on the inner connection.

No special Caddyfile configuration is needed for LAN clients vs.
internet clients — they're indistinguishable to Caddy.

## Failure modes — what each symptom means

| Symptom | Likely cause |
|---|---|
| Caddy logs show source IP `10.68.71.1` (or similar VyOS VLAN interface IP) | VyOS has a SNAT source rule active for the hairpin path. Drop it — cross-VLAN routing doesn't need SNAT. |
| `https://*.erfi.io` 404s from LAN but works from internet | Pi-hole is lying via a `dnsmasq_lines` wildcard or `/etc/dnsmasq.d/*.conf` inside the container is answering `10.68.71.2`. The client never reaches the hairpin DNAT because it's already at the internal IP, hitting whatever default vhost Caddy has. |
| `https://gloryhole.erfi.io` returns a servarr-Caddy 404 instead of Glory-Hole on Fly | Same root cause — Pi-hole wildcard catching a subdomain that's not on servarr. |
| Connection timeout from LAN, works externally | DNAT rule missing for the client's ingress VLAN. VyOS 1.3 requires one rule per LAN interface (`eth2`, `eth2.100`, `eth2.200`, `eth1`, `eth3`). |
| `X-Forwarded-For` shows `127.0.0.1` or empty | Caddy is not configured to read the trusted proxy header from upstream (Tailscale Funnel, composer, etc.) — unrelated to hairpin. |

## What this means for Caddyfile authoring

- Add a new `.erfi.io` site block → just publish the A record at Knot.
  No Pi-hole edits, no VyOS edits. LAN access works automatically as
  long as the host resolves to `118.189.189.102`.
- Migrate a site to Fly (e.g. `gloryhole.erfi.io` at `137.66.1.170`) →
  same answer. Update the A record at Knot, LAN clients will egress
  to Fly normally (the DNAT rule only matches
  `dst=118.189.189.102`).
- Internal-only service that should NOT be reachable from the
  internet → that's a firewall job (block at the WAN ingress), not a
  hairpin concern.

## Authoritative network config lives elsewhere

The VyOS NAT rules, Pi-hole state, and the architectural rationale are
documented in:

- `~/vyos/network-architecture.md` — SG router config, with validation
  recipes and history.
- `~/vyos-nl/network-architecture.md` — generic playbook for replicating
  the design in other locations.
