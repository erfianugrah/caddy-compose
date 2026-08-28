# policy_engine body scan caps request throughput at ~43KB/s

2026-08-29. Found while debugging an atuin sync that projected to ~35 hours.
Not fixed - the atuin vhost was moved to `waf_off` as a workaround. The
underlying plugin cost is still present on every vhost that imports `waf`.

## Symptom

`atuin sync` uploading 36,779 records showed 500 done after 1,702s - roughly
3.4s per record, ETA ~35h. The obvious suspects were all innocent:

| probe | result |
|---|---|
| GET through the full public path (client -> WAN -> caddy -> servarr) | 13ms |
| POST 200KB straight to the upstream `10.0.71.64:8888` | 1ms |
| atuin container CPU during the upload | 0.00% |
| Postgres during the upload | idle, no active queries, no lock waits |
| client `atuin sync` after 25min wall time | 0.06s CPU, parked in `epoll_wait` |

Caddy's own log showed exactly one `POST /api/v0/record` every 3-5s, each one
logged as `policy skip` by the atuin false-positive rule. So the client was
blocked on the request, the server was answering instantly, and the time was
being spent inside caddy.

## Isolation

Same caddy process, same loopback, same 200KB body, two vhosts differing only
in whether they `import waf`:

| path | 200KB POST |
|---|---|
| direct to upstream, no caddy | 1ms |
| `httpbin.erfi.io` - no `import waf` | 11ms |
| `atuin.erfi.io` - `import waf` | 4,680ms |

Cost is linear in body size. Measured totals (one POST each, via loopback);
the ~43KB/s / ~23us-per-byte figure quoted elsewhere is derived by division
from these numbers, not separately instrumented:

| body | total |
|---|---|
| 5KB | 0.11s |
| 10KB | 0.22s |
| 50KB | 1.11s |
| 100KB | 2.24s |
| 200KB | 4.68s |
| 400KB | 9.34s |

The rate is identical whether the verdict is 403 (blocked) or 400 (passed to
the upstream), so it is the scan path itself, not the block path.

## Why the rate is suspicious

The scan is far slower than the rule set should justify:

- `/etc/caddy/waf/default-rules.json` - CRS 4.26.0, 343 rules, 341 enabled.
- Of those, 62 conditions run `regex` against `body` / `response_body` /
  `all_args_values` / `all_args_names`.
- Total pattern text across all of them is ~5.8KB, longest single pattern 777
  bytes.

62 regexes over 200KB should be single-digit milliseconds, not the ~4.7s
measured above. That points at the body-read path in `caddy-policy-engine`
(pinned `v0.42.3` in the Dockerfile) - per-byte allocation or unbuffered reads -
rather than at regex evaluation cost. NOT YET CONFIRMED: the plugin source has
not been read. Anyone picking this up should start there before tuning rules,
because dropping rules will not fix a per-byte overhead.

Note the custom rule file (`/data/waf/policy-rules.json`) held only 2 rules at
the time, so "the WAF is basically off" was true of the custom rules and still
irrelevant - `import waf` pulls in the CRS default set regardless.

## Scope - who else pays this

Measured 2026-08-29, 200KB POST, via loopback:

| vhost | 200KB POST |
|---|---|
| `vault.erfi.io` | 4.88s |
| `joplin.erfi.io` | 4.79s |
| `docs.erfi.io` | 4.84s |

7 vhosts still `import waf`; 37 already use `waf_off`. The three above take
large request bodies in normal use. `vault.erfi.io` is the one to watch:
attachment uploads and a cold vault sync both post large bodies, so the same
tax applies there for real users, not just in a synthetic probe.

## Workaround applied

`atuin.erfi.io` switched `import waf` -> `import waf_off` (commit 9beb6bc).
Result on the same 200KB body: 4,680ms -> 19ms. 400KB: 9,340ms -> 21ms.

This is defensible for atuin specifically, and the reasoning does NOT
generalise: atuin sync payloads are client-side-encrypted opaque ciphertext, so
CRS body regexes have nothing to match, and the endpoint is authenticated by a
bearer session token. Do not copy the change to a vhost that serves
attacker-reachable unauthenticated form/JSON input without re-justifying it.

## Real fix options, in order of preference

1. Read the plugin's body handling and fix the per-byte overhead. Restores
   inspection everywhere and needs no per-site opt-outs.
2. Add a body-size ceiling to `policy_engine` - skip (or stream-scan) bodies
   above some threshold. CRS body rules mostly target small injection
   payloads, so a ceiling in the tens of KB loses little.
3. Keep per-vhost `waf_off` for authenticated, opaque-payload APIs only. What
   is in place today; leaves the tax on every other large-POST vhost.

## Reproducing

```bash
head -c 200000 /dev/zero | tr '\0' 'a' > /tmp/b200
scp /tmp/b200 router:/tmp/b200

# with waf
ssh router 'curl -sk -o /dev/null -w "%{http_code} %{time_total}\n" \
  --resolve vault.erfi.io:443:127.0.0.1 -X POST https://vault.erfi.io/ \
  -H "Content-Type: application/json" --data-binary @/tmp/b200'

# without waf (control)
ssh router 'curl -sk -o /dev/null -w "%{http_code} %{time_total}\n" \
  --resolve httpbin.erfi.io:443:127.0.0.1 -X POST https://httpbin.erfi.io/post \
  -H "Content-Type: application/json" --data-binary @/tmp/b200'
```
