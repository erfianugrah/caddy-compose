# Edge cache (Souin) removed - 2026-08-07

The Souin/`cache-handler` layer is out of `deploy/edge/Caddyfile`. The plugin is
still compiled into the image and `test/cache` still runs, so this is a config
removal, not a teardown. Everything needed to put it back is below.

## What was removed

| Where | What |
|---|---|
| global options | `order cache after policy_engine`, and the app-level `cache {}` (ttl 60s, `default_cache_control no-store`, `api { souin prometheus }`) |
| `docs.erfi.io` | whole-site cache, 5m/24h, `key { disable_query }`, `nuts` dir `docs` |
| `jellyfin.erfi.io` | `route @jf_images` around `/Items/*/Images/*`, 24h/72h, `nuts` dir `jellyfin` |
| `navidrome.erfi.io` | `route @nf_covers` around `/rest/getCoverArt*`, 24h/72h, `nuts` dir `navidrome` |
| `erfianugrah.com` | whole-site cache, `key { disable_query }`, `nuts` dir `erfianugrah` |
| `revista.erfi.io` | whole-site cache, `key { disable_query }`, `nuts` dir `revista` |

86 lines. The two `route @...` wrappers went with their cache blocks, since the
cache was their only content, and the orphaned `@jf_images` / `@nf_covers`
matchers went with them.

The on-disk databases under `/data/cache/nuts/` on the edge are **left in
place**. They are inert with no handler attached, and keeping them means a
revert does not start cold. Delete them if the space is wanted:
`docker exec caddy rm -rf /data/cache/nuts`.

## Why now

The post-deploy gate had stopped being trustworthy, and that is a worse state
than not having a cache.

### The bug that surfaced it: `cachectl verify` asserts the wrong file

`tools/cachectl/verify.go:58` checks `test -f <dir>/0.dat` as the liveness
marker for each configured `nuts` dir. nutsdb names its segment files
`<fileID>.dat`, starting at 0 and incrementing when a segment fills
(`SegmentSize`); merged and compacted segments are removed. So a namespace that
has written enough to roll over no longer has `0.dat` and the gate fails.

Observed live on 2026-08-07:

```
/data/cache/nuts/docs/         0.dat  bucket.Meta  nutsdb-flock
/data/cache/nuts/erfianugrah/  0.dat  bucket.Meta  nutsdb-flock
/data/cache/nuts/jellyfin/     0.dat  bucket.Meta  nutsdb-flock
/data/cache/nuts/navidrome/    4.dat  bucket.Meta  nutsdb-flock   <- healthy, gate said FAIL
/data/cache/nuts/revista/      0.dat  bucket.Meta  nutsdb-flock
```

`navidrome` caches cover art, the largest payloads of any namespace here, so it
rolled first. The gate therefore failed on the busiest, healthiest cache - and
would have failed on every other namespace in turn as each rolled over. A gate
that reddens on success trains you to ignore it, which is exactly what happened:
`make edge-restart` was already exiting non-zero before this session's unrelated
Caddyfile change, and the red was being read as background noise.

`verify.go:66` has the same latent flaw on `/tmp/souin-nuts/0.dat`. It matters
less (a freshly-trapped tmpfs DB is on segment 0) but a long-running trapped DB
would roll past it and the check would stop catching the incident it exists for.

### Not fixed, deliberately

The fix is small - glob `*.dat`, or assert on `bucket.Meta`, which nutsdb writes
at DB open and which never rolls. It was not done because fixing the gate for a
cache we are switching off is work in the wrong direction. Do it as part of
turning the cache back on, along with a test case covering a rolled-over segment
so it cannot regress.

## Other issues carried into the revert

- The three storage bugs from the 2026-07-31 incident are documented in
  `test/cache/README.md` and the config pattern that avoids them was correct in
  every site block at removal time (per-site `nuts{}`, unique `Dir`, `Dir`
  inside `configuration{}`, `HintKeyAndRAMIdxMode`). Nothing here supersedes
  that; restore that pattern verbatim.
- `stale-if-error` in `default_cache_control` was load-bearing on `docs`,
  `jellyfin` and `navidrome` for origin-down insurance. Removing the cache
  removes that insurance: those sites now fail hard when their backend is down
  rather than serving stale. This is the main functional regression.
- `key { disable_query }` on the three whole-site caches was a
  cache-amplification guard, not an optimisation - arbitrary `?spam=N` on a
  public site with no query validation upstream mints unbounded entries. Any
  restoration must keep it.

## Restoring

`git revert` the removal commit, or lift the blocks out of it. Then:

1. `make edge-restart`
2. `make edge-verify-cache` - expect the `0.dat` false positive on any namespace
   that rolled over; fix the assert before trusting the output
3. `make test-cache` (71 tests) for the behavioural contract

Deploy path and the `Cache-Status` diagnostics are unchanged - see
`test/cache/README.md`, which remains project truth for Souin behaviour.
