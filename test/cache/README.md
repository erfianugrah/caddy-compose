# Cache loop-test harness

Local runtime test suite for the edge Caddy HTTP cache
(`caddyserver/cache-handler` / Souin core, with `darkweak/storages/nuts` as
the on-disk storage backend). Exercises the *actual* prebuilt `caddy`
binary against a controllable Python origin - no Docker, no network egress,
deterministic and safe to re-run.

Versions under test (pinned in `../../Dockerfile`):

- `github.com/caddyserver/cache-handler@v0.16.0` (Souin core = our fork
  `github.com/erfianugrah/souin@v1.7.7-erfi.1`,
  `github.com/darkweak/storages/core@v0.0.15`)
- `github.com/darkweak/storages/nuts/caddy@v0.0.19` (nutsdb `v1.0.4`)
- Caddy `v2.11.4`

(The quirks below were first characterized reading `caddy/v2@v2.11.3`
source; the suite last ran green against `erfianugrah/caddy:3.97.0-2.11.4`
on Caddy `v2.11.4` - the behaviors are unchanged across the 2.11.3 ->
2.11.4 bump.)

## Running

```sh
./test/cache/run-tests.sh [label]
```

- `label` is just a string echoed in the final result line (the harness
  passes `loop` when run from the self-correcting-loop sensor).
- The script is fully self-contained: it wipes `.work/nuts` and the origin
  hit log at the start of every run, starts the origin (`origin.py`) and
  caddy, runs all assertions, and kills both at the end.
- Exit code is `0` iff every assertion passed (`set -u`, explicit
  `[ "$FAIL" -eq 0 ]` at the end).
- Ports used: `8090` (origin), `8091` (docs.erfi.io-shape site), `8092`
  (jellyfin.erfi.io-shape site), `2021` (Caddy admin). All are freed on
  exit via `cleanup()`, which kills by PID only (never `pkill -f` - that
  would match the test script's own argv under `bash -x` style tracing and
  kill the run itself).
- `.work/caddy` is a **prebuilt** binary extracted once from the built
  image - the suite never invokes `docker build`. The image is the
  `IMAGE` var at the top of `run-tests.sh`, which defaults to the
  `CADDY_IMAGE` from the `Makefile` (currently
  `erfianugrah/caddy:3.97.0-2.11.4`) and is overridable via the
  `CADDY_IMAGE` env var. If `.work/caddy` is missing it's re-extracted
  from that image via `docker create` + `docker cp`; it is never deleted
  by the suite itself (delete it manually after an image bump to
  re-extract the fresh binary).

### Files

- `origin.py` - controllable origin server. Logs every request (one line
  per hit, `METHOD path`) to `.work/origin-hits.log` so the suite can
  assert exact origin-fetch counts (proving cache hits actually skip the
  origin, not just that the response looked right).
- `Caddyfile.test` - mirrors `../../deploy/edge/Caddyfile`'s cache config
  exactly (same directive shapes, same site patterns for the docs vs.
  jellyfin cases) but with `ttl 2s` / `stale 1h` instead of production
  values, so TTL expiry is testable in seconds instead of hours.
- `run-tests.sh` - the suite itself.
- `adapt-edge.sh` - separately validates the **production**
  `deploy/edge/Caddyfile` inside the built image (`caddy adapt --validate`
  with dummy secrets) - a syntax/module-graph check, not a behavioral one.

### Debugging a failure

`Caddyfile.test`'s `cache { log_level debug }` directive is **inert** -
see the "log_level debug does nothing" quirk below. To get verbose Souin
logs when investigating a failure locally, run caddy with a global `debug`
directive added to a scratch copy of `Caddyfile.test` (do **not** add this
to the checked-in file or to production - it's extremely verbose):

```sh
cp test/cache/Caddyfile.test /tmp/Caddyfile.debug
sed -i '1a\	debug' /tmp/Caddyfile.debug
NUTS_PATH=test/cache/.work/nuts test/cache/.work/caddy run \
  --config /tmp/Caddyfile.debug --adapter caddyfile
```

This elevates Caddy's own log level, which is what the `ctx.Logger()`
loggers used by both `admin.api.souin` and `storages.cache.nuts` respect
(unlike the cache-handler middleware's own logger - see below).

## What each section tests

1. **Miss -> hit -> TTL expiry** (`:8091`, docs.erfi.io shape): cold GET
   forwards and stores, warm GET hits, after `ttl` elapses the entry is
   forwarded again, then hits again. Confirms the origin was only ever
   actually contacted twice, not four times.
2. **Upstream `Cache-Control` respected in strict mode**: `no-store` and
   `private` responses are never cached, even though the site config has
   `default_cache_control`. Confirms `default_cache_control` is a
   *fallback* used only when the origin doesn't send its own
   `Cache-Control`, not an override.
3. **POST is never cached and doesn't poison the GET cache key.**
4. **Route-scoped cache, per-token keying** (`:8092`, jellyfin.erfi.io
   shape): only `/Items/*/Images/*` is cached, and different `api_key`
   query values produce different cache entries (per-client image cache
   without cross-contamination).
5. **Non-image paths on the jellyfin-shape site are untouched by cache**
   (no `Cache-Status` header at all - the route matcher correctly scopes
   the `cache` handler to image paths only).
6. **stale-if-error**: with the origin killed and the entry past its TTL,
   a request with `Cache-Control: max-stale=3600` is still served (200,
   marked `hit`) from the stale copy instead of failing.
7. **nuts persistence across a caddy process restart.** See the dedicated
   section below - this needed a real fix to the test's *expectation*,
   not the config.
8. **Souin admin API** (`/souin-api/souin`, `/souin-api/metrics`,
   `PURGE /souin-api/souin/<key>`). See "Admin API storers are permanently
   empty" below - documents a real, evidenced upstream limitation.
9. **Direct `PURGE` to a cached URL** (not the admin API). See "Direct
   PURGE is a passthrough, not an admin operation" below.

## Souin/cache-handler behavior quirks discovered

All of the following were confirmed **empirically** against the exact
pinned versions (Caddy `v2.11.3`, `cache-handler v0.16.0`, `storages/nuts
v0.0.19`, nutsdb `v1.0.4`) using this harness, a from-scratch Go program
importing `github.com/darkweak/storages/nuts` directly, and by reading the
actual source of `caddy/v2@v2.11.3` (present in the local Go module cache)
and `cache-handler@v0.16.0` / `souin@v1.7.7` (fetched from GitHub, since
they aren't vendored anywhere on this box). Source references are exact
file paths/line numbers as of those tags; `master` was also diffed for
`admin.go` and is identical, i.e. this is not yet fixed upstream.

### 1. Stale is opt-in, not automatic (test 7's real bug)

The original test 7 assumed that after a caddy restart, a **plain** `GET
/static` would come back as a cache `hit`. It doesn't - and that has
nothing to do with persistence. By the time test 7 runs, `/static`'s
`ttl 2s` has been expired for a long time (tests 1-6 burn well over 6s of
wall clock, including two explicit `sleep 3`s and a `sleep 3` after
killing the origin in test 6). The entry in nuts is *stale*, not fresh.

Souin's request-serving logic
(`souin@v1.7.7` `pkg/middleware/middleware.go` `ServeHTTP`, around lines
751-815) looks up the key and gets back `(fresh, stale)`. If `fresh` is
nil (line 761 `if fresh != nil && ...`), it falls through to:

```go
} else if !requestCc.OnlyIfCached && (requestCc.MaxStaleSet || requestCc.MaxStale > -1) {
        response := stale
        ...
```

i.e. **a stale hit is only served if the incoming request itself carries
`Cache-Control: max-stale=...` (or equivalent)**. A plain request with no
such directive skips this branch entirely and falls through to
`Request the upstream server` (confirmed literally, via debug log: see
below), producing `Cache-Status: ...; fwd=uri-miss; stored` - a completely
correct RFC 7234 revalidation, mislabeled by the test as "not persisted".

Empirical proof the data *was* persisted (debug log from a real restart,
`.work/caddy2.log`, `debug` global option enabled per "Debugging a
failure" above):

```
{"logger":"storages.cache.nuts","msg":"The stored key GET-http-localhost:8091-/static matched the current iteration key ETag ... as stale"}
{"logger":"http.handlers.cache","msg":"Found at least one valid response in the NUTS storage"}
{"logger":"http.handlers.cache","msg":"Request the upstream server"}
```

The mapping *was* found on disk after the restart (`"Found at least one
valid response..."`) - it just wasn't fresh, so a plain GET correctly
revalidated. Sending `max-stale` on the same request after the same
restart instead returns:

```
Cache-Status: Souin; hit; ttl=-225; key=GET-http-localhost:8091-/static; detail=NUTS; fwd=stale
```

- an actual `hit` straight from the `NUTS` storer, with no origin fetch.
This is what the fixed test 7 now asserts.

Independently, a minimal Go program built against the exact same
`darkweak/storages/nuts@v0.0.19` + `nutsdb@v1.0.4` (no Caddy involved:
`Factory()` -> `SetMultiLevel()` -> process exit **without** calling
`Close()`/`Reset()` -> new process -> `Factory()` -> `GetMultiLevel()`)
found the persisted mapping every time. nutsdb's own `Persistent` TTL
sentinel (`nutsdb@v1.0.4` `metadata.go:94`, `const Persistent uint32 = 0`)
correctly means "never expires" in `IsExpired()` (`record.go:39-46`), and
neither nutsdb's `MMap` read/write mode nor lack of an explicit `Close()`
before process exit caused any data loss in dozens of repeated trials.
**Nuts persistence itself is not the problem; the test's expectation was.**

#### Addendum: the ERROR path is different - response-side `stale-if-error` works for plain requests

The request-`max-stale` requirement above applies to the *non-error* path
(origin reachable, entry past TTL -> revalidate unless the request opts
into stale). The *error* path (origin down/unreachable) is governed
separately: if the **cached response** carries `stale-if-error=<seconds>`
(RFC 5861), Souin serves the stale entry to a completely plain request -
no `max-stale` needed. Verified empirically (2026-07-25): cached with
`default_cache_control "public, max-age=2, stale-if-error=3600"`, origin
killed, plain `GET` ->

```
HTTP/1.1 200 OK
Cache-Status: Souin; hit; ttl=-25; key=GET-http-localhost:8091-/static; detail=NUTS; fwd=stale; fwd-status=200
```

Without `stale-if-error` in the cached response, that same plain GET
would fall through to the (dead) upstream and surface as a 502. This is
why both production cache blocks in `deploy/edge/Caddyfile` set
`stale-if-error` - it is what makes the "origin-down insurance" real for
browsers, which never send `max-stale`. Suite test 6 asserts both paths
(request `max-stale`, and plain GET via response `stale-if-error`).

Side effect to be aware of (measured 2026-07-25): once a cached response
carries a `stale-*` directive, Souin issues **coalesced background
revalidations** - even on fresh hits - at roughly 1/second per hot key
(10 rapid warm hits -> 2 origin fetches in testing). Two mitigating
facts: (a) the background revalidation does NOT refresh the stored entry
(it hits the souin#699 context-cancellation bug in the Caddy plugin - a
past-TTL request still revalidates synchronously, so TTL freshness
semantics are intact); (b) the traffic is bounded per key per second, so
origin load stays modest. But it does mean origin hit counts are not
exactly "1 per cache miss", which is why the suite's count assertions
are `>=` bounds, not exact.

### 2. `cache { log_level debug }` is inert

Setting `log_level debug` inside a `cache { }` block (global or per-site)
does **not** produce any debug-level output from Souin's own internal
logger, even though the Caddyfile directive is parsed correctly
(`cache-handler@v0.16.0` `configuration.go:609-611`) and correctly
inherited by every handler via `FromApp()`.

The reason: `cache-handler@v0.16.0` `httpcache.go` `Provision()` calls
`s.Configuration.SetLogger(s.logger)` (line ~262, using **Caddy's own**
`ctx.Logger(s).Sugar()`) *before* calling `middleware.NewHTTPCacheHandler`.
`souin@v1.7.7` `pkg/middleware/middleware.go` `NewHTTPCacheHandler` (lines
67-93) only builds its own level-aware logger `if c.GetLogger() == nil` -
since it's already been set to Caddy's logger, that branch never runs, and
`log_level debug` (which only affects the branch that never runs) is
silently ignored. Debug output only appears if **Caddy's own** log level
is `debug` (global `debug` directive or a `logging { }` block) - see
"Debugging a failure" above for how to get it. This is a config-Caddyfile
issue but not a *behavioral* one (nothing breaks; you just don't get the
logs you asked for), so it wasn't changed in either Caddyfile - the
directive is left in place as harmless, forward-compatible documentation
of intent, and this section exists so a future debugging session doesn't
waste time on the same dead end.

### 3. Admin API storers are permanently empty

`GET /souin-api/souin` (list stored keys) always returns `[]`, and
`PURGE /souin-api/souin/<key>` always answers `204 No Content` but never
actually evicts anything - **regardless of how much traffic has actually
been cached.**

Root cause, confirmed by reading `caddy/v2@v2.11.3` (`caddy.go`) and
`cache-handler@v0.16.0` (`admin.go`):

1. `caddy/v2@v2.11.3` `caddy.go` `provisionContext()` (lines ~558-580)
   starts the admin server (`replaceLocalAdminServer`, which provisions
   every `admin.api.*` module, including `admin.api.souin`) **before** it
   provisions any of the config's `apps` (the loop
   `for appName := range newCfg.AppsRaw { ctx.App(appName) }` runs
   strictly after `replaceLocalAdminServer` returns).
2. `cache-handler@v0.16.0` `admin.go` `Provision()` calls
   `ctx.App(moduleName)` (i.e. `ctx.App("cache")`) to get the `SouinApp`,
   then immediately snapshots `a.app.Storers` and `a.app.SurrogateStorage`
   into a `SouinAPI` value via `api.GenerateHandlerMap(&config,
   a.app.Storers, a.app.SurrogateStorage)` (lines ~66-72). Per
   `caddy/v2@v2.11.3` `context.go` `App()` (lines ~505-520), calling
   `ctx.App("cache")` when the app hasn't been loaded yet **eagerly
   provisions it right there** - and `cache-handler@v0.16.0` `app.go`
   `SouinApp.Provision()` is a no-op that does *not* populate `Storers`.
3. `Storers`/`SurrogateStorage` only get populated later, inside
   `cache-handler@v0.16.0` `httpcache.go` `SouinCaddyMiddleware.Provision()`
   (`if len(app.Storers) == 0 { app.Storers = s.SouinBaseHandler.Storers }`,
   lines ~276-284) - which runs when the `http` app's route handlers
   provision, i.e. *after* step 1 already finished.
4. `souin@v1.7.7` `pkg/api/souin.go` `SouinAPI.storers` is a plain `[]`
   field set once at construction (`initializeSouin`) - it's not a live
   reference to `SouinApp.Storers`, so even though the *App*'s field gets
   populated a few milliseconds later, the admin API's own already-baked
   copy stays `[]` forever, for the life of that Caddy process.

This was verified against a live restarted process (not just read from
source): `curl $ADMIN/souin-api/souin` returns `[]` immediately after
warming several entries via real traffic, and
`curl -X PURGE $ADMIN/souin-api/souin/static` returns `204` but a
follow-up `GET /static` is still a `hit` (see test 8). Checked `master` of
`caddyserver/cache-handler` too (`diff` against `v0.16.0`'s `admin.go` is
empty) - **this is not fixed in the latest released or unreleased code as
of this writing**, so pinning a newer `cache-handler` tag would not help
without a code change upstream.

Test 8 documents this as a known, evidenced limitation rather than
asserting the (impossible, given the above) "keys list is non-empty"
behavior the original test wanted.

### 4. Direct PURGE is a passthrough, not an admin operation

Sending an HTTP `PURGE` request straight to a cached URL (as opposed to
the admin API's `PURGE /souin-api/souin/<key>`) does **not** go through
Souin's cache-aware logic at all. `PURGE` isn't in `allowed_http_verbs`
(default `GET, HEAD`), so it hits the generic "unsupported method" bypass
in `souin@v1.7.7` `pkg/middleware/middleware.go` `ServeHTTP` (lines
~665-691):

```go
if !req.Context().Value(context.SupportedMethod).(bool) {
        rw.Header().Set("Cache-Status", cacheName+"; fwd=bypass; detail=UNSUPPORTED-METHOD")
        ...
        err := next(nrw, req)                 // forwarded to the real upstream, unconditionally
        ...
        if err == nil && req.Method != http.MethodGet && nrw.statusCode < http.StatusBadRequest {
                // only NOW does it evict the cached GET entry for this URL
                req.Method = http.MethodGet
                keyname := s.context.SetContext(req, rq).Context().Value(context.Key).(string)
                for _, storer := range s.Storers {
                        storer.Delete(core.MappingKeyPrefix + keyname)
                }
        }
        return err
}
```

This is a general "any mutating verb the origin accepts invalidates the
cached GET" mechanism (it's not PURGE-specific - `PUT`/`PATCH`/`DELETE`
would trigger the exact same code path), gated entirely on **the
upstream's own response status to that verb**: eviction only happens if
the *origin* answers `< 400`. `PURGE` is forwarded through to the real
backend exactly like any other unrecognized method - Souin does not
intercept or short-circuit it.

Real backends (static file servers, Jellyfin, etc.) generally don't
implement `PURGE` and answer `405`/`501`, which means this passthrough
mechanism **will not evict anything in front of a typical backend** -
confirmed with `origin.py`'s `/static` path, whose `do_PURGE` returns
`405` (test 9, first half). Given a backend that *does* answer success to
`PURGE` (`origin.py`'s `/purge-ok` path, `do_PURGE` returns `200`), the
exact same mechanism does evict correctly (test 9, second half) - so the
mechanism itself works as designed, it's just useless unless the origin
cooperates. Combined with quirk #3 above (the *documented*, admin-API-based
purge is unconditionally broken in this Caddy+cache-handler version),
**there is currently no reliable way to force-evict a single cached URL
in this deployment** short of restarting Caddy (which drops the whole
cache app's in-memory registry, though the on-disk nuts data itself
survives per quirk #1 above and gets picked back up as *stale*) or
lowering `ttl`. If a hard-purge capability becomes a real operational need
(e.g. purging a specific docs.erfi.io page after a content update),
options are: (a) wait for an upstream fix to the admin API ordering bug,
(b) add a tiny origin-side endpoint that accepts `PURGE` and returns `200`
specifically so the passthrough mechanism works, or (c) reduce the
affected `ttl`.

### 5. Multiple `cache {}` blocks share one nuts storer, correctly, via UUID matching - with one harmless wrinkle

The original task hypothesis was that each site-level `cache {}` handler
block might provision its own separate storage instance. Empirically this
turned out **not** to cause any of the 5 original failures, but it's worth
recording since it's real:

- `darkweak/storages/nuts@v0.0.19` `nuts.go` `Factory()` keeps a
  process-wide `nutsInstanceMap` keyed by directory path. The *first* call
  for a given `Dir` in a process opens the DB and sets a real `uuid` field
  (`fmt.Sprintf("%s-%s", dir, stale)`, `nuts.go` ~line 190). Every
  subsequent call for the *same* `Dir` in the *same* process hits the
  "already open" branch (`nuts.go` ~lines 162-168) and returns a **new**
  `*Nuts` wrapper around the same `*nutsdb.DB` but with an **empty**
  `uuid` field (`uuid`/`instanceKey` are simply never set on that branch).
- `nuts/caddy@v0.0.19` `nuts.go` `Provision()` registers each wrapper into
  the global `core.registered` map (`storages/core@v0.0.19`
  `registered.go`) under key `fmt.Sprintf("%s-%s", s.Name(), s.Uuid())`.
  The first handler to provision registers under the *correct* key
  (`"NUTS-<dir>-<stale>"`); every later handler for the same dir+stale
  registers a second, orphaned entry under the key `"NUTS-"` (empty uuid).
- This is harmless in practice: every handler's *own* lookup key
  (`cache-handler@v0.16.0` `cleaner.go` `parseStorages()`, which computes
  `Nuts.Uuid = fmt.Sprintf("NUTS-%s-%s", dir, stale)` using the *same*
  dir/stale each handler resolves via `FromApp()` inheritance) is also
  `"NUTS-<dir>-<stale>"`, so **every** handler's `NewHTTPCacheHandler()`
  storer lookup (`souin@v1.7.7` `middleware.go` lines ~94-101,
  `core.GetRegisteredStorer(dc.GetNuts().Uuid)`) resolves to the same,
  correctly-registered entry regardless of provisioning order. The orphan
  `"NUTS-"` entries are just dead weight in the registry (cleared anyway
  the moment `SouinApp.Start()` calls `core.ResetRegisteredStorages()`,
  `app.go` line ~38, right after all apps finish provisioning). No
  Caddyfile change was needed for this.

### 6. Slow origins are born stale (fixed in the erfi.io souin fork)

`souin@v1.7.7` `pkg/middleware/middleware.go` `Store()` computed the
fresh TTL to persist as:

```go
date, _ := http.ParseTime(now.Format(http.TimeFormat))
customWriter.Header().Set(rfc.StoredTTLHeader, ma.String())
ma = ma - time.Since(date)          // ~line 314
```

`now` here is `context.Now` - the time the *request arrived*, not the
time the response's `Date` header was generated. `time.Since(date)`
therefore measures the **entire upstream fetch latency**, not the
response's own age. Any origin slower than the resource's `max-age` gets
its stored TTL computed as `max-age - upstream_latency`, which goes
negative the moment `upstream_latency > max-age` - the entry is written
to storage **already expired**, and a plain request can never see it as
a fresh hit again (quirk #1 above: a plain GET only serves fresh, and a
stale entry needs `max-stale` from the client).

Caught by suite test 14 (`run-tests.sh` "14. Request coalescing /
singleflight" - see the comment above the `/slow` requests and
`origin.py`'s `/slow` handler comment, both of which cite this same
source line): the coalescing target sleeps 0.3s against a 2s `max-age`,
deliberately staying well under the threshold so the post-warm-up
`assert_cs "GET /slow after coalesced warm-up" hit` assertion is
meaningful. Widening that sleep past 2s reproduces the bug directly -
confirmed via debug log, which showed the stored TTL computed as
negative for a deliberately-slow response:

```
Store the response ... with duration -669.340244ms
```

i.e. the entry was stored **already 669ms past expiry**, before a single
client ever asked for it. Fixed in the erfi.io souin fork (landed as
commit `d104c5f9` in `~/ergo/souin` `pkg/middleware/middleware.go`, marked
`// erfi.io patch:`): `Store()` now parses the response's own `Date`
header and subtracts only `time.Since(respDate)` - the response's actual
apparent age per RFC 7234 section 4.2.3 - instead of the full
request-to-store latency. A fast `Date` header (age ~0) leaves `ma`
unchanged; a slow origin still loses a little freshness to network/proxy
transit time, but never the full fetch duration.

### 7. Revalidation doubles the stored body (fixed in the erfi.io souin fork)

Verified empirically (nuts DB dump + live hit): after a stale entry is
revalidated, the re-Stored object contains the response body **twice**,
plus duplicated `Date`/`Via` headers, and the next fresh hit serves the
doubled payload - `static-body-v1static-body-v1` for `/static` (28 bytes
for what should be a 14-byte body, `Content-Length: 28`).

Root cause: `souin@v1.7.7` `pkg/middleware/middleware.go` `ServeHTTP`'s
stale-if-error revalidation block, on a **successful** `Revalidate()`,
fell through the bottom of its `if` block straight into the `Upstream()`
call below it (~line 937) instead of returning. `Revalidate()` has
already fetched, buffered, and Stored the fresh response by that point;
falling through triggered a **second** origin fetch whose bytes were
appended to the already-populated `customWriter` buffer, and that
doubled buffer was Stored again, permanently corrupting the entry on
disk.

Caught by suite test 17 (`run-tests.sh` "17. KNOWN UPSTREAM BUG: stale
revalidation stores a DOUBLED body") against the dedicated
`/reval-target` origin path: cold store, sleep past the 2s TTL, one
revalidating request, then a fresh hit. Fixed in the erfi.io souin fork
(landed as commit `d104c5f9` in `~/ergo/souin` `pkg/middleware/middleware.go`,
marked `// erfi.io patch:`): the block now does
`_, _ = customWriter.Send(); return err` immediately after a successful
revalidation, so the fresh response is sent to the client and stored
exactly once, with no second origin fetch.

## Bounded storage and eviction

There is **no size-based bound on the cache anywhere in this stack**, and
no LRU/LFU-style eviction. Grep-verified: `max_cache_size` / `MaxCacheSize`
does not exist in `cache-handler@v0.16.0`, `souin@v1.7.7`, or
`storages/nuts@v0.0.19`. Storage is bounded by **time only**:

1. **Per-entry TTL = fresh ttl + stale.** `Nuts.SetMultiLevel`
   (`storages/nuts@v0.0.19` `nuts.go` ~line 322) writes every entry with a
   nutsdb TTL of `uint32((duration + provider.stale).Seconds())` - the
   fresh TTL and the stale window are baked into the record's expiry, so an
   entry's absolute lifetime is fixed at write time. Effective per-site
   ceilings (from `deploy/edge/Caddyfile`): global default `60s + 1h`,
   docs.erfi.io `5m + 24h`, jellyfin images `24h + 72h` (entries can live
   ~4 days).
2. **Expired entries are physically reclaimed by nutsdb's merge**, not by
   Souin. Reads stop returning an expired record immediately (nutsdb
   filters on read), and the background merge skips expired records when
   rewriting segments (`nutsdb@v1.0.4` `merge.go` ~line 250,
   `r.IsExpired()`), running every `MergeInterval` (default **2h**,
   `options.go` `DefaultOptions`). Worst-case disk footprint therefore
   converges to roughly "all writes within ttl+stale, plus up to one merge
   interval of garbage".
3. **Surrogate-key mappings are swept separately, once a minute.**
   `registerMappingKeysEviction` (`souin@v1.7.7`
   `pkg/middleware/middleware.go` ~line 53) spawns one goroutine per storer
   that loops over `api.EvictMapping` (`pkg/api/souin.go` ~line 167), which
   drops expired entries from the `SURROGATE-` mapping records and ends
   with `time.Sleep(time.Minute)` - it only touches mapping metadata, never
   cached objects.

Two consequences worth knowing operationally:

- **RAM, not just disk, scales with stored bytes under the defaults.**
  nutsdb `DefaultOptions` sets `EntryIdxMode: HintKeyValAndRAMIdxMode` -
  the full value index lives in RAM. If the cache grows large, switch to
  `HintKeyAndRAMIdxMode` (keys only in RAM, values read from disk) via the
  global block: `cache { nuts { path /data/cache/nuts; configuration {
  EntryIdxMode HintKeyAndRAMIdxMode } } }` (directive shape verified:
  `cache-handler@v0.16.0` `configuration.go` `case "nuts"` ~line 633,
  option strings mapped in `storages/nuts@v0.0.19` `nuts.go`
  `sanitizeProperties`). Other accepted nutsdb knobs there include
  `SegmentSize` (default 256MB), `MergeInterval`, `SyncEnable`,
  `ExpiredDeleteType` (`TimeWheel` default / `TimeHeap`).
- **There is no emergency size brake.** With the admin purge API broken
  (quirk #3) and direct PURGE gated on origin cooperation (quirk #4), the
  only hard reclaim today is deleting `/data/cache/nuts` and restarting the
  container. The preventive levers are: lower `stale`/`ttl` per site, and
  `key { disable_query }` (suite section 16) to keep URL cardinality -
  and therefore entry count - proportional to real content paths rather
  than attacker-controlled query strings. (This was also the reason the
  redis backend was rejected: its eviction path is SCAN-based and storms
  under load, souin#646/#671.)

## Summary: what's actually broken vs. what was just tested wrong

| # | Symptom | Real cause | Fix applied |
|---|---|---|---|
| 7 | Plain GET after restart is `fwd`, not `hit` | TTL had already expired from earlier tests' wall-clock time; Souin correctly revalidates a stale entry against a reachable origin unless the request sends `max-stale` (quirk #1) | Test now sends `max-stale`, proving persistence directly |
| 8 | `GET /souin-api/souin` always `[]` | Caddy provisions the admin server before the `cache` app; `admin.go` bakes in an empty `Storers` snapshot forever (quirk #3) | Test now asserts the documented-empty behavior, plus an explicit admin-PURGE-is-a-no-op check |
| 9 | `PURGE <url>` never evicts | Direct PURGE is a generic mutation-invalidation bypass gated on the *origin's* response to PURGE, not an admin/cache-aware operation (quirk #4); the mock origin didn't implement PURGE at all | Test now covers both a non-cooperating origin (`/static`, expect no eviction) and a cooperating one (new `/purge-ok` path, expect eviction) |

No changes were made to `Caddyfile.test` or `../../deploy/edge/Caddyfile` -
every failure traced back to either a test-timing assumption (test 7) or
an upstream `cache-handler`/Caddy provisioning-order limitation (tests 8
and 9) that no Caddyfile directive can work around.
