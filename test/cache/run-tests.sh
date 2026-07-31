#!/usr/bin/env bash
# Loop test suite for the edge Caddy HTTP cache (cache-handler/Souin + nuts).
# Deterministic: wipes all state at start, safe to run repeatedly.
# Usage: run-tests.sh [run-label]
set -u
LABEL="${1:-run}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$DIR/.work"
IMAGE="${CADDY_IMAGE:-$(sed -n 's/^CADDY_IMAGE *?= *//p' "$(dirname "${BASH_SOURCE[0]}")/../../Makefile")}"
CADDY="$WORK/caddy"
NUTS="$WORK/nuts"
HITSLOG="$WORK/origin-hits.log"
ORIGIN_PORT=8090
DOCS_PORT=8091    # whole-site cache (docs.erfi.io shape)
JF_PORT=8092      # route-scoped image cache (jellyfin.erfi.io shape)
ADMIN=http://localhost:2021

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

# assert_cache_status <name> <expect: hit|fwd|absent> <curl args...>
assert_cs() {
	local name="$1" expect="$2"; shift 2
	local out cs code
	out=$(curl -si --max-time 30 "$@" 2>/dev/null | tr -d '\0')
	cs=$(printf '%s' "$out" | tr -d '\r' | awk 'BEGIN{IGNORECASE=1} /^cache-status:/{print}')
	code=$(printf '%s' "$out" | head -1 | awk '{print $2}')
	case "$expect" in
		hit)    grep -qi '; *hit' <<<"$cs" && ok "$name (hit, $code)"  || bad "$name - wanted hit, got [$cs] code=$code" ;;
		fwd)    grep -qi 'fwd='     <<<"$cs" && ok "$name (fwd, $code)"  || bad "$name - wanted fwd, got [$cs] code=$code" ;;
		absent) [ -z "$cs" ]                 && ok "$name (no cache hdr)" || bad "$name - wanted no Cache-Status, got [$cs]" ;;
	esac
}

origin_hits() { grep -c "$1" "$HITSLOG" 2>/dev/null || echo 0; }

CADDY_PID=""; ORIGIN_PID=""
cleanup() {
	# PID-based only: pkill -f would match this script's own argv and
	# suicide the run.
	[ -n "$CADDY_PID" ]  && { kill "$CADDY_PID"  2>/dev/null; wait "$CADDY_PID"  2>/dev/null; }
	[ -n "$ORIGIN_PID" ] && { kill "$ORIGIN_PID" 2>/dev/null; wait "$ORIGIN_PID" 2>/dev/null; }
	CADDY_PID=""; ORIGIN_PID=""
}
start_origin() {
	python3 "$DIR/origin.py" $ORIGIN_PORT "$HITSLOG" &
	ORIGIN_PID=$!
	for i in $(seq 1 30); do curl -sf -o /dev/null "http://127.0.0.1:$ORIGIN_PORT/api/foo" && break; sleep 0.2; done
}
start_caddy() {
	NUTS_PATH="$NUTS" "$CADDY" run --config "$DIR/Caddyfile.test" --adapter caddyfile >"$WORK/caddy.log" 2>&1 &
	CADDY_PID=$!
	for i in $(seq 1 40); do curl -sf -o /dev/null "$ADMIN/config/" && break; sleep 0.25; done
}

hdr "setup ($LABEL)"
mkdir -p "$WORK"
# Extract the caddy binary from the built image if missing.
if [ ! -x "$CADDY" ]; then
	id=$(docker create "$IMAGE") && docker cp "$id":/usr/bin/caddy "$CADDY" && docker rm "$id" >/dev/null
	ok "extracted caddy binary from $IMAGE"
fi
cleanup; sleep 0.3
rm -rf "$NUTS" "$HITSLOG"
touch "$HITSLOG"
start_origin
start_caddy
curl -sf -o /dev/null "$ADMIN/config/" && ok "caddy up (admin :2021)" || { bad "caddy failed to start (see $WORK/caddy.log)"; cleanup; exit 1; }

hdr "1. miss -> hit -> TTL expiry (docs shape, :$DOCS_PORT)"
assert_cs "GET /static #1 cold"        fwd http://localhost:$DOCS_PORT/static
assert_cs "GET /static #2 warm"        hit http://localhost:$DOCS_PORT/static
sleep 3
assert_cs "GET /static #3 after ttl"   fwd http://localhost:$DOCS_PORT/static
assert_cs "GET /static #4 warm again"  hit http://localhost:$DOCS_PORT/static
# With stale-if-error in the cached response, Souin also issues coalesced
# BACKGROUND revalidations (~1/s per hot key) that do not refresh the stored
# entry (souin#699 context-cancellation) - so hits can add origin fetches.
# The hard requirement is: at least the cold miss + the post-TTL synchronous
# refetch happened (>= 2). See README quirk "background revalidation traffic".
n=$(origin_hits 'GET /static'); [ "$n" -ge 2 ] && ok "origin saw cold+expiry fetches for /static ($n total incl. background)" || bad "origin GET /static count = $n, want >= 2"

hdr "2. upstream Cache-Control respected (strict mode, :$DOCS_PORT)"
assert_cs "GET /nostore #1" fwd http://localhost:$DOCS_PORT/nostore
assert_cs "GET /nostore #2" fwd http://localhost:$DOCS_PORT/nostore
assert_cs "GET /private #1" fwd http://localhost:$DOCS_PORT/private
assert_cs "GET /private #2" fwd http://localhost:$DOCS_PORT/private

hdr "3. POST never cached, doesn't poison GET (:$DOCS_PORT)"
assert_cs "POST /static #1" fwd -X POST http://localhost:$DOCS_PORT/static
assert_cs "POST /static #2" fwd -X POST http://localhost:$DOCS_PORT/static

hdr "4. route-scoped cache, per-token keying (jellyfin shape, :$JF_PORT)"
assert_cs "img tokenA #1" fwd "http://localhost:$JF_PORT/Items/42/Images/Primary?api_key=tokenA"
assert_cs "img tokenA #2" hit "http://localhost:$JF_PORT/Items/42/Images/Primary?api_key=tokenA"
assert_cs "img tokenB #1" fwd "http://localhost:$JF_PORT/Items/42/Images/Primary?api_key=tokenB"
assert_cs "img tokenB #2" hit "http://localhost:$JF_PORT/Items/42/Images/Primary?api_key=tokenB"
# Per-token keying is proven by tokenB #1 being a fwd (a shared entry would
# have hit). Count is >= 2, not exactly 2: stale-if-error background
# revalidations can add fetches (same quirk as test 1).
n=$(origin_hits 'Images/Primary'); [ "$n" -ge 2 ] && ok "origin saw image fetches for both tokens ($n total incl. background)" || bad "image origin count = $n, want >= 2"

hdr "5. non-image paths untouched by cache (:$JF_PORT)"
assert_cs "GET /api/foo #1" absent http://localhost:$JF_PORT/api/foo
assert_cs "GET /api/foo #2" absent http://localhost:$JF_PORT/api/foo

hdr "6. stale-if-error: origin down, past TTL (:$DOCS_PORT)"
# /static entry is warm from test 1; kill origin and wait past the 2s TTL.
curl -s -o /dev/null http://localhost:$DOCS_PORT/static
kill "$ORIGIN_PID" 2>/dev/null; wait "$ORIGIN_PID" 2>/dev/null; ORIGIN_PID=""
sleep 3
# Two distinct stale paths (see README quirk #1 + the stale-if-error addendum):
#  (a) request opts in via max-stale -> stale served
#  (b) cached response carries stale-if-error + origin ERRORS -> stale served
#      to a plain request. (b) is the path real browsers depend on.
out=$(curl -si -H 'Cache-Control: max-stale=3600' http://localhost:$DOCS_PORT/static)
code=$(printf '%s' "$out" | head -1 | awk '{print $2}')
[ "$code" = 200 ] && ok "stale served with origin down, max-stale request (200)" || bad "stale-with-origin-down (max-stale) code=$code, want 200"
out=$(curl -si http://localhost:$DOCS_PORT/static)
code=$(printf '%s' "$out" | head -1 | awk '{print $2}')
cs=$(printf '%s' "$out" | tr -d '\r' | grep -i '^cache-status:')
{ [ "$code" = 200 ] && grep -qi '; *hit' <<<"$cs"; } && ok "stale served with origin down, plain GET via stale-if-error (200 hit)" || bad "stale-if-error plain GET failed: code=$code cs=[$cs]"
start_origin

hdr "7. nuts persistence across caddy restart"
# Storage-layout guards (2026-07-31): every site handler must provision its
# OWN nutsdb at its OWN configured path - no in-memory fallback, and never
# the /tmp/souin-nuts default (nuts.Factory drops provider.Path whenever
# Configuration is non-nil, so a missing Dir inside configuration silently
# relocates the DB; see README "per-site storage").
if grep -q 'default storage' "$WORK/caddy.log"; then bad "a cache handler fell back to in-memory default storage"; else ok "no handler on in-memory default storage"; fi
[ -f "$NUTS/a/0.dat" ] && ok ":8091 nuts db at configured path ($NUTS/a)" || bad ":8091 nuts db missing at $NUTS/a"
[ -f "$NUTS/b/0.dat" ] && ok ":8092 nuts db at configured path ($NUTS/b)" || bad ":8092 nuts db missing at $NUTS/b"
[ ! -e /tmp/souin-nuts/0.dat ] && ok "no fallback to /tmp/souin-nuts default path" || bad "nuts fell back to /tmp/souin-nuts (Dir dropped)"
before=$(origin_hits 'GET /static')
before_img=$(origin_hits 'GET /Items/42/Images/Primary')
[ -n "$CADDY_PID" ] && { kill "$CADDY_PID" 2>/dev/null; wait "$CADDY_PID" 2>/dev/null; CADDY_PID=""; }
start_caddy
# /static's TTL (2s) is long expired by this point in the suite (tests 1-6
# already burned >6s of wall clock incl. two `sleep 3`s), so the persisted
# entry is stale, not fresh. Per RFC 7234, Souin only serves a stale entry
# when the REQUEST explicitly permits it (see README "stale is opt-in, not
# automatic") - a plain GET here would correctly revalidate against the
# now-reachable origin regardless of whether nuts persisted anything,
# which would make this assertion vacuous. Sending max-stale forces Souin
# to answer straight from whatever it finds on disk, which is exactly what
# this test needs to prove: the on-disk nuts mapping round-tripped through
# the process restart.
assert_cs "GET /static after caddy restart" hit -H 'Cache-Control: max-stale=3600' http://localhost:$DOCS_PORT/static
after=$(origin_hits 'GET /static'); [ "$after" -eq "$before" ] && ok "no origin fetch after restart (disk cache)" || bad "origin refetched after restart (before=$before after=$after)"
# Same proof for the SECOND handler (:8092, route-scoped) - the blind spot
# that let the per-handler storage fallback ship undetected: image entries
# carry max-age=86400 so a plain GET must be a fresh HIT off disk.
assert_cs "GET image after caddy restart" hit "http://localhost:$JF_PORT/Items/42/Images/Primary?api_key=tokenA"
after_img=$(origin_hits 'GET /Items/42/Images/Primary'); [ "$after_img" -eq "$before_img" ] && ok "no image refetch after restart (disk cache, :8092)" || bad "image refetched after restart (before=$before_img after=$after_img)"

hdr "8. souin admin API"
# KNOWN LIMITATION, reproduced from source (see README "Admin API storers
# are permanently empty"): Caddy starts the admin server - which
# provisions admin.api.souin - BEFORE it provisions the "http"/"cache"
# apps, so adminAPI.Provision() always snapshots an empty Storers slice
# from the not-yet-populated "cache" App. The endpoint answers 200 but the
# key list is always [].
keys=$(curl -s "$ADMIN/souin-api/souin")
[ "$keys" = "[]" ] && ok "souin API keys list is [] (documented limitation, see README)" || bad "souin API keys list unexpected: ${keys:0:120}"
curl -s -o /dev/null -w '%{http_code}' "$ADMIN/souin-api/metrics" | grep -q 200 && ok "souin prometheus endpoint 200" || bad "souin prometheus endpoint not 200"
# Same root cause makes the *documented* admin PURGE endpoint a no-op too:
# it always answers success (204) but never actually evicts, because its
# `storers` slice was baked in empty at Provision time. Re-warm /static
# first so the follow-up GET is unambiguous (a stale entry would forward
# regardless of purge, same caveat as test 7 above).
curl -s -o /dev/null http://localhost:$DOCS_PORT/static
curl -s -o /dev/null -w '%{http_code}' -X PURGE "$ADMIN/souin-api/souin/static" | grep -q 204 && ok "admin PURGE /souin-api/souin/static returns 204" || bad "admin PURGE endpoint didn't return 204"
assert_cs "GET /static after admin-API PURGE (no-op, Storers empty)" hit http://localhost:$DOCS_PORT/static

hdr "9. purge (direct PURGE to the cached URL, not the admin API)"
# Re-warm /static so it's fresh (within its 2s TTL) before purging -
# isolates "did PURGE evict" from "was the entry stale anyway" (test 7/8
# caveat above): a stale entry would forward on the next GET regardless of
# whether purge did anything.
curl -s -o /dev/null http://localhost:$DOCS_PORT/static
before=$(origin_hits 'GET /static')
# /static's origin does NOT implement PURGE (405, like most real backends -
# static file servers, Jellyfin, etc. - see origin.py do_PURGE). Souin's
# direct-PURGE-to-URL mechanism forwards the method to the upstream and
# only evicts if that upstream answers success (see README "direct PURGE
# is a passthrough, not an admin operation") - it must NOT evict here.
curl -s -o /dev/null -X PURGE http://localhost:$DOCS_PORT/static
assert_cs "GET /static after PURGE (non-cooperating origin)" hit http://localhost:$DOCS_PORT/static
after=$(origin_hits 'GET /static')
[ "$after" -eq "$before" ] && ok "no origin refetch (purge correctly no-op'd; origin doesn't handle PURGE)" || bad "unexpected origin refetch after purge (before=$before after=$after)"

# /purge-ok's origin DOES answer PURGE with 2xx (see origin.py do_PURGE) -
# proves the passthrough mechanism itself works given a cooperating
# backend, isolating that from the /static case above.
curl -s -o /dev/null http://localhost:$DOCS_PORT/purge-ok
curl -s -o /dev/null http://localhost:$DOCS_PORT/purge-ok
before2=$(origin_hits 'GET /purge-ok')
curl -s -o /dev/null -X PURGE http://localhost:$DOCS_PORT/purge-ok
assert_cs "GET /purge-ok after PURGE (cooperating origin)" fwd http://localhost:$DOCS_PORT/purge-ok
after2=$(origin_hits 'GET /purge-ok')
[ "$after2" -gt "$before2" ] && ok "purge forced origin refetch when origin cooperates" || bad "purge-ok origin refetch missing (before=$before2 after=$after2)"

hdr "10. Vary: Accept-Encoding correctness + separate cache entries (:$DOCS_PORT)"
# origin.py's /vary sends no Cache-Control of its own (site default applies,
# like /static) but DOES send Vary: Accept-Encoding with a body that differs
# by the request's own Accept-Encoding. Souin must key on it - see README
# "Vary-based key splitting" (souin@v1.7.7 context/key.go computeKey +
# rfc/vary.go GetVariedCacheKey: the stored key is cachedKey plus a suffix
# derived from the request header values named in the response's Vary).
# NB: the FIRST request for each variant IS the cold fetch - body and
# Cache-Status must be captured from the SAME response. (A separate
# body-check curl first would consume the cold fetch, making a following
# "#1 cold" assertion see a hit.)
out=$(curl -si --max-time 30 -H 'Accept-Encoding: gzip' http://localhost:$DOCS_PORT/vary)
gz1=$(printf '%s' "$out" | tail -1)
gzcs=$(printf '%s' "$out" | tr -d '\r' | grep -i '^cache-status:')
[ "$gz1" = "vary-gzip-body" ] && ok "gzip client gets gzip body (cold)" || bad "gzip client cold body wrong: [$gz1]"
grep -qi 'fwd=' <<<"$gzcs" && ok "GET /vary gzip #1 cold (fwd)" || bad "GET /vary gzip #1 - wanted fwd, got [$gzcs]"
assert_cs "GET /vary gzip #2 warm"   hit -H 'Accept-Encoding: gzip' http://localhost:$DOCS_PORT/vary
out=$(curl -si --max-time 30 -H 'Accept-Encoding: identity' http://localhost:$DOCS_PORT/vary)
id1=$(printf '%s' "$out" | tail -1)
idcs=$(printf '%s' "$out" | tr -d '\r' | grep -i '^cache-status:')
[ "$id1" = "vary-identity-body" ] && ok "identity client gets identity body (cold)" || bad "identity client cold body wrong: [$id1]"
grep -qi 'fwd=' <<<"$idcs" && ok "GET /vary identity #1 cold, separate Vary entry from gzip (fwd)" || bad "GET /vary identity #1 - wanted fwd, got [$idcs]"
assert_cs "GET /vary identity #2 warm" hit -H 'Accept-Encoding: identity' http://localhost:$DOCS_PORT/vary
gz2=$(curl -s -H 'Accept-Encoding: gzip' http://localhost:$DOCS_PORT/vary)
[ "$gz2" = "vary-gzip-body" ] && ok "gzip client still served its own variant on warm hit" || bad "gzip warm body corrupted: [$gz2]"
id2=$(curl -s -H 'Accept-Encoding: identity' http://localhost:$DOCS_PORT/vary)
[ "$id2" = "vary-identity-body" ] && ok "identity client still served its own variant on warm hit" || bad "identity warm body corrupted: [$id2]"
n=$(origin_hits 'GET /vary'); [ "$n" -ge 2 ] && ok "origin saw >= 2 distinct fetches for /vary, one per Vary variant ($n total)" || bad "/vary origin count = $n, want >= 2"

hdr "11. Authorization isolation - never stored under strict mode (:$DOCS_PORT)"
# Strict mode is Souin's default when no `mode` directive is set (our
# Caddyfiles never set one): souin@v1.7.7 context/mode.go SetupContext
# leaves Bypass_request/Bypass_response false and Strict true. In strict
# mode, pkg/middleware/middleware.go ~line 269 refuses to STORE any
# response to a request carrying an Authorization header, unconditionally -
# this check runs before default_cache_control is even consulted, so
# "public, max-age=..." on the site does not override it. Net effect: no
# cross-user leak is even possible, because nothing is ever cached.
assert_cs "authed userA #1" fwd -H 'Authorization: Bearer userA' http://localhost:$DOCS_PORT/authed
assert_cs "authed userA #2 (still fwd - Authorization responses are never stored, so no hit is possible)" fwd -H 'Authorization: Bearer userA' http://localhost:$DOCS_PORT/authed
assert_cs "authed userB #1" fwd -H 'Authorization: Bearer userB' http://localhost:$DOCS_PORT/authed
bodyA=$(curl -s -H 'Authorization: Bearer userA' http://localhost:$DOCS_PORT/authed)
bodyB=$(curl -s -H 'Authorization: Bearer userB' http://localhost:$DOCS_PORT/authed)
{ [ "$bodyA" = "authed-body:Bearer userA" ] && [ "$bodyB" = "authed-body:Bearer userB" ]; } && ok "no cross-user leak: each request gets its own body every time" || bad "cross-user leak or wrong body: A=[$bodyA] B=[$bodyB]"
n=$(origin_hits 'GET /authed'); [ "$n" -ge 4 ] && ok "origin saw a fetch for every /authed request, none served from cache ($n total)" || bad "/authed origin count = $n, want >= 4"

hdr "12. HEAD request behavior - cache-aware but never stored (:$DOCS_PORT)"
# HEAD is in Souin's default allowed_http_verbs (souin@v1.7.7
# context/method.go:12 `defaultVerbs = []string{http.MethodGet,
# http.MethodHead}`), so unlike POST/PURGE it IS cache-aware - but a HEAD
# response can never be STORED: Store() (pkg/middleware/middleware.go ~line
# 352) only stores when `bLen > 0 || canStatusCodeEmptyContent(statusCode)`,
# and a HEAD response has an empty body with a 200 status - so it falls to
# the `detail=UPSTREAM-ERROR-OR-EMPTY-RESPONSE` branch (~line 443) and every
# HEAD is a miss. (The method is also part of the key since disable_method
# is unset, so a HEAD can't even ride on the GET entry.)
# NB: `--head` (curl HEAD mode, knows not to expect a body) instead of
# `-X HEAD` - with `-X HEAD` curl still waits for a response body that can
# never arrive and hangs forever on a keep-alive connection.
code=$(curl -s --head -o /dev/null -w '%{http_code}' http://localhost:$DOCS_PORT/static)
[ "$code" = 200 ] && ok "HEAD /static returns 200" || bad "HEAD /static code=$code"
assert_cs "HEAD /static #1 (fwd - never stored, empty body)" fwd --head http://localhost:$DOCS_PORT/static
assert_cs "HEAD /static #2 (still fwd - UPSTREAM-ERROR-OR-EMPTY-RESPONSE on store)" fwd --head http://localhost:$DOCS_PORT/static
dl=$(curl -s --head -o /dev/null -w '%{size_download}' http://localhost:$DOCS_PORT/static)
[ "$dl" = 0 ] && ok "HEAD response carries no body" || bad "HEAD response body not empty (size_download=$dl)"

hdr "13. Client conditional request (If-None-Match) against a cached entry (:$DOCS_PORT)"
assert_cs "GET /etag #1 cold"  fwd http://localhost:$DOCS_PORT/etag
assert_cs "GET /etag #2 warm"  hit http://localhost:$DOCS_PORT/etag
# Souin answers a client's conditional request straight from the cache-hit
# path when the incoming If-None-Match matches the stored response's ETag -
# a real 304, not the full cached body (souin@v1.7.7
# pkg/middleware/middleware.go ~lines 758-772: `if validator.ResponseETag
# != "" && validator.Matched { ... if validator.NotModified {
# customWriter.WriteHeader(http.StatusNotModified); ...; return } }`).
out=$(curl -si -H 'If-None-Match: "v1-etag"' http://localhost:$DOCS_PORT/etag)
code=$(printf '%s' "$out" | head -1 | awk '{print $2}')
cs=$(printf '%s' "$out" | tr -d '\r' | grep -i '^cache-status:')
{ [ "$code" = 304 ] && grep -qi '; *hit' <<<"$cs"; } && ok "matching If-None-Match against cached ETag -> 304 (Cache-Status hit)" || bad "If-None-Match match: code=$code cs=[$cs] (want 304, hit)"
# A NON-matching If-None-Match is the opposite: ValidateETagFromHeader
# (storages/core@v0.0.19 revalidator.go:24-27) sets `Matched =
# ResponseETag == "" || len(RequestETags) == 0` and only flips it true on a
# list match - so with a non-matching tag Matched stays false, and
# MappingElection (storages/core core.go:92) SKIPS the stored entry
# entirely (it only considers candidates when validator.Matched). The
# request falls through to the miss path and revalidates against the
# origin: `fwd=uri-miss; stored`, full 200 body. Conservative but
# RFC-correct.
out2=$(curl -si -H 'If-None-Match: "stale-etag"' http://localhost:$DOCS_PORT/etag)
code2=$(printf '%s' "$out2" | head -1 | awk '{print $2}')
cs2=$(printf '%s' "$out2" | tr -d '\r' | grep -i '^cache-status:')
{ [ "$code2" = 200 ] && grep -qi 'fwd=uri-miss' <<<"$cs2"; } && ok "non-matching If-None-Match -> origin revalidation (200 fwd, not served from cache)" || bad "non-matching If-None-Match: code=$code2 cs=[$cs2]"
n=$(origin_hits 'GET /etag'); [ "$n" -ge 2 ] && ok "origin saw cold fetch + non-match revalidation for /etag ($n total)" || bad "/etag origin count = $n, want >= 2"

hdr "14. Request coalescing / singleflight - 10 parallel cold GETs on one key (:$DOCS_PORT)"
# Coalescing is Souin's default: cache-handler v0.16.0 configuration.go
# `disable_coalescing` defaults false, and neither Caddyfile sets it.
# souin@v1.7.7 pkg/middleware/middleware.go ~lines 486-490 keys the
# golang.org/x/sync/singleflight.Group by the plain cache key UNLESS
# coalescing is disabled (in which case a fresh uuid is appended per
# request to force separate flights) - so concurrent requests for the same
# cold key should share a single in-flight origin fetch.
# /slow sleeps only 0.3s (NOT >= max-age): Store() subtracts the full
# upstream latency from the fresh TTL (middleware.go ~line 314), so a
# >= 2s-slow origin would be stored born-stale and the post-warm-up hit
# below could never pass. See README "Slow origins are born stale".
outdir="$WORK/coalesce"
rm -rf "$outdir"; mkdir -p "$outdir"
pids=()
for i in $(seq 1 10); do
	( curl -s -o "$outdir/$i.out" -w '%{http_code}' http://localhost:$DOCS_PORT/slow > "$outdir/$i.code" ) &
	pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
allok=1
for i in $(seq 1 10); do
	c=$(cat "$outdir/$i.code" 2>/dev/null)
	b=$(cat "$outdir/$i.out" 2>/dev/null)
	{ [ "$c" = 200 ] && [ "$b" = "slow-body" ]; } || allok=0
done
[ "$allok" -eq 1 ] && ok "all 10 parallel /slow requests returned 200 slow-body" || bad "one or more of the 10 parallel /slow requests failed"
n=$(origin_hits 'GET /slow'); [ "$n" -le 2 ] && ok "origin saw <= 2 fetches for 10 parallel cold requests on one key ($n total, singleflight coalesced)" || bad "/slow origin count = $n, want <= 2 (singleflight should coalesce)"
assert_cs "GET /slow after coalesced warm-up" hit http://localhost:$DOCS_PORT/slow

hdr "15. 404 is heuristically cacheable by default - not configurable to disable (:$DOCS_PORT)"
# souin@v1.7.7 pkg/middleware/middleware.go isCacheableCode() (~line 196)
# hardcodes 200,203,204,206,300,301,404,405,410,414,501 (RFC 7231 sec 6.1
# heuristically-cacheable statuses) as cacheable regardless of Caddyfile
# config. `allowed_additional_status_codes` only ever ADDS codes to that
# set (hasAllowedAdditionalStatusCodesToCache, ~line 222) - there is no
# config path that removes a code from the hardcoded list. See README
# "404 caching is not configurable to disable" for the full source trail
# and the accepted-risk writeup.
assert_cs "GET /nope-does-not-exist #1 cold (404)" fwd http://localhost:$DOCS_PORT/nope-does-not-exist
out=$(curl -si http://localhost:$DOCS_PORT/nope-does-not-exist)
code=$(printf '%s' "$out" | head -1 | awk '{print $2}')
[ "$code" = 404 ] && ok "404 status code preserved through the cache layer" || bad "expected 404, got $code"
assert_cs "GET /nope-does-not-exist #2 warm (404 served from cache)" hit http://localhost:$DOCS_PORT/nope-does-not-exist

hdr "16. query-string amplification mitigated by key { disable_query } (docs shape, :$DOCS_PORT)"
# deploy/edge/Caddyfile and this Caddyfile.test both add a flat
# `key { disable_query }` block inside docs.erfi.io's cache{} (verified
# directive shape: cache-handler v0.16.0 configuration.go ~lines 579-609,
# `case "key":` sits inside the site-level cache{} block as a sibling of
# ttl/stale - NOT the pattern-based `cache_keys{}` mechanism). With the
# query stripped from the key, /static and /static?spam=<anything> now
# resolve to the SAME stored entry (context/key.go parseKeyInformations:
# `if !kCtx.disable_query && len(req.URL.RawQuery) > 0 { query = ... }` -
# disabled here, so query is always empty regardless of what's on the
# wire). This closes the unbounded-query cache-blowing/amplification
# vector documented in the README.
# ?spam=1 may legitimately be fwd (shared entry stale -> revalidate) OR hit
# (background revalidations - quirk #1 addendum - keep re-warming the shared
# /static entry, so it can still be fresh here). Either is fine; the teeth of
# this test are that ?spam=2 and later HIT the same entry.
cs=$(curl -si --max-time 30 "http://localhost:$DOCS_PORT/static?spam=1" | tr -d '\r' | grep -i '^cache-status:')
{ grep -qi 'fwd=' <<<"$cs" || grep -qi '; *hit' <<<"$cs"; } && ok "GET /static?spam=1 (fwd or hit - shared /static entry either way)" || bad "GET /static?spam=1 - unexpected [$cs]"
assert_cs "GET /static?spam=2 (disable_query -> same entry as ?spam=1, HIT)" hit "http://localhost:$DOCS_PORT/static?spam=2"
assert_cs "GET /static?spam=anything-else (still the same entry, HIT)" hit "http://localhost:$DOCS_PORT/static?spam=anything-else"
assert_cs "GET /static (no query at all - also the same entry, HIT)" hit http://localhost:$DOCS_PORT/static

hdr "17. KNOWN UPSTREAM BUG: stale revalidation stores a DOUBLED body (:$DOCS_PORT)"
# Verified empirically 2026-07-25 (nuts DB dump + live hit): after a stale
# entry is revalidated, the re-Stored object contains the body TWICE, plus
# duplicated Date/Via headers, and the next fresh HIT serves the doubled
# payload (28 bytes for the 14-byte /static body, Content-Length: 28). The
# corrupt store comes from the Revalidate path (the stored object's baked
# Cache-Status reads `detail=REQUEST-REVALIDATION`): souin@v1.7.7
# pkg/middleware/middleware.go Revalidate() (~lines 594-613) Stores from
# customWriter.Buf and then `customWriter.Write(sfWriter.body)` re-appends
# the shared body into the same buffer, which the next Store on that path
# dumps wholesale. See README "Revalidation doubles the stored body".
# The fix has LANDED in the erfi.io souin fork (commit d104c5f9 in
# ~/ergo/souin pkg/middleware/middleware.go, marked `// erfi.io patch:` -
# see README "Revalidation doubles the stored body"): a successful
# Revalidate() now returns immediately instead of falling through to a
# second Upstream() fetch. This test stays dual-mode on purpose as the
# regression gate: it PASSES either way, but the branch it hits tells you
# whether the Caddy image was built against the patched fork. Against
# upstream v1.7.7 (no replace wired into the Dockerfile yet, or wired but
# not rebuilt) it reports "KNOWN BUG reproduced"; once the Dockerfile's
# `--with github.com/darkweak/souin=github.com/erfianugrah/souin@<sha>`
# replace is in place and the image is rebuilt, it reports "souin fork
# patch active".
curl -s -o /dev/null http://localhost:$DOCS_PORT/reval-target   # cold store (clean)
sleep 3                                                          # expire past 2s TTL
curl -s -o /dev/null http://localhost:$DOCS_PORT/reval-target   # stale revalidation (triggers the bug)
sleep 0.5                                                        # settle
body=$(curl -s http://localhost:$DOCS_PORT/reval-target)
if [ "$body" = "reval-body-v1reval-body-v1" ]; then
	ok "KNOWN BUG reproduced: revalidated entry serves doubled body (pin; flip after souin fork patch)"
elif [ "$body" = "reval-body-v1" ]; then
	ok "revalidated entry serves single correct body (souin fork patch active)"
else
	bad "revalidated entry body unexpected: [${body:0:80}]"
fi

cleanup
hdr "RESULT ($LABEL): $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
