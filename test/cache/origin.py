#!/usr/bin/env python3
"""Controllable origin for cache-handler loop tests.
Logs every request (one line per hit) to /tmp/cachetest/origin-hits.log.
"""
import http.server
import json
import sys
import time

LOG = sys.argv[2] if len(sys.argv) > 2 else "/tmp/cachetest/origin-hits.log"
ETAG = '"v1-etag"'


def log_hit(method, path):
    with open(LOG, "a") as f:
        f.write(f"{method} {path}\n")


class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        log_hit("GET", self.path)
        p = self.path.split("?")[0]

        if p == "/static":
            # No Cache-Control at all - site-level default_cache_control decides.
            self._send(200, "static-body-v1")
        elif p == "/nostore":
            self._send(200, "never-cache", {"Cache-Control": "no-store"})
        elif p == "/private":
            self._send(200, "private-body", {"Cache-Control": "private"})
        elif p == "/etag":
            # Conditional-request revalidation target (no CC, ETag only).
            if self.headers.get("If-None-Match") == ETAG:
                self._send(304, b"", {"ETag": ETAG})
            else:
                self._send(200, "etag-body-v1", {"ETag": ETAG})
        elif p.startswith("/Items/") and "/Images/" in p:
            # Jellyfin-style image bytes, no Cache-Control (like real Jellyfin).
            self._send(200, b"\x89PNG" + bytes(4096), {"Content-Type": "image/png"})
        elif p == "/purge-ok":
            # Cooperating backend: like /static, no Cache-Control of its own
            # (site default_cache_control decides), but it DOES answer PURGE
            # successfully (see do_PURGE) - used to prove Souin's direct-
            # PURGE-to-URL passthrough eviction works when the origin
            # cooperates, in contrast to /static below.
            self._send(200, "purge-ok-body-v1")
        elif p == "/api/foo":
            self._send(200, json.dumps({"ok": True}), {"Content-Type": "application/json"})
        elif p == "/reval-target":
            # Revalidation body-integrity target (suite test 17): plain
            # cacheable body, no Cache-Control of its own (site default
            # applies, like /static).
            self._send(200, "reval-body-v1")
        elif p == "/slow":
            # Slow-origin target for the coalescing test. Sleep must stay WELL
            # UNDER the site max-age (2s): Souin's Store() subtracts the full
            # upstream response latency from the fresh TTL (souin@v1.7.7
            # pkg/middleware/middleware.go ~line 314 `ma = ma -
            # time.Since(context.Now)`), so an origin slower than max-age is
            # stored born-stale and can never produce a fresh hit (see README
            # "Slow origins are born stale"). 0.3s leaves ~1.7s of fresh life.
            time.sleep(0.3)
            self._send(200, "slow-body")
        elif p == "/vary":
            # Vary/Accept-Encoding correctness target: no Cache-Control of its
            # own (site default_cache_control decides, like /static), but the
            # body differs by the request's own Accept-Encoding and the
            # response advertises Vary so Souin must key on it (see
            # souin@v1.7.7 context/key.go computeKey + rfc/vary.go
            # GetVariedCacheKey - cited in README).
            if "gzip" in self.headers.get("Accept-Encoding", ""):
                body = "vary-gzip-body"
            else:
                body = "vary-identity-body"
            self._send(200, body, {"Vary": "Accept-Encoding"})
        elif p == "/authed":
            # Authorization isolation target: no Cache-Control of its own
            # (site default_cache_control public applies, like /static) - the
            # point is that Souin refuses to store ANY response to a request
            # carrying Authorization regardless of that public default (see
            # README "Authorization requests are never stored"). Body echoes
            # the caller's own Authorization value so the test can prove
            # there is never a stale/foreign body served.
            auth = self.headers.get("Authorization", "none")
            self._send(200, f"authed-body:{auth}")
        else:
            self._send(404, "not found")

    def do_HEAD(self):
        # BaseHTTPRequestHandler has no default do_HEAD (unhandled methods
        # answer 501) - added so the suite can exercise HEAD, which IS in
        # Souin's default allowed_http_verbs (GET, HEAD; see README "HEAD
        # request behavior"). Mirrors /static's headers with an empty body,
        # per HTTP HEAD semantics.
        log_hit("HEAD", self.path)
        p = self.path.split("?")[0]
        if p == "/static":
            self.send_response(200)
            self.send_header("Content-Length", str(len("static-body-v1")))
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        log_hit("POST", self.path)
        self._send(200, "post-ok")

    def do_PURGE(self):
        log_hit("PURGE", self.path)
        p = self.path.split("?")[0]
        if p == "/purge-ok":
            # A cooperating backend acknowledges PURGE.
            self._send(200, "purged")
        else:
            # Realistic default: most real backends (static file servers,
            # Jellyfin, etc.) don't implement PURGE at all. Respond like a
            # real server would (405), NOT like BaseHTTPRequestHandler's
            # default (501) which is a Python-specific artifact - either
            # way it's >=400, which is the point of this handler existing.
            self._send(405, "method not allowed", {"Allow": "GET, POST, HEAD"})

    def log_message(self, *a):
        pass  # quiet; we log hits ourselves


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8090
    http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
