# cachectl

Ops CLI for the edge HTTP cache (cache-handler/Souin + nuts on-disk storage)
on the MS-01 edge router. Stdlib-only Go, no external deps.

Why this exists: the souin admin API permanently returns `[]` and admin PURGE
is a no-op (test/cache/README.md quirk #3), direct `PURGE <url>` only works
when the origin cooperates (quirk #4), and the nuts storage layout has three
upstream traps (per-site storage section). All live cache inspection and
reclaim therefore goes through the filesystem + caddy logs, which this tool
wraps.

## Usage

```bash
go run . status              # storage layout, per-site DB sizes, fallback check, RAM
go run . verify              # hard asserts (exit 1 on any failure) - the post-deploy gate
go run . probe <url> [url..] # request each URL twice via the edge, print Cache-Status
go run . purge <site|all>    # delete the site's nuts dir + restart caddy (-y skips confirm)

# or build once:
make build-cachectl          # -> tools/cachectl/cachectl
```

Env overrides: `SSH_HOST` (router), `CONTAINER` (caddy), `EDGE_IP`
(auto-detected via ifconfig.me from the edge), `HOST_ROOT`, `CTR_ROOT`.

## Semantics

- `verify` asserts: zero in-memory-fallback warnings since container start,
  every per-site `Dir` configured in the Caddyfile has a live `0.dat`, and no
  `/tmp/souin-nuts` default-path DB (the tmpfs Dir-drop trap). Wired into
  `make edge-verify` as the post-deploy gate.
- `probe` dials the edge IP directly (curl `--resolve` equivalent) with
  browser-ish headers over HTTP/2. Both choices are load-bearing: plain
  HTTP/1.1 requests with default Go headers trip the edge WAF's detect rules,
  and block pages are never cached - the response carries no `Cache-Status`
  header, which looks exactly like a cache bug but isn't (found 2026-08-01).
  Expect `#1 fwd=uri-miss;stored`, `#2 hit; detail=NUTS`. `detail=DEFAULT`
  means the handler fell back to in-memory storage.
- `purge` is THE ONLY working cache purge: delete the site's nuts dir inside
  the container + `docker restart caddy`; nuts re-creates the DB at open.

## Development

```bash
go test -race -count=1 ./...   # hermetic tests (scripted fake Runner, no ssh)
gofmt -w . && go vet ./...
```

Layout: `main.go` (dispatch), `runner.go` (config + Runner seam + edge
helpers), `status.go`, `verify.go`, `probe.go`, `purge.go`, `cachectl_test.go`.
The `Runner` interface is the test seam - every ssh/docker op flows through
it, so tests script remote responses instead of shelling out.
