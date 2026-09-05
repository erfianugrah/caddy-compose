# Fix: weekly forced Caddy `/load` from the Cloudflare proxy refresher

Status: OPEN (2026-09-05). Severity: high. Next fire: Monday 2026-09-07 06:00 UTC.

## What is wrong

`CFProxyStore.StartScheduledRefresh` (`wafctl/cfproxy.go`) wakes every Monday
at `WAF_BLOCKLIST_REFRESH_HOUR` (default 06 UTC), downloads Cloudflare's IP
ranges, rewrites `/data/waf/cf_trusted_proxies.caddy`, then calls
`reloadCaddy` (`wafctl/deploy.go`). `reloadCaddy` POSTs the entire Caddyfile
to the admin API `/load` with `Cache-Control: must-revalidate`, which forces
a full re-provision of every module even when the adapted JSON is unchanged.

Nothing consumes the file it refreshes:

- `deploy/edge/Caddyfile` has no `import` of `cf_trusted_proxies.caddy`. The
  only mention is the header comment saying "no cf_trusted_proxies". The
  `erfianugrah.com` trusted-proxy list is inline and static.
- The servarr `Caddyfile` header records that the import was dropped on
  2026-07-24, and no caddy container runs on servarr today.

So every Monday the edge gets a pointless full re-provision. That matters for
three reasons:

1. `/load` replaces the whole config and wipes anything pushed through the
   admin API. PLAN.md "Direction Change" item 3 makes admin-API-pushed site
   config the future of edgectl; this timer would erase it weekly.
2. Re-provision is where the ja4 accept-loop wedge happened
   (`docs/2026-08-08-ja4-accept-loop-wedge.md`). Fewer unnecessary
   re-provisions, fewer chances to hit that class of bug.
3. The reload goes through the `:2020` admin proxy; a failure only logs a
   warning and returns `status: partial`, so nobody notices either way.

Log evidence on the router (wafctl boot lines, 2026-09-04):

```
[cfproxy] next scheduled refresh at 2026-09-07T06:00:00Z (in 66h16m23s)
```

## Fix plan

Two stages. Stage 1 is a compose-only stopgap that can ship today. Stage 2
removes the feature.

### Stage 1: stopgap before Monday (compose only)

`reloadCaddy` is the only consumer of `DeployConfig.CaddyAdminURL` (confirm
with `rg -n 'CaddyAdminURL|reloadCaddy\(' wafctl/*.go`). Pointing it at a
closed port makes the reload fail fast and harmlessly:

1. In `deploy/edge/compose.yaml`, wafctl service environment, change
   `WAF_CADDY_ADMIN_URL=http://caddy:2020` to
   `WAF_CADDY_ADMIN_URL=http://127.0.0.1:1` with a comment pointing at this
   doc.
2. `git commit -m "chore(edge): neutralise wafctl weekly caddy reload"`,
   `git push`, `make restart`.
3. Verify: `ssh router 'docker logs wafctl 2>&1 | grep -E "cfproxy|admin"'`
   still shows the schedule line (expected; the timer still runs). On Monday
   after 06:00 UTC expect `[cfproxy] warning: Caddy reload failed` and no
   `config reload`/`serving initial configuration` lines in
   `docker logs caddy --since 2026-09-07T05:55:00Z`.

Skip this stage if stage 2 ships before Monday.

### Stage 2: remove the CF proxy store

The store, its handlers, the build stage and the seed step all serve the
same dead feature. Removal list (verified by `rg -l 'cfproxy|CFProxy|cf_trusted_proxies'`):

| File | Change |
|---|---|
| `wafctl/cfproxy.go` | delete |
| `wafctl/cfproxy_test.go` | delete |
| `wafctl/main.go` | remove `cfProxyStore` construction, `StartScheduledRefresh` call, routes `GET /api/cfproxy/stats` and `POST /api/cfproxy/refresh`, and the `cfProxyStore` argument to `handleHealth` |
| `wafctl/handlers_events.go` | drop the `cfProxyStore *CFProxyStore` parameter and the `"cfproxy"` entry in the health `stores` map |
| `wafctl/models.go` | delete `CFProxyStatsResponse`, `CFProxyRefreshResponse` |
| `wafctl/testhelpers_test.go` | drop the `NewCFProxyStore` argument from the `handleHealth` helper |
| `wafctl/deploy.go` | delete `reloadCaddy` and `deployFingerprint` (no remaining callers); drop the `CaddyAdminURL` field and the `CaddyfilePath` comment that says it is used for reload (`CaddyfilePath` stays: `BuildServiceFQDNMap` reads it) |
| `wafctl/deploy_test.go` | delete `TestDeployFingerprint` |
| `wafctl/main.go` | the `WriteTimeout: 150 * time.Second` comment references the 120 s reload client; lower to 60 s or reword |
| `Dockerfile` | delete the `cloudflare-ips` build stage and its `COPY --from=cloudflare-ips` line |
| `scripts/entrypoint.sh` | delete the CF seed block; keep `mkdir -p /data/waf` and the `exec` |
| `README.md` | drop the "Cloudflare trusted proxies" bullet under Security hardening and any `/api/cfproxy` rows |
| `AGENTS.md` (caddy-compose) | remove `CFProxyStore` from store lists and the "wafctl -> Caddy admin routing" note if nothing else uses `:2020` (edgectl will; keep the proxy block in the Caddyfile) |

The dashboard has no references (`rg -i cfproxy waf-dashboard/src` is empty).

Keep `WAF_CADDY_ADMIN_URL` and the `:2020` admin proxy block in the Caddyfile
if edgectl host management is coming next; otherwise remove both.

Steps:

1. Make the code changes above.
2. `cd wafctl && gofmt -l . && go vet ./... && go test -count=1 -timeout 60s ./...`
3. `make build-caddy build-wafctl` to prove the Dockerfile and entrypoint
   edits build, then `make test-e2e` (needs Docker) to prove both containers
   still start and wafctl reaches healthy without the seed step.
4. Bump `WAFCTL_IMAGE` and `CADDY_IMAGE` project versions (see
   `2026-09-05-fix-version-tag-sync.md` for the file list), commit, push, let
   CI build, then `make restart`.
5. Revert the stage 1 stopgap in the same commit if it shipped.

## Verification

```bash
ssh router 'docker logs wafctl 2>&1 | grep -c cfproxy'       # expect 0 after stage 2
ssh router 'docker exec wafctl wget -qO- http://localhost:8080/api/health' | jq '.stores | keys'
# expect no "cfproxy" key
ssh router 'docker logs caddy --since 2026-09-07T05:55:00Z 2>&1 | grep -iE "reload|initial configuration"'
# expect nothing on Monday morning
```

## Rollback

Stage 1: revert the compose line, `make restart`. Stage 2: redeploy the
previous image tags in `deploy/edge/compose.yaml` and `make restart`.
