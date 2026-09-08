# Fix: weekly forced Caddy `/load` from the Cloudflare proxy refresher

Status: RESOLVED 2026-09-07 (deletion DEPLOYED). Stage 2 (source deletion,
53b6b9a) landed and shipped the same day as container image wafctl:2.102.0 -
the 2026-09-07 06:00 UTC fire actually HAPPENED that morning and clobbered the
live Caddy config with wafctl's stale bind-mount view (ntop.erfi.io dropped;
restored via `caddy reload` through composer), so stage 1 was skipped in favour
of immediate image deploy. Task 1 of the router migration plan
(`~/infra/router/docs/plans/2026-09-06-caddy-native-migration.md`) is complete:
running wafctl no longer has WAF_CADDY_ADMIN_URL, reloadCaddy, or the CFProxy
store. The "stage 1"/"post-cutover" sections below are kept for history.

## What is wrong

`CFProxyStore.StartScheduledRefresh` (`wafctl/cfproxy.go`) wakes every Monday
at `WAF_BLOCKLIST_REFRESH_HOUR` (default 06 UTC), downloads Cloudflare's IP
ranges, rewrites `$WAF_DIR/cf_trusted_proxies.caddy`, then calls
`reloadCaddy` (`wafctl/deploy.go:171`). `reloadCaddy` POSTs the entire
Caddyfile to the admin API `/load`, which forces a full re-provision of every
module even when the adapted JSON is unchanged.

Nothing consumes the file it refreshes:

- `deploy/edge/Caddyfile` has no `import` of `cf_trusted_proxies.caddy`. The
  only mention is the header comment saying "no cf_trusted_proxies". The
  `erfianugrah.com` trusted-proxy list is inline and static (Caddyfile line
  48); lan_only sites use `trusted_proxies private_ranges` (line 206).
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

## What changed 2026-09-06

- Trusted proxies are settled as a plain **per-site Caddyfile config surface**
  (`trusted_proxies static <cidrs>` / `trusted_proxies private_ranges`). No
  runtime refresh store, no build-time seed. A programmatic refresh API, if
  ever wanted, belongs to the control-plane backlog (PLAN.md), not here.
- The NixOS native migration means the deletion needs no image bump, no
  `make restart` deploy, and no version-sync edit: the router builds wafctl
  from the pinned `caddy-compose` flake input at cutover (plan Task 3 pins the
  post-deletion HEAD).
- `WAF_CADDY_ADMIN_URL` and the `:2020` admin-proxy vhost are removed
  entirely, not kept "for edgectl host management": native edgectl runs on the
  router host and reaches Caddy's admin API at `127.0.0.1:2019` directly; the
  `:2020` bridge hop existed only for the container. (Plan Tasks 6-7.)

## Stage 1: stopgap before Monday (compose only) - plan Task 1 half (a)

The running container executes the old CI binary, so the source deletion alone
does not stop the 2026-09-07 06:00 UTC fire. `reloadCaddy` is the only
consumer of `DeployConfig.CaddyAdminURL`, and pointing it at a closed port
makes the reload fail fast and harmlessly:

1. In `deploy/edge/compose.yaml`, wafctl service environment, change
   `WAF_CADDY_ADMIN_URL=http://caddy:2020` to
   `WAF_CADDY_ADMIN_URL=http://127.0.0.1:1` with a comment pointing at this
   doc.
2. `git commit -m "chore(edge): neutralise wafctl weekly caddy reload"`,
   `git push`, `make edge-restart` (Makefile `edge-restart: edge-sync` -
   composer stack `edge-services`; wafctl container restarts, WAN untouched).
3. Verify the env took:
   `ssh router 'docker exec wafctl env | grep WAF_CADDY_ADMIN_URL'` ->
   `WAF_CADDY_ADMIN_URL=http://127.0.0.1:1`.
4. After Monday 06:00 UTC: one `[cfproxy] warning: Caddy reload failed` in
   `docker logs wafctl`, and no `config reload` / `serving initial
   configuration` lines in `docker logs caddy --since 2026-09-07T05:55:00Z`.

## Stage 2: remove the CF proxy store - plan Task 1 half (b)

The store, its handlers, the model types, the build-time seed and the image
seed step all serve the same dead feature. Removal list (verified by
`rg -l 'cfproxy|CFProxy|cf_trusted_proxies'` on 2026-09-06):

| File | Change |
|---|---|
| `wafctl/cfproxy.go` | delete |
| `wafctl/cfproxy_test.go` | delete |
| `wafctl/main.go` | remove `cfProxyStore` construction + `StartScheduledRefresh`, the `cfProxyPath` line, routes `GET /api/cfproxy/stats` and `POST /api/cfproxy/refresh`, the `cfProxyStore` argument to `handleHealth`, and the `WAF_CADDY_ADMIN_URL` env read |
| `wafctl/handlers_events.go` | drop the `cfProxyStore *CFProxyStore` parameter and the `"cfproxy"` entry in the health `stores` map |
| `wafctl/models.go` | delete `CFProxyStatsResponse`, `CFProxyRefreshResponse` |
| `wafctl/deploy.go` | delete `reloadCaddy` (line 171) and `deployFingerprint` (line 221, its only caller); drop the `CaddyAdminURL` field (line 30) and fix the `CaddyfilePath` comment (it feeds Caddyfile service discovery for CSP/security-header deploy, not reloads); fix the `WafDir` comment (drop "trusted proxies") |
| `wafctl/deploy_test.go` | delete `TestDeployFingerprint` (line 124) and the `CaddyAdminURL` literal in the test `DeployConfig` |
| `wafctl/testhelpers_test.go` | drop the `NewCFProxyStore` creation and the `cfStore` argument from the `handleHealth` helper |
| `deploy/edge/compose.yaml` | remove the `WAF_CADDY_ADMIN_URL` line (reconciles stage 1) |
| `Dockerfile` | delete the `cloudflare-ips` build stage (line 86) and its `COPY --from=cloudflare-ips` line (line 99) |
| `scripts/entrypoint.sh` | delete the CF seed block (`CF_SEED` / `CF_RUNTIME`); keep `mkdir -p /data/waf` and the `exec` |
| `README.md` | drop the `/api/cfproxy` API row (line 379), the "Cloudflare trusted proxies" Security bullet (line 569), and the `cfproxy.go` file-tree row (line 681) |
| `AGENTS.md` (caddy-compose) | remove `CFProxyStore` from store lists and the "wafctl -> Caddy admin routing" note (nothing else uses `:2020` after the migration) |

The dashboard has no references (`rg -i cfproxy waf-dashboard/src` is empty).

Steps:

1. Make the code changes above.
2. `cd wafctl && gofmt -l . && go vet ./... && go test -count=1 -timeout 120s ./...`
3. `rg -n 'cfproxy|CFProxy|CaddyAdminURL|WAF_CADDY_ADMIN_URL|n\.caddy' wafctl/ Dockerfile scripts/ README.md`
   -> no matches (or only doc comments).
4. Commit `refactor(wafctl): remove CFProxyStore - trusted proxies are Caddyfile
   config`, push. CI rebuilds the images (used by `test/e2e`, `test/crs`, and
   as the dashboard-dist source). No version bump, no `make restart`: the
   change reaches production via the router's nix pin at cutover (plan Task 3
   sets `caddyCompose` rev to this commit's SHA; Task 10 cuts over).
5. Revert the stage 1 stopgap line in `deploy/edge/compose.yaml` in the same
   commit (it is deleted, not flipped back).

## Verification

Pre-cutover (after stage 1):

```bash
ssh router 'docker exec wafctl env | grep WAF_CADDY_ADMIN_URL'   # expect 127.0.0.1:1
# Monday morning:
ssh router 'docker logs wafctl --since 2026-09-07T05:55:00Z 2>&1 | grep cfproxy'
# expect one warning line
ssh router 'docker logs caddy --since 2026-09-07T05:55:00Z 2>&1 | grep -iE "reload|initial configuration"'
# expect nothing
```

Post-cutover (native binary):

```bash
ssh router 'journalctl -u edgectl --since "2026-09-07 05:55" | grep -c cfproxy'   # expect 0 - the store no longer exists
ssh router 'curl -s http://127.0.0.1:8080/api/health' | jq '.stores | keys'      # expect no "cfproxy" key
```

## Rollback

Stage 1: revert the compose line, `make edge-restart`. Stage 2: `git revert`
the deletion commit - it affects no running system until the router's flake
pin moves to that commit (plan Task 3), which happens atomically with the
cutover (plan Task 10), whose own rollback is `nixos-rebuild switch
--rollback` + container re-up while the composer checkout still exists.
