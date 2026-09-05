# 2026-09-05 review: fix list

Findings from the 2026-09-05 review of `ergo/` (CRS side excluded). One guide
per item, each with evidence, steps, verification and rollback. Do them in
this order.

| # | Guide | Severity | Touches |
|---|---|---|---|
| 1 | [wafctl API reachable from the internet with no auth](2026-09-05-fix-waf-api-exposure.md) (layer 1 deployed 2026-09-05, commit d904752) | high | `deploy/edge/Caddyfile`, optionally `.env` + `deploy/edge/compose.yaml` |
| 2 | [Weekly forced Caddy `/load` from the CF proxy refresher](2026-09-05-fix-cfproxy-weekly-reload.md) | high (fires Mon 2026-09-07 06:00 UTC) | `wafctl/cfproxy.go`, `wafctl/main.go`, `Dockerfile`, `scripts/entrypoint.sh` |
| 3 | [`tsc --noEmit` broken by TypeScript 7 `baseUrl` removal](2026-09-05-fix-tsconfig-baseurl.md) | medium | `waf-dashboard/tsconfig.json`, `.github/workflows/build.yml` |
| 4 | [Image tag drift across the five version files](2026-09-05-fix-version-tag-sync.md) | medium | `Makefile`, `compose.yaml`, `deploy/edge/compose.yaml`, `README.md`, `.github/workflows/build.yml` |
| 5 | [CSP and header deploy paths drop the challenge HMAC key](2026-09-05-fix-deploy-paths-hmac.md) | low (moot after WAF removal) | `wafctl/csp.go`, `wafctl/security_headers.go`, `wafctl/deploy.go` |

The non-fix findings (API shape, config management, policy builder, UI data
layer, CI gates) are tracked as the improvement backlog in
`../PLAN.md` "Review Backlog (2026-09-05)", sequenced against the WAF nuke.

Verified state at review time:

- Router runs `erfianugrah/caddy:3.97.2-2.11.4` and `erfianugrah/wafctl:2.101.3`
  (`docker inspect` on `router`).
- No caddy container is running on `servarr`, so the root `compose.yaml` and
  root `Caddyfile` in this repo have no live consumer.
- `waf.erfi.io`, `waf.edge.erfi.io` and `composer.erfi.io` all resolve to the
  home WAN address. MS-01 is the live public edge.
- wafctl Go tests and dashboard Vitest pass. `tsc --noEmit` fails (item 3).

Every deploy in these guides goes through `make restart` from
`caddy-compose/` (composer sync + SOPS decrypt + compose up). Do not use
`make restart-caddy` or `make restart-wafctl` for anything that touches
`.env` or env passthrough; see AGENTS.md "Deployment".
