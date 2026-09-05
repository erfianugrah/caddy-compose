# Fix: wafctl API reachable from the internet with no auth

Status: LAYER 1 DEPLOYED 2026-09-05 (commit d904752, `docker restart caddy` at 04:44 UTC). Layer 2 open. Severity: high.

## What is wrong

The wafctl HTTP API (rule CRUD, `/api/deploy`, jail add/remove, DoS config,
backup restore) is served on `waf.erfi.io` and `waf.edge.erfi.io` with no
network gate and no token.

Evidence gathered 2026-09-05:

- `dig +short waf.erfi.io` and `waf.edge.erfi.io` both return the home WAN
  address. The edge Caddyfile header still says edge names are RFC1918; that
  comment predates cutover.
- `deploy/edge/Caddyfile` site blocks `waf.edge.erfi.io` (line ~239) and
  `waf.erfi.io` (line ~371) import `tls_config_rfc2136`, `proxy_headers`,
  `error_pages`, `site_log`. Neither imports `lan_only`, `research_auth` or a
  bearer gate. `waf.erfi.io` also imports `waf_off`, so the policy engine is
  not in front of it either.
- `deploy/edge/compose.yaml` does not set `WAF_AUTH_TOKEN` on the wafctl
  service. `authMiddleware` in `wafctl/main.go` passes every request through
  when the token is empty and logs a boot warning.
- `curl -o /dev/null -w '%{http_code}' https://waf.erfi.io/api/dos/config`
  returned 200 with no headers. The dev box hairpins through the same WAN IP,
  so this proves the block has no gate, not WAN reachability by itself.
  `composer.erfi.io` on the same edge is documented as externally curl-able
  (AGENTS.md "Downstream WAF behaviour"), so 443 is open.
- The dashboard never sends an `Authorization` header (`waf-dashboard/src/lib/api/shared.ts`
  `fetchJSON`), so switching on `WAF_AUTH_TOKEN` alone would break the UI.

## Fix plan

Two layers. Layer 1 is a Caddyfile-only change and closes the hole. Layer 2
adds a bearer for WAN access and is optional.

### Layer 1: gate both dashboard hosts at Caddy

1. Confirm exposure from off-LAN before changing anything, so you have a
   before/after. Use a Fly machine, a VPS, or a phone hotspot:

   ```bash
   curl -sS -o /dev/null -w '%{http_code}\n' https://waf.erfi.io/api/health
   curl -sS -o /dev/null -w '%{http_code}\n' https://waf.erfi.io/api/rules
   ```

   Expected today: `200` for both. Record it.

2. Move the auth snippets above the site blocks. `(lan_only)`,
   `(research_auth)` and `(memledger_auth)` are defined around line 871, and
   snippet imports resolve top-down (AGENTS.md "Deployment", crash-loop of
   2026-08-11). Cut the three snippet definitions plus their comment block and
   paste them directly after `(error_pages)` (ends around line 216), before
   the first site block `composer.edge.erfi.io`. Nothing in the snippets is
   position dependent; `{$RESEARCH_TOKEN}` and `{$MEMLEDGER_TOKEN}` resolve at
   adapt time wherever the snippet lives.

3. Add the gate to both blocks. Put it first in the block so the intent is
   visible; Caddy orders `respond` before `reverse_proxy` regardless.

   ```caddyfile
   waf.edge.erfi.io {
   	import lan_only
   	import tls_config_rfc2136
   	...
   }

   waf.erfi.io {
   	import lan_only
   	import waf_off
   	import tls_config_rfc2136
   	...
   }
   ```

   `lan_only` allows `10.0.0.0/8`, `100.64.0.0/10`, `172.16.0.0/12`,
   `192.168.0.0/16` and answers 401 to everything else. The tailnet range is
   included, so remote access via Tailscale keeps working.

4. While in the file, fix the stale header (lines ~12-16 claim edge names are
   RFC1918) and either delete the `# CUTOVER-ONLY` dynamic_dns block or
   re-title it to say what it is now that MS-01 is the edge.

5. Adapt the Caddyfile locally to catch snippet-order and syntax mistakes.
   `caddy adapt` does not provision modules, so dummy env values are fine:

   ```bash
   cd ~/infra/ergo/caddy-compose
   docker run --rm --entrypoint caddy \
     -e EMAIL=x -e TSIG_CADDY_ACME=x -e CF_API_TOKEN=x -e RESEARCH_TOKEN=x \
     -e MEMLEDGER_TOKEN=x -e SERVARR_API_KEY=x \
     -v "$PWD/deploy/edge/Caddyfile:/etc/caddy/Caddyfile:ro" \
     erfianugrah/caddy:3.97.2-2.11.4 \
     adapt --config /etc/caddy/Caddyfile --adapter caddyfile > /dev/null \
     && echo ADAPT_OK
   ```

   `--entrypoint caddy` matters: the image entrypoint is `entrypoint.sh`, which
   ignores its arguments and runs `caddy run`, so without it the container
   starts serving and then fails on the dummy Cloudflare token.
   A forward snippet reference fails here with `File to import not found`.

6. Commit and deploy:

   ```bash
   git add deploy/edge/Caddyfile
   git commit -m "sec(edge): LAN-gate the wafctl dashboard hosts"
   git push
   make restart
   ssh router 'docker restart caddy'
   ```

   The `docker restart` is required, learned while shipping this on
   2026-09-05. `make restart` leaves an unchanged service definition alone,
   and `make caddy-quick-reload` answered `config is unchanged`: the Caddyfile
   is a single-file bind mount, composer's git sync writes a new inode, and
   the running container keeps the old one. Check with
   `docker exec caddy grep -c 'import lan_only' /etc/caddy/Caddyfile` against
   the host copy; `docker restart` re-resolves the mount and preserves the
   SOPS-decrypted env (AGENTS.md "Caddy reload vs restart").

7. Verify.

   ```bash
   # from off-LAN: expect 401 on both
   curl -sS -o /dev/null -w '%{http_code}\n' https://waf.erfi.io/api/health
   curl -sS -o /dev/null -w '%{http_code}\n' https://waf.edge.erfi.io/

   # from LAN or tailnet: expect 200 and a working dashboard
   curl -sS -o /dev/null -w '%{http_code}\n' https://waf.erfi.io/api/health

   # no adapt/provision errors after the reload
   ssh router 'docker logs caddy --since 5m 2>&1 | grep -Ei "error|import" | head'
   ```

   Open `https://waf.erfi.io/` in a browser on the LAN and confirm the
   Overview page loads data.

### Layer 2 (optional): bearer for WAN access

Pick one. Option A keeps the dashboard unchanged; option B is the proper
long-term shape and belongs in the edgectl work.

**Option A: Caddy bearer gate, same shape as `research_auth`.** Requires the
three-edit dance from AGENTS.md (all in one commit):

1. `.env`: `sops -d -i .env`, add `WAF_API_TOKEN=<random 32+ bytes>`,
   `sops -e -i .env`. Generate with `openssl rand -hex 32`. Register the
   value with `secretctl set` per the secret-handling skill; never paste it
   into chat or a commit message.
2. `deploy/edge/compose.yaml`: add `- WAF_API_TOKEN=${WAF_API_TOKEN}` to the
   **caddy** service environment (Caddy evaluates the snippet, not wafctl).
3. `deploy/edge/Caddyfile`: add a snippet next to `research_auth` and use it
   instead of `lan_only` on the two waf blocks:

   ```caddyfile
   (waf_auth) {
   	@denied {
   		not remote_ip 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.168.0.0/16
   		not header Authorization "Bearer {$WAF_API_TOKEN}"
   	}
   	respond @denied 401
   }
   ```

   Then `make restart`, and re-run the step 7 checks plus one with
   `-H "Authorization: Bearer $WAF_API_TOKEN"` from off-LAN expecting 200.

**Option B: wafctl `WAF_AUTH_TOKEN` plus dashboard support.** Needed pieces:

- `waf-dashboard/src/lib/api/shared.ts`: read a token from `sessionStorage`
  and set `Authorization: Bearer` in `fetchJSON`; on a 401 clear it and show a
  token prompt (a small modal in `DashboardLayout.astro`'s island or a
  `/login` page).
- `deploy/edge/compose.yaml`: `- WAF_AUTH_TOKEN=${WAF_AUTH_TOKEN}` on the
  wafctl service, value in `.env`. `WAF_CORS_ORIGINS` can stay unset; the
  dashboard is same-origin.
- `wafctl/main.go` already exempts `/api/health` and non-`/api/` paths, so
  static assets keep loading.

Do not turn on `WAF_AUTH_TOKEN` before the dashboard change lands; every
panel would 401.

## Audit the rest of the file

Run this once and check each block that has no gate and no upstream auth of
its own:

```bash
awk '/^[a-z0-9.*-]+ \{/{host=$1} /import (lan_only|research_auth|memledger_auth|waf_auth)/{gated[host]=1} END{for (h in gated) print h}' deploy/edge/Caddyfile | sort > /tmp/gated.txt
grep -oE '^[a-z0-9.*-]+ \{' deploy/edge/Caddyfile | tr -d ' {' | sort | comm -23 - /tmp/gated.txt
```

Everything printed by the second command is reachable from the WAN with only
the upstream's own login. `caddy.erfi.io` (site log `caddy-api`) deserves a
look first.

## Rollback

```bash
git revert HEAD && git push && make restart
```

The change is a Caddyfile edit only (layer 1), so rollback is a reload.
