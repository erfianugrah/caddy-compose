# caddy-compose

Caddy reverse proxy for the **servarr** host, with Coraza WAF (OWASP CRS), a WAF management dashboard, per-service rate limiting, Authelia 2FA forward auth, custom error pages, and comprehensive security headers. All service subdomains are on **erfi.io**.

## Architecture

```
Internet -> Cloudflare -> Caddy (host network, :443) -> backend containers (Docker bridge IPs)
                                                    \-> Authelia (172.19.99.2:9091) for forward auth
                                                    \-> waf-api  (172.19.98.2:8080) WAF management sidecar
```

- **Caddy** runs with `network_mode: host` (binds :80, :443, :2019 admin)
- **Authelia** runs on an isolated bridge network (`172.19.99.0/24`, static IP `172.19.99.2`)
- **waf-api** runs on a separate bridge network (`172.19.98.0/24`, static IP `172.19.98.2`)
- Caddy reaches Authelia directly at `172.19.99.2:9091`; waf-api reaches Caddy's admin API via an internal `:2020` reverse proxy site restricted to `172.19.98.0/24`
- Metrics served via admin API at `localhost:2019/metrics`, proxied through `caddy-prometheus.erfi.io`
- WAF dashboard (Astro + React + shadcn/ui) served as static files by Caddy at `waf.erfi.io`

## Docker images

### Caddy image: `erfianugrah/caddy:<version>-2.10.2`

Built locally, pushed to Docker Hub. Includes:

- Caddy 2.10.2 with plugins: `caddy-dns/cloudflare`, `caddy-dynamicdns`, `caddy-ratelimit`, `coraza-caddy/v2`
- Custom Coraza WAF rules (`coraza/pre-crs.conf`, `coraza/post-crs.conf`) baked in
- WAF dashboard static files (Astro build) at `/etc/caddy/waf-ui/`
- Custom error pages (`errors/error.html`) at `/etc/caddy/errors/`
- IPsum blocklist (~20k IPs) fetched at build time
- Cloudflare IP ranges fetched at build time for `trusted_proxies`
- Entrypoint script that starts `crond` (for IPsum updates) + `caddy run`

### WAF API image: `erfianugrah/waf-api:<version>`

Go stdlib sidecar (zero external dependencies). Provides:

- WAF event log parsing and analytics (summary, timeline, top IPs/URIs, service breakdown)
- 429 rate limit event parsing from combined access log (merged into unified event stream)
- Custom time range queries (`?start=&end=` ISO 8601 timestamps, or `?hours=` for relative)
- Policy Engine: CRUD for exclusions, SecRule generation, deploy pipeline (writes conf files + reloads Caddy)
- CRS rule catalog (141 curated rules, 11 categories) with search/autocomplete
- Rate limit zone configuration: per-zone `.caddy` file generation and deploy
- IP lookup, service detail, configuration management
- UUIDv7 for rate-limit event IDs (time-ordered, globally unique), Coraza tx IDs for WAF events

### Building

```bash
# Caddy image (includes dashboard build)
docker build -t erfianugrah/caddy:1.13.0-2.10.2 .
docker push erfianugrah/caddy:1.13.0-2.10.2

# WAF API image
docker build -t erfianugrah/waf-api:0.5.0 ./waf-api
docker push erfianugrah/waf-api:0.5.0
```

## WAF tiers

Four WAF configurations applied per-site via snippets:

| Tier | Snippet | Paranoia | Inbound Threshold | Outbound Threshold | Usage |
|------|---------|----------|-------------------|-------------------|-------|
| Tuning | `(waf)` | PL1 | 10000 | - | Most services (high threshold for tuning) |
| Moderate | `(waf_moderate)` | PL1 | 15 | 15 | qbit, dockge-sg |
| Strict | `(waf_strict)` | PL1 | 5 | 4 | (reserved for high-security) |
| Off | `(waf_off)` | - | - | - | caddy.erfi.io |

All tiers include `SecAuditLogParts ABCFHKZ` (Part K for rule match messages) for full rule match data in audit logs. Dynamic config overrides are loaded from `/data/coraza/custom-{pre,post}-crs.conf` (written by waf-api Policy Engine).

## WAF dashboard

Accessible at `waf.erfi.io` (protected by Authelia `two_factor`).

### Pages
- **Overview** — Timeline chart (stacked blocked/logged/rate_limited), service breakdown donut, recent events (all types with badges), top clients/services. Grafana-style time range picker with quick ranges, custom from/to (to the second), auto-refresh intervals, refresh button
- **Events** — Paginated event table with unified WAF + 429 event stream, event type filter (All/Blocked/Logged/Rate Limited), type badges, expandable detail rows (rule match for WAF events, rate limit details for 429s). Same time range picker
- **Services** — Per-service stats, top URIs, top triggered rules
- **Investigate** — Top blocked IPs, top targeted URIs
- **Policy Engine** — Three-tab rule builder:
  - **Quick Actions** — Dynamic condition builder (field/operator/value with AND/OR logic) for Allow, Block, Skip/Bypass rules
  - **Advanced** — ModSecurity directive types (SecRuleRemoveById, ctl:ruleRemoveById, etc.) with condition builder for runtime types
  - **Raw Editor** — CodeMirror 6 with ModSecurity syntax highlighting and CRS autocomplete
- **Rate Limits** — Per-zone rate limit configuration, enable/disable zones, deploy pipeline
- **Settings** — WAF config (anomaly thresholds, paranoia level, body limits)

### Policy Engine condition builder

Pick a field, operator, and value. Multiple conditions with AND/OR logic:

| Field | Operators |
|---|---|
| IP Address | equals, not equals, is in (CIDR), is not in (CIDR) |
| Path / URI | equals, not equals, contains, begins with, ends with, matches regex |
| Host / Service | equals, not equals, contains |
| HTTP Method | equals, not equals, is in (multi-value) |
| User Agent | equals, contains, matches regex |
| Request Headers | header name + value (equals, contains, regex) |
| Query String | contains, matches regex |

## Services proxied

| Subdomain | Backend | WAF Tier | Authelia |
|-----------|---------|----------|----------|
| `authelia.erfi.io` | `172.19.99.2:9091` | tuning | -- (bypass) |
| `waf.erfi.io` | static files | tuning | two_factor |
| `servarr.erfi.io` | `localhost:90` | tuning | two_factor |
| `change.erfi.io` | `172.19.3.2:5000` | tuning | two_factor |
| `sonarr.erfi.io` | `172.19.1.3:8989` | tuning | -- |
| `radarr.erfi.io` | `172.19.1.2:7878` | tuning | -- |
| `bazarr.erfi.io` | `172.19.1.4:6767` | tuning | -- |
| `vault.erfi.io` | `172.19.4.2:80` | tuning | -- |
| `prowlarr.erfi.io` | `172.19.1.10:9696` | tuning | -- |
| `jellyfin.erfi.io` | `172.19.1.15:8096` | tuning | -- |
| `qbit.erfi.io` | `172.19.1.22:8080` | moderate | -- |
| `seerr.erfi.io` | `172.19.1.21:5055` | tuning | -- |
| `keycloak.erfi.io` | `172.19.12.2:8080` | tuning | -- |
| `joplin.erfi.io` | `172.19.13.2:22300` | tuning | -- |
| `navidrome.erfi.io` | `172.19.1.17:4533` | tuning | -- |
| `sabnzbd.erfi.io` | `172.19.1.19:6666` | tuning | -- |
| `immich.erfi.io` | `172.19.22.2:2283` | tuning | -- |
| `caddy-prometheus.erfi.io` | `localhost:2019` | tuning | -- |
| `copyparty.erfi.io` | `172.19.66.2:3923` | tuning | -- |
| `dockge-sg.erfi.io` | `172.17.0.2:5001` | moderate | -- |
| `httpbun.erfi.io` | `172.19.90.2:80` | tuning | -- |
| `httpbin.erfi.io` | `172.19.90.2:80` | tuning | -- |
| `caddy.erfi.io` | static response | off | -- |

## File structure

```
caddy-compose/
  Caddyfile              # Caddy config (snippets + 22+ site blocks)
  Dockerfile             # Multi-stage: xcaddy, ipsum, cloudflare-ips, waf-dashboard, final
  compose.yaml           # Caddy + Authelia + waf-api services
  .env                   # CF_API_TOKEN + EMAIL only (Authelia secrets in /secrets/)
  .gitignore
  README.md
  authelia/
    configuration.yml    # Authelia config (secrets loaded from files, not inline)
    users_database.yml   # User/password hashes
  coraza/
    pre-crs.conf         # WAF rules before CRS (body settings, socket.io exclusion, XXE)
    post-crs.conf        # WAF rules after CRS (RCE, CRLF)
  errors/
    error.html           # Custom error page template (Caddy templates, dark theme)
  scripts/
    entrypoint.sh        # Container entrypoint (crond + caddy run)
    update-ipsum.sh      # Fetches IPsum blocklist, generates Caddy snippet, reloads
  waf-api/
    main.go              # HTTP handlers and routes (summary/events/services with start/end support)
    models.go            # Data models (Event with EventType, SummaryResponse with RateLimited)
    exclusions.go        # Exclusion store, validation, UUIDv4/v7 generators
    generator.go         # Condition -> SecRule generation (AND=chain, OR=separate rules)
    logparser.go         # Coraza audit log parser (JSON, rule match extraction, SnapshotRange)
    rl_analytics.go      # Combined access log parser for 429 events, UUIDv7 event IDs
    deploy.go            # Deploy pipeline (write conf files, reload Caddy admin API)
    config.go            # WAF config store
    ratelimit.go         # Rate limit zone config store + .caddy file generation
    crs_rules.go         # CRS catalog (141 rules, 11 categories, autocomplete data)
    main_test.go         # 97 tests
    Dockerfile           # Standalone waf-api image
    go.mod
  waf-dashboard/
    src/
      components/
        TimeRangePicker.tsx    # Grafana-style: quick ranges, custom from/to, auto-refresh
        PolicyEngine.tsx       # Three-tab policy builder (Quick/Advanced/Raw)
        SecRuleEditor.tsx      # CodeMirror 6 with ModSecurity syntax highlighting
        EventsTable.tsx        # Unified WAF+429 events, type filter/badges, expandable detail
        OverviewDashboard.tsx  # Timeline, service breakdown, recent events (all types)
        AnalyticsDashboard.tsx # Top IPs, top URIs charts (renamed to "Investigate")
        RateLimitsPanel.tsx    # Rate limit zone config management
        ServicesList.tsx       # Per-service detail
        SettingsPanel.tsx      # WAF config management
        ui/popover.tsx         # Radix popover (used by TimeRangePicker)
      lib/
        api.ts                 # API client, types, Go<->frontend mappers, TimeRangeParams
        api.test.ts            # 39 tests
    package.json
    astro.config.mjs
    vitest.config.ts
  test/
    Caddyfile.test
    docker-compose.test.yml
```

## Security hardening

### Container security

| Feature | Caddy | Authelia | waf-api |
|---------|-------|----------|---------|
| `read_only: true` | yes | yes | yes |
| `cap_drop: ALL` | yes | yes | yes |
| `cap_add` | `NET_BIND_SERVICE`, `DAC_OVERRIDE` | none | none |
| `no-new-privileges` | yes | yes | yes |
| `user` | root (needs port 443) | `1000:1000` | `65534` (nobody) |
| Healthcheck | yes | yes | yes |
| Resource limits | 4 CPU / 1024M | 1 CPU / 256M | 0.5 CPU / 128M |

### Authelia secrets

Secrets are stored in individual files under `/mnt/user/data/authelia/secrets/` (0600 permissions, owned by 1000:1000) and mounted into the container at `/secrets:ro`. Environment variables use the `_FILE` suffix to point to the files:

- `AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=/secrets/jwt_secret`
- `AUTHELIA_SESSION_SECRET_FILE=/secrets/session_secret`
- `AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=/secrets/storage_encryption_key`

This prevents secrets from appearing in `docker inspect`, `/proc/PID/environ`, or process listings.

### X-Forwarded-For handling

Caddy uses `{client_ip}` (resolved via `trusted_proxies`) when setting `X-Forwarded-For` for backends. This works correctly whether behind Cloudflare or direct:

- **With Cloudflare**: CF IPs are trusted (fetched at build time), Caddy resolves the real client IP from the XFF chain
- **Without Cloudflare**: Remove the `import /etc/caddy/cf_trusted_proxies.caddy` line; Caddy uses the TCP source IP

### Security headers

Applied globally via `import security_headers`: HSTS (2yr, preload), nosniff, SAMEORIGIN, strict referrer, permissions-policy, COOP, CORP, baseline CSP. See Caddyfile for full details.

### Coraza WAF

OWASP CRS loaded via `load_owasp_crs` (embedded in Coraza module), plus custom rules:

| Rule file | Phase | Covers |
|-----------|-------|--------|
| `pre-crs.conf` | Before CRS | Body settings, JSON processor, socket.io exclusion (rule 920420), XXE rules, `SecResponseBodyAccess Off` |
| `post-crs.conf` | After CRS | RCE pipe-to-command, backtick substitution, CRLF injection |
| Dynamic `custom-pre-crs.conf` | Before CRS | Written by waf-api Policy Engine (allow/block/skip rules) |
| Dynamic `custom-post-crs.conf` | After CRS | Written by waf-api Policy Engine (advanced exclusions) |

### Other security layers

- **Per-service rate limiting** via `import rate_limit <zone> <events> <window>` (WebSocket upgrades excluded)
- **Authelia forward auth** for protected services (`import forward_auth`)
- **IPsum blocklist** (~20k IPs baked in at build, updated daily by cron)
- **Admin API** locked to `localhost:2019`
- **Strict SNI** host checking enabled
- **Cloudflare trusted proxies** (build-time fetched IP ranges)
- **HTTP/1.1, HTTP/2, HTTP/3** all enabled
- **ECH** (Encrypted Client Hello) — hides SNI from network observers

## Caddyfile snippets

| Snippet | Purpose |
|---------|---------|
| `(cors)` | CORS preflight + headers |
| `(security_headers)` | HSTS, CSP, COOP, CORP, nosniff, referrer-policy, permissions-policy |
| `(waf)` | Coraza WAF — tuning tier (PL1, threshold 10000) |
| `(waf_moderate)` | Coraza WAF — moderate tier (PL1, thresholds 15/15) |
| `(waf_strict)` | Coraza WAF — strict tier (PL1, thresholds 5/4) |
| `(waf_off)` | No WAF |
| `(rate_limit)` | Per-client-IP rate limiting (excludes WebSocket) |
| `(tls_config)` | ACME DNS challenge via Cloudflare |
| `(site_log)` | Per-site JSON access log + combined access log (`mode 0644`) for 429 analytics |
| `(ipsum_blocklist)` | IPsum threat intelligence IP blocklist |
| `(forward_auth)` | Authelia forward authentication |
| `(proxy_headers)` | Trusted proxies + `{client_ip}` XFF + strip upstream CORS |
| `(error_pages)` | Custom error pages via handle_errors + templates |

## Setup

### Prerequisites

- Docker
- A Cloudflare API token with DNS edit permissions for `erfi.io`
- DNS records for all subdomains (managed by Caddy's `dynamic_dns`)
- **Dockge** on the servarr host

### 1. Configure secrets

```bash
# .env — only non-secret config
cat > .env <<EOF
CF_API_TOKEN=<your-cloudflare-api-token>
EMAIL=<your-email>
EOF

# Authelia secrets — individual files
mkdir -p /mnt/user/data/authelia/secrets
openssl rand -hex 32 > /mnt/user/data/authelia/secrets/jwt_secret
openssl rand -hex 32 > /mnt/user/data/authelia/secrets/session_secret
openssl rand -hex 32 > /mnt/user/data/authelia/secrets/storage_encryption_key
chown -R 1000:1000 /mnt/user/data/authelia/secrets
chmod 700 /mnt/user/data/authelia/secrets
chmod 600 /mnt/user/data/authelia/secrets/*
```

### 2. Configure Authelia users

```bash
docker run --rm authelia/authelia:latest \
  authelia crypto hash generate argon2 --password 'your_password_here'
```

Edit `authelia/users_database.yml` and replace the placeholder hash.

### 3. Build and deploy

```bash
# Build images
docker build -t erfianugrah/caddy:1.13.0-2.10.2 .
docker build -t erfianugrah/waf-api:0.5.0 ./waf-api

# Push
docker push erfianugrah/caddy:1.13.0-2.10.2
docker push erfianugrah/waf-api:0.5.0

# Copy configs to servarr
scp Caddyfile servarr:/mnt/user/data/caddy/Caddyfile
scp authelia/configuration.yml servarr:/mnt/user/data/authelia/config/
scp compose.yaml servarr:/mnt/user/data/dockge/stacks/caddy/compose.yaml
scp .env servarr:/mnt/user/data/dockge/stacks/caddy/.env

# Deploy
ssh servarr "docker exec dockge docker compose -f /opt/stacks/caddy/compose.yaml pull && \
  docker exec dockge docker compose -f /opt/stacks/caddy/compose.yaml up -d"
```

## Operations

### Reload Caddy (config-only, no restart)

```bash
scp Caddyfile servarr:/mnt/user/data/caddy/Caddyfile
ssh servarr 'docker exec caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile'
```

### Full deploy (new image)

```bash
ssh servarr "docker exec dockge docker compose -f /opt/stacks/caddy/compose.yaml pull && \
  docker exec dockge docker compose -f /opt/stacks/caddy/compose.yaml up -d"
```

### Purge Cloudflare cache

```bash
curl -X POST "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/purge_cache" \
  -H "X-Auth-Email: ${CLOUDFLARE_EMAIL}" \
  -H "X-Auth-Key: ${CLOUDFLARE_API_KEY}" \
  -H "Content-Type: application/json" \
  --data '{"purge_everything":true}'
```

### View logs

```bash
ssh servarr 'docker logs caddy --tail 50'           # Caddy container logs
ssh servarr 'docker logs authelia --tail 50'         # Authelia logs
ssh servarr 'docker logs waf-api --tail 50'          # WAF API logs
ssh servarr 'tail -50 /mnt/user/data/caddy/log/coraza-audit.log'  # WAF audit log
```

### Run tests

```bash
# Go tests (97 tests)
cd waf-api && go test -v -count=1 ./...

# Frontend tests (39 tests)
cd waf-dashboard && npx vitest run

# TypeScript check
cd waf-dashboard && npm run build
```

## TODO

- [ ] SMTP notifier for Authelia (replace filesystem notifier)
- [ ] OpenID Connect provider for native SSO (Grafana, Immich, Jellyfin, Vaultwarden)
- [ ] Version tagging scheme for waf-api releases
