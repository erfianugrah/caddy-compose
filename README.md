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

### Caddy image: `erfianugrah/caddy:1.15.0-2.10.2`

Built locally, pushed to Docker Hub. Includes:

- Caddy 2.10.2 with plugins: `caddy-dns/cloudflare`, `caddy-dynamicdns`, `caddy-ratelimit`, `coraza-caddy/v2`
- Custom Coraza WAF rules (`coraza/pre-crs.conf`, `coraza/post-crs.conf`) baked in
- WAF dashboard static files (Astro build) at `/etc/caddy/waf-ui/`
- Custom error pages (`errors/error.html`) at `/etc/caddy/errors/`
- IPsum blocklist (~20k IPs) fetched at build time
- Cloudflare IP ranges fetched at build time for `trusted_proxies`
- Entrypoint script that starts `crond` (for IPsum updates) + `caddy run`

### WAF API image: `erfianugrah/waf-api:0.10.0`

Go stdlib sidecar (zero external dependencies). Provides:

- WAF event log parsing and analytics (summary, timeline, top IPs/URIs, service breakdown)
- Anomaly score extraction from rule 949110/980170 messages, with computed fallback from individual rule severities for DetectionOnly mode
- 429 rate limit event parsing from combined access log (merged into unified event stream)
- IPsum blocklist API: stats endpoint (IP count, last updated, source) and per-IP check endpoint with cached file parsing
- Custom time range queries (`?start=&end=` ISO 8601 timestamps, or `?hours=` for relative)
- Policy Engine: CRUD for exclusions, SecRule generation, deploy pipeline (writes conf files + reloads Caddy)
- CRS rule catalog (141 curated rules, 11 categories) with search/autocomplete
- WAF settings generator: emits `SecRuleEngine On/DetectionOnly/Off` + per-service `ctl:ruleEngine` overrides (single source of truth for engine mode)
- Rate limit zone configuration: per-zone `.caddy` file generation and deploy
- Deploy pipeline with SHA-256 fingerprint injection (ensures Caddy reprovisioning when only included files change)
- IP lookup, service detail, configuration management
- UUIDv7 for rate-limit event IDs (time-ordered, globally unique), Coraza tx IDs for WAF events

## Makefile

Common operations are available via `make`:

```bash
make help              # Show all targets
make config            # Show current configuration
make build             # Build both images
make build-caddy       # Build Caddy image (includes dashboard)
make build-waf-api     # Build waf-api image
make push              # Push both images to Docker Hub
make test              # Run all tests (Go + frontend)
make deploy            # Full deploy: build + push + SCP + restart
make deploy-caddy      # Build, push, SCP, restart Caddy
make deploy-waf-api    # Build, push, restart waf-api only
make scp               # SCP Caddyfile + compose.yaml to remote
make status            # Show container status on remote
make logs              # Tail logs from all containers
make waf-deploy        # Trigger WAF config deploy (generate + reload)
make waf-config        # Show current WAF config from remote
```

### Configuration

All settings can be overridden via a `.env.mk` file or inline variables:

```bash
# Create a .env.mk file (git-ignored)
echo 'REMOTE=myhost' > .env.mk
echo 'DEPLOY_MODE=compose' >> .env.mk
make deploy

# Or override inline
make deploy REMOTE=myhost DEPLOY_MODE=compose
```

| Variable | Default | Description |
|---|---|---|
| `REMOTE` | `servarr` | SSH host alias or `user@host` |
| `DEPLOY_MODE` | `dockge` | `dockge` (via dockge container) or `compose` (direct) |
| `CADDY_IMAGE` | `erfianugrah/caddy:1.15.0-2.10.2` | Caddy image tag |
| `WAF_API_IMAGE` | `erfianugrah/waf-api:0.10.0` | waf-api image tag |
| `STACK_PATH` | `/opt/stacks/caddy/compose.yaml` | Compose file path (inside dockge or on host) |
| `CADDYFILE_DEST` | `/mnt/user/data/caddy/Caddyfile` | Remote Caddyfile path for SCP |
| `COMPOSE_DEST` | `/mnt/user/data/dockge/stacks/caddy/compose.yaml` | Remote compose.yaml path for SCP |
| `DOCKGE_CONTAINER` | `dockge` | Dockge container name (dockge mode only) |
| `WAF_CONFIG_PATH` | `/mnt/user/data/waf-api/waf-config.json` | Remote waf-config.json path |
| `WAF_SETTINGS_PATH` | `/mnt/user/data/caddy/coraza/custom-waf-settings.conf` | Remote WAF settings path |

## WAF configuration

A single `(waf)` snippet handles all WAF-enabled services. Per-service settings (paranoia level, anomaly thresholds, rule groups, WAF mode) are fully dynamic — configured via the Settings page and written to `/data/coraza/custom-waf-settings.conf` by waf-api.

**The Caddyfile does NOT contain a `SecRuleEngine` directive.** The generated `custom-waf-settings.conf` is the single source of truth for the WAF engine mode. On first boot (before any deploy), the placeholder file includes `SecRuleEngine On` as a safe default.

A `(waf_off)` snippet exists for services that don't need WAF.

### WAF modes

| Mode | SecRuleEngine | Thresholds | Behavior |
|------|--------------|------------|----------|
| `enabled` | `On` | User-configured | Full blocking — requests exceeding thresholds get 403 |
| `detection_only` | `DetectionOnly` | Forced to 10000 | Log only — rules evaluate and log but never block |
| `disabled` | `Off` | N/A | No WAF processing |

Per-service overrides use `ctl:ruleEngine` to change the mode for individual services while keeping the global default. All 9 combinations of global + per-service mode transitions are supported and tested.

### Config loading order inside `(waf)`

1. `/etc/caddy/coraza/pre-crs.conf` — Baked-in defaults (body settings, JSON processor, socket.io exclusion, XXE rules, `SecResponseBodyAccess Off`)
2. `/data/coraza/custom-pre-crs.conf` — Dynamic pre-CRS exclusions (Policy Engine)
3. `@crs-setup.conf.example` — CRS default setup
4. `/data/coraza/custom-waf-settings.conf` — Dynamic settings (SecRuleEngine, paranoia, thresholds, rule groups — Settings page)
5. `@owasp_crs/*.conf` — CRS detection rules
6. `/etc/caddy/coraza/post-crs.conf` — Baked-in post-CRS rules (RCE, CRLF)
7. `/data/coraza/custom-post-crs.conf` — Dynamic post-CRS exclusions (Policy Engine)

All configs include `SecAuditLogParts ABCFHKZ` (Part K for rule match messages) for full rule match data in audit logs.

### Config persistence

All dynamic config survives container restarts:

- `waf-config.json` at `/data/waf-config.json` (volume: `/mnt/user/data/waf-api/`) — WAF settings (mode, paranoia, thresholds, per-service overrides)
- `custom-waf-settings.conf` at `/data/coraza/` (volume: `/mnt/user/data/caddy/coraza/`) — Generated SecRule directives
- `exclusions.json`, `rate-limits.json` at `/data/` — Policy Engine exclusions and rate limit zones

On startup, `ensureCorazaDir()` only creates placeholder files if they don't exist — existing deployed configs are never overwritten.

### Reload fingerprint

When only included config files change (not the Caddyfile itself), Caddy's `/load` endpoint may skip reprovisioning because the Caddyfile text is identical. To work around this, `reloadCaddy()` computes a SHA-256 fingerprint of all referenced config file contents and prepends a `# waf-api deploy <timestamp> fingerprint:<hash>` comment to the Caddyfile before POSTing to `/load`. The on-disk Caddyfile is never modified.

## WAF dashboard

Accessible at `waf.erfi.io` (protected by Authelia `two_factor`).

### Pages
- **Overview** — Timeline chart (stacked blocked/rate_limited/ipsum_blocked/logged), service breakdown donut, recent events (all types with badges), top clients/services with 4-color stacked bar charts (blocked pink, rate limited amber, ipsum violet, logged cyan/green) and legends. Grafana-style time range picker with quick ranges, custom from/to (to the second), auto-refresh intervals, refresh button
- **Blocklist** — IPsum threat intelligence stats (blocked IP count, last updated, source, min score), IP check search (look up any IP against the blocklist)
- **Events** — Paginated event table with unified WAF + 429 + IPsum event stream, event type filter (All/Blocked/Logged/Rate Limited/IPsum Blocked), type badges, anomaly score column (color-coded: cyan <10, amber 10-24, pink >=25), expandable detail rows (rule match for WAF events, rate limit details for 429s, ipsum info for blocklist blocks). Same time range picker
- **Services** — Per-service stats, top URIs, top triggered rules
- **Investigate** — Top blocked IPs, top targeted URIs
- **Policy Engine** — Three-tab rule builder:
  - **Quick Actions** — Dynamic condition builder (field/operator/value with AND/OR logic) for Allow, Block, Skip/Bypass rules. Host field has service dropdown with "All Services" option + custom text input
  - **Advanced** — ModSecurity directive types (SecRuleRemoveById, ctl:ruleRemoveById, etc.) with condition builder for runtime types
  - **Raw Editor** — CodeMirror 6 with ModSecurity syntax highlighting and CRS autocomplete
- **Rate Limits** — Per-zone rate limit configuration, enable/disable zones, deploy pipeline
- **Settings** — Per-service WAF config (paranoia level, anomaly thresholds, WAF mode) with global defaults and per-service overrides. Deploy buttons across all panels show step-by-step progress with spinner (e.g. "Saving config..." -> "Writing WAF files & reloading Caddy...")

### Policy Engine condition builder

Pick a field, operator, and value. Multiple conditions with AND/OR logic:

| Field | Operators |
|---|---|
| IP Address | equals, not equals, is in (CIDR), is not in (CIDR) |
| Path / URI | equals, not equals, contains, begins with, ends with, matches regex |
| Host / Service | equals, not equals, contains (dropdown with All Services + known services + custom input) |
| HTTP Method | equals, not equals, is in (multi-value) |
| User Agent | equals, contains, matches regex |
| Request Headers | header name + value (equals, contains, regex) |
| Query String | contains, matches regex |

When "All Services" (`*`) is selected for the Host field, the host condition is omitted from the generated SecRule — the rule applies globally.

## File structure

```
caddy-compose/
  Caddyfile              # Caddy config (snippets + 22+ site blocks)
  Dockerfile             # Multi-stage: xcaddy, ipsum, cloudflare-ips, waf-dashboard, waf-api, final
  Makefile               # Build, push, deploy, test, WAF operations
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
    models.go            # Data models (Event with AnomalyScore, SummaryResponse with RateLimited/IpsumBlocked, BlocklistStats)
    blocklist.go         # IPsum blocklist file parser, cached stats + IP check handlers
    config.go            # WAF config store (file-backed persistence, old format migration)
    exclusions.go        # Exclusion store, validation, UUIDv4/v7 generators
    generator.go         # SecRuleEngine emission, condition -> SecRule generation (AND=chain, OR=separate), All Services wildcard
    logparser.go         # Coraza audit log parser (JSON, rule match extraction, anomaly score computation, SnapshotRange)
    rl_analytics.go      # Combined access log parser for 429/ipsum events, UUIDv7 event IDs
    deploy.go            # Deploy pipeline (write conf files, SecRuleEngine placeholder, SHA-256 fingerprint, reload Caddy)
    ratelimit.go         # Rate limit zone config store + .caddy file generation
    crs_rules.go         # CRS catalog (141 rules, 11 categories, autocomplete data)
    main_test.go         # 150+ tests (WAF mode transitions, anomaly score, blocklist, exclusions, deploy, etc.)
    Dockerfile           # waf-api image (alpine + compiled binary, NOT the root Dockerfile's build stage)
    go.mod
  waf-dashboard/
    src/
      components/
        TimeRangePicker.tsx    # Grafana-style: quick ranges, custom from/to, auto-refresh
        PolicyEngine.tsx       # Three-tab policy builder (Quick/Advanced/Raw), controlled tabs, HostValueInput
        SecRuleEditor.tsx      # CodeMirror 6 with ModSecurity syntax highlighting
        EventsTable.tsx        # Unified WAF+429+ipsum events, type filter/badges, anomaly score column, expandable detail
        OverviewDashboard.tsx  # Timeline, service breakdown, recent events, 4-color stacked charts
        AnalyticsDashboard.tsx # Top IPs, top URIs charts (renamed to "Investigate")
        BlocklistPanel.tsx     # IPsum blocklist stats + IP check search
        RateLimitsPanel.tsx    # Rate limit zone config management
        ServicesList.tsx       # Per-service detail
        SettingsPanel.tsx      # WAF config management
        ui/popover.tsx         # Radix popover (used by TimeRangePicker)
      lib/
        api.ts                 # API client, types, Go<->frontend mappers, TimeRangeParams
        api.test.ts            # 38 tests
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
| Dynamic `custom-waf-settings.conf` | Between CRS setup and rules | SecRuleEngine, paranoia, thresholds, rule groups, per-service overrides |

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
| `(waf)` | Coraza WAF — unified snippet with dynamic per-service settings |
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
# Full deploy (build, push, SCP, restart)
make deploy

# Or step by step:
make build             # Build both images
make push              # Push to Docker Hub
make scp               # SCP Caddyfile + compose.yaml to servarr
make pull              # Pull images on servarr
make restart           # Restart stack

# Deploy just waf-api (faster — no Caddy rebuild)
make deploy-waf-api
```

## Operations

```bash
make status            # Container health
make logs              # Tail logs
make waf-config        # Show current WAF settings
make waf-deploy        # Trigger WAF config deploy + Caddy reload
make test              # Run all tests
```

### Reload Caddy (config-only, no restart)

```bash
scp Caddyfile servarr:/mnt/user/data/caddy/Caddyfile
ssh servarr 'docker exec caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile'
```

### Purge Cloudflare cache

```bash
curl -X POST "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/purge_cache" \
  -H "X-Auth-Email: ${CLOUDFLARE_EMAIL}" \
  -H "X-Auth-Key: ${CLOUDFLARE_API_KEY}" \
  -H "Content-Type: application/json" \
  --data '{"purge_everything":true}'
```

## TODO

- [ ] SMTP notifier for Authelia (replace filesystem notifier)
- [ ] OpenID Connect provider for native SSO (Grafana, Immich, Jellyfin, Vaultwarden)
