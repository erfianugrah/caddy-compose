# caddy-compose

Caddy reverse proxy for the **servarr** host, with Coraza WAF, per-service rate limiting, Authelia 2FA forward auth, custom error pages, and comprehensive security headers. Replaces the previous Cloudflare Tunnel (cloudflared) setup with direct public traffic to Caddy.

All service subdomains are on **erfi.io**.

## Architecture

```
Internet -> Caddy (host network, :443) -> backend containers (Docker bridge IPs)
                                      \-> Authelia (172.19.99.2:9091) for forward auth
```

- **Caddy** runs with `network_mode: host` (binds :80, :443, :2019 admin)
- **Authelia** runs on an isolated bridge network (`172.19.99.0/24`, static IP `172.19.99.2`)
- Caddy reaches Authelia directly at `172.19.99.2:9091`; all other backends are on their existing Docker bridge networks
- Metrics served via admin API at `localhost:2019/metrics`, proxied through `caddy-prometheus.erfi.io`

## Docker image

Pre-built and pushed to Docker Hub: **`erfianugrah/caddy:2.10.2`**

Built locally with `docker build`, **not** on the host. The image includes:

- Caddy 2.10.2 with plugins: `caddy-dns/cloudflare`, `caddy-dynamicdns`, `caddy-ratelimit`, `coraza-caddy/v2`
- Custom Coraza WAF rules (`coraza/pre-crs.conf`, `coraza/post-crs.conf`) baked in
- Custom error pages (`errors/error.html`) baked in at `/etc/caddy/errors/`
- IPsum blocklist (~20k IPs) fetched at build time — never starts with an empty blocklist
- Entrypoint script that starts `crond` (for IPsum updates) + `caddy run`

### Building a new image

```bash
# Build (fetches fresh IPsum at build time)
docker build -t erfianugrah/caddy:2.10.2 .

# Push to Docker Hub
docker push erfianugrah/caddy:2.10.2
```

To bump the Caddy version, change the `ARG VERSION` in the `Dockerfile`.

## Services proxied

| Subdomain | Backend | Rate limit | Authelia |
|-----------|---------|------------|----------|
| `authelia.erfi.io` | `172.19.99.2:9091` | 200/min | -- |
| `servarr.erfi.io` | `localhost:90` | 1000/min | two_factor |
| `sonarr.erfi.io` | `172.19.1.3:8989` | 300/min | -- |
| `radarr.erfi.io` | `172.19.1.2:7878` | 300/min | -- |
| `bazarr.erfi.io` | `172.19.1.4:6767` | 300/min | -- |
| `vault.erfi.io` | `172.19.4.2:80` | 300/min | -- |
| `prowlarr.erfi.io` | `172.19.1.10:9696` | 300/min | -- |
| `jellyfin.erfi.io` | `172.19.1.15:8096` | 1000/min | -- |
| `qbit.erfi.io` | `172.19.1.22:8080` | 300/min | -- |
| `change.erfi.io` | `172.19.3.2:5000` | 300/min | -- |
| `seerr.erfi.io` | `172.19.1.21:5055` | 300/min | -- |
| `keycloak.erfi.io` | `172.19.12.2:8080` | 100/min | -- |
| `joplin.erfi.io` | `172.19.13.2:22300` | 300/min | -- |
| `navidrome.erfi.io` | `172.19.1.17:4533` | 1000/min | -- |
| `sabnzbd.erfi.io` | `172.19.1.19:6666` | 300/min | -- |
| `immich.erfi.io` | `172.19.22.2:2283` | 1000/min | -- |
| `caddy-prometheus.erfi.io` | `localhost:2019` | 100/min | -- |
| `copyparty.erfi.io` | `172.19.66.2:3923` | 300/min | -- |
| `dockge-sg.erfi.io` | `172.17.0.2:5001` | 100/min | -- |
| `caddy.erfi.io` | static response | 100/min | -- |

Rate limit tiers:
- **1000/min** — media-heavy services (jellyfin, navidrome, immich, servarr)
- **300/min** — standard services (sonarr, radarr, bazarr, etc.)
- **200/min** — authelia (auth endpoint)
- **100/min** — admin/low-traffic (caddy, caddy-prometheus, keycloak, dockge)

WebSocket upgrade requests are excluded from rate limiting automatically.

Authelia is currently applied to `servarr.erfi.io` only. Add `import forward_auth` to other site blocks and a corresponding `access_control` rule in `authelia/configuration.yml` to expand coverage.

## File structure

```
caddy-compose/
  Caddyfile              # Caddy config (snippets + 20 site blocks)
  Dockerfile             # Custom Caddy build (plugins + IPsum + Coraza rules + error pages)
  compose.yaml           # Caddy + Authelia services (image-only, no build context)
  .env                   # Secrets — SOPS-encrypted, used by Docker Compose
  .gitignore
  .dockerignore
  README.md
  authelia/
    configuration.yml    # Authelia config (committed — secrets are in .env)
    users_database.yml   # User/password hashes (committed)
  coraza/
    pre-crs.conf         # Custom WAF rules loaded BEFORE OWASP CRS (XXE, body settings)
    post-crs.conf        # Custom WAF rules loaded AFTER OWASP CRS (RCE, CRLF)
  errors/
    error.html           # Custom error page template (Caddy templates, dark theme)
  scripts/
    entrypoint.sh        # Container entrypoint — starts crond + caddy run
    update-ipsum.sh      # Fetches IPsum blocklist, generates Caddy snippet, reloads Caddy
  test/
    Caddyfile.test       # Local test config (no TLS, no Cloudflare)
    docker-compose.test.yml  # Test stack (Caddy + httpbun)
```

## Security hardening

Both containers are hardened:

| Feature | Caddy | Authelia |
|---------|-------|----------|
| `read_only: true` | yes | yes |
| `cap_drop: ALL` | yes | yes |
| `cap_add` | `NET_BIND_SERVICE`, `DAC_OVERRIDE` | none |
| `no-new-privileges` | yes | yes |
| `user` | root (needs port 443) | `1000:1000` |
| Healthcheck | yes | yes |
| Resource limits | 4 CPU / 1024M | 1 CPU / 256M |

### Security headers

Applied globally to every site via `import security_headers`:

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | HSTS — 2 year max-age, preload-eligible |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME-type sniffing |
| `X-Frame-Options` | `SAMEORIGIN` | Clickjacking protection |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Restrict browser features |
| `Cross-Origin-Opener-Policy` | `same-origin` | Prevent cross-origin window references |
| `Cross-Origin-Resource-Policy` | `same-origin` | Prevent cross-origin resource embedding |
| `X-Permitted-Cross-Domain-Policies` | `none` | Block Flash/PDF cross-domain |
| `Content-Security-Policy` | See below | Baseline CSP for all services |
| `-Server` | removed | Hide server identity |
| `-X-Powered-By` | removed | Hide framework identity |

**Content-Security-Policy baseline:**

```
default-src 'self';
script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https:;
worker-src 'self' blob:;
style-src 'self' 'unsafe-inline' https:;
img-src 'self' data: blob: https:;
font-src 'self' data: https:;
connect-src 'self' wss: ws: https:;
media-src 'self' blob: https:;
frame-src 'self' https:;
object-src 'none';
frame-ancestors 'self';
base-uri 'self';
form-action 'self';
upgrade-insecure-requests
```

This is a permissive baseline that works across all proxied services (Jellyfin plugins, Unraid WebGUI, etc.). It allows any HTTPS external resource for scripts, styles, fonts, images, frames, and media, while blocking HTTP resources, `object` embeds, and restricting `frame-ancestors`, `base-uri`, and `form-action` to `self`.

Upstream CSP headers from backend services are stripped in `proxy_headers` so the global policy takes precedence.

### Coraza WAF

OWASP Core Rule Set plus custom rules for gaps CRS doesn't cover:

| Rule file | Loaded | Covers |
|-----------|--------|--------|
| `@crs-setup.conf.example` + `@owasp_crs/*.conf` | CRS baseline | SQLi, XSS, path traversal, LFI, RCE, scanners, Log4Shell, SSRF |
| `coraza/pre-crs.conf` | Before CRS | XXE (DOCTYPE/ENTITY SYSTEM/PUBLIC, parameter entities), request body settings |
| `coraza/post-crs.conf` | After CRS | RCE pipe-to-command, backtick substitution, CRLF injection |

`@coraza.conf-recommended` is intentionally **not** loaded — it activates the XML body processor which prevents regex-based XXE detection on `REQUEST_BODY`. The necessary settings are in `pre-crs.conf` instead.

**WebSocket bypass:** The WAF automatically skips WebSocket upgrade requests (`Connection: Upgrade` header). Coraza interferes with the HTTP 101 upgrade handshake, so these are excluded via a `@not_websocket` matcher in the `(waf)` snippet.

**Test results:** 34/34 attack vectors blocked, 7/7 legitimate requests passed (SQLi, XSS, path traversal, RCE, XXE, Log4Shell, SSRF, CRLF, scanner detection).

### Custom error pages

A dark-themed error page (`errors/error.html`) is served for all HTTP errors via the `(error_pages)` snippet. It uses Caddy's `templates` module with per-status-code messages:

| Status | Title | Description |
|--------|-------|-------------|
| 403 | Access denied | Permission denied |
| 404 | Not found | Page doesn't exist or moved |
| 429 | Slow down | Rate limit exceeded |
| 500 | Internal server error | Server-side failure |
| 502 | Bad gateway | Upstream not responding |
| 503 | Service unavailable | Maintenance |
| 504 | Gateway timeout | Upstream timeout |
| Other | Something went wrong | Generic fallback |

The error page is baked into the Docker image at `/etc/caddy/errors/` (not `/srv/`, which is overridden by the site bind mount).

### Encrypted Client Hello (ECH)

ECH hides the real domain name (SNI) from ISPs and network eavesdroppers during the TLS handshake. Without ECH, the SNI is sent in plaintext, revealing which service you're connecting to even though the traffic itself is encrypted.

Caddy automatically generates ECH key pairs and publishes them as HTTPS DNS records via Cloudflare. The public name `ech.erfi.io` appears in the outer ClientHello instead of the real domain.

**How it works:**

1. Caddy generates ECH configs (public/private key pairs) and publishes HTTPS-type DNS records for all domains
2. Client browsers look up the HTTPS record, get the ECH config, and encrypt the real SNI
3. The ISP only sees connections to `ech.erfi.io` — not the actual service domain

**Client requirements for full privacy:**

- Browser must support ECH (Firefox, Chrome)
- Browser must use **DNS-over-HTTPS (DoH)** or **DNS-over-TLS (DoT)** — plaintext DNS would leak the domain anyway
  - Firefox: Settings > Privacy & Security > DNS over HTTPS > Max Protection
- Clear DNS cache after enabling (`about:networking#dns` in Firefox)

**Verification:**

- Capture the TLS ClientHello with Wireshark — the SNI field should show `ech.erfi.io`, not the real domain
- Check that ECH configs are published: `dig +short HTTPS jellyfin.erfi.io` should return a record with `ech=` data

### Other security layers

- **Per-service rate limiting** via `import rate_limit <zone> <events> <window>` — WebSocket upgrades excluded
- **Authelia forward auth** for protected services (`import forward_auth`)
- **IPsum blocklist** via `import ipsum_blocklist` (~20k IPs baked in at build, updated daily by cron)
- **Admin API** locked to `localhost:2019`
- **Strict SNI** host checking enabled
- **Cloudflare trusted proxies** configured
- **HTTP/1.1, HTTP/2, HTTP/3** all enabled (H3 via QUIC)
- **ECH** — encrypts SNI to hide domain names from network observers

## Caddyfile snippets

Reusable snippets to keep site blocks DRY:

| Snippet | Usage | Purpose |
|---------|-------|---------|
| `(cors)` | `import cors` | CORS preflight + headers |
| `(security_headers)` | `import security_headers` | HSTS, CSP, COOP, CORP, nosniff, referrer-policy, permissions-policy |
| `(waf)` | `import waf` | Coraza WAF with OWASP CRS + custom rules (auto-skips WebSocket) |
| `(rate_limit)` | `import rate_limit <zone> <events> <window>` | Per-client-IP rate limiting (excludes WebSocket) |
| `(tls_config)` | `import tls_config` | ACME DNS challenge via Cloudflare |
| `(site_log)` | `import site_log <name>` | Per-site JSON access log |
| `(ipsum_blocklist)` | `import ipsum_blocklist` | IPsum threat intelligence IP blocklist |
| `(forward_auth)` | `import forward_auth` | Authelia forward authentication |
| `(proxy_headers)` | `import proxy_headers` | Trusted proxies + forwarded headers + strip upstream CORS/CSP (inside `reverse_proxy`) |
| `(error_pages)` | `import error_pages` | Custom error pages via handle_errors + templates |

## Setup

### Prerequisites

- Docker
- A Cloudflare API token with DNS edit permissions for `erfi.io`
- DNS records for all subdomains pointing to the server's public IP (managed by Caddy's `dynamic_dns` or Terraform)
- **Dockge** on the servarr host (manages docker compose stacks)

### 1. Clone and configure secrets

```bash
git clone <repo-url> caddy-compose && cd caddy-compose

# Decrypt .env (requires your age key)
sops -d -i .env
# Or create .env manually if starting fresh
```

Populate `.env`:

```bash
CF_API_TOKEN=<your-cloudflare-api-token>
EMAIL=<your-email>

# Generate each with: openssl rand -hex 32
AUTHELIA_JWT_SECRET=<random-64-char-hex>
AUTHELIA_SESSION_SECRET=<random-64-char-hex>
AUTHELIA_STORAGE_ENCRYPTION_KEY=<random-64-char-hex>
```

### 2. Configure Authelia users

Generate a password hash:

```bash
docker run --rm authelia/authelia:latest \
  authelia crypto hash generate argon2 --password 'your_password_here'
```

Edit `authelia/users_database.yml` and replace the placeholder hash.

### 3. Build and push the image (from your workstation)

```bash
docker build -t erfianugrah/caddy:2.10.2 .
docker push erfianugrah/caddy:2.10.2
```

### 4. Deploy to servarr

```bash
# Create host directories
ssh servarr 'mkdir -p /mnt/user/data/caddy/{site,data,config,log} /mnt/user/data/authelia/config'

# Copy configs
scp Caddyfile servarr:/mnt/user/data/caddy/Caddyfile
scp authelia/configuration.yml servarr:/mnt/user/data/authelia/config/
scp authelia/users_database.yml servarr:/mnt/user/data/authelia/config/

# Copy compose + .env to Dockge's stacks directory
scp compose.yaml servarr:/mnt/user/data/dockge/stacks/caddy/compose.yaml
scp .env servarr:/mnt/user/data/dockge/stacks/caddy/.env
```

Then deploy via Dockge UI.

### 5. Verify

```bash
# Test Authelia portal
curl -I https://authelia.erfi.io

# Test protected service (should redirect to Authelia)
curl -I https://servarr.erfi.io
```

## Operations

### Reload Caddy config

```bash
scp Caddyfile servarr:/mnt/user/data/caddy/Caddyfile
ssh servarr 'docker exec caddy caddy reload --config /etc/caddy/Caddyfile'
```

### View logs

```bash
# Caddy access logs
ssh servarr 'docker exec caddy tail -f /var/log/access.log'

# Per-site logs
ssh servarr 'docker exec caddy tail -f /var/log/servarr-access.log'

# Authelia logs
ssh servarr 'docker exec authelia cat /config/authelia.log'

# Coraza WAF audit
ssh servarr 'docker exec caddy tail -f /var/log/coraza-audit.log'
```

### Register TOTP (first time)

With the filesystem notifier, TOTP registration links are written to a file instead of emailed:

```bash
ssh servarr 'cat /mnt/user/data/authelia/config/notification.txt'
```

Open the link to register your TOTP device. For production, replace the filesystem notifier with SMTP in `authelia/configuration.yml`.

### IPsum blocklist

The IPsum blocklist is fetched from [stamparm/ipsum](https://github.com/stamparm/ipsum) and converted into a Caddy-importable snippet. It blocks IPs with a threat score >= 3.

- **At build time**: The Dockerfile fetches a fresh copy and bakes it into the image at `/etc/caddy/ipsum_block.caddy`
- **At runtime**: The entrypoint script starts `crond` which runs `update-ipsum.sh` daily to fetch fresh data and reload Caddy.

### Expand Authelia to more services

1. Add `import forward_auth` to the site block in `Caddyfile`
2. Add an `access_control` rule in `authelia/configuration.yml`:
   ```yaml
   - domain: 'dockge-sg.erfi.io'
     policy: 'two_factor'
   ```
3. Reload Caddy and restart Authelia

### Update the Caddy image

```bash
# On your workstation
docker build -t erfianugrah/caddy:2.10.2 .
docker push erfianugrah/caddy:2.10.2

# On servarr — pull new image and recreate via Dockge (Down + Up)
```

### DNS considerations

When migrating from Cloudflare Tunnel to direct public traffic:

- **LB vs CNAME conflict**: If a CNAME record (from the tunnel) and an LB/A record exist for the same hostname, behavior is undefined. Delete the existing CNAME before creating A records or LB entries.
- Caddy's `dynamic_dns` will create/update A records automatically, but pre-existing CNAMEs from the tunnel config must be removed first.
- The tunnel ingress in `tunnels.tf` should be decommissioned after the DNS migration is verified.

## Known issues

- **`superfluous response.WriteHeader`** — Info-level noise from Caddy's metrics delegator + encode middleware. Harmless, cannot fix from config.
- **YouTube `postMessage` errors** — YouTube iframes post messages to the parent origin; cross-origin mismatch causes console errors. Not fixable at proxy level.
- **Jellyfin Enhanced plugin errors** — `video.requestPictureInPicture is not a function` is a plugin bug, not proxy-related.

## TODO

- [ ] **SMTP notifier** — Replace filesystem notifier with real email delivery
- [ ] **Expand Authelia** — Add forward auth to more admin services (dockge-sg, qbit, sabnzbd, keycloak, caddy-prometheus, prowlarr, change, copyparty)
- [ ] **DNS migration** — Delete existing CNAME records from Cloudflare Tunnel before creating A/LB records (LB vs CNAME conflict)
- [ ] **Per-service CSP** — Tighten CSP for services that don't need external resources
