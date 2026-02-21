# caddy-compose

Caddy reverse proxy for the **servarr** host, with Coraza WAF, per-service rate limiting, and Authelia 2FA forward auth. Replaces the previous Cloudflare Tunnel (cloudflared) setup with direct public traffic to Caddy.

All service subdomains are on **erfi.io**.

## Architecture

```
Internet -> Caddy (host network, :443) -> backend containers (Docker bridge IPs)
                                      \-> Authelia (172.19.99.2:9091) for forward auth
```

- **Caddy** runs with `network_mode: host` (binds :80, :443, :2018 metrics, :2019 admin)
- **Authelia** runs on an isolated bridge network (`172.19.99.0/24`, static IP `172.19.99.2`)
- Caddy reaches Authelia directly at `172.19.99.2:9091`; all other backends are on their existing Docker bridge networks

## Docker image

Pre-built and pushed to Docker Hub: **`erfianugrah/caddy:2.10.2`**

Built locally with `docker build`, **not** on the host. The image includes:

- Caddy 2.10.2 with plugins: `caddy-dns/cloudflare`, `caddy-dynamicdns`, `caddy-ratelimit`, `coraza-caddy/v2`
- Custom Coraza WAF rules (`coraza/pre-crs.conf`, `coraza/post-crs.conf`) baked in
- IPsum blocklist (~20k IPs) fetched at build time — never starts with an empty blocklist

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
| `authelia.erfi.io` | `172.19.99.2:9091` | 50/min | -- |
| `servarr.erfi.io` | `localhost:90` | 15/min | two_factor |
| `sonarr.erfi.io` | `172.19.1.3:8989` | 100/min | -- |
| `radarr.erfi.io` | `172.19.1.2:7878` | 100/min | -- |
| `bazarr.erfi.io` | `172.19.1.4:6767` | 100/min | -- |
| `vault.erfi.io` | `172.19.4.2:80` | 100/min | -- |
| `prowlarr.erfi.io` | `172.19.1.10:9696` | 100/min | -- |
| `jellyfin.erfi.io` | `172.19.1.15:8096` | 300/min | -- |
| `qbit.erfi.io` | `172.19.1.22:8080` | 15/min | -- |
| `change.erfi.io` | `172.19.3.2:5000` | 100/min | -- |
| `seerr.erfi.io` | `172.19.1.21:5055` | 100/min | -- |
| `keycloak.erfi.io` | `172.19.12.2:8080` | 15/min | -- |
| `joplin.erfi.io` | `172.19.13.2:22300` | 100/min | -- |
| `navidrome.erfi.io` | `172.19.1.17:4533` | 300/min | -- |
| `sabnzbd.erfi.io` | `172.19.1.19:6666` | 15/min | -- |
| `immich.erfi.io` | `172.19.22.2:2283` | 100/min | -- |
| `caddy-prometheus.erfi.io` | `localhost:2018` | 15/min | -- |
| `copyparty.erfi.io` | `172.19.66.2:3923` | 100/min | -- |
| `dockge-sg.erfi.io` | `172.17.0.2:5001` | 15/min | -- |
| `caddy.erfi.io` | static response | 15/min | -- |

Authelia is currently applied to `servarr.erfi.io` only. Add `import forward_auth` to other site blocks and a corresponding `access_control` rule in `authelia/configuration.yml` to expand coverage.

## File structure

```
caddy-compose/
  Caddyfile              # Caddy config (snippets + 21 site blocks)
  Dockerfile             # Custom Caddy build (plugins + IPsum + Coraza rules baked in)
  docker-compose.yml     # Caddy + Authelia services (image-only, no build context)
  .env                   # Secrets — plaintext, gitignored, used by Docker Compose
  .env.enc               # Secrets — SOPS-encrypted copy, committed to git
  .sops.yaml             # SOPS encryption rules
  .gitignore
  .dockerignore
  authelia/
    configuration.yml    # Authelia config (committed — secrets are in .env)
    users_database.yml   # User/password hashes (committed, password field SOPS-encrypted)
  coraza/
    pre-crs.conf         # Custom WAF rules loaded BEFORE OWASP CRS (XXE, body settings)
    post-crs.conf        # Custom WAF rules loaded AFTER OWASP CRS (RCE, CRLF)
  scripts/
    update-ipsum.sh      # Fetches IPsum blocklist, generates Caddy snippet, reloads Caddy
  test/
    Caddyfile.test       # Local test config (no TLS, no Cloudflare)
    docker-compose.test.yml  # Test stack (Caddy + httpbun)
    ipsum_block.caddy    # Stub blocklist for local testing
```

## Security hardening

Both containers are hardened:

| Feature | Caddy | Authelia |
|---------|-------|----------|
| `read_only: true` | yes | yes |
| `cap_drop: ALL` | yes | yes |
| `cap_add` | `NET_BIND_SERVICE` | none |
| `no-new-privileges` | yes | yes |
| Healthcheck | yes | yes |
| Resource limits | 4 CPU / 1024M | 1 CPU / 256M |

### Coraza WAF

OWASP Core Rule Set plus custom rules for gaps CRS doesn't cover:

| Rule file | Loaded | Covers |
|-----------|--------|--------|
| `@crs-setup.conf.example` + `@owasp_crs/*.conf` | CRS baseline | SQLi, XSS, path traversal, LFI, RCE, scanners, Log4Shell, SSRF |
| `coraza/pre-crs.conf` | Before CRS | XXE (DOCTYPE/ENTITY SYSTEM/PUBLIC, parameter entities), request body settings |
| `coraza/post-crs.conf` | After CRS | RCE pipe-to-command, backtick substitution, CRLF injection |

`@coraza.conf-recommended` is intentionally **not** loaded — it activates the XML body processor which prevents regex-based XXE detection on `REQUEST_BODY`. The necessary settings are in `pre-crs.conf` instead.

**Test results:** 34/34 attack vectors blocked, 7/7 legitimate requests passed (SQLi, XSS, path traversal, RCE, XXE, Log4Shell, SSRF, CRLF, scanner detection).

### Other security layers

- **Per-service rate limiting** via `import rate_limit <zone> <events> <window>`
- **Security headers** (HSTS preload, nosniff, SAMEORIGIN, referrer-policy, permissions-policy)
- **Authelia forward auth** for protected services (`import forward_auth`)
- **IPsum blocklist** via `import ipsum_blocklist` (~20k IPs baked in at build, updated daily by cron)
- **Admin API** locked to `localhost:2019`
- **Strict SNI** host checking enabled
- **Cloudflare trusted proxies** configured

## Caddyfile snippets

Reusable snippets to keep site blocks DRY:

| Snippet | Usage | Purpose |
|---------|-------|---------|
| `(cors)` | `import cors` | CORS preflight + headers |
| `(security_headers)` | `import security_headers` | HSTS, nosniff, referrer-policy, permissions-policy |
| `(waf)` | `import waf` | Coraza WAF with OWASP CRS + custom rules |
| `(rate_limit)` | `import rate_limit <zone> <events> <window>` | Per-client-IP rate limiting |
| `(tls_config)` | `import tls_config` | ACME DNS challenge via Cloudflare |
| `(site_log)` | `import site_log <name>` | Per-site JSON access log |
| `(ipsum_blocklist)` | `import ipsum_blocklist` | IPsum threat intelligence IP blocklist |
| `(forward_auth)` | `import forward_auth` | Authelia forward authentication |
| `(proxy_headers)` | `import proxy_headers` | Trusted proxies + forwarded headers (inside `reverse_proxy`) |

## Setup

### Prerequisites

- Docker and Docker Compose
- A Cloudflare API token with DNS edit permissions for `erfi.io`
- DNS records for all subdomains pointing to the server's public IP (managed by Caddy's `dynamic_dns` or Terraform)
- **Dockge** on the servarr host (manages docker compose stacks)

### 1. Clone and configure secrets

```bash
git clone <repo-url> caddy-compose && cd caddy-compose

# Restore .env from the SOPS-encrypted copy (requires your age key)
sops -d .env.enc > .env
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
ssh servarr 'sudo mkdir -p /mnt/user/data/caddy/{site,data,config,log} /mnt/user/data/authelia/config'

# Copy configs
scp Caddyfile servarr:/mnt/user/data/caddy/Caddyfile
scp authelia/configuration.yml servarr:/mnt/user/data/authelia/config/
scp authelia/users_database.yml servarr:/mnt/user/data/authelia/config/

# Copy compose + .env to Dockge's stacks directory
scp docker-compose.yml servarr:/opt/stacks/caddy-compose/docker-compose.yml
scp .env servarr:/opt/stacks/caddy-compose/.env
```

Then deploy via Dockge UI, or:

```bash
ssh servarr 'cd /opt/stacks/caddy-compose && docker compose up -d'
```

### 5. Set up IPsum cron

The image ships with a fresh IPsum blocklist baked in at build time. To keep it updated at runtime:

```bash
# Copy the update script to servarr
scp scripts/update-ipsum.sh servarr:/usr/local/bin/update-ipsum.sh
ssh servarr 'chmod +x /usr/local/bin/update-ipsum.sh'

# Add to crontab (daily at 06:00)
ssh servarr 'crontab -l 2>/dev/null; echo "0 6 * * * /usr/local/bin/update-ipsum.sh >> /var/log/ipsum-update.log 2>&1"' | ssh servarr 'crontab -'
```

### 6. Verify

```bash
# Check containers are healthy
ssh servarr 'docker compose -f /opt/stacks/caddy-compose/docker-compose.yml ps'

# Test Authelia portal
curl -I https://authelia.erfi.io

# Test protected service (should redirect to Authelia)
curl -I https://servarr.erfi.io
```

## Operations

### Reload Caddy config

```bash
docker exec caddy caddy reload --config /etc/caddy/Caddyfile
```

### View logs

```bash
# Caddy access logs
docker exec caddy tail -f /var/log/access.log

# Per-site logs
docker exec caddy tail -f /var/log/servarr-access.log

# Authelia logs
docker exec authelia tail -f /config/authelia.log

# Coraza WAF audit
docker exec caddy tail -f /var/log/coraza-audit.log
```

### Register TOTP (first time)

With the filesystem notifier, TOTP registration links are written to a file instead of emailed:

```bash
docker exec authelia cat /config/notification.txt
```

Open the link to register your TOTP device. For production, replace the filesystem notifier with SMTP in `authelia/configuration.yml`.

### IPsum blocklist

The IPsum blocklist is fetched from [stamparm/ipsum](https://github.com/stamparm/ipsum) and converted into a Caddy-importable snippet. It blocks IPs with a threat score >= 3.

- **At build time**: The Dockerfile fetches a fresh copy and bakes it into the image at `/etc/caddy/ipsum_block.caddy`
- **At runtime**: The host volume mount (`/mnt/user/data/caddy/ipsum_block.caddy`) overwrites the baked-in copy. The cron job (`scripts/update-ipsum.sh`) updates it daily and reloads Caddy.

**Environment variables for `update-ipsum.sh`:**

| Variable | Default | Description |
|----------|---------|-------------|
| `IPSUM_MIN_SCORE` | `3` | Minimum IPsum threat score to block |
| `IPSUM_OUTPUT` | `/mnt/user/data/caddy/ipsum_block.caddy` | Output file path |
| `IPSUM_RELOAD_CADDY` | `true` | Auto-reload Caddy after update |

### Expand Authelia to more services

1. Add `import forward_auth` to the site block in `Caddyfile`
2. Add an `access_control` rule in `authelia/configuration.yml`:
   ```yaml
   - domain: 'dockge-sg.erfi.io'
     policy: 'two_factor'
   ```
3. Reload Caddy and restart Authelia

### Deploy config changes

After editing the Caddyfile or Authelia config, deploy to servarr:

```bash
# Copy Caddyfile and reload via admin API (atomic, validated, zero-downtime)
scp Caddyfile servarr:/mnt/user/data/caddy/Caddyfile
ssh servarr 'cat /mnt/user/data/caddy/Caddyfile | curl -sf -X POST http://localhost:2019/load \
  -H "Content-Type: text/caddyfile" --data-binary @-'

# If Authelia config changed
scp authelia/configuration.yml servarr:/mnt/user/data/authelia/config/configuration.yml
ssh servarr 'docker restart authelia'

# If users_database.yml changed (decrypt first if SOPS-encrypted)
sops -d authelia/users_database.yml | ssh servarr 'cat > /mnt/user/data/authelia/config/users_database.yml'
ssh servarr 'docker restart authelia'
```

The admin API validates config before applying — if invalid, the old config stays active.

### Update the Caddy image

```bash
# On your workstation
docker build -t erfianugrah/caddy:2.10.2 .
docker push erfianugrah/caddy:2.10.2

# On servarr (or via Dockge UI)
ssh servarr 'cd /opt/stacks/caddy-compose && docker compose pull && docker compose up -d'
```

### DNS considerations

When migrating from Cloudflare Tunnel to direct public traffic:

- **LB vs CNAME conflict**: If a CNAME record (from the tunnel) and an LB/A record exist for the same hostname, behavior is undefined. Delete the existing CNAME in `erfianugrah-cf-tf/main_zone/dns_servarr.tf` before creating A records or LB entries.
- Caddy's `dynamic_dns` will create/update A records automatically, but pre-existing CNAMEs from the tunnel config must be removed first.
- The tunnel ingress in `tunnels.tf` should be decommissioned after the DNS migration is verified.

### SOPS encryption

Secrets are encrypted at rest with [SOPS](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age).

- **`.env`** — plaintext, gitignored, used directly by Docker Compose
- **`.env.enc`** — SOPS-encrypted copy of `.env`, committed to git
- **`authelia/users_database.yml`** — committed with `password` field SOPS-encrypted

**One-time setup:**

```bash
# 1. Install sops and age
brew install sops age   # macOS
# or: apt install age && curl -fsSL -o /usr/local/bin/sops https://github.com/getsops/sops/releases/download/v3.9.4/sops-v3.9.4.linux.amd64 && chmod +x /usr/local/bin/sops

# 2. Generate an age key (if you don't have one)
age-keygen -o ~/.config/sops/age/keys.txt
# Note the public key (age1...)

# 3. Update .sops.yaml — replace REPLACE_WITH_YOUR_AGE_PUBLIC_KEY with your age1... key

# 4. Create the encrypted .env copy
cp .env .env.enc
sops -e -i .env.enc

# 5. Encrypt the users database password field
sops -e -i authelia/users_database.yml

# 6. Commit
git add .env.enc authelia/users_database.yml .sops.yaml
git commit -m "encrypt secrets with SOPS"
```

**Day-to-day usage:**

```bash
# Edit .env locally (plaintext, gitignored)
vim .env

# Re-encrypt after changes
cp .env .env.enc && sops -e -i .env.enc

# Edit users database (decrypts in $EDITOR, re-encrypts on save)
sops authelia/users_database.yml

# Restore .env from encrypted copy (e.g., after fresh clone)
sops -d .env.enc > .env
```

**`.sops.yaml` rules:**

| Pattern | Encrypted fields | Purpose |
|---------|-----------------|---------|
| `.env.enc` | All values | CF API token, Authelia secrets |
| `users_database.yml` | `password` only | Argon2id password hashes |

## Local testing

A test stack is provided to validate the config without Cloudflare credentials:

```bash
# Start Caddy + httpbun (HTTP echo server)
docker compose -f test/docker-compose.test.yml up -d

# Test proxy
curl http://localhost:8080/get

# Test WAF blocks
curl http://localhost:8080/get?id=1+OR+1=1     # 403
curl -X POST -H "Content-Type: application/xml" \
  -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' \
  http://localhost:8080/post                     # 403

# Test rate limiting (10 req/min in test config)
for i in $(seq 1 15); do curl -so/dev/null -w "%{http_code} " http://localhost:8080/get; done

# Tear down
docker compose -f test/docker-compose.test.yml down
```

## TODO

- [ ] **SMTP notifier** — Replace filesystem notifier with real email delivery
- [ ] **Expand Authelia** — Add forward auth to more admin services (dockge-sg, qbit, sabnzbd, keycloak, caddy-prometheus, prowlarr, change, copyparty)
- [ ] **DNS migration** — When moving from Cloudflare Tunnel to direct traffic, delete existing CNAME records before creating A/LB records for the same hostname (LB vs CNAME conflict — undefined behavior if both exist)
