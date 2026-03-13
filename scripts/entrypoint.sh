#!/bin/sh
# entrypoint.sh — Seed configs, then exec caddy.
# IPsum blocking is done via the policy engine plugin (managed lists).
set -eu

# Seed Cloudflare trusted proxies from build-time snapshot to the writable volume.
# wafctl's scheduled refresh will keep this updated at runtime.
CF_SEED="/etc/caddy/cf_trusted_proxies.caddy"
CF_RUNTIME="/data/waf/cf_trusted_proxies.caddy"
if [ ! -f "${CF_RUNTIME}" ] && [ -f "${CF_SEED}" ]; then
    mkdir -p "$(dirname "${CF_RUNTIME}")"
    cp "${CF_SEED}" "${CF_RUNTIME}"
    echo "[entrypoint] Seeded CF trusted proxies from build-time snapshot"
fi

# Ensure CSP config directory is writable by caddy.
CSP_DIR="/data/caddy/csp"
mkdir -p "${CSP_DIR}"
chmod 755 "${CSP_DIR}" 2>/dev/null || true

# Ensure policy engine data directory exists.
mkdir -p /data/waf

# Exec into caddy — becomes PID 1, receives SIGTERM on container stop
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
