#!/bin/sh
# entrypoint.sh — Seed configs, start crond, then exec caddy.
# crond is needed for audit log rotation only; the IPsum blocklist refresh
# is handled by wafctl's Go scheduler (StartScheduledRefresh).
# IPsum blocking is done via the policy engine plugin (managed lists).
set -eu

# Seed Cloudflare trusted proxies from build-time snapshot to the writable volume.
# wafctl's scheduled refresh will keep this updated at runtime.
CF_SEED="/etc/caddy/cf_trusted_proxies.caddy"
CF_RUNTIME="/data/coraza/cf_trusted_proxies.caddy"
if [ ! -f "${CF_RUNTIME}" ] && [ -f "${CF_SEED}" ]; then
    mkdir -p "$(dirname "${CF_RUNTIME}")"
    cp "${CF_SEED}" "${CF_RUNTIME}"
    echo "[entrypoint] Seeded CF trusted proxies from build-time snapshot"
fi

# Ensure CSP config directory is writable by caddy.
# Docker may create bind-mount dirs as root before the container starts.
CSP_DIR="/data/caddy/csp"
mkdir -p "${CSP_DIR}"
chmod 755 "${CSP_DIR}" 2>/dev/null || true

# Seed placeholder Coraza config files so Caddy's Include directives
# don't fail on a fresh deploy (wafctl's generateOnBoot populates them).
for f in custom-pre-crs.conf custom-waf-settings.conf custom-post-crs.conf; do
    target="/data/coraza/$f"
    if [ ! -f "$target" ]; then
        mkdir -p "$(dirname "$target")"
        echo "# Placeholder - will be populated by wafctl" > "$target"
        echo "[entrypoint] Created placeholder $target"
    fi
done

# Start crond in the background for audit log rotation.
if crond -b -l 2; then
    echo "[entrypoint] crond started (audit log rotation)"
else
    echo "[entrypoint] WARNING: crond failed to start (audit log rotation will not run)"
fi

# Exec into caddy — becomes PID 1, receives SIGTERM on container stop
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
