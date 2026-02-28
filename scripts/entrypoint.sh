#!/bin/sh
# entrypoint.sh — Seed ipsum blocklist, start crond, then exec caddy.
# crond is needed for audit log rotation only; the IPsum blocklist refresh
# is handled by wafctl's Go scheduler (StartScheduledRefresh).
set -eu

# Seed IPsum blocklist from build-time snapshot to the writable volume.
# Re-seed if the runtime file is missing OR lacks the "# Updated:" header
# (which older builds didn't include). wafctl's scheduled refresh will
# overwrite this daily.
IPSUM_SEED="/etc/caddy/ipsum_block.caddy"
IPSUM_RUNTIME="/data/coraza/ipsum_block.caddy"
needs_seed=false
if [ ! -f "${IPSUM_RUNTIME}" ]; then
    needs_seed=true
elif ! grep -q '^# Updated:' "${IPSUM_RUNTIME}" 2>/dev/null; then
    needs_seed=true
    echo "[entrypoint] Runtime ipsum blocklist missing '# Updated:' header, re-seeding"
fi
if [ "${needs_seed}" = true ] && [ -f "${IPSUM_SEED}" ]; then
    mkdir -p "$(dirname "${IPSUM_RUNTIME}")"
    cp "${IPSUM_SEED}" "${IPSUM_RUNTIME}"
    echo "[entrypoint] Seeded ipsum blocklist from build-time snapshot"
fi

# Seed Cloudflare trusted proxies from build-time snapshot to the writable volume.
# wafctl's scheduled refresh will keep this updated at runtime.
CF_SEED="/etc/caddy/cf_trusted_proxies.caddy"
CF_RUNTIME="/data/coraza/cf_trusted_proxies.caddy"
if [ ! -f "${CF_RUNTIME}" ] && [ -f "${CF_SEED}" ]; then
    mkdir -p "$(dirname "${CF_RUNTIME}")"
    cp "${CF_SEED}" "${CF_RUNTIME}"
    echo "[entrypoint] Seeded CF trusted proxies from build-time snapshot"
fi

# Start crond in the background for audit log rotation.
if crond -b -l 2; then
    echo "[entrypoint] crond started (audit log rotation)"
else
    echo "[entrypoint] WARNING: crond failed to start (audit log rotation will not run)"
fi

# Exec into caddy — becomes PID 1, receives SIGTERM on container stop
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
