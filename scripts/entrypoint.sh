#!/bin/sh
# entrypoint.sh — Seed ipsum blocklist, start crond, then exec caddy.
# The cron schedule is baked into the image at build time
# (/var/spool/cron/crontabs/root) because the container runs read_only.
set -eu

# Seed IPsum blocklist from build-time snapshot to the writable volume.
# Re-seed if the runtime file is missing OR lacks the "# Updated:" header
# (which older builds didn't include). Daily cron updates will overwrite it.
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

# Start crond in the background (runs as PID != 1, so signals go to caddy)
crond -b -l 8

# Exec into caddy — becomes PID 1, receives SIGTERM on container stop
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
