#!/bin/sh
# entrypoint.sh — Seed ipsum blocklist, start crond, then exec caddy.
# The cron schedule is baked into the image at build time
# (/var/spool/cron/crontabs/root) because the container runs read_only.
set -eu

# Seed IPsum blocklist from build-time snapshot to the writable volume
# if it doesn't already exist. Daily cron updates will overwrite it.
IPSUM_SEED="/etc/caddy/ipsum_block.caddy"
IPSUM_RUNTIME="/data/coraza/ipsum_block.caddy"
if [ ! -f "${IPSUM_RUNTIME}" ] && [ -f "${IPSUM_SEED}" ]; then
    mkdir -p "$(dirname "${IPSUM_RUNTIME}")"
    cp "${IPSUM_SEED}" "${IPSUM_RUNTIME}"
    echo "[entrypoint] Seeded ipsum blocklist from build-time snapshot"
fi

# Start crond in the background (runs as PID != 1, so signals go to caddy)
crond -b -l 8

# Exec into caddy — becomes PID 1, receives SIGTERM on container stop
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
