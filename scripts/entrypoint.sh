#!/bin/sh
# entrypoint.sh — Start crond for IPsum updates, then exec caddy.
set -eu

# Install the cron job: daily at 02:00 UTC
CRON_SCHEDULE="${IPSUM_CRON:-0 2 * * *}"
echo "${CRON_SCHEDULE} /usr/local/bin/update-ipsum.sh >> /var/log/ipsum-update.log 2>&1" \
    | crontab -

# Start crond in the background (runs as PID != 1, so signals go to caddy)
crond -b -l 8

# Exec into caddy — becomes PID 1, receives SIGTERM on container stop
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
