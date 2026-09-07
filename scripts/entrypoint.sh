#!/bin/sh
# entrypoint.sh - Seed configs, then exec caddy.
# IPsum blocking is done via the policy engine plugin (managed lists).
set -eu

# Ensure policy engine data directory exists.
mkdir -p /data/waf

# Exec into caddy - becomes PID 1, receives SIGTERM on container stop
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
