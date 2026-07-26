#!/usr/bin/env bash
# Validate the PROD edge Caddyfile (including cache config) inside the built
# image: parses + provisions every module. Dummy env only; CF provider
# format-checks its token, hence the 40-char fake.
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${CADDY_IMAGE:-$(sed -n 's/^CADDY_IMAGE *?= *//p' "$REPO/Makefile")}"
docker run --rm --entrypoint /usr/bin/caddy \
	-v "$REPO/deploy/edge/Caddyfile:/etc/caddy/Caddyfile:ro" \
	-e EMAIL=test@example.com \
	-e TSIG_CADDY_ACME='hmac-sha256:caddy-acme.:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
	-e TSIG_CADDY_DDNS='hmac-sha256:caddy-ddns.:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
	-e CF_API_TOKEN='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1' \
	"$IMAGE" adapt --config /etc/caddy/Caddyfile --adapter caddyfile --validate \
	>"${TMPDIR:-/tmp}/adapt-edge.json" 2>"${TMPDIR:-/tmp}/adapt-edge.err"
rc=$?
if [ $rc -ne 0 ]; then
	tail -5 "${TMPDIR:-/tmp}/adapt-edge.err"
fi
exit $rc
