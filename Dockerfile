ARG VERSION=2.10.2

FROM caddy:${VERSION}-builder AS builder
ARG VERSION
RUN xcaddy build \
	--with github.com/caddy-dns/cloudflare \
	--with github.com/mholt/caddy-dynamicdns \
	--with github.com/mholt/caddy-ratelimit \
	--with github.com/corazawaf/coraza-caddy/v2

# Fetch IPsum blocklist at build time so it's never empty on first boot.
# The host volume mount + cron job overwrites this at runtime.
FROM alpine:3.21 AS ipsum
ARG IPSUM_MIN_SCORE=3
RUN apk add --no-cache curl \
	&& curl -fsSL --retry 3 --max-time 60 \
	   https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt \
	   | awk -v min="${IPSUM_MIN_SCORE}" '/^#/{next} /^[[:space:]]*$/{next} {if($2+0>=min) printf "%s ",$1}' \
	   > /tmp/ipsum_ips \
	&& COUNT=$(wc -w < /tmp/ipsum_ips) \
	&& printf '# AUTO-GENERATED at build time\n# IPs: %s (min_score=%s)\n@ipsum_blocked client_ip %s\nabort @ipsum_blocked\n' \
	   "$COUNT" "$IPSUM_MIN_SCORE" "$(cat /tmp/ipsum_ips)" \
	   > /tmp/ipsum_block.caddy

FROM caddy:${VERSION}-alpine
RUN apk add --no-cache curl
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY --from=ipsum /tmp/ipsum_block.caddy /etc/caddy/ipsum_block.caddy
COPY errors/ /etc/caddy/errors/
COPY coraza/ /etc/caddy/coraza/
COPY scripts/update-ipsum.sh /usr/local/bin/update-ipsum.sh
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/update-ipsum.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
