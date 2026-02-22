ARG VERSION=2.10.2

FROM caddy:${VERSION}-builder AS builder
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

# Fetch Cloudflare IP ranges at build time for trusted_proxies.
# Rebuild the image periodically to pick up any Cloudflare IP changes.
FROM alpine:3.21 AS cloudflare-ips
RUN apk add --no-cache curl \
	&& curl -fsSL --retry 3 --max-time 30 https://www.cloudflare.com/ips-v4 > /tmp/cf_ipv4 \
	&& curl -fsSL --retry 3 --max-time 30 https://www.cloudflare.com/ips-v6 > /tmp/cf_ipv6 \
	&& { echo '# AUTO-GENERATED at build time — Cloudflare IP ranges'; \
	     printf 'trusted_proxies static'; \
	     while IFS= read -r cidr; do [ -n "$cidr" ] && printf ' %s' "$cidr"; done < /tmp/cf_ipv4; \
	     while IFS= read -r cidr; do [ -n "$cidr" ] && printf ' %s' "$cidr"; done < /tmp/cf_ipv6; \
	     echo; \
	   } > /tmp/cf_trusted_proxies.caddy

# Build WAF dashboard static site
FROM node:22-alpine AS waf-dashboard
WORKDIR /build
COPY waf-dashboard/package.json waf-dashboard/package-lock.json ./
RUN npm ci
COPY waf-dashboard/ ./
RUN npm run build

# Build WAF API sidecar
FROM golang:1.23-alpine AS waf-api
WORKDIR /build
COPY waf-api/go.mod ./
COPY waf-api/*.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o waf-api .

FROM caddy:${VERSION}-alpine
RUN apk add --no-cache curl
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY --from=ipsum /tmp/ipsum_block.caddy /etc/caddy/ipsum_block.caddy
COPY --from=cloudflare-ips /tmp/cf_trusted_proxies.caddy /etc/caddy/cf_trusted_proxies.caddy
COPY --from=waf-dashboard /build/dist/ /etc/caddy/waf-ui/
COPY errors/ /etc/caddy/errors/
COPY coraza/ /etc/caddy/coraza/
COPY scripts/update-ipsum.sh /usr/local/bin/update-ipsum.sh
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/update-ipsum.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
