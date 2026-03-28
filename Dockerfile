ARG VERSION=2.11.2
ARG CRS_VERSION=v4.24.1

FROM caddy:${VERSION}-builder AS builder
RUN xcaddy build \
	--with github.com/caddy-dns/cloudflare@v0.2.3 \
	--with github.com/mholt/caddy-dynamicdns \
	--with github.com/erfianugrah/caddy-body-matcher@v0.2.1 \
	--with github.com/erfianugrah/caddy-policy-engine@v0.39.3 \
	--with github.com/erfianugrah/caddy-ddos-mitigator@v0.16.0

# Convert CRS rules to policy-engine format at build time.
# Update CRS_VERSION to pick up new CRS releases.
FROM golang:1.26-alpine AS crs-rules
ARG CRS_VERSION
RUN apk add --no-cache git
WORKDIR /build
COPY tools/crs-converter/ ./converter/
RUN cd converter && CGO_ENABLED=0 go build -o /usr/local/bin/crs-converter .
RUN git clone --depth 1 --branch ${CRS_VERSION} \
      https://github.com/coreruleset/coreruleset.git /crs
COPY waf/custom-rules.json /build/custom-rules.json
RUN crs-converter \
      -crs-dir /crs/rules \
      -crs-version "${CRS_VERSION#v}" \
      -custom-rules /build/custom-rules.json \
      -output /build/default-rules.json \
      -metadata-output /build/crs-metadata.json

# Fetch Cloudflare IP ranges at build time for trusted_proxies.
# Rebuild the image periodically to pick up any Cloudflare IP changes.
FROM alpine:3.21 AS cloudflare-ips
RUN wget -qO /tmp/cf_ipv4 https://www.cloudflare.com/ips-v4 \
	&& wget -qO /tmp/cf_ipv6 https://www.cloudflare.com/ips-v6 \
	&& { echo '# AUTO-GENERATED at build time — Cloudflare IP ranges'; \
	     printf 'trusted_proxies static'; \
	     while IFS= read -r cidr; do [ -n "$cidr" ] && printf ' %s' "$cidr"; done < /tmp/cf_ipv4; \
	     while IFS= read -r cidr; do [ -n "$cidr" ] && printf ' %s' "$cidr"; done < /tmp/cf_ipv6; \
	     echo; \
	   } > /tmp/cf_trusted_proxies.caddy

FROM caddy:${VERSION}-alpine
RUN apk upgrade --no-cache && apk add --no-cache nftables
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY --from=cloudflare-ips /tmp/cf_trusted_proxies.caddy /etc/caddy/cf_trusted_proxies.caddy
COPY errors/ /etc/caddy/errors/
COPY --from=crs-rules /build/default-rules.json /etc/caddy/waf/default-rules.json
COPY --from=crs-rules /build/crs-metadata.json /etc/caddy/waf/crs-metadata.json
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
