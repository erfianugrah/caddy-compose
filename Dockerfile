ARG VERSION=2.11.1
ARG CRS_VERSION=v4.24.1

FROM caddy:${VERSION}-builder AS builder
COPY caddy-policy-engine/ /tmp/caddy-policy-engine/
RUN xcaddy build \
	--with github.com/caddy-dns/cloudflare \
	--with github.com/mholt/caddy-dynamicdns \
	--with github.com/erfianugrah/caddy-body-matcher@v0.1.1 \
	--with github.com/erfianugrah/caddy-policy-engine=/tmp/caddy-policy-engine

# Convert CRS rules to policy-engine format at build time.
# Update CRS_VERSION to pick up new CRS releases.
FROM golang:1.24-alpine AS crs-rules
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
      -output /build/default-rules.json

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

# Build wafctl sidecar
FROM golang:1.24-alpine AS wafctl
ARG WAFCTL_VERSION=dev
WORKDIR /build
COPY wafctl/go.mod ./
RUN go mod download
COPY wafctl/*.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${WAFCTL_VERSION}" -o wafctl .

FROM caddy:${VERSION}-alpine
RUN apk upgrade --no-cache && apk add --no-cache curl
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY --from=cloudflare-ips /tmp/cf_trusted_proxies.caddy /etc/caddy/cf_trusted_proxies.caddy
COPY errors/ /etc/caddy/errors/
COPY --from=crs-rules /build/default-rules.json /etc/caddy/waf/default-rules.json
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
