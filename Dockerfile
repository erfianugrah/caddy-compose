# Caddy base version. The MINIMUM version is determined by the union of all
# `--with` modules below — each module's go.mod declares its required
# caddy/v2 version, and Go module resolution takes the highest. If you bump
# any module to a release that pulls in a newer caddy/v2 minimum, this
# version must be bumped to match or the build fails with
# `requires github.com/caddyserver/caddy/v2@vX.Y.Z, not vX.Y.W`.
#
# When bumping this, also update CADDY_VERSION and CADDY_TAG in
# .github/workflows/build.yml, and the image tags in Makefile, compose.yaml,
# README.md (Version management section). See README.md §Version management.
ARG VERSION=2.11.3
ARG CRS_VERSION=v4.26.0

# xcaddy build manifest.
#   caddy-dns/cloudflare    — ACME DNS-01 + dynamic_dns + ECH publishing (CF auth DNS)
#   caddy-dns/rfc2136       — ACME DNS-01 via TSIG-authed nsupdate (own Knot DNS,
#                              see ~/knot-fly/docs/runbooks/cf-to-knot-migration.md)
#   caddy-dynamicdns        — home WAN IP → A/AAAA records (~30 hostnames)
#   caddy-l4                — L4 listener wrapper for DDoS-mitigator's TCP-RST path
#   caddy-body-matcher      — request body matchers + body_vars handler
#   caddy-policy-engine     — unified WAF (allow/block/challenge/skip/detect/rate_limit/header)
#   caddy-ddos-mitigator    — 3-layer DDoS detection (global rate, per-service, host-diversity)
#
# Pin all modules at known-good versions. Two modules below are intentionally
# unpinned (caddy-dynamicdns, caddy-l4); xcaddy resolves them to latest on
# every cache-bust build. This has bitten us before — e.g. caddy-l4 v0.1.1
# (2025-04-24) raised its caddy/v2 minimum to 2.11.3 and broke 2.11.2 builds.
# Pin those two too if you want fully reproducible builds across rebuilds.
FROM caddy:${VERSION}-builder AS builder
RUN xcaddy build \
	--with github.com/caddy-dns/cloudflare@v0.2.3 \
	--with github.com/caddy-dns/rfc2136@v1.0.0 \
	--with github.com/mholt/caddy-dynamicdns \
	--with github.com/mholt/caddy-l4 \
	--with github.com/erfianugrah/caddy-body-matcher@v0.2.1 \
	--with github.com/erfianugrah/caddy-policy-engine@v0.42.1 \
	--with github.com/erfianugrah/caddy-ddos-mitigator@v0.17.2

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
