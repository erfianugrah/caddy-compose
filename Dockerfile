ARG VERSION=2.8

FROM caddy:${VERSION}-builder-alpine AS builder
ARG VERSION
RUN xcaddy build ${VERSION} \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/mholt/caddy-dynamicdns
#--with github.com/mholt/caddy-l4/layer4 \
#--with github.com/lucaslorentz/caddy-docker-proxy/plugin \
#--with github.com/hslatman/caddy-crowdsec-bouncer 
#--with github.com/kirsch33/realip \
# Security
#--with github.com/greenpau/caddy-trace \
#--with github.com/greenpau/caddy-security \
#--with github.com/greenpau/caddy-systemd \
#--with github.com/greenpau/caddy-git
FROM caddy:${VERSION}-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
#CMD ["caddy", "docker-proxy"]
