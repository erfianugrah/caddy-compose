FROM golang:1.24-alpine AS builder
ARG VERSION=dev
WORKDIR /build
COPY wafctl/go.mod ./
COPY wafctl/*.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o wafctl .

FROM alpine:3.21
RUN apk add --no-cache wget
COPY --from=builder /build/wafctl /usr/local/bin/wafctl
COPY coraza/default-rules.json /etc/caddy/coraza/default-rules.json
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/wafctl"]
CMD ["serve"]
