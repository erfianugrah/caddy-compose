# Build WAF dashboard static site
FROM node:22-alpine AS frontend
WORKDIR /build
COPY waf-dashboard/package.json waf-dashboard/package-lock.json ./
RUN npm ci
COPY waf-dashboard/ ./
RUN npm run build

FROM golang:1.24-alpine AS builder
ARG VERSION=dev
WORKDIR /build
COPY wafctl/go.mod ./
RUN go mod download
COPY wafctl/*.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o wafctl .

FROM alpine:3.21
RUN apk add --no-cache wget
COPY --from=builder /build/wafctl /usr/local/bin/wafctl
COPY --from=frontend /build/dist/ /app/waf-ui/
COPY waf/default-rules.json /etc/caddy/waf/default-rules.json
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/wafctl"]
CMD ["serve"]
