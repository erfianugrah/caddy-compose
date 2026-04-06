ARG CRS_VERSION=v4.25.0

# Build WAF dashboard static site
FROM node:22-alpine AS frontend
WORKDIR /build
COPY waf-dashboard/package.json waf-dashboard/package-lock.json ./
RUN npm ci
COPY waf-dashboard/ ./
RUN npm run build

FROM golang:1.26-alpine AS builder
ARG VERSION=dev
WORKDIR /build
COPY wafctl/go.mod ./
RUN go mod download
COPY wafctl/*.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o wafctl .

# Convert CRS rules to policy-engine format at build time.
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

FROM alpine:3.21
RUN apk add --no-cache wget
COPY --from=builder /build/wafctl /usr/local/bin/wafctl
COPY --from=frontend /build/dist/ /app/waf-ui/
COPY --from=crs-rules /build/default-rules.json /etc/caddy/waf/default-rules.json
COPY --from=crs-rules /build/crs-metadata.json /etc/caddy/waf/crs-metadata.json
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/wafctl"]
CMD ["serve"]
