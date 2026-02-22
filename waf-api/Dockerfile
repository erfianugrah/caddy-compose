FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o waf-api .

FROM alpine:3.21
RUN apk add --no-cache wget
COPY --from=builder /build/waf-api /usr/local/bin/waf-api
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/waf-api"]
