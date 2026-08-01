package main

// ─── probe ─────────────────────────────────────────────────────────

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// cacheStatus is the parsed form of the Souin Cache-Status response header.
type cacheStatus struct {
	Raw    string
	Hit    bool
	Stored bool
	Fwd    string // uri-miss, request, ...
	Detail string // NUTS (disk) or DEFAULT (in-memory fallback)
}

// parseCacheStatus parses a Souin Cache-Status header value.
//
//	Souin; fwd=uri-miss; stored; key=GET-...; detail=NUTS
func parseCacheStatus(h string) cacheStatus {
	cs := cacheStatus{Raw: h}
	for _, part := range strings.Split(h, ";") {
		part = strings.TrimSpace(part)
		switch {
		case part == "hit":
			cs.Hit = true
		case part == "stored":
			cs.Stored = true
		case strings.HasPrefix(part, "fwd="):
			cs.Fwd = strings.TrimPrefix(part, "fwd=")
		case strings.HasPrefix(part, "detail="):
			cs.Detail = strings.TrimPrefix(part, "detail=")
		}
	}
	return cs
}

// edgeIP auto-detects the edge's public IP by asking the edge itself.
func edgeIP(e edge) (string, error) {
	out, err := e.ssh("curl -s -4 --max-time 5 ifconfig.me")
	ip := strings.TrimSpace(out)
	if err != nil {
		return "", fmt.Errorf("detect edge IP: %w", err)
	}
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("detect edge IP: %q is not an IP", ip)
	}
	return ip, nil
}

// edgeClient returns an HTTP client that dials ip for every connection
// while keeping the URL's host for SNI and cert validation - the Go
// equivalent of curl --resolve host:443:ip. ForceAttemptHTTP2 matters:
// plain HTTP/1.1 requests with no browser headers trip the edge WAF's
// detect rules (verified 2026-08-01: h1 + default headers scored 11/10
// and got a block page instead of a cached response).
func edgeClient(ip string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// cmdProbe requests each URL twice through the edge and prints the
// Cache-Status header of both requests.
//
// Expect: #1 fwd=uri-miss;stored (or hit), #2 hit with detail=NUTS.
// detail=DEFAULT means the handler fell back to in-memory storage.
func cmdProbe(e edge, urls []string) error {
	ip := envOr("EDGE_IP", "")
	if ip == "" {
		var err error
		ip, err = edgeIP(e)
		if err != nil {
			return err
		}
	}
	client := edgeClient(ip)

	for _, url := range urls {
		e.printf("== %s (via %s) ==", url, ip)
		for n := 1; n <= 2; n++ {
			cs, err := probeOnce(client, url)
			if err != nil {
				e.printf("  #%d  ERROR: %v", n, err)
				continue
			}
			if cs == "" {
				e.printf("  #%d  (no cache-status header - not a cached route)", n)
				continue
			}
			e.printf("  #%d  %s", n, cs)
		}
	}
	e.printf("expect: #1 fwd=uri-miss;stored (or hit), #2 hit with detail=NUTS. detail=DEFAULT means in-memory fallback.")
	return nil
}

// probeOnce performs a single GET and returns the Cache-Status header.
// The body is drained so souin sees a complete request. Headers mimic a
// browser: the edge WAF scores requests with missing Accept/UA headers
// as bots, and blocked responses are never cached (no Cache-Status).
func probeOnce(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "cachectl/1.0 (edge cache ops; +github.com/erfianugrah/caddy-compose)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	return resp.Header.Get("Cache-Status"), nil
}
