// flood.go — Standalone HTTP flood tool for DDoS mitigator testing.
// Run directly on the server to avoid TLS/network overhead:
//
//   go run flood.go -target http://localhost:8080/anything/api/flood -workers 500 -duration 30s
//
// Or build and copy:
//
//   CGO_ENABLED=0 go build -o flood flood.go
//   scp flood servarr:/tmp/ && ssh servarr /tmp/flood -target http://localhost:8080/anything/api/flood

package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	target := flag.String("target", "http://localhost:8080/anything/api/v1/flood-target", "URL to flood")
	workers := flag.Int("workers", 500, "concurrent workers")
	duration := flag.Duration("duration", 30*time.Second, "test duration")
	flag.Parse()

	transport := &http.Transport{
		MaxIdleConnsPerHost: *workers,
		MaxConnsPerHost:     0, // unlimited — let the OS handle connection limits
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		WriteBufferSize:     32 << 10,
		ReadBufferSize:      32 << 10,
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	var total, ok200, ok403, errors atomic.Int64
	var firstBlockMs atomic.Int64
	start := time.Now()
	stop := make(chan struct{})

	fmt.Fprintf(os.Stderr, "Flooding %s with %d workers for %s\n\n", *target, *workers, *duration)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest("GET", *target, nil)
				req.Header.Set("User-Agent", "flood-test/1.0")
				req.Header.Set("Accept", "*/*")
				resp, err := client.Do(req)
				total.Add(1)
				if err != nil {
					errors.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				switch resp.StatusCode {
				case 200:
					ok200.Add(1)
				case 403:
					ok403.Add(1)
					if firstBlockMs.Load() == 0 {
						firstBlockMs.Store(time.Since(start).Milliseconds())
					}
				default:
					errors.Add(1)
				}
			}
		}()
	}

	ticker := time.NewTicker(2 * time.Second)
	deadline := time.After(*duration)
	for {
		select {
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			t := total.Load()
			fmt.Fprintf(os.Stderr, "  [%5.1fs] total=%-8d rps=%-6.0f 200=%-6d 403=%-6d err=%d\n",
				elapsed, t, float64(t)/elapsed, ok200.Load(), ok403.Load(), errors.Load())
		case <-deadline:
			close(stop)
			goto done
		}
	}
done:
	ticker.Stop()
	wg.Wait()

	elapsed := time.Since(start).Seconds()
	t := total.Load()
	fmt.Fprintf(os.Stderr, "\n═══ Results ═══\n")
	fmt.Fprintf(os.Stderr, "Duration:    %.1fs\n", elapsed)
	fmt.Fprintf(os.Stderr, "Total:       %d (%.0f req/s)\n", t, float64(t)/elapsed)
	fmt.Fprintf(os.Stderr, "200 OK:      %d\n", ok200.Load())
	fmt.Fprintf(os.Stderr, "403 Blocked: %d (%.1f%%)\n", ok403.Load(), float64(ok403.Load())/float64(t)*100)
	fmt.Fprintf(os.Stderr, "Errors:      %d\n", errors.Load())
	if fb := firstBlockMs.Load(); fb > 0 {
		fmt.Fprintf(os.Stderr, "First block: %dms\n", fb)
	} else {
		fmt.Fprintf(os.Stderr, "First block: NEVER\n")
	}
}
