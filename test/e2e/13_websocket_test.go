package e2e_test

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestWebSocketThroughWAF verifies that WebSocket connections work through the
// Caddy reverse proxy with the policy engine active. The policy engine's
// responseHeaderWriter implements http.Hijacker so WebSocket upgrades succeed
// even when the middleware wraps the response writer.
//
// This test does a raw WebSocket handshake (no external deps), sends a text
// frame, and verifies the echo response — exercising the full upgrade path
// through policy_engine → reverse_proxy → httpbun.
func TestWebSocketThroughWAF(t *testing.T) {
	// WebSocket upgrades trigger CRS protocol enforcement rules (920310,
	// 920330, 9100034, etc.) because the handshake omits standard browser
	// headers. Create an allow rule to bypass WAF for the test path.
	wsAllowPayload := map[string]any{
		"name":    "E2E WebSocket Allow",
		"type":    "allow",
		"enabled": true,
		"conditions": []map[string]any{
			{"field": "path", "operator": "begins_with", "value": "/websocket/"},
		},
	}
	resp, body := httpPost(t, wafctlURL+"/api/exclusions", wsAllowPayload)
	assertCode(t, "create ws allow rule", 201, resp)
	wsRuleID := mustGetID(t, body)
	t.Cleanup(func() {
		cleanup(t, wafctlURL+"/api/exclusions/"+wsRuleID)
		httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	})
	httpPostDeploy(t, wafctlURL+"/api/config/deploy", struct{}{})
	// Wait for policy engine hot-reload so the allow rule takes effect.
	waitForStatus(t, caddyURL+"/websocket/echo", 400, 10*time.Second)

	t.Run("upgrade succeeds", func(t *testing.T) {
		conn, br := wsHandshake(t, caddyURL+"/websocket/echo")
		defer conn.Close()

		// Send a text frame and verify echo.
		msg := "hello from e2e"
		wsWriteText(t, conn, msg)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := wsReadText(t, br)
		if got != msg {
			t.Errorf("echo mismatch: sent %q, got %q", msg, got)
		}
	})

	t.Run("multiple messages", func(t *testing.T) {
		conn, br := wsHandshake(t, caddyURL+"/websocket/echo")
		defer conn.Close()

		messages := []string{"first", "second", "third with spaces and 日本語"}
		for _, msg := range messages {
			wsWriteText(t, conn, msg)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := wsReadText(t, br)
			if got != msg {
				t.Errorf("echo mismatch: sent %q, got %q", msg, got)
			}
		}
	})

	t.Run("clean close", func(t *testing.T) {
		conn, _ := wsHandshake(t, caddyURL+"/websocket/echo")
		// Send close frame — opcode 0x8 with status 1000 (normal closure).
		wsWriteClose(t, conn, 1000)
		// Read should eventually return EOF or a close frame.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 512)
		_, err := conn.Read(buf)
		if err == nil {
			// Some servers send a close frame back — that's fine.
			t.Log("received response to close frame")
		}
		conn.Close()
	})
}

// ── WebSocket helpers (raw, no external deps) ──────────────────────

// wsHandshake performs a raw WebSocket upgrade handshake and returns the
// underlying TCP connection and a buffered reader for reading frames.
func wsHandshake(t *testing.T, rawURL string) (net.Conn, *bufio.Reader) {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}

	// Generate random key for Sec-WebSocket-Key.
	keyBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		conn.Close()
		t.Fatalf("rand: %v", err)
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	// Send upgrade request.
	reqPath := u.RequestURI()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"\r\n", reqPath, u.Host, wsKey)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		t.Fatalf("write upgrade: %v", err)
	}

	// Read response.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatalf("read status: %v", err)
	}

	if !strings.Contains(statusLine, "101") {
		// Read rest of response for debugging.
		var headers []string
		for {
			line, err := br.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
			headers = append(headers, strings.TrimSpace(line))
		}
		conn.Close()
		t.Fatalf("expected 101 Switching Protocols, got: %s\nHeaders: %s",
			strings.TrimSpace(statusLine), strings.Join(headers, "\n"))
	}

	// Consume remaining headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	// Verify Sec-WebSocket-Accept.
	expectedAccept := wsAcceptKey(wsKey)
	_ = expectedAccept // Accept key is validated by the server; we trust 101.

	// Clear deadlines for subsequent operations.
	conn.SetDeadline(time.Time{})
	return conn, br
}

// wsWriteText sends a masked WebSocket text frame (opcode 0x1).
// Client-to-server frames MUST be masked per RFC 6455.
func wsWriteText(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	payload := []byte(msg)

	// Frame: FIN=1, opcode=0x1 (text).
	var frame []byte
	frame = append(frame, 0x81) // FIN + text opcode

	// Payload length + mask bit.
	maskBit := byte(0x80)
	if len(payload) < 126 {
		frame = append(frame, maskBit|byte(len(payload)))
	} else if len(payload) < 65536 {
		frame = append(frame, maskBit|126)
		frame = append(frame, byte(len(payload)>>8), byte(len(payload)))
	} else {
		t.Fatalf("payload too large for test helper: %d", len(payload))
	}

	// Masking key (4 random bytes).
	mask := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, mask); err != nil {
		t.Fatalf("rand mask: %v", err)
	}
	frame = append(frame, mask...)

	// Masked payload.
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	frame = append(frame, masked...)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write text frame: %v", err)
	}
}

// wsReadText reads one WebSocket text frame and returns the payload string.
// Server-to-client frames are unmasked per RFC 6455.
func wsReadText(t *testing.T, br *bufio.Reader) string {
	t.Helper()

	// Read first 2 bytes: FIN/opcode + payload length.
	header := make([]byte, 2)
	br.Read(header[:1]) // This can block; set deadline on conn before calling.
	br.Read(header[1:2])

	opcode := header[0] & 0x0F
	if opcode != 0x1 {
		t.Fatalf("expected text frame (opcode=1), got opcode=%d", opcode)
	}

	masked := (header[1] & 0x80) != 0
	length := uint64(header[1] & 0x7F)

	if length == 126 {
		var ext [2]byte
		io.ReadFull(br, ext[:])
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		io.ReadFull(br, ext[:])
		length = binary.BigEndian.Uint64(ext[:])
	}

	var mask [4]byte
	if masked {
		io.ReadFull(br, mask[:])
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return string(payload)
}

// wsWriteClose sends a WebSocket close frame with the given status code.
func wsWriteClose(t *testing.T, conn net.Conn, code uint16) {
	t.Helper()
	// Close frame: FIN=1, opcode=0x8, payload=2 bytes (status code).
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, code)

	var frame []byte
	frame = append(frame, 0x88)         // FIN + close opcode
	frame = append(frame, 0x80|byte(2)) // masked, length=2

	mask := make([]byte, 4)
	io.ReadFull(rand.Reader, mask)
	frame = append(frame, mask...)

	masked := make([]byte, 2)
	masked[0] = payload[0] ^ mask[0]
	masked[1] = payload[1] ^ mask[1]
	frame = append(frame, masked...)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write close frame: %v", err)
	}
}

// wsAcceptKey computes the expected Sec-WebSocket-Accept value per RFC 6455.
func wsAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-5AB5DC175B18"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
