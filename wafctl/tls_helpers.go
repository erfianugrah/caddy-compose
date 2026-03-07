package main

import (
	"crypto/tls"
	"fmt"
)

// ─── TLS Version and Cipher Suite Helpers ───────────────────────────

// TLS version codes as serialized by Caddy's JSON access log.
// These match the numeric values from crypto/tls constants.
var tlsVersionNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// tlsVersionName returns a human-readable name for a TLS version code.
// Returns "Unknown (0xNNNN)" for unrecognised codes, or empty for 0.
func tlsVersionName(code uint16) string {
	if code == 0 {
		return ""
	}
	if name, ok := tlsVersionNames[code]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04x)", code)
}

// tlsCipherSuiteName returns the standard name for a cipher suite ID
// using Go's crypto/tls package. Returns empty for 0.
func tlsCipherSuiteName(id uint16) string {
	if id == 0 {
		return ""
	}
	return tls.CipherSuiteName(id)
}
