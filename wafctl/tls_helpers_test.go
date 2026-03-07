package main

import "testing"

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		code uint16
		want string
	}{
		{0, ""},
		{769, "TLS 1.0"}, // 0x0301
		{770, "TLS 1.1"}, // 0x0302
		{771, "TLS 1.2"}, // 0x0303
		{772, "TLS 1.3"}, // 0x0304
		{999, "Unknown (0x03e7)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tlsVersionName(tt.code)
			if got != tt.want {
				t.Errorf("tlsVersionName(%d) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestTLSCipherSuiteName(t *testing.T) {
	tests := []struct {
		id   uint16
		want string
	}{
		{0, ""},
		{4865, "TLS_AES_128_GCM_SHA256"},                   // 0x1301
		{4866, "TLS_AES_256_GCM_SHA384"},                   // 0x1302
		{4867, "TLS_CHACHA20_POLY1305_SHA256"},             // 0x1303
		{49199, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},   // 0xc02f
		{49200, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},   // 0xc030
		{49195, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, // 0xc02b
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tlsCipherSuiteName(tt.id)
			if got != tt.want {
				t.Errorf("tlsCipherSuiteName(%d) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}
