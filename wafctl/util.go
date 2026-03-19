package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// withFileLock acquires an exclusive flock on path+".lock" for the duration
// of fn. Coordinates jail file access with the caddy-ddos-mitigator plugin.
// Returns an error if the lock cannot be acquired (matching the plugin's
// behavior to prevent uncoordinated writes).
func withFileLock(path string, fn func() error) error {
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire file lock: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

// queryIntEnv reads an integer from an environment variable with a default value.
func queryIntEnv(key string, defaultVal int) int {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	if v, err := strconv.Atoi(s); err == nil && v > 0 {
		return v
	}
	return defaultVal
}

// headerValue extracts the first value for a header key from a map[string][]string.
// Uses case-insensitive matching (delegates to headerValueCI in access_log_store.go).
func headerValue(headers map[string][]string, key string) string {
	return headerValueCI(headers, key)
}

// parseTimestamp parses "2006/01/02 15:04:05" format timestamps.
func parseTimestamp(raw string) time.Time {
	t, err := time.Parse("2006/01/02 15:04:05", raw)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// splitNamedField splits "Name:value" into (name, value). If no colon is
// present, returns (s, ""). Used by condition builders for named fields
// like header, cookie, args, etc.
func splitNamedField(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// atomicWriteFile writes data to a file atomically by first writing to a
// temporary file in the same directory, then renaming it to the target path.
// This prevents corruption if the process crashes mid-write.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up the temp file on any error.
	success := false
	defer func() {
		if !success {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	// Sync to ensure data is flushed to disk before rename.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	// Atomic rename: on POSIX, rename within the same filesystem is atomic.
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming temp file to %s: %w", path, err)
	}

	success = true
	return nil
}

// generateUUID produces a v4 UUID using crypto/rand.
func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: should never happen with crypto/rand.
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// loadOrGenerateChallengeKey reads or generates a 32-byte HMAC key for
// challenge cookie signing. The key is persisted to challenge-hmac.key in
// the data directory so it survives restarts without invalidating cookies.
// Returns the hex-encoded key string.
func loadOrGenerateChallengeKey(dataDir string) string {
	keyFile := filepath.Join(dataDir, "challenge-hmac.key")
	if data, err := os.ReadFile(keyFile); err == nil {
		s := strings.TrimSpace(string(data))
		if len(s) == 64 { // 32 bytes hex-encoded
			if _, err := hex.DecodeString(s); err == nil {
				return s
			}
		}
		log.Printf("[challenge] warning: invalid key in %s, regenerating", keyFile)
	}
	// Generate a new 32-byte random key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Printf("[challenge] warning: failed to generate HMAC key: %v", err)
		return ""
	}
	keyHex := hex.EncodeToString(key)
	if err := os.MkdirAll(dataDir, 0755); err == nil {
		if err := atomicWriteFile(keyFile, []byte(keyHex+"\n"), 0600); err != nil {
			log.Printf("[challenge] warning: failed to persist HMAC key to %s: %v", keyFile, err)
		} else {
			log.Printf("[challenge] generated and persisted HMAC key to %s", keyFile)
		}
	}
	return keyHex
}
