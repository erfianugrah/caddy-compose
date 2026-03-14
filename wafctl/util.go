package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
