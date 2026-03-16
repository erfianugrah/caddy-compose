package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── JailStore Tests ────────────────────────────────────────────────

func TestJailStore_LoadEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")

	s := NewJailStore(path)
	entries := s.List()
	if len(entries) != 0 {
		t.Fatalf("empty store should have 0 entries, got %d", len(entries))
	}
}

func TestJailStore_LoadExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")

	// Write a jail file
	jf := jailFile{
		Version: 1,
		Entries: map[string]jailFileEntry{
			"192.0.2.1": {
				ExpiresAt:   time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
				Infractions: 3,
				Reason:      "auto:z-score",
				JailedAt:    time.Now().UTC().Format(time.RFC3339),
			},
			"2001:db8::1": {
				ExpiresAt:   time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339),
				Infractions: 1,
				Reason:      "manual",
				JailedAt:    time.Now().UTC().Format(time.RFC3339),
			},
		},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(jf, "", "  ")
	os.WriteFile(path, data, 0644)

	s := NewJailStore(path)
	entries := s.List()
	if len(entries) != 2 {
		t.Fatalf("should have 2 entries, got %d", len(entries))
	}
}

func TestJailStore_SkipsExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")

	jf := jailFile{
		Version: 1,
		Entries: map[string]jailFileEntry{
			"10.0.0.1": {
				ExpiresAt:   time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
				Infractions: 0,
				Reason:      "alive",
				JailedAt:    time.Now().UTC().Format(time.RFC3339),
			},
			"10.0.0.2": {
				ExpiresAt:   time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339), // expired
				Infractions: 0,
				Reason:      "expired",
				JailedAt:    time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
			},
		},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(jf, "", "  ")
	os.WriteFile(path, data, 0644)

	s := NewJailStore(path)
	entries := s.List()
	if len(entries) != 1 {
		t.Fatalf("should skip expired, got %d entries", len(entries))
	}
	if entries[0].IP != "10.0.0.1" {
		t.Fatalf("wrong entry: got %s", entries[0].IP)
	}
}

func TestJailStore_AddAndRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")

	s := NewJailStore(path)

	s.Add("192.0.2.99", "1h", "manual:test")

	entries := s.List()
	if len(entries) != 1 {
		t.Fatalf("after add: got %d entries, want 1", len(entries))
	}
	if entries[0].IP != "192.0.2.99" {
		t.Fatalf("IP: got %s, want 192.0.2.99", entries[0].IP)
	}

	s.Remove("192.0.2.99")
	entries = s.List()
	if len(entries) != 0 {
		t.Fatalf("after remove: got %d entries, want 0", len(entries))
	}
}

func TestJailStore_PersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")

	s := NewJailStore(path)
	s.Add("10.0.0.1", "2h", "manual")

	// Read file directly
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read jail file: %v", err)
	}
	var jf jailFile
	if err := json.Unmarshal(data, &jf); err != nil {
		t.Fatalf("unmarshal jail file: %v", err)
	}
	if _, ok := jf.Entries["10.0.0.1"]; !ok {
		t.Fatal("jail file should contain 10.0.0.1")
	}
}

func TestJailStore_Reload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")

	s := NewJailStore(path)
	s.Add("10.0.0.1", "1h", "initial")

	// Simulate plugin writing a new entry to the file
	jf := jailFile{
		Version: 1,
		Entries: map[string]jailFileEntry{
			"10.0.0.1": {
				ExpiresAt:   time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
				Infractions: 0,
				Reason:      "initial",
				JailedAt:    time.Now().UTC().Format(time.RFC3339),
			},
			"10.0.0.2": {
				ExpiresAt:   time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
				Infractions: 2,
				Reason:      "auto:z-score",
				JailedAt:    time.Now().UTC().Format(time.RFC3339),
			},
		},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(jf, "", "  ")
	os.WriteFile(path, data, 0644)

	s.Reload()
	entries := s.List()
	if len(entries) != 2 {
		t.Fatalf("after reload: got %d entries, want 2", len(entries))
	}
}

// ─── DosConfigStore Tests ───────────────────────────────────────────

func TestDosConfigStore_Defaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dos-config.json")

	s := NewDosConfigStore(path)
	cfg := s.Get()

	if cfg.Threshold != 0.65 {
		t.Fatalf("default threshold: got %f, want 0.65", cfg.Threshold)
	}
	if cfg.BasePenalty != "60s" {
		t.Fatalf("default base_penalty: got %s, want 60s", cfg.BasePenalty)
	}
	if !cfg.Enabled {
		t.Fatal("default enabled should be true")
	}
}

func TestDosConfigStore_UpdateAndPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dos-config.json")

	s := NewDosConfigStore(path)
	cfg := s.Get()
	cfg.Threshold = 3.0
	cfg.EPSTrigger = 100

	if err := s.Update(cfg); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Reload from disk
	s2 := NewDosConfigStore(path)
	cfg2 := s2.Get()
	if cfg2.Threshold != 3.0 {
		t.Fatalf("threshold after reload: got %f, want 3.0", cfg2.Threshold)
	}
	if cfg2.EPSTrigger != 100 {
		t.Fatalf("eps_trigger after reload: got %f, want 100", cfg2.EPSTrigger)
	}
}
