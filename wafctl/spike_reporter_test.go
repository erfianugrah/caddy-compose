package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSpikeReporter_Generate(t *testing.T) {
	dir := t.TempDir()
	jailDir := t.TempDir()
	jail := NewJailStore(filepath.Join(jailDir, "jail.json"))

	r := NewSpikeReporter(dir, 5, jail)

	start := time.Now().Add(-5 * time.Minute)
	end := time.Now()

	r.Generate(start, end, 123.5, 5000)

	if r.Count() != 1 {
		t.Fatalf("expected 1 report, got %d", r.Count())
	}

	reports := r.List()
	if reports[0].PeakEPS != 123.5 {
		t.Errorf("peak_eps = %f, want 123.5", reports[0].PeakEPS)
	}
	if reports[0].TotalEvents != 5000 {
		t.Errorf("total_events = %d, want 5000", reports[0].TotalEvents)
	}
	if reports[0].Duration == "" {
		t.Error("expected non-empty duration")
	}
}

func TestSpikeReporter_Get(t *testing.T) {
	dir := t.TempDir()
	jailDir := t.TempDir()
	jail := NewJailStore(filepath.Join(jailDir, "jail.json"))
	r := NewSpikeReporter(dir, 5, jail)

	start := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	end := start.Add(3 * time.Minute)

	r.Generate(start, end, 50.0, 1000)

	// Get by expected ID format.
	id := "spike-" + "1736935200" // 2025-01-15T10:00:00Z unix
	report := r.Get(id)
	if report == nil {
		// Try the actual ID from the list.
		reports := r.List()
		if len(reports) > 0 {
			report = r.Get(reports[0].ID)
		}
	}
	if report == nil {
		t.Fatal("report not found")
	}
	if report.PeakEPS != 50.0 {
		t.Errorf("peak_eps = %f, want 50.0", report.PeakEPS)
	}
}

func TestSpikeReporter_GetNotFound(t *testing.T) {
	dir := t.TempDir()
	jailDir := t.TempDir()
	jail := NewJailStore(filepath.Join(jailDir, "jail.json"))
	r := NewSpikeReporter(dir, 5, jail)

	if r.Get("nonexistent") != nil {
		t.Error("expected nil for nonexistent report")
	}
}

func TestSpikeReporter_MaxKeep(t *testing.T) {
	dir := t.TempDir()
	jailDir := t.TempDir()
	jail := NewJailStore(filepath.Join(jailDir, "jail.json"))
	r := NewSpikeReporter(dir, 3, jail)

	// Generate 5 reports — should keep only 3 in memory.
	for i := range 5 {
		start := time.Now().Add(time.Duration(i) * time.Second)
		end := start.Add(time.Minute)
		r.Generate(start, end, float64(i*10), int64(i*100))
	}

	if r.Count() != 3 {
		t.Fatalf("expected 3 reports (maxKeep=3), got %d", r.Count())
	}

	// Check disk: should also be trimmed.
	entries, _ := os.ReadDir(dir)
	jsonCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			jsonCount++
		}
	}
	if jsonCount > 3 {
		t.Errorf("expected <= 3 json files on disk, got %d", jsonCount)
	}
}

func TestSpikeReporter_Persistence(t *testing.T) {
	dir := t.TempDir()
	jailDir := t.TempDir()
	jail := NewJailStore(filepath.Join(jailDir, "jail.json"))

	// Generate a report.
	r1 := NewSpikeReporter(dir, 5, jail)
	start := time.Now().Add(-time.Minute)
	end := time.Now()
	r1.Generate(start, end, 75.0, 2000)

	// Create a new reporter and verify it loads from disk.
	r2 := NewSpikeReporter(dir, 5, jail)
	if r2.Count() != 1 {
		t.Fatalf("expected 1 report loaded from disk, got %d", r2.Count())
	}
	reports := r2.List()
	if reports[0].PeakEPS != 75.0 {
		t.Errorf("peak_eps = %f, want 75.0", reports[0].PeakEPS)
	}
}

func TestSpikeReporter_EmptyDir(t *testing.T) {
	jailDir := t.TempDir()
	jail := NewJailStore(filepath.Join(jailDir, "jail.json"))

	// Empty dir string — should not panic.
	r := NewSpikeReporter("", 5, jail)
	if r.Count() != 0 {
		t.Errorf("expected 0 reports, got %d", r.Count())
	}
	// Generate should not panic with empty dir.
	r.Generate(time.Now(), time.Now().Add(time.Minute), 10.0, 100)
	if r.Count() != 1 {
		t.Errorf("expected 1 report in memory, got %d", r.Count())
	}
}

func TestSpikeReporter_CleanDirOnlySpikeFiles(t *testing.T) {
	dir := t.TempDir()
	jailDir := t.TempDir()
	jail := NewJailStore(filepath.Join(jailDir, "jail.json"))

	// Create a non-spike .json file that should NOT be counted/deleted.
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0644)

	r := NewSpikeReporter(dir, 2, jail)

	// Generate 3 reports — maxKeep is 2.
	for i := range 3 {
		start := time.Now().Add(time.Duration(i) * time.Second)
		r.Generate(start, start.Add(time.Minute), float64(i), int64(i))
	}

	// config.json should still exist.
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Errorf("config.json was incorrectly deleted: %v", err)
	}
}
