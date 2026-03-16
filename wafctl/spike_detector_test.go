package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSpikeDetector_InitialState(t *testing.T) {
	d := NewSpikeDetector("", 50, 10, 30*time.Second)
	if d.Mode() != "normal" {
		t.Fatalf("initial mode: got %q, want normal", d.Mode())
	}
	if d.EPS() != 0 {
		t.Fatalf("initial EPS: got %f, want 0", d.EPS())
	}
}

func TestSpikeDetector_RecordEvent(t *testing.T) {
	d := NewSpikeDetector("", 50, 10, 30*time.Second)

	// Record 60 events in 1 second
	now := time.Now()
	for range 60 {
		d.recordEventAt(now)
	}

	// EPS should be 60/60 = 1.0 (events spread across 60-second window)
	eps := d.EPS()
	if eps < 0.9 || eps > 1.1 {
		t.Fatalf("EPS after 60 events in 1 sec: got %f, want ~1.0", eps)
	}
}

func TestSpikeDetector_SpikeMode(t *testing.T) {
	d := NewSpikeDetector("", 5, 1, 100*time.Millisecond) // low thresholds for testing

	// Record enough events to trigger spike (5 eps = 300 events in 60s)
	now := time.Now()
	for i := range 60 {
		sec := now.Add(time.Duration(i) * time.Second)
		for range 10 { // 10 events per second = 10 EPS
			d.recordEventAt(sec)
		}
	}

	d.updateMode()

	if d.Mode() != "spike" {
		t.Fatalf("mode after 10 EPS (trigger=5): got %q, want spike", d.Mode())
	}

	status := d.Status()
	if status.PeakEPS < 5 {
		t.Fatalf("peak EPS should be >= 5, got %f", status.PeakEPS)
	}
}

func TestSpikeDetector_CooldownWithHysteresis(t *testing.T) {
	d := NewSpikeDetector("", 5, 2, 100*time.Millisecond) // cooldown=2 EPS

	// Push into spike mode
	now := time.Now()
	for i := range 60 {
		sec := now.Add(time.Duration(i) * time.Second)
		for range 10 {
			d.recordEventAt(sec)
		}
	}
	d.updateMode()
	if d.Mode() != "spike" {
		t.Fatal("should be in spike mode")
	}

	// Advance time far enough that all buckets are flushed (> 60 seconds with no events).
	// This drives EPS to 0, well below cooldown threshold of 2.
	futureBase := now.Add(200 * time.Second)
	d.recordEventAt(futureBase) // single event to advance the window

	d.updateMode() // EPS ≈ 0.017, below cooldown=2 → starts cooldown timer

	// Wait for cooldown delay
	time.Sleep(150 * time.Millisecond)
	d.updateMode() // cooldown elapsed → should exit spike

	if d.Mode() != "normal" {
		t.Fatalf("should return to normal after cooldown delay, got %q (eps=%f)",
			d.Mode(), d.EPS())
	}
}

func TestSpikeDetector_LogTailing(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "access.log")

	// Create empty file first, then create the detector (seeks to end)
	os.WriteFile(logFile, nil, 0644)
	d := NewSpikeDetector(logFile, 50, 10, 30*time.Second)

	// Now append events AFTER the detector's initial seek
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		entry := map[string]any{
			"level":       "info",
			"ts":          time.Now().Unix(),
			"msg":         "handled request",
			"status":      200,
			"ddos_action": "pass",
			"request":     map[string]any{"method": "GET", "uri": "/test"},
		}
		if i%10 == 0 {
			entry["ddos_action"] = "blocked"
		}
		line, _ := json.Marshal(entry)
		f.Write(line)
		f.Write([]byte("\n"))
	}
	f.Close()

	d.tail()

	// Should have recorded 100 events (all lines have ddos_action)
	eps := d.EPS()
	if eps < 1.0 {
		t.Fatalf("EPS after tailing 100 events: got %f, want > 1.0", eps)
	}
}

func TestSpikeDetector_LogTailingIncremental(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "access.log")

	// Create empty file, then detector (seeks to end)
	os.WriteFile(logFile, nil, 0644)
	d := NewSpikeDetector(logFile, 50, 10, 30*time.Second)

	// Write initial lines AFTER detector created
	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	for range 10 {
		entry := map[string]any{"ddos_action": "pass"}
		line, _ := json.Marshal(entry)
		f.Write(line)
		f.Write([]byte("\n"))
	}
	f.Close()

	d.tail()
	eps1 := d.EPS()

	// Append more lines
	f, _ = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	for range 20 {
		entry := map[string]any{"ddos_action": "pass"}
		line, _ := json.Marshal(entry)
		f.Write(line)
		f.Write([]byte("\n"))
	}
	f.Close()

	d.tail()
	eps2 := d.EPS()

	if eps2 <= eps1 {
		t.Fatalf("EPS should increase after more events: before=%f after=%f", eps1, eps2)
	}
}

func TestSpikeDetector_IgnoresLinesWithoutDDoSAction(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "access.log")

	// Create empty file, then detector (seeks to end)
	os.WriteFile(logFile, nil, 0644)
	d := NewSpikeDetector(logFile, 50, 10, 30*time.Second)

	// Append lines AFTER detector created
	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	// Lines without ddos_action
	for range 50 {
		entry := map[string]any{"status": 200, "msg": "handled request"}
		line, _ := json.Marshal(entry)
		f.Write(line)
		f.Write([]byte("\n"))
	}
	// Lines with ddos_action
	for range 10 {
		entry := map[string]any{"ddos_action": "pass"}
		line, _ := json.Marshal(entry)
		f.Write(line)
		f.Write([]byte("\n"))
	}
	f.Close()

	d.tail()

	// Only the 10 lines with ddos_action should be counted
	// EPS = 10/60 ≈ 0.17
	eps := d.EPS()
	if eps > 0.5 {
		t.Fatalf("EPS should reflect only ddos_action lines: got %f (expected ~0.17)", eps)
	}
}
