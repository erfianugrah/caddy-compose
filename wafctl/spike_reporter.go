package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ─── Spike Report ───────────────────────────────────────────────────

// SpikeReport is a forensic snapshot generated when a spike ends.
type SpikeReport struct {
	ID              string       `json:"id"`
	StartTime       string       `json:"start_time"`
	EndTime         string       `json:"end_time"`
	Duration        string       `json:"duration"`
	TotalEvents     int64        `json:"total_events"`
	PeakEPS         float64      `json:"peak_eps"`
	JailedIPs       int          `json:"jailed_ips"`
	TopIPs          []CountEntry `json:"top_ips,omitempty"`
	TopPaths        []CountEntry `json:"top_paths,omitempty"`
	TopFingerprints []CountEntry `json:"top_fingerprints,omitempty"`
}

// CountEntry is a key-count pair for top-N lists.
type CountEntry struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// ─── Spike Reporter ─────────────────────────────────────────────────

// SpikeReporter generates and persists spike forensic reports.
type SpikeReporter struct {
	mu        sync.RWMutex
	dir       string // directory for report JSON files
	maxKeep   int    // max reports to retain
	reports   []SpikeReport
	jailStore *JailStore
}

// NewSpikeReporter creates a reporter that saves reports to dir.
func NewSpikeReporter(dir string, maxKeep int, jailStore *JailStore) *SpikeReporter {
	r := &SpikeReporter{
		dir:       dir,
		maxKeep:   maxKeep,
		jailStore: jailStore,
	}
	r.loadExisting()
	return r
}

func (r *SpikeReporter) loadExisting() {
	if r.dir == "" {
		return
	}
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(r.dir, e.Name()))
		if err != nil {
			continue
		}
		var report SpikeReport
		if json.Unmarshal(data, &report) == nil && report.ID != "" {
			r.reports = append(r.reports, report)
		}
	}
	// Sort by start time descending (newest first)
	sort.Slice(r.reports, func(i, j int) bool {
		return r.reports[i].StartTime > r.reports[j].StartTime
	})
	if len(r.reports) > 0 {
		log.Printf("[dos] loaded %d spike reports from %s", len(r.reports), r.dir)
	}
}

// Generate creates a spike report from the given spike metadata.
// Called by SpikeDetector on spike → normal transition.
func (r *SpikeReporter) Generate(spikeStart, spikeEnd time.Time, peakEPS float64, totalEvents int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	report := SpikeReport{
		ID:          fmt.Sprintf("spike-%d", spikeStart.Unix()),
		StartTime:   spikeStart.UTC().Format(time.RFC3339),
		EndTime:     spikeEnd.UTC().Format(time.RFC3339),
		Duration:    spikeEnd.Sub(spikeStart).Truncate(time.Second).String(),
		TotalEvents: totalEvents,
		PeakEPS:     peakEPS,
		JailedIPs:   r.jailStore.Count(),
	}

	// Prepend (newest first)
	r.reports = append([]SpikeReport{report}, r.reports...)

	// Trim to max
	if len(r.reports) > r.maxKeep {
		r.reports = r.reports[:r.maxKeep]
	}

	// Persist to disk
	r.save(report)

	log.Printf("[dos] spike report generated: id=%s duration=%s peak_eps=%.1f events=%d jailed=%d",
		report.ID, report.Duration, report.PeakEPS, report.TotalEvents, report.JailedIPs)
}

func (r *SpikeReporter) save(report SpikeReport) {
	if r.dir == "" {
		return
	}
	os.MkdirAll(r.dir, 0755)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Printf("[dos] error marshaling spike report: %v", err)
		return
	}
	path := filepath.Join(r.dir, report.ID+".json")
	atomicWriteFile(path, data, 0644)

	// Clean old reports from disk
	r.cleanDir()
}

func (r *SpikeReporter) cleanDir() {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}
	// Sort by name descending (spike-TIMESTAMP, newer = larger number)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() > entries[j].Name()
	})
	for i, e := range entries {
		if i >= r.maxKeep && filepath.Ext(e.Name()) == ".json" {
			os.Remove(filepath.Join(r.dir, e.Name()))
		}
	}
}

// List returns all reports, newest first.
func (r *SpikeReporter) List() []SpikeReport {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]SpikeReport, len(r.reports))
	copy(result, r.reports)
	return result
}

// Get returns a single report by ID.
func (r *SpikeReporter) Get(id string) *SpikeReport {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rpt := range r.reports {
		if rpt.ID == id {
			cp := rpt
			return &cp
		}
	}
	return nil
}

// Count returns the number of stored reports.
func (r *SpikeReporter) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.reports)
}
