package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ─── SpikeDetector ──────────────────────────────────────────────────

// SpikeDetector tails the combined access log for ddos_action fields
// and computes real-time events-per-second (EPS). It determines
// spike/normal mode using configurable thresholds with hysteresis.
type SpikeDetector struct {
	mu sync.RWMutex

	// Config
	logFile       string
	triggerEPS    float64       // enter spike mode above this EPS
	cooldownEPS   float64       // exit spike mode below this EPS
	cooldownDelay time.Duration // sustain below cooldown for this long before exiting

	// State
	mode          string    // "normal" or "spike"
	currentEPS    float64   // current events per second
	peakEPS       float64   // peak EPS in current spike
	spikeStart    time.Time // when current spike began
	belowCooldown time.Time // when EPS first dropped below cooldown threshold

	// Sliding window: count events in 1-second buckets, keep 60 seconds.
	buckets    [60]int64
	bucketIdx  int
	bucketTime int64 // unix second of current bucket
	totalCount int64 // sum of all buckets

	// EPS history for sparkline (last 60 readings at 5s intervals = 5 min)
	epsHistory [60]float64
	epsHistIdx int

	// Callback for spike end (generates forensic report)
	onSpikeEnd func(start, end time.Time, peakEPS float64, totalEvents int64)

	// Log tailing
	offset atomic.Int64
}

// NewSpikeDetector creates a new detector with the given config.
func NewSpikeDetector(logFile string, triggerEPS, cooldownEPS float64, cooldownDelay time.Duration) *SpikeDetector {
	d := &SpikeDetector{
		logFile:       logFile,
		triggerEPS:    triggerEPS,
		cooldownEPS:   cooldownEPS,
		cooldownDelay: cooldownDelay,
		mode:          "normal",
	}
	// Skip the backlog on first tail — seek to end so only new events
	// feed the real-time EPS counter. Historical events are already
	// in the access log store's event pipeline.
	if logFile != "" {
		if f, err := os.Open(logFile); err == nil {
			if info, err := f.Stat(); err == nil {
				d.offset.Store(info.Size())
			}
			f.Close()
		}
	}
	return d
}

// SetOnSpikeEnd registers a callback invoked when spike mode exits.
func (d *SpikeDetector) SetOnSpikeEnd(fn func(start, end time.Time, peakEPS float64, totalEvents int64)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onSpikeEnd = fn
}

// StartTailing begins background log tailing and EPS computation.
func (d *SpikeDetector) StartTailing(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.tail()
				d.updateMode()
			}
		}
	}()
}

// ─── Queries ────────────────────────────────────────────────────────

// Status returns the current spike detection state.
func (d *SpikeDetector) Status() DosStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Build ordered history: oldest first, starting after current index
	history := make([]float64, len(d.epsHistory))
	for i := range history {
		history[i] = d.epsHistory[(d.epsHistIdx+i)%len(d.epsHistory)]
	}

	return DosStatus{
		Mode:       d.mode,
		EPS:        d.currentEPS,
		PeakEPS:    d.peakEPS,
		EPSHistory: history,
	}
}

// Mode returns "normal" or "spike".
func (d *SpikeDetector) Mode() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.mode
}

// EPS returns the current events per second.
func (d *SpikeDetector) EPS() float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.currentEPS
}

// ─── Sliding Window ─────────────────────────────────────────────────

// RecordEvent records a single event at the current time.
// Used for testing or manual injection.
func (d *SpikeDetector) RecordEvent() {
	d.recordEventAt(time.Now())
}

func (d *SpikeDetector) recordEventAt(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	sec := t.Unix()
	d.advanceTo(sec)
	d.buckets[d.bucketIdx]++
	d.totalCount++
	d.recomputeEPS()
}

// advanceTo moves the sliding window forward to the given unix second.
// Must be called with mu held.
func (d *SpikeDetector) advanceTo(sec int64) {
	if d.bucketTime == 0 {
		d.bucketTime = sec
		return
	}

	elapsed := sec - d.bucketTime
	if elapsed <= 0 {
		return // same second or time went backward
	}

	// Zero out buckets we're skipping over
	skip := int(elapsed)
	if skip > len(d.buckets) {
		skip = len(d.buckets)
	}
	for i := range skip {
		d.bucketIdx = (d.bucketIdx + 1) % len(d.buckets)
		d.totalCount -= d.buckets[d.bucketIdx]
		d.buckets[d.bucketIdx] = 0
		_ = i
	}
	d.bucketTime = sec
}

// recomputeEPS recalculates current EPS from the sliding window.
// Must be called with mu held.
func (d *SpikeDetector) recomputeEPS() {
	// EPS = total events in window / window duration (60s)
	d.currentEPS = float64(d.totalCount) / float64(len(d.buckets))
}

// ─── Mode Transitions ───────────────────────────────────────────────

func (d *SpikeDetector) updateMode() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Advance window to current time (flush stale buckets)
	d.advanceTo(time.Now().Unix())
	d.recomputeEPS()

	// Record EPS into sparkline history
	d.epsHistory[d.epsHistIdx] = d.currentEPS
	d.epsHistIdx = (d.epsHistIdx + 1) % len(d.epsHistory)

	switch d.mode {
	case "normal":
		if d.currentEPS >= d.triggerEPS {
			d.mode = "spike"
			d.spikeStart = time.Now()
			d.peakEPS = d.currentEPS
			d.belowCooldown = time.Time{}
			log.Printf("[dos] spike mode ENTERED: eps=%.1f trigger=%.1f", d.currentEPS, d.triggerEPS)
		}
	case "spike":
		if d.currentEPS > d.peakEPS {
			d.peakEPS = d.currentEPS
		}
		if d.currentEPS < d.cooldownEPS {
			if d.belowCooldown.IsZero() {
				d.belowCooldown = time.Now()
			} else if time.Since(d.belowCooldown) >= d.cooldownDelay {
				spikeEnd := time.Now()
				spikeDuration := spikeEnd.Sub(d.spikeStart)
				peakEPS := d.peakEPS
				totalEvents := d.totalCount
				log.Printf("[dos] spike mode EXITED: duration=%s peak_eps=%.1f",
					spikeDuration.Truncate(time.Second), peakEPS)
				if d.onSpikeEnd != nil {
					go d.onSpikeEnd(d.spikeStart, spikeEnd, peakEPS, totalEvents)
				}
				d.mode = "normal"
				d.peakEPS = 0
				d.belowCooldown = time.Time{}
			}
		} else {
			d.belowCooldown = time.Time{}
		}
	}
}

// ─── Log Tailing ────────────────────────────────────────────────────

// ddosLogEntry is a minimal struct to extract ddos_action from access log lines.
type ddosLogEntry struct {
	DDoSAction string  `json:"ddos_action"`
	Ts         float64 `json:"ts"` // unix timestamp (might be string in wall format)
}

func (d *SpikeDetector) tail() {
	if d.logFile == "" {
		return
	}

	f, err := os.Open(d.logFile)
	if err != nil {
		return // file may not exist yet
	}
	defer f.Close()

	// Check for rotation (copytruncate)
	info, err := f.Stat()
	if err != nil {
		return
	}
	curOffset := d.offset.Load()
	if info.Size() < curOffset {
		d.offset.Store(0)
		curOffset = 0
	}

	if _, err := f.Seek(curOffset, io.SeekStart); err != nil {
		return
	}

	reader := bufio.NewReaderSize(f, 64*1024)
	count := 0
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) == 0 || err != nil {
			break
		}

		var entry ddosLogEntry
		if json.Unmarshal(line, &entry) != nil {
			continue
		}

		// Only count lines that have a ddos_action field
		if entry.DDoSAction != "" {
			d.RecordEvent()
			count++
		}
	}

	newOffset, _ := f.Seek(0, io.SeekCurrent)
	d.offset.Store(newOffset)

	if count > 0 {
		log.Printf("[dos] tailed %d ddos events, eps=%.1f mode=%s", count, d.EPS(), d.Mode())
	}
}
