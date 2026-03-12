package main

import (
	"fmt"
	"sort"
	"strings"
)

// ─── Report Generation ─────────────────────────────────────────────

// PrintReport outputs the conversion report to stdout.
func (r *Report) PrintReport() {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  CRS → Policy Engine Conversion Report  (CRS %s)\n", r.CRSVersion)
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Summary
	pct := 0.0
	if r.TotalRules > 0 {
		pct = float64(r.ConvertedRules) / float64(r.TotalRules) * 100
	}
	fmt.Printf("  Total rules parsed:   %d\n", r.TotalRules)
	fmt.Printf("  Successfully converted: %d (%.1f%%)\n", r.ConvertedRules, pct)
	fmt.Printf("  Skipped:              %d\n", r.SkippedRules)
	fmt.Println()

	// Per-category breakdown
	if len(r.CategoryStats) > 0 {
		fmt.Println("─── Per-Category Coverage ────────────────────────────────────")
		var cats []string
		for c := range r.CategoryStats {
			cats = append(cats, c)
		}
		sort.Strings(cats)

		for _, cat := range cats {
			stat := r.CategoryStats[cat]
			cpct := 0.0
			if stat.Total > 0 {
				cpct = float64(stat.Converted) / float64(stat.Total) * 100
			}
			fmt.Printf("  %-50s %3d/%3d (%5.1f%%)\n",
				truncate(cat, 50), stat.Converted, stat.Total, cpct)
		}
		fmt.Println()
	}

	// Skip breakdown
	if len(r.SkippedFlowControl) > 0 {
		fmt.Printf("─── Skipped: Flow Control (%d) ───────────────────────────────\n", len(r.SkippedFlowControl))
		printSkipped(r.SkippedFlowControl, 10)
	}

	if len(r.SkippedResponsePhase) > 0 {
		fmt.Printf("─── Skipped: Response Phase (%d) ─────────────────────────────\n", len(r.SkippedResponsePhase))
		printSkipped(r.SkippedResponsePhase, 10)
	}

	if len(r.SkippedUnsupportedOp) > 0 {
		fmt.Printf("─── Skipped: Unsupported Operator (%d) ──────────────────────\n", len(r.SkippedUnsupportedOp))
		printSkipped(r.SkippedUnsupportedOp, 20)
	}

	if len(r.SkippedPCRERegex) > 0 {
		fmt.Printf("─── Skipped: PCRE-Only Regex (%d) ──────────────────────────\n", len(r.SkippedPCRERegex))
		printSkipped(r.SkippedPCRERegex, 20)
	}

	if len(r.SkippedOther) > 0 {
		fmt.Printf("─── Skipped: Other (%d) ─────────────────────────────────────\n", len(r.SkippedOther))
		printSkipped(r.SkippedOther, 50)
	}

	// Missing features
	if len(r.MissingOperators) > 0 {
		fmt.Println("─── Missing Operators ────────────────────────────────────────")
		printCountMap(r.MissingOperators)
	}

	if len(r.MissingTransforms) > 0 {
		fmt.Println("─── Missing Transforms ───────────────────────────────────────")
		printCountMap(r.MissingTransforms)
	}

	if len(r.MissingVariables) > 0 {
		fmt.Println("─── Missing Variables ────────────────────────────────────────")
		printCountMap(r.MissingVariables)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
}

func printSkipped(rules []SkippedRule, maxShow int) {
	for i, r := range rules {
		if i >= maxShow {
			fmt.Printf("  ... and %d more\n", len(rules)-maxShow)
			break
		}
		fmt.Printf("  %-10s %s\n", r.ID, r.Reason)
	}
	fmt.Println()
}

func printCountMap(m map[string]int) {
	type kv struct {
		key   string
		count int
	}
	var items []kv
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].count > items[j].count
	})
	for _, item := range items {
		fmt.Printf("  %-30s %d rules\n", item.key, item.count)
	}
	fmt.Println()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s + strings.Repeat(" ", maxLen-len(s))
	}
	return s[:maxLen-3] + "..."
}
