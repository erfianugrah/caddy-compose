package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ─── CRS-to-PolicyEngine Converter ─────────────────────────────────
//
// Standalone tool that reads CRS .conf files from the coreruleset
// repository and outputs default-rules.json for the caddy-policy-engine
// plugin.
//
// Usage:
//   crs-converter -crs-dir ./coreruleset/rules -output default-rules.json
//   crs-converter -crs-dir ./coreruleset/rules -report  # report only, no output

func main() {
	crsDir := flag.String("crs-dir", "", "Path to CRS rules directory (containing *.conf and *.data files)")
	output := flag.String("output", "default-rules.json", "Output file path")
	version := flag.String("crs-version", "", "CRS version string (e.g., 4.8.0)")
	reportOnly := flag.Bool("report", false, "Print conversion report without generating output")
	flag.Parse()

	if *crsDir == "" {
		fmt.Fprintln(os.Stderr, "Usage: crs-converter -crs-dir <path-to-crs-rules>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "The CRS rules directory should contain *.conf and *.data files.")
		fmt.Fprintln(os.Stderr, "Download CRS from: https://github.com/coreruleset/coreruleset")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Verify directory exists
	info, err := os.Stat(*crsDir)
	if err != nil || !info.IsDir() {
		log.Fatalf("CRS directory not found: %s", *crsDir)
	}

	// Auto-detect CRS version from CHANGES.md or VERSION file
	crsVer := *version
	if crsVer == "" {
		crsVer = detectCRSVersion(*crsDir)
	}

	// Find all .conf files
	confFiles, err := findConfFiles(*crsDir)
	if err != nil {
		log.Fatalf("Finding .conf files: %v", err)
	}

	if len(confFiles) == 0 {
		log.Fatalf("No .conf files found in %s", *crsDir)
	}

	fmt.Printf("Found %d .conf files in %s\n", len(confFiles), *crsDir)

	// Create data file resolver
	dataFiles := NewDataFileResolver(*crsDir)

	// Create converter
	converter := NewConverter(dataFiles)
	converter.report.CRSVersion = crsVer

	// Process each .conf file
	var allRules []PolicyRule
	for _, confFile := range confFiles {
		content, err := os.ReadFile(confFile)
		if err != nil {
			log.Printf("WARNING: reading %s: %v", confFile, err)
			continue
		}

		parsed, err := ParseFile(string(content), confFile)
		if err != nil {
			log.Printf("WARNING: parsing %s: %v", confFile, err)
			continue
		}

		rules := converter.Convert(parsed, confFile)
		allRules = append(allRules, rules...)
	}

	// Sort by rule ID
	SortRules(allRules)

	// Print report
	converter.report.PrintReport()

	if *reportOnly {
		return
	}

	// Build output
	outputFile := PolicyRulesFile{
		DefaultRules: allRules,
		Version:      7, // increment from current v6
		CRSVersion:   crsVer,
		Generated:    time.Now().UTC().Format(time.RFC3339),
	}

	// Write output
	data, err := json.MarshalIndent(outputFile, "", "  ")
	if err != nil {
		log.Fatalf("Marshaling JSON: %v", err)
	}

	if err := os.WriteFile(*output, data, 0644); err != nil {
		log.Fatalf("Writing output: %v", err)
	}

	fmt.Printf("\nWrote %d rules to %s\n", len(allRules), *output)
}

// ─── Helpers ───────────────────────────────────────────────────────

// findConfFiles finds all CRS .conf files in the given directory.
// Looks in the standard CRS layout: rules/*.conf or rules/@owasp_crs/*.conf
func findConfFiles(dir string) ([]string, error) {
	var files []string

	// Try standard layouts
	patterns := []string{
		filepath.Join(dir, "*.conf"),
		filepath.Join(dir, "@owasp_crs", "*.conf"),
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
	}

	// Sort by filename for deterministic order
	sort.Strings(files)

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, f := range files {
		abs, _ := filepath.Abs(f)
		if !seen[abs] {
			seen[abs] = true
			unique = append(unique, f)
		}
	}

	return unique, nil
}

// detectCRSVersion tries to detect the CRS version from the repository.
func detectCRSVersion(rulesDir string) string {
	// Try parent directory for VERSION file
	parent := filepath.Dir(rulesDir)

	// Check for CHANGES.md first line: "## Version 4.x.y"
	changes := filepath.Join(parent, "CHANGES.md")
	if data, err := os.ReadFile(changes); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "## Version ") {
				return strings.TrimPrefix(line, "## Version ")
			}
		}
	}

	// Check for VERSION file
	versionFile := filepath.Join(parent, "VERSION")
	if data, err := os.ReadFile(versionFile); err == nil {
		return strings.TrimSpace(string(data))
	}

	return "unknown"
}
