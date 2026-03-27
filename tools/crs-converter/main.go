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
	metadataOutput := flag.String("metadata-output", "", "Output path for crs-metadata.json (category taxonomy for wafctl)")
	version := flag.String("crs-version", "", "CRS version string (e.g., 4.8.0)")
	customRules := flag.String("custom-rules", "", "Path to custom rules JSON file to merge into output")
	reportOnly := flag.Bool("report", false, "Print conversion report without generating output")
	flag.BoolVar(&separateArgs, "separate-args", false, "Map ARGS_GET/ARGS_POST to dedicated fields (requires plugin support)")
	flag.Parse()

	// Apply separate-args mapping if enabled.
	initSeparateArgs()

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

	// Phase 1: Parse all .conf files — collect SecRules and TargetUpdates.
	// TargetUpdates (SecRuleUpdateTargetById) can appear in later files
	// than the rules they modify, so we collect everything first.
	var parsedFiles []parsedFile
	var allUpdates []TargetUpdate

	for _, confFile := range confFiles {
		content, err := os.ReadFile(confFile)
		if err != nil {
			log.Printf("WARNING: reading %s: %v", confFile, err)
			continue
		}

		result := ParseFileWithUpdates(string(content), confFile)
		if result.err != nil {
			log.Printf("WARNING: parsing %s: %v", confFile, result.err)
			continue
		}

		parsedFiles = append(parsedFiles, parsedFile{filename: confFile, rules: result.Rules})
		allUpdates = append(allUpdates, result.Updates...)
	}

	// Phase 2: Apply SecRuleUpdateTargetById directives to parsed rules.
	// Each update adds negation variable exclusions to the target rule.
	if len(allUpdates) > 0 {
		applyTargetUpdates(parsedFiles, allUpdates)
		fmt.Printf("Applied %d SecRuleUpdateTargetById directives to parsed rules\n", len(allUpdates))
	}

	// Phase 3: Convert parsed SecRules to PolicyRules.
	var allRules []PolicyRule
	for _, pf := range parsedFiles {
		rules := converter.Convert(pf.rules, pf.filename)
		allRules = append(allRules, rules...)
	}

	// Merge custom rules if provided. Custom rules take priority over
	// CRS-converted rules with the same ID — they are curated corrections
	// for rules the converter handles incorrectly.
	if *customRules != "" {
		data, err := os.ReadFile(*customRules)
		if err != nil {
			log.Fatalf("Reading custom rules: %v", err)
		}
		var custom []PolicyRule
		if err := json.Unmarshal(data, &custom); err != nil {
			log.Fatalf("Parsing custom rules: %v", err)
		}

		// Build set of custom rule IDs for deduplication.
		customIDs := make(map[string]bool, len(custom))
		for _, r := range custom {
			customIDs[r.ID] = true
		}

		// Remove CRS-converted rules that have a custom replacement.
		deduped := make([]PolicyRule, 0, len(allRules))
		dupeCount := 0
		for _, r := range allRules {
			if customIDs[r.ID] {
				dupeCount++
				continue
			}
			deduped = append(deduped, r)
		}
		allRules = append(deduped, custom...)

		if dupeCount > 0 {
			fmt.Printf("Merged %d custom rules from %s (%d CRS duplicates replaced)\n", len(custom), *customRules, dupeCount)
		} else {
			fmt.Printf("Merged %d custom rules from %s\n", len(custom), *customRules)
		}
	}

	// Sort by rule ID (stable to preserve custom-before-CRS order for same IDs)
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

	// Generate CRS metadata if requested
	if *metadataOutput != "" {
		meta := BuildMetadata(allRules, crsVer)
		metaData, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			log.Fatalf("Marshaling CRS metadata: %v", err)
		}
		if err := os.WriteFile(*metadataOutput, metaData, 0644); err != nil {
			log.Fatalf("Writing CRS metadata: %v", err)
		}
		fmt.Printf("Wrote CRS metadata (%d categories, %d prefixes) to %s\n",
			len(meta.Categories), len(meta.ValidPrefixes), *metadataOutput)
	}
}

// ─── Helpers ───────────────────────────────────────────────────────

// parsedFile holds parsed SecRules from a single .conf file.
type parsedFile struct {
	filename string
	rules    []SecRule
}

// applyTargetUpdates merges SecRuleUpdateTargetById directives into the
// parsed rules. Each update adds negation variable exclusions (e.g.,
// !REQUEST_COOKIES:/__utm/) to the target rule's variable list.
//
// This is how CRS suppresses false positives for well-known cookies
// (Google Analytics _ga, ad-tech FCCDCF/FCNEC, analytics _pk_ref, etc.).
// Without these exclusions, detection rules over-match on cookie values.
func applyTargetUpdates(files []parsedFile, updates []TargetUpdate) {
	// Build update index: rule ID → list of variables to add
	updatesByID := make(map[string][]Variable)
	for _, upd := range updates {
		updatesByID[upd.TargetRuleID] = append(updatesByID[upd.TargetRuleID], upd.Variables...)
	}

	// Walk all parsed rules and apply matching updates
	for fi := range files {
		for ri := range files[fi].rules {
			rule := &files[fi].rules[ri]
			if vars, ok := updatesByID[rule.ID]; ok {
				rule.Variables = append(rule.Variables, vars...)
			}
			// Also check chain links (rare but possible)
			for chain := rule.Chain; chain != nil; chain = chain.Chain {
				if vars, ok := updatesByID[chain.ID]; ok {
					chain.Variables = append(chain.Variables, vars...)
				}
			}
		}
	}
}

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
