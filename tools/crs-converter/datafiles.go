package main

import (
	"os"
	"path/filepath"
	"strings"
)

// ─── Data File Resolver ────────────────────────────────────────────
//
// CRS uses @pmFromFile to reference external .data files containing
// phrase match patterns (one per line). The converter reads these
// files and inlines the contents as list_items in the PolicyCondition.

// DataFileResolver reads CRS .data files from a rules directory.
type DataFileResolver struct {
	rulesDir string
	cache    map[string][]string
}

// NewDataFileResolver creates a resolver that reads from the given directory.
func NewDataFileResolver(rulesDir string) *DataFileResolver {
	return &DataFileResolver{
		rulesDir: rulesDir,
		cache:    make(map[string][]string),
	}
}

// Resolve reads a .data file and returns its entries as a string slice.
// Entries are one per line, with comments (#) and empty lines stripped.
func (r *DataFileResolver) Resolve(filename string) ([]string, error) {
	if cached, ok := r.cache[filename]; ok {
		return cached, nil
	}

	path := filepath.Join(r.rulesDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}

	r.cache[filename] = entries
	return entries, nil
}

// ResolveCount returns the number of entries in a data file.
func (r *DataFileResolver) ResolveCount(filename string) (int, error) {
	entries, err := r.Resolve(filename)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}
