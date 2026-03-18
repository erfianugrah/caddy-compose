package main

import (
	"encoding/json"
	"log"
	"os"
	"sync/atomic"
)

// ─── CRS Metadata (loaded from crs-metadata.json at startup) ───────
//
// This is the single source of truth for CRS category taxonomy.
// The converter generates crs-metadata.json at Docker build time from
// the actual CRS .conf files. All hardcoded category maps in this
// codebase are fallbacks — production always uses the generated file.

// CRSMetadata holds the CRS category taxonomy loaded from crs-metadata.json.
type CRSMetadata struct {
	CRSVersion      string                `json:"crs_version"`
	GeneratedAt     string                `json:"generated_at"`
	Categories      []CRSMetadataCategory `json:"categories"`
	CategoryMap     map[string]string     `json:"category_map"`
	ValidPrefixes   []string              `json:"valid_prefixes"`
	SeverityLevels  map[string]int        `json:"severity_levels"`
	CustomRuleRange string                `json:"custom_rule_range"`

	// Derived indexes built on load for O(1) lookup.
	prefixSet   map[string]bool   // ValidPrefixes as a set
	categoryMap map[string]string // same as CategoryMap (redundant but explicit)
}

// CRSMetadataCategory describes a single CRS rule category.
type CRSMetadataCategory struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Prefix      string `json:"prefix"`
	RuleRange   string `json:"rule_range"`
	Tag         string `json:"tag"`
	Phase       string `json:"phase"`
	RuleCount   int    `json:"rule_count"`
}

// defaultCRSMetadata is the package-level metadata instance.
// Uses atomic.Pointer for thread-safe access without a mutex.
// Initialized to an empty instance; production loads from crs-metadata.json
// in main(), tests load from testdata/crs-metadata.json in TestMain().
var defaultCRSMetadata atomic.Pointer[CRSMetadata]

func init() {
	// Seed with an empty-but-safe instance so GetCRSMetadata() never returns nil
	// before main() or TestMain() loads the real metadata.
	defaultCRSMetadata.Store(&CRSMetadata{
		CRSVersion:     "uninitialized",
		CategoryMap:    map[string]string{},
		SeverityLevels: map[string]int{},
		prefixSet:      map[string]bool{},
	})
}

// LoadCRSMetadata reads and parses crs-metadata.json from disk.
// Returns the parsed metadata with derived indexes built.
func LoadCRSMetadata(path string) (*CRSMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var meta CRSMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	meta.buildIndexes()
	return &meta, nil
}

// SetCRSMetadata sets the package-level metadata used by all lookup functions.
// Called once during server startup after loading from disk.
func SetCRSMetadata(meta *CRSMetadata) {
	defaultCRSMetadata.Store(meta)
	log.Printf("[crs] loaded metadata: version=%s categories=%d prefixes=%d",
		meta.CRSVersion, len(meta.Categories), len(meta.ValidPrefixes))
}

// GetCRSMetadata returns the current CRS metadata.
func GetCRSMetadata() *CRSMetadata {
	return defaultCRSMetadata.Load()
}

// ─── Lookup Methods ─────────────────────────────────────────────────

// NormalizeCategory maps a converter's full category string (e.g.,
// "REQUEST-920-PROTOCOL-ENFORCEMENT") to a short ID ("protocol-enforcement").
// Falls back to returning the input unchanged if no mapping exists.
func (m *CRSMetadata) NormalizeCategory(category string) string {
	if short, ok := m.CategoryMap[category]; ok {
		return short
	}
	return category
}

// IsValidPrefix returns true if the given 3-4 digit string is a known
// CRS rule ID prefix (for disabled_categories validation).
func (m *CRSMetadata) IsValidPrefix(prefix string) bool {
	return m.prefixSet[prefix]
}

// SeverityToNumeric converts a severity name to its numeric value.
// Returns 0 for unknown severities.
func (m *CRSMetadata) SeverityToNumeric(severity string) int {
	return m.SeverityLevels[severity]
}

// ─── Internal ───────────────────────────────────────────────────────

// buildIndexes populates derived lookup maps from the JSON fields.
func (m *CRSMetadata) buildIndexes() {
	m.prefixSet = make(map[string]bool, len(m.ValidPrefixes))
	for _, p := range m.ValidPrefixes {
		m.prefixSet[p] = true
	}
	// CategoryMap is already populated from JSON; copy to the internal field.
	if m.categoryMap == nil {
		m.categoryMap = m.CategoryMap
	}
}
