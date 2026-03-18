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
var defaultCRSMetadata atomic.Pointer[CRSMetadata]

func init() {
	defaultCRSMetadata.Store(fallbackMetadata())
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

// fallbackMetadata returns hardcoded metadata for use when crs-metadata.json
// is not available (tests, dev, or first startup before Docker build).
// This mirrors the static data that was previously in crs_rules.go and config.go.
func fallbackMetadata() *CRSMetadata {
	meta := &CRSMetadata{
		CRSVersion:  "fallback",
		GeneratedAt: "",
		Categories: []CRSMetadataCategory{
			{ID: "scanner-detection", Name: "Scanner Detection", Description: "Known security scanner detection", Prefix: "913", RuleRange: "913000-913999", Tag: "attack-reputation-scanner", Phase: "inbound"},
			{ID: "protocol-enforcement", Name: "Protocol Enforcement", Description: "HTTP protocol violations and anomalies", Prefix: "920", RuleRange: "920000-920999", Tag: "attack-protocol", Phase: "inbound"},
			{ID: "protocol-attack", Name: "Protocol Attack", Description: "HTTP request smuggling, response splitting", Prefix: "921", RuleRange: "921000-921999", Tag: "attack-protocol", Phase: "inbound"},
			{ID: "multipart-attack", Name: "Multipart Attack", Description: "Multipart request attack patterns", Prefix: "922", RuleRange: "922000-922999", Tag: "attack-protocol", Phase: "inbound"},
			{ID: "lfi", Name: "Local File Inclusion", Description: "Path traversal and LFI attacks", Prefix: "930", RuleRange: "930000-930999", Tag: "attack-lfi", Phase: "inbound"},
			{ID: "rfi", Name: "Remote File Inclusion", Description: "Remote file inclusion attempts", Prefix: "931", RuleRange: "931000-931999", Tag: "attack-rfi", Phase: "inbound"},
			{ID: "rce", Name: "Remote Code Execution", Description: "Command injection and RCE", Prefix: "932", RuleRange: "932000-932999", Tag: "attack-rce", Phase: "inbound"},
			{ID: "php", Name: "PHP Injection", Description: "PHP code injection attacks", Prefix: "933", RuleRange: "933000-933999", Tag: "attack-injection-php", Phase: "inbound"},
			{ID: "generic-attack", Name: "Generic Attack", Description: "Generic application attack patterns", Prefix: "934", RuleRange: "934000-934999", Tag: "attack-generic", Phase: "inbound"},
			{ID: "xss", Name: "Cross-Site Scripting", Description: "XSS attack detection", Prefix: "941", RuleRange: "941000-941999", Tag: "attack-xss", Phase: "inbound"},
			{ID: "sqli", Name: "SQL Injection", Description: "SQL injection detection", Prefix: "942", RuleRange: "942000-942999", Tag: "attack-sqli", Phase: "inbound"},
			{ID: "session-fixation", Name: "Session Fixation", Description: "Session fixation attacks", Prefix: "943", RuleRange: "943000-943999", Tag: "attack-fixation", Phase: "inbound"},
			{ID: "java", Name: "Java Injection", Description: "Java/Spring code injection", Prefix: "944", RuleRange: "944000-944999", Tag: "attack-injection-java", Phase: "inbound"},
			{ID: "bot-detection", Name: "Bot Detection", Description: "Bot signal and heuristic rules", Prefix: "9100", RuleRange: "9100030-9100036", Tag: "bot-signal", Phase: "inbound"},
		},
		CategoryMap: map[string]string{
			"REQUEST-913-SCANNER-DETECTION":                   "scanner-detection",
			"REQUEST-920-PROTOCOL-ENFORCEMENT":                "protocol-enforcement",
			"REQUEST-921-PROTOCOL-ATTACK":                     "protocol-attack",
			"REQUEST-922-MULTIPART-ATTACK":                    "multipart-attack",
			"REQUEST-930-APPLICATION-ATTACK-LFI":              "lfi",
			"REQUEST-931-APPLICATION-ATTACK-RFI":              "rfi",
			"REQUEST-932-APPLICATION-ATTACK-RCE":              "rce",
			"REQUEST-933-APPLICATION-ATTACK-PHP":              "php",
			"REQUEST-934-APPLICATION-ATTACK-GENERIC":          "generic-attack",
			"REQUEST-941-APPLICATION-ATTACK-XSS":              "xss",
			"REQUEST-942-APPLICATION-ATTACK-SQLI":             "sqli",
			"REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION": "session-fixation",
			"REQUEST-944-APPLICATION-ATTACK-JAVA":             "java",
			"RESPONSE-950-DATA-LEAKAGES":                      "data-leakage",
			"RESPONSE-951-DATA-LEAKAGES-SQL":                  "data-leakage-sql",
			"RESPONSE-952-DATA-LEAKAGES-JAVA":                 "data-leakage-java",
			"RESPONSE-953-DATA-LEAKAGES-PHP":                  "data-leakage-php",
			"RESPONSE-954-DATA-LEAKAGES-IIS":                  "data-leakage-iis",
			"RESPONSE-955-WEB-SHELLS":                         "web-shells",
		},
		ValidPrefixes: []string{
			"913", "920", "921", "922", "930", "931", "932", "933", "934",
			"941", "942", "943", "944", "950", "951", "952", "953", "954", "955", "9100",
		},
		SeverityLevels: map[string]int{
			"CRITICAL": 2,
			"ERROR":    3,
			"WARNING":  4,
			"NOTICE":   5,
		},
		CustomRuleRange: "9100",
	}
	meta.buildIndexes()
	return meta
}
