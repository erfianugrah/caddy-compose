package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ─── CRS Metadata Generator ───────────────────────────────────────
//
// Builds crs-metadata.json from the converted rules. All category
// taxonomy is derived from the actual .conf filenames and rule data,
// so adding a new CRS category requires zero manual updates.

// categoryDefs maps the full CRS filename-derived category string to
// human-friendly metadata. The ID, name, description, and tag are
// derived from the filename pattern.
//
// This table is populated from observed categories in the converted rules.
// New categories appearing in future CRS versions are auto-discovered
// and assigned reasonable defaults.
var categoryNameMap = map[string]struct {
	ID          string
	Name        string
	Description string
	Tag         string
}{
	"REQUEST-913-SCANNER-DETECTION":                   {"scanner-detection", "Scanner Detection", "Known security scanner detection", "attack-reputation-scanner"},
	"REQUEST-920-PROTOCOL-ENFORCEMENT":                {"protocol-enforcement", "Protocol Enforcement", "HTTP protocol violations and anomalies", "attack-protocol"},
	"REQUEST-921-PROTOCOL-ATTACK":                     {"protocol-attack", "Protocol Attack", "HTTP request smuggling, response splitting", "attack-protocol"},
	"REQUEST-922-MULTIPART-ATTACK":                    {"multipart-attack", "Multipart Attack", "Multipart request attack patterns", "attack-protocol"},
	"REQUEST-930-APPLICATION-ATTACK-LFI":              {"lfi", "Local File Inclusion", "Path traversal and LFI attacks", "attack-lfi"},
	"REQUEST-931-APPLICATION-ATTACK-RFI":              {"rfi", "Remote File Inclusion", "Remote file inclusion attempts", "attack-rfi"},
	"REQUEST-932-APPLICATION-ATTACK-RCE":              {"rce", "Remote Code Execution", "Command injection and RCE", "attack-rce"},
	"REQUEST-933-APPLICATION-ATTACK-PHP":              {"php", "PHP Injection", "PHP code injection attacks", "attack-injection-php"},
	"REQUEST-934-APPLICATION-ATTACK-GENERIC":          {"generic-attack", "Generic Attack", "Generic application attack patterns", "attack-generic"},
	"REQUEST-941-APPLICATION-ATTACK-XSS":              {"xss", "Cross-Site Scripting", "XSS attack detection", "attack-xss"},
	"REQUEST-942-APPLICATION-ATTACK-SQLI":             {"sqli", "SQL Injection", "SQL injection detection", "attack-sqli"},
	"REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION": {"session-fixation", "Session Fixation", "Session fixation attacks", "attack-fixation"},
	"REQUEST-944-APPLICATION-ATTACK-JAVA":             {"java", "Java Injection", "Java/Spring code injection", "attack-injection-java"},
	// Response-phase categories
	"RESPONSE-950-DATA-LEAKAGES":      {"data-leakage", "Data Leakages", "Outbound data leakage detection", "leakage"},
	"RESPONSE-951-DATA-LEAKAGES-SQL":  {"data-leakage-sql", "SQL Data Leakages", "SQL error message leakage", "leakage-sql"},
	"RESPONSE-952-DATA-LEAKAGES-JAVA": {"data-leakage-java", "Java Data Leakages", "Java exception leakage", "leakage-java"},
	"RESPONSE-953-DATA-LEAKAGES-PHP":  {"data-leakage-php", "PHP Data Leakages", "PHP error message leakage", "leakage-php"},
	"RESPONSE-954-DATA-LEAKAGES-IIS":  {"data-leakage-iis", "IIS Data Leakages", "IIS error message leakage", "leakage-iis"},
	"RESPONSE-955-WEB-SHELLS":         {"web-shells", "Web Shells", "Web shell detection in responses", "leakage-webshell"},
	"RESPONSE-956-DATA-LEAKAGES-RUBY": {"data-leakages-ruby", "Ruby Data Leakages", "Ruby error message leakage", "leakage-ruby"},
}

// ruleIDPrefixRe extracts the 3-4 digit prefix from a CRS category string.
// e.g., "REQUEST-920-PROTOCOL-ENFORCEMENT" → "920"
var ruleIDPrefixRe = regexp.MustCompile(`^(?:REQUEST|RESPONSE)-(\d{3,4})-`)

// BuildMetadata generates CRSMetadata from the list of converted rules and
// the CRS version string. Categories are derived from observed rule data.
func BuildMetadata(rules []PolicyRule, crsVersion string) CRSMetadata {
	// Count rules per category
	catCounts := make(map[string]int)
	seenPrefixes := make(map[string]bool)
	for _, r := range rules {
		if r.Category != "" {
			catCounts[r.Category]++
		}
		// Extract 3-digit prefix from rule ID
		if len(r.ID) >= 3 {
			prefix := r.ID[:3]
			// For 4-digit prefixes (custom rules 9100xxx), use first 4 digits
			if len(r.ID) >= 4 && r.ID[0] == '9' && r.ID[1] == '1' && r.ID[2] == '0' && r.ID[3] == '0' {
				prefix = r.ID[:4]
			}
			seenPrefixes[prefix] = true
		}
	}

	// Build category list and category map
	var categories []CRSMetadataCategory
	categoryMap := make(map[string]string)

	// Process all observed categories
	seen := make(map[string]bool)
	for cat, count := range catCounts {
		if seen[cat] {
			continue
		}
		seen[cat] = true

		info, known := categoryNameMap[cat]
		if !known {
			// Auto-generate metadata for unknown categories
			info = autoCategory(cat)
		}

		// Determine phase from category prefix
		phase := "inbound"
		if strings.HasPrefix(cat, "RESPONSE-") {
			phase = "outbound"
		}

		// Extract prefix for rule_range
		prefix := ""
		if m := ruleIDPrefixRe.FindStringSubmatch(cat); len(m) > 1 {
			prefix = m[1]
		}

		ruleRange := ""
		if prefix != "" {
			ruleRange = fmt.Sprintf("%s000-%s999", prefix, prefix)
		}

		categories = append(categories, CRSMetadataCategory{
			ID:          info.ID,
			Name:        info.Name,
			Description: info.Description,
			Prefix:      prefix,
			RuleRange:   ruleRange,
			Tag:         info.Tag,
			Phase:       phase,
			RuleCount:   count,
		})

		categoryMap[cat] = info.ID
	}

	// Sort categories by prefix for stable output
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Prefix < categories[j].Prefix
	})

	// Build sorted valid prefixes list
	var prefixes []string
	for p := range seenPrefixes {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	return CRSMetadata{
		CRSVersion:    crsVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Categories:    categories,
		CategoryMap:   categoryMap,
		ValidPrefixes: prefixes,
		SeverityLevels: map[string]int{
			"CRITICAL": 2,
			"ERROR":    3,
			"WARNING":  4,
			"NOTICE":   5,
		},
		CustomRuleRange: "9100",
	}
}

// autoCategory generates reasonable metadata for an unknown CRS category.
// This handles future CRS categories that aren't in categoryNameMap.
func autoCategory(cat string) struct {
	ID          string
	Name        string
	Description string
	Tag         string
} {
	// Strip REQUEST- or RESPONSE- prefix and number
	short := cat
	short = strings.TrimPrefix(short, "REQUEST-")
	short = strings.TrimPrefix(short, "RESPONSE-")
	// Remove the NNN- prefix (e.g., "920-PROTOCOL-ENFORCEMENT" → "PROTOCOL-ENFORCEMENT")
	if idx := strings.Index(short, "-"); idx >= 0 {
		short = short[idx+1:]
	}

	id := strings.ToLower(short)
	name := titleCase(strings.ToLower(strings.ReplaceAll(short, "-", " ")))

	return struct {
		ID          string
		Name        string
		Description string
		Tag         string
	}{
		ID:          id,
		Name:        name,
		Description: cat,
		Tag:         strings.ToLower(short),
	}
}

// titleCase capitalizes the first letter of each word.
// Replacement for deprecated strings.Title (Go 1.18+).
func titleCase(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
