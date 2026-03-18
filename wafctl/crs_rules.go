package main

import (
	"log"
	"sync/atomic"
)

// ─── CRS Catalog Types ─────────────────────────────────────────────
//
// The CRS catalog is derived dynamically from the DefaultRuleStore at
// runtime. The store loads default-rules.json (built by crs-converter
// at Docker build time), which contains description, category, and
// crs_file metadata for every converted CRS rule.
//
// Static data here is limited to:
//   - crsCategories: the human-friendly category taxonomy
//   - customRules: hand-written rules not in default-rules.json
//
// The old approach hardcoded ~170 CRS rules as Go literals, which
// drifted from the actual default-rules.json on every CRS version bump.

// CRSRule represents a CRS rule entry for the UI catalog.
type CRSRule struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags"`
	Severity    string   `json:"severity,omitempty"`
	ParanoiaLvl int      `json:"paranoia_level,omitempty"`
}

// CRSCategory groups rules by their functional area.
type CRSCategory struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	RuleRange   string `json:"rule_range"`
	Tag         string `json:"tag"` // CRS tag used for ctl:ruleRemoveByTag
}

// CRSCatalogResponse is the API response for /api/crs/rules.
type CRSCatalogResponse struct {
	Categories []CRSCategory `json:"categories"`
	Rules      []CRSRule     `json:"rules"`
	Total      int           `json:"total"`
}

// ─── Category Taxonomy (loaded from CRS metadata) ──────────────────
//
// All category data is now loaded from crs-metadata.json at startup
// via the CRSMetadata system (crs_metadata.go). The converter generates
// this file at Docker build time from actual CRS .conf filenames.
// No hardcoded category maps here — see fallbackMetadata() for the
// compile-time fallback used when the metadata file is not available.

// crsMetadataCategories returns the current CRS categories from loaded metadata.
// Used by GetCatalog() and the /api/crs/rules endpoint.
func crsMetadataCategories() []CRSCategory {
	meta := GetCRSMetadata()
	cats := make([]CRSCategory, len(meta.Categories))
	for i, mc := range meta.Categories {
		cats[i] = CRSCategory{
			ID:          mc.ID,
			Name:        mc.Name,
			Description: mc.Description,
			RuleRange:   mc.RuleRange,
			Tag:         mc.Tag,
		}
	}
	return cats
}

// normalizeCRSCategory maps a converter's full category string to a short ID.
// Uses the loaded CRS metadata (from crs-metadata.json) as the source of truth.
func normalizeCRSCategory(category string) string {
	return GetCRSMetadata().NormalizeCategory(category)
}

// ─── Custom Rules (not in default-rules.json) ──────────────────────
//
// Hand-written heuristic rules that aren't part of the OWASP CRS.
// These are defined in waf/custom-rules.json and merged by the converter,
// so they WILL be in default-rules.json. But we keep this static list as
// a fallback for enrichment when default-rules.json hasn't loaded yet.

var customRulesFallback = []CRSRule{
	// Pre-CRS baked rules
	{ID: "9100003", Description: "XXE: DOCTYPE/ENTITY with SYSTEM or PUBLIC", Category: "protocol-attack", Tags: []string{"attack-xxe"}, Severity: "CRITICAL"},
	{ID: "9100006", Description: "XXE: Parameter entity declaration", Category: "protocol-attack", Tags: []string{"attack-xxe"}, Severity: "CRITICAL"},
	{ID: "9100012", Description: "CRLF injection in query string", Category: "protocol-enforcement", Tags: []string{"attack-protocol"}, Severity: "CRITICAL"},
	{ID: "9100013", Description: "CRLF injection in request headers", Category: "protocol-enforcement", Tags: []string{"attack-protocol"}, Severity: "CRITICAL"},
	// Bot signal / heuristic rules
	{ID: "9100030", Description: "Empty User-Agent header", Category: "bot-detection", Tags: []string{"bot-signal", "heuristic"}, Severity: "NOTICE"},
	{ID: "9100031", Description: "Connection header set to close", Category: "bot-detection", Tags: []string{"bot-signal", "heuristic"}, Severity: "NOTICE"},
	{ID: "9100032", Description: "Known scanner User-Agent detected", Category: "bot-detection", Tags: []string{"bot-signal", "scanner"}, Severity: "CRITICAL"},
	{ID: "9100033", Description: "Empty Accept header", Category: "bot-detection", Tags: []string{"bot-signal", "heuristic"}, Severity: "WARNING"},
	{ID: "9100034", Description: "Missing common browser headers", Category: "bot-detection", Tags: []string{"bot-signal", "generic-ua"}, Severity: "NOTICE"},
	{ID: "9100035", Description: "Generic or non-browser User-Agent", Category: "bot-detection", Tags: []string{"bot-signal", "generic-ua"}, Severity: "CRITICAL"},
	{ID: "9100036", Description: "HTTP/1.0 protocol anomaly", Category: "protocol-enforcement", Tags: []string{"bot-signal", "protocol"}, Severity: "WARNING"},
}

// customRuleFallbackIndex is a map from rule ID to CRSRule for the static
// fallback custom rules. Used when a rule isn't found in DefaultRuleStore.
var customRuleFallbackIndex map[string]CRSRule

func init() {
	customRuleFallbackIndex = make(map[string]CRSRule, len(customRulesFallback))
	for _, r := range customRulesFallback {
		if _, exists := customRuleFallbackIndex[r.ID]; exists {
			log.Fatalf("duplicate custom rule ID %q", r.ID)
		}
		customRuleFallbackIndex[r.ID] = r
	}
}

// ─── CRS Catalog (dynamic, derived from DefaultRuleStore) ──────────

// CRSCatalog provides CRS rule lookup and catalog generation from the
// DefaultRuleStore. All CRS metadata (description, category, tags, severity,
// paranoia level) flows from default-rules.json through the store.
type CRSCatalog struct {
	ds *DefaultRuleStore
}

// NewCRSCatalog creates a CRS catalog backed by the given DefaultRuleStore.
func NewCRSCatalog(ds *DefaultRuleStore) *CRSCatalog {
	return &CRSCatalog{ds: ds}
}

// policyRuleToCRSRule converts a PolicyRule (from DefaultRuleStore) to a CRSRule
// for the UI catalog. The converter's category field is normalized to a short ID.
func policyRuleToCRSRule(pr PolicyRule) CRSRule {
	tags := make([]string, len(pr.Tags))
	copy(tags, pr.Tags)

	return CRSRule{
		ID:          pr.ID,
		Description: pr.Description,
		Category:    normalizeCRSCategory(pr.Category),
		Tags:        tags,
		Severity:    pr.Severity,
		ParanoiaLvl: pr.ParanoiaLevel,
	}
}

// Lookup returns the CRS rule metadata for the given ID, or ok=false.
// Checks DefaultRuleStore first (all CRS + custom rules from default-rules.json),
// then falls back to the static customRulesFallback for rules that may not
// be in default-rules.json (e.g., during tests with no loaded defaults).
func (c *CRSCatalog) Lookup(id string) (CRSRule, bool) {
	if c.ds != nil {
		c.ds.mu.RLock()
		if pr, ok := c.ds.defaultsByID[id]; ok {
			c.ds.mu.RUnlock()
			return policyRuleToCRSRule(pr), true
		}
		c.ds.mu.RUnlock()
	}
	// Fallback to static custom rules (for tests or when store is empty).
	r, ok := customRuleFallbackIndex[id]
	return r, ok
}

// GetCatalog returns the full CRS rule catalog for the UI.
// Builds the catalog dynamically from DefaultRuleStore.defaults —
// every rule in default-rules.json is included, plus any static custom
// rules not already present in the store.
func (c *CRSCatalog) GetCatalog() CRSCatalogResponse {
	// Get categories from loaded CRS metadata (dynamic, not hardcoded).
	cats := crsMetadataCategories()

	var rules []CRSRule
	seen := make(map[string]bool)

	// Primary source: DefaultRuleStore (all rules from default-rules.json).
	if c.ds != nil {
		c.ds.mu.RLock()
		rules = make([]CRSRule, 0, len(c.ds.defaults))
		for _, pr := range c.ds.defaults {
			rules = append(rules, policyRuleToCRSRule(pr))
			seen[pr.ID] = true
		}
		c.ds.mu.RUnlock()
	}

	// Fallback: add any static custom rules not already in the store.
	for _, cr := range customRulesFallback {
		if !seen[cr.ID] {
			tags := make([]string, len(cr.Tags))
			copy(tags, cr.Tags)
			cr.Tags = tags
			rules = append(rules, cr)
		}
	}

	return CRSCatalogResponse{
		Categories: cats,
		Rules:      rules,
		Total:      len(rules),
	}
}

// ─── Package-level convenience (backward compat for tests) ──────────

// defaultCRSCatalog is the package-level catalog instance, set during
// server startup by SetCRSCatalog. Uses atomic.Pointer for thread-safe
// access without a mutex. Tests that don't call SetCRSCatalog get a
// nil-store catalog that falls back to customRulesFallback.
var defaultCRSCatalog atomic.Pointer[CRSCatalog]

func init() {
	defaultCRSCatalog.Store(&CRSCatalog{})
}

// SetCRSCatalog sets the package-level CRS catalog used by LookupCRSRule.
// Called once during server startup after DefaultRuleStore is initialized.
func SetCRSCatalog(c *CRSCatalog) {
	defaultCRSCatalog.Store(c)
}

// LookupCRSRule returns the CRS or custom rule for the given ID, or ok=false.
// Uses the package-level catalog (set by SetCRSCatalog at startup).
func LookupCRSRule(id string) (CRSRule, bool) {
	return defaultCRSCatalog.Load().Lookup(id)
}

// GetCRSCatalog returns the full catalog. Uses the package-level catalog.
func GetCRSCatalog() CRSCatalogResponse {
	return defaultCRSCatalog.Load().GetCatalog()
}
