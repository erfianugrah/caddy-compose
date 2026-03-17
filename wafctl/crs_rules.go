package main

import "log"

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

// ─── Category Taxonomy ──────────────────────────────────────────────
//
// Maps the converter's full category strings (e.g. "REQUEST-932-APPLICATION-ATTACK-RCE")
// to short, human-friendly IDs. The converter category comes from the CRS .conf filename.

// CRS 4.x rule categories
var crsCategories = []CRSCategory{
	{ID: "scanner-detection", Name: "Scanner Detection", Description: "Known security scanner detection", RuleRange: "913000-913999", Tag: "attack-reputation-scanner"},
	{ID: "protocol-enforcement", Name: "Protocol Enforcement", Description: "HTTP protocol violations and anomalies", RuleRange: "920000-920999", Tag: "attack-protocol"},
	{ID: "protocol-attack", Name: "Protocol Attack", Description: "HTTP request smuggling, response splitting", RuleRange: "921000-921999", Tag: "attack-protocol"},
	{ID: "multipart-attack", Name: "Multipart Attack", Description: "Multipart request attack patterns", RuleRange: "922000-922999", Tag: "attack-protocol"},
	{ID: "lfi", Name: "Local File Inclusion", Description: "Path traversal and LFI attacks", RuleRange: "930000-930999", Tag: "attack-lfi"},
	{ID: "rfi", Name: "Remote File Inclusion", Description: "Remote file inclusion attempts", RuleRange: "931000-931999", Tag: "attack-rfi"},
	{ID: "rce", Name: "Remote Code Execution", Description: "Command injection and RCE", RuleRange: "932000-932999", Tag: "attack-rce"},
	{ID: "php", Name: "PHP Injection", Description: "PHP code injection attacks", RuleRange: "933000-933999", Tag: "attack-injection-php"},
	{ID: "nodejs", Name: "Node.js Injection", Description: "Node.js code injection attacks", RuleRange: "934000-934999", Tag: "attack-injection-nodejs"},
	{ID: "xss", Name: "Cross-Site Scripting", Description: "XSS attack detection", RuleRange: "941000-941999", Tag: "attack-xss"},
	{ID: "sqli", Name: "SQL Injection", Description: "SQL injection detection", RuleRange: "942000-942999", Tag: "attack-sqli"},
	{ID: "session-fixation", Name: "Session Fixation", Description: "Session fixation attacks", RuleRange: "943000-943999", Tag: "attack-fixation"},
	{ID: "java", Name: "Java Injection", Description: "Java/Spring code injection", RuleRange: "944000-944999", Tag: "attack-injection-java"},
	{ID: "bot-detection", Name: "Bot Detection", Description: "Bot signal and heuristic rules", RuleRange: "9100030-9100036", Tag: "bot-signal"},
}

// categoryFromCRSFile maps a converter category string (derived from .conf filename)
// to a short category ID. Returns the input unchanged if no mapping is found.
var categoryFromCRSFile = map[string]string{
	"REQUEST-913-SCANNER-DETECTION":                   "scanner-detection",
	"REQUEST-920-PROTOCOL-ENFORCEMENT":                "protocol-enforcement",
	"REQUEST-921-PROTOCOL-ATTACK":                     "protocol-attack",
	"REQUEST-922-MULTIPART-ATTACK":                    "multipart-attack",
	"REQUEST-930-APPLICATION-ATTACK-LFI":              "lfi",
	"REQUEST-931-APPLICATION-ATTACK-RFI":              "rfi",
	"REQUEST-932-APPLICATION-ATTACK-RCE":              "rce",
	"REQUEST-933-APPLICATION-ATTACK-PHP":              "php",
	"REQUEST-934-APPLICATION-ATTACK-GENERIC":          "nodejs",
	"REQUEST-941-APPLICATION-ATTACK-XSS":              "xss",
	"REQUEST-942-APPLICATION-ATTACK-SQLI":             "sqli",
	"REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION": "session-fixation",
	"REQUEST-944-APPLICATION-ATTACK-JAVA":             "java",
}

// normalizeCRSCategory maps a converter's full category string to a short ID.
func normalizeCRSCategory(category string) string {
	if short, ok := categoryFromCRSFile[category]; ok {
		return short
	}
	return category
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
	// Deep copy categories.
	cats := make([]CRSCategory, len(crsCategories))
	copy(cats, crsCategories)

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
// server startup by SetCRSCatalog. Tests that don't call SetCRSCatalog
// get a nil-store catalog that falls back to customRulesFallback.
var defaultCRSCatalog = &CRSCatalog{}

// SetCRSCatalog sets the package-level CRS catalog used by LookupCRSRule.
// Called once during server startup after DefaultRuleStore is initialized.
func SetCRSCatalog(c *CRSCatalog) {
	defaultCRSCatalog = c
}

// LookupCRSRule returns the CRS or custom rule for the given ID, or ok=false.
// Uses the package-level catalog (set by SetCRSCatalog at startup).
func LookupCRSRule(id string) (CRSRule, bool) {
	return defaultCRSCatalog.Lookup(id)
}

// GetCRSCatalog returns the full catalog. Uses the package-level catalog.
func GetCRSCatalog() CRSCatalogResponse {
	return defaultCRSCatalog.GetCatalog()
}
