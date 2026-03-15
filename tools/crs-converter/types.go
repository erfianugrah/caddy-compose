package main

// ─── SecRule AST Types ─────────────────────────────────────────────

// SecRule represents a parsed ModSecurity SecRule directive.
type SecRule struct {
	Variables []Variable
	Operator  Operator
	Actions   []Action
	Chain     *SecRule // Next rule in chain (nil if unchained)

	// Metadata extracted from actions for convenience
	ID            string
	Phase         int
	Msg           string
	Severity      string
	Tags          []string
	Transforms    []string
	ParanoiaLevel int

	// Source location
	File string
	Line int
}

// Variable represents a single variable in a SecRule.
// e.g., ARGS, REQUEST_HEADERS:User-Agent, !REQUEST_COOKIES:/__utm/
type Variable struct {
	Name       string // ARGS, REQUEST_HEADERS, etc.
	Key        string // :User-Agent, :/__utm/, etc. (without leading colon)
	KeyIsRegex bool   // true if Key is a /regex/ pattern
	IsCount    bool   // & prefix
	IsNegation bool   // ! prefix (exclusion from variable list)
}

// Operator represents a SecRule operator.
// e.g., @rx pattern, @pm word1 word2, @pmFromFile filename.data
type Operator struct {
	Name    string // rx, pm, pmFromFile, detectSQLi, etc. (without @)
	Value   string // Pattern, filename, space-separated words, etc.
	Negated bool   // !@ prefix
}

// Action represents a single SecRule action key=value pair.
type Action struct {
	Key   string // id, phase, msg, tag, severity, setvar, t, etc.
	Value string // The value (may be empty for flag actions like "block", "pass")
}

// ─── Policy Engine Output Types ────────────────────────────────────
// These mirror the caddy-policy-engine plugin's data model.

// PolicyRulesFile is the top-level JSON output.
type PolicyRulesFile struct {
	DefaultRules []PolicyRule `json:"default_rules"`
	Version      int          `json:"version"`
	CRSVersion   string       `json:"crs_version"`
	Generated    string       `json:"generated"`
}

// PolicyRule is a single detect rule for the policy engine.
type PolicyRule struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Type          string            `json:"type"`            // always "detect" for CRS rules
	Phase         string            `json:"phase,omitempty"` // "inbound" (default) or "outbound" for response-phase rules
	Conditions    []PolicyCondition `json:"conditions"`
	GroupOp       string            `json:"group_op"` // "and" or "or"
	Severity      string            `json:"severity,omitempty"`
	ParanoiaLevel int               `json:"paranoia_level,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	Enabled       bool              `json:"enabled"`
	Priority      int               `json:"priority"`
	Description   string            `json:"description,omitempty"`
	// CRS metadata
	Category string `json:"category,omitempty"` // e.g., "REQUEST-932-APPLICATION-ATTACK-RCE"
	CRSFile  string `json:"crs_file,omitempty"` // source .conf filename
}

// PolicyCondition is a single condition within a detect rule.
type PolicyCondition struct {
	Field      string   `json:"field"`
	Operator   string   `json:"operator"`
	Value      string   `json:"value,omitempty"`
	Negate     bool     `json:"negate,omitempty"`
	MultiMatch bool     `json:"multi_match,omitempty"`
	Transforms []string `json:"transforms,omitempty"`
	ListItems  []string `json:"list_items,omitempty"`
	Excludes   []string `json:"excludes,omitempty"` // variable patterns to skip (e.g., "cookie:__utm")
}

// ─── Conversion Report Types ───────────────────────────────────────

// Report tracks conversion statistics and gaps.
type Report struct {
	CRSVersion string

	TotalRules     int
	ConvertedRules int
	SkippedRules   int

	// Breakdown of skipped rules
	SkippedFlowControl    []SkippedRule // paranoia gating, SecMarker, SecAction
	SkippedResponsePhase  []SkippedRule // phase 3/4
	SkippedUnsupportedOp  []SkippedRule // unsupported operator
	SkippedUnsupportedVar []SkippedRule // unsupported variable
	SkippedPCRERegex      []SkippedRule // PCRE-only regex features
	SkippedOther          []SkippedRule // other reasons

	// Missing features encountered
	MissingTransforms map[string]int // transform name → count
	MissingOperators  map[string]int // operator name → count
	MissingVariables  map[string]int // variable name → count

	// Per-category stats
	CategoryStats map[string]CategoryStat
}

// SkippedRule records a rule that was skipped and why.
type SkippedRule struct {
	ID     string
	Reason string
	File   string
}

// CategoryStat tracks per-category conversion stats.
type CategoryStat struct {
	Total     int
	Converted int
	Skipped   int
}

func NewReport() *Report {
	return &Report{
		MissingTransforms: make(map[string]int),
		MissingOperators:  make(map[string]int),
		MissingVariables:  make(map[string]int),
		CategoryStats:     make(map[string]CategoryStat),
	}
}
