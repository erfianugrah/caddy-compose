package main

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
}

// CRSCatalogResponse is the API response for /api/crs/rules.
type CRSCatalogResponse struct {
	Categories []CRSCategory `json:"categories"`
	Rules      []CRSRule     `json:"rules"`
	Total      int           `json:"total"`
}

// CRS 4.x rule categories
var crsCategories = []CRSCategory{
	{ID: "protocol-enforcement", Name: "Protocol Enforcement", Description: "HTTP protocol violations and anomalies", RuleRange: "920000-920999"},
	{ID: "protocol-attack", Name: "Protocol Attack", Description: "HTTP request smuggling, response splitting", RuleRange: "921000-921999"},
	{ID: "lfi", Name: "Local File Inclusion", Description: "Path traversal and LFI attacks", RuleRange: "930000-930999"},
	{ID: "rfi", Name: "Remote File Inclusion", Description: "Remote file inclusion attempts", RuleRange: "931000-931999"},
	{ID: "rce", Name: "Remote Code Execution", Description: "Command injection and RCE", RuleRange: "932000-932999"},
	{ID: "php", Name: "PHP Injection", Description: "PHP code injection attacks", RuleRange: "933000-933999"},
	{ID: "nodejs", Name: "Node.js Injection", Description: "Node.js code injection attacks", RuleRange: "934000-934999"},
	{ID: "xss", Name: "Cross-Site Scripting", Description: "XSS attack detection", RuleRange: "941000-941999"},
	{ID: "sqli", Name: "SQL Injection", Description: "SQL injection detection", RuleRange: "942000-942999"},
	{ID: "session-fixation", Name: "Session Fixation", Description: "Session fixation attacks", RuleRange: "943000-943999"},
	{ID: "java", Name: "Java Injection", Description: "Java/Spring code injection", RuleRange: "944000-944999"},
}

// Commonly encountered CRS rules — the most frequently triggered rules that
// users are likely to need in exclusions. This is a curated subset; the full
// CRS has ~200+ rules.
var crsRules = []CRSRule{
	// 920xxx — Protocol Enforcement
	{ID: "920100", Description: "Invalid HTTP request line", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920120", Description: "Attempted multipart/form-data bypass", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920160", Description: "Content-Length HTTP header is not numeric", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920170", Description: "GET or HEAD request with body content", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920180", Description: "POST request missing Content-Type header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920210", Description: "Multiple/conflicting Connection header data", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920220", Description: "URL encoding abuse attack attempt", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920230", Description: "Multiple URL encoding detected", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920240", Description: "URL encoding abuse attack attempt", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920260", Description: "Unicode full/half width abuse attack attempt", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920270", Description: "Invalid character in request (null character)", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920271", Description: "Invalid character in request (non printable)", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920272", Description: "Invalid character in request (outside of printable chars, below ascii 127)", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920273", Description: "Invalid character in request (outside of very strict set)", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 3},
	{ID: "920274", Description: "Invalid character in request headers (outside of very strict set)", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 4},
	{ID: "920280", Description: "Request missing a Host header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920290", Description: "Empty Host header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920300", Description: "Request missing an Accept header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "NOTICE", ParanoiaLvl: 2},
	{ID: "920310", Description: "Request has an empty Accept header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "NOTICE", ParanoiaLvl: 2},
	{ID: "920311", Description: "Request has an empty Accept header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "NOTICE", ParanoiaLvl: 2},
	{ID: "920320", Description: "Missing User-Agent header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "NOTICE", ParanoiaLvl: 2},
	{ID: "920330", Description: "Empty User-Agent header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "NOTICE", ParanoiaLvl: 2},
	{ID: "920340", Description: "Request containing Content but missing Content-Type header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "NOTICE", ParanoiaLvl: 1},
	{ID: "920341", Description: "Request containing Content requires Content-Type header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "NOTICE", ParanoiaLvl: 1},
	{ID: "920350", Description: "Host header is a numeric IP address", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "WARNING", ParanoiaLvl: 1},
	{ID: "920420", Description: "Request content type is not allowed by policy", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920430", Description: "HTTP protocol version is not allowed by policy", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920440", Description: "URL file extension is restricted by policy", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920450", Description: "HTTP header is restricted by policy", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920460", Description: "Abnormal escape characters", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920470", Description: "Illegal Content-Type header", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "920480", Description: "Request content type charset is not allowed by policy", Category: "protocol-enforcement", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},

	// 921xxx — Protocol Attack
	{ID: "921100", Description: "HTTP request smuggling attack", Category: "protocol-attack", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "921110", Description: "HTTP request smuggling attack", Category: "protocol-attack", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "921120", Description: "HTTP response splitting attack", Category: "protocol-attack", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "921130", Description: "HTTP response splitting attack", Category: "protocol-attack", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "921140", Description: "HTTP header injection attack via headers", Category: "protocol-attack", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "921150", Description: "HTTP header injection attack via payload (CR/LF detected)", Category: "protocol-attack", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "921151", Description: "HTTP header injection attack via payload (CR/LF detected)", Category: "protocol-attack", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "921160", Description: "HTTP header injection attack via payload (CR/LF and header-name detected)", Category: "protocol-attack", Tags: []string{"OWASP_CRS", "attack-protocol"}, Severity: "CRITICAL", ParanoiaLvl: 1},

	// 930xxx — Local File Inclusion
	{ID: "930100", Description: "Path traversal attack (/../)", Category: "lfi", Tags: []string{"OWASP_CRS", "attack-lfi"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "930110", Description: "Path traversal attack (/../)", Category: "lfi", Tags: []string{"OWASP_CRS", "attack-lfi"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "930120", Description: "OS file access attempt", Category: "lfi", Tags: []string{"OWASP_CRS", "attack-lfi"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "930130", Description: "Restricted file access attempt", Category: "lfi", Tags: []string{"OWASP_CRS", "attack-lfi"}, Severity: "CRITICAL", ParanoiaLvl: 1},

	// 931xxx — Remote File Inclusion
	{ID: "931100", Description: "Possible RFI attack: URL parameter using IP address", Category: "rfi", Tags: []string{"OWASP_CRS", "attack-rfi"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "931110", Description: "Possible RFI attack: common RFI vulnerable parameter name used w/URL payload", Category: "rfi", Tags: []string{"OWASP_CRS", "attack-rfi"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "931120", Description: "Possible RFI attack: URL payload used w/trailing question mark character (?)", Category: "rfi", Tags: []string{"OWASP_CRS", "attack-rfi"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "931130", Description: "Possible RFI attack: off-domain reference/link", Category: "rfi", Tags: []string{"OWASP_CRS", "attack-rfi"}, Severity: "CRITICAL", ParanoiaLvl: 2},

	// 932xxx — Remote Code Execution
	{ID: "932100", Description: "Remote command execution: Unix command injection", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932105", Description: "Remote command execution: Unix command injection", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932106", Description: "Remote command execution: Unix command injection", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932110", Description: "Remote command execution: Windows command injection", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932115", Description: "Remote command execution: Windows command injection", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932120", Description: "Remote command execution: Windows PowerShell command found", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932130", Description: "Remote command execution: Unix shell expression found", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932140", Description: "Remote command execution: Windows FOR/IF command found", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932150", Description: "Remote command execution: direct Unix command execution", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932160", Description: "Remote command execution: Unix shell code found", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932170", Description: "Remote command execution: Shellshock (CVE-2014-6271)", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932171", Description: "Remote command execution: Shellshock (CVE-2014-6271)", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "932180", Description: "Restricted file upload attempt", Category: "rce", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},

	// 933xxx — PHP Injection
	{ID: "933100", Description: "PHP injection attack: opening/closing tag found", Category: "php", Tags: []string{"OWASP_CRS", "attack-injection-php"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "933110", Description: "PHP injection attack: PHP script file upload found", Category: "php", Tags: []string{"OWASP_CRS", "attack-injection-php"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "933120", Description: "PHP injection attack: configuration directive found", Category: "php", Tags: []string{"OWASP_CRS", "attack-injection-php"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "933130", Description: "PHP injection attack: variables found", Category: "php", Tags: []string{"OWASP_CRS", "attack-injection-php"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "933140", Description: "PHP injection attack: I/O stream found", Category: "php", Tags: []string{"OWASP_CRS", "attack-injection-php"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "933150", Description: "PHP injection attack: high-risk PHP function name found", Category: "php", Tags: []string{"OWASP_CRS", "attack-injection-php"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "933160", Description: "PHP injection attack: high-risk PHP function call found", Category: "php", Tags: []string{"OWASP_CRS", "attack-injection-php"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "933170", Description: "PHP injection attack: serialized object injection", Category: "php", Tags: []string{"OWASP_CRS", "attack-injection-php"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "933180", Description: "PHP injection attack: variable function call found", Category: "php", Tags: []string{"OWASP_CRS", "attack-injection-php"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "933210", Description: "PHP injection attack: variable function call found", Category: "php", Tags: []string{"OWASP_CRS", "attack-injection-php"}, Severity: "CRITICAL", ParanoiaLvl: 2},

	// 934xxx — Node.js Injection
	{ID: "934100", Description: "Node.js injection attack", Category: "nodejs", Tags: []string{"OWASP_CRS", "attack-injection-nodejs"}, Severity: "CRITICAL", ParanoiaLvl: 1},

	// 941xxx — XSS
	{ID: "941100", Description: "XSS attack detected via libinjection", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941110", Description: "XSS filter — Category 1: Script tag vector", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941120", Description: "XSS filter — Category 2: Event handler vector", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941130", Description: "XSS filter — Category 3: Attribute vector", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941140", Description: "XSS filter — Category 4: JavaScript URI vector", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941150", Description: "XSS filter — Category 5: Disallowed HTML attributes", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941160", Description: "NoScript XSS InjectionChecker: HTML injection", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941170", Description: "NoScript XSS InjectionChecker: Attribute injection", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941180", Description: "Node-Validator denylist keywords", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941190", Description: "XSS using style sheets", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941200", Description: "XSS using VML frames", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941210", Description: "XSS using obfuscated JavaScript", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941220", Description: "XSS using obfuscated VB Script", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941230", Description: "XSS using embed tag", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941240", Description: "XSS using import or implementation attribute", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941250", Description: "IE XSS filters — attack detected", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941260", Description: "XSS using meta tag", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941270", Description: "XSS using link href", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941280", Description: "XSS using base tag", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941290", Description: "XSS using applet tag", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941300", Description: "XSS using object tag", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941310", Description: "US-ASCII malformed encoding XSS filter — attack detected", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941320", Description: "Possible XSS attack detected — HTML tag handler", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941330", Description: "IE XSS filters — attack detected", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941340", Description: "IE XSS filters — attack detected", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "941350", Description: "UTF-7 encoding IE XSS — attack detected", Category: "xss", Tags: []string{"OWASP_CRS", "attack-xss"}, Severity: "CRITICAL", ParanoiaLvl: 1},

	// 942xxx — SQL Injection
	{ID: "942100", Description: "SQL injection attack detected via libinjection", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942110", Description: "SQL injection attack: common injection testing detected", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942120", Description: "SQL injection attack: SQL operator detected", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942130", Description: "SQL injection attack: SQL tautology detected", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942140", Description: "SQL injection attack: common DB names detected", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942150", Description: "SQL injection attack", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942160", Description: "Detects blind sqli tests using sleep() or benchmark()", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942170", Description: "Detects SQL benchmark and sleep injection attempts including conditional queries", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942180", Description: "Detects basic SQL authentication bypass attempts 1/3", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942190", Description: "Detects MSSQL code execution and information gathering attempts", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942200", Description: "Detects MySQL comment-/space-obfuscated injections and backtick termination", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942210", Description: "Detects chained SQL injection attempts 1/2", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942220", Description: "Looking for integer overflow attacks, these are taken from skipfish", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942230", Description: "Detects conditional SQL injection attempts", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942240", Description: "Detects MySQL charset switch and MSSQL DoS attempts", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942250", Description: "Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942251", Description: "Detects HAVING injections", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942260", Description: "Detects basic SQL authentication bypass attempts 2/3", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942270", Description: "Looking for basic sql injection. Common attack string for mysql, oracle and others", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942280", Description: "Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942290", Description: "Finds basic MongoDB SQL injection attempts", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942300", Description: "Detects MySQL comments, conditions and ch(a)r injections", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942310", Description: "Detects chained SQL injection attempts 2/2", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942320", Description: "Detects MySQL and PostgreSQL stored procedure/function injections", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942330", Description: "Detects classic SQL injection probings 1/3", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942340", Description: "Detects basic SQL authentication bypass attempts 3/3", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942350", Description: "Detects MySQL UDF injection and other data/structure manipulation attempts", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942360", Description: "Detects concatenated basic SQL injection and SQLLFI attempts", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942370", Description: "Detects classic SQL injection probings 2/3", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 2},
	{ID: "942380", Description: "SQL injection attack", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942390", Description: "SQL injection attack", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "942400", Description: "SQL injection attack", Category: "sqli", Tags: []string{"OWASP_CRS", "attack-sqli"}, Severity: "CRITICAL", ParanoiaLvl: 1},

	// 943xxx — Session Fixation
	{ID: "943100", Description: "Possible session fixation attack: setting cookie values in HTML", Category: "session-fixation", Tags: []string{"OWASP_CRS", "attack-fixation"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "943110", Description: "Possible session fixation attack: SessionID parameter name with off-domain referrer", Category: "session-fixation", Tags: []string{"OWASP_CRS", "attack-fixation"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "943120", Description: "Possible session fixation attack: SessionID parameter name with no referrer", Category: "session-fixation", Tags: []string{"OWASP_CRS", "attack-fixation"}, Severity: "CRITICAL", ParanoiaLvl: 1},

	// 944xxx — Java Injection
	{ID: "944100", Description: "Remote command execution: suspicious Java class detected", Category: "java", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "944110", Description: "Remote command execution: Java process spawn (CVE-2017-9805)", Category: "java", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "944120", Description: "Remote command execution: Java serialization (CVE-2015-5842)", Category: "java", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "944130", Description: "Suspicious Java class detected", Category: "java", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "944200", Description: "Magic bytes detected, probable Java serialization in use", Category: "java", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "944210", Description: "Magic bytes detected Base64 encoded, probable Java serialization in use", Category: "java", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "944240", Description: "Remote command execution: Java serialization (CVE-2015-5842)", Category: "java", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
	{ID: "944250", Description: "Remote command execution: suspicious Java method detected", Category: "java", Tags: []string{"OWASP_CRS", "attack-rce"}, Severity: "CRITICAL", ParanoiaLvl: 1},
}

// GetCRSCatalog returns the full CRS rule catalog for the UI.
func GetCRSCatalog() CRSCatalogResponse {
	return CRSCatalogResponse{
		Categories: crsCategories,
		Rules:      crsRules,
		Total:      len(crsRules),
	}
}

// ModSecurity variables available for SecRule directives.
var modsecVariables = []string{
	"ARGS", "ARGS_COMBINED_SIZE", "ARGS_GET", "ARGS_GET_NAMES", "ARGS_NAMES",
	"ARGS_POST", "ARGS_POST_NAMES", "FILES", "FILES_COMBINED_SIZE",
	"FILES_NAMES", "FILES_SIZES", "GEO", "MATCHED_VAR", "MATCHED_VARS",
	"MATCHED_VAR_NAME", "MATCHED_VARS_NAMES", "MULTIPART_FILENAME",
	"MULTIPART_NAME", "PATH_INFO", "QUERY_STRING", "REMOTE_ADDR",
	"REMOTE_HOST", "REMOTE_PORT", "REQUEST_BASENAME", "REQUEST_BODY",
	"REQUEST_COOKIES", "REQUEST_COOKIES_NAMES", "REQUEST_FILENAME",
	"REQUEST_HEADERS", "REQUEST_HEADERS_NAMES", "REQUEST_LINE",
	"REQUEST_METHOD", "REQUEST_PROTOCOL", "REQUEST_URI",
	"REQUEST_URI_RAW", "RESPONSE_BODY", "RESPONSE_CONTENT_LENGTH",
	"RESPONSE_CONTENT_TYPE", "RESPONSE_HEADERS", "RESPONSE_HEADERS_NAMES",
	"RESPONSE_PROTOCOL", "RESPONSE_STATUS", "SERVER_ADDR", "SERVER_NAME",
	"SERVER_PORT", "TX", "UNIQUE_ID", "XML",
}

// ModSecurity operators for SecRule directives.
type ModSecOperator struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
	HasArg      bool   `json:"has_arg"`
}

var modsecOperators = []ModSecOperator{
	{Name: "@rx", Label: "matches regex", Description: "Regular expression match", HasArg: true},
	{Name: "@streq", Label: "equals", Description: "Exact string match (case-sensitive)", HasArg: true},
	{Name: "@pm", Label: "contains phrase", Description: "Phrase match — matches any of the given phrases", HasArg: true},
	{Name: "@pmFromFile", Label: "contains phrase (file)", Description: "Phrase match from a file", HasArg: true},
	{Name: "@beginsWith", Label: "begins with", Description: "Matches if input begins with the given string", HasArg: true},
	{Name: "@endsWith", Label: "ends with", Description: "Matches if input ends with the given string", HasArg: true},
	{Name: "@contains", Label: "contains", Description: "Matches if input contains the given string", HasArg: true},
	{Name: "@within", Label: "is within", Description: "Matches if input is found within the given string", HasArg: true},
	{Name: "@ipMatch", Label: "IP in range", Description: "Matches IP addresses and CIDR ranges", HasArg: true},
	{Name: "@ipMatchFromFile", Label: "IP in range (file)", Description: "IP match from a file of addresses/CIDRs", HasArg: true},
	{Name: "@gt", Label: "greater than", Description: "Numeric greater than", HasArg: true},
	{Name: "@ge", Label: "greater or equal", Description: "Numeric greater than or equal", HasArg: true},
	{Name: "@lt", Label: "less than", Description: "Numeric less than", HasArg: true},
	{Name: "@le", Label: "less or equal", Description: "Numeric less than or equal", HasArg: true},
	{Name: "@eq", Label: "equals (numeric)", Description: "Numeric equality", HasArg: true},
	{Name: "@detectSQLi", Label: "detect SQL injection", Description: "SQL injection detection via libinjection", HasArg: false},
	{Name: "@detectXSS", Label: "detect XSS", Description: "XSS detection via libinjection", HasArg: false},
	{Name: "@validateByteRange", Label: "validate byte range", Description: "Validates the byte range of input", HasArg: true},
	{Name: "@validateUrlEncoding", Label: "validate URL encoding", Description: "Validates URL encoding", HasArg: false},
	{Name: "@validateUtf8Encoding", Label: "validate UTF-8", Description: "Validates UTF-8 encoding", HasArg: false},
}

// ModSecurity actions for SecRule directives.
var modsecActions = []string{
	"id:", "phase:", "pass", "deny", "drop", "allow", "redirect:",
	"log", "nolog", "auditlog", "noauditlog",
	"msg:", "severity:", "tag:", "rev:", "ver:", "maturity:", "accuracy:",
	"t:none", "t:lowercase", "t:urlDecodeUni", "t:htmlEntityDecode",
	"t:removeWhitespace", "t:compressWhitespace", "t:removeNulls",
	"t:replaceNulls", "t:base64Decode", "t:base64DecodeExt",
	"t:hexDecode", "t:jsDecode", "t:cssDecode", "t:utf8toUnicode",
	"t:normalizePath", "t:normalizePathWin", "t:removeComments",
	"t:replaceComments", "t:sha1", "t:md5", "t:length", "t:trim",
	"chain", "skip:", "skipAfter:",
	"setvar:", "expirevar:",
	"ctl:ruleRemoveById=", "ctl:ruleRemoveByTag=", "ctl:ruleRemoveTargetById=",
	"ctl:ruleRemoveTargetByTag=", "ctl:ruleEngine=",
	"ctl:requestBodyAccess=", "ctl:responseBodyAccess=",
	"ctl:forceRequestBodyVariable=",
	"capture", "multiMatch", "initcol:",
}

// CRSAutocompleteResponse provides data for the raw editor autocomplete.
type CRSAutocompleteResponse struct {
	Variables []string         `json:"variables"`
	Operators []ModSecOperator `json:"operators"`
	Actions   []string         `json:"actions"`
}

// GetCRSAutocomplete returns the autocomplete data for the SecRule editor.
func GetCRSAutocomplete() CRSAutocompleteResponse {
	return CRSAutocompleteResponse{
		Variables: modsecVariables,
		Operators: modsecOperators,
		Actions:   modsecActions,
	}
}
