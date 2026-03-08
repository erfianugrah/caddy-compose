package main

import (
	"fmt"
	"strings"
)

// ─── Condition → SecRule mapping ────────────────────────────────────

// conditionVariable maps a condition field to its SecRule variable.
func conditionVariable(c Condition) string {
	switch c.Field {
	case "ip":
		return "REMOTE_ADDR"
	case "path":
		return "REQUEST_URI"
	case "host":
		return "SERVER_NAME"
	case "method":
		return "REQUEST_METHOD"
	case "user_agent":
		return "REQUEST_HEADERS:User-Agent"
	case "header":
		// Header field value format: "Header-Name:value" — extract the header name.
		if idx := strings.Index(c.Value, ":"); idx > 0 {
			return fmt.Sprintf("REQUEST_HEADERS:%s", c.Value[:idx])
		}
		return "REQUEST_HEADERS"
	case "query":
		return "QUERY_STRING"
	case "country":
		return "REQUEST_HEADERS:Cf-Ipcountry"
	case "cookie":
		// Cookie field value format: "CookieName:value" — extract the cookie name.
		if idx := strings.Index(c.Value, ":"); idx > 0 {
			return fmt.Sprintf("REQUEST_COOKIES:%s", c.Value[:idx])
		}
		return "REQUEST_COOKIES"
	case "body":
		return "REQUEST_BODY"
	case "body_json":
		// JSON field matching — SecRule operates on raw REQUEST_BODY.
		// Caddy-side body matcher handles JSON path extraction; WAF falls back to raw body match.
		return "REQUEST_BODY"
	case "body_form":
		// Form field matching — SecRule can target ARGS for url-encoded form fields.
		// Use ARGS:<name> when a named field is present (same as args).
		if idx := strings.Index(c.Value, ":"); idx > 0 {
			return fmt.Sprintf("ARGS:%s", c.Value[:idx])
		}
		return "ARGS"
	case "args":
		// Args field value format: "ParamName:value" — extract the parameter name.
		if idx := strings.Index(c.Value, ":"); idx > 0 {
			return fmt.Sprintf("ARGS:%s", c.Value[:idx])
		}
		return "ARGS"
	case "uri_path":
		return "REQUEST_FILENAME"
	case "referer":
		return "REQUEST_HEADERS:Referer"
	case "response_header":
		// Response header value format: "Header-Name:value" — extract the header name.
		if idx := strings.Index(c.Value, ":"); idx > 0 {
			return fmt.Sprintf("RESPONSE_HEADERS:%s", c.Value[:idx])
		}
		return "RESPONSE_HEADERS"
	case "response_status":
		return "RESPONSE_STATUS"
	case "http_version":
		return "REQUEST_PROTOCOL"
	default:
		return "REQUEST_URI"
	}
}

// conditionOperator maps a condition operator to its SecRule operator string.
// Returns (operator_string, negate).
func conditionOperator(c Condition) (string, bool) {
	switch c.Operator {
	case "eq":
		return "@streq", false
	case "neq":
		return "@streq", true
	case "contains":
		return "@contains", false
	case "begins_with":
		return "@beginsWith", false
	case "ends_with":
		return "@endsWith", false
	case "regex":
		return "@rx", false
	case "ip_match":
		return "@ipMatch", false
	case "not_ip_match":
		return "@ipMatch", true
	case "in":
		return "@pm", false
	default:
		return "@streq", false
	}
}

// conditionValue extracts the value to match.
// For named fields (header, cookie, args, response_header, body_json, body_form),
// strips the "name:" prefix.
// For "in" operator, converts pipe-separated values to space-separated for @pm.
func conditionValue(c Condition) string {
	v := c.Value
	switch c.Field {
	case "header", "cookie", "args", "response_header", "body_json", "body_form":
		if idx := strings.Index(v, ":"); idx > 0 {
			v = strings.TrimSpace(v[idx+1:])
		}
	}
	if c.Operator == "in" {
		v = strings.ReplaceAll(v, "|", " ")
	}
	return v
}

// formatSecRuleOperator builds the full operator string like "@streq /path" or "!@ipMatch 1.2.3.4".
func formatSecRuleOperator(c Condition) string {
	op, negate := conditionOperator(c)
	val := escapeSecRuleValue(conditionValue(c))
	if negate {
		return fmt.Sprintf("\"!%s %s\"", op, val)
	}
	return fmt.Sprintf("\"%s %s\"", op, val)
}

// escapeSecRuleValue escapes special characters for SecRule patterns.
// SecRule values are typically enclosed in double quotes ("..."), and may also
// appear inside single-quoted action fields (msg:'...'). We escape:
//   - backslash → \\ (must come first to avoid double-escaping)
//   - double quote → \" (closes the SecRule pattern)
//   - single quote → \' (closes msg:'...' action fields)
//   - newlines/carriage returns → stripped (could inject new directives)
func escapeSecRuleValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// escapeSecRuleMsgValue escapes a value for use inside a msg:'...' field.
// In addition to standard escaping, commas are replaced with semicolons.
// While Coraza's parseActions correctly handles commas inside single-quoted
// values per the ModSecurity spec, removing commas from msg fields eliminates
// a class of parsing edge cases and makes the generated rules more robust.
func escapeSecRuleMsgValue(s string) string {
	s = escapeSecRuleValue(s)
	s = strings.ReplaceAll(s, ",", ";")
	return s
}

// sanitizeComment removes newlines from a string destined for a SecRule comment
// or msg field, preventing directive injection via crafted names.
func sanitizeComment(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// ruleIDGen is a per-invocation counter for generating unique rule IDs
// in the 9500000+ range (reserved for local exclusions).
// Using a struct instead of a package-level variable prevents concurrent
// calls from producing duplicate IDs.
type ruleIDGen struct {
	counter int
}

func newRuleIDGen() *ruleIDGen {
	return &ruleIDGen{}
}

func (g *ruleIDGen) next() string {
	g.counter++
	return fmt.Sprintf("95%05d", g.counter)
}

// peek returns the next ID that will be generated without consuming it.
func (g *ruleIDGen) peek() string {
	return fmt.Sprintf("95%05d", g.counter+1)
}
