package main

import (
	"fmt"
	"strings"
)

// resolveRLListConditions expands in_list/not_in_list conditions by looking
// up managed list items and converting them to operators the Caddy matchers
// understand natively (in, ip_match, not_ip_match, not_in) or keeping them
// as in_list/not_in_list with pipe-separated items for expression-based matching.
func resolveRLListConditions(conditions []Condition, ls *ManagedListStore) []Condition {
	if ls == nil {
		return conditions
	}
	resolved := make([]Condition, len(conditions))
	for i, c := range conditions {
		if c.Operator != "in_list" && c.Operator != "not_in_list" {
			resolved[i] = c
			continue
		}

		items, _ := resolveListItems(ls, c.Value)
		if len(items) == 0 {
			// Empty list or not found — keep original (matcher returns "" for unknown op).
			resolved[i] = c
			continue
		}

		negate := c.Operator == "not_in_list"
		switch c.Field {
		case "ip":
			if negate {
				resolved[i] = Condition{Field: "ip", Operator: "not_ip_match", Value: strings.Join(items, " ")}
			} else {
				resolved[i] = Condition{Field: "ip", Operator: "ip_match", Value: strings.Join(items, " ")}
			}
		case "path", "uri_path":
			if negate {
				resolved[i] = Condition{Field: c.Field, Operator: "not_in", Value: strings.Join(items, "|")}
			} else {
				resolved[i] = Condition{Field: c.Field, Operator: "in", Value: strings.Join(items, "|")}
			}
		case "method":
			if negate {
				resolved[i] = Condition{Field: "method", Operator: "not_in", Value: strings.Join(items, "|")}
			} else {
				resolved[i] = Condition{Field: "method", Operator: "in", Value: strings.Join(items, "|")}
			}
		case "country":
			if negate {
				resolved[i] = Condition{Field: "country", Operator: "not_in", Value: strings.Join(items, "|")}
			} else {
				resolved[i] = Condition{Field: "country", Operator: "in", Value: strings.Join(items, "|")}
			}
		default:
			// For fields without native "in" support (user_agent, header, cookie, etc.),
			// keep in_list/not_in_list operator with pipe-separated items for expression matching.
			resolved[i] = Condition{Field: c.Field, Operator: c.Operator, Value: strings.Join(items, "|")}
		}
	}
	return resolved
}

// writeConditionMatchers writes Caddy matcher directives for conditions.
func writeConditionMatchers(b *strings.Builder, conditions []Condition, groupOp string) {
	if len(conditions) == 0 {
		return
	}

	// For AND logic (default): all matchers in one match block.
	// For OR logic: Caddy evaluates multiple match blocks as OR,
	// but since we're already inside a single match block, we use
	// expression matchers for OR. For simplicity in v1, we emit
	// all conditions in one block (AND behavior) — OR support
	// requires named matcher composition which is more complex.
	// TODO: OR grouping via multiple named matchers in future version.
	for _, c := range conditions {
		line := rlConditionToMatcher(c)
		if line != "" {
			b.WriteString("\t\t\t" + line + "\n")
		}
	}
}

// rlConditionToMatcher translates a Condition to a Caddy matcher line.
func rlConditionToMatcher(c Condition) string {
	switch c.Field {
	case "path":
		return rlPathMatcher(c)
	case "method":
		return rlMethodMatcher(c)
	case "ip":
		return rlIPMatcher(c)
	case "header":
		return rlHeaderMatcher(c)
	case "user_agent":
		return rlUserAgentMatcher(c)
	case "query":
		return rlQueryMatcher(c)
	case "uri_path":
		return rlURIPathMatcher(c)
	case "host":
		// Host matching is implicit in Caddy site blocks; skip.
		return ""
	case "country":
		// Country matching via Cf-Ipcountry header.
		return rlCountryMatcher(c)
	case "cookie":
		return rlCookieMatcher(c)
	case "referer":
		return rlRefererMatcher(c)
	case "http_version":
		return rlHTTPVersionMatcher(c)
	case "body":
		return rlBodyMatcher(c)
	case "body_json":
		return rlBodyJSONMatcher(c)
	case "body_form":
		return rlBodyFormMatcher(c)
	}
	return ""
}

func rlPathMatcher(c Condition) string {
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("path %s", c.Value)
	case "begins_with":
		v := c.Value
		if !strings.HasSuffix(v, "*") {
			v += "*"
		}
		return fmt.Sprintf("path %s", v)
	case "ends_with":
		return fmt.Sprintf("path *%s", c.Value)
	case "contains":
		return fmt.Sprintf("path *%s*", c.Value)
	case "regex":
		return fmt.Sprintf("path_regexp %s", c.Value)
	case "in":
		paths := strings.Join(splitPipe(c.Value), " ")
		return fmt.Sprintf("path %s", paths)
	case "not_in":
		paths := strings.Join(splitPipe(c.Value), " ")
		return fmt.Sprintf("not path %s", paths)
	case "neq":
		return fmt.Sprintf("not path %s", c.Value)
	}
	return ""
}

func rlMethodMatcher(c Condition) string {
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("method %s", c.Value)
	case "in":
		methods := strings.Join(splitPipe(c.Value), " ")
		return fmt.Sprintf("method %s", methods)
	case "not_in":
		methods := strings.Join(splitPipe(c.Value), " ")
		return fmt.Sprintf("not method %s", methods)
	case "neq":
		return fmt.Sprintf("not method %s", c.Value)
	}
	return ""
}

func rlIPMatcher(c Condition) string {
	switch c.Operator {
	case "eq", "ip_match":
		return fmt.Sprintf("remote_ip %s", c.Value)
	case "neq", "not_ip_match":
		return fmt.Sprintf("not remote_ip %s", c.Value)
	}
	return ""
}

func rlHeaderMatcher(c Condition) string {
	name, value := splitNamedField(c.Value)
	if name == "" {
		return ""
	}
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("header %s %s", name, value)
	case "contains":
		return fmt.Sprintf("header %s *%s*", name, value)
	case "regex":
		return fmt.Sprintf("header_regexp %s %s", name, value)
	case "in_list":
		// After resolution, value is "HeaderName:item1|item2|..." — items are in the value part.
		return rlExpressionInList(fmt.Sprintf("{http.request.header.%s}", name), value, false)
	case "not_in_list":
		return rlExpressionInList(fmt.Sprintf("{http.request.header.%s}", name), value, true)
	}
	return ""
}

func rlUserAgentMatcher(c Condition) string {
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("header User-Agent %s", c.Value)
	case "contains":
		return fmt.Sprintf("header User-Agent *%s*", c.Value)
	case "regex":
		return fmt.Sprintf("header_regexp User-Agent %s", c.Value)
	case "in_list":
		return rlExpressionInList("{http.request.header.User-Agent}", c.Value, false)
	case "not_in_list":
		return rlExpressionInList("{http.request.header.User-Agent}", c.Value, true)
	}
	return ""
}

func rlQueryMatcher(c Condition) string {
	switch c.Operator {
	case "contains":
		// Caddy's query matcher does key=value matching. For substring matching,
		// use a wildcard pattern. This matches if any query param value contains the string.
		return fmt.Sprintf("query *%s*", c.Value)
	case "regex":
		// Caddy's query matcher doesn't support regex. Use an expression matcher instead.
		return fmt.Sprintf("expression {http.request.uri.query}.matches(%q)", c.Value)
	}
	return ""
}

func rlURIPathMatcher(c Condition) string {
	// uri_path is the same as path for Caddy matchers.
	return rlPathMatcher(Condition{Field: "path", Operator: c.Operator, Value: c.Value})
}

func rlCountryMatcher(c Condition) string {
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("header Cf-Ipcountry %s", c.Value)
	case "neq":
		return fmt.Sprintf("not header Cf-Ipcountry %s", c.Value)
	case "in":
		// Multiple countries as separate header matchers won't work with AND;
		// use expression matcher for OR across country values.
		countries := splitPipe(c.Value)
		if len(countries) == 1 {
			return fmt.Sprintf("header Cf-Ipcountry %s", countries[0])
		}
		// For multiple countries, use a Caddy expression.
		var parts []string
		for _, cc := range countries {
			parts = append(parts, fmt.Sprintf("{http.request.header.Cf-Ipcountry} == %q", cc))
		}
		return fmt.Sprintf("expression (%s)", strings.Join(parts, " || "))
	case "not_in":
		// not_in: block if country is NOT in list → match if country != all values.
		countries := splitPipe(c.Value)
		if len(countries) == 1 {
			return fmt.Sprintf("not header Cf-Ipcountry %s", countries[0])
		}
		var parts []string
		for _, cc := range countries {
			parts = append(parts, fmt.Sprintf("{http.request.header.Cf-Ipcountry} != %q", cc))
		}
		return fmt.Sprintf("expression (%s)", strings.Join(parts, " && "))
	}
	return ""
}

func rlCookieMatcher(c Condition) string {
	name, value := splitNamedField(c.Value)
	if name == "" {
		return ""
	}
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("header Cookie *%s=%s*", name, value)
	case "neq":
		return fmt.Sprintf("not header Cookie *%s=%s*", name, value)
	case "contains":
		return fmt.Sprintf("header Cookie *%s=*%s*", name, value)
	case "regex":
		// Caddy header matcher doesn't support regex. Use expression.
		return fmt.Sprintf("expression {http.request.cookie.%s}.matches(%q)", name, value)
	}
	return ""
}

func rlRefererMatcher(c Condition) string {
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("header Referer %s", c.Value)
	case "neq":
		return fmt.Sprintf("not header Referer %s", c.Value)
	case "contains":
		return fmt.Sprintf("header Referer *%s*", c.Value)
	case "regex":
		return fmt.Sprintf("header_regexp Referer %s", c.Value)
	case "in_list":
		return rlExpressionInList("{http.request.header.Referer}", c.Value, false)
	case "not_in_list":
		return rlExpressionInList("{http.request.header.Referer}", c.Value, true)
	}
	return ""
}

func rlHTTPVersionMatcher(c Condition) string {
	// Caddy's `protocol` matcher matches HTTP version.
	// Valid values: "http/1.0", "http/1.1", "http/2", "h2c", "http/3"
	// CRS uses "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0" format.
	// Caddy uses lowercase: "http/1.0", "http/1.1", "http/2", "http/3"
	val := strings.ToLower(c.Value)
	// Normalize "http/2.0" → "http/2" (Caddy uses "http/2", not "http/2.0")
	if val == "http/2.0" {
		val = "http/2"
	}
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("protocol %s", val)
	case "neq":
		return fmt.Sprintf("not protocol %s", val)
	}
	return ""
}

// ─── Body Matchers (caddy-body-matcher plugin) ─────────────────────

func rlBodyMatcher(c Condition) string {
	// Raw body matching via the body matcher plugin.
	// Caddyfile syntax: body <op> <value>
	switch c.Operator {
	case "contains":
		return fmt.Sprintf("body contains %q", c.Value)
	case "eq":
		return fmt.Sprintf("body eq %q", c.Value)
	case "begins_with":
		return fmt.Sprintf("body starts_with %q", c.Value)
	case "ends_with":
		return fmt.Sprintf("body ends_with %q", c.Value)
	case "regex":
		return fmt.Sprintf("body regex %q", c.Value)
	}
	return ""
}

func rlBodyJSONMatcher(c Condition) string {
	// JSON field matching via body matcher plugin.
	// Value format: "dotpath:value" (named field pattern like header).
	// Caddyfile syntax: body json <path> <value>, body json_contains <path> <value>,
	//                   body json_regex <path> <pattern>, body json_exists <path>
	name, value := splitNamedField(c.Value)
	if name == "" {
		return ""
	}
	// Ensure dot-path starts with "."
	if !strings.HasPrefix(name, ".") {
		name = "." + name
	}
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("body json %s %q", name, value)
	case "contains":
		return fmt.Sprintf("body json_contains %s %q", name, value)
	case "regex":
		return fmt.Sprintf("body json_regex %s %q", name, value)
	case "exists":
		return fmt.Sprintf("body json_exists %s", name)
	}
	return ""
}

func rlBodyFormMatcher(c Condition) string {
	// URL-encoded form field matching via body matcher plugin.
	// Value format: "field:value" (named field pattern like header).
	// Caddyfile syntax: body form <field> <value>, body form_contains <field> <value>,
	//                   body form_regex <field> <pattern>
	name, value := splitNamedField(c.Value)
	if name == "" {
		return ""
	}
	switch c.Operator {
	case "eq":
		return fmt.Sprintf("body form %s %q", name, value)
	case "contains":
		return fmt.Sprintf("body form_contains %s %q", name, value)
	case "regex":
		return fmt.Sprintf("body form_regex %s %q", name, value)
	}
	return ""
}

// ─── Expression-based List Matchers ─────────────────────────────────

// rlExpressionInList generates a Caddy CEL expression matcher for fields
// that lack native "in" support. The items string is pipe-separated.
// When negate is true, generates a "not in" expression (all != with &&).
func rlExpressionInList(placeholder, items string, negate bool) string {
	vals := splitPipe(items)
	if len(vals) == 0 {
		return ""
	}
	if negate {
		var parts []string
		for _, v := range vals {
			parts = append(parts, fmt.Sprintf("%s != %q", placeholder, v))
		}
		return fmt.Sprintf("expression (%s)", strings.Join(parts, " && "))
	}
	var parts []string
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("%s == %q", placeholder, v))
	}
	return fmt.Sprintf("expression (%s)", strings.Join(parts, " || "))
}
