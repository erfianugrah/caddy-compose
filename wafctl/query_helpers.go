package main

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// --- Query parameter helpers ---

// parseHours extracts and validates the ?hours= query parameter.
// Returns 0 (meaning "all time") if not provided or invalid.
// Accepts any positive integer; the validHours allowlist is only used
// by the frontend to populate quick-range pickers.
func parseHours(r *http.Request) int {
	s := r.URL.Query().Get("hours")
	if s == "" {
		return 0
	}
	h, err := strconv.Atoi(s)
	if err != nil || h < 0 {
		return 0
	}
	return h
}

// timeRange holds an optional absolute time range from ?start= and ?end= query params.
type timeRange struct {
	Start time.Time
	End   time.Time
	Valid bool // true if both start and end were successfully parsed
}

// parseTimeRange extracts ?start= and ?end= ISO 8601 query parameters.
// Returns a valid timeRange only if both are present and parseable.
// When valid, this takes precedence over ?hours=.
func parseTimeRange(r *http.Request) timeRange {
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")
	if startStr == "" || endStr == "" {
		return timeRange{}
	}

	// Try multiple common formats.
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	}

	var start, end time.Time
	var err error
	for _, f := range formats {
		start, err = time.Parse(f, startStr)
		if err == nil {
			break
		}
	}
	if err != nil {
		return timeRange{}
	}

	for _, f := range formats {
		end, err = time.Parse(f, endStr)
		if err == nil {
			break
		}
	}
	if err != nil {
		return timeRange{}
	}

	return timeRange{Start: start.UTC(), End: end.UTC(), Valid: true}
}

// getWAFEvents returns WAF events filtered by either time range or hours.
func getWAFEvents(store *Store, tr timeRange, hours int) []Event {
	if tr.Valid {
		return store.SnapshotRange(tr.Start, tr.End)
	}
	return store.SnapshotSince(hours)
}

// getRLEvents returns rate-limited events filtered by either time range or hours.
// If rules are provided, events are enriched with tags from the first matching rule.
func getRLEvents(als *AccessLogStore, tr timeRange, hours int, rules []RateLimitRule) []Event {
	if tr.Valid {
		return als.SnapshotAsEventsRange(tr.Start, tr.End, rules)
	}
	return als.SnapshotAsEvents(hours, rules)
}

// --- Field filter with operator support ---

// fieldFilter represents a single filter condition with an operator.
// Supported operators: eq (default), neq, contains, in, regex.
type fieldFilter struct {
	value      string
	valueLower string         // pre-lowered at parse time for case-insensitive ops
	op         string         // "eq", "neq", "contains", "in", "regex"
	re         *regexp.Regexp // compiled only when op == "regex"
	ins        []string       // split + lowered values only when op == "in"
}

// validFilterOps is the set of recognized filter operators.
var validFilterOps = map[string]bool{
	"eq": true, "neq": true, "contains": true, "in": true, "regex": true,
}

// parseFieldFilter reads a filter value and its companion _op param from query.
// Returns nil when the field is empty (no filter).
func parseFieldFilter(value, op string) *fieldFilter {
	if value == "" {
		return nil
	}
	if !validFilterOps[op] {
		op = "eq"
	}
	f := &fieldFilter{value: value, op: op}
	switch op {
	case "regex":
		if len(value) > 1024 {
			// Reject excessively large patterns — fall back to contains.
			f.op = "contains"
		} else if re, err := regexp.Compile(value); err != nil {
			// Fall back to literal contains on bad regex.
			f.op = "contains"
		} else {
			f.re = re
		}
	case "in":
		parts := strings.Split(value, ",")
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				f.ins = append(f.ins, strings.ToLower(t))
			}
		}
	}
	// Pre-lowercase for case-insensitive comparison — avoids per-event allocations.
	f.valueLower = strings.ToLower(f.value)
	return f
}

// matchTags tests whether any tag in the slice matches the filter condition.
// For neq, returns true only if NO tag equals the value (i.e., the tag is absent).
func (f *fieldFilter) matchTags(tags []string) bool {
	if f == nil {
		return true // no filter = always match
	}
	if f.op == "neq" {
		// neq semantics for tags: the specified tag must NOT be present.
		for _, tag := range tags {
			if strings.EqualFold(tag, f.value) {
				return false
			}
		}
		return true
	}
	// For all other operators, at least one tag must match.
	for _, tag := range tags {
		if f.matchField(tag) {
			return true
		}
	}
	return false
}

// matchField tests whether target matches the filter condition.
// Case-insensitive for eq/neq/contains/in; regex uses the compiled pattern as-is.
func (f *fieldFilter) matchField(target string) bool {
	if f == nil {
		return true // no filter = always match
	}
	switch f.op {
	case "eq":
		return strings.EqualFold(target, f.value)
	case "neq":
		return !strings.EqualFold(target, f.value)
	case "contains":
		return strings.Contains(strings.ToLower(target), f.valueLower)
	case "in":
		tl := strings.ToLower(target)
		for _, v := range f.ins {
			if tl == v {
				return true
			}
		}
		return false
	case "regex":
		if f.re != nil {
			return f.re.MatchString(target)
		}
		return strings.Contains(strings.ToLower(target), f.valueLower)
	}
	return true
}
