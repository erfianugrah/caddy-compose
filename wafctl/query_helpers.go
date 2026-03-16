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
// Capped at 2160 (90 days) to match the default event retention period.
func parseHours(r *http.Request) int {
	s := r.URL.Query().Get("hours")
	if s == "" {
		return 0
	}
	h, err := strconv.Atoi(s)
	if err != nil || h < 0 {
		return 0
	}
	if h > 2160 {
		h = 2160
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

// getRLEvents returns rate-limited and policy engine events filtered by either time range or hours.
// Rate limit events are enriched with tags from matching RL rules.
// Policy engine events are enriched with tags from the exclusion store (set via SetExclusionStore).
func getRLEvents(als *AccessLogStore, tr timeRange, hours int, rules []RateLimitRule) []Event {
	if tr.Valid {
		return als.SnapshotAsEventsRange(tr.Start, tr.End, rules)
	}
	return als.SnapshotAsEvents(hours, rules)
}

// getRawRLSnapshot returns raw RateLimitEvents without enrichment.
// This avoids the O(N) enrichment cost when only a small page is needed.
func getRawRLSnapshot(als *AccessLogStore, tr timeRange, hours int) []RateLimitEvent {
	if tr.Valid {
		return als.snapshotRange(tr.Start, tr.End)
	}
	return als.snapshotSince(hours)
}

// ─── Deferred enrichment helpers ────────────────────────────────────

// rleEventType maps RateLimitEvent.Source to the unified Event.EventType string.
func rleEventType(source string) string {
	switch source {
	case "policy", "ipsum":
		return "policy_block"
	case "detect_block":
		return "detect_block"
	case "ddos_blocked":
		return "ddos_blocked"
	case "ddos_jailed":
		return "ddos_jailed"
	case "logged":
		return "logged"
	case "policy_skip":
		return "policy_skip"
	default:
		return "rate_limited"
	}
}

// rleIsBlocked returns true if the RateLimitEvent source represents a blocked request.
func rleIsBlocked(source string) bool {
	return source != "logged" && source != "policy_skip"
}

// rleResponseStatus returns the HTTP status code for a RateLimitEvent.
func rleResponseStatus(rle *RateLimitEvent) int {
	switch rle.Source {
	case "policy", "ipsum", "detect_block", "ddos_blocked", "ddos_jailed":
		return 403
	case "policy_skip", "logged":
		return rle.Status
	default:
		return 429
	}
}

// rleBlockedBy returns the blocked_by string for a RateLimitEvent.
func rleBlockedBy(rle *RateLimitEvent) string {
	switch rle.Source {
	case "policy", "ipsum":
		return "policy-engine"
	case "detect_block":
		return "anomaly_inbound"
	case "ddos_blocked", "ddos_jailed":
		return "ddos_mitigator"
	default:
		return ""
	}
}

// enrichmentLookup holds pre-computed tag lookup tables for deferred enrichment.
type enrichmentLookup struct {
	excTagsByName map[string][]string
	rlTagsByName  map[string][]string
	sortedRules   []RateLimitRule
}

// buildEnrichmentLookup prepares tag lookup tables from the AccessLogStore's
// associated exclusion store. Built once per request, used for on-demand enrichment.
// Uses TagsByName() to avoid the expensive deep copy of List().
func buildEnrichmentLookup(als *AccessLogStore) enrichmentLookup {
	als.mu.RLock()
	es := als.exclusionStore
	als.mu.RUnlock()

	var excTags map[string][]string
	if es != nil {
		excTags = es.TagsByName()
	}

	return enrichmentLookup{
		excTagsByName: excTags,
	}
}

// enrichSingleRLE converts a single RateLimitEvent to a unified Event with
// tag enrichment. This is the deferred version of enrichAccessEvents — called
// only for events that land in the result page instead of all events.
func enrichSingleRLE(rle *RateLimitEvent, lookup *enrichmentLookup) Event {
	var tags []string
	switch rle.Source {
	case "detect_block", "logged":
		tags = rle.InlineTags
	case "policy", "ipsum":
		if t, ok := lookup.excTagsByName[rle.RuleName]; ok {
			tags = t
		}
	case "policy_rl":
		if t, ok := lookup.rlTagsByName[rle.RuleName]; ok {
			tags = t
		}
	case "policy_skip":
		tags = rle.InlineTags
	default:
		if len(lookup.sortedRules) > 0 {
			tags = matchEventToRuleTags(*rle, lookup.sortedRules)
		}
	}
	return RateLimitEventToEvent(*rle, tags)
}

// rleTags returns the tags for a RateLimitEvent using the pre-computed lookup.
// Used for tag filtering without full Event conversion.
func rleTags(rle *RateLimitEvent, lookup *enrichmentLookup) []string {
	switch rle.Source {
	case "detect_block", "logged":
		return rle.InlineTags
	case "policy", "ipsum":
		return lookup.excTagsByName[rle.RuleName]
	case "policy_rl":
		return lookup.rlTagsByName[rle.RuleName]
	case "policy_skip":
		return rle.InlineTags
	default:
		if len(lookup.sortedRules) > 0 {
			return matchEventToRuleTags(*rle, lookup.sortedRules)
		}
		return nil
	}
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
	valueInt   int            // pre-parsed int for matchIntField (valid when valueIntOK)
	valueIntOK bool           // true if value is a valid integer
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
	// Pre-parse integer value for matchIntField — avoids per-event strconv.Atoi.
	if v, err := strconv.Atoi(f.value); err == nil {
		f.valueInt = v
		f.valueIntOK = true
	}
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

// matchIntField tests whether an integer target matches the filter.
// For eq/neq this uses the pre-parsed valueInt (cached at parse time),
// avoiding per-event strconv.Atoi calls.
// Falls back to string comparison for regex/contains.
func (f *fieldFilter) matchIntField(target int) bool {
	if f == nil {
		return true
	}
	switch f.op {
	case "eq":
		return f.valueIntOK && target == f.valueInt
	case "neq":
		return !f.valueIntOK || target != f.valueInt
	case "in":
		ts := strconv.Itoa(target)
		tl := strings.ToLower(ts)
		for _, v := range f.ins {
			if tl == v {
				return true
			}
		}
		return false
	default:
		return f.matchField(strconv.Itoa(target))
	}
}

// ─── Event Source Routing ────────────────────────────────────────────

// wafEventTypes lists event types originating from the WAF (policy engine) event store.
// "detect_block" appears in both stores: WAF store (migrated from legacy "blocked" JSONL)
// and RL/access log store (new events from access log parsing).
var wafEventTypes = map[string]bool{
	"detect_block": true, "logged": true,
	"policy_skip": true, "policy_allow": true, "policy_block": true,
}

// rlEventTypes lists event types originating from the access log (RL/policy) event store.
var rlEventTypes = map[string]bool{
	"rate_limited": true, "policy_block": true, "detect_block": true,
}

// eventSourcesNeeded determines which event stores to query based on the event_type filter.
// Returns (needWAF, needRL). When no filter is active, both are true.
func eventSourcesNeeded(eventTypeF *fieldFilter) (needWAF, needRL bool) {
	if eventTypeF == nil {
		return true, true
	}
	switch eventTypeF.op {
	case "eq":
		return wafEventTypes[eventTypeF.value], rlEventTypes[eventTypeF.value]
	case "in":
		for _, v := range strings.Split(eventTypeF.value, ",") {
			v = strings.TrimSpace(v)
			if wafEventTypes[v] {
				needWAF = true
			}
			if rlEventTypes[v] {
				needRL = true
			}
		}
		return needWAF, needRL
	default:
		// neq, contains, regex — can't prune safely, fetch both
		return true, true
	}
}
