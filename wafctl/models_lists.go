package main

import "time"

// ─── Managed List Model ─────────────────────────────────────────────

// ManagedList is a named, reusable collection of items (IPs, hostnames,
// strings, or ASNs) referenced by in_list/not_in_list operators in
// policy conditions and rate limit rules.
type ManagedList struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"` // unique, slug-safe
	Description string    `json:"description,omitempty"`
	Kind        string    `json:"kind"`   // "ip", "hostname", "string", "asn"
	Source      string    `json:"source"` // "manual", "url", "ipsum"
	URL         string    `json:"url,omitempty"`
	Items       []string  `json:"items"`
	ItemCount   int       `json:"item_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ManagedListExport wraps lists for import/export.
type ManagedListExport struct {
	Version    int           `json:"version"`
	ExportedAt time.Time     `json:"exported_at"`
	Lists      []ManagedList `json:"lists"`
}

// ─── Kind and Source Constants ───────────────────────────────────────

var validListKinds = map[string]bool{
	"ip":       true,
	"hostname": true,
	"string":   true,
	"asn":      true,
}

var validListSources = map[string]bool{
	"manual": true,
	"url":    true,
	"ipsum":  true,
}

// ─── Field-Kind Compatibility ───────────────────────────────────────

// fieldKindCompatibility maps condition fields to the list kinds they
// accept when used with in_list/not_in_list operators.
var fieldKindCompatibility = map[string]map[string]bool{
	"ip":      {"ip": true},
	"country": {"string": true},
	"host":    {"hostname": true, "string": true},
	// All other fields accept hostname, string, and asn.
}

// defaultCompatibleKinds is used for fields not explicitly listed above.
var defaultCompatibleKinds = map[string]bool{
	"hostname": true,
	"string":   true,
	"asn":      true,
}

// CompatibleKinds returns the list kinds compatible with a condition field.
func CompatibleKinds(field string) map[string]bool {
	if kinds, ok := fieldKindCompatibility[field]; ok {
		return kinds
	}
	return defaultCompatibleKinds
}
