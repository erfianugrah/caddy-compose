package main

import (
	"net/http"
)

// ─── Rule Templates ─────────────────────────────────────────────────────────
//
// Pre-configured rule sets that users can apply with one click. Templates
// generate RuleExclusion entries that are created in the ExclusionStore.
// This replaces Caddyfile snippets like (static_cache) with hot-reloadable
// response_header rules managed via the API.

// RuleTemplate describes a template that can be applied to create rules.
type RuleTemplate struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    string          `json:"category"` // "cache", "security", "cors", "custom"
	Rules       []RuleExclusion `json:"rules"`
}

// builtinTemplates returns the list of available rule templates.
func builtinTemplates() []RuleTemplate {
	return []RuleTemplate{
		cacheStaticAssetsTemplate(),
		cacheImmutableAssetsTemplate(),
		securityHeadersBaselineTemplate(),
		removeServerHeadersTemplate(),
	}
}

// ─── Cache Templates ────────────────────────────────────────────────

func cacheStaticAssetsTemplate() RuleTemplate {
	return RuleTemplate{
		ID:          "cache-static-assets",
		Name:        "Cache Static Assets",
		Description: "Set Cache-Control headers for fonts, images, CSS, JS, and media files. Uses set-if-absent (default) mode so upstream Cache-Control is preserved.",
		Category:    "cache",
		Rules: []RuleExclusion{
			{
				Name:    "Cache fonts (1 year, immutable)",
				Type:    "response_header",
				Phase:   "outbound",
				Enabled: true,
				Conditions: []Condition{
					{Field: "path", Operator: "regex", Value: `\.(woff2?|ttf|eot|otf)$`},
				},
				HeaderDefault: map[string]string{
					"Cache-Control": "public, max-age=31536000, immutable",
				},
			},
			{
				Name:    "Cache images (7 days + SWR)",
				Type:    "response_header",
				Phase:   "outbound",
				Enabled: true,
				Conditions: []Condition{
					{Field: "path", Operator: "regex", Value: `\.(png|jpe?g|gif|webp|avif|svg|ico)$`},
				},
				HeaderDefault: map[string]string{
					"Cache-Control": "public, max-age=604800, stale-while-revalidate=86400",
				},
			},
			{
				Name:    "Cache CSS/JS (7 days + SWR)",
				Type:    "response_header",
				Phase:   "outbound",
				Enabled: true,
				Conditions: []Condition{
					{Field: "path", Operator: "regex", Value: `\.(css|js)$`},
				},
				HeaderDefault: map[string]string{
					"Cache-Control": "public, max-age=604800, stale-while-revalidate=86400",
				},
			},
			{
				Name:    "Cache media (30 days + SWR)",
				Type:    "response_header",
				Phase:   "outbound",
				Enabled: true,
				Conditions: []Condition{
					{Field: "path", Operator: "regex", Value: `\.(mp[34]|flac|mkv|avi|ogg|opus|wav|aac|webm)$`},
				},
				HeaderDefault: map[string]string{
					"Cache-Control": "public, max-age=2592000, stale-while-revalidate=86400",
				},
			},
		},
	}
}

func cacheImmutableAssetsTemplate() RuleTemplate {
	return RuleTemplate{
		ID:          "cache-immutable-hashed",
		Name:        "Cache Hashed/Immutable Assets",
		Description: "Set immutable Cache-Control for framework build output (Astro /_astro/, Vite /assets/, Next.js /_next/static/).",
		Category:    "cache",
		Rules: []RuleExclusion{
			{
				Name:    "Immutable hashed assets",
				Type:    "response_header",
				Phase:   "outbound",
				Enabled: true,
				Conditions: []Condition{
					{Field: "path", Operator: "regex", Value: `^/(_astro|assets|_next/static)/`},
				},
				HeaderSet: map[string]string{
					"Cache-Control": "public, max-age=31536000, immutable",
				},
			},
		},
	}
}

// ─── Security Templates ─────────────────────────────────────────────

func securityHeadersBaselineTemplate() RuleTemplate {
	return RuleTemplate{
		ID:          "security-headers-baseline",
		Name:        "Security Headers Baseline",
		Description: "Standard security headers: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP.",
		Category:    "security",
		Rules: []RuleExclusion{
			{
				Name:    "Security headers baseline",
				Type:    "response_header",
				Phase:   "outbound",
				Enabled: true,
				HeaderSet: map[string]string{
					"Strict-Transport-Security":         "max-age=63072000; includeSubDomains; preload",
					"X-Content-Type-Options":            "nosniff",
					"X-Frame-Options":                   "SAMEORIGIN",
					"Referrer-Policy":                   "strict-origin-when-cross-origin",
					"Permissions-Policy":                "camera=(), microphone=(), geolocation=(), payment=()",
					"Cross-Origin-Opener-Policy":        "same-origin",
					"Cross-Origin-Resource-Policy":      "cross-origin",
					"X-Permitted-Cross-Domain-Policies": "none",
				},
			},
		},
	}
}

func removeServerHeadersTemplate() RuleTemplate {
	return RuleTemplate{
		ID:          "remove-server-headers",
		Name:        "Remove Server Info Headers",
		Description: "Strip Server and X-Powered-By headers to reduce information disclosure.",
		Category:    "security",
		Rules: []RuleExclusion{
			{
				Name:    "Remove server info headers",
				Type:    "response_header",
				Phase:   "outbound",
				Enabled: true,
				HeaderRemove: []string{
					"Server",
					"X-Powered-By",
				},
			},
		},
	}
}

// ─── Handlers ───────────────────────────────────────────────────────

// handleListTemplates returns the list of available rule templates.
func handleListTemplates() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, builtinTemplates())
	}
}

// handleApplyTemplate creates all rules from a template in the ExclusionStore.
func handleApplyTemplate(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		templateID := r.PathValue("id")

		var found *RuleTemplate
		for _, t := range builtinTemplates() {
			if t.ID == templateID {
				found = &t
				break
			}
		}
		if found == nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "template not found"})
			return
		}

		var created []RuleExclusion
		for _, rule := range found.Rules {
			if err := validateExclusion(rule); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{
					Error:   "template rule validation failed",
					Details: err.Error(),
				})
				return
			}
			result, err := es.Create(rule)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{
					Error:   "failed to create rule from template",
					Details: err.Error(),
				})
				return
			}
			created = append(created, result)
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"template": found.Name,
			"created":  len(created),
			"rules":    created,
		})
	}
}
