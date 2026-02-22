package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	logPath := envOr("WAF_AUDIT_LOG", "/var/log/coraza-audit.log")
	port := envOr("WAF_API_PORT", "8080")
	exclusionsFile := envOr("WAF_EXCLUSIONS_FILE", "/data/exclusions.json")
	configFile := envOr("WAF_CONFIG_FILE", "/data/waf-config.json")

	deployCfg := DeployConfig{
		CorazaDir:     envOr("WAF_CORAZA_DIR", "/data/coraza"),
		CaddyfilePath: envOr("WAF_CADDYFILE_PATH", "/data/Caddyfile"),
		CaddyAdminURL: envOr("WAF_CADDY_ADMIN_URL", "http://caddy:2019"),
	}

	// Ensure custom coraza config directory and placeholder files exist.
	if err := ensureCorazaDir(deployCfg.CorazaDir); err != nil {
		log.Printf("warning: could not initialize coraza dir: %v", err)
	}

	log.Printf("waf-api starting: log=%s port=%s exclusions=%s config=%s coraza_dir=%s",
		logPath, port, exclusionsFile, configFile, deployCfg.CorazaDir)

	store := NewStore(logPath)
	store.StartTailing(30 * time.Second)

	exclusionStore := NewExclusionStore(exclusionsFile)
	configStore := NewConfigStore(configFile)

	mux := http.NewServeMux()

	// Existing endpoints (with hours filter support)
	mux.HandleFunc("GET /api/health", handleHealth)
	mux.HandleFunc("GET /api/summary", handleSummary(store))
	mux.HandleFunc("GET /api/events", handleEvents(store))
	mux.HandleFunc("GET /api/services", handleServices(store))

	// Analytics
	mux.HandleFunc("GET /api/analytics/top-ips", handleTopBlockedIPs(store))
	mux.HandleFunc("GET /api/analytics/top-uris", handleTopTargetedURIs(store))

	// IP Lookup
	mux.HandleFunc("GET /api/lookup/{ip}", handleIPLookup(store))

	// Exclusion CRUD
	mux.HandleFunc("GET /api/exclusions", handleListExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions", handleCreateExclusion(exclusionStore))
	mux.HandleFunc("GET /api/exclusions/export", handleExportExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions/import", handleImportExclusions(exclusionStore))
	mux.HandleFunc("POST /api/exclusions/generate", handleGenerateExclusions(exclusionStore))
	mux.HandleFunc("GET /api/exclusions/{id}", handleGetExclusion(exclusionStore))
	mux.HandleFunc("PUT /api/exclusions/{id}", handleUpdateExclusion(exclusionStore))
	mux.HandleFunc("DELETE /api/exclusions/{id}", handleDeleteExclusion(exclusionStore))

	// CRS Catalog
	mux.HandleFunc("GET /api/crs/rules", handleCRSRules)
	mux.HandleFunc("GET /api/crs/autocomplete", handleCRSAutocomplete)

	// WAF Config
	mux.HandleFunc("GET /api/config", handleGetConfig(configStore))
	mux.HandleFunc("PUT /api/config", handleUpdateConfig(configStore))
	mux.HandleFunc("POST /api/config/generate", handleGenerateConfig(configStore, exclusionStore))
	mux.HandleFunc("POST /api/config/deploy", handleDeploy(configStore, exclusionStore, deployCfg))

	handler := corsMiddleware(mux)

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- CORS middleware ---

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// --- Query parameter helpers ---

// parseHours extracts and validates the ?hours= query parameter.
// Returns 0 (meaning "all time") if not provided or invalid.
func parseHours(r *http.Request) int {
	s := r.URL.Query().Get("hours")
	if s == "" {
		return 0
	}
	h, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	if !validHours[h] {
		return 0
	}
	return h
}

// --- Handlers: Event endpoints ---

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{Status: "ok"})
}

func handleSummary(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := parseHours(r)
		writeJSON(w, http.StatusOK, store.Summary(hours))
	}
}

func handleEvents(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		service := q.Get("service")
		client := q.Get("client")
		method := q.Get("method")

		var blocked *bool
		if b := q.Get("blocked"); b != "" {
			val := strings.EqualFold(b, "true") || b == "1"
			blocked = &val
		}

		limit := queryInt(q.Get("limit"), 50)
		if limit <= 0 || limit > 1000 {
			limit = 50
		}
		offset := queryInt(q.Get("offset"), 0)
		if offset < 0 {
			offset = 0
		}

		hours := parseHours(r)
		result := store.FilteredEvents(service, client, method, blocked, limit, offset, hours)
		writeJSON(w, http.StatusOK, result)
	}
}

func handleServices(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := parseHours(r)
		writeJSON(w, http.StatusOK, store.Services(hours))
	}
}

// --- Handlers: Analytics ---

func handleTopBlockedIPs(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		writeJSON(w, http.StatusOK, store.TopBlockedIPs(hours, limit))
	}
}

func handleTopTargetedURIs(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := parseHours(r)
		limit := queryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		writeJSON(w, http.StatusOK, store.TopTargetedURIs(hours, limit))
	}
}

// --- Handler: IP Lookup ---

func handleIPLookup(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.PathValue("ip")
		if ip == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "IP address is required"})
			return
		}
		// Basic IP validation.
		if net.ParseIP(ip) == nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid IP address"})
			return
		}
		hours := parseHours(r)
		result := store.IPLookup(ip, hours)
		writeJSON(w, http.StatusOK, result)
	}
}

// --- Handlers: Exclusion CRUD ---

func handleListExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, es.List())
	}
}

func handleGetExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		exc, found := es.Get(id)
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}
		writeJSON(w, http.StatusOK, exc)
	}
}

func handleCreateExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var exc RuleExclusion
		if err := json.NewDecoder(r.Body).Decode(&exc); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON body", Details: err.Error()})
			return
		}
		if err := validateExclusion(exc); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		created, err := es.Create(exc)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to create exclusion", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func handleUpdateExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var exc RuleExclusion
		if err := json.NewDecoder(r.Body).Decode(&exc); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON body", Details: err.Error()})
			return
		}
		if err := validateExclusion(exc); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		updated, found, err := es.Update(id, exc)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update exclusion", Details: err.Error()})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func handleDeleteExclusion(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		found, err := es.Delete(id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to delete exclusion", Details: err.Error()})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "exclusion not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleGenerateExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		exclusions := es.EnabledExclusions()
		// Generate with a default config — this endpoint is exclusion-only.
		result := GenerateConfigs(defaultConfig(), exclusions)
		writeJSON(w, http.StatusOK, result)
	}
}

func handleExportExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, es.Export())
	}
}

func handleImportExclusions(es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var export ExclusionExport
		if err := json.NewDecoder(r.Body).Decode(&export); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON body", Details: err.Error()})
			return
		}
		if len(export.Exclusions) == 0 {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "no exclusions in import data"})
			return
		}
		// Validate all exclusions before importing.
		for i, exc := range export.Exclusions {
			if err := validateExclusion(exc); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{
					Error:   "validation failed",
					Details: "exclusion " + strconv.Itoa(i) + ": " + err.Error(),
				})
				return
			}
		}
		if err := es.Import(export.Exclusions); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to import exclusions", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"imported": len(export.Exclusions)})
	}
}

// --- Handlers: CRS Catalog ---

func handleCRSRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, GetCRSCatalog())
}

func handleCRSAutocomplete(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, GetCRSAutocomplete())
}

// --- Handlers: WAF Config ---

func handleGetConfig(cs *ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, cs.Get())
	}
}

func handleUpdateConfig(cs *ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg WAFConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON body", Details: err.Error()})
			return
		}
		if err := validateConfig(cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		updated, err := cs.Update(cfg)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to update config", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

// --- Handler: Generate Config ---

func handleGenerateConfig(cs *ConfigStore, es *ExclusionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		cfg := cs.Get()
		exclusions := es.EnabledExclusions()
		ResetRuleIDCounter()
		result := GenerateConfigs(cfg, exclusions)
		writeJSON(w, http.StatusOK, result)
	}
}

// --- Handler: Deploy ---

func handleDeploy(cs *ConfigStore, es *ExclusionStore, deployCfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		cfg := cs.Get()
		exclusions := es.EnabledExclusions()
		ResetRuleIDCounter()
		result := GenerateConfigs(cfg, exclusions)

		// Write config files to the shared volume.
		if err := writeConfFiles(deployCfg.CorazaDir, result.PreCRS, result.PostCRS); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error:   "failed to write config files",
				Details: err.Error(),
			})
			return
		}

		// Reload Caddy via admin API.
		reloaded := true
		if err := reloadCaddy(deployCfg.CaddyfilePath, deployCfg.CaddyAdminURL); err != nil {
			log.Printf("warning: Caddy reload failed: %v", err)
			reloaded = false
			// Don't fail the request — files were written successfully.
			// The user can manually reload or investigate.
		}

		status := "deployed"
		msg := "Config files written and Caddy reloaded successfully"
		if !reloaded {
			status = "partial"
			msg = "Config files written but Caddy reload failed — manual reload may be needed"
		}

		writeJSON(w, http.StatusOK, DeployResponse{
			Status:    status,
			Message:   msg,
			PreCRS:    filepath.Join(deployCfg.CorazaDir, "custom-pre-crs.conf"),
			PostCRS:   filepath.Join(deployCfg.CorazaDir, "custom-post-crs.conf"),
			Reloaded:  reloaded,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Printf("error encoding JSON response: %v", err)
	}
}

func queryInt(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}
