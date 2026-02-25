package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)


// --- CRS Catalog endpoint tests ---

func TestCRSRulesEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/crs/rules", handleCRSRules)

	req := httptest.NewRequest("GET", "/api/crs/rules", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var catalog CRSCatalogResponse
	if err := json.NewDecoder(rec.Body).Decode(&catalog); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if catalog.Total == 0 {
		t.Error("expected non-zero total rules")
	}
	if len(catalog.Categories) == 0 {
		t.Error("expected non-empty categories")
	}
	if len(catalog.Rules) != catalog.Total {
		t.Errorf("rules length %d != total %d", len(catalog.Rules), catalog.Total)
	}
	// Verify a known rule exists.
	found := false
	for _, r := range catalog.Rules {
		if r.ID == "920420" {
			found = true
			if r.Category != "protocol-enforcement" {
				t.Errorf("rule 920420: expected category protocol-enforcement, got %s", r.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected rule 920420 in catalog")
	}
}



func TestCRSAutocompleteEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/crs/autocomplete", handleCRSAutocomplete)

	req := httptest.NewRequest("GET", "/api/crs/autocomplete", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var ac CRSAutocompleteResponse
	if err := json.NewDecoder(rec.Body).Decode(&ac); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(ac.Variables) == 0 {
		t.Error("expected non-empty variables")
	}
	if len(ac.Operators) == 0 {
		t.Error("expected non-empty operators")
	}
	if len(ac.Actions) == 0 {
		t.Error("expected non-empty actions")
	}
	// Verify operators have human-readable labels.
	for _, op := range ac.Operators {
		if op.Label == "" {
			t.Errorf("operator %s has empty label", op.Name)
		}
	}
}

// --- Rule match (messages) parsing tests ---



// --- Rule match (messages) parsing tests ---

func TestParseEventWithMessages(t *testing.T) {
	// Audit log entry with messages array (part H)
	logLine := `{"transaction":{"timestamp":"2026/02/22 09:00:00","unix_timestamp":1771750800000000000,"id":"MSG111","client_ip":"10.0.0.1","client_port":0,"host_ip":"","host_port":0,"server_id":"radarr.erfi.io","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/.env","http_version":"","headers":{"User-Agent":["curl/7.68"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":403,"headers":{},"body":""},"producer":{"connector":"","version":"","server":"","rule_engine":"On","stopwatch":"","rulesets":["OWASP_CRS/4.15.0"]},"highest_severity":"","is_interrupted":true},"messages":[{"actionset":"","message":"","data":{"file":"REQUEST-930-APPLICATION-ATTACK-LFI.conf","line":100,"id":930120,"rev":"","msg":"OS File Access Attempt","data":"Matched Data: .env found within REQUEST_FILENAME: /.env","severity":2,"ver":"OWASP_CRS/4.15.0","tags":["attack-lfi","OWASP_CRS"]}},{"actionset":"","message":"","data":{"file":"REQUEST-949-BLOCKING-EVALUATION.conf","line":1,"id":949110,"rev":"","msg":"Inbound Anomaly Score Exceeded","data":"","severity":0,"ver":"","tags":["anomaly-evaluation"]}}]}`

	path := writeTempLog(t, []string{logLine})
	store := NewStore(path)
	store.Load()

	events := store.FilteredEvents("", "", "", nil, 50, 0, 0)
	if events.Total != 1 {
		t.Fatalf("expected 1 event, got %d", events.Total)
	}

	ev := events.Events[0]
	// Should pick rule 930120 (the real detection rule), not 949110 (anomaly scoring)
	if ev.RuleID != 930120 {
		t.Errorf("expected rule_id=930120, got %d", ev.RuleID)
	}
	if ev.RuleMsg != "OS File Access Attempt" {
		t.Errorf("expected rule_msg='OS File Access Attempt', got %q", ev.RuleMsg)
	}
	if ev.Severity != 2 {
		t.Errorf("expected severity=2, got %d", ev.Severity)
	}
	if !strings.Contains(ev.MatchedData, ".env") {
		t.Errorf("expected matched_data to contain '.env', got %q", ev.MatchedData)
	}
	if len(ev.RuleTags) == 0 {
		t.Error("expected non-empty rule_tags")
	}
}



func TestParseEventWithoutMessages(t *testing.T) {
	// Original format without messages — should still work with zero values
	path := writeTempLog(t, sampleLines[:1])
	store := NewStore(path)
	store.Load()

	events := store.FilteredEvents("", "", "", nil, 50, 0, 0)
	if events.Total != 1 {
		t.Fatalf("expected 1 event, got %d", events.Total)
	}

	ev := events.Events[0]
	if ev.RuleID != 0 {
		t.Errorf("expected rule_id=0 (no messages), got %d", ev.RuleID)
	}
	if ev.RuleMsg != "" {
		t.Errorf("expected empty rule_msg, got %q", ev.RuleMsg)
	}
}

// --- Rate Limit Store tests ---
