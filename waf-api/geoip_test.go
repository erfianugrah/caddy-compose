package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)


// ─── GeoIP Tests ─────────────────────────────────────────────────────────────

func TestGeoIPStore_ResolveWithCFHeader(t *testing.T) {
	store := NewGeoIPStore("", nil) // no MMDB

	// CF header takes priority
	if got := store.Resolve("1.2.3.4", "DE"); got != "DE" {
		t.Errorf("Resolve with CF header = %q, want DE", got)
	}
	// Lowercase CF header is uppercased
	if got := store.Resolve("1.2.3.4", "de"); got != "DE" {
		t.Errorf("Resolve with lowercase CF header = %q, want DE", got)
	}
	// XX (unknown) is ignored
	if got := store.Resolve("1.2.3.4", "XX"); got != "" {
		t.Errorf("Resolve with XX = %q, want empty", got)
	}
	// T1 (Tor) is ignored
	if got := store.Resolve("1.2.3.4", "T1"); got != "" {
		t.Errorf("Resolve with T1 = %q, want empty", got)
	}
	// Empty header, no MMDB → empty
	if got := store.Resolve("1.2.3.4", ""); got != "" {
		t.Errorf("Resolve with no header = %q, want empty", got)
	}
}



func TestGeoIPStore_LookupIPNoDB(t *testing.T) {
	store := NewGeoIPStore("", nil)
	if got := store.LookupIP("8.8.8.8"); got != "" {
		t.Errorf("LookupIP with no DB = %q, want empty", got)
	}
}



func TestGeoIPStore_HasDB(t *testing.T) {
	store := NewGeoIPStore("", nil)
	if store.HasDB() {
		t.Error("HasDB() should be false with no MMDB")
	}
}



func TestGeoIPStore_CacheBehavior(t *testing.T) {
	store := NewGeoIPStore("", nil) // no MMDB, but we can test cache directly
	// Manually inject a cache entry
	store.mu.Lock()
	store.cache["1.2.3.4"] = geoEntry{country: "US", ts: time.Now()}
	store.mu.Unlock()

	// LookupIP should return cached value even without MMDB
	if got := store.LookupIP("1.2.3.4"); got != "US" {
		t.Errorf("LookupIP cached = %q, want US", got)
	}
}



func TestGeoIPStore_CacheEviction(t *testing.T) {
	store := NewGeoIPStore("", nil)
	store.mu.Lock()
	// Fill cache to max
	for i := 0; i < geoCacheMaxSize; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		store.cache[ip] = geoEntry{country: "XX", ts: time.Now()}
	}
	// Manually trigger eviction
	store.evictRandom()
	size := len(store.cache)
	store.mu.Unlock()

	expected := geoCacheMaxSize - geoCacheMaxSize/4
	if size != expected {
		t.Errorf("cache size after eviction = %d, want %d", size, expected)
	}
}



func TestTopCountries(t *testing.T) {
	events := []Event{
		{ID: "1", Country: "US", IsBlocked: true},
		{ID: "2", Country: "US", IsBlocked: false},
		{ID: "3", Country: "DE", IsBlocked: true},
		{ID: "4", Country: "DE", IsBlocked: true},
		{ID: "5", Country: "DE", IsBlocked: false},
		{ID: "6", Country: "", IsBlocked: false},
		{ID: "7", Country: "JP", IsBlocked: false},
	}

	result := TopCountries(events, 10)
	if len(result) != 4 {
		t.Fatalf("TopCountries returned %d entries, want 4", len(result))
	}

	// DE should be first (3 events)
	if result[0].Country != "DE" {
		t.Errorf("result[0].Country = %q, want DE", result[0].Country)
	}
	if result[0].Count != 3 {
		t.Errorf("result[0].Count = %d, want 3", result[0].Count)
	}
	if result[0].Blocked != 2 {
		t.Errorf("result[0].Blocked = %d, want 2", result[0].Blocked)
	}

	// US should be second (2 events)
	if result[1].Country != "US" {
		t.Errorf("result[1].Country = %q, want US", result[1].Country)
	}
	if result[1].Count != 2 {
		t.Errorf("result[1].Count = %d, want 2", result[1].Count)
	}
}



func TestTopCountries_Limit(t *testing.T) {
	events := []Event{
		{ID: "1", Country: "US"},
		{ID: "2", Country: "DE"},
		{ID: "3", Country: "JP"},
		{ID: "4", Country: "FR"},
	}
	result := TopCountries(events, 2)
	if len(result) != 2 {
		t.Errorf("TopCountries with limit=2 returned %d, want 2", len(result))
	}
}



func TestTopCountries_EmptyCountryBecomesXX(t *testing.T) {
	events := []Event{
		{ID: "1", Country: ""},
		{ID: "2", Country: ""},
	}
	result := TopCountries(events, 10)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
	if result[0].Country != "XX" {
		t.Errorf("empty country mapped to %q, want XX", result[0].Country)
	}
}



func TestSummarizeEvents_IncludesTopCountries(t *testing.T) {
	events := []Event{
		{ID: "1", Country: "US", EventType: "blocked", IsBlocked: true, Timestamp: time.Now()},
		{ID: "2", Country: "DE", EventType: "logged", IsBlocked: false, Timestamp: time.Now()},
		{ID: "3", Country: "US", EventType: "logged", IsBlocked: false, Timestamp: time.Now()},
	}
	summary := summarizeEvents(events)
	if len(summary.TopCountries) == 0 {
		t.Fatal("TopCountries is empty in summary")
	}
	if summary.TopCountries[0].Country != "US" {
		t.Errorf("TopCountries[0] = %q, want US", summary.TopCountries[0].Country)
	}
	if summary.TopCountries[0].Count != 2 {
		t.Errorf("TopCountries[0].Count = %d, want 2", summary.TopCountries[0].Count)
	}
}



func TestTopBlockedIPs_IncludesCountry(t *testing.T) {
	s := NewStore("")
	s.mu.Lock()
	s.events = []Event{
		{ID: "1", ClientIP: "1.2.3.4", Country: "US", IsBlocked: true, Timestamp: time.Now()},
		{ID: "2", ClientIP: "1.2.3.4", Country: "US", IsBlocked: false, Timestamp: time.Now()},
		{ID: "3", ClientIP: "5.6.7.8", Country: "DE", IsBlocked: true, Timestamp: time.Now()},
	}
	s.mu.Unlock()

	result := s.TopBlockedIPs(168, 10)
	if len(result) != 2 {
		t.Fatalf("TopBlockedIPs returned %d, want 2", len(result))
	}
	for _, r := range result {
		if r.ClientIP == "1.2.3.4" && r.Country != "US" {
			t.Errorf("1.2.3.4 country = %q, want US", r.Country)
		}
		if r.ClientIP == "5.6.7.8" && r.Country != "DE" {
			t.Errorf("5.6.7.8 country = %q, want DE", r.Country)
		}
	}
}



func TestSummaryClientCountsIncludeCountry(t *testing.T) {
	events := []Event{
		{ID: "1", ClientIP: "1.2.3.4", Country: "JP", EventType: "blocked", IsBlocked: true, Timestamp: time.Now()},
		{ID: "2", ClientIP: "1.2.3.4", Country: "JP", EventType: "logged", IsBlocked: false, Timestamp: time.Now()},
	}
	summary := summarizeEvents(events)
	if len(summary.TopClients) == 0 {
		t.Fatal("TopClients is empty")
	}
	if summary.TopClients[0].Country != "JP" {
		t.Errorf("TopClients[0].Country = %q, want JP", summary.TopClients[0].Country)
	}
}



func TestRateLimitEventToEvent_PropagatesCountry(t *testing.T) {
	rle := RateLimitEvent{
		Timestamp: time.Now(),
		ClientIP:  "10.0.0.1",
		Country:   "FR",
		Service:   "example.com",
		Method:    "GET",
		URI:       "/test",
		UserAgent: "curl/8.0",
	}
	ev := RateLimitEventToEvent(rle)
	if ev.Country != "FR" {
		t.Errorf("Event.Country = %q, want FR", ev.Country)
	}
}



func TestHandleTopCountries(t *testing.T) {
	s := NewStore("")
	s.mu.Lock()
	s.events = []Event{
		{ID: "1", Country: "US", EventType: "blocked", IsBlocked: true, Timestamp: time.Now()},
		{ID: "2", Country: "US", EventType: "logged", IsBlocked: false, Timestamp: time.Now()},
		{ID: "3", Country: "DE", EventType: "blocked", IsBlocked: true, Timestamp: time.Now()},
	}
	s.mu.Unlock()

	als := NewAccessLogStore("")

	handler := handleTopCountries(s, als)
	req := httptest.NewRequest("GET", "/api/analytics/top-countries?hours=168&limit=10", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var result []CountryCount
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("got %d countries, want 2", len(result))
	}
	// US has 2 events, DE has 1
	if result[0].Country != "US" || result[0].Count != 2 {
		t.Errorf("result[0] = %+v, want US:2", result[0])
	}
}

// ─── Per-Hour/Service/Client Breakdown Tests ─────────────────────────────────



// --- GeoIP Online API Fallback Tests ---

func TestGeoIPStore_OnlineAPIFallback(t *testing.T) {
	// Mock API server that returns IPinfo-style JSON.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract IP from path (e.g., /1.2.3.4)
		ip := strings.TrimPrefix(r.URL.Path, "/")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ip":"%s","country":"DE"}`, ip)
	}))
	defer srv.Close()

	store := NewGeoIPStore("", &GeoIPAPIConfig{URL: srv.URL + "/%s"})

	// No CF header, no MMDB — should use online API.
	country := store.Resolve("1.2.3.4", "")
	if country != "DE" {
		t.Errorf("Resolve() = %q, want DE", country)
	}

	// CF header should still take priority.
	country = store.Resolve("1.2.3.4", "US")
	if country != "US" {
		t.Errorf("Resolve() with CF header = %q, want US", country)
	}
}



func TestGeoIPStore_OnlineAPICaching(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"country":"FR"}`)
	}))
	defer srv.Close()

	store := NewGeoIPStore("", &GeoIPAPIConfig{URL: srv.URL + "/%s"})

	// First call hits the API.
	c1 := store.Resolve("5.6.7.8", "")
	if c1 != "FR" {
		t.Errorf("first Resolve() = %q, want FR", c1)
	}
	if callCount != 1 {
		t.Errorf("expected 1 API call, got %d", callCount)
	}

	// Second call should be served from cache.
	c2 := store.Resolve("5.6.7.8", "")
	if c2 != "FR" {
		t.Errorf("second Resolve() = %q, want FR", c2)
	}
	if callCount != 1 {
		t.Errorf("expected cache hit (still 1 API call), got %d", callCount)
	}
}



func TestGeoIPStore_OnlineAPIError(t *testing.T) {
	// Server that returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	store := NewGeoIPStore("", &GeoIPAPIConfig{URL: srv.URL + "/%s"})

	// Should gracefully return "" on API error.
	country := store.Resolve("9.8.7.6", "")
	if country != "" {
		t.Errorf("Resolve() on API error = %q, want empty", country)
	}
}



func TestGeoIPStore_OnlineAPIBearerAuth(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"country":"JP"}`)
	}))
	defer srv.Close()

	store := NewGeoIPStore("", &GeoIPAPIConfig{URL: srv.URL + "/%s", Key: "test-key-123"})
	store.Resolve("1.1.1.1", "")

	if receivedAuth != "Bearer test-key-123" {
		t.Errorf("Authorization header = %q, want 'Bearer test-key-123'", receivedAuth)
	}
}



func TestGeoIPStore_OnlineAPICountryCodeFormats(t *testing.T) {
	// Test different JSON field names for country code.
	tests := []struct {
		name     string
		jsonBody string
		want     string
	}{
		{"ipinfo style", `{"country":"US"}`, "US"},
		{"ip-api style", `{"countryCode":"GB"}`, "GB"},
		{"underscore style", `{"country_code":"BR"}`, "BR"},
		{"lowercase country", `{"country":"de"}`, "DE"},
		{"no country field", `{"ip":"1.2.3.4"}`, ""},
		{"invalid JSON", `not json`, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tc.jsonBody)
			}))
			defer srv.Close()

			store := NewGeoIPStore("", &GeoIPAPIConfig{URL: srv.URL + "/%s"})
			country := store.Resolve("1.2.3.4", "")
			if country != tc.want {
				t.Errorf("got %q, want %q", country, tc.want)
			}
		})
	}
}



func TestGeoIPStore_OnlineAPIURLFormat(t *testing.T) {
	var receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"country":"AU"}`)
	}))
	defer srv.Close()

	// Test URL without %s placeholder — should append IP as path segment.
	store := NewGeoIPStore("", &GeoIPAPIConfig{URL: srv.URL})
	store.Resolve("10.20.30.40", "")

	if receivedPath != "/10.20.30.40" {
		t.Errorf("URL path = %q, want /10.20.30.40", receivedPath)
	}
}



func TestGeoIPStore_HasAPI(t *testing.T) {
	// No API configured.
	s1 := NewGeoIPStore("", nil)
	if s1.HasAPI() {
		t.Error("HasAPI() should be false with nil config")
	}

	// API configured.
	s2 := NewGeoIPStore("", &GeoIPAPIConfig{URL: "https://example.com"})
	if !s2.HasAPI() {
		t.Error("HasAPI() should be true with URL configured")
	}

	// Empty URL — should not enable API.
	s3 := NewGeoIPStore("", &GeoIPAPIConfig{URL: ""})
	if s3.HasAPI() {
		t.Error("HasAPI() should be false with empty URL")
	}
}

// ─── Tests for audit fix changes ──────────────────────────────────
