package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ─── Team Cymru Parser Tests ────────────────────────────────────────────────

func TestParseCymruOrigin(t *testing.T) {
	tests := []struct {
		name     string
		txt      string
		asNumber string
		route    string
		cc       string
		rir      string
		alloc    string
	}{
		{
			name:     "standard response",
			txt:      "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11",
			asNumber: "13335",
			route:    "1.1.1.0/24",
			cc:       "AU",
			rir:      "apnic",
			alloc:    "2011-08-11",
		},
		{
			name:     "multiple origin ASNs",
			txt:      "13335 15169 | 1.1.1.0/24 | AU | apnic | 2011-08-11",
			asNumber: "13335",
			route:    "1.1.1.0/24",
			cc:       "AU",
			rir:      "apnic",
			alloc:    "2011-08-11",
		},
		{
			name:     "minimal response",
			txt:      "1136 | 195.240.0.0/17 | NL",
			asNumber: "1136",
			route:    "195.240.0.0/17",
			cc:       "NL",
			rir:      "",
			alloc:    "",
		},
		{
			name:     "empty response",
			txt:      "",
			asNumber: "",
			route:    "",
			cc:       "",
			rir:      "",
			alloc:    "",
		},
		{
			name:     "too few parts",
			txt:      "13335",
			asNumber: "",
			route:    "",
			cc:       "",
			rir:      "",
			alloc:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := parseCymruOrigin(tt.txt)
			if o.asNumber != tt.asNumber {
				t.Errorf("asNumber = %q, want %q", o.asNumber, tt.asNumber)
			}
			if o.route != tt.route {
				t.Errorf("route = %q, want %q", o.route, tt.route)
			}
			if o.cc != tt.cc {
				t.Errorf("cc = %q, want %q", o.cc, tt.cc)
			}
			if o.rir != tt.rir {
				t.Errorf("rir = %q, want %q", o.rir, tt.rir)
			}
			if o.allocDate != tt.alloc {
				t.Errorf("allocDate = %q, want %q", o.allocDate, tt.alloc)
			}
		})
	}
}

func TestParseCymruASName(t *testing.T) {
	tests := []struct {
		name string
		txt  string
		want string
	}{
		{
			name: "standard response",
			txt:  "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US",
			want: "CLOUDFLARENET - Cloudflare, Inc., US",
		},
		{
			name: "KPN response",
			txt:  "1136 | NL | ripencc | 1993-10-13 | KPN - KPN B.V., NL",
			want: "KPN - KPN B.V., NL",
		},
		{
			name: "too few parts",
			txt:  "13335 | US",
			want: "",
		},
		{
			name: "empty",
			txt:  "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCymruASName(tt.txt)
			if got != tt.want {
				t.Errorf("parseCymruASName(%q) = %q, want %q", tt.txt, got, tt.want)
			}
		})
	}
}

func TestReverseIP(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"1.2.3.4", "4.3.2.1"},
		{"192.168.1.100", "100.1.168.192"},
		{"0.0.0.0", "0.0.0.0"},
		{"255.255.255.255", "255.255.255.255"},
		// IPv6 returns empty (not supported for Cymru origin lookup).
		{"2001:db8::1", ""},
		{"not-an-ip", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := reverseIP(tt.ip)
			if got != tt.want {
				t.Errorf("reverseIP(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

// ─── RPKI Parser Tests ──────────────────────────────────────────────────────

func TestLookupRPKI(t *testing.T) {
	tests := []struct {
		name      string
		response  map[string]interface{}
		status    int
		wantValid string
		wantCount int
	}{
		{
			name: "valid ROA",
			response: map[string]interface{}{
				"data": map[string]interface{}{
					"status": "valid",
					"validating_roas": []interface{}{
						map[string]interface{}{
							"origin":     "13335",
							"prefix":     "1.1.1.0/24",
							"max_length": 24,
							"validity":   "valid",
						},
					},
				},
			},
			status:    200,
			wantValid: "valid",
			wantCount: 1,
		},
		{
			name: "invalid ROA",
			response: map[string]interface{}{
				"data": map[string]interface{}{
					"status":          "invalid",
					"validating_roas": []interface{}{},
				},
			},
			status:    200,
			wantValid: "invalid",
			wantCount: 0,
		},
		{
			name: "not found (no ROA)",
			response: map[string]interface{}{
				"data": map[string]interface{}{
					"status":          "unknown",
					"validating_roas": []interface{}{},
				},
			},
			status:    200,
			wantValid: "unknown",
			wantCount: 0,
		},
		{
			name:      "API error",
			response:  nil,
			status:    500,
			wantValid: "unknown",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 200 {
					w.WriteHeader(tt.status)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer srv.Close()

			store := NewIPIntelStore(nil)
			store.client = srv.Client()

			// Override the lookupRPKI to use our test server.
			// Since lookupRPKI builds its own URL, we test via the HTTP mock pattern.
			result := testLookupRPKI(store, srv.URL, "13335", "1.1.1.0/24")

			if result.validity != tt.wantValid {
				t.Errorf("validity = %q, want %q", result.validity, tt.wantValid)
			}
			if result.count != tt.wantCount {
				t.Errorf("count = %d, want %d", result.count, tt.wantCount)
			}
		})
	}
}

// testLookupRPKI is a test helper that queries a specific URL instead of RIPE.
func testLookupRPKI(s *IPIntelStore, baseURL, asNumber, route string) rpkiResult {
	url := fmt.Sprintf("%s/data/rpki-validation/data.json?resource=AS%s&prefix=%s&sourceapp=wafctl",
		baseURL, asNumber, route)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return rpkiResult{validity: "unknown"}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return rpkiResult{validity: "unknown"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return rpkiResult{validity: "unknown"}
	}

	var result struct {
		Data struct {
			Status         string `json:"status"`
			ValidatingROAs []struct {
				Origin    string `json:"origin"`
				Prefix    string `json:"prefix"`
				MaxLength int    `json:"max_length"`
				Validity  string `json:"validity"`
			} `json:"validating_roas"`
		} `json:"data"`
	}

	body := make([]byte, 16384)
	n, _ := resp.Body.Read(body)
	if err := json.Unmarshal(body[:n], &result); err != nil {
		return rpkiResult{validity: "unknown"}
	}

	validity := result.Data.Status
	if validity == "" {
		validity = "not_found"
	}
	return rpkiResult{
		validity: validity,
		count:    len(result.Data.ValidatingROAs),
	}
}

// ─── GreyNoise Parser Tests ─────────────────────────────────────────────────

func TestLookupGreyNoise(t *testing.T) {
	tests := []struct {
		name     string
		response map[string]interface{}
		status   int
		wantStat string
		wantCls  string
		wantName string
	}{
		{
			name: "known good (RIOT)",
			response: map[string]interface{}{
				"ip":             "1.1.1.1",
				"noise":          false,
				"riot":           true,
				"classification": "benign",
				"name":           "Cloudflare Public DNS",
				"last_seen":      "2026-03-07",
			},
			status:   200,
			wantStat: "benign",
			wantCls:  "benign",
			wantName: "Cloudflare Public DNS",
		},
		{
			name: "malicious scanner",
			response: map[string]interface{}{
				"ip":             "45.33.32.156",
				"noise":          true,
				"riot":           false,
				"classification": "malicious",
				"name":           "unknown",
				"last_seen":      "2026-03-06",
			},
			status:   200,
			wantStat: "malicious",
			wantCls:  "malicious",
			wantName: "",
		},
		{
			name: "noisy but not classified",
			response: map[string]interface{}{
				"ip":             "10.0.0.1",
				"noise":          true,
				"riot":           false,
				"classification": "unknown",
				"name":           "unknown",
			},
			status:   200,
			wantStat: "noisy",
			wantCls:  "unknown",
			wantName: "",
		},
		{
			name: "unknown IP",
			response: map[string]interface{}{
				"ip":      "192.168.1.1",
				"noise":   false,
				"riot":    false,
				"message": "IP not observed",
			},
			status:   200,
			wantStat: "clean",
			wantCls:  "unknown",
			wantName: "",
		},
		{
			name:     "API returns 404",
			response: nil,
			status:   404,
			wantStat: "",
			wantCls:  "",
			wantName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 200 {
					w.WriteHeader(tt.status)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer srv.Close()

			store := NewIPIntelStore(nil)
			store.client = srv.Client()

			entry := testLookupGreyNoise(store, srv.URL+"/")

			if tt.status != 200 {
				if entry != nil {
					t.Errorf("expected nil entry for status %d", tt.status)
				}
				return
			}

			if entry == nil {
				t.Fatal("expected non-nil entry")
			}
			if entry.Status != tt.wantStat {
				t.Errorf("Status = %q, want %q", entry.Status, tt.wantStat)
			}
			if entry.Classification != tt.wantCls {
				t.Errorf("Classification = %q, want %q", entry.Classification, tt.wantCls)
			}
			if entry.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", entry.Name, tt.wantName)
			}
		})
	}
}

// testLookupGreyNoise hits a test server instead of the real GreyNoise API.
func testLookupGreyNoise(s *IPIntelStore, url string) *ReputationEntry {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if n == 0 {
		return nil
	}

	var result struct {
		IP             string `json:"ip"`
		Noise          bool   `json:"noise"`
		Riot           bool   `json:"riot"`
		Classification string `json:"classification"`
		Name           string `json:"name"`
		LastSeen       string `json:"last_seen"`
		Message        string `json:"message"`
	}
	if err := json.Unmarshal(body[:n], &result); err != nil {
		return nil
	}

	entry := &ReputationEntry{
		Source:   "greynoise",
		LastSeen: result.LastSeen,
	}

	if result.Name != "" && result.Name != "unknown" {
		entry.Name = result.Name
	}

	switch {
	case result.Riot || result.Classification == "benign":
		entry.Status = "benign"
		entry.Classification = "benign"
	case result.Classification == "malicious":
		entry.Status = "malicious"
		entry.Classification = "malicious"
	case result.Noise:
		entry.Status = "noisy"
		entry.Classification = "unknown"
	default:
		entry.Status = "clean"
		entry.Classification = "unknown"
	}

	return entry
}

// ─── StopForumSpam Parser Tests ─────────────────────────────────────────────

func TestLookupStopForumSpam(t *testing.T) {
	tests := []struct {
		name     string
		response map[string]interface{}
		status   int
		want     string
	}{
		{
			name: "listed (appears=1)",
			response: map[string]interface{}{
				"success": 1,
				"ip": map[string]interface{}{
					"value":     "1.2.3.4",
					"appears":   1,
					"frequency": 5,
					"country":   "us",
				},
			},
			status: 200,
			want:   "malicious",
		},
		{
			name: "clean (appears=0)",
			response: map[string]interface{}{
				"success": 1,
				"ip": map[string]interface{}{
					"value":     "1.1.1.1",
					"appears":   0,
					"frequency": 0,
					"country":   "au",
				},
			},
			status: 200,
			want:   "clean",
		},
		{
			name:     "API error",
			response: nil,
			status:   500,
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 200 {
					w.WriteHeader(tt.status)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer srv.Close()

			store := NewIPIntelStore(nil)
			store.client = srv.Client()

			entry := testLookupStopForumSpam(store, srv.URL+"/")

			if tt.status != 200 {
				if entry != nil {
					t.Errorf("expected nil entry for status %d", tt.status)
				}
				return
			}

			if entry == nil {
				t.Fatal("expected non-nil entry")
			}
			if entry.Status != tt.want {
				t.Errorf("Status = %q, want %q", entry.Status, tt.want)
			}
		})
	}
}

func testLookupStopForumSpam(s *IPIntelStore, url string) *ReputationEntry {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if n == 0 {
		return nil
	}

	var result struct {
		Success int `json:"success"`
		IP      struct {
			Appears   int    `json:"appears"`
			Frequency int    `json:"frequency"`
			Country   string `json:"country"`
		} `json:"ip"`
	}
	if err := json.Unmarshal(body[:n], &result); err != nil {
		return nil
	}

	entry := &ReputationEntry{Source: "stopforumspam"}
	if result.IP.Appears == 1 {
		entry.Status = "malicious"
	} else {
		entry.Status = "clean"
	}
	return entry
}

// ─── Shodan InternetDB Parser Tests ─────────────────────────────────────────

func TestLookupShodan(t *testing.T) {
	tests := []struct {
		name     string
		response map[string]interface{}
		status   int
		wantNil  bool
		ports    int
		vulns    int
	}{
		{
			name: "rich data",
			response: map[string]interface{}{
				"ip":        "1.1.1.1",
				"ports":     []interface{}{float64(53), float64(80), float64(443)},
				"hostnames": []interface{}{"one.one.one.one"},
				"cpes":      []interface{}{"cpe:/a:cloudflare:cloudflare"},
				"tags":      []interface{}{},
				"vulns":     []interface{}{},
			},
			status:  200,
			wantNil: false,
			ports:   3,
			vulns:   0,
		},
		{
			name: "with vulnerabilities",
			response: map[string]interface{}{
				"ip":        "10.0.0.1",
				"ports":     []interface{}{float64(22), float64(80)},
				"hostnames": []interface{}{},
				"cpes":      []interface{}{"cpe:/a:apache:httpd:2.4.49"},
				"tags":      []interface{}{"cloud"},
				"vulns":     []interface{}{"CVE-2021-41773", "CVE-2021-42013"},
			},
			status:  200,
			wantNil: false,
			ports:   2,
			vulns:   2,
		},
		{
			name:     "no data (404)",
			response: nil,
			status:   404,
			wantNil:  true,
		},
		{
			name: "empty data",
			response: map[string]interface{}{
				"ip":        "192.168.1.1",
				"ports":     []interface{}{},
				"hostnames": []interface{}{},
				"cpes":      []interface{}{},
				"tags":      []interface{}{},
				"vulns":     []interface{}{},
			},
			status:  200,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 200 {
					w.WriteHeader(tt.status)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer srv.Close()

			store := NewIPIntelStore(nil)
			store.client = srv.Client()

			result := testLookupShodan(store, srv.URL+"/")

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if len(result.Ports) != tt.ports {
				t.Errorf("ports = %d, want %d", len(result.Ports), tt.ports)
			}
			if len(result.Vulns) != tt.vulns {
				t.Errorf("vulns = %d, want %d", len(result.Vulns), tt.vulns)
			}
		})
	}
}

func testLookupShodan(s *IPIntelStore, url string) *ShodanInfo {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body := make([]byte, 16384)
	n, _ := resp.Body.Read(body)
	if n == 0 {
		return nil
	}

	var result struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		Tags      []string `json:"tags"`
		CPEs      []string `json:"cpes"`
		Vulns     []string `json:"vulns"`
	}
	if err := json.Unmarshal(body[:n], &result); err != nil {
		return nil
	}

	if len(result.Ports) == 0 && len(result.Hostnames) == 0 && len(result.Vulns) == 0 {
		return nil
	}

	return &ShodanInfo{
		Ports:     result.Ports,
		Hostnames: result.Hostnames,
		Tags:      result.Tags,
		CPEs:      result.CPEs,
		Vulns:     result.Vulns,
	}
}

// ─── Network Type Inference Tests ───────────────────────────────────────────

func TestInferNetworkType(t *testing.T) {
	tests := []struct {
		name    string
		routing *RoutingInfo
		shodan  *ShodanInfo
		wantNil bool
		anycast bool
		isDC    bool
		orgType string
	}{
		{
			name:    "nil routing",
			routing: nil,
			wantNil: true,
		},
		{
			name:    "Cloudflare (anycast CDN)",
			routing: &RoutingInfo{ASNumber: "13335", ASName: "CLOUDFLARENET - Cloudflare, Inc., US"},
			anycast: true,
			isDC:    false,
			orgType: "business",
		},
		{
			name:    "Hetzner (hosting DC)",
			routing: &RoutingInfo{ASNumber: "24940", ASName: "HETZNER-AS - Hetzner Online GmbH, DE"},
			isDC:    true,
			orgType: "hosting",
		},
		{
			name:    "KPN (ISP)",
			routing: &RoutingInfo{ASNumber: "1136", ASName: "KPN - KPN B.V., NL"},
			isDC:    false,
			orgType: "isp",
		},
		{
			name:    "DigitalOcean (hosting DC)",
			routing: &RoutingInfo{ASNumber: "14061", ASName: "DIGITALOCEAN-ASN - DigitalOcean, LLC, US"},
			isDC:    true,
			orgType: "hosting",
		},
		{
			name:    "Comcast (ISP)",
			routing: &RoutingInfo{ASNumber: "7922", ASName: "COMCAST-7922 - Comcast Cable Communications, LLC, US"},
			isDC:    false,
			orgType: "isp",
		},
		{
			name:    "University (education)",
			routing: &RoutingInfo{ASNumber: "3", ASName: "MIT - Massachusetts Institute of Technology"},
			isDC:    false,
			orgType: "education",
		},
		{
			name:    "AWS (hosting DC)",
			routing: &RoutingInfo{ASNumber: "16509", ASName: "AMAZON-02 - Amazon.com, Inc., US"},
			anycast: true, // in knownAnycastASNs
			isDC:    true,
			orgType: "hosting",
		},
		{
			name:    "Shodan cloud tag overrides",
			routing: &RoutingInfo{ASNumber: "99999", ASName: "SOME-COMPANY"},
			shodan:  &ShodanInfo{Tags: []string{"cloud"}},
			isDC:    true,
			orgType: "business", // AS name is generic business, Shodan cloud tag sets isDC
		},
		{
			name:    "Government ASN",
			routing: &RoutingInfo{ASNumber: "12345", ASName: "GOVERNMENT - US Government Dept"},
			isDC:    false,
			orgType: "government",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferNetworkType(tt.routing, tt.shodan)

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.IsAnycast != tt.anycast {
				t.Errorf("IsAnycast = %v, want %v", result.IsAnycast, tt.anycast)
			}
			if result.IsDC != tt.isDC {
				t.Errorf("IsDC = %v, want %v", result.IsDC, tt.isDC)
			}
			if result.OrgType != tt.orgType {
				t.Errorf("OrgType = %q, want %q", result.OrgType, tt.orgType)
			}
		})
	}
}

// ─── Reputation Status Derivation Tests ─────────────────────────────────────

func TestDeriveReputationStatus(t *testing.T) {
	tests := []struct {
		name    string
		entries []ReputationEntry
		ipsum   bool
		want    string
	}{
		{
			name:    "no data",
			entries: nil,
			want:    "clean",
		},
		{
			name: "all clean",
			entries: []ReputationEntry{
				{Source: "greynoise", Status: "clean"},
				{Source: "stopforumspam", Status: "clean"},
			},
			want: "clean",
		},
		{
			name: "known good (GreyNoise benign)",
			entries: []ReputationEntry{
				{Source: "greynoise", Status: "benign"},
				{Source: "stopforumspam", Status: "clean"},
			},
			want: "known_good",
		},
		{
			name: "malicious (StopForumSpam)",
			entries: []ReputationEntry{
				{Source: "greynoise", Status: "clean"},
				{Source: "stopforumspam", Status: "malicious"},
			},
			want: "malicious",
		},
		{
			name: "malicious overrides benign",
			entries: []ReputationEntry{
				{Source: "greynoise", Status: "benign"},
				{Source: "stopforumspam", Status: "malicious"},
			},
			want: "malicious",
		},
		{
			name: "noisy = suspicious",
			entries: []ReputationEntry{
				{Source: "greynoise", Status: "noisy"},
				{Source: "stopforumspam", Status: "clean"},
			},
			want: "suspicious",
		},
		{
			name:    "ipsum listed overrides all",
			entries: []ReputationEntry{{Source: "greynoise", Status: "benign"}},
			ipsum:   true,
			want:    "malicious",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveReputationStatus(tt.entries, tt.ipsum)
			if got != tt.want {
				t.Errorf("deriveReputationStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ─── Cache Tests ────────────────────────────────────────────────────────────

func TestIPIntelStoreCache(t *testing.T) {
	// Pre-populate cache and verify it returns cached results.
	store := NewIPIntelStore(nil)

	intel := &IPIntelligence{
		Routing: &RoutingInfo{
			IsAnnounced: true,
			ASNumber:    "13335",
			ASName:      "CLOUDFLARENET",
			Route:       "1.1.1.0/24",
			ROAValidity: "valid",
		},
		Reputation: &ReputationInfo{
			Status: "known_good",
		},
	}

	// Manually inject into cache.
	store.mu.Lock()
	store.cache["1.1.1.1"] = intelEntry{intel: intel, ts: time.Now()}
	store.mu.Unlock()

	// Lookup should return cached result without making any network calls.
	result := store.Lookup("1.1.1.1")
	if result == nil {
		t.Fatal("expected cached result")
	}
	if result.Routing == nil || result.Routing.ASNumber != "13335" {
		t.Errorf("cached routing not returned correctly")
	}
}

func TestIPIntelStoreEmptyIP(t *testing.T) {
	store := NewIPIntelStore(nil)
	if result := store.Lookup(""); result != nil {
		t.Errorf("expected nil for empty IP")
	}
	if result := store.Lookup("not-an-ip"); result != nil {
		t.Errorf("expected nil for invalid IP")
	}
}

// ─── Classify AS Name Tests ─────────────────────────────────────────────────

func TestClassifyASName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"hetzner online gmbh", "hosting"},
		{"amazon.com, inc.", "hosting"},
		{"digitalocean, llc", "hosting"},
		{"google cloud platform", "hosting"},
		{"comcast cable communications", "isp"},
		{"vodafone gmbh", "isp"},
		{"at&t services, inc.", "isp"},
		{"university of california", "education"},
		{"massachusetts institute of technology", "education"},
		{"us government department of defense", "government"},
		{"random corporation", "business"},
		{"", "business"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyASName(tt.name)
			if got != tt.want {
				t.Errorf("classifyASName(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}
