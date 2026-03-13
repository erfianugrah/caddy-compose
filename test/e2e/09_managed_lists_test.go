package e2e_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// 18. Managed Lists CRUD
// ════════════════════════════════════════════════════════════════════

func TestManagedListsCRUD(t *testing.T) {
	// List — initially empty (or whatever exists).
	t.Run("list empty", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists")
		assertCode(t, "list", 200, resp)
		n := jsonArrayLen(body)
		t.Logf("existing managed lists: %d", n)
	})

	// Create an IP list — must return 201.
	var listID string
	t.Run("create IP list", func(t *testing.T) {
		payload := map[string]any{
			"name":        "e2e-test-ips",
			"description": "E2E test IP list",
			"kind":        "ip",
			"source":      "manual",
			"items":       []string{"10.0.0.1", "192.168.1.0/24", "172.16.0.5"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "create IP list", 201, resp)
		listID = mustGetID(t, body)
		assertField(t, "create", body, "name", "e2e-test-ips")
		assertField(t, "create", body, "kind", "ip")
		assertField(t, "create", body, "source", "manual")
		count := jsonInt(body, "item_count")
		if count != 3 {
			t.Errorf("expected item_count=3, got %d", count)
		}
	})

	if listID == "" {
		t.Fatal("no list ID, cannot continue CRUD tests")
	}
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+listID) })

	// Get by ID.
	t.Run("get", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists/"+listID)
		assertCode(t, "get", 200, resp)
		assertField(t, "get", body, "id", listID)
		assertField(t, "get", body, "name", "e2e-test-ips")
	})

	// Update (partial — add description, change items).
	t.Run("update", func(t *testing.T) {
		payload := map[string]any{
			"description": "Updated E2E IP list",
			"items":       []string{"10.0.0.1", "10.0.0.2"},
		}
		resp, body := httpPut(t, wafctlURL+"/api/lists/"+listID, payload)
		assertCode(t, "update", 200, resp)
		assertField(t, "update", body, "description", "Updated E2E IP list")
		// Name should be preserved from original.
		assertField(t, "update", body, "name", "e2e-test-ips")
		count := jsonInt(body, "item_count")
		if count != 2 {
			t.Errorf("expected item_count=2, got %d", count)
		}
	})

	// List — should contain at least 1.
	t.Run("list non-empty", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists")
		assertCode(t, "list", 200, resp)
		n := jsonArrayLen(body)
		if n < 1 {
			t.Errorf("expected at least 1 list, got %d", n)
		}
	})

	// Export — response is ManagedListExport: {version, exported_at, lists}.
	t.Run("export", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists/export")
		assertCode(t, "export", 200, resp)
		version := jsonInt(body, "version")
		if version != 1 {
			t.Errorf("expected export version=1, got %d", version)
		}
		listsRaw := jsonField(body, "lists")
		if listsRaw == "" || listsRaw == "null" {
			t.Errorf("expected lists array in export, got: %.200s", string(body))
		}
	})

	// Delete — must return 204.
	t.Run("delete", func(t *testing.T) {
		resp, _ := httpDelete(t, wafctlURL+"/api/lists/"+listID)
		assertCode(t, "delete list", 204, resp)
		listID = "" // prevent cleanup double-delete
	})

	// Get non-existent — should be 404.
	t.Run("get non-existent", func(t *testing.T) {
		code, err := httpGetCode(wafctlURL + "/api/lists/nonexistent-id-12345")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if code != 404 {
			t.Errorf("expected 404, got %d", code)
		}
	})
}

func TestManagedListsImportExport(t *testing.T) {
	// Import replaces the entire store (same as exclusion import).
	// Test it in isolation to avoid interfering with CRUD tests.
	t.Run("import", func(t *testing.T) {
		payload := map[string]any{
			"version": 1,
			"lists": []map[string]any{
				{
					"name":   "e2e-imported-hosts",
					"kind":   "hostname",
					"source": "manual",
					"items":  []string{"evil.example.com", "bad.example.org"},
				},
				{
					"name":   "e2e-imported-ips",
					"kind":   "ip",
					"source": "manual",
					"items":  []string{"10.0.0.1"},
				},
			},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists/import", payload)
		assertCode(t, "import", 200, resp)
		imported := jsonInt(body, "imported")
		if imported != 2 {
			t.Errorf("expected imported=2, got %d", imported)
		}
	})

	// Verify imported lists exist.
	t.Run("imported lists exist", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists")
		assertCode(t, "list after import", 200, resp)
		n := jsonArrayLen(body)
		if n < 2 {
			t.Errorf("expected at least 2 lists after import, got %d", n)
		}
		// Find and clean up both imported lists.
		var arr []json.RawMessage
		if err := json.Unmarshal(body, &arr); err == nil {
			for _, raw := range arr {
				id := jsonField(raw, "id")
				if id != "" && id != "null" {
					t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })
				}
			}
		}
	})

	// Export after import should include the imported lists.
	t.Run("export after import", func(t *testing.T) {
		resp, body := httpGet(t, wafctlURL+"/api/lists/export")
		assertCode(t, "export", 200, resp)
		version := jsonInt(body, "version")
		if version != 1 {
			t.Errorf("expected export version=1, got %d", version)
		}
	})
}

func TestManagedListsValidation(t *testing.T) {
	t.Run("invalid kind rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-bad-kind",
			"kind":   "invalid_kind",
			"source": "manual",
			"items":  []string{"test"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "invalid kind", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error field, got: %s", body)
		}
	})

	t.Run("invalid source rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-bad-source",
			"kind":   "ip",
			"source": "invalid_source",
			"items":  []string{"10.0.0.1"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "invalid source", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error field, got: %s", body)
		}
	})

	t.Run("ipsum source rejected via API", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-ipsum-attempt",
			"kind":   "ip",
			"source": "ipsum",
			"items":  []string{"10.0.0.1"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "ipsum rejected", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error field, got: %s", body)
		}
	})

	t.Run("bad slug name rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "Invalid Name With Spaces!",
			"kind":   "string",
			"source": "manual",
			"items":  []string{"test"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "bad slug", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error field, got: %s", body)
		}
	})

	t.Run("duplicate name rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-dup-test",
			"kind":   "string",
			"source": "manual",
			"items":  []string{"test"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "create first", 201, resp)
		firstID := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+firstID) })

		// Second create with same name — should fail.
		resp2, body2 := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "duplicate name", 400, resp2)
		errMsg := jsonField(body2, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error for duplicate name, got: %s", body2)
		}
	})

	t.Run("invalid IP in IP list rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-bad-ip",
			"kind":   "ip",
			"source": "manual",
			"items":  []string{"not-an-ip"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "bad IP", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error for invalid IP, got: %s", body)
		}
	})

	t.Run("invalid ASN format rejected", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-bad-asn",
			"kind":   "asn",
			"source": "manual",
			"items":  []string{"INVALID123"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "bad ASN", 400, resp)
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error for invalid ASN, got: %s", body)
		}
	})
}

func TestManagedListsStringAndASN(t *testing.T) {
	// Create a string kind list (for country codes, etc.).
	t.Run("create string list", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-countries",
			"kind":   "string",
			"source": "manual",
			"items":  []string{"CN", "RU", "KP"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "create string list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })
		assertField(t, "kind", body, "kind", "string")
		count := jsonInt(body, "item_count")
		if count != 3 {
			t.Errorf("expected item_count=3, got %d", count)
		}
	})

	// Create an ASN kind list.
	t.Run("create ASN list", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-asns",
			"kind":   "asn",
			"source": "manual",
			"items":  []string{"AS13335", "AS15169"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "create ASN list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })
		assertField(t, "kind", body, "kind", "asn")
	})

	// Create a hostname kind list.
	t.Run("create hostname list", func(t *testing.T) {
		payload := map[string]any{
			"name":   "e2e-hostnames",
			"kind":   "hostname",
			"source": "manual",
			"items":  []string{"evil.example.com", "bad.example.org"},
		}
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		assertCode(t, "create hostname list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })
		assertField(t, "kind", body, "kind", "hostname")
	})
}

func TestManagedListsStress(t *testing.T) {
	// Stress test: large lists that exceed the inline threshold (1000 items)
	// and exercise external file storage.

	t.Run("50K IPs — external file storage", func(t *testing.T) {
		const n = 50_000
		ips := generateIPs(n)
		payload := map[string]any{
			"name":   "e2e-stress-50k",
			"kind":   "ip",
			"source": "manual",
			"items":  ips,
		}
		start := time.Now()
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		createDur := time.Since(start)
		assertCode(t, "create 50K list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })

		count := jsonInt(body, "item_count")
		if count != n {
			t.Errorf("expected item_count=%d, got %d", n, count)
		}
		t.Logf("create 50K list: %v", createDur)

		// Get — verify items are returned from external file.
		start = time.Now()
		resp2, body2 := httpGet(t, wafctlURL+"/api/lists/"+id)
		getDur := time.Since(start)
		assertCode(t, "get 50K list", 200, resp2)
		assertField(t, "get", body2, "name", "e2e-stress-50k")
		getCount := jsonInt(body2, "item_count")
		if getCount != n {
			t.Errorf("expected item_count=%d on get, got %d", n, getCount)
		}
		t.Logf("get 50K list: %v", getDur)

		// Update — replace with different items.
		start = time.Now()
		newIPs := generateIPs(25_000)
		resp3, body3 := httpPut(t, wafctlURL+"/api/lists/"+id, map[string]any{"items": newIPs})
		updateDur := time.Since(start)
		assertCode(t, "update 50K→25K", 200, resp3)
		updCount := jsonInt(body3, "item_count")
		if updCount != 25_000 {
			t.Errorf("expected item_count=25000 after update, got %d", updCount)
		}
		t.Logf("update 50K→25K list: %v", updateDur)
	})

	t.Run("200K IPs — near API body limit", func(t *testing.T) {
		// 200K IPs ≈ 3MB JSON payload (well under the 5MB MaxBytesReader).
		const n = 200_000
		ips := generateIPs(n)
		payload := map[string]any{
			"name":   "e2e-stress-200k",
			"kind":   "ip",
			"source": "manual",
			"items":  ips,
		}
		start := time.Now()
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		createDur := time.Since(start)
		assertCode(t, "create 200K list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })

		count := jsonInt(body, "item_count")
		if count != n {
			t.Errorf("expected item_count=%d, got %d", n, count)
		}
		t.Logf("create 200K list: %v", createDur)

		// Get and verify count survives round-trip.
		start = time.Now()
		resp2, body2 := httpGet(t, wafctlURL+"/api/lists/"+id)
		getDur := time.Since(start)
		assertCode(t, "get 200K list", 200, resp2)
		getCount := jsonInt(body2, "item_count")
		if getCount != n {
			t.Errorf("expected item_count=%d on get, got %d", n, getCount)
		}
		t.Logf("get 200K list: %v", getDur)

		// Delete large list — should clean up external file.
		start = time.Now()
		resp3, _ := httpDelete(t, wafctlURL+"/api/lists/"+id)
		deleteDur := time.Since(start)
		assertCode(t, "delete 200K list", 204, resp3)
		t.Logf("delete 200K list: %v", deleteDur)
		id = "" // prevent cleanup double-delete (captured by closure but unused)
	})

	t.Run("300K strings — push harder", func(t *testing.T) {
		// 300K short strings ≈ 4MB JSON. Tests string kind at scale.
		const n = 300_000
		items := make([]string, n)
		for i := range items {
			items[i] = fmt.Sprintf("item-%06d", i)
		}
		payload := map[string]any{
			"name":   "e2e-stress-300k-strings",
			"kind":   "string",
			"source": "manual",
			"items":  items,
		}
		start := time.Now()
		resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
		createDur := time.Since(start)
		assertCode(t, "create 300K string list", 201, resp)
		id := mustGetID(t, body)
		t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })

		count := jsonInt(body, "item_count")
		if count != n {
			t.Errorf("expected item_count=%d, got %d", n, count)
		}
		t.Logf("create 300K string list: %v", createDur)
	})
}

func TestManagedListsURLRefreshError(t *testing.T) {
	// Create a URL-sourced list with a non-existent URL — refresh should fail gracefully.
	payload := map[string]any{
		"name":   "e2e-url-list",
		"kind":   "ip",
		"source": "url",
		"url":    "http://localhost:1/nonexistent-list.txt",
		"items":  []string{},
	}
	resp, body := httpPost(t, wafctlURL+"/api/lists", payload)
	assertCode(t, "create URL list", 201, resp)
	id := mustGetID(t, body)
	t.Cleanup(func() { cleanup(t, wafctlURL+"/api/lists/"+id) })

	t.Run("refresh with bad URL returns error", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/lists/"+id+"/refresh", nil)
		// Should return 400 because the URL can't be reached.
		if resp.StatusCode != 400 {
			t.Errorf("expected 400 for unreachable URL refresh, got %d: %s", resp.StatusCode, body)
		}
		errMsg := jsonField(body, "error")
		if errMsg == "" || errMsg == "null" {
			t.Errorf("expected error in response, got: %s", body)
		}
	})

	t.Run("refresh non-existent list returns error", func(t *testing.T) {
		resp, body := httpPost(t, wafctlURL+"/api/lists/nonexistent-id/refresh", nil)
		if resp.StatusCode != 400 {
			t.Errorf("expected 400 for non-existent list refresh, got %d: %s", resp.StatusCode, body)
		}
	})
}
