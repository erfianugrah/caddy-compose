package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── Test Helpers ───────────────────────────────────────────────────

func newTestManagedListStore(t *testing.T) *ManagedListStore {
	t.Helper()
	dir := t.TempDir()
	return NewManagedListStore(
		filepath.Join(dir, "lists.json"),
		filepath.Join(dir, "lists"),
	)
}

func setupListMux(t *testing.T) (*http.ServeMux, *ManagedListStore) {
	t.Helper()
	ls := newTestManagedListStore(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/lists", handleListManagedLists(ls))
	mux.HandleFunc("POST /api/lists", handleCreateManagedList(ls))
	mux.HandleFunc("GET /api/lists/export", handleExportManagedLists(ls))
	mux.HandleFunc("POST /api/lists/import", handleImportManagedLists(ls))
	mux.HandleFunc("GET /api/lists/{id}", handleGetManagedList(ls))
	mux.HandleFunc("PUT /api/lists/{id}", handleUpdateManagedList(ls))
	mux.HandleFunc("DELETE /api/lists/{id}", handleDeleteManagedList(ls))
	mux.HandleFunc("POST /api/lists/{id}/refresh", handleRefreshManagedList(ls))
	return mux, ls
}

// ─── Store CRUD Tests ───────────────────────────────────────────────

func TestManagedListStore_CreateAndGet(t *testing.T) {
	store := newTestManagedListStore(t)

	created, err := store.Create(ManagedList{
		Name:   "test-ips",
		Kind:   "ip",
		Source: "manual",
		Items:  []string{"1.2.3.4", "10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Error("expected non-empty ID")
	}
	if created.ItemCount != 2 {
		t.Errorf("ItemCount = %d, want 2", created.ItemCount)
	}

	got, found := store.Get(created.ID)
	if !found {
		t.Fatal("Get: not found")
	}
	if got.Name != "test-ips" {
		t.Errorf("Name = %q, want %q", got.Name, "test-ips")
	}
	if len(got.Items) != 2 {
		t.Errorf("Items len = %d, want 2", len(got.Items))
	}
}

func TestManagedListStore_GetByName(t *testing.T) {
	store := newTestManagedListStore(t)

	store.Create(ManagedList{
		Name:   "my-hostnames",
		Kind:   "hostname",
		Source: "manual",
		Items:  []string{"example.com"},
	})

	got, found := store.GetByName("my-hostnames")
	if !found {
		t.Fatal("GetByName: not found")
	}
	if got.Kind != "hostname" {
		t.Errorf("Kind = %q, want %q", got.Kind, "hostname")
	}

	_, found = store.GetByName("nonexistent")
	if found {
		t.Error("expected not found for nonexistent name")
	}
}

func TestManagedListStore_NameUniqueness(t *testing.T) {
	store := newTestManagedListStore(t)

	_, err := store.Create(ManagedList{
		Name: "dup-name", Kind: "string", Source: "manual",
	})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	_, err = store.Create(ManagedList{
		Name: "dup-name", Kind: "string", Source: "manual",
	})
	if err == nil {
		t.Error("expected error for duplicate name")
	}
}

func TestManagedListStore_Update(t *testing.T) {
	store := newTestManagedListStore(t)

	created, _ := store.Create(ManagedList{
		Name:   "update-me",
		Kind:   "string",
		Source: "manual",
		Items:  []string{"a"},
	})

	updated, found, err := store.Update(created.ID, ManagedList{
		Name:        "update-me",
		Description: "updated description",
		Kind:        "string",
		Source:      "manual",
		Items:       []string{"a", "b", "c"},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !found {
		t.Fatal("Update: not found")
	}
	if updated.Description != "updated description" {
		t.Errorf("Description = %q, want %q", updated.Description, "updated description")
	}
	if updated.ItemCount != 3 {
		t.Errorf("ItemCount = %d, want 3", updated.ItemCount)
	}
	if updated.CreatedAt.IsZero() {
		t.Error("CreatedAt should be preserved")
	}
}

func TestManagedListStore_UpdateNameConflict(t *testing.T) {
	store := newTestManagedListStore(t)

	store.Create(ManagedList{Name: "list-a", Kind: "string", Source: "manual"})
	b, _ := store.Create(ManagedList{Name: "list-b", Kind: "string", Source: "manual"})

	_, _, err := store.Update(b.ID, ManagedList{
		Name: "list-a", Kind: "string", Source: "manual",
	})
	if err == nil {
		t.Error("expected error when renaming to existing name")
	}
}

func TestManagedListStore_Delete(t *testing.T) {
	store := newTestManagedListStore(t)

	created, _ := store.Create(ManagedList{
		Name: "delete-me", Kind: "string", Source: "manual",
	})

	found, err := store.Delete(created.ID)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !found {
		t.Fatal("Delete: not found")
	}

	_, found = store.Get(created.ID)
	if found {
		t.Error("expected not found after delete")
	}
}

func TestManagedListStore_DeleteNotFound(t *testing.T) {
	store := newTestManagedListStore(t)

	found, err := store.Delete("nonexistent-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected not found")
	}
}

func TestManagedListStore_List(t *testing.T) {
	store := newTestManagedListStore(t)

	store.Create(ManagedList{Name: "list-1", Kind: "ip", Source: "manual", Items: []string{"1.2.3.4"}})
	store.Create(ManagedList{Name: "list-2", Kind: "string", Source: "manual"})

	all := store.List()
	if len(all) != 2 {
		t.Errorf("List len = %d, want 2", len(all))
	}
}

func TestManagedListStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "lists.json")
	listsDir := filepath.Join(dir, "lists")

	store1 := NewManagedListStore(filePath, listsDir)
	store1.Create(ManagedList{
		Name:   "persist-test",
		Kind:   "ip",
		Source: "manual",
		Items:  []string{"192.168.1.1"},
	})

	// Reload from disk.
	store2 := NewManagedListStore(filePath, listsDir)
	all := store2.List()
	if len(all) != 1 {
		t.Fatalf("expected 1 list after reload, got %d", len(all))
	}
	if all[0].Name != "persist-test" {
		t.Errorf("Name = %q, want %q", all[0].Name, "persist-test")
	}
	if len(all[0].Items) != 1 {
		t.Errorf("Items len = %d, want 1", len(all[0].Items))
	}
}

func TestManagedListStore_LargeListExternalFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "lists.json")
	listsDir := filepath.Join(dir, "lists")

	store1 := NewManagedListStore(filePath, listsDir)

	// Create a list with > inlineItemThreshold items.
	items := make([]string, inlineItemThreshold+10)
	for i := range items {
		items[i] = "item-" + strings.Repeat("x", 5)
	}

	store1.Create(ManagedList{
		Name:   "big-list",
		Kind:   "string",
		Source: "manual",
		Items:  items,
	})

	// Verify external file exists.
	extPath := filepath.Join(listsDir, "big-list.txt")
	if _, err := os.Stat(extPath); os.IsNotExist(err) {
		t.Fatal("external items file not created")
	}

	// Verify metadata JSON does NOT contain items inline.
	data, _ := os.ReadFile(filePath)
	if strings.Contains(string(data), "item-xxxxx") {
		t.Error("large list items should not be inline in metadata JSON")
	}

	// Reload from disk — items should be loaded from external file.
	store2 := NewManagedListStore(filePath, listsDir)
	all := store2.List()
	if len(all) != 1 {
		t.Fatalf("expected 1 list, got %d", len(all))
	}
	if len(all[0].Items) != inlineItemThreshold+10 {
		t.Errorf("expected %d items after reload, got %d", inlineItemThreshold+10, len(all[0].Items))
	}
}

// ─── Validation Tests ───────────────────────────────────────────────

func TestValidateManagedList_EmptyName(t *testing.T) {
	err := validateManagedList(ManagedList{Kind: "ip", Source: "manual"})
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Errorf("expected name required error, got %v", err)
	}
}

func TestValidateManagedList_InvalidSlug(t *testing.T) {
	err := validateManagedList(ManagedList{Name: "Has Spaces", Kind: "ip", Source: "manual"})
	if err == nil || !strings.Contains(err.Error(), "slug-safe") {
		t.Errorf("expected slug-safe error, got %v", err)
	}
}

func TestValidateManagedList_InvalidKind(t *testing.T) {
	err := validateManagedList(ManagedList{Name: "test", Kind: "invalid", Source: "manual"})
	if err == nil || !strings.Contains(err.Error(), "invalid kind") {
		t.Errorf("expected invalid kind error, got %v", err)
	}
}

func TestValidateManagedList_InvalidSource(t *testing.T) {
	err := validateManagedList(ManagedList{Name: "test", Kind: "ip", Source: "invalid"})
	if err == nil || !strings.Contains(err.Error(), "invalid source") {
		t.Errorf("expected invalid source error, got %v", err)
	}
}

func TestValidateManagedList_URLSourceRequiresURL(t *testing.T) {
	err := validateManagedList(ManagedList{Name: "test", Kind: "ip", Source: "url"})
	if err == nil || !strings.Contains(err.Error(), "url is required") {
		t.Errorf("expected url required error, got %v", err)
	}
}

func TestValidateManagedList_IpsumSourceRejected(t *testing.T) {
	err := validateManagedList(ManagedList{Name: "test", Kind: "ip", Source: "ipsum"})
	if err == nil || !strings.Contains(err.Error(), "system") {
		t.Errorf("expected ipsum rejection error, got %v", err)
	}
}

func TestValidateItems_IP(t *testing.T) {
	tests := []struct {
		name    string
		items   []string
		wantErr bool
	}{
		{"valid IP", []string{"1.2.3.4"}, false},
		{"valid CIDR", []string{"10.0.0.0/8"}, false},
		{"valid IPv6", []string{"::1"}, false},
		{"valid IPv6 CIDR", []string{"2001:db8::/32"}, false},
		{"mixed valid", []string{"1.2.3.4", "10.0.0.0/8", "::1"}, false},
		{"invalid IP", []string{"not-an-ip"}, true},
		{"empty item", []string{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateItems("ip", tt.items)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateItems(ip, %v) error = %v, wantErr %v", tt.items, err, tt.wantErr)
			}
		})
	}
}

func TestValidateItems_Hostname(t *testing.T) {
	tests := []struct {
		name    string
		items   []string
		wantErr bool
	}{
		{"valid hostname", []string{"example.com"}, false},
		{"valid subdomain", []string{"sub.example.com"}, false},
		{"with whitespace", []string{"bad host"}, true},
		{"with wildcard", []string{"*.example.com"}, true},
		{"empty item", []string{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateItems("hostname", tt.items)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateItems(hostname, %v) error = %v, wantErr %v", tt.items, err, tt.wantErr)
			}
		})
	}
}

func TestValidateItems_ASN(t *testing.T) {
	tests := []struct {
		name    string
		items   []string
		wantErr bool
	}{
		{"valid ASN", []string{"AS13335"}, false},
		{"valid multi", []string{"AS13335", "AS15169"}, false},
		{"lowercase", []string{"as13335"}, true},
		{"no prefix", []string{"13335"}, true},
		{"empty item", []string{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateItems("asn", tt.items)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateItems(asn, %v) error = %v, wantErr %v", tt.items, err, tt.wantErr)
			}
		})
	}
}

func TestValidateItems_String(t *testing.T) {
	// String kind accepts any non-empty value.
	if err := validateItems("string", []string{"anything goes!", "123"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := validateItems("string", []string{""}); err == nil {
		t.Error("expected error for empty string item")
	}
}

func TestIsSlugSafe(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"valid-slug", true},
		{"another_slug", true},
		{"lowercase123", true},
		{"HasUppercase", false},
		{"has spaces", false},
		{"has.dots", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isSlugSafe(tt.input); got != tt.want {
				t.Errorf("isSlugSafe(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseItemLines(t *testing.T) {
	input := `# comment
1.2.3.4
  
10.0.0.0/8
# another comment
192.168.1.1
`
	items := parseItemLines(input)
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d: %v", len(items), items)
	}
	expected := []string{"1.2.3.4", "10.0.0.0/8", "192.168.1.1"}
	for i, want := range expected {
		if items[i] != want {
			t.Errorf("item[%d] = %q, want %q", i, items[i], want)
		}
	}
}

// ─── IPsum Sync Tests ───────────────────────────────────────────────

func TestManagedListStore_SyncIPsum(t *testing.T) {
	store := newTestManagedListStore(t)

	// First sync creates the list.
	store.SyncIPsum([]string{"1.2.3.4", "5.6.7.8"})

	all := store.List()
	if len(all) != 1 {
		t.Fatalf("expected 1 list, got %d", len(all))
	}
	if all[0].Name != "ipsum-ips" {
		t.Errorf("Name = %q, want %q", all[0].Name, "ipsum-ips")
	}
	if all[0].Kind != "ip" {
		t.Errorf("Kind = %q, want %q", all[0].Kind, "ip")
	}
	if all[0].Source != "ipsum" {
		t.Errorf("Source = %q, want %q", all[0].Source, "ipsum")
	}
	if all[0].ItemCount != 2 {
		t.Errorf("ItemCount = %d, want 2", all[0].ItemCount)
	}

	// Second sync updates in place.
	store.SyncIPsum([]string{"1.2.3.4", "5.6.7.8", "9.10.11.12"})

	all = store.List()
	if len(all) != 1 {
		t.Fatalf("expected 1 list after re-sync, got %d", len(all))
	}
	if all[0].ItemCount != 3 {
		t.Errorf("ItemCount after re-sync = %d, want 3", all[0].ItemCount)
	}
	// ID should be preserved.
}

func TestManagedListStore_IpsumCannotBeDeleted(t *testing.T) {
	store := newTestManagedListStore(t)
	store.SyncIPsum([]string{"1.2.3.4"})

	all := store.List()
	_, err := store.Delete(all[0].ID)
	if err == nil {
		t.Error("expected error when deleting ipsum list")
	}
	if !strings.Contains(err.Error(), "ipsum") {
		t.Errorf("error should mention ipsum: %v", err)
	}
}

func TestManagedListStore_ImportPreservesIPsum(t *testing.T) {
	store := newTestManagedListStore(t)

	// Sync an ipsum list first.
	store.SyncIPsum([]string{"1.2.3.4"})

	// Import replaces non-ipsum lists but preserves ipsum.
	err := store.Import([]ManagedList{
		{Name: "imported-list", Kind: "string", Source: "manual", Items: []string{"hello"}},
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	all := store.List()
	if len(all) != 2 {
		t.Fatalf("expected 2 lists (ipsum + imported), got %d", len(all))
	}

	names := map[string]bool{}
	for _, l := range all {
		names[l.Name] = true
	}
	if !names["ipsum-ips"] {
		t.Error("ipsum-ips list should be preserved after import")
	}
	if !names["imported-list"] {
		t.Error("imported-list should be present")
	}
}

func TestManagedListStore_ExportExcludesIPsum(t *testing.T) {
	store := newTestManagedListStore(t)

	store.SyncIPsum([]string{"1.2.3.4"})
	store.Create(ManagedList{Name: "my-list", Kind: "string", Source: "manual", Items: []string{"a"}})

	export := store.Export()
	if len(export.Lists) != 1 {
		t.Fatalf("expected 1 exported list, got %d", len(export.Lists))
	}
	if export.Lists[0].Name != "my-list" {
		t.Errorf("exported list name = %q, want %q", export.Lists[0].Name, "my-list")
	}
}

// ─── URL Refresh Tests ──────────────────────────────────────────────

func TestManagedListStore_RefreshURL(t *testing.T) {
	// Start a test HTTP server serving a list.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("# comment\n1.2.3.4\n10.0.0.0/8\n\n"))
	}))
	defer srv.Close()

	store := newTestManagedListStore(t)
	created, _ := store.Create(ManagedList{
		Name:   "url-list",
		Kind:   "ip",
		Source: "url",
		URL:    srv.URL,
	})

	refreshed, err := store.RefreshURL(created.ID)
	if err != nil {
		t.Fatalf("RefreshURL: %v", err)
	}
	if refreshed.ItemCount != 2 {
		t.Errorf("ItemCount = %d, want 2", refreshed.ItemCount)
	}
	if refreshed.Items[0] != "1.2.3.4" {
		t.Errorf("Items[0] = %q, want %q", refreshed.Items[0], "1.2.3.4")
	}
}

func TestManagedListStore_RefreshURL_NotURLSource(t *testing.T) {
	store := newTestManagedListStore(t)
	created, _ := store.Create(ManagedList{
		Name: "manual-list", Kind: "string", Source: "manual",
	})

	_, err := store.RefreshURL(created.ID)
	if err == nil || !strings.Contains(err.Error(), "url-sourced") {
		t.Errorf("expected url-sourced error, got %v", err)
	}
}

func TestManagedListStore_RefreshURL_ValidationFailure(t *testing.T) {
	// Serve invalid IPs.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not-an-ip\n"))
	}))
	defer srv.Close()

	store := newTestManagedListStore(t)
	created, _ := store.Create(ManagedList{
		Name: "bad-url-list", Kind: "ip", Source: "url", URL: srv.URL,
	})

	_, err := store.RefreshURL(created.ID)
	if err == nil || !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestManagedListStore_RefreshURL_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer srv.Close()

	store := newTestManagedListStore(t)
	created, _ := store.Create(ManagedList{
		Name: "error-url-list", Kind: "ip", Source: "url", URL: srv.URL,
	})

	_, err := store.RefreshURL(created.ID)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected HTTP 500 error, got %v", err)
	}
}

// ─── Handler Tests ──────────────────────────────────────────────────

func TestHandlerListManagedLists_Empty(t *testing.T) {
	mux, _ := setupListMux(t)

	req := httptest.NewRequest("GET", "/api/lists", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var lists []ManagedList
	json.Unmarshal(w.Body.Bytes(), &lists)
	if len(lists) != 0 {
		t.Errorf("expected 0 lists, got %d", len(lists))
	}
}

func TestHandlerCreateManagedList(t *testing.T) {
	mux, _ := setupListMux(t)

	body := `{"name":"test-list","kind":"ip","source":"manual","items":["1.2.3.4"]}`
	req := httptest.NewRequest("POST", "/api/lists", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body: %s", w.Code, w.Body.String())
	}

	var created ManagedList
	json.Unmarshal(w.Body.Bytes(), &created)
	if created.ID == "" {
		t.Error("expected non-empty ID")
	}
	if created.ItemCount != 1 {
		t.Errorf("ItemCount = %d, want 1", created.ItemCount)
	}
}

func TestHandlerCreateManagedList_ValidationError(t *testing.T) {
	mux, _ := setupListMux(t)

	body := `{"name":"bad list name","kind":"ip","source":"manual"}`
	req := httptest.NewRequest("POST", "/api/lists", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandlerGetManagedList(t *testing.T) {
	mux, ls := setupListMux(t)

	created, _ := ls.Create(ManagedList{
		Name: "get-test", Kind: "string", Source: "manual", Items: []string{"a", "b"},
	})

	req := httptest.NewRequest("GET", "/api/lists/"+created.ID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var got ManagedList
	json.Unmarshal(w.Body.Bytes(), &got)
	if got.Name != "get-test" {
		t.Errorf("Name = %q, want %q", got.Name, "get-test")
	}
}

func TestHandlerGetManagedList_NotFound(t *testing.T) {
	mux, _ := setupListMux(t)

	req := httptest.NewRequest("GET", "/api/lists/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestHandlerUpdateManagedList(t *testing.T) {
	mux, ls := setupListMux(t)

	created, _ := ls.Create(ManagedList{
		Name: "update-test", Kind: "string", Source: "manual", Items: []string{"a"},
	})

	body := `{"description":"updated","items":["a","b","c"]}`
	req := httptest.NewRequest("PUT", "/api/lists/"+created.ID, strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	var updated ManagedList
	json.Unmarshal(w.Body.Bytes(), &updated)
	if updated.Description != "updated" {
		t.Errorf("Description = %q, want %q", updated.Description, "updated")
	}
	if updated.ItemCount != 3 {
		t.Errorf("ItemCount = %d, want 3", updated.ItemCount)
	}
}

func TestHandlerDeleteManagedList(t *testing.T) {
	mux, ls := setupListMux(t)

	created, _ := ls.Create(ManagedList{
		Name: "delete-test", Kind: "string", Source: "manual",
	})

	req := httptest.NewRequest("DELETE", "/api/lists/"+created.ID, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
}

func TestHandlerDeleteManagedList_NotFound(t *testing.T) {
	mux, _ := setupListMux(t)

	req := httptest.NewRequest("DELETE", "/api/lists/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestHandlerExportImportManagedLists(t *testing.T) {
	mux, ls := setupListMux(t)

	ls.Create(ManagedList{Name: "export-1", Kind: "ip", Source: "manual", Items: []string{"1.2.3.4"}})
	ls.Create(ManagedList{Name: "export-2", Kind: "string", Source: "manual", Items: []string{"hello"}})

	// Export.
	req := httptest.NewRequest("GET", "/api/lists/export", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("export status = %d, want 200", w.Code)
	}

	exportBody := w.Body.Bytes()

	// Create fresh store for import.
	mux2, ls2 := setupListMux(t)

	req = httptest.NewRequest("POST", "/api/lists/import", strings.NewReader(string(exportBody)))
	w = httptest.NewRecorder()
	mux2.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("import status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	imported := ls2.List()
	if len(imported) != 2 {
		t.Errorf("expected 2 imported lists, got %d", len(imported))
	}
}

func TestHandlerRefreshManagedList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("example.com\ntest.org\n"))
	}))
	defer srv.Close()

	mux, ls := setupListMux(t)

	created, _ := ls.Create(ManagedList{
		Name: "refresh-test", Kind: "hostname", Source: "url", URL: srv.URL,
	})

	req := httptest.NewRequest("POST", "/api/lists/"+created.ID+"/refresh", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	var refreshed ManagedList
	json.Unmarshal(w.Body.Bytes(), &refreshed)
	if refreshed.ItemCount != 2 {
		t.Errorf("ItemCount = %d, want 2", refreshed.ItemCount)
	}
}

func TestHandlerRefreshManagedList_NotURLSource(t *testing.T) {
	mux, ls := setupListMux(t)

	created, _ := ls.Create(ManagedList{
		Name: "manual-refresh", Kind: "string", Source: "manual",
	})

	req := httptest.NewRequest("POST", "/api/lists/"+created.ID+"/refresh", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandlerUpdateManagedList_IpsumReadOnly(t *testing.T) {
	mux, ls := setupListMux(t)

	ls.SyncIPsum([]string{"1.2.3.4"})
	all := ls.List()
	ipsumID := all[0].ID

	body := `{"description":"hacked"}`
	req := httptest.NewRequest("PUT", "/api/lists/"+ipsumID, strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for ipsum update", w.Code)
	}
}

// ─── Field-Kind Compatibility Tests ─────────────────────────────────

func TestCompatibleKinds(t *testing.T) {
	tests := []struct {
		field    string
		wantIP   bool
		wantStr  bool
		wantHost bool
		wantASN  bool
	}{
		{"ip", true, false, false, false},
		{"country", false, true, false, false},
		{"host", false, true, true, false},
		{"path", false, true, true, true},
		{"user_agent", false, true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			kinds := CompatibleKinds(tt.field)
			if kinds["ip"] != tt.wantIP {
				t.Errorf("ip = %v, want %v", kinds["ip"], tt.wantIP)
			}
			if kinds["string"] != tt.wantStr {
				t.Errorf("string = %v, want %v", kinds["string"], tt.wantStr)
			}
			if kinds["hostname"] != tt.wantHost {
				t.Errorf("hostname = %v, want %v", kinds["hostname"], tt.wantHost)
			}
			if kinds["asn"] != tt.wantASN {
				t.Errorf("asn = %v, want %v", kinds["asn"], tt.wantASN)
			}
		})
	}
}

// ─── in_list/not_in_list operator availability ──────────────────────

func TestInListOperatorsAddedToAllFields(t *testing.T) {
	for field, ops := range validOperatorsForField {
		if !ops["in_list"] {
			t.Errorf("field %q missing in_list operator", field)
		}
		if !ops["not_in_list"] {
			t.Errorf("field %q missing not_in_list operator", field)
		}
	}
}

// ─── Blocklist OnRefresh callback ───────────────────────────────────

func TestBlocklistStore_OnRefreshCallback(t *testing.T) {
	path := writeTempBlocklist(t, "# empty\n")
	bs := NewBlocklistStore(path)

	var called bool
	var receivedIPs []string
	bs.SetOnRefresh(func(ips []string) {
		called = true
		receivedIPs = ips
	})

	// We can't easily test the full Refresh flow (requires HTTP download),
	// but we can verify the callback mechanism is wired up by checking the
	// SetOnRefresh/onRefresh field.
	bs.mu.RLock()
	if bs.onRefresh == nil {
		t.Fatal("onRefresh callback not set")
	}
	bs.mu.RUnlock()

	// Manually invoke the callback to verify it works.
	bs.onRefresh([]string{"1.2.3.4", "5.6.7.8"})
	if !called {
		t.Error("callback was not called")
	}
	if len(receivedIPs) != 2 {
		t.Errorf("received %d IPs, want 2", len(receivedIPs))
	}
}
