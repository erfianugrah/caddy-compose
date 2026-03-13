package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ─── Managed List Store ─────────────────────────────────────────────

// inlineItemThreshold is the max number of items stored inline in the
// metadata JSON. Lists with more items are persisted to separate files.
const inlineItemThreshold = 1000

// asnRe validates ASN format: AS followed by one or more digits.
var asnRe = regexp.MustCompile(`^AS\d+$`)

// ManagedListStore manages named, reusable collections of items (IPs,
// hostnames, strings, ASNs) with file-backed persistence.
type ManagedListStore struct {
	mu                sync.RWMutex
	lists             []ManagedList
	filePath          string // metadata JSON path (e.g., /data/lists.json)
	listsDir          string // directory for large list item files (e.g., /data/lists/)
	skipURLValidation bool   // test-only: bypass SSRF validation for httptest servers
}

// NewManagedListStore creates a store and loads existing data from disk.
func NewManagedListStore(filePath, listsDir string) *ManagedListStore {
	s := &ManagedListStore{
		filePath: filePath,
		listsDir: listsDir,
	}
	// Ensure the lists directory exists.
	if err := os.MkdirAll(listsDir, 0755); err != nil {
		log.Printf("[lists] warning: could not create lists dir %s: %v", listsDir, err)
	}
	s.load()
	return s
}

// load reads lists from the JSON file on disk.
func (s *ManagedListStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[lists] file not found at %s, starting empty", s.filePath)
			s.lists = []ManagedList{}
			return
		}
		log.Printf("[lists] error reading file: %v", err)
		s.lists = []ManagedList{}
		return
	}

	var lists []ManagedList
	if err := json.Unmarshal(data, &lists); err != nil {
		log.Printf("[lists] error parsing file: %v", err)
		s.lists = []ManagedList{}
		return
	}

	// Load items from external files for large lists.
	for i := range lists {
		if len(lists[i].Items) == 0 && lists[i].ItemCount > 0 {
			items, err := s.loadItemsFile(lists[i].Name)
			if err != nil {
				log.Printf("[lists] warning: could not load items for %q: %v", lists[i].Name, err)
			} else {
				lists[i].Items = items
			}
		}
		if lists[i].Items == nil {
			lists[i].Items = []string{}
		}
	}

	s.lists = lists
	log.Printf("[lists] loaded %d managed lists from %s", len(lists), s.filePath)
}

// save writes the current lists to the JSON file atomically.
// Large lists have their items persisted to separate files.
func (s *ManagedListStore) save() error {
	// Prepare a copy for serialization — strip items from large lists
	// (they are stored in separate files).
	toSave := make([]ManagedList, len(s.lists))
	for i, l := range s.lists {
		toSave[i] = l
		if len(l.Items) >= inlineItemThreshold {
			// Write items to external file.
			if err := s.writeItemsFile(l.Name, l.Items); err != nil {
				return fmt.Errorf("writing items file for %q: %w", l.Name, err)
			}
			toSave[i].Items = nil // omit from JSON
		}
	}

	data, err := json.MarshalIndent(toSave, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling lists: %w", err)
	}
	if err := atomicWriteFile(s.filePath, data, 0644); err != nil {
		return fmt.Errorf("writing lists file: %w", err)
	}
	return nil
}

// itemsFilePath returns the path for a list's external items file.
func (s *ManagedListStore) itemsFilePath(name string) string {
	// Sanitize name to filesystem-safe slug.
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)
	return filepath.Join(s.listsDir, safe+".txt")
}

// loadItemsFile reads items from an external file (one per line).
func (s *ManagedListStore) loadItemsFile(name string) ([]string, error) {
	path := s.itemsFilePath(name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseItemLines(string(data)), nil
}

// writeItemsFile writes items to an external file (one per line).
func (s *ManagedListStore) writeItemsFile(name string, items []string) error {
	content := strings.Join(items, "\n") + "\n"
	return atomicWriteFile(s.itemsFilePath(name), []byte(content), 0644)
}

// deleteItemsFile removes the external items file for a list.
func (s *ManagedListStore) deleteItemsFile(name string) {
	path := s.itemsFilePath(name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("[lists] warning: could not remove items file %s: %v", path, err)
	}
}

// parseItemLines parses a newline-separated list, stripping comments and blanks.
func parseItemLines(text string) []string {
	var items []string
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		items = append(items, line)
	}
	return items
}

// ─── CRUD Operations ────────────────────────────────────────────────

// List returns all managed lists (deep copy).
func (s *ManagedListStore) List() []ManagedList {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]ManagedList, len(s.lists))
	for i, l := range s.lists {
		cp[i] = l
		cp[i].Items = make([]string, len(l.Items))
		copy(cp[i].Items, l.Items)
	}
	return cp
}

// Get returns a single list by ID.
func (s *ManagedListStore) Get(id string) (ManagedList, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, l := range s.lists {
		if l.ID == id {
			cp := l
			cp.Items = make([]string, len(l.Items))
			copy(cp.Items, l.Items)
			return cp, true
		}
	}
	return ManagedList{}, false
}

// GetByName returns a single list by name.
func (s *ManagedListStore) GetByName(name string) (ManagedList, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, l := range s.lists {
		if l.Name == name {
			cp := l
			cp.Items = make([]string, len(l.Items))
			copy(cp.Items, l.Items)
			return cp, true
		}
	}
	return ManagedList{}, false
}

// Create adds a new managed list and persists to disk.
func (s *ManagedListStore) Create(l ManagedList) (ManagedList, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check name uniqueness.
	for _, existing := range s.lists {
		if existing.Name == l.Name {
			return ManagedList{}, fmt.Errorf("list name %q already exists", l.Name)
		}
	}

	l.ID = generateUUID()
	now := time.Now().UTC()
	l.CreatedAt = now
	l.UpdatedAt = now
	if l.Items == nil {
		l.Items = []string{}
	}
	l.ItemCount = len(l.Items)

	s.lists = append(s.lists, l)
	if err := s.save(); err != nil {
		// Roll back.
		s.lists = s.lists[:len(s.lists)-1]
		return ManagedList{}, err
	}
	return l, nil
}

// Update modifies an existing managed list and persists to disk.
func (s *ManagedListStore) Update(id string, updated ManagedList) (ManagedList, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, l := range s.lists {
		if l.ID == id {
			// Check name uniqueness (if name changed).
			if updated.Name != l.Name {
				for _, other := range s.lists {
					if other.ID != id && other.Name == updated.Name {
						return ManagedList{}, true, fmt.Errorf("list name %q already exists", updated.Name)
					}
				}
			}

			// Preserve immutable fields.
			updated.ID = l.ID
			updated.CreatedAt = l.CreatedAt
			updated.UpdatedAt = time.Now().UTC()
			if updated.Items == nil {
				updated.Items = []string{}
			}
			updated.ItemCount = len(updated.Items)

			// If name changed, clean up old items file.
			oldName := l.Name
			old := s.lists[i]
			s.lists[i] = updated
			if err := s.save(); err != nil {
				s.lists[i] = old // roll back
				return ManagedList{}, true, err
			}
			// Clean up old items file if name changed.
			if oldName != updated.Name {
				s.deleteItemsFile(oldName)
			}
			return updated, true, nil
		}
	}
	return ManagedList{}, false, nil
}

// Delete removes a managed list by ID and persists to disk.
func (s *ManagedListStore) Delete(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, l := range s.lists {
		if l.ID == id {
			// ipsum lists cannot be deleted (managed by the system).
			if l.Source == "ipsum" {
				return true, fmt.Errorf("cannot delete ipsum-sourced list %q (managed by blocklist system)", l.Name)
			}

			name := l.Name
			old := make([]ManagedList, len(s.lists))
			copy(old, s.lists)
			s.lists = append(s.lists[:i], s.lists[i+1:]...)
			if err := s.save(); err != nil {
				s.lists = old // roll back
				return true, err
			}
			// Remove external items file.
			s.deleteItemsFile(name)
			return true, nil
		}
	}
	return false, nil
}

// Import replaces all non-ipsum lists with the provided list and persists.
func (s *ManagedListStore) Import(lists []ManagedList) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	// Preserve ipsum lists.
	var preserved []ManagedList
	for _, l := range s.lists {
		if l.Source == "ipsum" {
			preserved = append(preserved, l)
		}
	}

	// Validate and assign IDs.
	nameSet := make(map[string]bool)
	for _, p := range preserved {
		nameSet[p.Name] = true
	}
	for i := range lists {
		lists[i].ID = generateUUID()
		if lists[i].CreatedAt.IsZero() {
			lists[i].CreatedAt = now
		}
		lists[i].UpdatedAt = now
		if lists[i].Items == nil {
			lists[i].Items = []string{}
		}
		lists[i].ItemCount = len(lists[i].Items)

		// Skip ipsum-sourced imports.
		if lists[i].Source == "ipsum" {
			continue
		}
		if nameSet[lists[i].Name] {
			return fmt.Errorf("duplicate list name %q", lists[i].Name)
		}
		nameSet[lists[i].Name] = true
		preserved = append(preserved, lists[i])
	}

	old := s.lists
	s.lists = preserved
	if err := s.save(); err != nil {
		s.lists = old
		return err
	}
	return nil
}

// Export returns all non-ipsum lists wrapped in an export envelope.
func (s *ManagedListStore) Export() ManagedListExport {
	all := s.List()
	var exported []ManagedList
	for _, l := range all {
		if l.Source != "ipsum" {
			exported = append(exported, l)
		}
	}
	if exported == nil {
		exported = []ManagedList{}
	}
	return ManagedListExport{
		Version:    1,
		ExportedAt: time.Now().UTC(),
		Lists:      exported,
	}
}

// ─── URL Refresh ────────────────────────────────────────────────────

// validateRefreshURL checks that a URL is safe to fetch (no SSRF).
// Only HTTPS is allowed. HTTP is permitted only for github.com and
// raw.githubusercontent.com (IPsum lists). Private/loopback IPs are rejected.
func validateRefreshURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow HTTPS (and HTTP for known-safe GitHub hosts).
	switch u.Scheme {
	case "https":
		// always allowed
	case "http":
		host := strings.ToLower(u.Hostname())
		if host != "github.com" && host != "raw.githubusercontent.com" {
			return fmt.Errorf("only HTTPS URLs are allowed (HTTP permitted for github.com only)")
		}
	default:
		return fmt.Errorf("unsupported URL scheme %q: only HTTPS is allowed", u.Scheme)
	}

	// Resolve the hostname and reject private/loopback IPs.
	hostname := u.Hostname()
	ips, err := net.LookupHost(hostname)
	if err != nil {
		return fmt.Errorf("cannot resolve hostname %q: %w", hostname, err)
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("URL resolves to private/loopback address %s", ipStr)
		}
	}

	return nil
}

// RefreshURL re-fetches items from the list's URL, re-validates, and persists.
// The HTTP request is performed outside the mutex lock to avoid blocking other
// store operations during slow/stalled fetches.
func (s *ManagedListStore) RefreshURL(id string) (ManagedList, error) {
	// Phase 1: Read list metadata under read lock.
	s.mu.RLock()
	var listURL, listKind, listName string
	found := false
	for _, l := range s.lists {
		if l.ID == id {
			if l.Source != "url" {
				s.mu.RUnlock()
				return ManagedList{}, fmt.Errorf("only url-sourced lists can be refreshed")
			}
			if l.URL == "" {
				s.mu.RUnlock()
				return ManagedList{}, fmt.Errorf("list has no URL configured")
			}
			listURL = l.URL
			listKind = l.Kind
			listName = l.Name
			found = true
			break
		}
	}
	s.mu.RUnlock()

	if !found {
		return ManagedList{}, fmt.Errorf("list not found")
	}

	// Phase 2: Validate URL safety (SSRF protection) and fetch — no lock held.
	if !s.skipURLValidation {
		if err := validateRefreshURL(listURL); err != nil {
			return ManagedList{}, fmt.Errorf("URL validation failed: %w", err)
		}
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(listURL)
	if err != nil {
		return ManagedList{}, fmt.Errorf("fetching %s: %w", listURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return ManagedList{}, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, listURL, string(errBody))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024)) // 50 MB limit
	if err != nil {
		return ManagedList{}, fmt.Errorf("reading response: %w", err)
	}

	items := parseItemLines(string(body))

	if err := validateItems(listKind, items); err != nil {
		return ManagedList{}, fmt.Errorf("validation failed: %w", err)
	}

	// Phase 3: Re-acquire write lock and apply mutation.
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	for i, l := range s.lists {
		if l.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ManagedList{}, fmt.Errorf("list not found (removed during fetch)")
	}

	old := s.lists[idx]
	updated := s.lists[idx]
	updated.Items = items
	updated.ItemCount = len(items)
	updated.UpdatedAt = time.Now().UTC()
	s.lists[idx] = updated

	if err := s.save(); err != nil {
		s.lists[idx] = old // roll back
		return ManagedList{}, err
	}

	log.Printf("[lists] refreshed %q from URL: %d items", listName, len(items))
	return updated, nil
}

// ─── IPsum Sync ─────────────────────────────────────────────────────

// ipsumLevelName returns the managed list name for a given IPsum threat level.
func ipsumLevelName(level int) string {
	return fmt.Sprintf("ipsum-level-%d", level)
}

// ipsumLevelDescription returns the description for an IPsum threat level list.
func ipsumLevelDescription(level int) string {
	return fmt.Sprintf("IPsum threat level %d IPs (auto-synced, read-only)", level)
}

// SyncIPsum creates or updates per-level IPsum managed lists from the blocklist
// store's parsed IPs. Creates one list per score level (1–8), named
// "ipsum-level-1" through "ipsum-level-8". Called as a callback after blocklist
// refresh. Also cleans up the legacy "ipsum-ips" flat list if present.
func (s *ManagedListStore) SyncIPsum(ipsByScore map[int][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	// Build index of existing ipsum lists by name.
	existingByName := make(map[string]int) // name → index in s.lists
	for i, l := range s.lists {
		if l.Source == "ipsum" {
			existingByName[l.Name] = i
		}
	}

	// Remove legacy "ipsum-ips" flat list (replaced by per-level lists).
	if idx, ok := existingByName["ipsum-ips"]; ok {
		old := s.lists[idx]
		s.lists = append(s.lists[:idx], s.lists[idx+1:]...)
		log.Printf("[lists] removed legacy ipsum-ips list (%d IPs) — replaced by per-level lists", old.ItemCount)
		// Rebuild index after removal (indices shifted).
		existingByName = make(map[string]int)
		for i, l := range s.lists {
			if l.Source == "ipsum" {
				existingByName[l.Name] = i
			}
		}
	}

	var totalIPs int
	for level := 1; level <= 8; level++ {
		name := ipsumLevelName(level)
		ips := ipsByScore[level] // may be nil/empty for high levels
		if ips == nil {
			ips = []string{}
		}
		totalIPs += len(ips)

		list := ManagedList{
			Name:        name,
			Description: ipsumLevelDescription(level),
			Kind:        "ip",
			Source:      "ipsum",
			Items:       ips,
			ItemCount:   len(ips),
			UpdatedAt:   now,
		}

		if idx, ok := existingByName[name]; ok {
			// Update existing.
			list.ID = s.lists[idx].ID
			list.CreatedAt = s.lists[idx].CreatedAt
			s.lists[idx] = list
		} else {
			// Create new.
			list.ID = generateUUID()
			list.CreatedAt = now
			s.lists = append(s.lists, list)
		}
	}

	if err := s.save(); err != nil {
		log.Printf("[lists] error saving ipsum sync: %v", err)
	} else {
		log.Printf("[lists] synced 8 ipsum level lists: %d total IPs", totalIPs)
	}
}

// ─── Validation ─────────────────────────────────────────────────────

// validateManagedList validates a ManagedList's fields.
func validateManagedList(l ManagedList) error {
	if l.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Name must be slug-safe: lowercase alphanumeric, hyphens, underscores.
	if !isSlugSafe(l.Name) {
		return fmt.Errorf("name must be slug-safe (lowercase alphanumeric, hyphens, underscores)")
	}
	if !validListKinds[l.Kind] {
		return fmt.Errorf("invalid kind %q (valid: ip, hostname, string, asn)", l.Kind)
	}
	if !validListSources[l.Source] {
		return fmt.Errorf("invalid source %q (valid: manual, url, ipsum)", l.Source)
	}
	if l.Source == "url" && l.URL == "" {
		return fmt.Errorf("url is required for url-sourced lists")
	}
	if l.Source == "ipsum" {
		return fmt.Errorf("ipsum-sourced lists are managed by the system and cannot be created manually")
	}

	// Validate items.
	if err := validateItems(l.Kind, l.Items); err != nil {
		return err
	}

	return nil
}

// validateItems validates list items per kind.
func validateItems(kind string, items []string) error {
	for i, item := range items {
		if item == "" {
			return fmt.Errorf("item %d: empty item", i)
		}
		switch kind {
		case "ip":
			if err := validateIPItem(item); err != nil {
				return fmt.Errorf("item %d (%q): %w", i, item, err)
			}
		case "hostname":
			if err := validateHostnameItem(item); err != nil {
				return fmt.Errorf("item %d (%q): %w", i, item, err)
			}
		case "string":
			// Any non-empty string is valid.
		case "asn":
			if !asnRe.MatchString(item) {
				return fmt.Errorf("item %d (%q): must match AS<digits> format (e.g., AS13335)", i, item)
			}
		}
	}
	return nil
}

// validateIPItem checks that an item is a valid IP or CIDR.
func validateIPItem(item string) error {
	if net.ParseIP(item) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(item); err == nil {
		return nil
	}
	return fmt.Errorf("not a valid IP or CIDR")
}

// validateHostnameItem checks that a hostname contains no whitespace or wildcard chars.
func validateHostnameItem(item string) error {
	if strings.ContainsAny(item, " \t\n\r*?") {
		return fmt.Errorf("hostname must not contain whitespace or wildcard characters")
	}
	return nil
}

// isSlugSafe returns true if the string contains only lowercase alphanumeric,
// hyphens, and underscores.
func isSlugSafe(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return len(s) > 0
}
