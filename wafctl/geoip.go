package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── GeoIP Store ─────────────────────────────────────────────────────────────
// Thread-safe country lookup with three-tier resolution:
//   Priority 1: Cf-Ipcountry header (free, zero latency, present when behind CF)
//   Priority 2: Local MMDB database lookup (sub-microsecond, offline)
//   Priority 3: Online API fallback (for deployments without CF or MMDB)

// GeoIPAPIConfig holds configuration for the online GeoIP API fallback.
type GeoIPAPIConfig struct {
	URL     string        // API URL template with %s for IP (e.g., "https://ipinfo.io/%s/json")
	Key     string        // API key (sent as Bearer token, empty = no auth)
	Timeout time.Duration // HTTP request timeout (default 2s)
}

// GeoIPStore provides IP-to-country resolution with caching.
type GeoIPStore struct {
	mu     sync.RWMutex
	db     *geoIPDB // nil if no MMDB loaded
	cache  map[string]geoEntry
	api    *GeoIPAPIConfig // nil if no online API configured
	client *http.Client    // shared HTTP client for API calls
}

type geoEntry struct {
	country string
	ts      time.Time
}

const geoCacheTTL = 24 * time.Hour
const geoCacheMaxSize = 100000

// NewGeoIPStore creates a new GeoIP store. If dbPath is non-empty and the file
// exists, it loads the MMDB database. If apiCfg is provided with a non-empty URL,
// the store will fall back to online API lookups when both CF header and MMDB
// are unavailable. Otherwise the store works in header-only mode (Cf-Ipcountry).
func NewGeoIPStore(dbPath string, apiCfg *GeoIPAPIConfig) *GeoIPStore {
	s := &GeoIPStore{
		cache: make(map[string]geoEntry),
	}
	if dbPath != "" {
		if _, err := os.Stat(dbPath); err == nil {
			db, err := newGeoIPDB(dbPath)
			if err != nil {
				log.Printf("geoip: failed to load MMDB %s: %v", dbPath, err)
			} else {
				s.db = db
				log.Printf("geoip: loaded MMDB %s (ipVersion=%d, nodeCount=%d, recordSize=%d)",
					dbPath, db.ipVersion, db.nodeCount, db.recordSize)
			}
		} else {
			log.Printf("geoip: MMDB file not found at %s, running in header-only mode", dbPath)
		}
	}

	// Configure online API fallback.
	if apiCfg != nil && apiCfg.URL != "" {
		timeout := apiCfg.Timeout
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		s.api = apiCfg
		s.client = &http.Client{Timeout: timeout}
		log.Printf("geoip: online API fallback enabled (url=%s, timeout=%s)", apiCfg.URL, timeout)
	}

	return s
}

// HasDB returns true if an MMDB database is loaded.
func (s *GeoIPStore) HasDB() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db != nil
}

// LookupIP resolves an IP address to a country code using the MMDB database.
// Returns "" if no database is loaded or the IP is not found.
// Results are cached for geoCacheTTL.
func (s *GeoIPStore) LookupIP(ip string) string {
	if ip == "" {
		return ""
	}

	// Check cache first
	s.mu.RLock()
	if entry, ok := s.cache[ip]; ok && time.Since(entry.ts) < geoCacheTTL {
		s.mu.RUnlock()
		return entry.country
	}
	db := s.db
	s.mu.RUnlock()

	if db == nil {
		return ""
	}

	country := db.lookupCountry(ip)

	// Store in cache
	s.mu.Lock()
	// Evict if cache too large
	if len(s.cache) >= geoCacheMaxSize {
		s.evictRandom()
	}
	s.cache[ip] = geoEntry{country: country, ts: time.Now()}
	s.mu.Unlock()

	return country
}

// Resolve returns the country for an IP, using the CF header first, then MMDB,
// then online API. cfCountry is the value of the Cf-Ipcountry header (empty if
// not present).
func (s *GeoIPStore) Resolve(ip, cfCountry string) string {
	// Priority 1: Cloudflare header
	if cfCountry != "" && cfCountry != "XX" && cfCountry != "T1" {
		return strings.ToUpper(cfCountry)
	}
	// Priority 2: MMDB lookup
	if country := s.LookupIP(ip); country != "" {
		return country
	}
	// Priority 3: Online API fallback
	if s.api != nil {
		return s.lookupOnline(ip)
	}
	return ""
}

// HasAPI returns true if an online GeoIP API fallback is configured.
func (s *GeoIPStore) HasAPI() bool {
	return s.api != nil
}

// lookupOnline queries the configured online GeoIP API for a country code.
// Results are cached in the shared cache. Returns "" on error.
func (s *GeoIPStore) lookupOnline(ip string) string {
	if ip == "" {
		return ""
	}

	// Check cache first (may have been populated by a previous online lookup).
	s.mu.RLock()
	if entry, ok := s.cache[ip]; ok && time.Since(entry.ts) < geoCacheTTL {
		s.mu.RUnlock()
		return entry.country
	}
	s.mu.RUnlock()

	// Build URL — support %s placeholder for IP, or append as path segment.
	url := s.api.URL
	if strings.Contains(url, "%s") {
		url = fmt.Sprintf(url, ip)
	} else {
		url = strings.TrimRight(url, "/") + "/" + ip
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("geoip: online API request error: %v", err)
		return ""
	}
	if s.api.Key != "" {
		req.Header.Set("Authorization", "Bearer "+s.api.Key)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("geoip: online API request failed for %s: %v", ip, err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("geoip: online API returned status %d for %s", resp.StatusCode, ip)
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		log.Printf("geoip: online API read error for %s: %v", ip, err)
		return ""
	}

	// Parse JSON — supports common API response formats:
	// IPinfo.io: {"country": "US", ...}
	// ip-api.com: {"countryCode": "US", ...}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("geoip: online API JSON parse error for %s: %v", ip, err)
		return ""
	}

	// Try common field names for country code.
	country := ""
	for _, field := range []string{"country", "countryCode", "country_code"} {
		if val, ok := result[field]; ok {
			if s, ok := val.(string); ok && len(s) == 2 {
				country = strings.ToUpper(s)
				break
			}
		}
	}

	// Cache the result (even empty results to avoid repeated failed lookups).
	s.mu.Lock()
	if len(s.cache) >= geoCacheMaxSize {
		s.evictRandom()
	}
	s.cache[ip] = geoEntry{country: country, ts: time.Now()}
	s.mu.Unlock()

	return country
}

// evictRandom removes ~25% of cache entries. Map iteration order is random in Go,
// so this is effectively random eviction — acceptable for a country-code cache
// where re-derivation is cheap. Caller must hold s.mu write lock.
func (s *GeoIPStore) evictRandom() {
	target := geoCacheMaxSize / 4
	type aged struct {
		key string
		ts  time.Time
	}
	oldest := make([]aged, 0, len(s.cache))
	for k, v := range s.cache {
		oldest = append(oldest, aged{k, v.ts})
	}
	// Simple approach: delete entries older than median. For simplicity, just
	// delete the first `target` entries we find (map iteration is random).
	deleted := 0
	for k := range s.cache {
		if deleted >= target {
			break
		}
		delete(s.cache, k)
		deleted++
	}
}

// TopCountries returns the top N countries by request count from the given events.
func TopCountries(events []Event, n int) []CountryCount {
	counts := make(map[string]*CountryCount)
	for i := range events {
		cc := events[i].Country
		if cc == "" {
			cc = "XX" // unknown
		}
		entry, ok := counts[cc]
		if !ok {
			entry = &CountryCount{Country: cc}
			counts[cc] = entry
		}
		entry.Count++
		if events[i].IsBlocked {
			entry.Blocked++
		}
	}

	result := make([]CountryCount, 0, len(counts))
	for _, v := range counts {
		result = append(result, *v)
	}

	// Sort by count descending.
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	if n > 0 && len(result) > n {
		result = result[:n]
	}
	return result
}

// ─── Pure Go MMDB Reader ─────────────────────────────────────────────────────
// Ported from k3s Sentinel. Reads GeoLite2-Country or DB-IP Lite Country MMDB
// files. Only extracts country.iso_code — no other fields.

// MMDB metadata marker: \xAB\xCD\xEF followed by "MaxMind.com"
var mmdbMarker = []byte{0xAB, 0xCD, 0xEF, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'}

// geoIPDB holds the parsed MMDB data for fast IP lookups.
type geoIPDB struct {
	data             []byte
	nodeCount        uint32
	recordSize       uint16
	ipVersion        uint16
	nodeSize         int // bytes per tree node (recordSize * 2 / 8)
	treeSize         int
	dataSectionStart int
	ipv4Start        uint32 // cached IPv4 subtree root for IPv6 DBs
}

// newGeoIPDB loads and parses an MMDB file.
func newGeoIPDB(path string) (*geoIPDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mmdb: %w", err)
	}

	// Find metadata marker (search backwards for last occurrence)
	markerIdx := -1
	for i := len(data) - len(mmdbMarker); i >= 0; i-- {
		match := true
		for j := 0; j < len(mmdbMarker); j++ {
			if data[i+j] != mmdbMarker[j] {
				match = false
				break
			}
		}
		if match {
			markerIdx = i
			break
		}
	}
	if markerIdx < 0 {
		return nil, fmt.Errorf("mmdb metadata marker not found")
	}

	db := &geoIPDB{data: data}

	// Parse metadata (starts right after the marker)
	metaStart := markerIdx + len(mmdbMarker)
	if err := db.parseMetadata(metaStart); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}

	db.nodeSize = int(db.recordSize) * 2 / 8
	db.treeSize = int(db.nodeCount) * db.nodeSize
	db.dataSectionStart = db.treeSize + 16 // 16-byte null separator

	// For IPv6 databases, find the IPv4 subtree root by walking 96 zero bits
	if db.ipVersion == 6 {
		node := uint32(0)
		for i := 0; i < 96; i++ {
			if node >= db.nodeCount {
				break
			}
			node = db.readLeft(node)
		}
		db.ipv4Start = node
	}

	return db, nil
}

// parseMetadata extracts record_size, node_count, ip_version from the metadata map.
func (db *geoIPDB) parseMetadata(offset int) error {
	if offset >= len(db.data) {
		return fmt.Errorf("metadata offset out of bounds")
	}
	typ, size, off := db.decodeControl(offset)
	if typ != 7 { // map
		return fmt.Errorf("expected map at metadata, got type %d", typ)
	}
	for i := 0; i < size; i++ {
		key, nextOff := db.decodeString(off)
		off = nextOff
		switch key {
		case "record_size":
			val, nextOff := db.decodeUint(off)
			db.recordSize = uint16(val)
			off = nextOff
		case "node_count":
			val, nextOff := db.decodeUint(off)
			db.nodeCount = uint32(val)
			off = nextOff
		case "ip_version":
			val, nextOff := db.decodeUint(off)
			db.ipVersion = uint16(val)
			off = nextOff
		default:
			off = db.skipValue(off)
		}
	}
	if db.recordSize == 0 || db.nodeCount == 0 {
		return fmt.Errorf("missing record_size or node_count in metadata")
	}
	return nil
}

// lookupCountry resolves an IP string to an ISO country code (e.g., "US").
// Returns "" if not found or on any error.
func (db *geoIPDB) lookupCountry(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	var ipBytes []byte
	var bitCount int

	ip4 := ip.To4()
	if ip4 != nil {
		ipBytes = ip4
		bitCount = 32
	} else {
		ipBytes = ip.To16()
		bitCount = 128
	}
	if ipBytes == nil {
		return ""
	}

	// Tree traversal
	var node uint32
	if ip4 != nil && db.ipVersion == 6 {
		node = db.ipv4Start
		if node >= db.nodeCount {
			return "" // no IPv4 subtree
		}
	}

	for i := 0; i < bitCount; i++ {
		if node >= db.nodeCount {
			break
		}
		bit := (ipBytes[i/8] >> uint(7-i%8)) & 1
		if bit == 0 {
			node = db.readLeft(node)
		} else {
			node = db.readRight(node)
		}
	}

	if node == db.nodeCount {
		return "" // not found
	}
	if node < db.nodeCount {
		return "" // still in tree (shouldn't happen after full traversal)
	}

	// Resolve data pointer
	dataOffset := int(node-db.nodeCount) - 16 + db.dataSectionStart
	if dataOffset < 0 || dataOffset >= len(db.data) {
		return ""
	}

	return db.extractCountryISO(dataOffset)
}

// extractCountryISO navigates the data record map to find country.iso_code.
func (db *geoIPDB) extractCountryISO(offset int) string {
	typ, size, off := db.decodeControlFollow(offset)
	if typ != 7 { // not a map
		return ""
	}
	for i := 0; i < size; i++ {
		key, nextOff := db.decodeString(off)
		off = nextOff
		if key == "country" {
			return db.extractISOFromSubmap(off)
		}
		off = db.skipValue(off)
	}
	return ""
}

// extractISOFromSubmap reads iso_code from a country sub-map.
func (db *geoIPDB) extractISOFromSubmap(offset int) string {
	typ, size, off := db.decodeControlFollow(offset)
	if typ != 7 { // not a map
		return ""
	}
	for i := 0; i < size; i++ {
		key, nextOff := db.decodeString(off)
		off = nextOff
		if key == "iso_code" {
			val, _ := db.decodeString(off)
			return val
		}
		off = db.skipValue(off)
	}
	return ""
}

// readLeft reads the left record of node n.
func (db *geoIPDB) readLeft(n uint32) uint32 {
	off := int(n) * db.nodeSize
	switch db.recordSize {
	case 24:
		return uint32(db.data[off])<<16 | uint32(db.data[off+1])<<8 | uint32(db.data[off+2])
	case 28:
		return uint32(db.data[off+3]&0xF0)<<20 | uint32(db.data[off])<<16 | uint32(db.data[off+1])<<8 | uint32(db.data[off+2])
	case 32:
		return binary.BigEndian.Uint32(db.data[off : off+4])
	}
	return 0
}

// readRight reads the right record of node n.
func (db *geoIPDB) readRight(n uint32) uint32 {
	off := int(n) * db.nodeSize
	switch db.recordSize {
	case 24:
		return uint32(db.data[off+3])<<16 | uint32(db.data[off+4])<<8 | uint32(db.data[off+5])
	case 28:
		return uint32(db.data[off+3]&0x0F)<<24 | uint32(db.data[off+4])<<16 | uint32(db.data[off+5])<<8 | uint32(db.data[off+6])
	case 32:
		return binary.BigEndian.Uint32(db.data[off+4 : off+8])
	}
	return 0
}

// ─── MMDB Data Section Decoder ───────────────────────────────────────────────

// decodeControl reads the control byte(s) and returns (type, size, newOffset).
func (db *geoIPDB) decodeControl(offset int) (int, int, int) {
	if offset >= len(db.data) {
		return 0, 0, offset
	}
	b := db.data[offset]
	offset++
	typ := int(b >> 5)
	size := int(b & 0x1F)

	// Extended type
	if typ == 0 {
		if offset >= len(db.data) {
			return 0, 0, offset
		}
		typ = int(db.data[offset]) + 7
		offset++
	}

	// Size extension
	if size < 29 {
		// literal
	} else if size == 29 {
		if offset >= len(db.data) {
			return typ, 0, offset
		}
		size = 29 + int(db.data[offset])
		offset++
	} else if size == 30 {
		if offset+1 >= len(db.data) {
			return typ, 0, offset
		}
		size = 285 + int(db.data[offset])<<8 + int(db.data[offset+1])
		offset += 2
	} else if size == 31 {
		if offset+2 >= len(db.data) {
			return typ, 0, offset
		}
		size = 65821 + int(db.data[offset])<<16 + int(db.data[offset+1])<<8 + int(db.data[offset+2])
		offset += 3
	}

	return typ, size, offset
}

// decodePointerAt decodes a pointer starting at offset.
// Returns (resolved data section offset, newOffset past the pointer bytes).
func (db *geoIPDB) decodePointerAt(offset int) (int, int) {
	b := db.data[offset]
	ss := int((b >> 3) & 0x03)
	vvv := int(b & 0x07)
	offset++ // past control byte

	switch ss {
	case 0:
		ptr := vvv<<8 + int(db.data[offset])
		return db.dataSectionStart + ptr, offset + 1
	case 1:
		ptr := 2048 + vvv<<16 + int(db.data[offset])<<8 + int(db.data[offset+1])
		return db.dataSectionStart + ptr, offset + 2
	case 2:
		ptr := 526336 + vvv<<24 + int(db.data[offset])<<16 + int(db.data[offset+1])<<8 + int(db.data[offset+2])
		return db.dataSectionStart + ptr, offset + 3
	case 3:
		ptr := int(binary.BigEndian.Uint32(db.data[offset : offset+4]))
		return db.dataSectionStart + ptr, offset + 4
	}
	return 0, offset
}

// isPointer checks if the byte at offset is a pointer control byte (type bits = 001).
func (db *geoIPDB) isPointer(offset int) bool {
	if offset >= len(db.data) {
		return false
	}
	return (db.data[offset] >> 5) == 1
}

// decodeString reads a UTF-8 string starting at offset. Handles pointer indirection.
func (db *geoIPDB) decodeString(offset int) (string, int) {
	if db.isPointer(offset) {
		ptr, newOff := db.decodePointerAt(offset)
		s, _ := db.decodeString(ptr)
		return s, newOff
	}
	typ, size, off := db.decodeControl(offset)
	if typ != 2 { // not a string
		return "", off + size
	}
	end := off + size
	if end > len(db.data) {
		return "", end
	}
	return string(db.data[off:end]), end
}

// decodeUint reads an unsigned integer starting at offset.
func (db *geoIPDB) decodeUint(offset int) (uint64, int) {
	if db.isPointer(offset) {
		ptr, newOff := db.decodePointerAt(offset)
		v, _ := db.decodeUint(ptr)
		return v, newOff
	}
	_, size, off := db.decodeControl(offset)
	var val uint64
	for i := 0; i < size; i++ {
		if off+i < len(db.data) {
			val = val<<8 | uint64(db.data[off+i])
		}
	}
	return val, off + size
}

// skipValue advances past a value of any type without decoding it.
func (db *geoIPDB) skipValue(offset int) int {
	if offset >= len(db.data) {
		return offset
	}
	if db.isPointer(offset) {
		ss := int((db.data[offset] >> 3) & 0x03)
		return offset + 2 + ss
	}
	b := db.data[offset]
	rawTyp := int(b >> 5)
	_, size, off := db.decodeControl(offset)

	actualTyp := rawTyp
	if rawTyp == 0 && offset+1 < len(db.data) {
		actualTyp = int(db.data[offset+1]) + 7
	}

	switch actualTyp {
	case 7: // map
		for i := 0; i < size; i++ {
			off = db.skipValue(off) // key
			off = db.skipValue(off) // value
		}
		return off
	case 11: // array
		for i := 0; i < size; i++ {
			off = db.skipValue(off)
		}
		return off
	default:
		return off + size
	}
}

// decodeControlFollow reads control byte, following pointers transparently.
func (db *geoIPDB) decodeControlFollow(offset int) (int, int, int) {
	if db.isPointer(offset) {
		ptr, _ := db.decodePointerAt(offset)
		return db.decodeControlFollow(ptr)
	}
	return db.decodeControl(offset)
}
