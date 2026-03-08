package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

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
	if off+db.nodeSize > len(db.data) {
		return 0 // bounds check: corrupted or truncated MMDB
	}
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
	if off+db.nodeSize > len(db.data) {
		return 0 // bounds check: corrupted or truncated MMDB
	}
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
