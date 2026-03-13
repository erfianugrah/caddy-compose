package main

import (
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// responseCache is a lightweight cache for expensive read-path computations.
// Entries are keyed by a string (typically the query param fingerprint) and
// invalidated when the underlying data generation changes. A time-based TTL
// provides a secondary expiry (e.g. for time-relative queries like "last 24h"
// which produce different results even at the same generation).
type responseCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	maxSize int
}

type cacheEntry struct {
	value      interface{}
	generation int64
	created    time.Time
	ttl        time.Duration
}

func newResponseCache(maxSize int) *responseCache {
	return &responseCache{
		entries: make(map[string]*cacheEntry, maxSize),
		maxSize: maxSize,
	}
}

// get returns the cached value if it exists, the generation matches, and
// the TTL hasn't expired. Returns (value, true) on hit, (nil, false) on miss.
func (c *responseCache) get(key string, gen int64) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if e.generation != gen || time.Since(e.created) > e.ttl {
		delete(c.entries, key)
		return nil, false
	}
	return e.value, true
}

// set stores a value in the cache. If the cache is full, the oldest entry
// is evicted.
func (c *responseCache) set(key string, value interface{}, gen int64, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest if at capacity.
	if len(c.entries) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, e := range c.entries {
			if first || e.created.Before(oldestTime) {
				oldestKey = k
				oldestTime = e.created
				first = false
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}

	c.entries[key] = &cacheEntry{
		value:      value,
		generation: gen,
		created:    time.Now(),
		ttl:        ttl,
	}
}

// combinedGeneration returns a composite generation from two stores.
// A change in either store invalidates the cache.
func combinedGeneration(a, b *atomic.Int64) int64 {
	return a.Load()*1_000_000 + b.Load()
}

// normalizeCacheKey sorts query parameters to produce a canonical cache key.
// This prevents cache-key splitting attacks where reordering the same parameters
// (e.g. "hours=24&service=foo" vs "service=foo&hours=24") creates separate entries.
func normalizeCacheKey(rawQuery string) string {
	params, err := url.ParseQuery(rawQuery)
	if err != nil || len(params) == 0 {
		return rawQuery
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		vals := params[k]
		sort.Strings(vals)
		for j, v := range vals {
			if i > 0 || j > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}
