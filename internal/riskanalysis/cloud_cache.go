package riskanalysis

import (
	"sync"
	"time"
)

type cloudCache struct {
	mu    sync.Mutex
	items map[string]cloudCacheEntry
	TTL   time.Duration
}

type cloudCacheEntry struct {
	analysis CloudAnalysis
	score    float64
	expires  time.Time
}

func newCloudCache(ttl time.Duration) *cloudCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &cloudCache{
		items: make(map[string]cloudCacheEntry),
		TTL:   ttl,
	}
}

func (c *cloudCache) Get(key string) (CloudAnalysis, float64, bool) {
	if c == nil {
		return CloudAnalysis{}, 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.items[key]
	if !ok {
		return CloudAnalysis{}, 0, false
	}
	if time.Now().After(entry.expires) {
		delete(c.items, key)
		return CloudAnalysis{}, 0, false
	}
	return entry.analysis, entry.score, true
}

func (c *cloudCache) Set(key string, analysis CloudAnalysis, score float64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = cloudCacheEntry{
		analysis: analysis,
		score:    score,
		expires:  time.Now().Add(c.TTL),
	}
}
