package riskanalysis

import (
	"container/list"
	"sync"
	"time"
)

// LocalReputationCache caches local safe/malicious verdicts with TTL and LRU bounds.
type LocalReputationCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	now      func() time.Time
	items    map[string]*list.Element
	order    *list.List
}

type reputationEntry struct {
	Hash      string
	Decision  WhitelistDecision
	ExpiresAt time.Time
}

func NewLocalReputationCache(capacity int, ttl time.Duration) *LocalReputationCache {
	if capacity <= 0 {
		capacity = 4096
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &LocalReputationCache{
		capacity: capacity,
		ttl:      ttl,
		now:      time.Now,
		items:    make(map[string]*list.Element, capacity),
		order:    list.New(),
	}
}

func (c *LocalReputationCache) Get(hash string) (WhitelistDecision, *time.Time, bool) {
	if c == nil {
		return "", nil, false
	}
	key := normalizeHex(hash)
	if key == "" {
		return "", nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ele, ok := c.items[key]
	if !ok {
		return "", nil, false
	}
	entry := ele.Value.(*reputationEntry)
	now := c.clockNow()
	if now.After(entry.ExpiresAt) {
		c.removeElement(ele)
		return "", nil, false
	}
	c.order.MoveToFront(ele)
	expires := entry.ExpiresAt
	return entry.Decision, &expires, true
}

func (c *LocalReputationCache) Set(hash string, decision WhitelistDecision) {
	if c == nil {
		return
	}
	key := normalizeHex(hash)
	if key == "" {
		return
	}
	if decision != WhitelistDecisionAllow && decision != WhitelistDecisionDeny {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, ok := c.items[key]; ok {
		entry := ele.Value.(*reputationEntry)
		entry.Decision = decision
		entry.ExpiresAt = c.clockNow().Add(c.ttl)
		c.order.MoveToFront(ele)
		return
	}
	entry := &reputationEntry{
		Hash:      key,
		Decision:  decision,
		ExpiresAt: c.clockNow().Add(c.ttl),
	}
	ele := c.order.PushFront(entry)
	c.items[key] = ele
	for len(c.items) > c.capacity {
		c.removeElement(c.order.Back())
	}
}

func (c *LocalReputationCache) clockNow() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *LocalReputationCache) removeElement(ele *list.Element) {
	if c == nil || ele == nil {
		return
	}
	c.order.Remove(ele)
	entry := ele.Value.(*reputationEntry)
	delete(c.items, entry.Hash)
}
