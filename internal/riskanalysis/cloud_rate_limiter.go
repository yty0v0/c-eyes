package riskanalysis

import (
	"context"
	"errors"
	"sync"
	"time"
)

type rateLimiter struct {
	ticker *time.Ticker
}

var ErrRateLimited = errors.New("cloud rate limit exceeded")

func newRateLimiter(interval time.Duration) *rateLimiter {
	if interval <= 0 {
		return nil
	}
	return &rateLimiter{ticker: time.NewTicker(interval)}
}

func (r *rateLimiter) Wait(ctx context.Context) error {
	if r == nil || r.ticker == nil {
		return nil
	}
	select {
	case <-r.ticker.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type tokenBucketLimiter struct {
	mu             sync.Mutex
	capacity       float64
	tokens         float64
	refillPerSec   float64
	lastRefillTime time.Time
}

func newTokenBucketLimiter(capacity int, refillWindow time.Duration) *tokenBucketLimiter {
	if capacity <= 0 || refillWindow <= 0 {
		return nil
	}
	return &tokenBucketLimiter{
		capacity:       float64(capacity),
		tokens:         float64(capacity),
		refillPerSec:   float64(capacity) / refillWindow.Seconds(),
		lastRefillTime: time.Now(),
	}
}

func (l *tokenBucketLimiter) TryTake() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refill(time.Now())
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

func (l *tokenBucketLimiter) refill(now time.Time) {
	elapsed := now.Sub(l.lastRefillTime).Seconds()
	if elapsed <= 0 {
		return
	}
	l.tokens += elapsed * l.refillPerSec
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
	l.lastRefillTime = now
}
