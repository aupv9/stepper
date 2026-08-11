package gateway

import (
	"sync"
	"time"
)

// RateLimiter decides whether a request identified by key may proceed.
type RateLimiter interface {
	// Allow reports whether a request for the given key is permitted now.
	Allow(key string) bool
}

// TokenBucketLimiter is an in-memory per-key token-bucket rate limiter. Each key
// (e.g. client IP) gets a bucket that refills at Rate tokens/second up to Burst.
// Safe for concurrent use.
type TokenBucketLimiter struct {
	rate  float64 // tokens per second
	burst float64

	mu      sync.Mutex
	buckets map[string]*bucket
	nowFn   func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewTokenBucketLimiter creates a limiter allowing `rate` requests/second per
// key with a burst capacity. A non-positive rate disables limiting (Allow
// always true).
func NewTokenBucketLimiter(rate float64, burst int) *TokenBucketLimiter {
	l := &TokenBucketLimiter{
		rate:    rate,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		nowFn:   time.Now,
	}
	if rate > 0 {
		go l.cleanupLoop()
	}
	return l
}

// Allow consumes one token for key, refilling based on elapsed time.
func (l *TokenBucketLimiter) Allow(key string) bool {
	if l.rate <= 0 {
		return true
	}
	now := l.nowFn()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		// New key starts full, minus the current request.
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}

	// Refill according to elapsed time, capped at burst.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// cleanupLoop drops idle buckets that have fully refilled so the map doesn't
// grow unbounded under churn of distinct keys.
func (l *TokenBucketLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := l.nowFn()
		l.mu.Lock()
		for key, b := range l.buckets {
			elapsed := now.Sub(b.last).Seconds()
			if b.tokens+elapsed*l.rate >= l.burst {
				delete(l.buckets, key)
			}
		}
		l.mu.Unlock()
	}
}
