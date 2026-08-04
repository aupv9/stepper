package gateway

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a per-key token-bucket rate limiter (no external deps).
// Buckets refill at rps tokens/second up to burst; a request consumes one
// token. Idle buckets are evicted periodically to bound memory.
type rateLimiter struct {
	rps   float64
	burst float64

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

func newRateLimiter(rps float64, burst int) *rateLimiter {
	if burst <= 0 {
		burst = int(rps)
		if burst < 1 {
			burst = 1
		}
	}
	rl := &rateLimiter{
		rps:     rps,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
	}
	go rl.cleanupLoop()
	return rl
}

// allow reports whether the request identified by key may proceed.
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{tokens: rl.burst - 1, lastSeen: now}
		return true
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * rl.rps
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-5 * time.Minute)
		rl.mu.Lock()
		for k, b := range rl.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

// clientKey extracts the rate-limit key for a request: the client IP.
// RemoteAddr is used as-is (host part); X-Forwarded-For is deliberately NOT
// trusted here — terminate it at your edge or wrap the guard if needed.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
