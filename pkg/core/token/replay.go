package token

import (
	"context"
	"sync"
	"time"
)

// ReplayGuard detects reuse of a DPoP proof's jti within its freshness window
// (RFC 9449 §11.1). A proof whose htm/htu are fixed can otherwise be replayed
// against the same endpoint until it ages out.
type ReplayGuard interface {
	// CheckAndSet atomically records jti and reports whether it was already
	// seen (and still live). The mapping expires after ttl.
	CheckAndSet(ctx context.Context, jti string, ttl time.Duration) (seen bool, err error)
}

// MemoryReplayGuard is an in-process ReplayGuard for single-instance
// deployments or development. Safe for concurrent use.
type MemoryReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti -> expiry
}

// NewMemoryReplayGuard creates an empty replay guard with background cleanup.
func NewMemoryReplayGuard() *MemoryReplayGuard {
	g := &MemoryReplayGuard{seen: make(map[string]time.Time)}
	go g.cleanupLoop()
	return g
}

func (g *MemoryReplayGuard) CheckAndSet(_ context.Context, jti string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		ttl = time.Minute
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if exp, ok := g.seen[jti]; ok && now.Before(exp) {
		return true, nil
	}
	g.seen[jti] = now.Add(ttl)
	return false, nil
}

func (g *MemoryReplayGuard) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		g.mu.Lock()
		now := time.Now()
		for jti, exp := range g.seen {
			if now.After(exp) {
				delete(g.seen, jti)
			}
		}
		g.mu.Unlock()
	}
}
