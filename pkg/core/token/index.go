package token

import (
	"context"
	"sync"
	"time"
)

// TokenIndex maps a token's jti and subject to the cache key(s) (token hashes)
// under which its claims are cached. The introspection cache is keyed by
// sha256(token), but revocation webhooks typically only carry a jti or a
// subject — this index lets those events resolve the correct cache key(s)
// instead of guessing (which previously made jti-based revocation a no-op).
type TokenIndex interface {
	// Add records that the given tokenHash belongs to jti and subject.
	// Empty jti or subject are ignored. The mapping expires after ttl.
	Add(ctx context.Context, tokenHash, jti, subject string, ttl time.Duration) error

	// KeysByJTI returns the cache keys associated with a jti.
	KeysByJTI(ctx context.Context, jti string) ([]string, error)

	// KeysBySubject returns the cache keys associated with a subject.
	KeysBySubject(ctx context.Context, subject string) ([]string, error)
}

// --- In-memory implementation ---

type indexEntry struct {
	hashes map[string]time.Time // tokenHash -> expiry
}

// MemoryTokenIndex is an in-process TokenIndex suitable for single-instance
// deployments or development. It is safe for concurrent use.
type MemoryTokenIndex struct {
	mu        sync.Mutex
	byJTI     map[string]*indexEntry
	bySubject map[string]*indexEntry
}

// NewMemoryTokenIndex creates an empty in-memory index with background cleanup.
func NewMemoryTokenIndex() *MemoryTokenIndex {
	idx := &MemoryTokenIndex{
		byJTI:     make(map[string]*indexEntry),
		bySubject: make(map[string]*indexEntry),
	}
	go idx.cleanupLoop()
	return idx
}

func (idx *MemoryTokenIndex) Add(_ context.Context, tokenHash, jti, subject string, ttl time.Duration) error {
	if tokenHash == "" || ttl <= 0 {
		return nil
	}
	exp := time.Now().Add(ttl)
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if jti != "" {
		addTo(idx.byJTI, jti, tokenHash, exp)
	}
	if subject != "" {
		addTo(idx.bySubject, subject, tokenHash, exp)
	}
	return nil
}

func (idx *MemoryTokenIndex) KeysByJTI(_ context.Context, jti string) ([]string, error) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	return liveKeys(idx.byJTI, jti), nil
}

func (idx *MemoryTokenIndex) KeysBySubject(_ context.Context, subject string) ([]string, error) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	return liveKeys(idx.bySubject, subject), nil
}

func addTo(m map[string]*indexEntry, key, hash string, exp time.Time) {
	e, ok := m[key]
	if !ok {
		e = &indexEntry{hashes: make(map[string]time.Time)}
		m[key] = e
	}
	e.hashes[hash] = exp
}

func liveKeys(m map[string]*indexEntry, key string) []string {
	e, ok := m[key]
	if !ok {
		return nil
	}
	now := time.Now()
	out := make([]string, 0, len(e.hashes))
	for h, exp := range e.hashes {
		if now.After(exp) {
			delete(e.hashes, h)
			continue
		}
		out = append(out, h)
	}
	if len(e.hashes) == 0 {
		delete(m, key)
	}
	return out
}

func (idx *MemoryTokenIndex) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		idx.mu.Lock()
		now := time.Now()
		for _, m := range []map[string]*indexEntry{idx.byJTI, idx.bySubject} {
			for key, e := range m {
				for h, exp := range e.hashes {
					if now.After(exp) {
						delete(e.hashes, h)
					}
				}
				if len(e.hashes) == 0 {
					delete(m, key)
				}
			}
		}
		idx.mu.Unlock()
	}
}
