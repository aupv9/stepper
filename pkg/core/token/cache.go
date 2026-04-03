package token

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Cache defines the interface for token claim caching.
type Cache interface {
	Get(ctx context.Context, tokenHash string) (*CommonClaims, bool)
	Set(ctx context.Context, tokenHash string, claims *CommonClaims, ttl time.Duration) error
	Delete(ctx context.Context, tokenHash string) error
	Flush(ctx context.Context) error
}

// HashToken returns a SHA-256 hash of the token string for use as a cache key.
// We never store the raw token.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// --- In-Memory Cache ---

type memoryCacheEntry struct {
	claims    *CommonClaims
	expiresAt time.Time
}

// MemoryCache is a simple in-process token cache.
// Suitable for single-instance deployments or development.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]memoryCacheEntry
}

// NewMemoryCache creates a new in-memory cache with background cleanup.
func NewMemoryCache() *MemoryCache {
	mc := &MemoryCache{entries: make(map[string]memoryCacheEntry)}
	go mc.cleanupLoop()
	return mc
}

func (m *MemoryCache) Get(_ context.Context, key string) (*CommonClaims, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.claims, true
}

func (m *MemoryCache) Set(_ context.Context, key string, claims *CommonClaims, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = memoryCacheEntry{claims: claims, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (m *MemoryCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

func (m *MemoryCache) Flush(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = make(map[string]memoryCacheEntry)
	return nil
}

func (m *MemoryCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for k, v := range m.entries {
			if now.After(v.expiresAt) {
				delete(m.entries, k)
			}
		}
		m.mu.Unlock()
	}
}

// --- Redis Cache ---

// RedisClient defines the subset of Redis operations we need.
// This abstraction allows using go-redis or any compatible client.
type RedisClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
	FlushDB(ctx context.Context) error
}

// RedisCache is a distributed token cache backed by Redis.
type RedisCache struct {
	client    RedisClient
	keyPrefix string
}

// NewRedisCache creates a Redis-backed cache.
func NewRedisCache(client RedisClient, keyPrefix string) *RedisCache {
	if keyPrefix == "" {
		keyPrefix = "iam:token:"
	}
	return &RedisCache{client: client, keyPrefix: keyPrefix}
}

func (r *RedisCache) Get(ctx context.Context, key string) (*CommonClaims, bool) {
	val, err := r.client.Get(ctx, r.keyPrefix+key)
	if err != nil || val == "" {
		return nil, false
	}
	var claims CommonClaims
	if err := json.Unmarshal([]byte(val), &claims); err != nil {
		return nil, false
	}
	return &claims, true
}

func (r *RedisCache) Set(ctx context.Context, key string, claims *CommonClaims, ttl time.Duration) error {
	b, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("marshaling claims: %w", err)
	}
	return r.client.Set(ctx, r.keyPrefix+key, string(b), ttl)
}

func (r *RedisCache) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, r.keyPrefix+key)
}

func (r *RedisCache) Flush(ctx context.Context) error {
	return r.client.FlushDB(ctx)
}

// --- Cached Introspector ---

// CachedIntrospector wraps an Introspector with a Cache layer.
type CachedIntrospector struct {
	inner *Introspector
	cache Cache
	ttl   time.Duration
}

// NewCachedIntrospector creates an introspector with caching.
// Default TTL is 30 seconds (short enough to catch revocations quickly).
func NewCachedIntrospector(inner *Introspector, cache Cache, ttl time.Duration) *CachedIntrospector {
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	return &CachedIntrospector{inner: inner, cache: cache, ttl: ttl}
}

// Introspect checks cache first; falls through to the AS on miss.
func (ci *CachedIntrospector) Introspect(ctx context.Context, token string) (*CommonClaims, error) {
	key := HashToken(token)

	if claims, ok := ci.cache.Get(ctx, key); ok {
		return claims, nil
	}

	claims, err := ci.inner.Introspect(ctx, token)
	if err != nil {
		return nil, err
	}

	// Only cache active tokens
	if claims.Active {
		_ = ci.cache.Set(ctx, key, claims, ci.ttl)
	}

	return claims, nil
}

// Revoke removes a token from cache (call on revocation events).
func (ci *CachedIntrospector) Revoke(ctx context.Context, token string) {
	_ = ci.cache.Delete(ctx, HashToken(token))
}
