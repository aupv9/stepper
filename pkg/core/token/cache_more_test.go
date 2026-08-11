package token

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeRedis is an in-memory RedisClient for testing RedisCache without a server.
type fakeRedis struct {
	mu   sync.Mutex
	data map[string]string
}

func newFakeRedis() *fakeRedis { return &fakeRedis{data: map[string]string{}} }

func (f *fakeRedis) Get(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data[key], nil
}
func (f *fakeRedis) Set(_ context.Context, key, value string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
	return nil
}
func (f *fakeRedis) Del(_ context.Context, keys ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range keys {
		delete(f.data, k)
	}
	return nil
}
func (f *fakeRedis) FlushDB(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data = map[string]string{}
	return nil
}

func TestRedisCache_RoundTrip(t *testing.T) {
	ctx := context.Background()
	c := NewRedisCache(newFakeRedis(), "") // default prefix
	claims := &CommonClaims{Active: true, Subject: "bob", JTI: "j1"}

	if err := c.Set(ctx, "k", claims, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok := c.Get(ctx, "k")
	if !ok || got.Subject != "bob" {
		t.Fatalf("Get returned %+v, ok=%v", got, ok)
	}
	if _, ok := c.Get(ctx, "missing"); ok {
		t.Error("missing key should be a miss")
	}
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := c.Get(ctx, "k"); ok {
		t.Error("expected miss after Delete")
	}
	// Re-add then Flush.
	_ = c.Set(ctx, "k2", claims, time.Minute)
	if err := c.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, ok := c.Get(ctx, "k2"); ok {
		t.Error("expected miss after Flush")
	}
}

func TestMemoryCache_Flush(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache()
	_ = c.Set(ctx, "a", &CommonClaims{Active: true}, time.Minute)
	if err := c.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, ok := c.Get(ctx, "a"); ok {
		t.Error("expected miss after Flush")
	}
}

func TestCachedIntrospector_Revoke(t *testing.T) {
	ctx := context.Background()
	srv := introspectServer(t, IntrospectionResponse{Active: true, Sub: "u", Exp: time.Now().Add(time.Hour).Unix()})
	cache := NewMemoryCache()
	ci := NewCachedIntrospector(NewIntrospector(IntrospectorConfig{Endpoint: srv.URL}), cache, time.Minute)

	if _, err := ci.Introspect(ctx, "tok"); err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if _, ok := cache.Get(ctx, HashToken("tok")); !ok {
		t.Fatal("token should be cached")
	}
	ci.Revoke(ctx, "tok")
	if _, ok := cache.Get(ctx, HashToken("tok")); ok {
		t.Error("token should be evicted after Revoke")
	}
}

func TestClaims_HasRoleAndExtractBearer(t *testing.T) {
	c := &CommonClaims{Roles: []string{"admin", "user"}}
	if !c.HasRole("admin") || c.HasRole("root") {
		t.Error("HasRole mismatch")
	}

	tok, err := ExtractBearerToken("Bearer abc.def")
	if err != nil || tok != "abc.def" {
		t.Errorf("ExtractBearerToken = %q, %v", tok, err)
	}
	if _, err := ExtractBearerToken(""); err == nil {
		t.Error("empty header should error")
	}
	if _, err := ExtractBearerToken("Basic xyz"); err == nil {
		t.Error("non-bearer scheme should error")
	}
}
