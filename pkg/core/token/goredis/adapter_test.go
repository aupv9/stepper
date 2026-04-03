package goredis

import (
	"context"
	"testing"
	"time"

	iamtoken "github.com/common-iam/iam/pkg/core/token"
)

// Compile-time check: Adapter must implement token.RedisClient.
var _ iamtoken.RedisClient = (*Adapter)(nil)

// mockRedisClient is a simple in-memory mock implementing iamtoken.RedisClient,
// used to verify the adapter's interface contract without a real Redis server.
type mockRedisClient struct {
	data map[string]string
}

func newMock() *mockRedisClient {
	return &mockRedisClient{data: make(map[string]string)}
}

func (m *mockRedisClient) Get(_ context.Context, key string) (string, error) {
	return m.data[key], nil
}

func (m *mockRedisClient) Set(_ context.Context, key, value string, _ time.Duration) error {
	m.data[key] = value
	return nil
}

func (m *mockRedisClient) Del(_ context.Context, keys ...string) error {
	for _, k := range keys {
		delete(m.data, k)
	}
	return nil
}

func (m *mockRedisClient) FlushDB(_ context.Context) error {
	m.data = make(map[string]string)
	return nil
}

// Verify the mock satisfies the same interface.
var _ iamtoken.RedisClient = (*mockRedisClient)(nil)

func TestRedisCache_SetAndGet(t *testing.T) {
	mock := newMock()
	cache := iamtoken.NewRedisCache(mock, "test:")
	ctx := context.Background()

	claims := &iamtoken.CommonClaims{
		Subject: "alice",
		ACR:     "silver",
		Active:  true,
	}

	if err := cache.Set(ctx, "key1", claims, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, ok := cache.Get(ctx, "key1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Subject != "alice" {
		t.Errorf("subject: got %q, want %q", got.Subject, "alice")
	}
	if got.ACR != "silver" {
		t.Errorf("acr: got %q, want %q", got.ACR, "silver")
	}
}

func TestRedisCache_Delete(t *testing.T) {
	mock := newMock()
	cache := iamtoken.NewRedisCache(mock, "test:")
	ctx := context.Background()

	claims := &iamtoken.CommonClaims{Subject: "bob", Active: true}
	_ = cache.Set(ctx, "key2", claims, time.Minute)

	if err := cache.Delete(ctx, "key2"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, ok := cache.Get(ctx, "key2")
	if ok {
		t.Fatal("expected cache miss after delete")
	}
}

func TestRedisCache_Flush(t *testing.T) {
	mock := newMock()
	cache := iamtoken.NewRedisCache(mock, "test:")
	ctx := context.Background()

	_ = cache.Set(ctx, "k1", &iamtoken.CommonClaims{Subject: "a", Active: true}, time.Minute)
	_ = cache.Set(ctx, "k2", &iamtoken.CommonClaims{Subject: "b", Active: true}, time.Minute)

	if err := cache.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if _, ok := cache.Get(ctx, "k1"); ok {
		t.Error("expected miss after flush")
	}
}

func TestRedisCache_Miss(t *testing.T) {
	mock := newMock()
	cache := iamtoken.NewRedisCache(mock, "test:")
	ctx := context.Background()

	_, ok := cache.Get(ctx, "nonexistent")
	if ok {
		t.Fatal("expected cache miss for unknown key")
	}
}
