package token

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeRedis implements RedisClient over a plain map (no TTL expiry).
type fakeRedis struct {
	data map[string]string
}

func newFakeRedis() *fakeRedis { return &fakeRedis{data: make(map[string]string)} }

func (f *fakeRedis) Get(_ context.Context, key string) (string, error) {
	v, ok := f.data[key]
	if !ok {
		return "", errors.New("redis: nil")
	}
	return v, nil
}

func (f *fakeRedis) Set(_ context.Context, key, value string, _ time.Duration) error {
	f.data[key] = value
	return nil
}

func (f *fakeRedis) Del(_ context.Context, keys ...string) error {
	for _, k := range keys {
		delete(f.data, k)
	}
	return nil
}

func (f *fakeRedis) FlushDB(_ context.Context) error {
	f.data = make(map[string]string)
	return nil
}

func TestRedisCache_RoundTrip(t *testing.T) {
	ctx := context.Background()
	client := newFakeRedis()
	c := NewRedisCache(client, "")

	claims := &CommonClaims{Active: true, Subject: "alice", JTI: "j1"}
	if err := c.Set(ctx, "hash1", claims, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Key prefix applied.
	for k := range client.data {
		if !strings.HasPrefix(k, "iam:token:") {
			t.Errorf("key %q missing default prefix", k)
		}
	}

	got, ok := c.Get(ctx, "hash1")
	if !ok || got.Subject != "alice" || got.JTI != "j1" {
		t.Fatalf("Get = %+v, ok=%v", got, ok)
	}

	if _, ok := c.Get(ctx, "missing"); ok {
		t.Error("missing key must not be found")
	}

	if err := c.Delete(ctx, "hash1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := c.Get(ctx, "hash1"); ok {
		t.Error("deleted key must not be found")
	}

	_ = c.Set(ctx, "hash2", claims, time.Minute)
	if err := c.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, ok := c.Get(ctx, "hash2"); ok {
		t.Error("flushed key must not be found")
	}
}

// TestRedisCache_IndexRoundTrip verifies the revocation secondary index
// survives the JSON round-trip a real Redis imposes ([]string → []interface{}).
func TestRedisCache_IndexRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := NewRedisCache(newFakeRedis(), "")

	claims := &CommonClaims{Active: true, Subject: "alice", JTI: "j1", SessionID: "s1"}
	_ = c.Set(ctx, "hash1", claims, time.Minute)
	IndexClaims(ctx, c, "hash1", claims, time.Minute)

	if hash, ok := lookupIndexHash(ctx, c, jtiIndexPrefix+"j1"); !ok || hash != "hash1" {
		t.Errorf("jti index lookup = %q, %v", hash, ok)
	}
	if hashes := indexHashes(ctx, c, subIndexPrefix+"alice"); len(hashes) != 1 || hashes[0] != "hash1" {
		t.Errorf("subject index = %v", hashes)
	}
	if err := deleteIndexedTokens(ctx, c, sidIndexPrefix+"s1"); err != nil {
		t.Fatalf("deleteIndexedTokens: %v", err)
	}
	if _, ok := c.Get(ctx, "hash1"); ok {
		t.Error("session index deletion must evict the token entry")
	}
}
