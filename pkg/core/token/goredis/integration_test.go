package goredis

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	iamtoken "github.com/common-iam/iam/pkg/core/token"
)

// TestRedisCache_Integration exercises the adapter against a real Redis server.
// It is skipped unless IAM_TEST_REDIS_ADDR is set (e.g. "127.0.0.1:6379"), so
// the default `go test ./...` run needs no external dependency while CI or a
// developer with Redis available gets real coverage of the adapter + RedisCache.
func TestRedisCache_Integration(t *testing.T) {
	addr := os.Getenv("IAM_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set IAM_TEST_REDIS_ADDR to run the Redis integration test")
	}

	ctx := context.Background()
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("cannot reach Redis at %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = client.Close() })

	cache := iamtoken.NewRedisCache(New(client), "iamtest:")
	t.Cleanup(func() { _ = cache.Flush(ctx) })

	key := iamtoken.HashToken("integration-token")
	claims := &iamtoken.CommonClaims{Active: true, Subject: "alice", JTI: "j-int"}

	if err := cache.Set(ctx, key, claims, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok := cache.Get(ctx, key)
	if !ok {
		t.Fatal("expected cache hit after Set")
	}
	if got.Subject != "alice" || !got.Active {
		t.Errorf("round-tripped claims mismatch: %+v", got)
	}

	if err := cache.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := cache.Get(ctx, key); ok {
		t.Error("expected miss after Delete")
	}
}
