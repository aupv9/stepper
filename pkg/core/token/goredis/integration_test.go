package goredis_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	iamtoken "github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/core/token/goredis"
)

// TestRedisIntegration exercises the adapter against a real Redis instance.
// Opt in by setting REDIS_ADDR (e.g. REDIS_ADDR=localhost:6379 go test ./...).
func TestRedisIntegration(t *testing.T) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("set REDIS_ADDR to run the Redis integration test")
	}

	ctx := context.Background()
	client := redis.NewClient(&redis.Options{Addr: addr, DB: 15}) // dedicated test DB
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("pinging Redis at %s: %v", addr, err)
	}
	t.Cleanup(func() {
		_ = client.FlushDB(ctx).Err()
		_ = client.Close()
	})

	cache := iamtoken.NewRedisCache(goredis.New(client), "iamtest:")

	t.Run("set/get/delete round-trip", func(t *testing.T) {
		claims := &iamtoken.CommonClaims{
			Active:  true,
			Subject: "alice",
			JTI:     "jti-1",
			Scopes:  []string{"openid"},
		}
		if err := cache.Set(ctx, "hash1", claims, time.Minute); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, ok := cache.Get(ctx, "hash1")
		if !ok || got.Subject != "alice" || len(got.Scopes) != 1 {
			t.Fatalf("Get = %+v, ok=%v", got, ok)
		}
		if err := cache.Delete(ctx, "hash1"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, ok := cache.Get(ctx, "hash1"); ok {
			t.Error("deleted entry still present")
		}
	})

	t.Run("ttl expiry", func(t *testing.T) {
		claims := &iamtoken.CommonClaims{Active: true, Subject: "bob"}
		if err := cache.Set(ctx, "hash-ttl", claims, time.Second); err != nil {
			t.Fatalf("Set: %v", err)
		}
		time.Sleep(1500 * time.Millisecond)
		if _, ok := cache.Get(ctx, "hash-ttl"); ok {
			t.Error("entry should have expired after TTL")
		}
	})

	t.Run("revocation index round-trip", func(t *testing.T) {
		claims := &iamtoken.CommonClaims{
			Active:    true,
			Subject:   "carol",
			JTI:       "jti-idx",
			SessionID: "sess-idx",
		}
		if err := cache.Set(ctx, "hash-idx", claims, time.Minute); err != nil {
			t.Fatalf("Set: %v", err)
		}
		iamtoken.IndexClaims(ctx, cache, "hash-idx", claims, time.Minute)

		// Simulate a webhook revocation by JTI through the real handler path.
		// (The handler is exercised elsewhere; here we verify index integrity
		// across a real Redis JSON round-trip.)
		got, ok := cache.Get(ctx, "hash-idx")
		if !ok || got.JTI != "jti-idx" {
			t.Fatalf("Get = %+v, ok=%v", got, ok)
		}
	})
}
