package gateway

import (
	"testing"
	"time"
)

func TestTokenBucketLimiter_BurstThenDeny(t *testing.T) {
	now := time.Now()
	l := &TokenBucketLimiter{rate: 1, burst: 3, buckets: map[string]*bucket{}, nowFn: func() time.Time { return now }}

	// Burst of 3 allowed, 4th denied (no time elapsed → no refill).
	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d within burst should be allowed", i+1)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("4th request should be denied after burst is exhausted")
	}

	// A different key has its own bucket.
	if !l.Allow("5.6.7.8") {
		t.Fatal("distinct key should have its own bucket")
	}
}

func TestTokenBucketLimiter_RefillsOverTime(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	l := &TokenBucketLimiter{rate: 2, burst: 2, buckets: map[string]*bucket{}, nowFn: nowFn}

	if !l.Allow("k") || !l.Allow("k") {
		t.Fatal("first two requests should be allowed")
	}
	if l.Allow("k") {
		t.Fatal("third immediate request should be denied")
	}
	// Advance 1s → rate 2/s refills 2 tokens.
	now = now.Add(1 * time.Second)
	if !l.Allow("k") {
		t.Fatal("after 1s a refilled token should allow the request")
	}
}

func TestTokenBucketLimiter_DisabledWhenRateZero(t *testing.T) {
	l := NewTokenBucketLimiter(0, 0)
	for i := 0; i < 100; i++ {
		if !l.Allow("x") {
			t.Fatal("rate<=0 must disable limiting")
		}
	}
}
