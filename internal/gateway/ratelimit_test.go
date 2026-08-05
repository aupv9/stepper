package gateway

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_BurstThenBlock(t *testing.T) {
	rl := newRateLimiter(10, 3)

	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d within burst should be allowed", i+1)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Error("request over burst should be blocked")
	}

	// A different client has its own bucket.
	if !rl.allow("5.6.7.8") {
		t.Error("other client must not be affected")
	}

	// Refill: at 10 rps, ~150ms restores at least one token.
	time.Sleep(150 * time.Millisecond)
	if !rl.allow("1.2.3.4") {
		t.Error("bucket should refill over time")
	}
}

// fakeCounter is an in-memory RateCounter simulating Redis INCR semantics.
type fakeCounter struct {
	mu     sync.Mutex
	counts map[string]int64
}

func (f *fakeCounter) Incr(_ context.Context, key string, _ time.Duration) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.counts == nil {
		f.counts = make(map[string]int64)
	}
	f.counts[key]++
	return f.counts[key], nil
}

func TestDistributedRateLimiter(t *testing.T) {
	counter := &fakeCounter{}
	// Two limiter instances sharing one counter = two gateway replicas.
	l1 := newDistributedRateLimiter(counter, 3, 0)
	l2 := newDistributedRateLimiter(counter, 3, 0)

	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "9.9.9.9:1234"

	allowed := 0
	for i := 0; i < 6; i++ {
		l := l1
		if i%2 == 1 {
			l = l2 // alternate replicas
		}
		if l.allowRequest(req) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("allowed %d requests across replicas, want 3 (shared window)", allowed)
	}

	// A different client IP is counted separately.
	other := httptest.NewRequest("GET", "/x", nil)
	other.RemoteAddr = "8.8.8.8:1234"
	if !l1.allowRequest(other) {
		t.Error("different client must have its own window")
	}
}
