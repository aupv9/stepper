package gateway

import (
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
