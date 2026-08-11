package token

import (
	"context"
	"testing"
	"time"
)

// BenchmarkCachedIntrospector_Hit measures the hot path: an introspection that
// is served entirely from the cache without an AS round-trip.
func BenchmarkCachedIntrospector_Hit(b *testing.B) {
	ctx := context.Background()
	srv := introspectServer(b, IntrospectionResponse{
		Active: true, Sub: "u", Exp: time.Now().Add(time.Hour).Unix(),
	})
	ci := NewCachedIntrospector(
		NewIntrospector(IntrospectorConfig{Endpoint: srv.URL}),
		NewMemoryCache(), 30*time.Second,
	)
	// Warm the cache.
	if _, err := ci.Introspect(ctx, "tok"); err != nil {
		b.Fatalf("warm introspect: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ci.Introspect(ctx, "tok"); err != nil {
			b.Fatalf("introspect: %v", err)
		}
	}
}

// BenchmarkHashToken measures the per-request cache-key hashing cost.
func BenchmarkHashToken(b *testing.B) {
	const tok = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payloadpayloadpayload.sig"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = HashToken(tok)
	}
}
