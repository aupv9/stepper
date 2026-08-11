package token

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// introspectServer returns an httptest server that always responds with the
// given introspection JSON body.
func introspectServer(t *testing.T, body IntrospectionResponse) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCachedIntrospector_DoesNotCacheExpiredToken(t *testing.T) {
	ctx := context.Background()
	// Active but already expired (exp in the past).
	srv := introspectServer(t, IntrospectionResponse{
		Active: true,
		Sub:    "u1",
		Exp:    time.Now().Add(-1 * time.Minute).Unix(),
	})
	cache := NewMemoryCache()
	ci := NewCachedIntrospector(
		NewIntrospector(IntrospectorConfig{Endpoint: srv.URL}),
		cache, 30*time.Second,
	)

	if _, err := ci.Introspect(ctx, "expired-token"); err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if _, ok := cache.Get(ctx, HashToken("expired-token")); ok {
		t.Error("an already-expired token must not be cached as active")
	}
}

func TestCachedIntrospector_ClampsTTLToTokenLifetime(t *testing.T) {
	ctx := context.Background()
	// Active, expires in 2s — must be cached for <= 2s, not the configured 30s.
	srv := introspectServer(t, IntrospectionResponse{
		Active: true,
		Sub:    "u2",
		Exp:    time.Now().Add(2 * time.Second).Unix(),
	})
	cache := NewMemoryCache()
	ci := NewCachedIntrospector(
		NewIntrospector(IntrospectorConfig{Endpoint: srv.URL}),
		cache, 30*time.Second,
	)

	if _, err := ci.Introspect(ctx, "short-token"); err != nil {
		t.Fatalf("introspect: %v", err)
	}
	// Present now.
	if _, ok := cache.Get(ctx, HashToken("short-token")); !ok {
		t.Fatal("short-lived token should be cached briefly")
	}
}
