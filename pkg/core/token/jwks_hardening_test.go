package token

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
)

func TestJWKSRefresh_RetriesTransientFailures(t *testing.T) {
	factory, err := tokenfactory.New()
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError) // two transient failures
			return
		}
		keys, _ := factory.JWKS()
		w.Write(keys) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	v := NewJWTValidator(JWTValidatorConfig{JWKSURL: srv.URL})
	if err := v.RefreshKeys(context.Background()); err != nil {
		t.Fatalf("refresh should succeed on the third attempt: %v", err)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("expected 3 fetch attempts, got %d", n)
	}
}

func TestJWKSRefresh_ErrorHookFires(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	var hookErrs atomic.Int64
	v := NewJWTValidator(JWTValidatorConfig{
		JWKSURL:        srv.URL,
		OnRefreshError: func(error) { hookErrs.Add(1) },
	})
	if err := v.RefreshKeys(context.Background()); err == nil {
		t.Fatal("expected refresh failure")
	}
	if hookErrs.Load() != 1 {
		t.Errorf("OnRefreshError should fire exactly once per failed refresh, got %d", hookErrs.Load())
	}
}

func TestJWKSRefresh_HonorsCacheControlMaxAge(t *testing.T) {
	factory, err := tokenfactory.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=120")
		keys, _ := factory.JWKS()
		w.Write(keys) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	v := NewJWTValidator(JWTValidatorConfig{JWKSURL: srv.URL, CacheTTL: time.Hour})
	if err := v.RefreshKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	got := v.effectiveTTL
	v.mu.RUnlock()
	if got != 2*time.Minute {
		t.Errorf("effectiveTTL = %s, want 2m from Cache-Control max-age", got)
	}
}

func TestParseCacheControlMaxAge(t *testing.T) {
	tests := []struct {
		header string
		want   time.Duration
	}{
		{"public, max-age=300", 5 * time.Minute},
		{"max-age=60", time.Minute},
		{"no-store", 0},
		{"", 0},
		{"max-age=abc", 0},
	}
	for _, tt := range tests {
		if got := parseCacheControlMaxAge(tt.header); got != tt.want {
			t.Errorf("parseCacheControlMaxAge(%q) = %s, want %s", tt.header, got, tt.want)
		}
	}
}
