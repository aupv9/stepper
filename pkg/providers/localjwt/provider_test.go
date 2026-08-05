package localjwt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
	"github.com/common-iam/iam/pkg/providers/generic"
	"github.com/common-iam/iam/pkg/providers/localjwt"
)

// fakeAS serves an OIDC discovery doc, the factory's JWKS, and a counting
// introspection endpoint.
type fakeAS struct {
	srv             *httptest.Server
	factory         *tokenfactory.Factory
	introspectCalls atomic.Int64
}

func newFakeAS(t *testing.T) *fakeAS {
	t.Helper()
	factory, err := tokenfactory.New()
	if err != nil {
		t.Fatal(err)
	}
	as := &fakeAS{factory: factory}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 as.srv.URL,
			"jwks_uri":               as.srv.URL + "/jwks",
			"token_endpoint":         as.srv.URL + "/token",
			"introspection_endpoint": as.srv.URL + "/introspect",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		keys, _ := factory.JWKS()
		w.Write(keys) //nolint:errcheck
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		as.introspectCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active": true,
			"sub":    "opaque-user",
			"iss":    as.srv.URL,
			"exp":    time.Now().Add(time.Hour).Unix(),
		})
	})

	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

func (as *fakeAS) issueJWT(t *testing.T, sub string) string {
	t.Helper()
	raw, err := as.factory.Generate(tokenfactory.TokenOptions{
		Subject:   sub,
		Issuer:    as.srv.URL,
		ACR:       "silver",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newProvider(t *testing.T, as *fakeAS) *localjwt.Provider {
	t.Helper()
	inner := generic.New(generic.Config{
		DiscoveryURL: as.srv.URL + "/.well-known/openid-configuration",
	})
	p := localjwt.New(inner, localjwt.Config{})
	if err := p.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}
	return p
}

func TestLocalJWT_ValidatesWithoutIntrospection(t *testing.T) {
	as := newFakeAS(t)
	p := newProvider(t, as)

	claims, err := p.Introspect(context.Background(), as.issueJWT(t, "alice"))
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !claims.Active || claims.Subject != "alice" || claims.ACR != "silver" {
		t.Errorf("claims = %+v", claims)
	}
	if n := as.introspectCalls.Load(); n != 0 {
		t.Errorf("JWT validation must not hit the introspection endpoint (got %d calls)", n)
	}
}

func TestLocalJWT_OpaqueFallsBackToIntrospection(t *testing.T) {
	as := newFakeAS(t)
	p := newProvider(t, as)

	claims, err := p.Introspect(context.Background(), "opaque-token-no-dots")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !claims.Active || claims.Subject != "opaque-user" {
		t.Errorf("claims = %+v", claims)
	}
	if n := as.introspectCalls.Load(); n != 1 {
		t.Errorf("opaque token must introspect exactly once, got %d", n)
	}
}

func TestLocalJWT_TamperedJWTFailsClosed(t *testing.T) {
	as := newFakeAS(t)
	p := newProvider(t, as)

	raw := as.issueJWT(t, "alice")
	parts := strings.Split(raw, ".")
	tampered := parts[0] + "." + parts[1] + ".AAAA" + parts[2][4:]

	claims, err := p.Introspect(context.Background(), tampered)
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if claims.Active {
		t.Error("tampered JWT must be inactive")
	}
	if n := as.introspectCalls.Load(); n != 0 {
		t.Errorf("invalid JWT must NOT be downgraded to introspection, got %d calls", n)
	}
}

func TestLocalJWT_WrongIssuerRejected(t *testing.T) {
	as := newFakeAS(t)
	p := newProvider(t, as)

	raw, err := as.factory.Generate(tokenfactory.TokenOptions{
		Subject:   "mallory",
		Issuer:    "https://evil.example", // signed with the right key, wrong iss
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := p.Introspect(context.Background(), raw)
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if claims.Active {
		t.Error("token with wrong issuer must be inactive")
	}
}

// BenchmarkLocalJWT_Validate measures the local validation hot path — the M6
// exit criterion is p99 well under 1ms once the JWKS is cached.
func BenchmarkLocalJWT_Validate(b *testing.B) {
	t := &testing.T{}
	as := newFakeAS(t)
	p := newProvider(t, as)
	raw := as.issueJWT(t, "bench")

	ctx := context.Background()
	if _, err := p.Introspect(ctx, raw); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		claims, err := p.Introspect(ctx, raw)
		if err != nil || !claims.Active {
			b.Fatal("validation failed")
		}
	}
}
