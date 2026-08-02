package token

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newIntrospectionServer serves a canned RFC 7662 response and records the
// last form values it received.
func newIntrospectionServer(t *testing.T, resp map[string]interface{}) (*httptest.Server, *map[string][]string) {
	t.Helper()
	var lastForm map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		lastForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &lastForm
}

func TestIntrospector_Introspect(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	srv, lastForm := newIntrospectionServer(t, map[string]interface{}{
		"active":    true,
		"sub":       "alice",
		"iss":       "https://as.example.com",
		"aud":       []string{"api", "web"},
		"exp":       exp,
		"iat":       time.Now().Unix(),
		"auth_time": time.Now().Add(-time.Minute).Unix(),
		"acr":       "silver",
		"amr":       []string{"pwd", "otp"},
		"scope":     "openid profile",
		"jti":       "tok-123",
		"cnf":       map[string]string{"jkt": "thumb-abc"},
	})

	intro := NewIntrospector(IntrospectorConfig{
		Endpoint: srv.URL,
		ClientID: "client",
	})
	claims, err := intro.Introspect(context.Background(), "raw-token")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}

	if !claims.Active || claims.Subject != "alice" || claims.Issuer != "https://as.example.com" {
		t.Errorf("basic claims wrong: %+v", claims)
	}
	if len(claims.Audience) != 2 || claims.Audience[0] != "api" {
		t.Errorf("aud = %v, want [api web]", claims.Audience)
	}
	if claims.JTI != "tok-123" {
		t.Errorf("jti = %q", claims.JTI)
	}
	if claims.Confirmation == nil || claims.Confirmation.JKT != "thumb-abc" {
		t.Errorf("cnf.jkt not mapped: %+v", claims.Confirmation)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "openid" {
		t.Errorf("scopes = %v", claims.Scopes)
	}
	if claims.AuthAge() <= 0 {
		t.Error("auth_time should yield a positive AuthAge")
	}

	// RFC 7662 §2.1 SHOULD: token_type_hint sent.
	if got := (*lastForm)["token_type_hint"]; len(got) != 1 || got[0] != "access_token" {
		t.Errorf("token_type_hint = %v, want [access_token]", got)
	}
}

func TestAudience_UnmarshalJSON_StringForm(t *testing.T) {
	var r IntrospectionResponse
	if err := json.Unmarshal([]byte(`{"active":true,"aud":"single-api"}`), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(r.Aud) != 1 || r.Aud[0] != "single-api" {
		t.Errorf("aud = %v, want [single-api]", r.Aud)
	}

	if err := json.Unmarshal([]byte(`{"aud":42}`), &r); err == nil {
		t.Error("numeric aud must fail to unmarshal")
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		header  string
		want    string
		wantErr bool
	}{
		{"Bearer abc123", "abc123", false},
		{"bearer abc123", "abc123", false},
		{"", "", true},
		{"Basic dXNlcjpwYXNz", "", true},
		{"Bearer ", "", true},
		{"Bearer", "", true},
	}
	for _, tt := range tests {
		got, err := ExtractBearerToken(tt.header)
		if (err != nil) != tt.wantErr {
			t.Errorf("ExtractBearerToken(%q) error = %v, wantErr %v", tt.header, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("ExtractBearerToken(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestCachedIntrospector(t *testing.T) {
	calls := 0
	exp := time.Now().Add(time.Hour).Unix()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active": true, "sub": "bob", "exp": exp, "jti": "j-1",
		})
	}))
	t.Cleanup(srv.Close)

	cache := NewMemoryCache()
	ci := NewCachedIntrospector(NewIntrospector(IntrospectorConfig{Endpoint: srv.URL}), cache, 30*time.Second)

	ctx := context.Background()
	if _, err := ci.Introspect(ctx, "tok"); err != nil {
		t.Fatalf("first introspect: %v", err)
	}
	if _, err := ci.Introspect(ctx, "tok"); err != nil {
		t.Fatalf("second introspect: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 upstream call (second served from cache), got %d", calls)
	}

	// Revoke evicts; next call goes upstream again.
	ci.Revoke(ctx, "tok")
	if _, err := ci.Introspect(ctx, "tok"); err != nil {
		t.Fatalf("post-revoke introspect: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 upstream calls after revoke, got %d", calls)
	}
}

func TestCachedIntrospector_DoesNotCacheExpired(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		// Active but already past exp — TTL clamp must prevent caching.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active": true, "sub": "bob", "exp": time.Now().Add(-time.Minute).Unix(),
		})
	}))
	t.Cleanup(srv.Close)

	ci := NewCachedIntrospector(NewIntrospector(IntrospectorConfig{Endpoint: srv.URL}), NewMemoryCache(), 30*time.Second)
	ctx := context.Background()
	_, _ = ci.Introspect(ctx, "tok")
	_, _ = ci.Introspect(ctx, "tok")
	if calls != 2 {
		t.Errorf("expired-token result must not be cached; upstream calls = %d, want 2", calls)
	}
}

// BenchmarkCachedIntrospector_CacheHit measures the hot path: introspection
// served entirely from the in-memory cache.
func BenchmarkCachedIntrospector_CacheHit(b *testing.B) {
	exp := time.Now().Add(time.Hour).Unix()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active": true, "sub": "bench", "exp": exp,
		})
	}))
	defer srv.Close()

	ci := NewCachedIntrospector(NewIntrospector(IntrospectorConfig{Endpoint: srv.URL}), NewMemoryCache(), 5*time.Minute)
	ctx := context.Background()
	if _, err := ci.Introspect(ctx, "bench-token"); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ci.Introspect(ctx, "bench-token"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestMemoryCache_Flush(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache()
	_ = c.Set(ctx, "k1", &CommonClaims{Subject: "a"}, time.Minute)
	_ = c.Set(ctx, "k2", &CommonClaims{Subject: "b"}, time.Minute)
	if err := c.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, ok := c.Get(ctx, "k1"); ok {
		t.Error("k1 should be gone after Flush")
	}
}

func TestCommonClaims_Helpers(t *testing.T) {
	c := &CommonClaims{
		Roles:  []string{"admin"},
		Scopes: []string{"openid"},
		Extra: map[string]interface{}{
			"nonce":       "n-1",
			"request_uri": "urn:ietf:params:oauth:request_uri:abc",
		},
		Confirmation: &Confirmation{JKT: "x"},
		AuthTime:     time.Now().Add(-2 * time.Minute),
	}
	if !c.HasRole("admin") || c.HasRole("user") {
		t.Error("HasRole wrong")
	}
	if !c.HasScope("openid") || c.HasScope("payments") {
		t.Error("HasScope wrong")
	}
	if !c.HasDPoP() {
		t.Error("HasDPoP should be true with cnf.jkt")
	}
	if !c.HasPARRequestURI() {
		t.Error("HasPARRequestURI should be true with request_uri")
	}
	if c.GetNonce() != "n-1" {
		t.Errorf("GetNonce = %q", c.GetNonce())
	}
	if c.GetAuthAge() < time.Minute {
		t.Errorf("GetAuthAge = %s, want ≥ 1m", c.GetAuthAge())
	}

	empty := &CommonClaims{}
	if empty.HasDPoP() || empty.HasPARRequestURI() || empty.GetNonce() != "" || empty.GetAuthAge() != 0 {
		t.Error("zero-value claims must report no bindings")
	}
}
