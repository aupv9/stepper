package token

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
)

// startJWKSServer spins up an httptest server serving the factory's JWKS.
func startJWKSServer(t *testing.T, factory *tokenfactory.Factory) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks, err := factory.JWKS()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestJWTValidator_ValidToken(t *testing.T) {
	factory, err := tokenfactory.New()
	if err != nil {
		t.Fatalf("tokenfactory.New: %v", err)
	}

	jwksSrv := startJWKSServer(t, factory)

	rawToken, err := factory.Generate(tokenfactory.TokenOptions{
		Subject:   "alice",
		ACR:       "urn:mace:incommon:iap:silver",
		AMR:       []string{"pwd", "otp"},
		Scopes:    []string{"openid", "profile"},
		ExpiresIn: time.Hour,
		AuthTime:  time.Now().Add(-5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("factory.Generate: %v", err)
	}

	v := NewJWTValidator(JWTValidatorConfig{JWKSURL: jwksSrv.URL})
	claims, err := v.Validate(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if claims.Subject != "alice" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "alice")
	}
	if claims.ACR != "urn:mace:incommon:iap:silver" {
		t.Errorf("acr: got %q", claims.ACR)
	}
	if !claims.Active {
		t.Error("expected Active=true")
	}
	if !claims.HasScope("openid") {
		t.Error("expected scope 'openid'")
	}
}

func TestJWTValidator_ExpiredToken(t *testing.T) {
	factory, _ := tokenfactory.New()
	jwksSrv := startJWKSServer(t, factory)

	// Issue token that expired 1 minute ago
	rawToken, _ := factory.Generate(tokenfactory.TokenOptions{
		Subject:   "bob",
		ExpiresIn: -1 * time.Minute, // already expired
		AuthTime:  time.Now().Add(-10 * time.Minute),
	})

	v := NewJWTValidator(JWTValidatorConfig{JWKSURL: jwksSrv.URL})
	_, err := v.Validate(context.Background(), rawToken)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestJWTValidator_WrongKey(t *testing.T) {
	factory, _ := tokenfactory.New()
	otherFactory, _ := tokenfactory.New() // different key pair
	jwksSrv := startJWKSServer(t, otherFactory) // serve other factory's JWKS

	rawToken, _ := factory.Generate(tokenfactory.TokenOptions{
		Subject:   "eve",
		ExpiresIn: time.Hour,
		AuthTime:  time.Now(),
	})

	v := NewJWTValidator(JWTValidatorConfig{JWKSURL: jwksSrv.URL})
	_, err := v.Validate(context.Background(), rawToken)
	if err == nil {
		t.Fatal("expected error for wrong signing key")
	}
}

func TestJWTValidator_RefreshKeys(t *testing.T) {
	factory, _ := tokenfactory.New()

	// JWKS server that can be swapped
	var currentJWKS []byte
	currentJWKS, _ = factory.JWKS()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(currentJWKS) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	v := NewJWTValidator(JWTValidatorConfig{JWKSURL: srv.URL, CacheTTL: 5 * time.Minute})

	// First token validates fine
	tok1, _ := factory.Generate(tokenfactory.TokenOptions{Subject: "u1", ExpiresIn: time.Hour, AuthTime: time.Now()})
	if _, err := v.Validate(context.Background(), tok1); err != nil {
		t.Fatalf("first validation: %v", err)
	}

	// Rotate to a new factory key; update server JWKS
	newFactory, _ := tokenfactory.New()
	currentJWKS, _ = newFactory.JWKS()

	// Force refresh
	if err := v.RefreshKeys(context.Background()); err != nil {
		t.Fatalf("RefreshKeys: %v", err)
	}

	// New token from new factory should now validate
	tok2, _ := newFactory.Generate(tokenfactory.TokenOptions{Subject: "u2", ExpiresIn: time.Hour, AuthTime: time.Now()})
	if _, err := v.Validate(context.Background(), tok2); err != nil {
		t.Fatalf("validation after key rotation: %v", err)
	}
}

func TestJWTValidator_JWKS404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	v := NewJWTValidator(JWTValidatorConfig{JWKSURL: srv.URL})
	_, err := v.Validate(context.Background(), "some.fake.token")
	if err == nil {
		t.Fatal("expected error for 404 JWKS endpoint")
	}
}

// Ensure jwtRawClaims maps scopes and roles correctly.
func TestJWTRawClaims_ScopeMapping(t *testing.T) {
	raw := &jwtRawClaims{Scope: "openid profile admin:read"}
	c := raw.toCommonClaims()
	want := []string{"openid", "profile", "admin:read"}
	if len(c.Scopes) != len(want) {
		t.Fatalf("scopes: got %v, want %v", c.Scopes, want)
	}
	for i, s := range want {
		if c.Scopes[i] != s {
			t.Errorf("scope[%d]: got %q, want %q", i, c.Scopes[i], s)
		}
	}
}

func TestJWTRawClaims_KeycloakRolesPriority(t *testing.T) {
	raw := &jwtRawClaims{Roles: []string{"generic-role"}}
	raw.RealmAccess.Roles = []string{"keycloak-role"}
	c := raw.toCommonClaims()
	if len(c.Roles) != 1 || c.Roles[0] != "keycloak-role" {
		t.Errorf("expected keycloak roles to take priority, got %v", c.Roles)
	}
}

// Verify JWKS output format from tokenfactory is parseable by our validator.
func TestJWKSFormat(t *testing.T) {
	factory, _ := tokenfactory.New()
	jwks, err := factory.JWKS()
	if err != nil {
		t.Fatalf("factory.JWKS: %v", err)
	}

	var parsed struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &parsed); err != nil {
		t.Fatalf("JWKS not valid JSON: %v", err)
	}
	if len(parsed.Keys) == 0 {
		t.Fatal("JWKS has no keys")
	}

	key := parsed.Keys[0]
	if _, err := PublicKeyFromJWK(key); err != nil {
		t.Fatalf("PublicKeyFromJWK on factory JWKS: %v", err)
	}
}
