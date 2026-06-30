package generic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/common-iam/iam/pkg/providers"
)

// fakeOIDC stands up an httptest server that serves an OIDC discovery document
// whose endpoints point back at itself, plus introspection and JWKS endpoints.
type fakeOIDC struct {
	srv *httptest.Server

	// introspectResponse is the JSON body returned by the introspection endpoint.
	introspectResponse string
	introspectStatus   int

	// jwksBody is returned by the JWKS endpoint.
	jwksBody string

	// captured request fields for assertions.
	lastIntrospectToken    string
	lastIntrospectAuthUser string
	lastIntrospectAuthPass string
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	f := &fakeOIDC{
		introspectStatus: http.StatusOK,
		introspectResponse: `{"active":true,"sub":"user-1","iss":"https://fake.example.com",` +
			`"acr":"silver","amr":["pwd","otp"],"scope":"openid profile","username":"alice"}`,
		jwksBody: `{"keys":[{"kty":"RSA","kid":"test-key","n":"abc","e":"AQAB"}]}`,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := f.srv.URL
		doc := providers.OIDCDiscovery{
			Issuer:                base,
			AuthorizationEndpoint: base + "/auth",
			TokenEndpoint:         base + "/token",
			IntrospectionEndpoint: base + "/introspect",
			JWKSUri:               base + "/jwks",
			UserinfoEndpoint:      base + "/userinfo",
			SupportedACRValues:    []string{"bronze", "silver", "gold"},
			SupportedAMRValues:    []string{"pwd", "otp"},
			ScopesSupported:       []string{"openid", "profile", "email"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.lastIntrospectToken = r.Form.Get("token")
		u, p, _ := r.BasicAuth()
		f.lastIntrospectAuthUser = u
		f.lastIntrospectAuthPass = p
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.introspectStatus)
		_, _ = w.Write([]byte(f.introspectResponse))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.jwksBody))
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOIDC) discoveryURL() string {
	return f.srv.URL + "/.well-known/openid-configuration"
}

func TestRefreshConfig_PopulatesEndpoints(t *testing.T) {
	f := newFakeOIDC(t)
	a := New(Config{
		DiscoveryURL: f.discoveryURL(),
		ClientID:     "client",
		ClientSecret: "secret",
	})

	if err := a.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}

	if got, want := a.Issuer(), f.srv.URL; got != want {
		t.Errorf("Issuer: got %q, want %q", got, want)
	}

	// discovery should now be populated; verify via Issuer and that JWKS works.
	a.mu.RLock()
	disc := a.discovery
	a.mu.RUnlock()
	if disc == nil {
		t.Fatal("discovery doc not populated after RefreshConfig")
	}
	if disc.IntrospectionEndpoint != f.srv.URL+"/introspect" {
		t.Errorf("IntrospectionEndpoint: got %q", disc.IntrospectionEndpoint)
	}
	if disc.JWKSUri != f.srv.URL+"/jwks" {
		t.Errorf("JWKSUri: got %q", disc.JWKSUri)
	}
	if disc.TokenEndpoint != f.srv.URL+"/token" {
		t.Errorf("TokenEndpoint: got %q", disc.TokenEndpoint)
	}
}

func TestRefreshConfig_Errors(t *testing.T) {
	t.Run("unreachable discovery URL", func(t *testing.T) {
		// A port nobody is listening on; the request should fail.
		a := New(Config{DiscoveryURL: "http://127.0.0.1:0/.well-known/openid-configuration"})
		err := a.RefreshConfig(context.Background())
		if err == nil {
			t.Fatal("expected error for unreachable discovery URL")
		}
	})

	t.Run("malformed discovery URL", func(t *testing.T) {
		a := New(Config{DiscoveryURL: "://bad-url"})
		if err := a.RefreshConfig(context.Background()); err == nil {
			t.Fatal("expected error for malformed discovery URL")
		}
	})

	t.Run("invalid JSON body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("this is not json"))
		}))
		t.Cleanup(srv.Close)

		a := New(Config{DiscoveryURL: srv.URL})
		err := a.RefreshConfig(context.Background())
		if err == nil {
			t.Fatal("expected error decoding malformed discovery JSON")
		}
		if !strings.Contains(err.Error(), "decoding discovery document") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestIntrospect_ActiveTrue(t *testing.T) {
	f := newFakeOIDC(t)
	a := New(Config{
		DiscoveryURL: f.discoveryURL(),
		ClientID:     "my-client",
		ClientSecret: "my-secret",
	})
	if err := a.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}

	claims, err := a.Introspect(context.Background(), "raw-access-token")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !claims.Active {
		t.Error("expected Active=true")
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject: got %q, want user-1", claims.Subject)
	}
	if claims.Issuer != "https://fake.example.com" {
		t.Errorf("Issuer: got %q", claims.Issuer)
	}
	if claims.ACR != "silver" {
		t.Errorf("ACR: got %q, want silver", claims.ACR)
	}
	if len(claims.AMR) != 2 || claims.AMR[0] != "pwd" {
		t.Errorf("AMR: got %v, want [pwd otp]", claims.AMR)
	}
	if !claims.HasScope("openid") || !claims.HasScope("profile") {
		t.Errorf("Scopes: got %v", claims.Scopes)
	}
	if claims.Username != "alice" {
		t.Errorf("Username: got %q, want alice", claims.Username)
	}

	// Verify the introspection request carried the token and basic auth creds.
	if f.lastIntrospectToken != "raw-access-token" {
		t.Errorf("introspection token: got %q", f.lastIntrospectToken)
	}
	if f.lastIntrospectAuthUser != "my-client" || f.lastIntrospectAuthPass != "my-secret" {
		t.Errorf("introspection basic auth: got %q/%q", f.lastIntrospectAuthUser, f.lastIntrospectAuthPass)
	}
}

func TestIntrospect_ActiveFalse(t *testing.T) {
	f := newFakeOIDC(t)
	f.introspectResponse = `{"active":false}`
	a := New(Config{DiscoveryURL: f.discoveryURL(), ClientID: "c", ClientSecret: "s"})
	if err := a.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}

	// RFC 7662 active=false is a valid 200 response, not an error.
	claims, err := a.Introspect(context.Background(), "expired-token")
	if err != nil {
		t.Fatalf("Introspect (active=false should not error): %v", err)
	}
	if claims.Active {
		t.Error("expected Active=false")
	}
}

func TestIntrospect_NotInitialized(t *testing.T) {
	// Calling Introspect before RefreshConfig must error, not panic.
	a := New(Config{DiscoveryURL: "http://example.invalid"})
	_, err := a.Introspect(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error when introspecting before RefreshConfig")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIntrospect_EndpointError(t *testing.T) {
	f := newFakeOIDC(t)
	f.introspectStatus = http.StatusInternalServerError
	f.introspectResponse = `{}`
	a := New(Config{DiscoveryURL: f.discoveryURL(), ClientID: "c", ClientSecret: "s"})
	if err := a.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}

	_, err := a.Introspect(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error for non-200 introspection response")
	}
}

func TestJWKS_Success(t *testing.T) {
	f := newFakeOIDC(t)
	a := New(Config{DiscoveryURL: f.discoveryURL()})
	if err := a.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}

	body, err := a.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var parsed struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("JWKS body not valid JSON: %v", err)
	}
	if len(parsed.Keys) != 1 || parsed.Keys[0]["kid"] != "test-key" {
		t.Errorf("unexpected JWKS: %s", body)
	}
}

func TestJWKS_NotInitialized(t *testing.T) {
	a := New(Config{DiscoveryURL: "http://example.invalid"})
	_, err := a.JWKS(context.Background())
	if err == nil {
		t.Fatal("expected error when JWKS called before RefreshConfig")
	}
	if !strings.Contains(err.Error(), "JWKS URI not available") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestName(t *testing.T) {
	a := New(Config{})
	if a.Name() != "generic-oidc" {
		t.Errorf("Name: got %q, want generic-oidc", a.Name())
	}
}

func TestIssuer_EmptyBeforeRefresh(t *testing.T) {
	a := New(Config{DiscoveryURL: "http://example.invalid"})
	if a.Issuer() != "" {
		t.Errorf("Issuer before RefreshConfig: got %q, want empty", a.Issuer())
	}
}

func TestNew_DefaultHTTPClient(t *testing.T) {
	// New should install a default HTTP client when none is provided.
	a := New(Config{DiscoveryURL: "http://example.invalid"})
	if a.cfg.HTTPClient == nil {
		t.Fatal("expected default HTTPClient to be set")
	}
}
