package auth0

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/common-iam/iam/pkg/providers"
)

func TestName(t *testing.T) {
	a := New(Config{Domain: "myapp.us.auth0.com"})
	if a.Name() != "auth0" {
		t.Errorf("Name: got %q, want auth0", a.Name())
	}
}

func TestNew_DefaultHTTPClient(t *testing.T) {
	a := New(Config{Domain: "myapp.us.auth0.com"})
	if a.cfg.HTTPClient == nil {
		t.Fatal("expected default HTTPClient to be set")
	}
}

// TestDiscoveryURL_Construction verifies the Auth0-specific discovery URL:
// https://{Domain}/.well-known/openid-configuration
//
// We point Domain at a TLS httptest server's host (so the https:// scheme that
// the adapter hardcodes resolves to our fake server) and inject that server's
// client (which trusts the test certificate).
func TestDiscoveryURL_Construction(t *testing.T) {
	var requestedPath string
	var srvURL string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		doc := providers.OIDCDiscovery{
			Issuer:                srvURL + "/",
			IntrospectionEndpoint: srvURL + "/oauth/introspect",
			JWKSUri:               srvURL + "/.well-known/jwks.json",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	// srv.URL is like https://127.0.0.1:54321 — strip scheme to get the Domain.
	domain := strings.TrimPrefix(srv.URL, "https://")

	a := New(Config{
		Domain:       domain,
		ClientID:     "client",
		ClientSecret: "secret",
		Audience:     "https://api.example.com",
		HTTPClient:   srv.Client(), // trusts the test TLS cert
	})

	if err := a.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}

	if requestedPath != "/.well-known/openid-configuration" {
		t.Errorf("discovery path: got %q", requestedPath)
	}
	if got, want := a.Issuer(), srvURL+"/"; got != want {
		t.Errorf("Issuer: got %q, want %q", got, want)
	}
}

func TestRefreshConfig_DiscoveryFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html>nope</html>"))
	}))
	t.Cleanup(srv.Close)

	domain := strings.TrimPrefix(srv.URL, "https://")
	a := New(Config{Domain: domain, HTTPClient: srv.Client()})
	if err := a.RefreshConfig(context.Background()); err == nil {
		t.Fatal("expected error when discovery returns non-JSON body")
	}
}

func TestRefreshConfig_Unreachable(t *testing.T) {
	// .invalid TLD never resolves -> request error.
	a := New(Config{Domain: "nonexistent.invalid"})
	if err := a.RefreshConfig(context.Background()); err == nil {
		t.Fatal("expected error for unreachable Auth0 domain")
	}
}

func TestIntrospect_NamespacedRolesNote(t *testing.T) {
	// Auth0 introspection runs through token.Introspector (RFC 7662), which does
	// not carry namespaced role claims. This documents CURRENT behavior: roles
	// returned by the introspection endpoint are NOT mapped into CommonClaims.Roles.
	// (Namespaced-role mapping is exercised via MapToCommon in the providers tests.)
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := providers.OIDCDiscovery{
			Issuer:                srvURL + "/",
			IntrospectionEndpoint: srvURL + "/oauth/introspect",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/oauth/introspect", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"active":true,"sub":"auth0|123","scope":"openid email"}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	domain := strings.TrimPrefix(srv.URL, "https://")
	a := New(Config{Domain: domain, ClientID: "c", ClientSecret: "s", HTTPClient: srv.Client()})
	if err := a.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}

	claims, err := a.Introspect(context.Background(), "tok")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !claims.Active || claims.Subject != "auth0|123" {
		t.Errorf("expected active auth0|123, got active=%v sub=%q", claims.Active, claims.Subject)
	}
	if !claims.HasScope("openid") || !claims.HasScope("email") {
		t.Errorf("scopes: got %v", claims.Scopes)
	}
}

func TestJWKS_AfterRefresh(t *testing.T) {
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := providers.OIDCDiscovery{
			Issuer:  srvURL + "/",
			JWKSUri: srvURL + "/.well-known/jwks.json",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kid":"auth0-key","kty":"RSA"}]}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	domain := strings.TrimPrefix(srv.URL, "https://")
	a := New(Config{Domain: domain, HTTPClient: srv.Client()})
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
		t.Fatalf("JWKS not valid JSON: %v", err)
	}
	if len(parsed.Keys) != 1 || parsed.Keys[0]["kid"] != "auth0-key" {
		t.Errorf("unexpected JWKS: %s", body)
	}
}
