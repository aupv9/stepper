package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/common-iam/iam/pkg/providers"
)

func TestName(t *testing.T) {
	a := New(Config{BaseURL: "https://kc.example.com", Realm: "myrealm"})
	if a.Name() != "keycloak" {
		t.Errorf("Name: got %q, want keycloak", a.Name())
	}
}

func TestNew_DefaultHTTPClient(t *testing.T) {
	// New must default the HTTPClient when not supplied (and not panic).
	a := New(Config{BaseURL: "https://kc.example.com", Realm: "r"})
	if a.cfg.HTTPClient == nil {
		t.Fatal("expected default HTTPClient to be set")
	}
}

// TestDiscoveryURL_Construction verifies the Keycloak-specific discovery path:
// {BaseURL}/realms/{Realm}/.well-known/openid-configuration
func TestDiscoveryURL_Construction(t *testing.T) {
	var requestedPath string

	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/realms/test-realm/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		doc := providers.OIDCDiscovery{
			Issuer:                srvURL + "/realms/test-realm",
			IntrospectionEndpoint: srvURL + "/realms/test-realm/protocol/openid-connect/token/introspect",
			JWKSUri:               srvURL + "/realms/test-realm/protocol/openid-connect/certs",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	a := New(Config{
		BaseURL:      srv.URL,
		Realm:        "test-realm",
		ClientID:     "client",
		ClientSecret: "secret",
	})

	if err := a.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}

	if requestedPath != "/realms/test-realm/.well-known/openid-configuration" {
		t.Errorf("discovery path: got %q", requestedPath)
	}
	if got, want := a.Issuer(), srv.URL+"/realms/test-realm"; got != want {
		t.Errorf("Issuer: got %q, want %q", got, want)
	}
}

func TestRefreshConfig_DiscoveryFailure(t *testing.T) {
	// A 404 on the discovery path produces an empty (zero) discovery doc when the
	// body is non-JSON, so we serve a 404 with an HTML body to force a decode error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html>not found</html>"))
	}))
	t.Cleanup(srv.Close)

	a := New(Config{BaseURL: srv.URL, Realm: "missing"})
	if err := a.RefreshConfig(context.Background()); err == nil {
		t.Fatal("expected error when discovery returns non-JSON 404 body")
	}
}

func TestJWKS_AfterRefresh(t *testing.T) {
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/r/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := providers.OIDCDiscovery{
			Issuer:  srvURL + "/realms/r",
			JWKSUri: srvURL + "/realms/r/protocol/openid-connect/certs",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/realms/r/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kid":"kc-key","kty":"RSA"}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	a := New(Config{BaseURL: srv.URL, Realm: "r"})
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
	if len(parsed.Keys) != 1 || parsed.Keys[0]["kid"] != "kc-key" {
		t.Errorf("unexpected JWKS: %s", body)
	}
}

func TestIntrospect_RealmRolesNote(t *testing.T) {
	// Keycloak introspection runs through token.Introspector, whose response
	// struct (RFC 7662) does NOT carry realm_access.roles. This test documents
	// the CURRENT behavior: roles from the introspection endpoint are NOT mapped
	// into CommonClaims.Roles (realm-role mapping only happens via MapToCommon on
	// a full JWT claim set, which is covered in the providers package tests).
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/r/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := providers.OIDCDiscovery{
			Issuer:                srvURL + "/realms/r",
			IntrospectionEndpoint: srvURL + "/introspect",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		// Active token that includes Keycloak realm_access roles.
		_, _ = w.Write([]byte(`{"active":true,"sub":"kc-user","realm_access":{"roles":["admin"]},"scope":"openid"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	a := New(Config{BaseURL: srv.URL, Realm: "r", ClientID: "c", ClientSecret: "s"})
	if err := a.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}

	claims, err := a.Introspect(context.Background(), "tok")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !claims.Active || claims.Subject != "kc-user" {
		t.Errorf("expected active kc-user, got active=%v sub=%q", claims.Active, claims.Subject)
	}
	// Current behavior: realm roles are not surfaced via the introspection path.
	if len(claims.Roles) != 0 {
		t.Errorf("CURRENT behavior expected no roles from introspection, got %v", claims.Roles)
	}
}
