package localas

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
)

// startServer spins up a LocalAS and registers cleanup that stops it.
func startServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	base, err := s.Start()
	if err != nil {
		t.Fatalf("Start: unexpected error: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	})
	return s, base
}

func getJSON(t *testing.T, url string) (int, map[string]interface{}) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec,noctx
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	m := map[string]interface{}{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("unmarshal %s body %q: %v", url, string(body), err)
		}
	}
	return resp.StatusCode, m
}

func TestStart_ReturnsReachableBaseURL(t *testing.T) {
	_, base := startServer(t)

	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Fatalf("base URL = %q, want http://127.0.0.1:<port>", base)
	}

	status, disc := getJSON(t, base+"/.well-known/openid-configuration")
	if status != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", status)
	}
	if disc["issuer"] != base {
		t.Errorf("issuer = %v, want %v", disc["issuer"], base)
	}
}

func TestDiscovery_ValidJSON(t *testing.T) {
	_, base := startServer(t)
	status, disc := getJSON(t, base+"/.well-known/openid-configuration")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	tests := []struct {
		key  string
		want string
	}{
		{"token_endpoint", base + "/token"},
		{"introspection_endpoint", base + "/introspect"},
		{"revocation_endpoint", base + "/revoke"},
		{"jwks_uri", base + "/jwks"},
		{"authorization_endpoint", base + "/authorize"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if disc[tt.key] != tt.want {
				t.Errorf("%s = %v, want %v", tt.key, disc[tt.key], tt.want)
			}
		})
	}

	t.Run("acr_values_supported is a non-empty array", func(t *testing.T) {
		arr, ok := disc["acr_values_supported"].([]interface{})
		if !ok || len(arr) == 0 {
			t.Errorf("acr_values_supported = %v, want non-empty array", disc["acr_values_supported"])
		}
	})

	t.Run("RS256 signing supported", func(t *testing.T) {
		algs, ok := disc["id_token_signing_alg_values_supported"].([]interface{})
		if !ok || len(algs) == 0 || algs[0] != "RS256" {
			t.Errorf("id_token_signing_alg_values_supported = %v, want [RS256]", disc["id_token_signing_alg_values_supported"])
		}
	})
}

func TestJWKS_ReturnsKeys(t *testing.T) {
	_, base := startServer(t)
	status, doc := getJSON(t, base+"/jwks")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	keys, ok := doc["keys"].([]interface{})
	if !ok {
		t.Fatalf("keys not an array: %T", doc["keys"])
	}
	if len(keys) == 0 {
		t.Fatal("JWKS returned zero keys")
	}
	key := keys[0].(map[string]interface{})
	if key["kty"] != "RSA" {
		t.Errorf("kty = %v, want RSA", key["kty"])
	}
	if _, ok := key["n"].(string); !ok {
		t.Error("JWKS key missing modulus 'n'")
	}
}

func TestIssueToken_ValidatesAgainstServerJWKS(t *testing.T) {
	s, base := startServer(t)

	raw, err := s.IssueToken(tokenfactory.TokenOptions{
		Subject: "issued-user",
		ACR:     "urn:mace:incommon:iap:silver",
		Scopes:  []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("IssueToken: unexpected error: %v", err)
	}

	// Pull the JWKS from the running server over HTTP, build a public key, verify.
	_, doc := getJSON(t, base+"/jwks")
	keys := doc["keys"].([]interface{})
	pub := jwkToPublicKey(t, keys[0].(map[string]interface{}))

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (interface{}, error) {
		return pub, nil
	})
	if err != nil {
		t.Fatalf("ParseWithClaims against server JWKS: %v", err)
	}
	if !token.Valid {
		t.Fatal("issued token failed validation against server JWKS")
	}
	if claims["sub"] != "issued-user" {
		t.Errorf("sub = %v, want issued-user", claims["sub"])
	}
	if claims["iss"] != base {
		t.Errorf("iss = %v, want %v (server issuer)", claims["iss"], base)
	}
}

func TestTokenEndpoint_IssuesAndIntrospects(t *testing.T) {
	_, base := startServer(t)

	form := url.Values{"username": {"http-user"}, "acr_values": {"urn:mace:incommon:iap:gold"}}
	resp, err := http.PostForm(base+"/token", form) //nolint:noctx
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token status = %d, want 200", resp.StatusCode)
	}
	var tokResp map[string]interface{}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &tokResp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	accessToken, _ := tokResp["access_token"].(string)
	if accessToken == "" {
		t.Fatal("token response missing access_token")
	}
	if tokResp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", tokResp["token_type"])
	}

	t.Run("introspect active token", func(t *testing.T) {
		intr := introspect(t, base, accessToken)
		if intr["active"] != true {
			t.Fatalf("active = %v, want true", intr["active"])
		}
		if intr["sub"] != "http-user" {
			t.Errorf("sub = %v, want http-user", intr["sub"])
		}
		if intr["acr"] != "urn:mace:incommon:iap:gold" {
			t.Errorf("acr = %v, want gold", intr["acr"])
		}
	})

	t.Run("introspect unknown token is inactive", func(t *testing.T) {
		intr := introspect(t, base, "not-a-real-token")
		if intr["active"] != false {
			t.Errorf("active = %v, want false for unknown token", intr["active"])
		}
	})
}

func TestRevoke_MakesTokenInactive(t *testing.T) {
	s, base := startServer(t)

	raw, err := s.IssueToken(tokenfactory.TokenOptions{Subject: "to-revoke", ExpiresIn: time.Hour})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	if intr := introspect(t, base, raw); intr["active"] != true {
		t.Fatalf("token should be active before revoke, got %v", intr["active"])
	}

	resp, err := http.PostForm(base+"/revoke", url.Values{"token": {raw}}) //nolint:noctx
	if err != nil {
		t.Fatalf("POST /revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/revoke status = %d, want 200", resp.StatusCode)
	}

	if intr := introspect(t, base, raw); intr["active"] != false {
		t.Errorf("token should be inactive after revoke, got %v", intr["active"])
	}
}

func TestTokenEndpoint_RejectsGET(t *testing.T) {
	_, base := startServer(t)
	resp, err := http.Get(base + "/token") //nolint:noctx
	if err != nil {
		t.Fatalf("GET /token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /token status = %d, want 405", resp.StatusCode)
	}
}

func TestStop_ShutsDownCleanly(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	base, err := s.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Reachable while running.
	if status, _ := getJSON(t, base+"/.well-known/openid-configuration"); status != http.StatusOK {
		t.Fatalf("pre-stop status = %d, want 200", status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("Stop: unexpected error: %v", err)
	}

	// After shutdown, the listener should be closed → connection refused.
	client := &http.Client{Timeout: time.Second}
	if _, err := client.Get(base + "/.well-known/openid-configuration"); err == nil { //nolint:noctx
		t.Error("expected error connecting to a stopped server, got nil")
	}
}

func TestStop_NilServerIsNoop(t *testing.T) {
	// New() does not call Start(), so httpSrv is nil; Stop must not panic/error.
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop on unstarted server = %v, want nil", err)
	}
}

// --- helpers ---

func introspect(t *testing.T, base, token string) map[string]interface{} {
	t.Helper()
	resp, err := http.PostForm(base+"/introspect", url.Values{"token": {token}}) //nolint:noctx
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	m := map[string]interface{}{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal introspect body %q: %v", string(body), err)
	}
	return m
}

func jwkToPublicKey(t *testing.T, jwk map[string]interface{}) *rsa.PublicKey {
	t.Helper()
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk["n"].(string))
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk["e"].(string))
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
}
