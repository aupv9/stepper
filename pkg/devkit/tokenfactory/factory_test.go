package tokenfactory

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// keyFunc returns a jwt.Keyfunc that verifies against the factory's public key.
func keyFunc(f *Factory) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		return &f.privateKey.PublicKey, nil
	}
}

func TestGenerate_ProducesParseable3PartJWT(t *testing.T) {
	f, err := New()
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}

	raw, err := f.Generate(TokenOptions{Subject: "alice"})
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWT, got %d parts: %q", len(parts), raw)
	}
	for i, p := range parts {
		if p == "" {
			t.Errorf("JWT part %d is empty", i)
		}
	}
}

func TestGenerate_ClaimsMatchOptions(t *testing.T) {
	f, err := New()
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}

	authTime := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	opts := TokenOptions{
		Subject:   "user-123",
		Issuer:    "https://issuer.example.com",
		Audience:  []string{"api://orders"},
		ExpiresIn: 2 * time.Hour,
		ACR:       "urn:mace:incommon:iap:gold",
		AMR:       []string{"pwd", "otp"},
		Scopes:    []string{"openid", "profile", "orders.read"},
		Roles:     []string{"admin", "auditor"},
		TenantID:  "tenant-42",
		SessionID: "sess-abc",
		AuthTime:  authTime,
	}

	before := time.Now().Unix()
	raw, err := f.Generate(opts)
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}
	after := time.Now().Unix()

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, keyFunc(f))
	if err != nil {
		t.Fatalf("ParseWithClaims: unexpected error: %v", err)
	}
	if !token.Valid {
		t.Fatal("token reported as invalid")
	}

	tests := []struct {
		name string
		key  string
		want interface{}
	}{
		{"sub", "sub", "user-123"},
		{"iss", "iss", "https://issuer.example.com"},
		{"acr", "acr", "urn:mace:incommon:iap:gold"},
		{"tenant_id", "tenant_id", "tenant-42"},
		{"sid", "sid", "sess-abc"},
		{"scope", "scope", "openid profile orders.read"},
		{"active", "active", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := claims[tt.key]
			if !ok {
				t.Fatalf("claim %q missing", tt.key)
			}
			if got != tt.want {
				t.Errorf("claim %q = %v, want %v", tt.key, got, tt.want)
			}
		})
	}

	t.Run("amr", func(t *testing.T) {
		amr, ok := claims["amr"].([]interface{})
		if !ok {
			t.Fatalf("amr not a JSON array: %T", claims["amr"])
		}
		want := []string{"pwd", "otp"}
		if len(amr) != len(want) {
			t.Fatalf("amr len = %d, want %d", len(amr), len(want))
		}
		for i, v := range want {
			if amr[i] != v {
				t.Errorf("amr[%d] = %v, want %v", i, amr[i], v)
			}
		}
	})

	t.Run("roles", func(t *testing.T) {
		realmAccess, ok := claims["realm_access"].(map[string]interface{})
		if !ok {
			t.Fatalf("realm_access not an object: %T", claims["realm_access"])
		}
		roles, ok := realmAccess["roles"].([]interface{})
		if !ok {
			t.Fatalf("realm_access.roles not an array: %T", realmAccess["roles"])
		}
		want := []string{"admin", "auditor"}
		if len(roles) != len(want) {
			t.Fatalf("roles len = %d, want %d", len(roles), len(want))
		}
		for i, v := range want {
			if roles[i] != v {
				t.Errorf("roles[%d] = %v, want %v", i, roles[i], v)
			}
		}
	})

	t.Run("aud", func(t *testing.T) {
		// json numbers come back as float64; aud is []interface{}
		aud, ok := claims["aud"].([]interface{})
		if !ok {
			t.Fatalf("aud not an array: %T", claims["aud"])
		}
		if len(aud) != 1 || aud[0] != "api://orders" {
			t.Errorf("aud = %v, want [api://orders]", aud)
		}
	})

	t.Run("auth_time", func(t *testing.T) {
		at, ok := claims["auth_time"].(float64)
		if !ok {
			t.Fatalf("auth_time not numeric: %T", claims["auth_time"])
		}
		if int64(at) != authTime.Unix() {
			t.Errorf("auth_time = %d, want %d", int64(at), authTime.Unix())
		}
	})

	t.Run("iat_within_bounds", func(t *testing.T) {
		iat, ok := claims["iat"].(float64)
		if !ok {
			t.Fatalf("iat not numeric: %T", claims["iat"])
		}
		if int64(iat) < before || int64(iat) > after {
			t.Errorf("iat = %d, want within [%d, %d]", int64(iat), before, after)
		}
	})

	t.Run("exp_honors_expires_in", func(t *testing.T) {
		iat, _ := claims["iat"].(float64)
		exp, ok := claims["exp"].(float64)
		if !ok {
			t.Fatalf("exp not numeric: %T", claims["exp"])
		}
		gotDelta := int64(exp) - int64(iat)
		wantDelta := int64((2 * time.Hour).Seconds())
		if gotDelta != wantDelta {
			t.Errorf("exp-iat = %d, want %d", gotDelta, wantDelta)
		}
	})
}

func TestGenerate_Defaults(t *testing.T) {
	f, err := New()
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}

	before := time.Now().Unix()
	raw, err := f.Generate(TokenOptions{Subject: "bob"})
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}

	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(raw, claims, keyFunc(f)); err != nil {
		t.Fatalf("ParseWithClaims: unexpected error: %v", err)
	}

	t.Run("default issuer", func(t *testing.T) {
		if claims["iss"] != "http://localhost:8080/devkit" {
			t.Errorf("default iss = %v, want http://localhost:8080/devkit", claims["iss"])
		}
	})

	t.Run("default expires_in is one hour", func(t *testing.T) {
		iat := int64(claims["iat"].(float64))
		exp := int64(claims["exp"].(float64))
		if exp-iat != int64(time.Hour.Seconds()) {
			t.Errorf("default lifetime = %ds, want %ds", exp-iat, int64(time.Hour.Seconds()))
		}
	})

	t.Run("default auth_time set to ~now", func(t *testing.T) {
		at := int64(claims["auth_time"].(float64))
		if at < before-2 || at > time.Now().Unix()+2 {
			t.Errorf("default auth_time = %d, want near %d", at, before)
		}
	})

	t.Run("omitted optional claims absent", func(t *testing.T) {
		for _, k := range []string{"acr", "amr", "scope", "realm_access", "tenant_id", "sid", "aud"} {
			if _, present := claims[k]; present {
				t.Errorf("claim %q should be absent when not set in options", k)
			}
		}
	})
}

func TestGenerate_ExpiredTokenRejected(t *testing.T) {
	f, err := New()
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}

	// Negative ExpiresIn makes exp earlier than iat → already expired.
	raw, err := f.Generate(TokenOptions{Subject: "carol", ExpiresIn: -time.Hour})
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}

	_, err = jwt.ParseWithClaims(raw, jwt.MapClaims{}, keyFunc(f))
	if err == nil {
		t.Fatal("expected expired token to fail validation, got nil error")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected an expiry error, got: %v", err)
	}
}

func TestGenerate_ExtraClaims(t *testing.T) {
	f, err := New()
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}

	raw, err := f.Generate(TokenOptions{
		Subject: "dave",
		Extra:   map[string]interface{}{"custom": "value", "department": "eng"},
	})
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}

	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(raw, claims, keyFunc(f)); err != nil {
		t.Fatalf("ParseWithClaims: unexpected error: %v", err)
	}
	if claims["custom"] != "value" {
		t.Errorf("extra claim custom = %v, want value", claims["custom"])
	}
	if claims["department"] != "eng" {
		t.Errorf("extra claim department = %v, want eng", claims["department"])
	}
}

func TestGenerate_SignatureVerifiesAgainstPublicKey(t *testing.T) {
	f, err := New()
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	raw, err := f.Generate(TokenOptions{Subject: "eve"})
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}

	t.Run("valid against own key", func(t *testing.T) {
		token, err := jwt.Parse(raw, keyFunc(f))
		if err != nil {
			t.Fatalf("Parse: unexpected error: %v", err)
		}
		if !token.Valid {
			t.Error("token should be valid against its own public key")
		}
		if alg, _ := token.Header["alg"].(string); alg != "RS256" {
			t.Errorf("alg header = %v, want RS256", alg)
		}
		if kid, _ := token.Header["kid"].(string); kid != f.keyID {
			t.Errorf("kid header = %v, want %v", kid, f.keyID)
		}
	})

	t.Run("invalid against a different key", func(t *testing.T) {
		other, err := New()
		if err != nil {
			t.Fatalf("New(other): unexpected error: %v", err)
		}
		_, err = jwt.Parse(raw, keyFunc(other))
		if err == nil {
			t.Error("token must NOT verify against a different factory's key")
		}
	})
}

func TestNewWithKey_UsesProvidedKeyAndKeyID(t *testing.T) {
	base, err := New()
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}

	f := NewWithKey(base.privateKey, "my-custom-kid")
	raw, err := f.Generate(TokenOptions{Subject: "frank"})
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}

	token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		return &base.privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if kid, _ := token.Header["kid"].(string); kid != "my-custom-kid" {
		t.Errorf("kid = %v, want my-custom-kid", kid)
	}
}

func TestJWKS_AndPublicKeyJSON(t *testing.T) {
	f, err := New()
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}

	t.Run("PublicKeyJSON has RSA JWK fields", func(t *testing.T) {
		jwk, err := f.PublicKeyJSON()
		if err != nil {
			t.Fatalf("PublicKeyJSON: unexpected error: %v", err)
		}
		m := mustUnmarshal(t, jwk)
		assertField(t, m, "kty", "RSA")
		assertField(t, m, "kid", f.keyID)
		assertField(t, m, "use", "sig")
		assertField(t, m, "alg", "RS256")
		if _, ok := m["n"].(string); !ok {
			t.Error("jwk missing modulus 'n'")
		}
		if _, ok := m["e"].(string); !ok {
			t.Error("jwk missing exponent 'e'")
		}
	})

	t.Run("JWKS wraps the key in a keys array", func(t *testing.T) {
		doc, err := f.JWKS()
		if err != nil {
			t.Fatalf("JWKS: unexpected error: %v", err)
		}
		m := mustUnmarshal(t, doc)
		keys, ok := m["keys"].([]interface{})
		if !ok {
			t.Fatalf("JWKS keys not an array: %T", m["keys"])
		}
		if len(keys) != 1 {
			t.Fatalf("JWKS keys len = %d, want 1", len(keys))
		}
		key, ok := keys[0].(map[string]interface{})
		if !ok {
			t.Fatalf("JWKS key entry not an object: %T", keys[0])
		}
		assertField(t, key, "kid", f.keyID)
		assertField(t, key, "kty", "RSA")
	})

	t.Run("JWKS modulus reconstructs the signing key", func(t *testing.T) {
		// Verify a token using the public key derived from the JWKS-exported
		// modulus/exponent, proving the JWKS describes the actual signing key.
		raw, err := f.Generate(TokenOptions{Subject: "grace"})
		if err != nil {
			t.Fatalf("Generate: unexpected error: %v", err)
		}
		doc, _ := f.JWKS()
		m := mustUnmarshal(t, doc)
		key := m["keys"].([]interface{})[0].(map[string]interface{})
		pub := jwkToPublicKey(t, key)

		token, err := jwt.Parse(raw, func(*jwt.Token) (interface{}, error) { return pub, nil })
		if err != nil {
			t.Fatalf("Parse with JWKS-derived key: %v", err)
		}
		if !token.Valid {
			t.Error("token should verify against the JWKS-published key")
		}
	})
}

// --- helpers ---

func mustUnmarshal(t *testing.T, b []byte) map[string]interface{} {
	t.Helper()
	m := map[string]interface{}{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func assertField(t *testing.T, m map[string]interface{}, key, want string) {
	t.Helper()
	if got, _ := m[key].(string); got != want {
		t.Errorf("field %q = %q, want %q", key, got, want)
	}
}

// jwkToPublicKey reconstructs an *rsa.PublicKey from a JWK's base64url n/e.
func jwkToPublicKey(t *testing.T, jwk map[string]interface{}) *rsa.PublicKey {
	t.Helper()
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: n, E: e}
}
