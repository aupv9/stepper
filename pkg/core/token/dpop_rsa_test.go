package token

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"
)

// signDPoPRSA builds an RS256-signed DPoP proof for testing the RSA verify path.
func signDPoPRSA(t *testing.T, priv *rsa.PrivateKey, htm, htu string) string {
	t.Helper()
	pub := &priv.PublicKey

	eBytes := big.NewInt(int64(pub.E)).Bytes()
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}
	header := map[string]interface{}{"typ": "dpop+jwt", "alg": "RS256", "jwk": jwk}
	payload := map[string]interface{}{
		"jti": "rsa-jti",
		"htm": htm,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)
	input := base64.RawURLEncoding.EncodeToString(hJSON) + "." + base64.RawURLEncoding.EncodeToString(pJSON)

	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestValidateDPoP_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	proof := signDPoPRSA(t, priv, "GET", "https://api.example.com/r")

	req := httptest.NewRequest("GET", "https://api.example.com/r", nil)
	req.Header.Set("DPoP", proof)

	got, err := ValidateDPoP(req, "tok", DPoPConfig{MaxAge: 60 * time.Second})
	if err != nil {
		t.Fatalf("expected valid RSA DPoP proof, got: %v", err)
	}
	if got.Algorithm != "RS256" {
		t.Errorf("alg = %q, want RS256", got.Algorithm)
	}

	// Thumbprint of the RSA JWK should compute without error.
	if _, err := JWKThumbprint(got.JWK); err != nil {
		t.Errorf("RSA thumbprint: %v", err)
	}
}

func TestValidateDPoP_HTUNormalizesQuery(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Proof htu carries no query; request has one → htuMatches must normalize.
	proof := signDPoPRSA(t, priv, "GET", "http://api.example.com/r")
	req := httptest.NewRequest("GET", "http://api.example.com/r?x=1", nil)
	req.Header.Set("DPoP", proof)

	if _, err := ValidateDPoP(req, "tok", DPoPConfig{MaxAge: 60 * time.Second}); err != nil {
		t.Fatalf("htu with differing query should still validate: %v", err)
	}
}
