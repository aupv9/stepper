package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"
)

// signDPoP builds a properly signed DPoP proof JWT for testing.
func signDPoP(t *testing.T, priv *ecdsa.PrivateKey, htm, htu, ath string) string {
	t.Helper()

	pub := &priv.PublicKey
	byteLen := (pub.Curve.Params().BitSize + 7) / 8

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": pub.Curve.Params().Name,
		"x":   base64.RawURLEncoding.EncodeToString(padLeft(pub.X, byteLen)),
		"y":   base64.RawURLEncoding.EncodeToString(padLeft(pub.Y, byteLen)),
	}
	header := map[string]interface{}{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	payload := map[string]interface{}{
		"jti": "jti-" + htm,
		"htm": htm,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if ath != "" {
		payload["ath"] = ath
	}

	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)
	hB64 := base64.RawURLEncoding.EncodeToString(hJSON)
	pB64 := base64.RawURLEncoding.EncodeToString(pJSON)
	input := hB64 + "." + pB64

	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}

	sig := make([]byte, 2*byteLen)
	r.FillBytes(sig[:byteLen])
	s.FillBytes(sig[byteLen:])

	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func padLeft(n *big.Int, length int) []byte {
	b := n.Bytes()
	if len(b) == length {
		return b
	}
	out := make([]byte, length)
	copy(out[length-len(b):], b)
	return out
}

// ---------- PublicKeyFromJWK tests ----------

func TestPublicKeyFromJWK_EC(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey
	byteLen := 32

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padLeft(pub.X, byteLen)),
		"y":   base64.RawURLEncoding.EncodeToString(padLeft(pub.Y, byteLen)),
	}

	got, err := PublicKeyFromJWK(jwk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ecGot, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected *ecdsa.PublicKey")
	}
	if ecGot.X.Cmp(pub.X) != 0 || ecGot.Y.Cmp(pub.Y) != 0 {
		t.Fatal("recovered key coordinates differ from original")
	}
}

func TestPublicKeyFromJWK_UnsupportedKty(t *testing.T) {
	_, err := PublicKeyFromJWK(map[string]interface{}{"kty": "oct"})
	if err == nil {
		t.Fatal("expected error for unsupported kty")
	}
}

func TestPublicKeyFromJWK_InvalidCurvePoint(t *testing.T) {
	// x=1, y=1 is not on P-256
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		"y":   base64.RawURLEncoding.EncodeToString([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
	}
	_, err := PublicKeyFromJWK(jwk)
	if err == nil {
		t.Fatal("expected error for point not on curve")
	}
}

// ---------- ValidateDPoP integration tests ----------

func TestValidateDPoP_Valid(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	accessToken := "test-access-token"
	ath := hashTokenForDPoP(accessToken)
	proof := signDPoP(t, priv, "GET", "https://api.example.com/resource", ath)

	req := httptest.NewRequest("GET", "https://api.example.com/resource", nil)
	req.Header.Set("DPoP", proof)

	cfg := DPoPConfig{MaxAge: 60 * time.Second}
	got, err := ValidateDPoP(req, accessToken, cfg)
	if err != nil {
		t.Fatalf("expected valid proof, got error: %v", err)
	}
	if got.HTM != "GET" {
		t.Errorf("expected htm=GET, got %q", got.HTM)
	}
}

func TestValidateDPoP_MissingHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	_, err := ValidateDPoP(req, "tok", DefaultDPoPConfig())
	if err == nil {
		t.Fatal("expected error for missing DPoP header")
	}
}

func TestValidateDPoP_WrongMethod(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proof := signDPoP(t, priv, "POST", "https://api.example.com/resource", "")

	req := httptest.NewRequest("GET", "https://api.example.com/resource", nil)
	req.Header.Set("DPoP", proof)

	_, err := ValidateDPoP(req, "tok", DPoPConfig{MaxAge: 60 * time.Second})
	if err == nil {
		t.Fatal("expected error for htm mismatch")
	}
}

func TestValidateDPoP_ATHMismatch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proof := signDPoP(t, priv, "GET", "https://api.example.com/r", hashTokenForDPoP("other-token"))

	req := httptest.NewRequest("GET", "https://api.example.com/r", nil)
	req.Header.Set("DPoP", proof)

	_, err := ValidateDPoP(req, "real-token", DPoPConfig{MaxAge: 60 * time.Second})
	if err == nil {
		t.Fatal("expected error for ath mismatch")
	}
}

func TestValidateDPoP_TamperedSignature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proof := signDPoP(t, priv, "GET", "https://api.example.com/r", "")

	// Flip last byte of signature
	parts := splitJWT(proof)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sigBytes[len(sigBytes)-1] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sigBytes)
	tampered := parts[0] + "." + parts[1] + "." + parts[2]

	req := httptest.NewRequest("GET", "https://api.example.com/r", nil)
	req.Header.Set("DPoP", tampered)

	_, err := ValidateDPoP(req, "tok", DPoPConfig{MaxAge: 60 * time.Second})
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestValidateDPoP_ExpiredProof(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Build proof with old iat
	pub := &priv.PublicKey
	byteLen := 32
	jwk := map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(padLeft(pub.X, byteLen)),
		"y": base64.RawURLEncoding.EncodeToString(padLeft(pub.Y, byteLen)),
	}
	header := map[string]interface{}{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	payload := map[string]interface{}{
		"jti": "old",
		"htm": "GET",
		"htu": "https://api.example.com/r",
		"iat": time.Now().Add(-2 * time.Minute).Unix(), // 2 min old
	}
	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)
	hB64 := base64.RawURLEncoding.EncodeToString(hJSON)
	pB64 := base64.RawURLEncoding.EncodeToString(pJSON)
	input := hB64 + "." + pB64
	digest := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, priv, digest[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	proof := input + "." + base64.RawURLEncoding.EncodeToString(sig)

	req := httptest.NewRequest("GET", "https://api.example.com/r", nil)
	req.Header.Set("DPoP", proof)

	_, err := ValidateDPoP(req, "tok", DPoPConfig{MaxAge: 60 * time.Second})
	if err == nil {
		t.Fatal("expected error for expired proof")
	}
}

func splitJWT(jwt string) [3]string {
	var out [3]string
	parts := []string{}
	start := 0
	for i, c := range jwt {
		if c == '.' {
			parts = append(parts, jwt[start:i])
			start = i + 1
		}
	}
	parts = append(parts, jwt[start:])
	if len(parts) == 3 {
		out[0], out[1], out[2] = parts[0], parts[1], parts[2]
	}
	return out
}
