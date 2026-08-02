package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

// TestJWKThumbprint_RFC7638Vector checks the RSA test vector from RFC 7638 §3.1.
func TestJWKThumbprint_RFC7638Vector(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
	}
	want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	got, err := JWKThumbprint(jwk)
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
	if got != want {
		t.Errorf("thumbprint = %q, want %q", got, want)
	}
}

func TestValidateDPoP_MissingATH_Rejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proof := signDPoP(t, priv, "GET", "https://api.example.com/r", "") // no ath

	req := httptest.NewRequest("GET", "https://api.example.com/r", nil)
	req.Header.Set("DPoP", proof)

	_, err := ValidateDPoP(req, "tok", DPoPConfig{MaxAge: 60 * time.Second})
	if !errors.Is(err, ErrDPoPMissingATH) {
		t.Fatalf("expected ErrDPoPMissingATH, got %v", err)
	}
}

func TestDPoPValidator_ReplayRejected(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const accessToken = "tok"
	proof := signDPoP(t, priv, "GET", "https://api.example.com/r", hashTokenForDPoP(accessToken))

	v := NewDPoPValidator(DPoPConfig{MaxAge: 60 * time.Second}, NewMemoryCache())

	req := httptest.NewRequest("GET", "https://api.example.com/r", nil)
	req.Header.Set("DPoP", proof)
	if _, err := v.Validate(req, accessToken); err != nil {
		t.Fatalf("first use should pass: %v", err)
	}

	req2 := httptest.NewRequest("GET", "https://api.example.com/r", nil)
	req2.Header.Set("DPoP", proof)
	if _, err := v.Validate(req2, accessToken); !errors.Is(err, ErrDPoPReplay) {
		t.Fatalf("expected ErrDPoPReplay on second use, got %v", err)
	}
}

func TestVerifyDPoPBinding(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const accessToken = "tok"
	proofJWT := signDPoP(t, priv, "GET", "https://api.example.com/r", hashTokenForDPoP(accessToken))

	req := httptest.NewRequest("GET", "https://api.example.com/r", nil)
	req.Header.Set("DPoP", proofJWT)
	proof, err := ValidateDPoP(req, accessToken, DPoPConfig{MaxAge: 60 * time.Second})
	if err != nil {
		t.Fatalf("ValidateDPoP: %v", err)
	}

	thumb, err := proof.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}

	t.Run("matching jkt passes", func(t *testing.T) {
		claims := &CommonClaims{Confirmation: &Confirmation{JKT: thumb}}
		if err := VerifyDPoPBinding(proof, claims); err != nil {
			t.Errorf("expected binding to pass: %v", err)
		}
	})
	t.Run("mismatched jkt rejected", func(t *testing.T) {
		claims := &CommonClaims{Confirmation: &Confirmation{JKT: "wrong-thumbprint"}}
		if !errors.Is(VerifyDPoPBinding(proof, claims), ErrDPoPBindingMismatch) {
			t.Error("expected ErrDPoPBindingMismatch")
		}
	})
	t.Run("unbound token rejected", func(t *testing.T) {
		if VerifyDPoPBinding(proof, &CommonClaims{}) == nil {
			t.Error("token without cnf.jkt must be rejected when DPoP is enforced")
		}
	})
}

func TestNonceProvider(t *testing.T) {
	np := NewNonceProvider("secret", 5*time.Minute)
	if !np.Valid(np.Current()) {
		t.Error("current nonce must validate")
	}
	if np.Valid("bogus") {
		t.Error("bogus nonce must not validate")
	}
	if np.Valid("") {
		t.Error("empty nonce must not validate")
	}

	other := NewNonceProvider("other-secret", 5*time.Minute)
	if np.Valid(other.Current()) {
		t.Error("nonce from a different secret must not validate")
	}
}

func TestValidateDPoP_NonceRequired(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const accessToken = "tok"
	proof := signDPoP(t, priv, "GET", "https://api.example.com/r", hashTokenForDPoP(accessToken))

	req := httptest.NewRequest("GET", "https://api.example.com/r", nil)
	req.Header.Set("DPoP", proof)

	cfg := DPoPConfig{MaxAge: 60 * time.Second, Nonce: NewNonceProvider("s", 0)}
	if _, err := ValidateDPoP(req, accessToken, cfg); !errors.Is(err, ErrDPoPNonceRequired) {
		t.Fatalf("expected ErrDPoPNonceRequired for proof without nonce, got %v", err)
	}
}
