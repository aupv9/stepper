package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

// jwkAndThumb builds an EC JWK for the given key plus its RFC 7638 thumbprint.
func jwkAndThumb(t *testing.T, priv *ecdsa.PrivateKey) (map[string]interface{}, string) {
	t.Helper()
	pub := &priv.PublicKey
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": pub.Curve.Params().Name,
		"x":   base64.RawURLEncoding.EncodeToString(padLeft(pub.X, byteLen)),
		"y":   base64.RawURLEncoding.EncodeToString(padLeft(pub.Y, byteLen)),
	}
	thumb, err := JWKThumbprint(jwk)
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
	return jwk, thumb
}

func TestJWKThumbprint_RFC7638Vector(t *testing.T) {
	// The canonical example from RFC 7638 §3.1 (RSA key) → known thumbprint.
	jwk := map[string]interface{}{
		"kty": "RSA",
		"e":   "AQAB",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt" +
			"VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6" +
			"4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD" +
			"W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9" +
			"1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH" +
			"aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	}
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	got, err := JWKThumbprint(jwk)
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
	if got != want {
		t.Errorf("thumbprint = %q, want %q", got, want)
	}
}

func TestVerifyBinding_Success(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, thumb := jwkAndThumb(t, priv)

	accessToken := "the-access-token"
	proof := &DPoPProof{JWK: jwk, JTI: "j1", ATH: hashTokenForDPoP(accessToken)}

	if err := proof.VerifyBinding(accessToken, &Confirmation{JKT: thumb}); err != nil {
		t.Fatalf("expected valid binding, got: %v", err)
	}
}

func TestVerifyBinding_StolenTokenAttackerKey(t *testing.T) {
	// Attacker holds a stolen bearer token but signs the proof with THEIR key,
	// which does not match the token's cnf.jkt (the legitimate key).
	legit, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, legitThumb := jwkAndThumb(t, legit)

	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attackerJWK, _ := jwkAndThumb(t, attacker)

	accessToken := "stolen-token"
	proof := &DPoPProof{JWK: attackerJWK, JTI: "j2", ATH: hashTokenForDPoP(accessToken)}

	if err := proof.VerifyBinding(accessToken, &Confirmation{JKT: legitThumb}); err != ErrDPoPBindingMismatch {
		t.Fatalf("expected ErrDPoPBindingMismatch, got: %v", err)
	}
}

func TestVerifyBinding_MissingATH(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, thumb := jwkAndThumb(t, priv)
	proof := &DPoPProof{JWK: jwk, JTI: "j3"} // no ATH

	if err := proof.VerifyBinding("tok", &Confirmation{JKT: thumb}); err != ErrDPoPMissingATH {
		t.Fatalf("expected ErrDPoPMissingATH, got: %v", err)
	}
}

func TestVerifyBinding_NoCnf(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := jwkAndThumb(t, priv)
	accessToken := "tok"
	proof := &DPoPProof{JWK: jwk, JTI: "j4", ATH: hashTokenForDPoP(accessToken)}

	if err := proof.VerifyBinding(accessToken, nil); err != ErrDPoPNoCnf {
		t.Fatalf("expected ErrDPoPNoCnf, got: %v", err)
	}
}

func TestMemoryReplayGuard(t *testing.T) {
	ctx := context.Background()
	g := NewMemoryReplayGuard()

	seen, _ := g.CheckAndSet(ctx, "jti-1", time.Minute)
	if seen {
		t.Fatal("first sight of jti should not be seen")
	}
	seen, _ = g.CheckAndSet(ctx, "jti-1", time.Minute)
	if !seen {
		t.Fatal("second sight of same jti must be flagged as replay")
	}
	seen, _ = g.CheckAndSet(ctx, "jti-2", time.Minute)
	if seen {
		t.Fatal("a different jti must not be flagged")
	}
}
