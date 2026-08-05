package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestVerifyCertBinding(t *testing.T) {
	cert := selfSignedCert(t)
	sum := sha256.Sum256(cert.Raw)
	thumb := base64.RawURLEncoding.EncodeToString(sum[:])

	withCert := httptest.NewRequest("GET", "https://api.example/r", nil)
	withCert.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	noCert := httptest.NewRequest("GET", "https://api.example/r", nil)
	noCert.TLS = &tls.ConnectionState{}

	t.Run("unbound token passes without cert", func(t *testing.T) {
		if err := VerifyCertBinding(noCert, &CommonClaims{}); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("bound token with matching cert passes", func(t *testing.T) {
		claims := &CommonClaims{Confirmation: &Confirmation{X5TS256: thumb}}
		if err := VerifyCertBinding(withCert, claims); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("bound token without cert fails closed", func(t *testing.T) {
		claims := &CommonClaims{Confirmation: &Confirmation{X5TS256: thumb}}
		if VerifyCertBinding(noCert, claims) == nil {
			t.Error("expected rejection when no client certificate presented")
		}
	})

	t.Run("bound token with wrong cert rejected", func(t *testing.T) {
		other := selfSignedCert(t)
		req := httptest.NewRequest("GET", "https://api.example/r", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{other}}
		claims := &CommonClaims{Confirmation: &Confirmation{X5TS256: thumb}}
		if !errors.Is(VerifyCertBinding(req, claims), ErrCertBindingMismatch) {
			t.Error("expected ErrCertBindingMismatch")
		}
	})
}
