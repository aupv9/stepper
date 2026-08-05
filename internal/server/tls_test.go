package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSigned generates a self-signed cert/key pair for 127.0.0.1.
func writeSelfSigned(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "iam-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestServer_TLS(t *testing.T) {
	certFile, keyFile := writeSelfSigned(t)
	addr := freePort(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("expected TLS connection state on request")
		}
		w.WriteHeader(http.StatusOK)
	})

	s, err := New(handler, Config{Addr: addr, CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !s.TLSEnabled() {
		t.Fatal("TLSEnabled should be true")
	}
	go s.Start() //nolint:errcheck
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test cert
		},
		Timeout: 5 * time.Second,
	}

	var lastErr error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("https://%s/", addr))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 over TLS, got %d", resp.StatusCode)
			}
			// Plain HTTP against the TLS listener must not be served
			// (Go answers "400 client sent an HTTP request to an HTTPS server").
			plainResp, plainErr := (&http.Client{Timeout: 2 * time.Second}).Get(fmt.Sprintf("http://%s/", addr))
			if plainErr == nil {
				if plainResp.StatusCode == http.StatusOK {
					t.Error("plaintext HTTP against TLS listener must not succeed")
				}
				plainResp.Body.Close()
			}
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("TLS server never became reachable: %v", lastErr)
}

func TestServer_ClientCARequiresCert(t *testing.T) {
	if _, err := New(http.NewServeMux(), Config{Addr: ":0", ClientCAFile: "/nonexistent-ca.pem"}); err == nil {
		t.Error("ClientCAFile without CertFile/KeyFile must be rejected")
	}
}
