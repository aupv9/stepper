package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
)

// ErrCertBindingMismatch indicates an RFC 8705 certificate-bound token was
// presented without the matching client certificate.
var ErrCertBindingMismatch = errors.New("client certificate does not match token cnf.x5t#S256 binding")

// VerifyCertBinding enforces RFC 8705 §3: when the access token carries a
// cnf.x5t#S256 confirmation, the TLS client certificate's SHA-256 thumbprint
// must match. Tokens without the binding pass through unchanged; bound tokens
// presented without a client certificate are rejected (fail closed).
func VerifyCertBinding(r *http.Request, claims *CommonClaims) error {
	if claims.Confirmation == nil || claims.Confirmation.X5TS256 == "" {
		return nil // token is not certificate-bound
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errors.New("token is certificate-bound (cnf.x5t#S256) but no TLS client certificate was presented")
	}
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	thumb := base64.RawURLEncoding.EncodeToString(sum[:])
	if !hmac.Equal([]byte(thumb), []byte(claims.Confirmation.X5TS256)) {
		return ErrCertBindingMismatch
	}
	return nil
}
