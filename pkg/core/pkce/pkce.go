// Package pkce implements RFC 7636 Proof Key for Code Exchange.
// It provides code verifier generation, code challenge derivation (S256 only),
// and challenge verification — used by both clients and authorization servers.
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// Method identifies the code challenge transformation algorithm.
type Method string

const (
	// MethodS256 is the only method allowed by FAPI 2.0 and recommended by RFC 7636.
	MethodS256 Method = "S256"
	// MethodPlain is allowed by RFC 7636 but MUST NOT be used in FAPI 2.0 profiles.
	MethodPlain Method = "plain"
)

const (
	// MinVerifierLength is the minimum allowed code_verifier length (RFC 7636 §4.1).
	MinVerifierLength = 43
	// MaxVerifierLength is the maximum allowed code_verifier length (RFC 7636 §4.1).
	MaxVerifierLength = 128
)

// GenerateVerifier returns a cryptographically random code_verifier that satisfies
// RFC 7636 §4.1: [A-Za-z0-9\-._~]{43,128}.
func GenerateVerifier() (string, error) {
	b := make([]byte, 96) // 96 random bytes → 128 base64url chars
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating PKCE verifier: %w", err)
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	// Trim to MaxVerifierLength if encoding produces more.
	if len(v) > MaxVerifierLength {
		v = v[:MaxVerifierLength]
	}
	return v, nil
}

// S256Challenge computes the code_challenge for the given verifier using
// the S256 method: BASE64URL(SHA256(ASCII(code_verifier))).
func S256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// Verify checks that the code_verifier satisfies the code_challenge produced
// by method. Returns nil on success.
//
// For FAPI 2.0 deployments, enforce that method == MethodS256 before calling.
func Verify(verifier, challenge string, method Method) error {
	if err := validateVerifier(verifier); err != nil {
		return err
	}
	switch method {
	case MethodS256:
		expected := S256Challenge(verifier)
		if !secureEqual(expected, challenge) {
			return fmt.Errorf("PKCE: code_verifier does not match code_challenge")
		}
	case MethodPlain:
		if !secureEqual(verifier, challenge) {
			return fmt.Errorf("PKCE: code_verifier does not match code_challenge (plain)")
		}
	default:
		return fmt.Errorf("PKCE: unsupported code_challenge_method %q", method)
	}
	return nil
}

// ValidateMethod returns an error if method is not supported or not allowed
// by the given config. Use this to reject "plain" in strict FAPI 2.0 mode.
func ValidateMethod(method Method, allowPlain bool) error {
	switch method {
	case MethodS256:
		return nil
	case MethodPlain:
		if allowPlain {
			return nil
		}
		return fmt.Errorf("PKCE: 'plain' code_challenge_method is not permitted; use S256")
	default:
		return fmt.Errorf("PKCE: unsupported code_challenge_method %q", method)
	}
}

// validateVerifier checks RFC 7636 §4.1 character set and length constraints.
func validateVerifier(v string) error {
	if len(v) < MinVerifierLength {
		return fmt.Errorf("PKCE: code_verifier too short (%d < %d)", len(v), MinVerifierLength)
	}
	if len(v) > MaxVerifierLength {
		return fmt.Errorf("PKCE: code_verifier too long (%d > %d)", len(v), MaxVerifierLength)
	}
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for i, c := range v {
		if !strings.ContainsRune(allowed, c) {
			return fmt.Errorf("PKCE: code_verifier contains invalid character %q at position %d", c, i)
		}
	}
	return nil
}

// secureEqual performs a constant-time string comparison to prevent timing attacks.
func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
