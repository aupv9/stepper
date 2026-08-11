package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

// ErrInvalidNonce is returned when a DPoP nonce is malformed, tampered, or expired.
var ErrInvalidNonce = errors.New("invalid or expired DPoP nonce")

// NonceService issues and validates server-side DPoP nonces (RFC 9449 §8)
// statelessly: each nonce is a timestamp plus an HMAC over it, so no storage is
// needed and any instance sharing the secret can validate. Requiring a nonce
// lets the server bound the lifetime of a proof and defeat pre-computed proofs.
type NonceService struct {
	secret []byte
	ttl    time.Duration
	nowFn  func() time.Time
}

// NewNonceService creates a nonce service. ttl defaults to 5 minutes.
func NewNonceService(secret string, ttl time.Duration) *NonceService {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &NonceService{secret: []byte(secret), ttl: ttl, nowFn: time.Now}
}

// Issue returns a fresh nonce for the DPoP-Nonce response header.
func (n *NonceService) Issue() string {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(n.nowFn().Unix()))
	mac := n.sign(ts)
	return base64.RawURLEncoding.EncodeToString(append(ts, mac...))
}

// Validate checks a nonce's signature and freshness.
func (n *NonceService) Validate(nonce string) error {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 8+sha256.Size {
		return ErrInvalidNonce
	}
	ts, mac := raw[:8], raw[8:]
	if !hmac.Equal(mac, n.sign(ts)) {
		return ErrInvalidNonce
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(ts)), 0)
	if n.nowFn().Sub(issued) > n.ttl {
		return ErrInvalidNonce
	}
	return nil
}

func (n *NonceService) sign(ts []byte) []byte {
	m := hmac.New(sha256.New, n.secret)
	m.Write(ts)
	return m.Sum(nil)
}
