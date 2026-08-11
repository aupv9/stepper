package token

import (
	"testing"
	"time"
)

func TestNonceService_IssueValidate(t *testing.T) {
	ns := NewNonceService("secret", time.Minute)
	nonce := ns.Issue()
	if err := ns.Validate(nonce); err != nil {
		t.Fatalf("freshly issued nonce should validate, got: %v", err)
	}
}

func TestNonceService_RejectsTampered(t *testing.T) {
	ns := NewNonceService("secret", time.Minute)
	nonce := ns.Issue()
	// Flip the last character (part of the HMAC). The leading timestamp bytes are
	// zero, so tampering the front can be a no-op; the tail is always signature.
	repl := byte('A')
	if nonce[len(nonce)-1] == 'A' {
		repl = 'B'
	}
	bad := nonce[:len(nonce)-1] + string(repl)
	if err := ns.Validate(bad); err == nil {
		t.Fatal("tampered nonce must be rejected")
	}
	if err := ns.Validate("not-base64!!"); err == nil {
		t.Fatal("malformed nonce must be rejected")
	}
	if err := ns.Validate(""); err == nil {
		t.Fatal("empty nonce must be rejected")
	}
}

func TestNonceService_RejectsExpired(t *testing.T) {
	now := time.Now()
	ns := NewNonceService("secret", time.Minute)
	ns.nowFn = func() time.Time { return now }
	nonce := ns.Issue()

	// Advance beyond the TTL.
	ns.nowFn = func() time.Time { return now.Add(2 * time.Minute) }
	if err := ns.Validate(nonce); err != ErrInvalidNonce {
		t.Fatalf("expired nonce should be ErrInvalidNonce, got: %v", err)
	}
}

func TestNonceService_RejectsWrongSecret(t *testing.T) {
	a := NewNonceService("secret-a", time.Minute)
	b := NewNonceService("secret-b", time.Minute)
	nonce := a.Issue()
	if err := b.Validate(nonce); err == nil {
		t.Fatal("nonce signed with a different secret must not validate")
	}
}
