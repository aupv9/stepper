package pkce_test

import (
	"strings"
	"testing"

	"github.com/common-iam/iam/pkg/core/pkce"
)

func TestGenerateVerifier_Length(t *testing.T) {
	v, err := pkce.GenerateVerifier()
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	if len(v) < pkce.MinVerifierLength || len(v) > pkce.MaxVerifierLength {
		t.Errorf("verifier length %d out of range [%d, %d]", len(v), pkce.MinVerifierLength, pkce.MaxVerifierLength)
	}
}

func TestGenerateVerifier_Uniqueness(t *testing.T) {
	v1, _ := pkce.GenerateVerifier()
	v2, _ := pkce.GenerateVerifier()
	if v1 == v2 {
		t.Error("two generated verifiers must not be identical")
	}
}

func TestS256Challenge_Deterministic(t *testing.T) {
	verifier := strings.Repeat("A", 43)
	c1 := pkce.S256Challenge(verifier)
	c2 := pkce.S256Challenge(verifier)
	if c1 != c2 {
		t.Error("S256Challenge must be deterministic")
	}
	if c1 == "" {
		t.Error("challenge must not be empty")
	}
	// BASE64URL has no padding characters
	if strings.Contains(c1, "=") {
		t.Errorf("challenge must use raw base64url (no '='): %s", c1)
	}
}

func TestVerify_S256_Valid(t *testing.T) {
	verifier, err := pkce.GenerateVerifier()
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	challenge := pkce.S256Challenge(verifier)
	if err := pkce.Verify(verifier, challenge, pkce.MethodS256); err != nil {
		t.Errorf("valid S256 pair should pass: %v", err)
	}
}

func TestVerify_S256_WrongVerifier(t *testing.T) {
	v1, _ := pkce.GenerateVerifier()
	v2, _ := pkce.GenerateVerifier()
	challenge := pkce.S256Challenge(v1)
	if err := pkce.Verify(v2, challenge, pkce.MethodS256); err == nil {
		t.Error("wrong verifier should fail S256 verification")
	}
}

func TestVerify_Plain_Valid(t *testing.T) {
	verifier := strings.Repeat("Aa1-", 11) // 44 chars, valid charset
	if err := pkce.Verify(verifier, verifier, pkce.MethodPlain); err != nil {
		t.Errorf("plain method with matching verifier/challenge should pass: %v", err)
	}
}

func TestVerify_Plain_Mismatch(t *testing.T) {
	verifier := strings.Repeat("B", 43)
	challenge := strings.Repeat("C", 43)
	if err := pkce.Verify(verifier, challenge, pkce.MethodPlain); err == nil {
		t.Error("mismatched plain verifier should fail")
	}
}

func TestVerify_ShortVerifier(t *testing.T) {
	if err := pkce.Verify("short", "challenge", pkce.MethodS256); err == nil {
		t.Error("verifier shorter than 43 chars should be rejected")
	}
}

func TestVerify_InvalidCharset(t *testing.T) {
	bad := strings.Repeat("A", 42) + "!" // 43 chars but '!' is not allowed
	if err := pkce.Verify(bad, "any", pkce.MethodS256); err == nil {
		t.Error("invalid character should be rejected")
	}
}

func TestVerify_UnsupportedMethod(t *testing.T) {
	verifier := strings.Repeat("A", 43)
	if err := pkce.Verify(verifier, verifier, "sha512"); err == nil {
		t.Error("unsupported method should be rejected")
	}
}

func TestValidateMethod_S256(t *testing.T) {
	if err := pkce.ValidateMethod(pkce.MethodS256, false); err != nil {
		t.Errorf("S256 should always be valid: %v", err)
	}
}

func TestValidateMethod_Plain_Allowed(t *testing.T) {
	if err := pkce.ValidateMethod(pkce.MethodPlain, true); err != nil {
		t.Errorf("plain should be valid when allowPlain=true: %v", err)
	}
}

func TestValidateMethod_Plain_Rejected(t *testing.T) {
	if err := pkce.ValidateMethod(pkce.MethodPlain, false); err == nil {
		t.Error("plain should be rejected when allowPlain=false")
	}
}

func TestValidateMethod_Unknown(t *testing.T) {
	if err := pkce.ValidateMethod("RS256", false); err == nil {
		t.Error("unknown method should be rejected")
	}
}

func TestVerify_FullRoundTrip(t *testing.T) {
	verifier, err := pkce.GenerateVerifier()
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	challenge := pkce.S256Challenge(verifier)
	if err := pkce.ValidateMethod(pkce.MethodS256, false); err != nil {
		t.Fatalf("ValidateMethod: %v", err)
	}
	if err := pkce.Verify(verifier, challenge, pkce.MethodS256); err != nil {
		t.Errorf("full round-trip should pass: %v", err)
	}
}
