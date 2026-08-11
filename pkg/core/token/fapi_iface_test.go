package token

import (
	"testing"
	"time"

	"github.com/common-iam/iam/pkg/core/fapi"
)

// Compile-time assertion that CommonClaims satisfies fapi.TokenClaims.
var _ fapi.TokenClaims = (*CommonClaims)(nil)

func TestCommonClaims_FAPIInterface(t *testing.T) {
	c := &CommonClaims{
		CNF:        &Confirmation{JKT: "thumb"},
		Nonce:      "n-123",
		RequestURI: "urn:ietf:params:oauth:request_uri:abc",
		AuthTime:   time.Now().Add(-30 * time.Second),
	}
	if !c.HasDPoP() {
		t.Error("HasDPoP should be true when cnf.jkt is set")
	}
	if !c.HasPARRequestURI() {
		t.Error("HasPARRequestURI should be true when RequestURI is set")
	}
	if c.GetNonce() != "n-123" {
		t.Errorf("GetNonce = %q", c.GetNonce())
	}
	if age := c.GetAuthAge(); age <= 0 {
		t.Errorf("GetAuthAge should be positive, got %s", age)
	}

	// A bare bearer token satisfies none of the FAPI signals.
	bare := &CommonClaims{}
	if bare.HasDPoP() || bare.HasPARRequestURI() || bare.GetNonce() != "" {
		t.Error("empty claims must not report DPoP/PAR/nonce")
	}
	// PAR via Extra claim.
	viaExtra := &CommonClaims{Extra: map[string]interface{}{"request_uri": "x"}}
	if !viaExtra.HasPARRequestURI() {
		t.Error("HasPARRequestURI should detect request_uri in Extra")
	}
}
