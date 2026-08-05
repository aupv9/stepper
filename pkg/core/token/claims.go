package token

import (
	"errors"
	"time"

	"github.com/common-iam/iam/pkg/core/rar"
)

// Sentinel errors for token operations.
var (
	ErrMissingToken        = errors.New("missing bearer token")
	ErrTokenExpired        = errors.New("token has expired")
	ErrTokenInactive       = errors.New("token is not active")
	ErrDPoPBindingMismatch = errors.New("dpop proof does not match token binding")
)

// CommonClaims is the normalized representation of JWT/introspection claims
// across all providers (Keycloak, Auth0, generic OIDC).
type CommonClaims struct {
	// Standard OIDC
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss"`
	Audience  []string `json:"aud"`
	JTI       string   `json:"jti"`
	ExpiresAt time.Time
	IssuedAt  time.Time

	// Confirmation carries the RFC 7800 cnf claim. For DPoP-bound tokens
	// (RFC 9449) JKT holds the RFC 7638 SHA-256 thumbprint of the client's
	// public key; the guard compares it against the DPoP proof's JWK.
	Confirmation *Confirmation `json:"cnf,omitempty"`

	// Auth context (RFC 9470)
	ACR string   `json:"acr"` // Authentication Context Class Reference
	AMR []string `json:"amr"` // Authentication Methods References

	// Session
	SessionID string    `json:"sid"`
	AuthTime  time.Time `json:"auth_time"` // when user authenticated (for max_age check)

	// Identity
	Email    string `json:"email"`
	Username string `json:"preferred_username"`
	Roles    []string
	Scopes   []string

	// Tenant
	TenantID string `json:"tenant_id"`

	// AuthorizationDetails carries RFC 9396 Rich Authorization Request details
	// when the token was issued with an authorization_details claim.
	AuthorizationDetails []rar.AuthorizationDetail `json:"authorization_details,omitempty"`

	// Raw extra claims from provider
	Extra map[string]interface{}

	// Active (from RFC 7662 introspection)
	Active bool
}

// Confirmation is the RFC 7800 cnf (confirmation) claim.
type Confirmation struct {
	// JKT is the RFC 7638 JWK SHA-256 thumbprint (base64url, no padding)
	// of the DPoP public key the token is bound to (RFC 9449 §6.1).
	JKT string `json:"jkt,omitempty"`

	// X5TS256 is the base64url SHA-256 thumbprint of the client certificate
	// the token is bound to (RFC 8705 §3.1, mTLS sender-constrained tokens).
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// AuthAge returns how long ago the user authenticated.
func (c *CommonClaims) AuthAge() time.Duration {
	if c.AuthTime.IsZero() {
		return 0
	}
	return time.Since(c.AuthTime)
}

// --- FAPI 2.0 profile interface (pkg/core/fapi.TokenClaims) ---

// HasDPoP reports whether the token is DPoP-bound (carries cnf.jkt).
func (c *CommonClaims) HasDPoP() bool {
	return c.Confirmation != nil && c.Confirmation.JKT != ""
}

// HasPARRequestURI reports whether the authorization was initiated via a
// Pushed Authorization Request (request_uri or par_id claim present).
func (c *CommonClaims) HasPARRequestURI() bool {
	return c.extraString("request_uri") != "" || c.extraString("par_id") != ""
}

// GetAuthAge returns the time since user authentication (0 = unknown).
func (c *CommonClaims) GetAuthAge() time.Duration {
	return c.AuthAge()
}

// GetNonce returns the token's nonce claim, if any.
func (c *CommonClaims) GetNonce() string {
	return c.extraString("nonce")
}

func (c *CommonClaims) extraString(key string) string {
	if c.Extra == nil {
		return ""
	}
	s, _ := c.Extra[key].(string)
	return s
}

// HasScope checks if the token contains a specific scope.
func (c *CommonClaims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasRole checks if the token contains a specific role.
func (c *CommonClaims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}
