package token

import (
	"errors"
	"time"
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
	ExpiresAt time.Time
	IssuedAt  time.Time

	// Auth context (RFC 9470)
	ACR string `json:"acr"` // Authentication Context Class Reference
	AMR []string `json:"amr"` // Authentication Methods References

	// Session
	SessionID   string    `json:"sid"`
	AuthTime    time.Time `json:"auth_time"` // when user authenticated (for max_age check)

	// Identity
	Email    string `json:"email"`
	Username string `json:"preferred_username"`
	Roles    []string
	Scopes   []string

	// Tenant
	TenantID string `json:"tenant_id"`

	// Raw extra claims from provider
	Extra map[string]interface{}

	// Active (from RFC 7662 introspection)
	Active bool
}

// AuthAge returns how long ago the user authenticated.
func (c *CommonClaims) AuthAge() time.Duration {
	if c.AuthTime.IsZero() {
		return 0
	}
	return time.Since(c.AuthTime)
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
