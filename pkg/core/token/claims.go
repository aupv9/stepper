package token

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/common-iam/iam/pkg/core/rar"
)

// Audience represents an OAuth/OIDC "aud" claim, which per spec may be either a
// single string or an array of strings. It always unmarshals to a slice.
type Audience []string

func (a *Audience) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	// Try array first, then fall back to a single string.
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*a = list
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	if single != "" {
		*a = []string{single}
	}
	return nil
}

// Sentinel errors for token operations.
var (
	ErrMissingToken        = errors.New("missing bearer token")
	ErrTokenExpired        = errors.New("token has expired")
	ErrTokenInactive       = errors.New("token is not active")
	ErrDPoPBindingMismatch = errors.New("dpop proof does not match token binding")
	ErrDPoPMissingATH      = errors.New("dpop proof missing required ath claim")
	ErrDPoPNoCnf           = errors.New("access token has no cnf.jkt confirmation to bind against")
	ErrDPoPReplay          = errors.New("dpop proof jti has already been seen (replay)")
)

// Confirmation is the RFC 7800 cnf claim. For DPoP (RFC 9449) it carries the
// JWK SHA-256 thumbprint (RFC 7638) that the presented proof key must match.
type Confirmation struct {
	JKT string `json:"jkt"`
}

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
	ACR string   `json:"acr"` // Authentication Context Class Reference
	AMR []string `json:"amr"` // Authentication Methods References

	// Session
	SessionID string    `json:"sid"`
	AuthTime  time.Time `json:"auth_time"` // when user authenticated (for max_age check)

	// JTI is the token's unique ID (RFC 7662). Used to build the revocation
	// index so a webhook that only knows the jti can invalidate the cache entry.
	JTI string `json:"jti,omitempty"`

	// CNF is the RFC 7800 confirmation claim. When present, cnf.jkt binds the
	// token to a DPoP key (RFC 9449) and must match the presented proof.
	CNF *Confirmation `json:"cnf,omitempty"`

	// Nonce is the OIDC nonce, surfaced for FAPI 2.0 profile validation.
	Nonce string `json:"nonce,omitempty"`

	// RequestURI is set when the authorization was initiated via a Pushed
	// Authorization Request (RFC 9126), used by the FAPI 2.0 profile.
	RequestURI string `json:"request_uri,omitempty"`

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

// --- fapi.TokenClaims implementation (FAPI 2.0 profile) ---

// HasDPoP reports whether the token is DPoP-bound (has a cnf.jkt confirmation).
func (c *CommonClaims) HasDPoP() bool {
	return c.CNF != nil && c.CNF.JKT != ""
}

// HasPARRequestURI reports whether the authorization was initiated via PAR.
func (c *CommonClaims) HasPARRequestURI() bool {
	if c.RequestURI != "" {
		return true
	}
	if c.Extra != nil {
		if _, ok := c.Extra["request_uri"]; ok {
			return true
		}
		if _, ok := c.Extra["par_id"]; ok {
			return true
		}
	}
	return false
}

// GetAuthAge returns the elapsed time since authentication (0 if auth_time absent).
func (c *CommonClaims) GetAuthAge() time.Duration { return c.AuthAge() }

// GetNonce returns the nonce claim value.
func (c *CommonClaims) GetNonce() string { return c.Nonce }
