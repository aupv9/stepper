package providers

import (
	"context"

	"github.com/common-iam/iam/pkg/core/token"
)

// Provider is the abstraction over any OIDC-compatible identity provider.
// Implementations: Keycloak, Auth0, Generic OIDC.
type Provider interface {
	// Introspect validates a token and returns normalized claims.
	Introspect(ctx context.Context, rawToken string) (*token.CommonClaims, error)

	// JWKS returns the provider's current JSON Web Key Set for local JWT validation.
	JWKS(ctx context.Context) ([]byte, error)

	// RefreshConfig fetches/refreshes the OIDC discovery document.
	RefreshConfig(ctx context.Context) error

	// Name returns a human-readable provider name (e.g. "keycloak", "auth0").
	Name() string

	// Issuer returns the token issuer URL this provider handles.
	Issuer() string
}

// OIDCDiscovery is the standard OIDC discovery document.
type OIDCDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	SupportedACRValues    []string `json:"acr_values_supported"`
	SupportedAMRValues    []string `json:"amr_values_supported"`
	ScopesSupported       []string `json:"scopes_supported"`
}
