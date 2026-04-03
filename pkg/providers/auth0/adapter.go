package auth0

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/providers/generic"
)

// Config holds Auth0-specific configuration.
type Config struct {
	// Domain is the Auth0 tenant domain, e.g. "myapp.us.auth0.com"
	Domain string

	// ClientID and ClientSecret of the machine-to-machine app used for introspection.
	ClientID     string
	ClientSecret string

	// Audience is the API identifier (for access token validation).
	Audience string

	// HTTPClient for customization (optional).
	HTTPClient *http.Client
}

// Adapter wraps the generic OIDC adapter for Auth0.
type Adapter struct {
	inner    *generic.Adapter
	cfg      Config
}

// New creates an Auth0 adapter. Call RefreshConfig before use.
func New(cfg Config) *Adapter {
	discoveryURL := fmt.Sprintf("https://%s/.well-known/openid-configuration", cfg.Domain)
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	inner := generic.New(generic.Config{
		DiscoveryURL: discoveryURL,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		HTTPClient:   cfg.HTTPClient,
	})
	return &Adapter{inner: inner, cfg: cfg}
}

func (a *Adapter) Name() string   { return "auth0" }
func (a *Adapter) Issuer() string { return a.inner.Issuer() }

func (a *Adapter) RefreshConfig(ctx context.Context) error {
	return a.inner.RefreshConfig(ctx)
}

func (a *Adapter) Introspect(ctx context.Context, rawToken string) (*token.CommonClaims, error) {
	return a.inner.Introspect(ctx, rawToken)
}

func (a *Adapter) JWKS(ctx context.Context) ([]byte, error) {
	return a.inner.JWKS(ctx)
}
