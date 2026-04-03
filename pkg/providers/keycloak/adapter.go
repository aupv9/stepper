package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/common-iam/iam/pkg/providers/generic"
	"github.com/common-iam/iam/pkg/core/token"
)

// Config holds Keycloak-specific configuration.
type Config struct {
	// BaseURL is the Keycloak server URL, e.g. https://keycloak.example.com
	BaseURL string

	// Realm is the Keycloak realm name.
	Realm string

	// ClientID and ClientSecret for the confidential client used for introspection.
	ClientID     string
	ClientSecret string

	// HTTPClient for customization (optional).
	HTTPClient *http.Client
}

// Adapter wraps the generic OIDC adapter with Keycloak-specific discovery URL.
type Adapter struct {
	inner *generic.Adapter
	cfg   Config
}

// New creates a Keycloak adapter. Call RefreshConfig before use.
func New(cfg Config) *Adapter {
	discoveryURL := fmt.Sprintf(
		"%s/realms/%s/.well-known/openid-configuration",
		cfg.BaseURL, cfg.Realm,
	)
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

func (a *Adapter) Name() string    { return "keycloak" }
func (a *Adapter) Issuer() string  { return a.inner.Issuer() }

func (a *Adapter) RefreshConfig(ctx context.Context) error {
	return a.inner.RefreshConfig(ctx)
}

func (a *Adapter) Introspect(ctx context.Context, rawToken string) (*token.CommonClaims, error) {
	return a.inner.Introspect(ctx, rawToken)
}

func (a *Adapter) JWKS(ctx context.Context) ([]byte, error) {
	return a.inner.JWKS(ctx)
}
