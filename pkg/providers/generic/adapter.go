package generic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/providers"
)

// Config holds configuration for the generic OIDC adapter.
type Config struct {
	// DiscoveryURL is the OIDC provider's well-known discovery endpoint.
	// e.g. https://accounts.google.com/.well-known/openid-configuration
	DiscoveryURL string

	// ClientID and ClientSecret for introspection endpoint auth.
	ClientID     string
	ClientSecret string

	// HTTPClient allows injecting a custom HTTP client.
	HTTPClient *http.Client
}

// Adapter is a generic OIDC provider adapter.
// It auto-discovers endpoints via the OIDC discovery document.
type Adapter struct {
	cfg       Config
	discovery *providers.OIDCDiscovery
	mu        sync.RWMutex
	introspector *token.Introspector
}

// New creates a new generic OIDC adapter.
func New(cfg Config) *Adapter {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Adapter{cfg: cfg}
}

func (a *Adapter) Name() string { return "generic-oidc" }

func (a *Adapter) Issuer() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.discovery != nil {
		return a.discovery.Issuer
	}
	return ""
}

// RefreshConfig fetches the OIDC discovery document and rebuilds the introspector.
func (a *Adapter) RefreshConfig(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.DiscoveryURL, nil)
	if err != nil {
		return fmt.Errorf("building discovery request: %w", err)
	}

	resp, err := a.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching discovery document: %w", err)
	}
	defer resp.Body.Close()

	var doc providers.OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("decoding discovery document: %w", err)
	}

	introspector := token.NewIntrospector(token.IntrospectorConfig{
		Endpoint:     doc.IntrospectionEndpoint,
		ClientID:     a.cfg.ClientID,
		ClientSecret: a.cfg.ClientSecret,
		HTTPClient:   a.cfg.HTTPClient,
	})

	a.mu.Lock()
	a.discovery = &doc
	a.introspector = introspector
	a.mu.Unlock()

	return nil
}

// Introspect validates the token via the discovered introspection endpoint.
func (a *Adapter) Introspect(ctx context.Context, rawToken string) (*token.CommonClaims, error) {
	a.mu.RLock()
	intro := a.introspector
	a.mu.RUnlock()

	if intro == nil {
		return nil, fmt.Errorf("provider not initialized: call RefreshConfig first")
	}

	return intro.Introspect(ctx, rawToken)
}

// JWKS fetches the provider's current JWKS.
func (a *Adapter) JWKS(ctx context.Context) ([]byte, error) {
	a.mu.RLock()
	disc := a.discovery
	a.mu.RUnlock()

	if disc == nil || disc.JWKSUri == "" {
		return nil, fmt.Errorf("JWKS URI not available, call RefreshConfig first")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disc.JWKSUri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}
