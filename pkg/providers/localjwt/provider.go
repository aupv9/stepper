// Package localjwt wraps any Provider with local JWT validation: JWS access
// tokens are verified against the provider's JWKS (signature, exp, iss, aud)
// without an introspection round-trip; opaque tokens still fall back to
// RFC 7662 introspection.
//
// Trade-off: locally validated tokens are trusted until they expire — an
// AS-side revocation is NOT visible to this path (there is no per-request
// introspection to catch it). Use short access-token lifetimes, and keep the
// gateway's revocation webhook wired for cache-based eviction of introspected
// tokens. Where instant revocation matters more than latency, keep the
// default introspection mode.
package localjwt

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/providers"
)

// InnerProvider is a Provider that exposes its JWKS endpoint URL.
// generic, keycloak, and auth0 adapters all satisfy it.
type InnerProvider interface {
	providers.Provider
	JWKSURL() string
}

// Config for the local-JWT wrapper.
type Config struct {
	// ExpectedAudience, when set, is enforced on every locally validated
	// token (jwt.WithAudience). Strongly recommended.
	ExpectedAudience string

	// JWKSOnRefreshError is passed through to the JWT validator.
	JWKSOnRefreshError func(error)
}

// Provider validates JWT access tokens locally and delegates everything else.
type Provider struct {
	inner InnerProvider
	cfg   Config

	mu        sync.RWMutex
	validator *token.JWTValidator
}

// New wraps inner with local JWT validation. Call RefreshConfig before use —
// it discovers the JWKS URL and issuer that anchor validation.
func New(inner InnerProvider, cfg Config) *Provider {
	return &Provider{inner: inner, cfg: cfg}
}

func (p *Provider) Name() string   { return p.inner.Name() + "+local-jwt" }
func (p *Provider) Issuer() string { return p.inner.Issuer() }

func (p *Provider) JWKS(ctx context.Context) ([]byte, error) { return p.inner.JWKS(ctx) }

// JWKSURL exposes the inner provider's JWKS endpoint (for chaining wrappers).
func (p *Provider) JWKSURL() string { return p.inner.JWKSURL() }

// RefreshConfig refreshes the inner provider's discovery document and
// (re)builds the local validator pinned to the discovered issuer.
func (p *Provider) RefreshConfig(ctx context.Context) error {
	if err := p.inner.RefreshConfig(ctx); err != nil {
		return err
	}

	jwksURL := p.inner.JWKSURL()
	if jwksURL == "" {
		return fmt.Errorf("provider %s exposes no jwks_uri; local JWT validation impossible", p.inner.Name())
	}

	v := token.NewJWTValidator(token.JWTValidatorConfig{
		JWKSURL:          jwksURL,
		ExpectedIssuer:   p.inner.Issuer(),
		ExpectedAudience: p.cfg.ExpectedAudience,
		OnRefreshError:   p.cfg.JWKSOnRefreshError,
	})

	p.mu.Lock()
	p.validator = v
	p.mu.Unlock()
	return nil
}

// Introspect validates JWS tokens locally; opaque tokens fall back to the
// inner provider's RFC 7662 introspection. A malformed or invalid JWT fails
// closed — it is never "downgraded" to introspection, so an attacker cannot
// route a forged JWT around signature validation.
func (p *Provider) Introspect(ctx context.Context, rawToken string) (*token.CommonClaims, error) {
	if !looksLikeJWS(rawToken) {
		return p.inner.Introspect(ctx, rawToken)
	}

	p.mu.RLock()
	v := p.validator
	p.mu.RUnlock()
	if v == nil {
		return nil, fmt.Errorf("local JWT validator not initialized: call RefreshConfig first")
	}

	claims, err := v.Validate(ctx, rawToken)
	if err != nil {
		// Inactive rather than transport error: the token was presented and
		// failed cryptographic validation.
		return &token.CommonClaims{Active: false}, nil //nolint:nilerr
	}
	return claims, nil
}

// looksLikeJWS reports whether the token has the three-part JWS shape.
func looksLikeJWS(raw string) bool {
	return strings.Count(raw, ".") == 2
}
