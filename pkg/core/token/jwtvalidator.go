package token

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTValidatorConfig configures local JWT validation.
type JWTValidatorConfig struct {
	// JWKSURL is the endpoint to fetch the JSON Web Key Set from.
	JWKSURL string

	// CacheTTL controls how long fetched keys are cached (default: 5 minutes).
	CacheTTL time.Duration

	// HTTPClient is used to fetch the JWKS (default: 10s timeout client).
	HTTPClient *http.Client
}

// JWTValidator validates JWTs locally using a remote JWKS endpoint.
// This bypasses introspection round-trips, useful when the AS is trusted
// and low-latency validation is needed.
type JWTValidator struct {
	jwksURL    string
	httpClient *http.Client
	cacheTTL   time.Duration

	mu        sync.RWMutex
	keySet    map[string]crypto.PublicKey // kid → key; "" key for kidless JWKS
	fetchedAt time.Time
}

// NewJWTValidator creates a local JWT validator backed by a JWKS endpoint.
func NewJWTValidator(cfg JWTValidatorConfig) *JWTValidator {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &JWTValidator{
		jwksURL:    cfg.JWKSURL,
		httpClient: cfg.HTTPClient,
		cacheTTL:   cfg.CacheTTL,
		keySet:     make(map[string]crypto.PublicKey),
	}
}

// Validate parses and verifies a raw JWT, returning normalized CommonClaims.
func (v *JWTValidator) Validate(ctx context.Context, rawToken string) (*CommonClaims, error) {
	token, err := jwt.ParseWithClaims(rawToken, &jwtRawClaims{}, v.keyfunc(ctx),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("jwt validation: %w", err)
	}

	raw, ok := token.Claims.(*jwtRawClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return raw.toCommonClaims(), nil
}

// RefreshKeys forces a JWKS cache refresh. Call this on key rotation events.
func (v *JWTValidator) RefreshKeys(ctx context.Context) error {
	return v.fetchJWKS(ctx)
}

// keyfunc returns a jwt.Keyfunc that resolves the signing key from the JWKS cache.
func (v *JWTValidator) keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)

		key, err := v.lookupKey(kid)
		if err != nil {
			// Cache miss or expired — refresh once and retry
			if fetchErr := v.fetchJWKS(ctx); fetchErr != nil {
				return nil, fmt.Errorf("fetching JWKS: %w", fetchErr)
			}
			key, err = v.lookupKey(kid)
			if err != nil {
				return nil, err
			}
		}
		return key, nil
	}
}

// lookupKey checks the in-memory key cache.
func (v *JWTValidator) lookupKey(kid string) (crypto.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keySet[kid]
	expired := time.Since(v.fetchedAt) > v.cacheTTL
	v.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}
	return nil, fmt.Errorf("key %q not found in JWKS cache", kid)
}

// fetchJWKS retrieves keys from the JWKS endpoint and populates the cache.
func (v *JWTValidator) fetchJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS from %s: %w", v.jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decoding JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		key, err := PublicKeyFromJWK(jwk)
		if err != nil {
			continue // skip keys with unsupported algorithms
		}
		kid, _ := jwk["kid"].(string)
		keys[kid] = key
	}

	v.mu.Lock()
	v.keySet = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()

	return nil
}

// --- Claims mapping ---

// jwtRawClaims holds standard + provider-extended JWT claims for parsing.
type jwtRawClaims struct {
	jwt.RegisteredClaims

	ACR      string   `json:"acr"`
	AMR      []string `json:"amr"`
	SID      string   `json:"sid"`
	AuthTime int64    `json:"auth_time"`
	Email    string   `json:"email"`
	Username string   `json:"preferred_username"`
	Scope    string   `json:"scope"`
	TenantID string   `json:"tenant_id"`

	// Keycloak nested roles
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`

	// Generic / Auth0 top-level roles
	Roles []string `json:"roles"`
}

func (r *jwtRawClaims) toCommonClaims() *CommonClaims {
	c := &CommonClaims{
		Subject:   r.Subject,
		Issuer:    r.Issuer,
		ACR:       r.ACR,
		AMR:       r.AMR,
		SessionID: r.SID,
		Email:     r.Email,
		Username:  r.Username,
		TenantID:  r.TenantID,
		Active:    true,
	}

	if r.ExpiresAt != nil {
		c.ExpiresAt = r.ExpiresAt.Time
	}
	if r.IssuedAt != nil {
		c.IssuedAt = r.IssuedAt.Time
	}
	if r.AuthTime != 0 {
		c.AuthTime = time.Unix(r.AuthTime, 0)
	}
	c.Audience = append(c.Audience, r.Audience...)

	if r.Scope != "" {
		c.Scopes = strings.Fields(r.Scope)
	}

	// Keycloak roles take precedence over generic roles
	if len(r.RealmAccess.Roles) > 0 {
		c.Roles = r.RealmAccess.Roles
	} else {
		c.Roles = r.Roles
	}

	return c
}
