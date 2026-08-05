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

	"github.com/common-iam/iam/pkg/core/rar"
)

// JWTValidatorConfig configures local JWT validation.
type JWTValidatorConfig struct {
	// JWKSURL is the endpoint to fetch the JSON Web Key Set from.
	JWKSURL string

	// CacheTTL controls how long fetched keys are cached (default: 5 minutes).
	CacheTTL time.Duration

	// HTTPClient is used to fetch the JWKS (default: 10s timeout client).
	HTTPClient *http.Client

	// ExpectedIssuer, when set, rejects tokens whose iss claim differs.
	ExpectedIssuer string

	// ExpectedAudience, when set, rejects tokens whose aud claim does not
	// contain this value.
	ExpectedAudience string

	// ValidMethods restricts acceptable signing algorithms (e.g. ["RS256",
	// "ES256"]). Default: RS256/RS384/RS512/ES256/ES384/ES512 — "none" and
	// HMAC algorithms are never accepted.
	ValidMethods []string

	// OnRefreshError, when set, is called whenever a JWKS refresh attempt
	// fails (after retries). Use it to increment a metric or log.
	OnRefreshError func(error)
}

// JWTValidator validates JWTs locally using a remote JWKS endpoint.
// This bypasses introspection round-trips, useful when the AS is trusted
// and low-latency validation is needed.
type JWTValidator struct {
	jwksURL        string
	httpClient     *http.Client
	cacheTTL       time.Duration
	parseOpts      []jwt.ParserOption
	onRefreshError func(error)

	mu        sync.RWMutex
	keySet    map[string]crypto.PublicKey // kid → key; "" key for kidless JWKS
	fetchedAt time.Time
	// effectiveTTL is cacheTTL possibly overridden by the endpoint's
	// Cache-Control max-age (clamped to [30s, 24h]).
	effectiveTTL time.Duration
}

// defaultValidMethods are the asymmetric algorithms accepted when
// ValidMethods is not configured. HMAC and "none" are never accepted.
var defaultValidMethods = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

// NewJWTValidator creates a local JWT validator backed by a JWKS endpoint.
func NewJWTValidator(cfg JWTValidatorConfig) *JWTValidator {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	methods := cfg.ValidMethods
	if len(methods) == 0 {
		methods = defaultValidMethods
	}
	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods(methods),
	}
	if cfg.ExpectedIssuer != "" {
		opts = append(opts, jwt.WithIssuer(cfg.ExpectedIssuer))
	}
	if cfg.ExpectedAudience != "" {
		opts = append(opts, jwt.WithAudience(cfg.ExpectedAudience))
	}

	return &JWTValidator{
		jwksURL:        cfg.JWKSURL,
		httpClient:     cfg.HTTPClient,
		cacheTTL:       cfg.CacheTTL,
		effectiveTTL:   cfg.CacheTTL,
		parseOpts:      opts,
		onRefreshError: cfg.OnRefreshError,
		keySet:         make(map[string]crypto.PublicKey),
	}
}

// ParseWithClaims verifies a raw JWT's signature against the JWKS and
// unmarshals its payload into claims. Use this for non-access-token JWTs
// (e.g. OIDC back-channel logout tokens) that need custom claim structures.
// The same signing-algorithm restrictions as Validate apply.
func (v *JWTValidator) ParseWithClaims(ctx context.Context, rawToken string, claims jwt.Claims) error {
	token, err := jwt.ParseWithClaims(rawToken, claims, v.keyfunc(ctx), v.parseOpts...)
	if err != nil {
		return fmt.Errorf("jwt validation: %w", err)
	}
	if !token.Valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}

// Validate parses and verifies a raw JWT, returning normalized CommonClaims.
func (v *JWTValidator) Validate(ctx context.Context, rawToken string) (*CommonClaims, error) {
	token, err := jwt.ParseWithClaims(rawToken, &jwtRawClaims{}, v.keyfunc(ctx), v.parseOpts...)
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
	expired := time.Since(v.fetchedAt) > v.effectiveTTL
	v.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}
	return nil, fmt.Errorf("key %q not found in JWKS cache", kid)
}

// fetchJWKS retrieves keys from the JWKS endpoint and populates the cache.
// Transient failures are retried with backoff; the endpoint's Cache-Control
// max-age (when present) overrides the configured cache TTL, clamped to
// [30s, 24h], so key rotation follows the AS's own schedule.
func (v *JWTValidator) fetchJWKS(ctx context.Context) error {
	var lastErr error
	backoff := 250 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoff):
				backoff *= 4
			case <-ctx.Done():
				if v.onRefreshError != nil {
					v.onRefreshError(ctx.Err())
				}
				return ctx.Err()
			}
		}
		if err := v.fetchJWKSOnce(ctx); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if v.onRefreshError != nil && lastErr != nil {
		v.onRefreshError(lastErr)
	}
	return lastErr
}

func (v *JWTValidator) fetchJWKSOnce(ctx context.Context) error {
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

	ttl := v.cacheTTL
	if maxAge := parseCacheControlMaxAge(resp.Header.Get("Cache-Control")); maxAge > 0 {
		ttl = clampDuration(maxAge, 30*time.Second, 24*time.Hour)
	}

	v.mu.Lock()
	v.keySet = keys
	v.fetchedAt = time.Now()
	v.effectiveTTL = ttl
	v.mu.Unlock()

	return nil
}

// parseCacheControlMaxAge extracts max-age from a Cache-Control header (0 = absent).
func parseCacheControlMaxAge(header string) time.Duration {
	for _, directive := range strings.Split(header, ",") {
		directive = strings.TrimSpace(strings.ToLower(directive))
		if rest, ok := strings.CutPrefix(directive, "max-age="); ok {
			var seconds int
			if _, err := fmt.Sscanf(rest, "%d", &seconds); err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return 0
}

func clampDuration(d, min, max time.Duration) time.Duration {
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}

// --- Claims mapping ---

// jwtRawClaims holds standard + provider-extended JWT claims for parsing.
type jwtRawClaims struct {
	jwt.RegisteredClaims

	ACR      string        `json:"acr"`
	AMR      []string      `json:"amr"`
	SID      string        `json:"sid"`
	AuthTime int64         `json:"auth_time"`
	Email    string        `json:"email"`
	Username string        `json:"preferred_username"`
	Scope    string        `json:"scope"`
	TenantID string        `json:"tenant_id"`
	Cnf      *Confirmation `json:"cnf"`

	// AuthorizationDetails carries RFC 9396 details when present.
	AuthorizationDetails []rar.AuthorizationDetail `json:"authorization_details"`

	// Keycloak nested roles
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`

	// Generic / Auth0 top-level roles
	Roles []string `json:"roles"`
}

func (r *jwtRawClaims) toCommonClaims() *CommonClaims {
	c := &CommonClaims{
		Subject:              r.Subject,
		Issuer:               r.Issuer,
		JTI:                  r.ID,
		ACR:                  r.ACR,
		AMR:                  r.AMR,
		SessionID:            r.SID,
		Email:                r.Email,
		Username:             r.Username,
		TenantID:             r.TenantID,
		Confirmation:         r.Cnf,
		AuthorizationDetails: r.AuthorizationDetails,
		Active:               true,
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
