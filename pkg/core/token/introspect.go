package token

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/common-iam/iam/pkg/core/rar"
)

// IntrospectionResponse is the RFC 7662 token introspection response.
// The authorization_details field is an RFC 9396 extension.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Sub       string   `json:"sub"`
	Iss       string   `json:"iss"`
	Exp       int64    `json:"exp"`
	IAT       int64    `json:"iat"`
	AuthTime  int64    `json:"auth_time"`
	ACR       string   `json:"acr"`
	AMR       []string `json:"amr"`
	Scope     string   `json:"scope"`
	ClientID  string   `json:"client_id"`
	Username  string   `json:"username"`
	TokenType string   `json:"token_type"`
	JTI       string   `json:"jti"`

	// AuthorizationDetails carries RFC 9396 authorization_details when present.
	AuthorizationDetails []rar.AuthorizationDetail `json:"authorization_details,omitempty"`
}

// IntrospectorConfig holds configuration for the token introspector.
type IntrospectorConfig struct {
	// Endpoint is the RFC 7662 introspection endpoint URL.
	Endpoint string

	// ClientID and ClientSecret for authenticating to the introspection endpoint.
	ClientID     string
	ClientSecret string

	// HTTPClient allows injecting a custom HTTP client (for testing).
	HTTPClient *http.Client

	// Timeout for introspection requests.
	Timeout time.Duration
}

// Introspector performs RFC 7662 token introspection against an AS endpoint.
type Introspector struct {
	cfg IntrospectorConfig
}

// NewIntrospector creates a new token introspector.
func NewIntrospector(cfg IntrospectorConfig) *Introspector {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &Introspector{cfg: cfg}
}

// Introspect calls the AS introspection endpoint and returns normalized claims.
func (i *Introspector) Introspect(ctx context.Context, token string) (*CommonClaims, error) {
	ctx, cancel := context.WithTimeout(ctx, i.cfg.Timeout)
	defer cancel()

	form := url.Values{}
	form.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.cfg.Endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(i.cfg.ClientID, i.cfg.ClientSecret)

	resp, err := i.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection endpoint returned %d", resp.StatusCode)
	}

	var intro IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&intro); err != nil {
		return nil, fmt.Errorf("decoding introspection response: %w", err)
	}

	return introToCommonClaims(&intro), nil
}

// introToCommonClaims maps an IntrospectionResponse to CommonClaims.
func introToCommonClaims(r *IntrospectionResponse) *CommonClaims {
	c := &CommonClaims{
		Active:   r.Active,
		Subject:  r.Sub,
		Issuer:   r.Iss,
		ACR:      r.ACR,
		AMR:      r.AMR,
		Username: r.Username,
	}
	if r.Exp > 0 {
		c.ExpiresAt = time.Unix(r.Exp, 0)
	}
	if r.IAT > 0 {
		c.IssuedAt = time.Unix(r.IAT, 0)
	}
	if r.AuthTime > 0 {
		c.AuthTime = time.Unix(r.AuthTime, 0)
	}
	if r.Scope != "" {
		c.Scopes = strings.Fields(r.Scope)
	}
	if len(r.AuthorizationDetails) > 0 {
		c.AuthorizationDetails = r.AuthorizationDetails
	}
	return c
}

// ExtractBearerToken extracts the Bearer token from an Authorization header.
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrMissingToken
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", fmt.Errorf("invalid Authorization header format")
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", ErrMissingToken
	}
	return token, nil
}
