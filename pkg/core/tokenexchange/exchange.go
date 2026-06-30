// Package tokenexchange implements OAuth 2.0 Token Exchange as defined in RFC 8693.
// Token exchange allows a service to obtain a new token on behalf of a subject
// (impersonation) or act for a subject with a different identity (delegation).
package tokenexchange

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Token type URIs defined in RFC 8693 §3.
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeSAML1        = "urn:ietf:params:oauth:token-type:saml1"
	TokenTypeSAML2        = "urn:ietf:params:oauth:token-type:saml2"
)

// Request is an RFC 8693 token exchange request.
type Request struct {
	// GrantType must be "urn:ietf:params:oauth:grant-type:token-exchange".
	// It is set automatically by Exchange().
	GrantType string

	// SubjectToken is the token representing the subject (REQUIRED).
	SubjectToken string

	// SubjectTokenType identifies the type of SubjectToken (REQUIRED).
	// Use one of the TokenType* constants.
	SubjectTokenType string

	// ActorToken is the token representing the acting party (OPTIONAL).
	// Present in delegation scenarios.
	ActorToken string

	// ActorTokenType identifies the type of ActorToken.
	ActorTokenType string

	// RequestedTokenType indicates the type of the desired output token.
	// Defaults to TokenTypeAccessToken if empty.
	RequestedTokenType string

	// Resource is the URI of the target service (OPTIONAL, RFC 8693 §2.1).
	Resource string

	// Audience identifies the intended audience (OPTIONAL).
	Audience string

	// Scope is the requested scope (OPTIONAL, space-separated).
	Scope string

	// ClientID and ClientSecret authenticate the requesting client.
	ClientID     string
	ClientSecret string
}

// Response is an RFC 8693 token exchange response.
type Response struct {
	// AccessToken is the exchanged token value.
	AccessToken string `json:"access_token"`

	// IssuedTokenType identifies the type of the issued token (REQUIRED).
	IssuedTokenType string `json:"issued_token_type"`

	// TokenType is the token type (usually "Bearer").
	TokenType string `json:"token_type"`

	// ExpiresIn is the lifetime in seconds of the issued token.
	ExpiresIn int `json:"expires_in,omitempty"`

	// Scope is the scope of the issued token.
	Scope string `json:"scope,omitempty"`

	// RefreshToken may be present for offline access.
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Error represents an RFC 6749 error response returned by the token endpoint.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("token exchange error %q: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("token exchange error %q", e.Code)
}

// Client performs RFC 8693 token exchange against a token endpoint.
type Client struct {
	endpoint   string
	httpClient *http.Client
}

// NewClient creates a token exchange client targeting the given token endpoint URL.
func NewClient(tokenEndpoint string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{endpoint: tokenEndpoint, httpClient: httpClient}
}

// Exchange submits a token exchange request and returns the response.
// The grant_type "urn:ietf:params:oauth:grant-type:token-exchange" is set automatically.
func (c *Client) Exchange(ctx context.Context, req *Request) (*Response, error) {
	if req.SubjectToken == "" {
		return nil, fmt.Errorf("SubjectToken is required")
	}
	if req.SubjectTokenType == "" {
		return nil, fmt.Errorf("SubjectTokenType is required")
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", req.SubjectToken)
	form.Set("subject_token_type", req.SubjectTokenType)

	if req.ActorToken != "" {
		form.Set("actor_token", req.ActorToken)
		tokenType := req.ActorTokenType
		if tokenType == "" {
			tokenType = TokenTypeAccessToken
		}
		form.Set("actor_token_type", tokenType)
	}

	requestedType := req.RequestedTokenType
	if requestedType == "" {
		requestedType = TokenTypeAccessToken
	}
	form.Set("requested_token_type", requestedType)

	if req.Resource != "" {
		form.Set("resource", req.Resource)
	}
	if req.Audience != "" {
		form.Set("audience", req.Audience)
	}
	if req.Scope != "" {
		form.Set("scope", req.Scope)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building exchange request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if req.ClientID != "" {
		httpReq.SetBasicAuth(req.ClientID, req.ClientSecret)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp Error
		if jsonErr := json.NewDecoder(resp.Body).Decode(&errResp); jsonErr == nil && errResp.Code != "" {
			return nil, &errResp
		}
		return nil, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var tokenResp Response
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decoding token exchange response: %w", err)
	}
	return &tokenResp, nil
}

// Validate checks that a Response satisfies the RFC 8693 REQUIRED fields.
func Validate(r *Response) error {
	if r.AccessToken == "" {
		return fmt.Errorf("response missing access_token")
	}
	if r.IssuedTokenType == "" {
		return fmt.Errorf("response missing issued_token_type")
	}
	if r.TokenType == "" {
		return fmt.Errorf("response missing token_type")
	}
	return nil
}
