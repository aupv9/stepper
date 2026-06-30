// Package fapi implements Financial-grade API (FAPI) 2.0 security profile
// primitives. Currently covers:
//
//   - Pushed Authorization Requests (PAR) — RFC 9126
//   - FAPI 2.0 request validation helpers (DPoP + PAR required, PKCE required,
//     nonce required, response_type restricted to "code")
package fapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// --- PAR (RFC 9126) ---

// PARRequest is an authorization request pushed to the AS before the redirect.
// The client POSTs this to the PAR endpoint and receives a request_uri in return.
type PARRequest struct {
	// ResponseType must be "code" for FAPI 2.0.
	ResponseType string `json:"response_type"`

	// ClientID identifies the requesting client (REQUIRED).
	ClientID string `json:"client_id"`

	// RedirectURI is the callback URL (REQUIRED).
	RedirectURI string `json:"redirect_uri"`

	// Scope is the requested scope (REQUIRED).
	Scope string `json:"scope"`

	// State is an opaque CSRF token (REQUIRED by FAPI 2.0).
	State string `json:"state"`

	// Nonce prevents token replay attacks (REQUIRED by FAPI 2.0).
	Nonce string `json:"nonce"`

	// CodeChallenge is the PKCE code challenge (REQUIRED by FAPI 2.0).
	CodeChallenge string `json:"code_challenge"`

	// CodeChallengeMethod must be "S256" for FAPI 2.0.
	CodeChallengeMethod string `json:"code_challenge_method"`

	// Resource is the resource indicator (RFC 8707, OPTIONAL).
	Resource string `json:"resource,omitempty"`

	// AuthorizationDetails is a JSON-encoded RFC 9396 authorization_details array (OPTIONAL).
	AuthorizationDetails string `json:"authorization_details,omitempty"`

	// ClientSecret authenticates the client via HTTP Basic Auth.
	ClientSecret string `json:"-"`
}

// PARResponse is the RFC 9126 §2.2 response returned by the PAR endpoint.
type PARResponse struct {
	// RequestURI is the opaque URI the client sends as "request_uri" to the
	// authorization endpoint. Valid only for ExpiresIn seconds.
	RequestURI string `json:"request_uri"`

	// ExpiresIn is the lifetime of the request_uri in seconds.
	ExpiresIn int `json:"expires_in"`
}

// PARError is an RFC 6749 error returned by the PAR endpoint.
type PARError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *PARError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("PAR error %q: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("PAR error %q", e.Code)
}

// PARClient submits authorization requests to a PAR endpoint.
type PARClient struct {
	endpoint   string
	httpClient *http.Client
}

// NewPARClient creates a PAR client targeting the given PAR endpoint URL.
func NewPARClient(parEndpoint string, httpClient *http.Client) *PARClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &PARClient{endpoint: parEndpoint, httpClient: httpClient}
}

// Push sends the authorization request to the PAR endpoint and returns the
// request_uri that the client must then use with the authorization endpoint.
func (c *PARClient) Push(ctx context.Context, req *PARRequest) (*PARResponse, error) {
	if err := validatePARRequest(req); err != nil {
		return nil, err
	}

	form := buildPARForm(req)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building PAR request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if req.ClientID != "" {
		httpReq.SetBasicAuth(req.ClientID, req.ClientSecret)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("PAR request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var parErr PARError
		if jsonErr := json.NewDecoder(resp.Body).Decode(&parErr); jsonErr == nil && parErr.Code != "" {
			return nil, &parErr
		}
		return nil, fmt.Errorf("PAR endpoint returned %d", resp.StatusCode)
	}

	var parResp PARResponse
	if err := json.NewDecoder(resp.Body).Decode(&parResp); err != nil {
		return nil, fmt.Errorf("decoding PAR response: %w", err)
	}
	if parResp.RequestURI == "" {
		return nil, fmt.Errorf("PAR response missing request_uri")
	}
	return &parResp, nil
}

// AuthorizationURL builds the authorization endpoint URL using the request_uri
// returned from Push(). The client_id is included per RFC 9126 §2.3.
func AuthorizationURL(authEndpoint, clientID, requestURI string) (string, error) {
	u, err := url.Parse(authEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid authorization endpoint: %w", err)
	}
	q := u.Query()
	q.Set("client_id", clientID)
	q.Set("request_uri", requestURI)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// validatePARRequest checks FAPI 2.0 mandatory fields.
func validatePARRequest(req *PARRequest) error {
	if req.ClientID == "" {
		return fmt.Errorf("FAPI 2.0: client_id is required")
	}
	if req.RedirectURI == "" {
		return fmt.Errorf("FAPI 2.0: redirect_uri is required")
	}
	if req.ResponseType != "code" {
		return fmt.Errorf("FAPI 2.0: response_type must be 'code', got %q", req.ResponseType)
	}
	if req.Nonce == "" {
		return fmt.Errorf("FAPI 2.0: nonce is required")
	}
	if req.State == "" {
		return fmt.Errorf("FAPI 2.0: state is required")
	}
	if req.CodeChallenge == "" {
		return fmt.Errorf("FAPI 2.0: PKCE code_challenge is required")
	}
	if req.CodeChallengeMethod != "S256" {
		return fmt.Errorf("FAPI 2.0: code_challenge_method must be 'S256', got %q", req.CodeChallengeMethod)
	}
	return nil
}

func buildPARForm(req *PARRequest) url.Values {
	form := url.Values{}
	form.Set("response_type", req.ResponseType)
	form.Set("client_id", req.ClientID)
	form.Set("redirect_uri", req.RedirectURI)
	form.Set("scope", req.Scope)
	form.Set("state", req.State)
	form.Set("nonce", req.Nonce)
	form.Set("code_challenge", req.CodeChallenge)
	form.Set("code_challenge_method", req.CodeChallengeMethod)
	if req.Resource != "" {
		form.Set("resource", req.Resource)
	}
	if req.AuthorizationDetails != "" {
		form.Set("authorization_details", req.AuthorizationDetails)
	}
	return form
}

// --- FAPI 2.0 request validation (Resource Server side) ---

// ValidationConfig holds FAPI 2.0 enforcement settings.
type ValidationConfig struct {
	// RequireDPoP enforces RFC 9449 DPoP proof-of-possession on every request.
	RequireDPoP bool

	// RequireRequestURI enforces that the authorization was initiated via PAR
	// (the token's "aud" or claims must carry proof of PAR usage).
	// When true, tokens not associated with a PAR request are rejected.
	// Note: this requires the AS to embed a "par" or "request_uri" claim.
	RequireRequestURI bool

	// AllowedResponseTypes restricts the response_type values accepted.
	// FAPI 2.0 mandates only "code".
	AllowedResponseTypes []string
}

// DefaultFAPI2Config returns ValidationConfig with FAPI 2.0 Security Profile defaults.
func DefaultFAPI2Config() ValidationConfig {
	return ValidationConfig{
		RequireDPoP:          true,
		RequireRequestURI:    true,
		AllowedResponseTypes: []string{"code"},
	}
}

// ValidateResponseType checks that the response_type is allowed by FAPI 2.0.
func ValidateResponseType(responseType string, cfg ValidationConfig) error {
	allowed := cfg.AllowedResponseTypes
	if len(allowed) == 0 {
		allowed = []string{"code"}
	}
	for _, a := range allowed {
		if strings.EqualFold(responseType, a) {
			return nil
		}
	}
	return fmt.Errorf("FAPI 2.0: response_type %q not allowed; permitted: %s",
		responseType, strings.Join(allowed, ", "))
}
