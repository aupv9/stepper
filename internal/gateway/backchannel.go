package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"

	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/telemetry"
	"github.com/common-iam/iam/pkg/tenant"
)

// backchannelLogoutEvent is the required member of the logout token's events
// claim (OIDC Back-Channel Logout 1.0 §2.4).
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// logoutTokenClaims is the OIDC Back-Channel Logout 1.0 logout token payload.
type logoutTokenClaims struct {
	jwt.RegisteredClaims

	SID    string                     `json:"sid"`
	Events map[string]json.RawMessage `json:"events"`
	Nonce  string                     `json:"nonce"`
}

// jwksURLProvider matches providers that expose their JWKS endpoint.
type jwksURLProvider interface {
	JWKSURL() string
}

// BackchannelLogoutHandler implements the OIDC Back-Channel Logout 1.0 RP
// endpoint: it validates the logout token against the issuing tenant's JWKS
// and evicts every cached token for the logged-out session (sid) or subject.
type BackchannelLogoutHandler struct {
	registry *tenant.Registry
	cache    token.Cache
	audit    *telemetry.AuditLogger

	mu         sync.Mutex
	validators map[string]*token.JWTValidator // issuer → validator
}

// NewBackchannelLogoutHandler creates the /webhook/backchannel-logout handler.
func NewBackchannelLogoutHandler(registry *tenant.Registry, cache token.Cache, audit *telemetry.AuditLogger) *BackchannelLogoutHandler {
	return &BackchannelLogoutHandler{
		registry:   registry,
		cache:      cache,
		audit:      audit,
		validators: make(map[string]*token.JWTValidator),
	}
}

// ServeHTTP handles POST logout_token=<jwt> (application/x-www-form-urlencoded,
// per OIDC Back-Channel Logout 1.0 §2.5).
func (h *BackchannelLogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeLogoutError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeLogoutError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	raw := r.PostFormValue("logout_token")
	if raw == "" {
		writeLogoutError(w, http.StatusBadRequest, "invalid_request", "missing logout_token")
		return
	}

	claims, err := h.validate(r, raw)
	if err != nil {
		// §2.8: error responses use the OAuth error format.
		writeLogoutError(w, http.StatusBadRequest, "invalid_request", "invalid logout token: "+err.Error())
		return
	}

	// Evict cached tokens: by session when sid is present, else by subject.
	ctx := r.Context()
	if claims.SID != "" {
		_ = token.RevokeBySession(ctx, h.cache, claims.SID)
	}
	if claims.Subject != "" && claims.SID == "" {
		_ = token.RevokeBySubject(ctx, h.cache, claims.Subject)
	}

	if h.audit != nil {
		h.audit.Emit(ctx, &telemetry.AuditEvent{
			Type:    telemetry.AuditBackchannelLogout,
			Subject: claims.Subject,
			Reason:  "sid=" + claims.SID,
			Allowed: true,
		})
	}

	w.WriteHeader(http.StatusOK) // §2.7: 200 on success
}

// validate verifies the logout token per OIDC Back-Channel Logout 1.0 §2.6.
func (h *BackchannelLogoutHandler) validate(r *http.Request, raw string) (*logoutTokenClaims, error) {
	iss, err := peekIssuer(raw)
	if err != nil {
		return nil, err
	}

	validator, err := h.validatorForIssuer(iss)
	if err != nil {
		return nil, err
	}

	claims := &logoutTokenClaims{}
	if err := validator.ParseWithClaims(r.Context(), raw, claims); err != nil {
		return nil, err
	}

	// §2.6 checks beyond the signature:
	eventValue, ok := claims.Events[backchannelLogoutEvent]
	if !ok {
		return nil, fmt.Errorf("events claim missing %s", backchannelLogoutEvent)
	}
	if !isEmptyJSONObject(eventValue) {
		return nil, fmt.Errorf("events[%s] value must be an empty JSON object", backchannelLogoutEvent)
	}
	if claims.Nonce != "" {
		return nil, fmt.Errorf("logout token must not contain a nonce claim")
	}
	if claims.Subject == "" && claims.SID == "" {
		return nil, fmt.Errorf("logout token must contain sub or sid")
	}
	return claims, nil
}

// isEmptyJSONObject reports whether raw is `{}` (whitespace tolerated).
func isEmptyJSONObject(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	return len(m) == 0
}

func writeLogoutError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// validatorForIssuer finds the registered tenant whose provider issued the
// token and returns (building lazily) a JWKS validator pinned to that issuer.
func (h *BackchannelLogoutHandler) validatorForIssuer(iss string) (*token.JWTValidator, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if v, ok := h.validators[iss]; ok {
		return v, nil
	}

	for _, id := range h.registry.List() {
		p, err := h.registry.Get(id)
		if err != nil || p.Issuer() != iss {
			continue
		}
		jp, ok := p.(jwksURLProvider)
		if !ok || jp.JWKSURL() == "" {
			return nil, fmt.Errorf("provider for issuer %q exposes no JWKS URL", iss)
		}
		// §2.6 step 3: aud must be validated like an ID Token's — it must
		// contain this RP's client_id. Enforced whenever the provider knows
		// its client ID (dev setups without one skip the check).
		expectedAud := ""
		if cp, ok := p.(interface{ ClientID() string }); ok {
			expectedAud = cp.ClientID()
		}
		v := token.NewJWTValidator(token.JWTValidatorConfig{
			JWKSURL:          jp.JWKSURL(),
			ExpectedIssuer:   iss,
			ExpectedAudience: expectedAud,
		})
		h.validators[iss] = v
		return v, nil
	}
	return nil, fmt.Errorf("no registered tenant for issuer %q", iss)
}

// peekIssuer extracts iss from an unverified JWT payload — used only to pick
// the right JWKS; every security decision happens after signature validation.
func peekIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("not a JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding payload: %w", err)
	}
	var p struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return "", fmt.Errorf("parsing payload: %w", err)
	}
	if p.Iss == "" {
		return "", fmt.Errorf("logout token has no iss")
	}
	return p.Iss, nil
}
