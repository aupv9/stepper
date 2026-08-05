package gateway

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/core/tokenexchange"
	"github.com/common-iam/iam/pkg/telemetry"
	"github.com/common-iam/iam/pkg/tenant"
)

// RequiredExchangeScope gates access to the token exchange endpoint.
const RequiredExchangeScope = "token:exchange"

// TokenEndpointProvider is a Provider that exposes its AS token endpoint.
// generic, keycloak, and auth0 adapters (and localjwt wrappers around them)
// satisfy it after RefreshConfig.
type TokenEndpointProvider interface {
	TokenEndpoint() string
}

// ExchangeCredentials are the client credentials the gateway uses against a
// tenant's token endpoint when brokering an RFC 8693 exchange.
type ExchangeCredentials struct {
	ClientID     string
	ClientSecret string
}

// ExchangeConfig wires the RFC 8693 token exchange endpoint.
type ExchangeConfig struct {
	Registry *tenant.Registry
	Resolver tenant.Resolver

	// Credentials maps tenant ID → client credentials for that tenant's AS.
	Credentials map[string]ExchangeCredentials

	Audit *telemetry.AuditLogger
}

// ExchangeHandler brokers RFC 8693 token exchange: the caller authenticates
// with a bearer token carrying the token:exchange scope, and the gateway
// forwards the exchange request to the resolved tenant's token endpoint.
type ExchangeHandler struct {
	cfg ExchangeConfig
}

// NewExchangeHandler creates the /token/exchange handler.
func NewExchangeHandler(cfg ExchangeConfig) *ExchangeHandler {
	return &ExchangeHandler{cfg: cfg}
}

func (h *ExchangeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID, err := h.cfg.Resolver.Resolve(r)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_request", "tenant resolution failed")
		return
	}
	provider, err := h.cfg.Registry.Get(tenantID)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_request", "unknown tenant")
		return
	}

	// Authenticate the caller and gate on the exchange scope.
	rawToken, err := token.ExtractBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "missing bearer token")
		return
	}
	claims, err := provider.Introspect(r.Context(), rawToken)
	if err != nil || !claims.Active {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "token inactive or validation failed")
		return
	}
	if !claims.HasScope(RequiredExchangeScope) {
		writeOAuthError(w, http.StatusForbidden, "insufficient_scope",
			"token exchange requires scope "+RequiredExchangeScope)
		return
	}

	// Locate the tenant's token endpoint and gateway credentials.
	tep, ok := provider.(TokenEndpointProvider)
	if !ok || tep.TokenEndpoint() == "" {
		writeOAuthError(w, http.StatusNotImplemented, "unsupported_grant_type",
			"tenant provider exposes no token endpoint")
		return
	}
	creds := h.cfg.Credentials[tenantID]

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	// RFC 8693 §2.1: subject_token and subject_token_type are REQUIRED.
	subjectToken := r.PostFormValue("subject_token")
	subjectTokenType := r.PostFormValue("subject_token_type")
	if subjectToken == "" || subjectTokenType == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"subject_token and subject_token_type are required")
		return
	}

	client := tokenexchange.NewClient(tep.TokenEndpoint(), nil)
	resp, err := client.Exchange(r.Context(), &tokenexchange.Request{
		SubjectToken:       subjectToken,
		SubjectTokenType:   subjectTokenType,
		ActorToken:         r.PostFormValue("actor_token"),
		ActorTokenType:     r.PostFormValue("actor_token_type"),
		RequestedTokenType: r.PostFormValue("requested_token_type"),
		Resource:           r.PostFormValue("resource"),
		Audience:           r.PostFormValue("audience"),
		Scope:              r.PostFormValue("scope"),
		ClientID:           creds.ClientID,
		ClientSecret:       creds.ClientSecret,
	})

	if h.cfg.Audit != nil {
		h.cfg.Audit.Emit(r.Context(), &telemetry.AuditEvent{
			Type:     telemetry.AuditTokenExchanged,
			Subject:  claims.Subject,
			TenantID: tenantID,
			Resource: r.PostFormValue("audience"),
			Method:   r.Method,
			Allowed:  err == nil,
			Reason:   errString(err),
		})
	}

	if err != nil {
		var oauthErr *tokenexchange.Error
		if errors.As(err, &oauthErr) {
			writeOAuthError(w, http.StatusBadRequest, oauthErr.Code, oauthErr.Description)
			return
		}
		writeOAuthError(w, http.StatusBadGateway, "server_error", "exchange with authorization server failed")
		return
	}

	// RFC 8693 §2.2.1: never relay a response missing REQUIRED fields.
	if err := tokenexchange.Validate(resp); err != nil {
		writeOAuthError(w, http.StatusBadGateway, "server_error",
			"authorization server returned an invalid exchange response: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
