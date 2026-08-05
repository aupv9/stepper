package gateway_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/common-iam/iam/internal/gateway"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/tenant"
)

// exchangeStubProvider is a stubProvider that also exposes a token endpoint.
type exchangeStubProvider struct {
	stubProvider
	tokenEndpoint string
}

func (s *exchangeStubProvider) TokenEndpoint() string { return s.tokenEndpoint }

func TestExchangeHandler(t *testing.T) {
	// Fake AS token endpoint implementing the RFC 8693 grant.
	asEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if got := r.PostFormValue("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":      "exchanged-token",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        300,
		})
	}))
	t.Cleanup(asEndpoint.Close)

	newHandler := func(scopes []string) *gateway.ExchangeHandler {
		provider := &exchangeStubProvider{
			stubProvider: stubProvider{
				issuer: "https://as.example",
				claims: &token.CommonClaims{
					Active:    true,
					Subject:   "alice",
					Issuer:    "https://as.example",
					Scopes:    scopes,
					ExpiresAt: time.Now().Add(time.Hour),
				},
			},
			tokenEndpoint: asEndpoint.URL,
		}
		reg := tenant.NewRegistry()
		reg.Register("default", provider)
		return gateway.NewExchangeHandler(gateway.ExchangeConfig{
			Registry:    reg,
			Resolver:    tenant.NewStaticResolver("default"),
			Credentials: map[string]gateway.ExchangeCredentials{"default": {ClientID: "gw", ClientSecret: "s"}},
		})
	}

	post := func(h *gateway.ExchangeHandler, form url.Values, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/token/exchange", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	t.Run("happy path", func(t *testing.T) {
		h := newHandler([]string{"openid", gateway.RequiredExchangeScope})
		rr := post(h, url.Values{
			"subject_token":      {"caller-token"},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"audience":           {"downstream-api"},
		}, "caller-token")
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || resp.AccessToken != "exchanged-token" {
			t.Errorf("response = %s", rr.Body.String())
		}
	})

	t.Run("missing subject_token rejected", func(t *testing.T) {
		h := newHandler([]string{gateway.RequiredExchangeScope})
		rr := post(h, url.Values{"audience": {"downstream-api"}}, "caller-token")
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing subject_token (RFC 8693 §2.1 REQUIRED), got %d", rr.Code)
		}
	})

	t.Run("missing scope forbidden", func(t *testing.T) {
		h := newHandler([]string{"openid"})
		rr := post(h, url.Values{}, "caller-token")
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 without %s scope, got %d", gateway.RequiredExchangeScope, rr.Code)
		}
	})

	t.Run("no bearer unauthorized", func(t *testing.T) {
		h := newHandler([]string{gateway.RequiredExchangeScope})
		rr := post(h, url.Values{}, "")
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("GET not allowed", func(t *testing.T) {
		h := newHandler([]string{gateway.RequiredExchangeScope})
		req := httptest.NewRequest(http.MethodGet, "/token/exchange", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}
