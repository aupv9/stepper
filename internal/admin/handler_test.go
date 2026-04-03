package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/tenant"
)

func newTestHandler(adminToken string) *Handler {
	registry := tenant.NewRegistry()
	cfg, _ := policy.LoadFromBytes([]byte(`
acr_levels:
  - "bronze"
  - "silver"
policies: []
`))
	engine := policy.New(cfg)
	return New(Config{
		Registry:   registry,
		Engine:     engine,
		AdminToken: adminToken,
	})
}

func TestAdminHandler_NoAuth_Open(t *testing.T) {
	h := newTestHandler("") // no token required

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAdminHandler_Auth_MissingToken(t *testing.T) {
	h := newTestHandler("secret-token")

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAdminHandler_Auth_WrongToken(t *testing.T) {
	h := newTestHandler("secret-token")

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAdminHandler_Auth_CorrectToken(t *testing.T) {
	h := newTestHandler("secret-token")

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestAdminHandler_Auth_BearerCaseSensitive(t *testing.T) {
	h := newTestHandler("tok")

	// "bearer" lowercase should NOT match ("Bearer" is required by checkBearer)
	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("Authorization", "bearer tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for lowercase bearer, got %d", w.Code)
	}
}

func TestAdminHandler_Tenants_Response(t *testing.T) {
	h := newTestHandler("")

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["tenants"]; !ok {
		t.Error("response missing 'tenants' key")
	}
	if _, ok := resp["count"]; !ok {
		t.Error("response missing 'count' key")
	}
}

func TestAdminHandler_PolicySummary(t *testing.T) {
	h := newTestHandler("")

	req := httptest.NewRequest(http.MethodGet, "/policy/summary", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAdminHandler_WrongHTTPMethod(t *testing.T) {
	h := newTestHandler("")

	req := httptest.NewRequest(http.MethodPost, "/tenants", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestAdminHandler_WWWAuthenticateHeader(t *testing.T) {
	h := newTestHandler("secret")

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
}
