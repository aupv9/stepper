package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/common-iam/iam/internal/admin"
	"github.com/common-iam/iam/internal/gateway"
	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/tenant"
)

// newTestRouterConfig builds a RouterConfig backed by real Guard and Admin
// handlers, constructed the same way guard_test.go / handler_test.go do.
// The Guard has no provider/registry wired for protected paths, so requests to
// "/" produce an observable 401 with a WWW-Authenticate challenge (the missing
// token path), which is sufficient to prove routing reaches the Guard.
func newTestRouterConfig(t *testing.T) RouterConfig {
	t.Helper()

	// Admin handler with one registered tenant so /tenants returns it.
	adminReg := tenant.NewRegistry()
	adminReg.Register("acme", nil)
	adminCfg, err := policy.LoadFromBytes([]byte(`
acr_levels:
  - "bronze"
  - "silver"
policies: []
`))
	if err != nil {
		t.Fatalf("policy.LoadFromBytes: %v", err)
	}
	adminHandler := admin.New(admin.Config{
		Registry:   adminReg,
		Engine:     policy.New(adminCfg),
		AdminToken: "", // open, so we can hit admin routes without a token
	})

	// Guard with an empty registry and a header resolver. Requests without a
	// token are rejected with 401 + WWW-Authenticate before any tenant lookup.
	guard := gateway.NewGuard(gateway.GuardConfig{
		Registry: tenant.NewRegistry(),
		Resolver: tenant.NewChainResolver(tenant.NewHeaderResolver("X-Tenant-ID")),
		Upstream: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		Realm: "Test",
	})

	return RouterConfig{
		Gateway:      guard,
		AdminHandler: adminHandler,
	}
}

func TestNewRouter_Health(t *testing.T) {
	h := NewRouter(newTestRouterConfig(t))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"status":"ok"}` {
		t.Errorf("unexpected body: %q", got)
	}
}

func TestNewRouter_Metrics(t *testing.T) {
	h := NewRouter(newTestRouterConfig(t))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 from /metrics, got %d", w.Code)
	}
	// Prometheus exposition format always advertises a text content type.
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("expected prometheus text/plain content type, got %q", ct)
	}
}

func TestNewRouter_AdminPrefixStripped(t *testing.T) {
	h := NewRouter(newTestRouterConfig(t))

	// The router mounts the admin handler under "/admin" with the prefix
	// stripped. The admin mux only knows the route "/tenants", so a 200 here
	// proves the "/admin" prefix was stripped before dispatch. Without the
	// strip, the admin mux would see "/admin/tenants" and 404.
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /admin/tenants, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid JSON from admin route: %v", err)
	}
	if _, ok := resp["tenants"]; !ok {
		t.Errorf("admin response missing 'tenants' key: %v", resp)
	}
	if _, ok := resp["count"]; !ok {
		t.Errorf("admin response missing 'count' key: %v", resp)
	}
}

func TestNewRouter_AdminUnknownRoute404(t *testing.T) {
	h := NewRouter(newTestRouterConfig(t))

	// A path under /admin/ that the admin mux does not define should 404 from
	// the admin handler (not be swallowed by the gateway catch-all). This also
	// confirms the prefix strip leaves a leading-slash path for the admin mux.
	req := httptest.NewRequest(http.MethodGet, "/admin/does-not-exist", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 from unknown admin route, got %d", w.Code)
	}
}

func TestNewRouter_WebhookRevoke(t *testing.T) {
	h := NewRouter(newTestRouterConfig(t))

	t.Run("GET returns 405 from revocation handler", func(t *testing.T) {
		// The revocation handler only accepts POST. A 405 (rather than the
		// gateway's 401) proves the request was routed to the revocation
		// handler and not the catch-all guard.
		req := httptest.NewRequest(http.MethodGet, "/webhook/revoke", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 from /webhook/revoke GET, got %d", w.Code)
		}
	})

	t.Run("POST valid event returns 204", func(t *testing.T) {
		event := token.RevocationEvent{TokenHash: token.HashToken("some-token")}
		body, _ := json.Marshal(event)
		req := httptest.NewRequest(http.MethodPost, "/webhook/revoke", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("expected 204 from /webhook/revoke POST, got %d (body: %s)", w.Code, w.Body.String())
		}
	})
}

func TestNewRouter_CatchAllToGateway(t *testing.T) {
	h := NewRouter(newTestRouterConfig(t))

	// An arbitrary path with no Authorization header must reach the gateway
	// guard, which rejects it with 401 + WWW-Authenticate. This status/header
	// pair is unique to the guard among the router's handlers.
	cases := []string{"/anything", "/api/data", "/", "/foo/bar/baz"}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 from gateway for %q, got %d", path, w.Code)
			}
			if w.Header().Get("WWW-Authenticate") == "" {
				t.Errorf("expected WWW-Authenticate header from gateway for %q", path)
			}
		})
	}
}

// TestNewRouter_NilAdminHandler verifies the router is still constructible and
// usable when no AdminHandler is supplied: /admin/* then falls through to the
// gateway catch-all (current behavior), while /health still works.
func TestNewRouter_NilAdminHandler(t *testing.T) {
	cfg := newTestRouterConfig(t)
	cfg.AdminHandler = nil
	h := NewRouter(cfg)

	t.Run("health still served", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("admin path falls through to gateway", func(t *testing.T) {
		// With no admin handler registered, /admin/tenants matches only the
		// "/" catch-all → gateway → 401 (no token).
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 (gateway catch-all) for /admin/tenants with nil admin, got %d", w.Code)
		}
	})
}
