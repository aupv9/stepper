// Package integration_test contains end-to-end tests for the full IAM service stack.
// Each test wires the same components as cmd/iam-service/main.go (LocalAS, policy
// engine, in-memory cache, guard, admin handler, router) but uses httptest.Server
// instead of a real TCP listener.
package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/common-iam/iam/internal/admin"
	"github.com/common-iam/iam/internal/gateway"
	"github.com/common-iam/iam/internal/server"
	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/devkit/localas"
	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
	"github.com/common-iam/iam/pkg/providers/generic"
	"github.com/common-iam/iam/pkg/tenant"
)

// e2eEnv is the full-stack test harness.
type e2eEnv struct {
	srv      *httptest.Server
	as       *localas.Server
	provider *generic.Adapter
	cache    *token.MemoryCache
	guard    *gateway.Guard
}

// allowAllEngine returns a policy engine that matches every resource with no
// requirements — effectively a pass-through for any authenticated request.
// Used when a test needs auth (token validation) but no ACR/scope policy.
func allowAllEngine() *policy.Engine {
	return policy.New(&policy.Config{
		Policies: []policy.Policy{
			{Name: "allow-all", Resources: []string{"/**"}, Enabled: true},
		},
	})
}

// newE2EEnv wires the full service stack. pCfg may be nil (allow-all policy).
// adminToken may be empty (admin API unauthenticated). cookieSecret may be empty.
// The guard and admin handler share the same *policy.Engine so admin hot-reload
// takes effect on the guard immediately.
func newE2EEnv(t *testing.T, pCfg *policy.Config, adminToken, cookieSecret string) *e2eEnv {
	t.Helper()

	as, err := localas.New()
	if err != nil {
		t.Fatalf("localas.New: %v", err)
	}
	baseURL, err := as.Start()
	if err != nil {
		t.Fatalf("localas.Start: %v", err)
	}

	provider := generic.New(generic.Config{
		DiscoveryURL: baseURL + "/.well-known/openid-configuration",
	})
	if err := provider.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("provider.RefreshConfig: %v", err)
	}

	reg := tenant.NewRegistry()
	reg.Register("default", provider)

	cache := token.NewMemoryCache()

	// Shared engine between guard and admin so hot-reload takes effect immediately.
	var eng *policy.Engine
	if pCfg != nil {
		eng = policy.New(pCfg)
	} else {
		eng = allowAllEngine()
	}

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	guard := gateway.NewGuard(gateway.GuardConfig{
		Registry:     reg,
		Resolver:     tenant.NewChainResolver(tenant.NewHeaderResolver("X-Tenant-ID")),
		PolicyEngine: eng,
		Realm:        "Test",
		Cache:        cache,
		Upstream:     upstream,
		CookieSecret: cookieSecret,
	})

	adminHandler := admin.New(admin.Config{
		Registry:   reg,
		Engine:     eng,
		AdminToken: adminToken,
	})

	router := server.NewRouter(server.RouterConfig{
		Gateway:      guard,
		AdminHandler: adminHandler,
	})

	srv := httptest.NewServer(router)
	t.Cleanup(func() {
		srv.Close()
		as.Stop(context.Background()) //nolint:errcheck
	})

	return &e2eEnv{srv: srv, as: as, provider: provider, cache: cache, guard: guard}
}

// --- Infra endpoints ---

func TestE2E_HealthEndpoint(t *testing.T) {
	env := newE2EEnv(t, nil, "", "")

	resp, err := http.Get(env.srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestE2E_MetricsEndpoint(t *testing.T) {
	env := newE2EEnv(t, nil, "", "")

	resp, err := http.Get(env.srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("metrics should return text/plain, got %q", ct)
	}
}

// --- Auth flows ---

// TestE2E_StepUpFlow exercises the full RFC 9470 step-up sequence:
// bronze token → 401 challenge → silver token → 200.
func TestE2E_StepUpFlow(t *testing.T) {
	pCfg := &policy.Config{
		ACRLevels: []string{"urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"},
		Policies: []policy.Policy{
			{
				Name:       "need-silver",
				Resources:  []string{"/api/**"},
				RequireACR: "urn:mace:incommon:iap:silver",
				Enabled:    true,
			},
		},
	}
	env := newE2EEnv(t, pCfg, "", "step-cookie-secret")

	// Step 1: Bronze token → policy denial → RFC 9470 challenge.
	bronze, _ := env.as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "alice",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	req1, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/api/data", nil)
	req1.Header.Set("Authorization", "Bearer "+bronze)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("step 1: expected 401, got %d", resp1.StatusCode)
	}

	wwwAuth := resp1.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "insufficient_user_authentication") {
		t.Errorf("step 1: WWW-Authenticate missing RFC 9470 error: %s", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "acr_values") {
		t.Errorf("step 1: WWW-Authenticate missing acr_values: %s", wwwAuth)
	}

	// Step 2: Client obtains a silver token and retries.
	silver, _ := env.as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "alice",
		ACR:       "urn:mace:incommon:iap:silver",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	req2, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/api/data", nil)
	req2.Header.Set("Authorization", "Bearer "+silver)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("step 2: expected 200 with silver token, got %d", resp2.StatusCode)
	}
}

// TestE2E_RevocationFlow exercises the full token revocation path:
// issue → cache → revoke at AS → webhook clears cache → 401.
func TestE2E_RevocationFlow(t *testing.T) {
	env := newE2EEnv(t, nil, "", "")

	raw, _ := env.as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "bob",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	// First request: token cached.
	req1, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/resource", nil)
	req1.Header.Set("Authorization", "Bearer "+raw)
	resp1, _ := http.DefaultClient.Do(req1)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("initial request: expected 200, got %d", resp1.StatusCode)
	}

	// Revoke at the AS so introspection returns active:false.
	revokeResp, err := http.Post(
		env.provider.Issuer()+"/revoke",
		"application/x-www-form-urlencoded",
		strings.NewReader("token="+raw),
	)
	if err != nil {
		t.Fatalf("AS revoke: %v", err)
	}
	revokeResp.Body.Close()

	// Send the revocation webhook so the guard's cache is invalidated.
	event := token.RevocationEvent{TokenHash: token.HashToken(raw)}
	body, _ := json.Marshal(event)
	webhookReq, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/webhook/revoke", bytes.NewReader(body))
	webhookReq.Header.Set("Content-Type", "application/json")
	webhookResp, err := http.DefaultClient.Do(webhookReq)
	if err != nil {
		t.Fatalf("webhook request: %v", err)
	}
	if webhookResp.StatusCode != http.StatusNoContent {
		t.Fatalf("webhook: expected 204, got %d", webhookResp.StatusCode)
	}

	// Third request: cache miss → introspect → inactive → 401.
	req2, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/resource", nil)
	req2.Header.Set("Authorization", "Bearer "+raw)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("after revocation: expected 401, got %d", resp2.StatusCode)
	}
}

// TestE2E_MultiTenantIsolation verifies that a token from one tenant's AS is
// rejected when routed to a different tenant.
func TestE2E_MultiTenantIsolation(t *testing.T) {
	// Set up two independent Authorization Servers.
	as1, err := localas.New()
	if err != nil {
		t.Fatalf("localas.New (acme): %v", err)
	}
	baseURL1, _ := as1.Start()
	t.Cleanup(func() { as1.Stop(context.Background()) }) //nolint:errcheck

	as2, err := localas.New()
	if err != nil {
		t.Fatalf("localas.New (bravo): %v", err)
	}
	baseURL2, _ := as2.Start()
	t.Cleanup(func() { as2.Stop(context.Background()) }) //nolint:errcheck

	provider1 := generic.New(generic.Config{DiscoveryURL: baseURL1 + "/.well-known/openid-configuration"})
	provider2 := generic.New(generic.Config{DiscoveryURL: baseURL2 + "/.well-known/openid-configuration"})
	if err := provider1.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("provider1 discovery: %v", err)
	}
	if err := provider2.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("provider2 discovery: %v", err)
	}

	reg := tenant.NewRegistry()
	reg.Register("acme", provider1)
	reg.Register("bravo", provider2)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	eng := allowAllEngine()
	guard := gateway.NewGuard(gateway.GuardConfig{
		Registry:     reg,
		Resolver:     tenant.NewChainResolver(tenant.NewHeaderResolver("X-Tenant-ID")),
		Realm:        "Test",
		Upstream:     upstream,
		PolicyEngine: eng,
	})
	router := server.NewRouter(server.RouterConfig{
		Gateway:      guard,
		AdminHandler: admin.New(admin.Config{Registry: reg, Engine: eng}),
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// Issue a token from the "acme" AS.
	raw, _ := as1.IssueToken(tokenfactory.TokenOptions{
		Subject: "carol", ACR: "urn:mace:incommon:iap:bronze",
		Scopes: []string{"openid"}, ExpiresIn: time.Hour,
	})

	// Correct tenant → 200.
	reqOK, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	reqOK.Header.Set("Authorization", "Bearer "+raw)
	reqOK.Header.Set("X-Tenant-ID", "acme")
	respOK, _ := http.DefaultClient.Do(reqOK)
	if respOK.StatusCode != http.StatusOK {
		t.Errorf("acme token vs acme tenant: expected 200, got %d", respOK.StatusCode)
	}

	// Wrong tenant: "bravo"'s AS doesn't know this token → inactive → 401.
	reqBad, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	reqBad.Header.Set("Authorization", "Bearer "+raw)
	reqBad.Header.Set("X-Tenant-ID", "bravo")
	respBad, _ := http.DefaultClient.Do(reqBad)
	if respBad.StatusCode != http.StatusUnauthorized {
		t.Errorf("acme token vs bravo tenant: expected 401, got %d", respBad.StatusCode)
	}
}

// --- Admin API ---

func TestE2E_AdminAPI_Unauthorized(t *testing.T) {
	env := newE2EEnv(t, nil, "super-secret-admin-token", "")

	// No Authorization header.
	resp, err := http.Get(env.srv.URL + "/admin/tenants")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without admin token, got %d", resp.StatusCode)
	}
}

func TestE2E_AdminAPI_ListTenants(t *testing.T) {
	const adminToken = "super-secret-admin-token"
	env := newE2EEnv(t, nil, adminToken, "")

	req, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/admin/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with admin token, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
	if _, ok := body["tenants"]; !ok {
		t.Error("response missing 'tenants' field")
	}
}

// TestE2E_AdminAPI_PolicyReload verifies that a new policy YAML can be
// uploaded via the admin API and takes effect on subsequent requests.
func TestE2E_AdminAPI_PolicyReload(t *testing.T) {
	const adminToken = "reload-token"

	// Start with no policy (allow all).
	env := newE2EEnv(t, nil, adminToken, "")

	raw, _ := env.as.IssueToken(tokenfactory.TokenOptions{
		Subject: "dave", ACR: "urn:mace:incommon:iap:bronze",
		Scopes: []string{"openid"}, ExpiresIn: time.Hour,
	})

	// Before reload: request passes.
	req1, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/api/data", nil)
	req1.Header.Set("Authorization", "Bearer "+raw)
	resp1, _ := http.DefaultClient.Do(req1)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("before reload: expected 200, got %d", resp1.StatusCode)
	}

	// Reload policy that now requires silver for /api/**.
	newYAML := `
acr_levels:
  - urn:mace:incommon:iap:bronze
  - urn:mace:incommon:iap:silver
policies:
  - name: need-silver
    resources: ["/api/**"]
    require_acr: urn:mace:incommon:iap:silver
    enabled: true
`
	reloadBody, _ := json.Marshal(map[string]string{"yaml": newYAML})
	reloadReq, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/admin/policy/reload", bytes.NewReader(reloadBody))
	reloadReq.Header.Set("Authorization", "Bearer "+adminToken)
	reloadReq.Header.Set("Content-Type", "application/json")
	reloadResp, err := http.DefaultClient.Do(reloadReq)
	if err != nil {
		t.Fatalf("policy reload: %v", err)
	}
	if reloadResp.StatusCode != http.StatusOK {
		t.Fatalf("policy reload: expected 200, got %d", reloadResp.StatusCode)
	}

	// After reload: same token now denied.
	req2, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/api/data", nil)
	req2.Header.Set("Authorization", "Bearer "+raw)
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("after reload: expected 401, got %d", resp2.StatusCode)
	}
}
