package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/common-iam/iam/internal/gateway"
	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/devkit/localas"
	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
	"github.com/common-iam/iam/pkg/providers/generic"
	"github.com/common-iam/iam/pkg/tenant"
)

// setupAS starts a LocalAS, waits for it to serve the discovery doc, and returns
// the server plus a configured generic.Adapter.
func setupAS(t *testing.T) (*localas.Server, *generic.Adapter) {
	t.Helper()
	as, err := localas.New()
	if err != nil {
		t.Fatalf("localas.New: %v", err)
	}
	baseURL, err := as.Start()
	if err != nil {
		t.Fatalf("localas.Start: %v", err)
	}
	t.Cleanup(func() { as.Stop(context.Background()) }) //nolint:errcheck

	provider := generic.New(generic.Config{
		DiscoveryURL: baseURL + "/.well-known/openid-configuration",
	})
	if err := provider.RefreshConfig(context.Background()); err != nil {
		t.Fatalf("provider.RefreshConfig: %v", err)
	}
	return as, provider
}

// buildGuard constructs a Guard and wraps it in an httptest.Server.
// cfg.Registry defaults to a single "default" tenant backed by provider.
// cfg.Resolver defaults to X-Tenant-ID header resolver.
// cfg.Upstream defaults to a 200 OK echo handler.
func buildGuard(t *testing.T, provider *generic.Adapter, cfg gateway.GuardConfig) (*gateway.Guard, *httptest.Server) {
	t.Helper()

	if cfg.Registry == nil {
		reg := tenant.NewRegistry()
		reg.Register("default", provider)
		cfg.Registry = reg
	}
	if cfg.Resolver == nil {
		cfg.Resolver = tenant.NewChainResolver(tenant.NewHeaderResolver("X-Tenant-ID"))
	}
	if cfg.Upstream == nil {
		cfg.Upstream = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}
	if cfg.Realm == "" {
		cfg.Realm = "Test"
	}

	guard := gateway.NewGuard(cfg)
	srv := httptest.NewServer(guard)
	t.Cleanup(srv.Close)
	return guard, srv
}

func TestGuard_ValidToken(t *testing.T) {
	as, provider := setupAS(t)

	raw, err := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "alice",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	_, srv := buildGuard(t, provider, gateway.GuardConfig{})

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestGuard_MissingToken_Returns401WithChallenge(t *testing.T) {
	_, provider := setupAS(t)
	_, srv := buildGuard(t, provider, gateway.GuardConfig{})

	resp, err := http.Get(srv.URL + "/resource")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
}

// TestGuard_PolicyDenial_RFC9470Challenge verifies that a token with insufficient ACR
// receives a 401 with a WWW-Authenticate header that satisfies RFC 9470 §3.
func TestGuard_PolicyDenial_RFC9470Challenge(t *testing.T) {
	as, provider := setupAS(t)

	raw, _ := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "bob",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	pCfg := &policy.Config{
		ACRLevels: []string{"urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"},
		Policies: []policy.Policy{
			{
				Name:       "require-silver",
				Resources:  []string{"/api/**"},
				RequireACR: "urn:mace:incommon:iap:silver",
				Enabled:    true,
			},
		},
	}

	_, srv := buildGuard(t, provider, gateway.GuardConfig{PolicyEngine: policy.New(pCfg)})

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/data", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Fatal("missing WWW-Authenticate header")
	}
	if !strings.Contains(wwwAuth, "insufficient_user_authentication") {
		t.Errorf("WWW-Authenticate missing RFC 9470 error=insufficient_user_authentication: %s", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "acr_values") {
		t.Errorf("WWW-Authenticate missing acr_values: %s", wwwAuth)
	}
}

// TestGuard_CacheHit verifies that a second request is served entirely from the
// in-process cache and does not call the AS introspection endpoint.
// We prove this by stopping the AS after the first request — if the second
// request still succeeds, it was served from cache.
func TestGuard_CacheHit(t *testing.T) {
	as, provider := setupAS(t)

	raw, _ := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "carol",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	cache := token.NewMemoryCache()
	_, srv := buildGuard(t, provider, gateway.GuardConfig{Cache: cache})

	// First request: live introspection + cache populate.
	req1, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	req1.Header.Set("Authorization", "Bearer "+raw)
	resp1, _ := http.DefaultClient.Do(req1)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", resp1.StatusCode)
	}

	// Verify cache was populated.
	if _, ok := cache.Get(context.Background(), token.HashToken(raw)); !ok {
		t.Fatal("token not cached after first request")
	}

	// Stop the AS — from here, any introspection call would fail.
	if err := as.Stop(context.Background()); err != nil {
		t.Fatalf("stopping AS: %v", err)
	}

	// Second request must succeed from cache without calling the AS.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	req2.Header.Set("Authorization", "Bearer "+raw)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("second request (cache hit): expected 200, got %d", resp2.StatusCode)
	}
}

// TestGuard_RevocationWebhook_InvalidatesCache verifies the full revocation path:
// token cached → AS revocation → webhook clears cache → next request hits AS → 401.
func TestGuard_RevocationWebhook_InvalidatesCache(t *testing.T) {
	as, provider := setupAS(t)

	raw, _ := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "dave",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	cache := token.NewMemoryCache()
	guard, srv := buildGuard(t, provider, gateway.GuardConfig{Cache: cache})

	// First request: success + token enters cache.
	req1, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	req1.Header.Set("Authorization", "Bearer "+raw)
	resp1, _ := http.DefaultClient.Do(req1)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("initial request: expected 200, got %d", resp1.StatusCode)
	}

	// Revoke the token at the AS so introspection will return active:false.
	asBase := provider.Issuer() // e.g. "http://127.0.0.1:<port>"
	revokeResp, err := http.Post(
		asBase+"/revoke",
		"application/x-www-form-urlencoded",
		strings.NewReader("token="+raw),
	)
	if err != nil {
		t.Fatalf("AS revocation: %v", err)
	}
	revokeResp.Body.Close()

	// Send the revocation webhook so the guard's cache is also cleared.
	event := token.RevocationEvent{TokenHash: token.HashToken(raw)}
	eventBody, _ := json.Marshal(event)
	webhookReq := httptest.NewRequest(http.MethodPost, "/webhook/revoke", bytes.NewReader(eventBody))
	webhookReq.Header.Set("Content-Type", "application/json")
	webhookW := httptest.NewRecorder()
	guard.RevocationHandler().ServeHTTP(webhookW, webhookReq)
	if webhookW.Code != http.StatusNoContent {
		t.Fatalf("revocation webhook: expected 204, got %d: %s", webhookW.Code, webhookW.Body)
	}

	// Third request: cache miss → introspect → AS returns inactive → 401.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	req2.Header.Set("Authorization", "Bearer "+raw)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("after revocation: expected 401, got %d", resp2.StatusCode)
	}
}

// TestGuard_DPoP_MissingProof verifies that when DPoP enforcement is enabled,
// requests without a DPoP proof header are rejected with 401.
func TestGuard_DPoP_MissingProof(t *testing.T) {
	as, provider := setupAS(t)

	raw, _ := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "eve",
		ACR:       "urn:mace:incommon:iap:silver",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	_, srv := buildGuard(t, provider, gateway.GuardConfig{EnableDPoP: true})

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	// No DPoP header set — must be rejected.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 (DPoP required), got %d", resp.StatusCode)
	}
}

// TestGuard_CookieOnStepUpChallenge verifies that when CookieSecret is configured
// a policy denial writes a signed iam_stepup_state cookie onto the response,
// allowing the client to replay the original request after re-authentication.
func TestGuard_CookieOnStepUpChallenge(t *testing.T) {
	as, provider := setupAS(t)

	raw, _ := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "frank",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	pCfg := &policy.Config{
		ACRLevels: []string{"urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"},
		Policies: []policy.Policy{
			{
				Name:       "need-silver",
				Resources:  []string{"/secure/**"},
				RequireACR: "urn:mace:incommon:iap:silver",
				Enabled:    true,
			},
		},
	}

	_, srv := buildGuard(t, provider, gateway.GuardConfig{
		PolicyEngine: policy.New(pCfg),
		CookieSecret: "test-signing-key",
	})

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/secure/profile", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	var stepupCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "iam_stepup_state" {
			stepupCookie = c
			break
		}
	}
	if stepupCookie == nil {
		t.Fatal("expected iam_stepup_state cookie on step-up challenge")
	}
	if stepupCookie.HttpOnly != true {
		t.Error("iam_stepup_state cookie should be HttpOnly")
	}
	// Cookie must contain the signed payload (two dot-separated parts).
	if !strings.Contains(stepupCookie.Value, ".") {
		t.Errorf("cookie value appears unsigned: %q", stepupCookie.Value)
	}
}

// TestGuard_MultiTenant_TokenIsolation verifies that a token issued by one tenant's AS
// is rejected when presented to a guard routing to a different tenant's AS.
func TestGuard_MultiTenant_TokenIsolation(t *testing.T) {
	as1, provider1 := setupAS(t)
	_, provider2 := setupAS(t)

	// Token issued by tenant "acme"'s AS.
	raw, _ := as1.IssueToken(tokenfactory.TokenOptions{
		Subject:   "mallory",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	reg := tenant.NewRegistry()
	reg.Register("acme", provider1)
	reg.Register("bravo", provider2)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	guard := gateway.NewGuard(gateway.GuardConfig{
		Registry: reg,
		Resolver: tenant.NewChainResolver(tenant.NewHeaderResolver("X-Tenant-ID")),
		Upstream: upstream,
		Realm:    "Test",
	})
	srv := httptest.NewServer(guard)
	t.Cleanup(srv.Close)

	// Correct tenant — should succeed.
	reqOK, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	reqOK.Header.Set("Authorization", "Bearer "+raw)
	reqOK.Header.Set("X-Tenant-ID", "acme")
	respOK, _ := http.DefaultClient.Do(reqOK)
	if respOK.StatusCode != http.StatusOK {
		t.Errorf("acme token vs acme tenant: expected 200, got %d", respOK.StatusCode)
	}

	// Wrong tenant — bravo's AS does not know this token → inactive → 401.
	reqBad, _ := http.NewRequest(http.MethodGet, srv.URL+"/resource", nil)
	reqBad.Header.Set("Authorization", "Bearer "+raw)
	reqBad.Header.Set("X-Tenant-ID", "bravo")
	respBad, _ := http.DefaultClient.Do(reqBad)
	if respBad.StatusCode != http.StatusUnauthorized {
		t.Errorf("acme token vs bravo tenant: expected 401, got %d", respBad.StatusCode)
	}
}

// TestGuard_StepUpCookieReplay verifies that when a client returns to /callback with a
// higher-assurance token and the step-up state cookie, the guard transparently forwards
// the request to the original saved path (/original) instead of /callback.
func TestGuard_StepUpCookieReplay(t *testing.T) {
	as, provider := setupAS(t)

	// Policy: /original requires silver ACR; /callback is open to any valid token
	// (the policy engine denies by default when no policy matches, so /callback
	// needs an explicit allow-with-bronze rule so the silver token passes through).
	pCfg := &policy.Config{
		ACRLevels: []string{"urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"},
		Policies: []policy.Policy{
			{
				Name:       "need-silver-for-original",
				Resources:  []string{"/original"},
				RequireACR: "urn:mace:incommon:iap:silver",
				Enabled:    true,
			},
			{
				// /callback is the re-auth landing path — allow any valid token (bronze+).
				Name:       "allow-callback",
				Resources:  []string{"/callback"},
				RequireACR: "urn:mace:incommon:iap:bronze",
				Enabled:    true,
			},
		},
	}

	// Track which path the upstream next handler received.
	var upstreamPath string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})

	_, srv := buildGuard(t, provider, gateway.GuardConfig{
		PolicyEngine: policy.New(pCfg),
		CookieSecret: "test-replay-secret",
		Upstream:     upstream,
	})

	// Step 1: hit /original with a bronze token → expect 401 + cookie set.
	bronzeToken, err := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "grace",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueToken (bronze): %v", err)
	}

	req1, _ := http.NewRequest(http.MethodGet, srv.URL+"/original", nil)
	req1.Header.Set("Authorization", "Bearer "+bronzeToken)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("first request: expected 401, got %d", resp1.StatusCode)
	}

	// Capture the step-up state cookie.
	var stepupCookie *http.Cookie
	for _, c := range resp1.Cookies() {
		if c.Name == "iam_stepup_state" {
			stepupCookie = c
			break
		}
	}
	if stepupCookie == nil {
		t.Fatal("expected iam_stepup_state cookie on step-up challenge response")
	}

	// Step 2: client obtains a silver token and hits /callback (not /original).
	silverToken, err := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "grace",
		ACR:       "urn:mace:incommon:iap:silver",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueToken (silver): %v", err)
	}

	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/callback", nil)
	req2.Header.Set("Authorization", "Bearer "+silverToken)
	// Attach the step-up state cookie captured from the denial response.
	for _, c := range resp1.Cookies() {
		req2.AddCookie(c)
	}
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}

	// Guard must have let the request through (silver satisfies policy for /original).
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("second request: expected 200, got %d", resp2.StatusCode)
	}

	// The upstream must have seen the original path, not /callback.
	if upstreamPath != "/original" {
		t.Errorf("upstream received path %q, want %q", upstreamPath, "/original")
	}
}
