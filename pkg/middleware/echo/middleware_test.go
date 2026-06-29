package echo_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	echofwk "github.com/labstack/echo/v4"

	"github.com/common-iam/iam/pkg/core/policy"
	iamecho "github.com/common-iam/iam/pkg/middleware/echo"
	"github.com/common-iam/iam/pkg/devkit/localas"
	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
	"github.com/common-iam/iam/pkg/providers/generic"
)

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

func newEcho(mw echofwk.MiddlewareFunc) *echofwk.Echo {
	e := echofwk.New()
	e.Use(mw)
	e.GET("/resource", func(c echofwk.Context) error { return c.NoContent(http.StatusOK) })
	e.GET("/secure/data", func(c echofwk.Context) error { return c.NoContent(http.StatusOK) })
	return e
}

func TestEchoMiddleware_ValidToken(t *testing.T) {
	as, provider := setupAS(t)

	raw, _ := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "alice",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	e := newEcho(iamecho.Middleware(iamecho.Config{Provider: provider}))
	srv := httptest.NewServer(e)
	defer srv.Close()

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

func TestEchoMiddleware_MissingToken(t *testing.T) {
	_, provider := setupAS(t)

	e := newEcho(iamecho.Middleware(iamecho.Config{Provider: provider}))
	srv := httptest.NewServer(e)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/resource")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestEchoMiddleware_PolicyDenial_StepUp(t *testing.T) {
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
			{Name: "need-silver", Resources: []string{"/secure/**"}, RequireACR: "urn:mace:incommon:iap:silver", Enabled: true},
		},
	}

	e := newEcho(iamecho.Middleware(iamecho.Config{Provider: provider, PolicyEngine: policy.New(pCfg), Realm: "Test"}))
	srv := httptest.NewServer(e)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/secure/data", nil)
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
		t.Error("missing WWW-Authenticate header")
	}
}

func TestEchoMiddleware_ClaimsInContext(t *testing.T) {
	as, provider := setupAS(t)

	raw, _ := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "carol",
		ACR:       "urn:mace:incommon:iap:silver",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	var gotSubject string
	e := echofwk.New()
	e.Use(iamecho.Middleware(iamecho.Config{Provider: provider}))
	e.GET("/", func(c echofwk.Context) error {
		if claims, ok := iamecho.ClaimsFromContext(c); ok {
			gotSubject = claims.Subject
		}
		return c.NoContent(http.StatusOK)
	})

	srv := httptest.NewServer(e)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	http.DefaultClient.Do(req) //nolint:errcheck

	if gotSubject != "carol" {
		t.Errorf("expected subject=carol, got %q", gotSubject)
	}
}
