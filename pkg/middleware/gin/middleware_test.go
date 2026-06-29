package gin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ginfwk "github.com/gin-gonic/gin"

	"github.com/common-iam/iam/pkg/core/policy"
	iamgin "github.com/common-iam/iam/pkg/middleware/gin"
	"github.com/common-iam/iam/pkg/devkit/localas"
	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
	"github.com/common-iam/iam/pkg/providers/generic"
)

func init() { ginfwk.SetMode(ginfwk.TestMode) }

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

func newRouter(mw ginfwk.HandlerFunc) *ginfwk.Engine {
	r := ginfwk.New()
	r.Use(mw)
	r.GET("/resource", func(c *ginfwk.Context) { c.Status(http.StatusOK) })
	r.GET("/secure/data", func(c *ginfwk.Context) { c.Status(http.StatusOK) })
	return r
}

func TestGinMiddleware_ValidToken(t *testing.T) {
	as, provider := setupAS(t)

	raw, _ := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "alice",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	r := newRouter(iamgin.Middleware(iamgin.Config{Provider: provider}))
	srv := httptest.NewServer(r)
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

func TestGinMiddleware_MissingToken(t *testing.T) {
	_, provider := setupAS(t)

	r := newRouter(iamgin.Middleware(iamgin.Config{Provider: provider}))
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/resource")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestGinMiddleware_PolicyDenial(t *testing.T) {
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

	r := newRouter(iamgin.Middleware(iamgin.Config{Provider: provider, PolicyEngine: policy.New(pCfg), Realm: "Test"}))
	srv := httptest.NewServer(r)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/secure/data", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 step-up, got %d", resp.StatusCode)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

func TestGinMiddleware_ClaimsInContext(t *testing.T) {
	as, provider := setupAS(t)

	raw, _ := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "carol",
		ACR:       "urn:mace:incommon:iap:silver",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})

	var gotSubject string
	ginfwk.SetMode(ginfwk.TestMode)
	r := ginfwk.New()
	r.Use(iamgin.Middleware(iamgin.Config{Provider: provider}))
	r.GET("/", func(c *ginfwk.Context) {
		if claims, ok := iamgin.ClaimsFromContext(c); ok {
			gotSubject = claims.Subject
		}
		c.Status(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	http.DefaultClient.Do(req) //nolint:errcheck

	if gotSubject != "carol" {
		t.Errorf("expected subject=carol, got %q", gotSubject)
	}
}
