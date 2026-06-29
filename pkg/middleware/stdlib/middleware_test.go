package stdlib_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/devkit/localas"
	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
	"github.com/common-iam/iam/pkg/middleware/stdlib"
	"github.com/common-iam/iam/pkg/providers/generic"
)

// setupAS starts a LocalAS and returns a configured provider + stop func.
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

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestStdlibMiddleware_ValidToken_Passes(t *testing.T) {
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

	mw := stdlib.Middleware(stdlib.Config{Provider: provider})
	srv := httptest.NewServer(mw(okHandler()))
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

func TestStdlibMiddleware_MissingToken_Returns401(t *testing.T) {
	_, provider := setupAS(t)

	mw := stdlib.Middleware(stdlib.Config{Provider: provider})
	srv := httptest.NewServer(mw(okHandler()))
	defer srv.Close()

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

func TestStdlibMiddleware_PolicyDenial_StepUpChallenge(t *testing.T) {
	as, provider := setupAS(t)

	// Issue bronze token but policy requires silver.
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
				Name:       "need-silver",
				Resources:  []string{"/secure/**"},
				RequireACR: "urn:mace:incommon:iap:silver",
				Enabled:    true,
			},
		},
	}
	engine := policy.New(pCfg)

	mw := stdlib.Middleware(stdlib.Config{Provider: provider, PolicyEngine: engine, Realm: "TestRealm"})
	srv := httptest.NewServer(mw(okHandler()))
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
	if !contains(wwwAuth, "insufficient_user_authentication") {
		t.Errorf("WWW-Authenticate missing RFC 9470 error: %s", wwwAuth)
	}
	if !contains(wwwAuth, "urn:mace:incommon:iap:silver") {
		t.Errorf("WWW-Authenticate missing required acr_values: %s", wwwAuth)
	}
}

func TestStdlibMiddleware_ClaimsInContext(t *testing.T) {
	as, provider := setupAS(t)

	raw, _ := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "carol",
		ACR:       "urn:mace:incommon:iap:silver",
		Scopes:    []string{"openid", "profile"},
		ExpiresIn: time.Hour,
	})

	var gotClaims *token.CommonClaims
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		c, ok := stdlib.ClaimsFromContext(r.Context())
		if !ok {
			return
		}
		gotClaims = c
	})

	mw := stdlib.Middleware(stdlib.Config{Provider: provider})
	srv := httptest.NewServer(mw(inner))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	http.DefaultClient.Do(req) //nolint:errcheck

	if gotClaims == nil {
		t.Fatal("claims not injected into context")
	}
	if gotClaims.Subject != "carol" {
		t.Errorf("expected subject=carol, got %s", gotClaims.Subject)
	}
}

func contains(s, sub string) bool {
	return len(s) > 0 && len(sub) > 0 && (s == sub || len(s) >= len(sub) &&
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
