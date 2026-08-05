package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/common-iam/iam/internal/gateway"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
	"github.com/common-iam/iam/pkg/tenant"
)

const bclEvent = "http://schemas.openid.net/event/backchannel-logout"

func TestBackchannelLogout(t *testing.T) {
	as, provider := setupAS(t)
	issuer := provider.Issuer()

	reg := tenant.NewRegistry()
	reg.Register("default", provider)

	ctx := context.Background()
	cache := token.NewMemoryCache()
	handler := gateway.NewBackchannelLogoutHandler(reg, cache, nil)

	// Seed a cached token bound to session sess-42.
	hash := token.HashToken("cached-access-token")
	claims := &token.CommonClaims{Active: true, Subject: "alice", SessionID: "sess-42"}
	_ = cache.Set(ctx, hash, claims, time.Minute)
	token.IndexClaims(ctx, cache, hash, claims, time.Minute)

	logoutToken := func(opts tokenfactory.TokenOptions) string {
		t.Helper()
		raw, err := as.IssueToken(opts)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	post := func(raw string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"logout_token": {raw}}
		req := httptest.NewRequest(http.MethodPost, "/webhook/backchannel-logout",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	t.Run("valid logout token evicts session", func(t *testing.T) {
		raw := logoutToken(tokenfactory.TokenOptions{
			Subject:   "alice",
			Issuer:    issuer,
			SessionID: "sess-42",
			ExpiresIn: 2 * time.Minute,
			Extra: map[string]interface{}{
				"events": map[string]interface{}{bclEvent: map[string]interface{}{}},
			},
		})
		rr := post(raw)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		if _, ok := cache.Get(ctx, hash); ok {
			t.Error("cached token for the logged-out session must be evicted")
		}
	})

	t.Run("missing events claim rejected", func(t *testing.T) {
		raw := logoutToken(tokenfactory.TokenOptions{
			Subject:   "alice",
			Issuer:    issuer,
			SessionID: "sess-42",
			ExpiresIn: 2 * time.Minute,
		})
		if rr := post(raw); rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for token without events claim, got %d", rr.Code)
		}
	})

	t.Run("nonce present rejected", func(t *testing.T) {
		raw := logoutToken(tokenfactory.TokenOptions{
			Subject:   "alice",
			Issuer:    issuer,
			ExpiresIn: 2 * time.Minute,
			Extra: map[string]interface{}{
				"events": map[string]interface{}{bclEvent: map[string]interface{}{}},
				"nonce":  "should-not-be-here",
			},
		})
		if rr := post(raw); rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for logout token with nonce, got %d", rr.Code)
		}
	})

	t.Run("unknown issuer rejected", func(t *testing.T) {
		otherAS, _ := setupAS(t) // not registered in the registry
		raw, err := otherAS.IssueToken(tokenfactory.TokenOptions{
			Subject:   "alice",
			ExpiresIn: 2 * time.Minute,
			Extra: map[string]interface{}{
				"events": map[string]interface{}{bclEvent: map[string]interface{}{}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if rr := post(raw); rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for unregistered issuer, got %d", rr.Code)
		}
	})

	t.Run("garbage token rejected", func(t *testing.T) {
		if rr := post("not-a-jwt"); rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})
}
