package tokenexchange_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/common-iam/iam/pkg/core/tokenexchange"
)

func mockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestExchange_Success(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		r.ParseForm() //nolint:errcheck
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
			t.Errorf("wrong grant_type: %s", r.FormValue("grant_type"))
		}
		if r.FormValue("subject_token") != "subject-tok" {
			t.Errorf("wrong subject_token: %s", r.FormValue("subject_token"))
		}
		if r.FormValue("subject_token_type") != tokenexchange.TokenTypeAccessToken {
			t.Errorf("wrong subject_token_type: %s", r.FormValue("subject_token_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"access_token":      "new-access-token",
			"issued_token_type": tokenexchange.TokenTypeAccessToken,
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	})

	client := tokenexchange.NewClient(srv.URL, nil)
	resp, err := client.Exchange(context.Background(), &tokenexchange.Request{
		SubjectToken:     "subject-tok",
		SubjectTokenType: tokenexchange.TokenTypeAccessToken,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %q", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q", resp.TokenType)
	}
}

func TestExchange_ErrorResponse(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"error":             "invalid_grant",
			"error_description": "subject token expired",
		})
	})

	client := tokenexchange.NewClient(srv.URL, nil)
	_, err := client.Exchange(context.Background(), &tokenexchange.Request{
		SubjectToken:     "expired",
		SubjectTokenType: tokenexchange.TokenTypeAccessToken,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error should contain 'invalid_grant': %v", err)
	}
}

func TestExchange_MissingSubjectToken(t *testing.T) {
	client := tokenexchange.NewClient("http://localhost", nil)
	_, err := client.Exchange(context.Background(), &tokenexchange.Request{
		SubjectTokenType: tokenexchange.TokenTypeAccessToken,
	})
	if err == nil {
		t.Error("expected error for missing SubjectToken")
	}
}

func TestExchange_DelegationWithActorToken(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm() //nolint:errcheck
		if r.FormValue("actor_token") != "actor-tok" {
			t.Errorf("actor_token not sent: %q", r.FormValue("actor_token"))
		}
		if r.FormValue("actor_token_type") != tokenexchange.TokenTypeAccessToken {
			t.Errorf("actor_token_type not sent: %q", r.FormValue("actor_token_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"access_token":      "delegated-token",
			"issued_token_type": tokenexchange.TokenTypeAccessToken,
			"token_type":        "Bearer",
		})
	})

	client := tokenexchange.NewClient(srv.URL, nil)
	resp, err := client.Exchange(context.Background(), &tokenexchange.Request{
		SubjectToken:     "subject-tok",
		SubjectTokenType: tokenexchange.TokenTypeAccessToken,
		ActorToken:       "actor-tok",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken != "delegated-token" {
		t.Errorf("AccessToken = %q", resp.AccessToken)
	}
}

func TestExchange_ScopeAndAudience(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm() //nolint:errcheck

		if r.FormValue("scope") != "read write" {
			t.Errorf("scope = %q, want 'read write'", r.FormValue("scope"))
		}
		if r.FormValue("audience") != "https://api.example.com" {
			t.Errorf("audience = %q", r.FormValue("audience"))
		}
		// Verify client_id is sent via Basic Auth.
		clientID, _, _ := r.BasicAuth()
		if clientID != "my-client" {
			t.Errorf("client_id = %q, want 'my-client'", clientID)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"access_token":      "scoped-token",
			"issued_token_type": tokenexchange.TokenTypeAccessToken,
			"token_type":        "Bearer",
			"scope":             "read write",
		})
	})

	client := tokenexchange.NewClient(srv.URL, nil)
	resp, err := client.Exchange(context.Background(), &tokenexchange.Request{
		SubjectToken:     "subject-tok",
		SubjectTokenType: tokenexchange.TokenTypeAccessToken,
		Scope:            "read write",
		Audience:         "https://api.example.com",
		ClientID:         "my-client",
		ClientSecret:     "secret",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Scope != "read write" {
		t.Errorf("Scope = %q", resp.Scope)
	}
}

func TestValidate_RequiredFields(t *testing.T) {
	good := &tokenexchange.Response{
		AccessToken:     "tok",
		IssuedTokenType: tokenexchange.TokenTypeAccessToken,
		TokenType:       "Bearer",
	}
	if err := tokenexchange.Validate(good); err != nil {
		t.Errorf("Validate should pass: %v", err)
	}

	missing := &tokenexchange.Response{IssuedTokenType: tokenexchange.TokenTypeAccessToken, TokenType: "Bearer"}
	if err := tokenexchange.Validate(missing); err == nil {
		t.Error("Validate should fail for missing access_token")
	}
}

func TestExchange_ResourceParameter(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		vals, _ := url.ParseQuery(string(body[:n]))
		if vals.Get("resource") != "https://target.svc/api" {
			t.Errorf("resource = %q", vals.Get("resource"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"access_token":      "tok",
			"issued_token_type": tokenexchange.TokenTypeAccessToken,
			"token_type":        "Bearer",
		})
	})

	client := tokenexchange.NewClient(srv.URL, nil)
	_, err := client.Exchange(context.Background(), &tokenexchange.Request{
		SubjectToken:     "st",
		SubjectTokenType: tokenexchange.TokenTypeAccessToken,
		Resource:         "https://target.svc/api",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
}
