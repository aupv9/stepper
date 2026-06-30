package fapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/common-iam/iam/pkg/core/fapi"
)

// --- PAR client tests ---

func parServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func validPARReq() *fapi.PARRequest {
	return &fapi.PARRequest{
		ResponseType:        "code",
		ClientID:            "client-1",
		ClientSecret:        "secret",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "openid accounts",
		State:               "state-abc",
		Nonce:               "nonce-xyz",
		CodeChallenge:       "challenge-abc123",
		CodeChallengeMethod: "S256",
	}
}

func TestPARClient_Push_Success(t *testing.T) {
	srv := parServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/x-www-form-urlencoded") {
			t.Errorf("Content-Type = %q", ct)
		}
		r.ParseForm() //nolint:errcheck
		if r.FormValue("response_type") != "code" {
			t.Errorf("response_type = %q", r.FormValue("response_type"))
		}
		if r.FormValue("code_challenge_method") != "S256" {
			t.Errorf("code_challenge_method = %q", r.FormValue("code_challenge_method"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"request_uri": "urn:ietf:params:oauth:request_uri:abc123",
			"expires_in":  90,
		})
	})

	client := fapi.NewPARClient(srv.URL, nil)
	resp, err := client.Push(context.Background(), validPARReq())
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if resp.RequestURI != "urn:ietf:params:oauth:request_uri:abc123" {
		t.Errorf("RequestURI = %q", resp.RequestURI)
	}
	if resp.ExpiresIn != 90 {
		t.Errorf("ExpiresIn = %d", resp.ExpiresIn)
	}
}

func TestPARClient_Push_ErrorResponse(t *testing.T) {
	srv := parServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"error":             "invalid_request",
			"error_description": "redirect_uri not registered",
		})
	})

	client := fapi.NewPARClient(srv.URL, nil)
	_, err := client.Push(context.Background(), validPARReq())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid_request") {
		t.Errorf("error should contain 'invalid_request': %v", err)
	}
}

func TestPARClient_Push_ValidationErrors(t *testing.T) {
	client := fapi.NewPARClient("http://localhost", nil)

	cases := []struct {
		name string
		req  func(*fapi.PARRequest)
		want string
	}{
		{"missing client_id", func(r *fapi.PARRequest) { r.ClientID = "" }, "client_id"},
		{"missing redirect_uri", func(r *fapi.PARRequest) { r.RedirectURI = "" }, "redirect_uri"},
		{"wrong response_type", func(r *fapi.PARRequest) { r.ResponseType = "token" }, "response_type"},
		{"missing nonce", func(r *fapi.PARRequest) { r.Nonce = "" }, "nonce"},
		{"missing state", func(r *fapi.PARRequest) { r.State = "" }, "state"},
		{"missing code_challenge", func(r *fapi.PARRequest) { r.CodeChallenge = "" }, "code_challenge"},
		{"wrong code_challenge_method", func(r *fapi.PARRequest) { r.CodeChallengeMethod = "plain" }, "S256"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validPARReq()
			tc.req(req)
			_, err := client.Push(context.Background(), req)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should contain %q", err, tc.want)
			}
		})
	}
}

func TestAuthorizationURL(t *testing.T) {
	u, err := fapi.AuthorizationURL("https://as.example.com/authorize", "client-1",
		"urn:ietf:params:oauth:request_uri:abc")
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	parsed, _ := url.Parse(u)
	q := parsed.Query()
	if q.Get("client_id") != "client-1" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("request_uri") != "urn:ietf:params:oauth:request_uri:abc" {
		t.Errorf("request_uri = %q", q.Get("request_uri"))
	}
}

func TestValidateResponseType(t *testing.T) {
	cfg := fapi.DefaultFAPI2Config()

	if err := fapi.ValidateResponseType("code", cfg); err != nil {
		t.Errorf("'code' should be allowed: %v", err)
	}
	if err := fapi.ValidateResponseType("token", cfg); err == nil {
		t.Error("'token' should be rejected")
	}
	if err := fapi.ValidateResponseType("code id_token", cfg); err == nil {
		t.Error("'code id_token' should be rejected by default FAPI 2.0 config")
	}
}

// --- Profile validation tests ---

type fakeClaims struct {
	dpop        bool
	parURI      bool
	authAge     time.Duration
	nonce       string
}

func (f *fakeClaims) HasDPoP() bool              { return f.dpop }
func (f *fakeClaims) HasPARRequestURI() bool      { return f.parURI }
func (f *fakeClaims) GetAuthAge() time.Duration   { return f.authAge }
func (f *fakeClaims) GetNonce() string            { return f.nonce }

func goodClaims() *fakeClaims {
	return &fakeClaims{dpop: true, parURI: true, authAge: 30 * time.Second, nonce: "n1"}
}

func TestValidateRequest_AllGood(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	cfg := fapi.DefaultFAPI2Config()
	if err := fapi.ValidateRequest(r, goodClaims(), cfg); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateRequest_MissingDPoP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	cfg := fapi.DefaultFAPI2Config()
	claims := goodClaims()
	claims.dpop = false
	err := fapi.ValidateRequest(r, claims, cfg)
	if err == nil {
		t.Fatal("expected error for missing DPoP")
	}
	if !strings.Contains(err.Error(), "DPoP") {
		t.Errorf("error should mention DPoP: %v", err)
	}
}

func TestValidateRequest_MissingPAR(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	cfg := fapi.DefaultFAPI2Config()
	claims := goodClaims()
	claims.parURI = false
	err := fapi.ValidateRequest(r, claims, cfg)
	if err == nil {
		t.Fatal("expected error for missing PAR")
	}
	if !strings.Contains(err.Error(), "PAR") {
		t.Errorf("error should mention PAR: %v", err)
	}
}

func TestValidateRequest_AuthTimeTooOld(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	cfg := fapi.DefaultFAPI2Config()
	claims := goodClaims()
	claims.authAge = 120 * time.Second // exceeds 60s limit
	err := fapi.ValidateRequest(r, claims, cfg)
	if err == nil {
		t.Fatal("expected error for stale auth_time")
	}
	if !strings.Contains(err.Error(), "auth_time") {
		t.Errorf("error should mention auth_time: %v", err)
	}
}

func TestValidateRequest_MissingNonce(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	cfg := fapi.DefaultFAPI2Config()
	claims := goodClaims()
	claims.nonce = ""
	err := fapi.ValidateRequest(r, claims, cfg)
	if err == nil {
		t.Fatal("expected error for missing nonce")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("error should mention nonce: %v", err)
	}
}

func TestValidateRequest_ZeroAuthAge_Skipped(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	cfg := fapi.DefaultFAPI2Config()
	claims := goodClaims()
	claims.authAge = 0 // auth_time absent in token — skip freshness check
	if err := fapi.ValidateRequest(r, claims, cfg); err != nil {
		t.Errorf("zero authAge should skip freshness check, got: %v", err)
	}
}

func TestValidateTokenBinding_DPoP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	claims := goodClaims()
	claims.dpop = true
	if err := fapi.ValidateTokenBinding(r, claims, false); err != nil {
		t.Errorf("DPoP bound token should pass: %v", err)
	}
}

func TestValidateTokenBinding_NeitherDPoPNormTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	claims := goodClaims()
	claims.dpop = false
	err := fapi.ValidateTokenBinding(r, claims, false)
	if err == nil {
		t.Error("expected error when neither DPoP nor mTLS")
	}
	if !strings.Contains(err.Error(), "sender-constrained") {
		t.Errorf("error should mention sender-constrained: %v", err)
	}
}

func TestProfileError_Format(t *testing.T) {
	pe := &fapi.ProfileError{Requirement: "DPoP", Detail: "proof missing"}
	if !strings.Contains(pe.Error(), "FAPI 2.0") {
		t.Errorf("error should contain 'FAPI 2.0': %v", pe)
	}
	if !strings.Contains(pe.Error(), "DPoP") {
		t.Errorf("error should contain requirement: %v", pe)
	}
}

// TestPARClient_Push_OptionalFields verifies that resource + authorization_details
// are included in the form when provided.
func TestPARClient_Push_OptionalFields(t *testing.T) {
	srv := parServer(t, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm() //nolint:errcheck
		if r.FormValue("resource") != "https://api.example.com" {
			t.Errorf("resource = %q", r.FormValue("resource"))
		}
		if r.FormValue("authorization_details") == "" {
			t.Error("authorization_details should be present")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"request_uri":"urn:test:1","expires_in":60}`)
	})

	req := validPARReq()
	req.Resource = "https://api.example.com"
	req.AuthorizationDetails = `[{"type":"payment_initiation"}]`

	client := fapi.NewPARClient(srv.URL, nil)
	if _, err := client.Push(context.Background(), req); err != nil {
		t.Fatalf("Push: %v", err)
	}
}
