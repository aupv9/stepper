package providers

import (
	"testing"
	"time"
)

func TestMapToCommon_StandardOIDCClaims(t *testing.T) {
	now := time.Now()
	raw := RawClaims{
		"sub":                "user-123",
		"iss":                "https://issuer.example.com",
		"acr":                "urn:mace:incommon:iap:silver",
		"sid":                "session-abc",
		"email":              "alice@example.com",
		"preferred_username": "alice",
		"amr":                []interface{}{"pwd", "otp"},
		"aud":                "my-api",
		"exp":                float64(now.Add(time.Hour).Unix()),
		"iat":                float64(now.Unix()),
		"auth_time":          float64(now.Add(-5 * time.Minute).Unix()),
		"scope":              "openid profile email",
	}

	c := MapToCommon(raw)

	if c.Subject != "user-123" {
		t.Errorf("Subject: got %q, want %q", c.Subject, "user-123")
	}
	if c.Issuer != "https://issuer.example.com" {
		t.Errorf("Issuer: got %q", c.Issuer)
	}
	if c.ACR != "urn:mace:incommon:iap:silver" {
		t.Errorf("ACR: got %q", c.ACR)
	}
	if c.SessionID != "session-abc" {
		t.Errorf("SessionID: got %q", c.SessionID)
	}
	if c.Email != "alice@example.com" {
		t.Errorf("Email: got %q", c.Email)
	}
	if c.Username != "alice" {
		t.Errorf("Username: got %q", c.Username)
	}
	if len(c.AMR) != 2 || c.AMR[0] != "pwd" || c.AMR[1] != "otp" {
		t.Errorf("AMR: got %v, want [pwd otp]", c.AMR)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "my-api" {
		t.Errorf("Audience: got %v, want [my-api]", c.Audience)
	}
	wantScopes := []string{"openid", "profile", "email"}
	if len(c.Scopes) != len(wantScopes) {
		t.Fatalf("Scopes: got %v, want %v", c.Scopes, wantScopes)
	}
	for i, s := range wantScopes {
		if c.Scopes[i] != s {
			t.Errorf("Scopes[%d]: got %q, want %q", i, c.Scopes[i], s)
		}
	}
	// exp is in the future -> Active should be true (no explicit "active" claim).
	if !c.Active {
		t.Error("expected Active=true for non-expired token without explicit active claim")
	}
	// Time fields
	if c.ExpiresAt.Unix() != now.Add(time.Hour).Unix() {
		t.Errorf("ExpiresAt: got %v", c.ExpiresAt)
	}
	if c.IssuedAt.Unix() != now.Unix() {
		t.Errorf("IssuedAt: got %v", c.IssuedAt)
	}
	if c.AuthTime.Unix() != now.Add(-5*time.Minute).Unix() {
		t.Errorf("AuthTime: got %v", c.AuthTime)
	}
}

func TestMapToCommon_UsernameFallback(t *testing.T) {
	tests := []struct {
		name string
		raw  RawClaims
		want string
	}{
		{
			name: "preferred_username wins",
			raw:  RawClaims{"preferred_username": "pref", "username": "uname", "nickname": "nick"},
			want: "pref",
		},
		{
			name: "username when no preferred_username",
			raw:  RawClaims{"username": "uname", "nickname": "nick"},
			want: "uname",
		},
		{
			name: "nickname when only nickname",
			raw:  RawClaims{"nickname": "nick"},
			want: "nick",
		},
		{
			name: "empty when none present",
			raw:  RawClaims{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := MapToCommon(tt.raw)
			if c.Username != tt.want {
				t.Errorf("Username: got %q, want %q", c.Username, tt.want)
			}
		})
	}
}

func TestMapToCommon_ActiveFromIntrospection(t *testing.T) {
	t.Run("explicit active=false overrides expiry heuristic", func(t *testing.T) {
		raw := RawClaims{
			"active": false,
			"exp":    float64(time.Now().Add(time.Hour).Unix()), // not expired
		}
		c := MapToCommon(raw)
		if c.Active {
			t.Error("expected Active=false from explicit introspection claim")
		}
	})
	t.Run("explicit active=true", func(t *testing.T) {
		raw := RawClaims{"active": true}
		c := MapToCommon(raw)
		if !c.Active {
			t.Error("expected Active=true from explicit introspection claim")
		}
	})
	t.Run("no active claim, expired token -> inactive", func(t *testing.T) {
		raw := RawClaims{"exp": float64(time.Now().Add(-time.Hour).Unix())}
		c := MapToCommon(raw)
		if c.Active {
			t.Error("expected Active=false for expired token without active claim")
		}
	})
	t.Run("no active claim, no exp -> active", func(t *testing.T) {
		raw := RawClaims{"sub": "x"}
		c := MapToCommon(raw)
		if !c.Active {
			t.Error("expected Active=true when no exp and no active claim (zero ExpiresAt)")
		}
	})
}

func TestMapToCommon_Roles(t *testing.T) {
	t.Run("keycloak realm_access.roles", func(t *testing.T) {
		raw := RawClaims{
			"realm_access": map[string]interface{}{
				"roles": []interface{}{"admin", "user"},
			},
		}
		c := MapToCommon(raw)
		if len(c.Roles) != 2 || c.Roles[0] != "admin" || c.Roles[1] != "user" {
			t.Errorf("Roles: got %v, want [admin user]", c.Roles)
		}
	})
	t.Run("auth0 namespaced /roles claim", func(t *testing.T) {
		raw := RawClaims{
			"https://example.com/roles": []interface{}{"editor"},
		}
		c := MapToCommon(raw)
		if len(c.Roles) != 1 || c.Roles[0] != "editor" {
			t.Errorf("Roles: got %v, want [editor]", c.Roles)
		}
	})
	t.Run("generic roles claim", func(t *testing.T) {
		raw := RawClaims{
			"roles": []interface{}{"viewer"},
		}
		c := MapToCommon(raw)
		if len(c.Roles) != 1 || c.Roles[0] != "viewer" {
			t.Errorf("Roles: got %v, want [viewer]", c.Roles)
		}
	})
	t.Run("no roles", func(t *testing.T) {
		c := MapToCommon(RawClaims{"sub": "x"})
		if c.Roles != nil {
			t.Errorf("Roles: got %v, want nil", c.Roles)
		}
	})
	t.Run("keycloak realm_access takes priority over generic roles", func(t *testing.T) {
		raw := RawClaims{
			"realm_access": map[string]interface{}{
				"roles": []interface{}{"kc-role"},
			},
			"roles": []interface{}{"generic-role"},
		}
		c := MapToCommon(raw)
		if len(c.Roles) != 1 || c.Roles[0] != "kc-role" {
			t.Errorf("Roles: got %v, want [kc-role] (realm_access priority)", c.Roles)
		}
	})
}

func TestMapToCommon_TenantID(t *testing.T) {
	tests := []struct {
		name string
		raw  RawClaims
		want string
	}{
		{"tenant_id", RawClaims{"tenant_id": "t1"}, "t1"},
		{"tid Azure style", RawClaims{"tid": "t2"}, "t2"},
		{"org_id Auth0 style", RawClaims{"org_id": "t3"}, "t3"},
		{"tenant_id wins over tid and org_id", RawClaims{"tenant_id": "t1", "tid": "t2", "org_id": "t3"}, "t1"},
		{"none", RawClaims{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := MapToCommon(tt.raw)
			if c.TenantID != tt.want {
				t.Errorf("TenantID: got %q, want %q", c.TenantID, tt.want)
			}
		})
	}
}

func TestMapToCommon_ExtraClaims(t *testing.T) {
	raw := RawClaims{
		"sub":          "user-1",       // known -> not in Extra
		"iss":          "iss",          // known
		"custom_field": "custom_value", // unknown -> Extra
		"department":   "engineering",  // unknown -> Extra
	}
	c := MapToCommon(raw)

	if c.Extra == nil {
		t.Fatal("Extra map must not be nil")
	}
	if _, ok := c.Extra["sub"]; ok {
		t.Error("known claim 'sub' must not appear in Extra")
	}
	if _, ok := c.Extra["iss"]; ok {
		t.Error("known claim 'iss' must not appear in Extra")
	}
	if v, _ := c.Extra["custom_field"].(string); v != "custom_value" {
		t.Errorf("Extra[custom_field]: got %v, want custom_value", c.Extra["custom_field"])
	}
	if v, _ := c.Extra["department"].(string); v != "engineering" {
		t.Errorf("Extra[department]: got %v, want engineering", c.Extra["department"])
	}
}

func TestMapToCommon_AudienceVariants(t *testing.T) {
	t.Run("string audience", func(t *testing.T) {
		c := MapToCommon(RawClaims{"aud": "single-api"})
		if len(c.Audience) != 1 || c.Audience[0] != "single-api" {
			t.Errorf("Audience: got %v, want [single-api]", c.Audience)
		}
	})
	t.Run("array audience", func(t *testing.T) {
		c := MapToCommon(RawClaims{"aud": []interface{}{"api-1", "api-2"}})
		if len(c.Audience) != 2 || c.Audience[0] != "api-1" || c.Audience[1] != "api-2" {
			t.Errorf("Audience: got %v, want [api-1 api-2]", c.Audience)
		}
	})
}

func TestMapToCommon_UnixTimeIntVariants(t *testing.T) {
	// unixTimeClaim handles float64, int64 and int. JSON decoding yields float64,
	// but maps built in-code may carry int/int64.
	ts := int64(1700000000)
	tests := []struct {
		name string
		val  interface{}
	}{
		{"float64", float64(ts)},
		{"int64", ts},
		{"int", int(ts)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := MapToCommon(RawClaims{"exp": tt.val})
			if c.ExpiresAt.Unix() != ts {
				t.Errorf("ExpiresAt: got %d, want %d", c.ExpiresAt.Unix(), ts)
			}
		})
	}
}
