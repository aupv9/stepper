package policy

import (
	"testing"
	"time"
)

func TestEngine_DefaultDeny(t *testing.T) {
	// No policy covers /unknown — must deny, not allow.
	cfg := &Config{
		ACRLevels: []string{"bronze", "silver"},
		Policies: []Policy{
			{
				Name:      "payments",
				Resources: []string{"/api/payments/**"},
				Methods:   []string{"POST"},
				Enabled:   true,
			},
		},
	}
	e := New(cfg)
	result, err := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/unknown"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("unmatched request must be denied by default")
	}
	if result.Reason == "" {
		t.Error("denial reason must not be empty")
	}
}

func TestEngine_NilConfig_DefaultDeny(t *testing.T) {
	e := New(nil)
	result, err := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/anything"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("nil config must deny all requests")
	}
}

func TestEngine_ACRHierarchy(t *testing.T) {
	cfg := &Config{
		ACRLevels: []string{"bronze", "silver", "gold"},
		Policies: []Policy{
			{Name: "payments", Resources: []string{"/api/payments"}, Methods: []string{"POST"}, RequireACR: "silver", Enabled: true},
		},
	}
	e := New(cfg)

	tests := []struct {
		tokenACR string
		want     bool
	}{
		{"gold", true},
		{"silver", true},
		{"bronze", false},
		{"", false},
	}
	for _, tt := range tests {
		result, err := e.Evaluate(&PolicyRequest{Method: "POST", Path: "/api/payments", TokenACR: tt.tokenACR})
		if err != nil {
			t.Fatalf("acr=%q: unexpected error: %v", tt.tokenACR, err)
		}
		if result.Allowed != tt.want {
			t.Errorf("acr=%q: got allowed=%v, want %v (reason: %s)", tt.tokenACR, result.Allowed, tt.want, result.Reason)
		}
	}
}

func TestEngine_MaxAge(t *testing.T) {
	cfg := &Config{
		Policies: []Policy{
			{Name: "fresh", Resources: []string{"/secure"}, MaxAge: 60, Enabled: true},
		},
	}
	e := New(cfg)

	t.Run("within max_age", func(t *testing.T) {
		result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/secure", AuthAge: 30 * time.Second})
		if !result.Allowed {
			t.Errorf("expected allowed, got: %s", result.Reason)
		}
	})
	t.Run("exceeds max_age", func(t *testing.T) {
		result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/secure", AuthAge: 90 * time.Second})
		if result.Allowed {
			t.Error("expected denial when auth_age > max_age")
		}
	})
	t.Run("zero auth_age skips check", func(t *testing.T) {
		result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/secure", AuthAge: 0})
		if !result.Allowed {
			t.Errorf("zero AuthAge should skip max_age check, got: %s", result.Reason)
		}
	})
}

func TestEngine_MFA(t *testing.T) {
	cfg := &Config{
		Policies: []Policy{
			{Name: "admin", Resources: []string{"/admin/**"}, RequireMFA: true, Enabled: true},
		},
	}
	e := New(cfg)

	result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/admin/users", TokenAMR: []string{"pwd"}})
	if result.Allowed {
		t.Error("expected denial without MFA AMR")
	}

	result, _ = e.Evaluate(&PolicyRequest{Method: "GET", Path: "/admin/users", TokenAMR: []string{"pwd", "otp"}})
	if !result.Allowed {
		t.Errorf("expected allowed with otp AMR, got: %s", result.Reason)
	}
}

func TestEngine_ScopeCheck(t *testing.T) {
	cfg := &Config{
		Policies: []Policy{
			{Name: "read-write", Resources: []string{"/api/data"}, RequireScopes: []string{"read", "write"}, Enabled: true},
		},
	}
	e := New(cfg)

	result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/api/data", TokenScopes: []string{"read"}})
	if result.Allowed {
		t.Error("expected denial with missing scope 'write'")
	}

	result, _ = e.Evaluate(&PolicyRequest{Method: "GET", Path: "/api/data", TokenScopes: []string{"read", "write"}})
	if !result.Allowed {
		t.Errorf("expected allowed with all scopes, got: %s", result.Reason)
	}
}

func TestEngine_HotReload(t *testing.T) {
	cfg := &Config{
		Policies: []Policy{
			{Name: "v1", Resources: []string{"/v1/**"}, Enabled: true},
		},
	}
	e := New(cfg)

	result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/v2/anything"})
	if result.Allowed {
		t.Error("v2 path should be denied before reload")
	}

	newCfg := &Config{
		Policies: []Policy{
			{Name: "v2", Resources: []string{"/v2/**"}, Enabled: true},
		},
	}
	e.Reload(newCfg)

	result, _ = e.Evaluate(&PolicyRequest{Method: "GET", Path: "/v2/anything"})
	if !result.Allowed {
		t.Errorf("v2 path should be allowed after reload, got: %s", result.Reason)
	}
}
