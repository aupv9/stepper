package policy

import (
	"testing"
	"time"
)

func TestEngine_DenyEffectAndPriority(t *testing.T) {
	cfg := &Config{
		Policies: []Policy{
			// File order puts the allow first; priority must flip evaluation order.
			{Name: "allow-api", Resources: []string{"/api/**"}, Enabled: true},
			{Name: "block-legacy", Resources: []string{"/api/legacy/**"}, Effect: "deny", Priority: 100, Enabled: true},
		},
	}
	e := New(cfg)

	result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/api/legacy/x"})
	if result.Allowed {
		t.Error("deny policy with higher priority must win over allow")
	}
	if result.MatchedPolicy == nil || result.MatchedPolicy.Name != "block-legacy" {
		t.Errorf("matched = %+v, want block-legacy", result.MatchedPolicy)
	}

	result, _ = e.Evaluate(&PolicyRequest{Method: "GET", Path: "/api/other"})
	if !result.Allowed {
		t.Errorf("non-legacy path should be allowed: %s", result.Reason)
	}
}

func TestEngine_TenantScopedPolicies(t *testing.T) {
	cfg := &Config{
		Policies: []Policy{
			{Name: "acme-only", Resources: []string{"/data/**"}, Tenants: []string{"acme"}, Enabled: true},
		},
	}
	e := New(cfg)

	result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/data/x", TenantID: "acme"})
	if !result.Allowed {
		t.Errorf("acme tenant should match: %s", result.Reason)
	}

	result, _ = e.Evaluate(&PolicyRequest{Method: "GET", Path: "/data/x", TenantID: "bravo"})
	if result.Allowed {
		t.Error("bravo tenant must fall through to default deny")
	}
}

func TestEngine_RequireRoles(t *testing.T) {
	cfg := &Config{
		Policies: []Policy{
			{Name: "admins", Resources: []string{"/admin/**"}, RequireRoles: []string{"admin"}, Enabled: true},
		},
	}
	e := New(cfg)

	result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/admin/x", TokenRoles: []string{"admin", "user"}})
	if !result.Allowed {
		t.Errorf("admin role should pass: %s", result.Reason)
	}
	result, _ = e.Evaluate(&PolicyRequest{Method: "GET", Path: "/admin/x", TokenRoles: []string{"user"}})
	if result.Allowed {
		t.Error("missing admin role must deny")
	}
}

func TestEngine_IPCIDRCondition(t *testing.T) {
	cfg := &Config{
		Policies: []Policy{
			{
				Name: "block-internal-range", Resources: []string{"/**"}, Effect: "deny", Priority: 10,
				When:    &Condition{IPCIDR: []string{"10.0.0.0/8", "192.168.1.5"}},
				Enabled: true,
			},
			{Name: "allow-rest", Resources: []string{"/**"}, Enabled: true},
		},
	}
	e := New(cfg)

	for ip, wantAllowed := range map[string]bool{
		"10.1.2.3":    false, // inside CIDR
		"192.168.1.5": false, // bare IP entry
		"8.8.8.8":     true,  // outside → falls through to allow
	} {
		result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/x", ClientIP: ip})
		if result.Allowed != wantAllowed {
			t.Errorf("ip %s: allowed = %v, want %v", ip, result.Allowed, wantAllowed)
		}
	}
}

func TestEngine_TimeWindowCondition(t *testing.T) {
	cfg := &Config{
		Policies: []Policy{
			{
				Name: "office-hours", Resources: []string{"/**"},
				When:    &Condition{TimeWindow: &TimeWindow{Start: "08:00", End: "18:00", Days: []string{"mon", "tue", "wed", "thu", "fri"}}},
				Enabled: true,
			},
		},
	}
	e := New(cfg)

	// Wednesday 10:00 UTC.
	weekday := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/x", Now: weekday})
	if !result.Allowed {
		t.Errorf("weekday office hours should match: %s", result.Reason)
	}

	// Wednesday 22:00 UTC — outside window → no match → default deny.
	night := time.Date(2026, 8, 5, 22, 0, 0, 0, time.UTC)
	result, _ = e.Evaluate(&PolicyRequest{Method: "GET", Path: "/x", Now: night})
	if result.Allowed {
		t.Error("outside office hours must fall through to default deny")
	}

	// Sunday 10:00 UTC — wrong day.
	sunday := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	result, _ = e.Evaluate(&PolicyRequest{Method: "GET", Path: "/x", Now: sunday})
	if result.Allowed {
		t.Error("sunday must fall through to default deny")
	}
}

func TestEngine_HeaderCondition(t *testing.T) {
	cfg := &Config{
		Policies: []Policy{
			{
				Name: "canary", Resources: []string{"/**"},
				When:    &Condition{Headers: map[string]string{"X-Canary": "true"}},
				Enabled: true,
			},
		},
	}
	e := New(cfg)

	result, _ := e.Evaluate(&PolicyRequest{Method: "GET", Path: "/x", Headers: map[string]string{"x-canary": "true"}})
	if !result.Allowed {
		t.Errorf("case-insensitive header match should pass: %s", result.Reason)
	}
	result, _ = e.Evaluate(&PolicyRequest{Method: "GET", Path: "/x"})
	if result.Allowed {
		t.Error("missing header must fall through to default deny")
	}
}

func TestEngine_OvernightTimeWindow(t *testing.T) {
	w := &TimeWindow{Start: "22:00", End: "06:00"}
	if !matchTimeWindow(w, time.Date(2026, 8, 5, 23, 30, 0, 0, time.UTC)) {
		t.Error("23:30 should be inside 22:00–06:00")
	}
	if !matchTimeWindow(w, time.Date(2026, 8, 5, 3, 0, 0, 0, time.UTC)) {
		t.Error("03:00 should be inside 22:00–06:00")
	}
	if matchTimeWindow(w, time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)) {
		t.Error("12:00 should be outside 22:00–06:00")
	}
}
