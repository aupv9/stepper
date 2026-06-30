package simulator

import (
	"strings"
	"testing"
	"time"

	"github.com/common-iam/iam/pkg/core/policy"
)

// testEngine builds a policy engine with a representative ruleset:
//   - payments: POST /api/payments/** requires ACR=silver
//   - data:     GET /api/data requires scopes read+write
//   - fresh:    GET /secure requires max_age=60s
func testEngine() *policy.Engine {
	return policy.New(&policy.Config{
		Realm:     "test",
		ACRLevels: []string{"bronze", "silver", "gold"},
		Policies: []policy.Policy{
			{
				Name:       "payments",
				Resources:  []string{"/api/payments/**"},
				Methods:    []string{"POST"},
				RequireACR: "silver",
				Enabled:    true,
			},
			{
				Name:          "data",
				Resources:     []string{"/api/data"},
				RequireScopes: []string{"read", "write"},
				Enabled:       true,
			},
			{
				Name:      "fresh",
				Resources: []string{"/secure"},
				MaxAge:    60,
				Enabled:   true,
			},
		},
	})
}

func TestSimulate_Cases(t *testing.T) {
	sim := New(testEngine())

	tests := []struct {
		name           string
		req            Request
		wantAllowed    bool
		wantPolicy     string
		wantReqACR     string
		wantReqMaxAge  int
		reasonContains string // checked only when not allowed
	}{
		{
			name:          "acr satisfies (gold >= silver)",
			req:           Request{Method: "POST", Path: "/api/payments/charge", ACR: "gold"},
			wantAllowed:   true,
			wantPolicy:    "payments",
			wantReqACR:    "silver",
			wantReqMaxAge: 0,
		},
		{
			name:        "acr exact match",
			req:         Request{Method: "POST", Path: "/api/payments/charge", ACR: "silver"},
			wantAllowed: true,
			wantPolicy:  "payments",
			wantReqACR:  "silver",
		},
		{
			name:           "acr too low (bronze < silver)",
			req:            Request{Method: "POST", Path: "/api/payments/charge", ACR: "bronze"},
			wantAllowed:    false,
			wantPolicy:     "payments",
			wantReqACR:     "silver",
			reasonContains: "does not satisfy",
		},
		{
			name:           "acr empty",
			req:            Request{Method: "POST", Path: "/api/payments/charge", ACR: ""},
			wantAllowed:    false,
			wantPolicy:     "payments",
			wantReqACR:     "silver",
			reasonContains: "does not satisfy",
		},
		{
			name:           "scope missing (only read)",
			req:            Request{Method: "GET", Path: "/api/data", Scopes: []string{"read"}},
			wantAllowed:    false,
			wantPolicy:     "data",
			reasonContains: "missing required scope",
		},
		{
			name:        "scope satisfied (read+write)",
			req:         Request{Method: "GET", Path: "/api/data", Scopes: []string{"read", "write"}},
			wantAllowed: true,
			wantPolicy:  "data",
		},
		{
			name:          "max_age within limit",
			req:           Request{Method: "GET", Path: "/secure", AuthAge: 30 * time.Second},
			wantAllowed:   true,
			wantPolicy:    "fresh",
			wantReqMaxAge: 60,
		},
		{
			name:           "max_age exceeded",
			req:            Request{Method: "GET", Path: "/secure", AuthAge: 120 * time.Second},
			wantAllowed:    false,
			wantPolicy:     "fresh",
			wantReqMaxAge:  60,
			reasonContains: "old",
		},
		{
			name:           "no matching policy → default deny",
			req:            Request{Method: "GET", Path: "/totally/unknown"},
			wantAllowed:    false,
			wantPolicy:     "",
			reasonContains: "no matching policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := sim.Simulate(tt.req)
			if err != nil {
				t.Fatalf("Simulate: unexpected error: %v", err)
			}
			if res.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v (reason: %q)", res.Allowed, tt.wantAllowed, res.Reason)
			}
			if res.PolicyName != tt.wantPolicy {
				t.Errorf("PolicyName = %q, want %q", res.PolicyName, tt.wantPolicy)
			}
			if res.RequiredACR != tt.wantReqACR {
				t.Errorf("RequiredACR = %q, want %q", res.RequiredACR, tt.wantReqACR)
			}
			if res.RequiredMaxAge != tt.wantReqMaxAge {
				t.Errorf("RequiredMaxAge = %d, want %d", res.RequiredMaxAge, tt.wantReqMaxAge)
			}
			if !tt.wantAllowed {
				if res.Reason == "" {
					t.Error("denial Reason must not be empty")
				}
				if tt.reasonContains != "" && !strings.Contains(res.Reason, tt.reasonContains) {
					t.Errorf("Reason = %q, want substring %q", res.Reason, tt.reasonContains)
				}
			}
		})
	}
}

func TestSimulate_NilConfigEngineDeniesAll(t *testing.T) {
	sim := New(policy.New(nil))
	res, err := sim.Simulate(Request{Method: "GET", Path: "/anything"})
	if err != nil {
		t.Fatalf("Simulate: unexpected error: %v", err)
	}
	if res.Allowed {
		t.Error("nil-config engine must deny")
	}
	if res.PolicyName != "" {
		t.Errorf("PolicyName = %q, want empty when no policy matched", res.PolicyName)
	}
	if res.Reason == "" {
		t.Error("denial Reason must not be empty")
	}
}

func TestRunTable_RendersRows(t *testing.T) {
	sim := New(testEngine())
	out := sim.RunTable([]Request{
		{Method: "POST", Path: "/api/payments/charge", ACR: "gold"},
		{Method: "POST", Path: "/api/payments/charge", ACR: "bronze"},
		{Method: "GET", Path: "/api/data", Scopes: []string{"read"}},
	})

	t.Run("has header", func(t *testing.T) {
		if !strings.Contains(out, "METHOD") || !strings.Contains(out, "ALLOWED") {
			t.Errorf("table missing header row:\n%s", out)
		}
	})
	t.Run("renders allow and deny", func(t *testing.T) {
		if !strings.Contains(out, "YES") {
			t.Errorf("expected a YES row for the gold payments request:\n%s", out)
		}
		if !strings.Contains(out, "NO") {
			t.Errorf("expected a NO row for the bronze/scope-missing requests:\n%s", out)
		}
	})
	t.Run("one row per request plus header and separator", func(t *testing.T) {
		// header + separator + 3 request rows = 5 newline-terminated lines.
		lines := strings.Count(out, "\n")
		if lines != 5 {
			t.Errorf("line count = %d, want 5\n%s", lines, out)
		}
	})
}

func TestRunTable_FallbackReasonForACR(t *testing.T) {
	// A policy with only RequireACR and no other failure produces an empty
	// engine Reason path? It does not — engine sets a Reason. This test
	// documents that RunTable still surfaces a reason for denied ACR rows.
	sim := New(testEngine())
	out := sim.RunTable([]Request{
		{Method: "POST", Path: "/api/payments/charge", ACR: "bronze"},
	})
	if !strings.Contains(out, "bronze") {
		t.Errorf("expected the bronze ACR to appear in the row:\n%s", out)
	}
}
