package policy

import "testing"

func TestMatchResource(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Exact
		{"/api/users", "/api/users", true},
		{"/api/users", "/api/users/42", false},

		// Single-level wildcard
		{"/api/users/*", "/api/users/42", true},
		{"/api/users/*", "/api/users/42/orders", false},

		// Double wildcard with segment boundary
		{"/api/**", "/api", true},
		{"/api/**", "/api/users", true},
		{"/api/**", "/api/users/42/orders", true},
		{"/api/**", "/api-internal/users", false}, // boundary regression
		{"/api/**", "/apiv2/users", false},        // boundary regression
		{"/api**", "/apiv2", false},               // boundary regression
		{"/**", "/anything/at/all", true},

		// Trailing slash normalization
		{"/api/users/", "/api/users", true},
		{"/api/**", "/api/users/", true},
	}
	for _, tt := range tests {
		if got := MatchResource(tt.pattern, tt.path); got != tt.want {
			t.Errorf("MatchResource(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestACRSatisfies(t *testing.T) {
	hierarchy := []string{"bronze", "silver", "gold"}
	tests := []struct {
		provided, required string
		want               bool
	}{
		{"gold", "silver", true},
		{"silver", "silver", true},
		{"bronze", "silver", false},
		{"unknown", "silver", false},
		{"silver", "unknown", false},
		{"same", "same", true}, // exact match outside hierarchy
	}
	for _, tt := range tests {
		if got := ACRSatisfies(tt.provided, tt.required, hierarchy); got != tt.want {
			t.Errorf("ACRSatisfies(%q, %q) = %v, want %v", tt.provided, tt.required, got, tt.want)
		}
	}
}
