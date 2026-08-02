package policy

import "testing"

func TestMatchResource_DoubleWildcardBoundary(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Legitimate matches: prefix aligns on a segment boundary.
		{"/public/**", "/public", true},
		{"/public/**", "/public/", true},
		{"/public/**", "/public/x", true},
		{"/public/**", "/public/x/y", true},
		{"/admin/**", "/admin/users", true},
		{"/**", "/anything/at/all", true},

		// Bypass attempts: shared string prefix but different segment.
		{"/public/**", "/publicSECRET/admin", false},
		{"/admin/**", "/adminpanelbypass", false},
		{"/admin/**", "/administrator-selfservice/x", false},
		{"/public/**", "/private", false},

		// Exact and single-wildcard behaviour is unchanged.
		{"/api/users", "/api/users", true},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/users/1", false},
	}
	for _, c := range cases {
		if got := MatchResource(c.pattern, c.path); got != c.want {
			t.Errorf("MatchResource(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}
