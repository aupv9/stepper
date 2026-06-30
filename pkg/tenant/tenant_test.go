package tenant

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/providers"
)

// --- Fake Provider ---

// fakeProvider is a minimal providers.Provider implementation for tests.
type fakeProvider struct {
	name         string
	issuer       string
	refreshErr   error
	refreshCalls int
}

func (f *fakeProvider) Introspect(ctx context.Context, rawToken string) (*token.CommonClaims, error) {
	return nil, nil
}

func (f *fakeProvider) JWKS(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (f *fakeProvider) RefreshConfig(ctx context.Context) error {
	f.refreshCalls++
	return f.refreshErr
}

func (f *fakeProvider) Name() string { return f.name }

func (f *fakeProvider) Issuer() string { return f.issuer }

// compile-time check that fakeProvider satisfies the interface.
var _ providers.Provider = (*fakeProvider)(nil)

// newRequest builds an *http.Request with the given host and path.
func newRequest(host, path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	r.Host = host
	return r
}

// --- HeaderResolver ---

func TestHeaderResolver_DefaultHeader(t *testing.T) {
	// Empty header string defaults to X-Tenant-ID.
	h := NewHeaderResolver("")
	if h.Header != "X-Tenant-ID" {
		t.Fatalf("expected default header X-Tenant-ID, got %q", h.Header)
	}
}

func TestHeaderResolver_Resolve(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		setHeader  string
		setValue   string
		wantTenant string
		wantErr    bool
	}{
		{name: "resolves from default header", header: "", setHeader: "X-Tenant-ID", setValue: "acme", wantTenant: "acme"},
		{name: "resolves from custom header", header: "X-Org", setHeader: "X-Org", setValue: "globex", wantTenant: "globex"},
		{name: "missing header returns error", header: "X-Tenant-ID", setHeader: "", setValue: "", wantErr: true},
		{name: "wrong header set returns error", header: "X-Tenant-ID", setHeader: "X-Other", setValue: "acme", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHeaderResolver(tt.header)
			r := newRequest("example.com", "/")
			if tt.setHeader != "" {
				r.Header.Set(tt.setHeader, tt.setValue)
			}
			got, err := h.Resolve(r)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got tenant %q", got)
				}
				if got != "" {
					t.Errorf("expected empty tenant on error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantTenant {
				t.Errorf("got tenant %q, want %q", got, tt.wantTenant)
			}
		})
	}
}

// --- SubdomainResolver ---

func TestSubdomainResolver_Resolve(t *testing.T) {
	tests := []struct {
		name       string
		baseDomain string
		host       string
		wantTenant string
		wantErr    bool
	}{
		{name: "simple subdomain", baseDomain: "api.example.com", host: "acme.api.example.com", wantTenant: "acme"},
		{name: "subdomain with port", baseDomain: "api.example.com", host: "acme.api.example.com:8443", wantTenant: "acme"},
		{name: "multi-level subdomain captured whole", baseDomain: "example.com", host: "acme.api.example.com", wantTenant: "acme.api"},
		{name: "no subdomain (bare base domain)", baseDomain: "api.example.com", host: "api.example.com", wantErr: true},
		{name: "host not under base domain", baseDomain: "api.example.com", host: "acme.other.com", wantErr: true},
		{name: "empty tenant before suffix", baseDomain: "api.example.com", host: ".api.example.com", wantErr: true},
		{name: "base domain with port still resolves", baseDomain: "example.com", host: "tenant.example.com:443", wantTenant: "tenant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSubdomainResolver(tt.baseDomain)
			r := newRequest(tt.host, "/")
			got, err := s.Resolve(r)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got tenant %q", got)
				}
				if got != "" {
					t.Errorf("expected empty tenant on error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantTenant {
				t.Errorf("got tenant %q, want %q", got, tt.wantTenant)
			}
		})
	}
}

// --- PathResolver ---

func TestPathResolver_Resolve(t *testing.T) {
	tests := []struct {
		name       string
		segment    int
		path       string
		wantTenant string
		wantErr    bool
	}{
		{name: "first segment", segment: 0, path: "/acme/api/users", wantTenant: "acme"},
		{name: "second segment", segment: 1, path: "/api/globex/users", wantTenant: "globex"},
		{name: "single segment path", segment: 0, path: "/acme", wantTenant: "acme"},
		{name: "root path empty segment", segment: 0, path: "/", wantErr: true},
		{name: "segment out of range", segment: 5, path: "/acme/api", wantErr: true},
		{name: "empty segment in middle", segment: 1, path: "/acme//users", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPathResolver(tt.segment)
			r := newRequest("example.com", tt.path)
			got, err := p.Resolve(r)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got tenant %q", got)
				}
				if got != "" {
					t.Errorf("expected empty tenant on error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantTenant {
				t.Errorf("got tenant %q, want %q", got, tt.wantTenant)
			}
		})
	}
}

// --- ChainResolver ---

func TestChainResolver_Resolve(t *testing.T) {
	t.Run("first resolver wins", func(t *testing.T) {
		// Header present and path present; header is first → header wins.
		chain := NewChainResolver(
			NewHeaderResolver("X-Tenant-ID"),
			NewPathResolver(0),
		)
		r := newRequest("example.com", "/pathtenant/api")
		r.Header.Set("X-Tenant-ID", "headertenant")
		got, err := chain.Resolve(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "headertenant" {
			t.Errorf("got %q, want headertenant", got)
		}
	})

	t.Run("falls through to second resolver", func(t *testing.T) {
		// Header missing → falls through to path resolver.
		chain := NewChainResolver(
			NewHeaderResolver("X-Tenant-ID"),
			NewPathResolver(0),
		)
		r := newRequest("example.com", "/pathtenant/api")
		got, err := chain.Resolve(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "pathtenant" {
			t.Errorf("got %q, want pathtenant", got)
		}
	})

	t.Run("none match returns last error", func(t *testing.T) {
		chain := NewChainResolver(
			NewHeaderResolver("X-Tenant-ID"),
			NewSubdomainResolver("api.example.com"),
		)
		r := newRequest("other.com", "/")
		got, err := chain.Resolve(r)
		if err == nil {
			t.Fatalf("expected error, got tenant %q", got)
		}
		if got != "" {
			t.Errorf("expected empty tenant, got %q", got)
		}
	})

	t.Run("empty chain returns error", func(t *testing.T) {
		chain := NewChainResolver()
		r := newRequest("example.com", "/acme")
		got, err := chain.Resolve(r)
		if err == nil {
			t.Fatalf("expected error for empty chain, got tenant %q", got)
		}
		if got != "" {
			t.Errorf("expected empty tenant, got %q", got)
		}
	})

	t.Run("single resolver success", func(t *testing.T) {
		chain := NewChainResolver(NewPathResolver(0))
		r := newRequest("example.com", "/solo/x")
		got, err := chain.Resolve(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "solo" {
			t.Errorf("got %q, want solo", got)
		}
	})
}

// --- Registry ---

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	p := &fakeProvider{name: "keycloak", issuer: "https://kc.example.com"}
	reg.Register("acme", p)

	got, err := reg.Get("acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != p {
		t.Errorf("Get returned different provider instance")
	}
}

func TestRegistry_GetUnknown(t *testing.T) {
	reg := NewRegistry()
	got, err := reg.Get("missing")
	if err == nil {
		t.Fatalf("expected error for unknown tenant")
	}
	if got != nil {
		t.Errorf("expected nil provider, got %v", got)
	}
}

func TestRegistry_Overwrite(t *testing.T) {
	// Re-registering the same tenant ID replaces the provider.
	reg := NewRegistry()
	p1 := &fakeProvider{name: "first"}
	p2 := &fakeProvider{name: "second"}
	reg.Register("acme", p1)
	reg.Register("acme", p2)

	got, err := reg.Get("acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != p2 {
		t.Errorf("expected overwrite to second provider, got %v", got.Name())
	}
	if len(reg.List()) != 1 {
		t.Errorf("expected 1 tenant after overwrite, got %d", len(reg.List()))
	}
}

func TestRegistry_List(t *testing.T) {
	reg := NewRegistry()

	t.Run("empty registry", func(t *testing.T) {
		if len(reg.List()) != 0 {
			t.Errorf("expected empty list, got %v", reg.List())
		}
	})

	t.Run("lists all registered", func(t *testing.T) {
		reg.Register("acme", &fakeProvider{})
		reg.Register("globex", &fakeProvider{})
		reg.Register("initech", &fakeProvider{})

		ids := reg.List()
		sort.Strings(ids)
		want := []string{"acme", "globex", "initech"}
		if len(ids) != len(want) {
			t.Fatalf("got %d ids %v, want %d", len(ids), ids, len(want))
		}
		for i := range want {
			if ids[i] != want[i] {
				t.Errorf("ids[%d] = %q, want %q", i, ids[i], want[i])
			}
		}
	})
}

func TestRegistry_Unregister(t *testing.T) {
	reg := NewRegistry()
	reg.Register("acme", &fakeProvider{})
	reg.Register("globex", &fakeProvider{})

	reg.Unregister("acme")

	if _, err := reg.Get("acme"); err == nil {
		t.Error("expected error getting unregistered tenant")
	}
	if _, err := reg.Get("globex"); err != nil {
		t.Errorf("globex should remain registered: %v", err)
	}

	// Unregister non-existent tenant is a no-op (must not panic).
	reg.Unregister("nonexistent")
}

func TestRegistry_RefreshAll(t *testing.T) {
	t.Run("all succeed returns empty error map", func(t *testing.T) {
		reg := NewRegistry()
		p1 := &fakeProvider{name: "p1"}
		p2 := &fakeProvider{name: "p2"}
		reg.Register("acme", p1)
		reg.Register("globex", p2)

		errs := reg.RefreshAll(context.Background())
		if len(errs) != 0 {
			t.Errorf("expected no errors, got %v", errs)
		}
		if p1.refreshCalls != 1 || p2.refreshCalls != 1 {
			t.Errorf("expected each provider refreshed once, got p1=%d p2=%d", p1.refreshCalls, p2.refreshCalls)
		}
	})

	t.Run("collects errors keyed by tenant", func(t *testing.T) {
		reg := NewRegistry()
		boom := errors.New("refresh failed")
		good := &fakeProvider{name: "good"}
		bad := &fakeProvider{name: "bad", refreshErr: boom}
		reg.Register("ok", good)
		reg.Register("fail", bad)

		errs := reg.RefreshAll(context.Background())
		if len(errs) != 1 {
			t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
		}
		if !errors.Is(errs["fail"], boom) {
			t.Errorf("expected error for tenant 'fail' to wrap boom, got %v", errs["fail"])
		}
		if _, ok := errs["ok"]; ok {
			t.Error("did not expect error for successful tenant 'ok'")
		}
	})

	t.Run("empty registry returns empty map", func(t *testing.T) {
		reg := NewRegistry()
		errs := reg.RefreshAll(context.Background())
		if len(errs) != 0 {
			t.Errorf("expected empty error map, got %v", errs)
		}
	})
}

// --- session.go context helpers ---

func TestTenantContext(t *testing.T) {
	t.Run("set then get", func(t *testing.T) {
		ctx := WithTenantID(context.Background(), "acme")
		got, ok := TenantIDFromContext(ctx)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got != "acme" {
			t.Errorf("got %q, want acme", got)
		}
	})

	t.Run("empty context returns not found", func(t *testing.T) {
		got, ok := TenantIDFromContext(context.Background())
		if ok {
			t.Errorf("expected ok=false for empty context, got tenant %q", got)
		}
		if got != "" {
			t.Errorf("expected empty tenant, got %q", got)
		}
	})

	t.Run("empty string value treated as not found", func(t *testing.T) {
		// TenantIDFromContext returns ok only when id != "".
		ctx := WithTenantID(context.Background(), "")
		got, ok := TenantIDFromContext(ctx)
		if ok {
			t.Errorf("expected ok=false for empty tenant value, got %q", got)
		}
	})

	t.Run("overwrite in context", func(t *testing.T) {
		ctx := WithTenantID(context.Background(), "acme")
		ctx = WithTenantID(ctx, "globex")
		got, ok := TenantIDFromContext(ctx)
		if !ok || got != "globex" {
			t.Errorf("got %q ok=%v, want globex true", got, ok)
		}
	})
}
