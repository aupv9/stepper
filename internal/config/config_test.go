package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "iam.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Addr != ":8080" || cfg.Realm != "IAM" || cfg.DefaultTenant != "default" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestLoad_FileAndEnvOverride(t *testing.T) {
	path := writeTemp(t, `
addr: ":9090"
realm: "FileRealm"
log_format: "json"
tenants:
  - id: "acme"
    provider: "generic"
    discovery_url: "https://as.acme.example/.well-known/openid-configuration"
resolvers:
  - type: "header"
    header: "X-Org"
  - type: "static"
    tenant: "acme"
`)
	t.Setenv("IAM_REALM", "EnvRealm") // env must win over file

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Addr != ":9090" {
		t.Errorf("addr = %q, want :9090 (from file)", cfg.Addr)
	}
	if cfg.Realm != "EnvRealm" {
		t.Errorf("realm = %q, want EnvRealm (env wins)", cfg.Realm)
	}
	if len(cfg.Tenants) != 1 || cfg.Tenants[0].ID != "acme" {
		t.Errorf("tenants = %+v", cfg.Tenants)
	}
	if len(cfg.Resolvers) != 2 || cfg.Resolvers[0].Header != "X-Org" {
		t.Errorf("resolvers = %+v", cfg.Resolvers)
	}
}

func TestLoad_OIDCEnvCreatesDefaultTenant(t *testing.T) {
	t.Setenv("IAM_OIDC_DISCOVERY_URL", "https://as.example/.well-known/openid-configuration")
	t.Setenv("IAM_OIDC_CLIENT_ID", "cid")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Tenants) != 1 || cfg.Tenants[0].ID != "default" || cfg.Tenants[0].ClientID != "cid" {
		t.Errorf("tenants = %+v", cfg.Tenants)
	}
}

func TestValidate_Errors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"duplicate tenant id", `
tenants:
  - {id: a, provider: generic, discovery_url: "https://x"}
  - {id: a, provider: generic, discovery_url: "https://y"}
`},
		{"missing tenant id", `
tenants:
  - {provider: generic, discovery_url: "https://x"}
`},
		{"unknown provider", `
tenants:
  - {id: a, provider: okta, discovery_url: "https://x"}
`},
		{"generic without discovery_url", `
tenants:
  - {id: a, provider: generic}
`},
		{"keycloak without realm", `
tenants:
  - {id: a, provider: keycloak, base_url: "https://kc"}
`},
		{"auth0 without domain", `
tenants:
  - {id: a, provider: auth0}
`},
		{"unknown resolver", `
resolvers:
  - {type: magic}
`},
		{"static resolver without tenant", `
resolvers:
  - {type: static}
`},
		{"jwt validation without audience", `
tenants:
  - {id: a, provider: generic, discovery_url: "https://x", validation: jwt}
`},
		{"cert without key", `
tls:
  cert_file: "/x.crt"
`},
		{"client CA without cert", `
tls:
  client_ca_file: "/ca.crt"
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, tt.yaml)); err == nil {
				t.Errorf("expected validation error for %s", tt.name)
			}
		})
	}
}

func TestBuildResolver_DefaultChain(t *testing.T) {
	r := BuildResolver(nil, "solo")
	// A request with no headers must fall through to the static default.
	req := newRequest(t)
	id, err := r.Resolve(req)
	if err != nil || id != "solo" {
		t.Errorf("Resolve = %q, %v; want solo", id, err)
	}
}

func TestBuildProvider_AllTypes(t *testing.T) {
	for _, tc := range []Tenant{
		{ID: "g", Provider: "generic", DiscoveryURL: "https://x"},
		{ID: "k", Provider: "keycloak", BaseURL: "https://kc", Realm: "r"},
		{ID: "a", Provider: "auth0", Domain: "d.auth0.com"},
	} {
		p, err := BuildProvider(tc)
		if err != nil || p == nil {
			t.Errorf("BuildProvider(%s): %v", tc.Provider, err)
		}
	}
	if _, err := BuildProvider(Tenant{ID: "x", Provider: "nope"}); err == nil {
		t.Error("unknown provider must error")
	}
}
