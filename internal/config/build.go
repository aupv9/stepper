package config

import (
	"fmt"

	"github.com/common-iam/iam/pkg/providers"
	"github.com/common-iam/iam/pkg/providers/auth0"
	"github.com/common-iam/iam/pkg/providers/generic"
	"github.com/common-iam/iam/pkg/providers/keycloak"
	"github.com/common-iam/iam/pkg/providers/localjwt"
	"github.com/common-iam/iam/pkg/tenant"
)

// BuildProvider constructs the provider adapter for one tenant declaration,
// wrapping it with local JWT validation when validation: jwt is configured.
// The caller is responsible for calling RefreshConfig before serving traffic.
func BuildProvider(t Tenant) (providers.Provider, error) {
	var inner localjwt.InnerProvider
	switch t.Provider {
	case "generic", "":
		inner = generic.New(generic.Config{
			DiscoveryURL: t.DiscoveryURL,
			ClientID:     t.ClientID,
			ClientSecret: t.ClientSecret,
		})
	case "keycloak":
		inner = keycloak.New(keycloak.Config{
			BaseURL:      t.BaseURL,
			Realm:        t.Realm,
			ClientID:     t.ClientID,
			ClientSecret: t.ClientSecret,
		})
	case "auth0":
		inner = auth0.New(auth0.Config{
			Domain:       t.Domain,
			Audience:     t.Audience,
			ClientID:     t.ClientID,
			ClientSecret: t.ClientSecret,
		})
	default:
		return nil, fmt.Errorf("unknown provider %q", t.Provider)
	}

	if t.Validation == "jwt" {
		return localjwt.New(inner, localjwt.Config{ExpectedAudience: t.Audience}), nil
	}
	return inner, nil
}

// BuildResolver constructs the tenant resolution chain. An empty declaration
// yields the default chain: X-Tenant-ID header, then static default tenant.
func BuildResolver(rs []Resolver, defaultTenant string) tenant.Resolver {
	if len(rs) == 0 {
		return tenant.NewChainResolver(
			tenant.NewHeaderResolver("X-Tenant-ID"),
			tenant.NewStaticResolver(defaultTenant),
		)
	}
	chain := make([]tenant.Resolver, 0, len(rs))
	for _, r := range rs {
		switch r.Type {
		case "header":
			chain = append(chain, tenant.NewHeaderResolver(r.Header))
		case "subdomain":
			chain = append(chain, tenant.NewSubdomainResolver(r.BaseDomain))
		case "path":
			chain = append(chain, tenant.NewPathResolver(r.Segment))
		case "static":
			chain = append(chain, tenant.NewStaticResolver(r.Tenant))
		}
	}
	return tenant.NewChainResolver(chain...)
}
