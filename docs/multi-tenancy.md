# Multi-Tenancy

`common-iam` supports multi-tenant architectures where each tenant uses its own Identity Provider (different Keycloak realm, different Auth0 tenant, etc.).

---

## Core Concepts

| Component | Role |
|---|---|
| `TenantResolver` | Determines **which tenant** a request belongs to |
| `Registry` | Stores **provider per tenant** (thread-safe) |
| `session.go` | Propagates tenant ID through `context.Context` |

---

## Step 1: Choose a TenantResolver

### Header-based (simplest)

```go
import "github.com/common-iam/iam/pkg/tenant"

resolver := tenant.NewHeaderResolver("X-Tenant-ID")
// Request must include: X-Tenant-ID: acme
```

### Subdomain-based

```go
resolver := tenant.NewSubdomainResolver("api.example.com")
// acme.api.example.com → tenantID = "acme"
// corp.api.example.com → tenantID = "corp"
```

### Path-based

```go
resolver := tenant.NewPathResolver(0)
// /acme/api/users → tenantID = "acme"  (segment 0)
// /corp/api/users → tenantID = "corp"
```

### Chain (try multiple strategies)

```go
resolver := tenant.NewChainResolver(
    tenant.NewHeaderResolver("X-Tenant-ID"),   // try header first
    tenant.NewSubdomainResolver("api.myapp.com"), // fallback to subdomain
)
```

---

## Step 2: Build the Registry

```go
import (
    "github.com/common-iam/iam/pkg/tenant"
    "github.com/common-iam/iam/pkg/providers/keycloak"
    "github.com/common-iam/iam/pkg/providers/auth0"
)

registry := tenant.NewRegistry()

// Register Keycloak tenants
registry.Register("acme", keycloak.New(keycloak.Config{
    BaseURL:      "https://keycloak.acme.com",
    Realm:        "acme-prod",
    ClientID:     "resource-server",
    ClientSecret: os.Getenv("ACME_KC_SECRET"),
}))

// Register Auth0 tenants
registry.Register("corp", auth0.New(auth0.Config{
    Domain:       "corp.us.auth0.com",
    ClientID:     os.Getenv("CORP_AUTH0_CLIENT_ID"),
    ClientSecret: os.Getenv("CORP_AUTH0_SECRET"),
}))

// Initialize all providers
ctx := context.Background()
errs := registry.RefreshAll(ctx)
for tenantID, err := range errs {
    log.Printf("provider init failed for tenant %s: %v", tenantID, err)
}
```

---

## Step 3: Wire into Gateway

The `Gateway Guard` handles tenant resolution + provider dispatch automatically:

```go
import "github.com/common-iam/iam/internal/gateway"

guard := gateway.NewGuard(gateway.GuardConfig{
    Registry:     registry,
    Resolver:     resolver,
    PolicyEngine: engine,
    Realm:        "MyApp",
    Upstream:     yourHandler,
})
```

Each request:
1. Resolver extracts `tenantID` from request
2. Registry looks up the correct provider
3. Introspection happens against that tenant's AS
4. `tenantID` is stored in `context.Context`

---

## Reading TenantID in Handlers

```go
import "github.com/common-iam/iam/pkg/tenant"

func myHandler(w http.ResponseWriter, r *http.Request) {
    tenantID, ok := tenant.TenantIDFromContext(r.Context())
    if !ok {
        // single-tenant or tenant not resolved
    }
    // Use tenantID for data isolation
    db.QueryWithTenant(tenantID, "SELECT * FROM users")
}
```

---

## Dynamic Tenant Registration

Add/remove tenants at runtime without restarting:

```go
// Add a new tenant
newProvider := keycloak.New(keycloak.Config{...})
newProvider.RefreshConfig(ctx)
registry.Register("new-tenant", newProvider)

// Remove a tenant
registry.Unregister("old-tenant")

// List all tenants (for admin API)
tenants := registry.List()
```

---

## Periodic Refresh

OIDC provider configurations can change (key rotation, endpoint changes). Schedule periodic refresh:

```go
go func() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    for range ticker.C {
        errs := registry.RefreshAll(context.Background())
        for id, err := range errs {
            slog.Error("provider refresh failed", "tenant", id, "error", err)
        }
    }
}()
```

---

## Session Isolation

Each tenant's data is isolated via the context. The `TenantIDFromContext` function provides the tenant boundary for your data layer:

```go
// Example: per-tenant database connection pool
type TenantDB struct {
    pools map[string]*sql.DB
}

func (t *TenantDB) ForRequest(ctx context.Context) (*sql.DB, error) {
    tenantID, ok := tenant.TenantIDFromContext(ctx)
    if !ok {
        return t.pools["default"], nil
    }
    pool, exists := t.pools[tenantID]
    if !exists {
        return nil, fmt.Errorf("no database for tenant %s", tenantID)
    }
    return pool, nil
}
```

---

## Example: Full Multi-Tenant Setup

```go
func setupMultiTenant() http.Handler {
    registry := tenant.NewRegistry()

    tenantConfigs := []struct {
        id       string
        provider providers.Provider
    }{
        {"acme", keycloak.New(keycloak.Config{BaseURL: "...", Realm: "acme"})},
        {"corp", auth0.New(auth0.Config{Domain: "corp.auth0.com"})},
        {"startup", generic.New(generic.Config{DiscoveryURL: "https://startup-idp.com/.well-known/openid-configuration"})},
    }

    for _, tc := range tenantConfigs {
        tc.provider.RefreshConfig(context.Background())
        registry.Register(tc.id, tc.provider)
    }

    // Resolve by subdomain: acme.api.myapp.com → "acme"
    resolver := tenant.NewChainResolver(
        tenant.NewSubdomainResolver("api.myapp.com"),
        tenant.NewHeaderResolver("X-Tenant-ID"),  // fallback for local dev
    )

    policyCfg, _ := policy.LoadFromFile("policy.yaml")
    engine := policy.New(policyCfg)

    return gateway.NewGuard(gateway.GuardConfig{
        Registry:     registry,
        Resolver:     resolver,
        PolicyEngine: engine,
        Realm:        "MyApp",
        Upstream:     yourBackendHandler,
    })
}
```
