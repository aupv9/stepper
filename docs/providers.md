# Identity Providers

Providers connect `common-iam` to your Authorization Server. All providers implement the `providers.Provider` interface and expose token introspection, JWKS fetching, and OIDC discovery refresh.

---

## Provider Interface

```go
type Provider interface {
    Introspect(ctx context.Context, rawToken string) (*token.CommonClaims, error)
    JWKS(ctx context.Context) ([]byte, error)
    RefreshConfig(ctx context.Context) error
    Name() string
    Issuer() string
}
```

---

## Keycloak

```go
import "github.com/common-iam/iam/pkg/providers/keycloak"

provider := keycloak.New(keycloak.Config{
    BaseURL:      "https://keycloak.example.com",
    Realm:        "myrealm",
    ClientID:     "my-resource-server",
    ClientSecret: "client-secret",
})

// Must call before first use — fetches OIDC discovery document
if err := provider.RefreshConfig(context.Background()); err != nil {
    log.Fatal(err)
}
```

**Discovery URL built automatically:** `{BaseURL}/realms/{Realm}/.well-known/openid-configuration`

**Keycloak-specific claims mapping:**
- `realm_access.roles` → `CommonClaims.Roles`
- `preferred_username` → `CommonClaims.Username`
- `sid` → `CommonClaims.SessionID`

---

## Auth0

```go
import "github.com/common-iam/iam/pkg/providers/auth0"

provider := auth0.New(auth0.Config{
    Domain:       "myapp.us.auth0.com",
    ClientID:     "machine-to-machine-client-id",
    ClientSecret: "client-secret",
    Audience:     "https://api.myapp.com",  // your API identifier
})

if err := provider.RefreshConfig(context.Background()); err != nil {
    log.Fatal(err)
}
```

**Discovery URL built automatically:** `https://{Domain}/.well-known/openid-configuration`

**Auth0-specific claims mapping:**
- `https://myapp.com/roles` (namespaced custom claim) → `CommonClaims.Roles`
- `org_id` → `CommonClaims.TenantID`
- `nickname` → `CommonClaims.Username` (fallback)

---

## Generic OIDC

Use for any OIDC-compliant provider (Google, Microsoft Entra ID, Okta, Ping Identity, etc.):

```go
import "github.com/common-iam/iam/pkg/providers/generic"

provider := generic.New(generic.Config{
    DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
    ClientID:     "my-client-id",
    ClientSecret: "my-client-secret",
})

if err := provider.RefreshConfig(context.Background()); err != nil {
    log.Fatal(err)
}
```

**Other examples:**
```go
// Microsoft Entra ID (Azure AD)
DiscoveryURL: "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"

// Okta
DiscoveryURL: "https://dev-xxxxx.okta.com/.well-known/openid-configuration"

// Ping Identity
DiscoveryURL: "https://auth.pingone.com/{envId}/as/.well-known/openid-configuration"
```

---

## CommonClaims — Normalized Output

All providers return `*token.CommonClaims`, regardless of provider-specific differences:

```go
type CommonClaims struct {
    Subject   string        // "sub"
    Issuer    string        // "iss"
    Audience  []string      // "aud"
    ExpiresAt time.Time
    IssuedAt  time.Time
    ACR       string        // Authentication Context Class Reference
    AMR       []string      // Authentication Methods References (["pwd"], ["mfa", "otp"])
    SessionID string        // "sid"
    AuthTime  time.Time     // when the user actually authenticated (for max_age)
    Email     string
    Username  string
    Roles     []string      // normalized from realm_access.roles, /roles, etc.
    Scopes    []string      // from "scope" claim
    TenantID  string        // from tenant_id / org_id / tid
    Active    bool          // from introspection "active" field
    Extra     map[string]interface{}  // all other claims
}
```

### Useful helpers on CommonClaims

```go
claims.AuthAge()          // time.Duration since auth_time
claims.HasScope("write")  // check if scope present
claims.HasRole("admin")   // check if role present
```

---

## Periodic Config Refresh

OIDC provider keys rotate. Schedule `RefreshConfig` periodically to keep JWKS and endpoints up to date:

```go
go func() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    for range ticker.C {
        if err := provider.RefreshConfig(context.Background()); err != nil {
            slog.Error("failed to refresh provider config", "error", err)
        }
    }
}()
```

For multi-tenant setups, use the Registry's bulk refresh:

```go
// RefreshAll refreshes all registered tenant providers
errs := registry.RefreshAll(context.Background())
for tenantID, err := range errs {
    slog.Error("refresh failed", "tenant", tenantID, "error", err)
}
```

---

## Writing a Custom Provider

Implement the `Provider` interface to support any AS:

```go
package myprovider

import (
    "context"
    "github.com/common-iam/iam/pkg/core/token"
    "github.com/common-iam/iam/pkg/providers"
)

type MyProvider struct{ /* ... */ }

func (p *MyProvider) Name() string   { return "my-provider" }
func (p *MyProvider) Issuer() string { return "https://my-as.example.com" }

func (p *MyProvider) RefreshConfig(ctx context.Context) error {
    // fetch discovery document, update introspection endpoint, etc.
    return nil
}

func (p *MyProvider) Introspect(ctx context.Context, rawToken string) (*token.CommonClaims, error) {
    // call your AS introspection endpoint
    // use providers.MapToCommon(rawClaims) to normalize
    return providers.MapToCommon(rawClaims), nil
}

func (p *MyProvider) JWKS(ctx context.Context) ([]byte, error) {
    // return JWKS JSON bytes
    return jwksBytes, nil
}
```

Then register it:

```go
registry.Register("my-tenant", &myprovider.MyProvider{})
```

---

## Token Caching

Wrap any provider with caching to reduce load on your AS:

```go
import (
    "github.com/common-iam/iam/pkg/core/token"
    "github.com/redis/go-redis/v9"
)

// In-memory cache (single instance)
cache := token.NewMemoryCache()

// OR Redis cache (distributed)
rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
cache := token.NewRedisCache(rdb, "iam:token:")   // custom key prefix

// Wrap introspector
introspector := token.NewIntrospector(token.IntrospectorConfig{
    Endpoint:     "https://as.example.com/introspect",
    ClientID:     "rs-client",
    ClientSecret: "secret",
})
cached := token.NewCachedIntrospector(introspector, cache, 30*time.Second)
```

The default TTL of 30 seconds balances performance vs. revocation latency.
