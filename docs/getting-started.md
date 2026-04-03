# Getting Started

## Prerequisites

- Go 1.25+
- A running Identity Provider (Keycloak, Auth0, or any OIDC-compatible AS)
- Redis (optional, for distributed token caching)

---

## Option A: Use as a Go Library

### 1. Install

```bash
go get github.com/common-iam/iam
```

### 2. Minimal setup (net/http)

```go
package main

import (
    "context"
    "net/http"

    "github.com/common-iam/iam/pkg/core/policy"
    iamstdlib "github.com/common-iam/iam/pkg/middleware/stdlib"
    "github.com/common-iam/iam/pkg/providers/keycloak"
)

func main() {
    ctx := context.Background()

    // Create provider
    provider := keycloak.New(keycloak.Config{
        BaseURL:      "https://keycloak.example.com",
        Realm:        "myrealm",
        ClientID:     "my-rs",
        ClientSecret: "secret",
    })
    if err := provider.RefreshConfig(ctx); err != nil {
        panic(err)
    }

    // Load policies
    policyCfg, err := policy.LoadFromFile("policy.yaml")
    if err != nil {
        panic(err)
    }
    engine := policy.New(policyCfg)

    // Build middleware
    iam := iamstdlib.Middleware(iamstdlib.Config{
        Provider:     provider,
        PolicyEngine: engine,
        Realm:        "MyApp",
    })

    // Apply to routes
    mux := http.NewServeMux()
    mux.HandleFunc("/api/hello", func(w http.ResponseWriter, r *http.Request) {
        claims, _ := iamstdlib.ClaimsFromContext(r.Context())
        w.Write([]byte("Hello, " + claims.Subject))
    })

    http.ListenAndServe(":8080", iam(mux))
}
```

### 3. With Gin

```go
import iamgin "github.com/common-iam/iam/pkg/middleware/gin"

r := gin.New()
r.Use(iamgin.Middleware(iamgin.Config{
    Provider:     provider,
    PolicyEngine: engine,
    Realm:        "MyApp",
}))

r.GET("/api/hello", func(c *gin.Context) {
    claims, _ := iamgin.ClaimsFromContext(c)
    c.JSON(200, gin.H{"subject": claims.Subject, "acr": claims.ACR})
})
```

### 4. With Echo

```go
import iamecho "github.com/common-iam/iam/pkg/middleware/echo"

e := echo.New()
e.Use(iamecho.Middleware(iamecho.Config{
    Provider:     provider,
    PolicyEngine: engine,
    Realm:        "MyApp",
}))

e.GET("/api/hello", func(c echo.Context) error {
    claims, _ := iamecho.ClaimsFromContext(c)
    return c.JSON(200, map[string]string{"subject": claims.Subject})
})
```

---

## Option B: Standalone Gateway (Sidecar)

Deploy `iam-service` in front of your backend. Your backend receives only authenticated, policy-checked requests.

### docker-compose

```yaml
services:
  iam-service:
    image: common-iam:latest
    ports:
      - "8080:8080"
    environment:
      IAM_UPSTREAM_URL: "http://your-backend:3000"
      IAM_POLICY_FILE: "/config/policy.yaml"
      IAM_REALM: "MyApp"
    volumes:
      - ./policy.yaml:/config/policy.yaml:ro

  your-backend:
    image: your-backend:latest
    # No longer exposed externally — only through IAM
```

Your backend at port 3000 only needs to trust that `X-Tenant-ID` and `Authorization` headers have been validated.

---

## Your First Policy File

Create `policy.yaml`:

```yaml
version: "1"
realm: "MyApp"

acr_levels:
  - "urn:mace:incommon:iap:bronze"   # password only
  - "urn:mace:incommon:iap:silver"   # + step-up or MFA
  - "urn:mace:incommon:iap:gold"     # + hardware key / strongest MFA

policies:
  - name: public
    enabled: true
    resources: [/api/public/**]
    methods: [GET]

  - name: authenticated
    enabled: true
    resources: [/api/**]
    require_acr: "urn:mace:incommon:iap:bronze"
    require_scopes: [openid]

  - name: payments
    enabled: true
    resources: [/api/payments/**]
    methods: [POST, PUT, DELETE]
    require_acr: "urn:mace:incommon:iap:silver"
    max_age: 300
```

---

## Verify Policy with CLI

```bash
# Should be ALLOWED
go run cmd/iam-cli/main.go test-policy \
  -c policy.yaml -m POST -p /api/payments/pay \
  -a "urn:mace:incommon:iap:silver" -s "openid"

# Should be DENIED (bronze < silver)
go run cmd/iam-cli/main.go test-policy \
  -c policy.yaml -m POST -p /api/payments/pay \
  -a "urn:mace:incommon:iap:bronze" -s "openid"
```

> **Windows note:** Prefix path arguments with `MSYS_NO_PATHCONV=1` to prevent Git Bash from converting `/api/...` to a Windows path.

---

## What Happens on a Policy Denial

When a request doesn't meet the policy requirements, the middleware returns:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="MyApp",
  error="insufficient_user_authentication",
  acr_values="urn:mace:incommon:iap:silver",
  max_age=300
Content-Type: application/json

{
  "error": "insufficient_user_authentication",
  "error_description": "higher authentication level required"
}
```

Your client should read the `WWW-Authenticate` header, redirect to the AS with the `acr_values` and `max_age` hints, obtain a new token, then retry the request.

---

## Next Steps

- [Policy Configuration](policy-configuration.md) — full policy YAML reference
- [Providers](providers.md) — Keycloak, Auth0, custom OIDC setup
- [DevKit](devkit.md) — testing without a real AS
