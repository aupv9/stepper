# common-iam

Reusable Go library + standalone gateway implementing **RFC 9470 OAuth 2.0 Step Up Authentication Challenge Protocol** — cùng với toàn bộ IAM stack xung quanh.

> **Mục tiêu:** Build IAM một lần, tái sử dụng mãi mãi. Mỗi dự án mới cần auth chỉ cần cấu hình — không build lại từ đầu.

---

## Tính năng

| Tính năng | RFC | Mô tả |
|---|---|---|
| Step-up auth challenge | RFC 9470 | Phát `WWW-Authenticate` yêu cầu ACR level cao hơn |
| Token introspection | RFC 7662 | Validate token qua AS endpoint |
| Token cache | — | Redis / in-memory, TTL 30s mặc định |
| Token revocation webhook | RFC 7009 | Nhận và xử lý revocation events |
| DPoP proof-of-possession | RFC 9449 | Bind token với client key pair |
| Policy-as-config | — | YAML policy, hot-reload không cần restart |
| Multi-tenant | — | Mỗi tenant một AS riêng |
| Gin / Echo / stdlib | — | Middleware cho 3 framework phổ biến nhất |
| Observability | RFC 8417 | slog + Prometheus + OpenTelemetry + audit events |
| DevKit | — | LocalAS mock, TestTokenFactory, PolicySimulator, CLI |

---

## Hai cách dùng

### Cách 1 — Library: nhúng vào service Go của bạn

```go
import (
    iamgin "github.com/common-iam/iam/pkg/middleware/gin"
    "github.com/common-iam/iam/pkg/core/policy"
    "github.com/common-iam/iam/pkg/providers/keycloak"
)

provider := keycloak.New(keycloak.Config{
    BaseURL:      "https://keycloak.example.com",
    Realm:        "myrealm",
    ClientID:     "my-resource-server",
    ClientSecret: os.Getenv("KC_SECRET"),
})
provider.RefreshConfig(ctx)

policyCfg, _ := policy.LoadFromFile("policy.yaml")
engine := policy.New(policyCfg)

r := gin.New()
r.Use(iamgin.Middleware(iamgin.Config{
    Provider:     provider,
    PolicyEngine: engine,
    Realm:        "MyApp",
}))
```

### Cách 2 — Gateway: đặt trước backend, auth tập trung

```
Internet → [IAM Gateway :8080] → [Backend :3000]
```

```bash
IAM_UPSTREAM_URL=http://backend:3000 \
IAM_OIDC_DISCOVERY_URL=https://keycloak.example.com/realms/prod/.well-known/openid-configuration \
IAM_OIDC_CLIENT_ID=iam-rs \
IAM_OIDC_CLIENT_SECRET=secret \
./iam-service
```

Backend **không cần** xử lý auth — mọi request đến backend đã được xác thực.

---

## Quickstart — 5 phút

### 1. Build

```bash
git clone https://github.com/common-iam/iam.git
cd iam
go build -o iam-service ./cmd/iam-service/
go build -o iam-cli    ./cmd/iam-cli/
```

### 2. Chạy dev mode (không cần Keycloak/Auth0)

Service tự khởi động **LocalAS** bên trong:

```bash
./iam-service
```

Output:
```
level=INFO msg="policy loaded" file=config/policy.example.yaml policies=5
level=INFO msg="LocalAS running (dev mode)" url=http://127.0.0.1:XXXXX
level=INFO msg="demo token ready" token=eyJhbGci...
level=INFO msg="ready" addr=:8080
```

### 3. Test

Copy token từ log, thay vào `$TOKEN`:

```bash
# Health check
curl http://localhost:8080/health
# {"status":"ok"}

# Không có token → 401 + WWW-Authenticate
curl -i http://localhost:8080/api/payments/charge
# HTTP/1.1 401
# Www-Authenticate: Bearer realm="IAM", error="invalid_token", ...

# Token hợp lệ (silver ACR + payments:write) → 200
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/payments/charge
# {"message":"auth passed","path":"/api/payments/charge","method":"GET"}

# Admin route cần gold ACR → RFC 9470 step-up
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin/users
# HTTP/1.1 401
# Www-Authenticate: Bearer error="insufficient_user_authentication",
#   acr_values="urn:mace:incommon:iap:gold", max_age=900

# Admin API: xem policy đang chạy
curl http://localhost:8080/admin/policy/summary

# Admin API: danh sách tenants
curl http://localhost:8080/admin/tenants
# {"count":1,"tenants":["default"]}
```

---

## Environment Variables

| Biến | Mặc định | Mô tả |
|---|---|---|
| `IAM_ADDR` | `:8080` | HTTP listen address |
| `IAM_REALM` | `IAM` | Realm trong WWW-Authenticate header |
| `IAM_POLICY_FILE` | `config/policy.example.yaml` | Đường dẫn policy YAML |
| `IAM_UPSTREAM_URL` | _(trống)_ | URL backend để reverse proxy. Trống = echo auth result |
| `IAM_LOG_FORMAT` | `text` | `text` hoặc `json` |
| `IAM_OIDC_DISCOVERY_URL` | _(trống)_ | OIDC discovery URL. **Trống = dev mode (LocalAS)** |
| `IAM_OIDC_CLIENT_ID` | _(trống)_ | Client ID cho introspection endpoint |
| `IAM_OIDC_CLIENT_SECRET` | _(trống)_ | Client Secret |

---

## Policy Configuration

```yaml
version: "1"
realm: "MyApp"

# Thứ tự quan trọng: index cao hơn = bảo đảm cao hơn
acr_levels:
  - "urn:mace:incommon:iap:bronze"   # password only
  - "urn:mace:incommon:iap:silver"   # soft MFA / step-up
  - "urn:mace:incommon:iap:gold"     # hardware key / strongest MFA

policies:
  # Không có require_acr → ai cũng truy cập được
  - name: public
    enabled: true
    resources: [/api/public/**, /health]

  # Yêu cầu silver ACR + fresh auth (5 phút) + đúng scope
  - name: payments-write
    enabled: true
    resources: [/api/payments/**]
    methods: [POST, PUT, DELETE]
    require_acr: "urn:mace:incommon:iap:silver"
    max_age: 300
    require_scopes: [openid, payments:write]

  # Gold ACR + MFA bắt buộc
  - name: admin
    enabled: true
    resources: [/api/admin/**]
    require_acr: "urn:mace:incommon:iap:gold"
    max_age: 900
    require_mfa: true
    require_scopes: [openid, admin]
```

**Nguyên tắc:** Policy đầu tiên match → áp dụng. Không match → ALLOW mặc định.

### Dry-run policy (không cần start service)

```bash
# Linux / macOS
./iam-cli test-policy -c config/policy.example.yaml \
  -m POST -p /api/admin/users \
  -a "urn:mace:incommon:iap:silver" -s "openid admin"
# → ✗ DENIED: ACR "silver" does not satisfy required "gold"

# Windows Git Bash — thêm MSYS_NO_PATHCONV=1 cho path bắt đầu bằng /
MSYS_NO_PATHCONV=1 ./iam-cli.exe test-policy -c config/policy.example.yaml \
  -m POST -p /api/payments/charge \
  -a "urn:mace:incommon:iap:silver" -s "openid payments:write"
# → ✓ ALLOWED [policy: payments-write]
```

### Hot-reload không restart

```bash
curl -X POST http://localhost:8080/admin/policy/reload \
  -H "Content-Type: application/json" \
  -d '{"yaml": "version: \"1\"\nrealm: MyApp\npolicies:\n  ..."}'
```

---

## Provider Setup

### Keycloak

```go
provider := keycloak.New(keycloak.Config{
    BaseURL:      "https://keycloak.example.com",
    Realm:        "myrealm",
    ClientID:     "my-rs",
    ClientSecret: os.Getenv("KC_SECRET"),
})
// Discovery URL tự build: {BaseURL}/realms/{Realm}/.well-known/openid-configuration
provider.RefreshConfig(ctx)
```

### Auth0

```go
provider := auth0.New(auth0.Config{
    Domain:       "myapp.us.auth0.com",
    ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
    ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
})
// Discovery URL tự build: https://{Domain}/.well-known/openid-configuration
provider.RefreshConfig(ctx)
```

### Generic OIDC (Okta, Google, Azure AD, Ping...)

```go
provider := generic.New(generic.Config{
    DiscoveryURL: "https://dev-xxx.okta.com/.well-known/openid-configuration",
    ClientID:     os.Getenv("CLIENT_ID"),
    ClientSecret: os.Getenv("CLIENT_SECRET"),
})
provider.RefreshConfig(ctx)
```

---

## Multi-Tenant

```go
registry := tenant.NewRegistry()
registry.Register("acme", keycloakProvider)   // acme → Keycloak realm riêng
registry.Register("corp", auth0Provider)       // corp → Auth0 tenant riêng

// Phân giải tenant từ request — thử theo thứ tự
resolver := tenant.NewChainResolver(
    tenant.NewSubdomainResolver("api.myapp.com"), // acme.api.myapp.com → "acme"
    tenant.NewHeaderResolver("X-Tenant-ID"),       // fallback: header
)

// Trong handler, đọc tenant context
tenantID, _ := tenant.TenantIDFromContext(r.Context())
```

---

## Middleware

### Gin

```go
r.Use(iamgin.Middleware(iamgin.Config{
    Provider:     provider,
    PolicyEngine: engine,
    Realm:        "MyApp",
}))

r.GET("/api/me", func(c *gin.Context) {
    claims, _ := iamgin.ClaimsFromContext(c)
    // claims.Subject, .ACR, .AMR, .Scopes, .Roles, .TenantID, .AuthAge()
    c.JSON(200, gin.H{"sub": claims.Subject, "acr": claims.ACR})
})
```

### Echo

```go
e.Use(iamecho.Middleware(iamecho.Config{Provider: p, PolicyEngine: e, Realm: "App"}))

e.GET("/api/me", func(c echo.Context) error {
    claims, _ := iamecho.ClaimsFromContext(c)
    return c.JSON(200, map[string]string{"sub": claims.Subject})
})
```

### net/http

```go
mux := http.NewServeMux()
mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
    claims, _ := iamstdlib.ClaimsFromContext(r.Context())
    fmt.Fprintf(w, `{"sub":%q}`, claims.Subject)
})
http.ListenAndServe(":8080", iamstdlib.Middleware(cfg)(mux))
```

---

## CLI Tools

```bash
# Decode JWT — debug nhanh, không cần key
./iam-cli inspect-token <jwt>

# Test policy — không cần start service
./iam-cli test-policy --config policy.yaml \
  --method POST --path /api/admin \
  --acr "urn:mace:incommon:iap:gold" --scopes "openid admin"

# Tạo test JWT (fresh key pair, dev only)
./iam-cli issue-token \
  --subject alice \
  --acr "urn:mace:incommon:iap:silver" \
  --scopes "openid payments:write" \
  --ttl 3600

# Parse WWW-Authenticate step-up header
./iam-cli parse-challenge \
  'Bearer realm="App", error="insufficient_user_authentication", acr_values="urn:mace:incommon:iap:gold", max_age=300'
```

---

## Docker

```bash
# Build image
docker build -f deployments/Dockerfile -t common-iam:latest .

# Dev mode — LocalAS tự boot bên trong
docker run -p 8080:8080 common-iam:latest

# Production — Keycloak + upstream backend
docker run -p 8080:8080 \
  -e IAM_OIDC_DISCOVERY_URL=https://keycloak.example.com/realms/prod/.well-known/openid-configuration \
  -e IAM_OIDC_CLIENT_ID=iam-rs \
  -e IAM_OIDC_CLIENT_SECRET=secret \
  -e IAM_UPSTREAM_URL=http://backend:3000 \
  -e IAM_REALM=MyApp \
  -v $(pwd)/policy.yaml:/app/config/policy.yaml:ro \
  common-iam:latest

# Full stack (IAM + Redis + sample backend)
docker compose -f deployments/docker-compose.yml up
```

---

## Admin API

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/admin/tenants` | Danh sách tenants đang active |
| `GET` | `/admin/policy/summary` | Tóm tắt policy hiện tại |
| `POST` | `/admin/policy/reload` | Hot-reload policy từ YAML body |
| `POST` | `/webhook/revoke` | Nhận token revocation events |

---

## RFC 9470 Flow

```
Client                    IAM Gateway                   Authorization Server
  │                              │                              │
  │── POST /api/payments ───────>│                              │
  │                              │── introspect(token) ────────>│
  │                              │<── {active, acr:"bronze"} ───│
  │                              │                              │
  │                              │  policy: cần acr=silver      │
  │<── 401 ─────────────────────│                              │
  │    Www-Authenticate: Bearer  │                              │
  │      error="insufficient_user_authentication"               │
  │      acr_values="...silver"                                 │
  │      max_age=300             │                              │
  │                              │                              │
  │── /authorize?acr_values=silver&max_age=300 ────────────────>│
  │<── new token (acr:"silver") ────────────────────────────────│
  │                              │                              │
  │── POST /api/payments ───────>│                              │
  │<── 200 OK ──────────────────│                              │
```

---

## Project Structure

```
.
├── cmd/
│   ├── iam-service/        # Standalone gateway binary
│   └── iam-cli/            # Developer CLI binary
├── internal/               # Service internals (không export)
│   ├── admin/              # Admin REST API
│   ├── gateway/            # ResourceServerGuard + reverse proxy
│   └── server/             # HTTP server + router
├── pkg/                    # Public library — import các package này
│   ├── core/
│   │   ├── policy/         # Policy engine: YAML loader, path matcher, evaluator
│   │   ├── stepup/         # RFC 9470: challenge, state machine, error types
│   │   └── token/          # Introspection, cache, revocation webhook, DPoP
│   ├── devkit/
│   │   ├── localas/        # Mock AS (in-process, zero config)
│   │   ├── simulator/      # Policy dry-run
│   │   └── tokenfactory/   # Test JWT generator
│   ├── middleware/
│   │   ├── gin/            # Gin middleware
│   │   ├── echo/           # Echo middleware
│   │   └── stdlib/         # net/http middleware
│   ├── providers/
│   │   ├── keycloak/       # Keycloak adapter
│   │   ├── auth0/          # Auth0 adapter
│   │   ├── generic/        # Generic OIDC (discovery-based)
│   │   └── claims_mapper.go
│   ├── telemetry/          # slog, Prometheus, OTel, audit
│   └── tenant/             # Resolver, Registry, session context
├── config/
│   └── policy.example.yaml
└── deployments/
    ├── Dockerfile
    └── docker-compose.yml
```

---

## Docs

| | |
|---|---|
| [Getting Started](docs/getting-started.md) | Cài đặt, ví dụ đầu tiên |
| [Policy Configuration](docs/policy-configuration.md) | YAML reference đầy đủ |
| [Providers](docs/providers.md) | Keycloak, Auth0, Generic OIDC, custom |
| [Middleware](docs/middleware.md) | Gin, Echo, stdlib, client-side step-up |
| [Multi-Tenancy](docs/multi-tenancy.md) | Resolver, registry, session isolation |
| [DevKit](docs/devkit.md) | LocalAS, TokenFactory, Simulator, CLI |
| [Deployment](docs/deployment.md) | Docker, Kubernetes, production checklist |
| [Extending](docs/extending.md) | Roadmap, cách thêm feature mới |

---

## License

MIT
