# common-iam — Full Feature Design

---

## 1. Tổng quan hệ thống

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                              common-iam                                          ║
║                                                                                  ║
║   Hai chế độ hoạt động:                                                         ║
║                                                                                  ║
║   ┌─────────────────────────────┐     ┌──────────────────────────────────────┐  ║
║   │      MODE 1: LIBRARY        │     │        MODE 2: GATEWAY               │  ║
║   │                             │     │                                      │  ║
║   │  go get github.com/         │     │  $ ./iam-service                     │  ║
║   │         common-iam/iam      │     │                                      │  ║
║   │                             │     │  Internet → [:8080] → Backend[:3000] │  ║
║   │  import pkg/middleware/gin  │     │                                      │  ║
║   │  import pkg/core/policy     │     │  Auth tập trung — backend không cần  │  ║
║   │  import pkg/providers/...   │     │  tự handle token validation          │  ║
║   │                             │     │                                      │  ║
║   │  Nhúng auth vào service Go  │     │  Sidecar / API Gateway pattern       │  ║
║   └─────────────────────────────┘     └──────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 2. Request Flow — đường đi của một request

```
                              ┌──────────────────────────────────────────────────┐
                              │                  IAM Gateway                     │
                              │                                                  │
  HTTP Request                │  ┌────────────┐                                 │
  ─────────────────────────── ▶  │  Router    │                                 │
  POST /api/payments          │  │            │                                 │
  Authorization: Bearer <tok> │  │ /health ───┼──▶ 200 OK                      │
                              │  │ /metrics ──┼──▶ Prometheus                  │
                              │  │ /admin/* ──┼──▶ Admin API                   │
                              │  │ /webhook/* ┼──▶ Revocation Handler          │
                              │  │ /* ────────┼──▶ ResourceServerGuard         │
                              │  └────────────┘          │                      │
                              │                          │                      │
                              │  ┌───────────────────────▼──────────────────┐  │
                              │  │          ResourceServerGuard              │  │
                              │  │                                           │  │
                              │  │  1. TenantResolver                        │  │
                              │  │     Header X-Tenant-ID → "acme"          │  │
                              │  │     Subdomain acme.api.app.com → "acme"  │  │
                              │  │     Path /acme/api/... → "acme"          │  │
                              │  │     Fallback → "default"                 │  │
                              │  │                    │                      │  │
                              │  │  2. ProviderRegistry                     │  │
                              │  │     "acme" → KeycloakAdapter             │  │
                              │  │     "corp" → Auth0Adapter                │  │
                              │  │                    │                      │  │
                              │  │  3. Token Extraction                     │  │
                              │  │     Authorization: Bearer <token>        │  │
                              │  │     → missing? → 401 invalid_token       │  │
                              │  │                    │                      │  │
                              │  │  4. Token Introspection                  │  │
                              │  │     Cache hit? → CommonClaims            │  │
                              │  │     Cache miss → AS endpoint → cache     │  │
                              │  │     inactive? → 401 invalid_token        │  │
                              │  │                    │                      │  │
                              │  │  5. Policy Evaluation                    │  │
                              │  │     Match resource + method              │  │
                              │  │     Check ACR level                      │  │
                              │  │     Check max_age                        │  │
                              │  │     Check scopes                         │  │
                              │  │     Check MFA (AMR)                      │  │
                              │  │                    │                      │  │
                              │  │         ┌──────────┴──────────┐          │  │
                              │  │         │                      │          │  │
                              │  │      ALLOWED               DENIED         │  │
                              │  │         │                      │          │  │
                              │  │  6a. Attach context   6b. StepUpChallenge│  │
                              │  │      tenant_id             WWW-Auth       │  │
                              │  │      claims                401 + body     │  │
                              │  │         │                  Audit log      │  │
                              │  │         ▼                  Metrics        │  │
                              │  │    Upstream / Next                        │  │
                              │  └───────────────────────────────────────────┘  │
                              └──────────────────────────────────────────────────┘
```

---

## 3. RFC 9470 Step-Up Flow

```
  Client App            IAM Gateway              Authorization Server
      │                      │                          │
      │                      │                          │
      │──POST /api/pay ──────▶│                          │
      │  Bearer: token-bronze │                          │
      │                      │──introspect(token) ──────▶│
      │                      │◀── {active, acr:bronze} ──│
      │                      │                          │
      │                      │ Policy: need acr=silver   │
      │                      │ max_age=300               │
      │                      │                          │
      │◀─ 401 Unauthorized ──│                          │
      │   Www-Authenticate:   │                          │
      │     Bearer            │                          │
      │     realm="MyApp"     │                          │
      │     error="insufficient_user_authentication"     │
      │     acr_values="urn:mace:incommon:iap:silver"    │
      │     max_age=300       │                          │
      │                      │                          │
      │  [Client saves original request]                 │
      │  [Client builds authorize URL with hints]        │
      │                      │                          │
      │──GET /authorize? ─────────────────────────────────▶│
      │   acr_values=silver   │                          │  [User step-up]
      │   max_age=300         │                          │  [MFA / re-login]
      │   prompt=login        │                          │
      │◀─ new access_token ───────────────────────────────│
      │   (acr: silver,       │                          │
      │    auth_time: now)    │                          │
      │                      │                          │
      │──POST /api/pay ──────▶│                          │
      │  Bearer: token-silver │                          │
      │                      │──introspect(token) ──────▶│
      │                      │◀── {active, acr:silver} ──│
      │                      │                          │
      │                      │ Policy: silver ≥ silver ✓ │
      │                      │ auth_age=5s < 300s ✓      │
      │                      │                          │
      │◀─ 200 OK ────────────│                          │
      │   {"message":"auth    │                          │
      │    passed"}           │                          │
```

---

## 4. Package Map — toàn bộ packages và relationships

```
github.com/common-iam/iam
│
├── cmd/
│   ├── iam-service/          Binary: standalone HTTP gateway
│   │   └── main.go           Boot: logger → policy → registry → guard → server
│   │
│   └── iam-cli/              Binary: developer CLI tool
│       └── main.go           Commands: inspect-token | test-policy | issue-token | parse-challenge
│
├── internal/                 (không export — chỉ dùng trong service)
│   ├── server/
│   │   ├── server.go         HTTP server với graceful shutdown
│   │   └── router.go         Route: /health /metrics /admin/* /webhook/* /*
│   │
│   ├── gateway/
│   │   ├── guard.go          ResourceServerGuard — main auth enforcement
│   │   └── proxy.go          httputil.ReverseProxy wrapper
│   │
│   └── admin/
│       └── handler.go        REST: GET /tenants, GET /policy/summary, POST /policy/reload
│
└── pkg/                      (export — import vào project của bạn)
    │
    ├── core/
    │   ├── stepup/
    │   │   ├── challenge.go  StepUpChallenge, WWW-Authenticate builder/parser
    │   │   ├── statemachine.go  State: Idle → Challenge → Completed/Failed
    │   │   └── errors.go     Error codes: invalid_token, insufficient_user_auth, insufficient_scope
    │   │
    │   ├── token/
    │   │   ├── claims.go     CommonClaims struct + sentinel errors
    │   │   ├── introspect.go RFC 7662 introspector (HTTP POST to AS)
    │   │   ├── cache.go      MemoryCache + RedisCache + CachedIntrospector
    │   │   ├── revocation.go RevocationHandler (webhook receiver)
    │   │   └── dpop.go       RFC 9449 DPoP proof parsing + validation
    │   │
    │   └── policy/
    │       ├── types.go      Config, Policy, PolicyRequest, PolicyResult structs
    │       ├── matcher.go    MatchResource (** glob), MatchMethod, ACRSatisfies
    │       ├── engine.go     Evaluate() — first-match, ordered evaluation
    │       └── loader.go     LoadFromFile(), LoadFromBytes() (gopkg.in/yaml.v3)
    │
    ├── providers/
    │   ├── provider.go       interface Provider { Introspect, JWKS, RefreshConfig }
    │   ├── claims_mapper.go  RawClaims → CommonClaims (Keycloak/Auth0/generic)
    │   ├── keycloak/
    │   │   └── adapter.go    wraps generic, builds {BaseURL}/realms/{Realm}/...
    │   ├── auth0/
    │   │   └── adapter.go    wraps generic, builds https://{Domain}/...
    │   └── generic/
    │       └── adapter.go    OIDC discovery → introspection endpoint auto-config
    │
    ├── middleware/
    │   ├── gin/
    │   │   └── middleware.go  gin.HandlerFunc + ClaimsFromContext(*gin.Context)
    │   ├── echo/
    │   │   └── middleware.go  echo.MiddlewareFunc + ClaimsFromContext(echo.Context)
    │   └── stdlib/
    │       └── middleware.go  func(http.Handler)http.Handler + ClaimsFromContext(ctx)
    │
    ├── tenant/
    │   ├── resolver.go       HeaderResolver, SubdomainResolver, PathResolver, ChainResolver
    │   ├── registry.go       Registry: Register/Unregister/Get/List/RefreshAll
    │   └── session.go        WithTenantID(ctx) / TenantIDFromContext(ctx)
    │
    ├── telemetry/
    │   ├── logger.go         NewLogger(format, level) + WithLogger(ctx) + IAMEvent
    │   ├── metrics.go        Prometheus: stepup_total, token_validation_duration, policy_denied_total, ...
    │   ├── tracing.go        OpenTelemetry: StartSpan, SpanFromToken, TraceIDFromContext
    │   └── audit.go          AuditLogger (RFC 8417 SET): token.validated, stepup.issued, policy.denied, ...
    │
    └── devkit/
        ├── localas/
        │   └── server.go     In-process mock AS: discovery + JWKS + token + introspect + revoke
        ├── tokenfactory/
        │   └── factory.go    RSA-2048 key gen + JWT sign + JWKS export
        └── simulator/
            └── policy.go     Simulate(Request) + RunTable([]Request) string
```

---

## 5. Token Cache Layer

```
  Request với Bearer token
          │
          ▼
  ┌─────────────────┐
  │  HashToken()    │  SHA-256(rawToken) → hex string
  │  (never store   │  Cache key = hash, không phải raw token
  │   raw token)    │
  └────────┬────────┘
           │
           ▼
  ┌─────────────────────────────────────────────────────┐
  │                   Cache.Get(hash)                   │
  │                                                     │
  │   ┌─────────────────┐    ┌──────────────────────┐  │
  │   │   MemoryCache   │ OR │    RedisCache         │  │
  │   │                 │    │                       │  │
  │   │ sync.RWMutex    │    │ key: "iam:token:<h>"  │  │
  │   │ map[hash]entry  │    │ JSON serialized       │  │
  │   │ background GC   │    │ distributed           │  │
  │   └────────┬────────┘    └──────────┬────────────┘  │
  │            │                        │               │
  │            └──────────┬─────────────┘               │
  └───────────────────────┼─────────────────────────────┘
                          │
               ┌──────────┴──────────┐
               │                     │
            HIT (TTL ok)         MISS / expired
               │                     │
               ▼                     ▼
         CommonClaims      Introspector.Introspect()
         (từ cache)            (HTTP POST to AS)
                                     │
                              ┌──────┴──────┐
                              │             │
                           active?        inactive
                              │             │
                          Cache.Set()    return error
                          TTL: 30s
                              │
                         CommonClaims
```

---

## 6. Policy Evaluation Engine

```
  PolicyRequest {Method, Path, TokenACR, TokenAMR, TokenScopes, AuthAge}
          │
          ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                     Policy Engine                                │
  │                                                                  │
  │  for each policy in order:                                       │
  │                                                                  │
  │  ┌─── Policy 1: public ────────────────────────────────────┐    │
  │  │  resources: [/api/public/**, /health]                   │    │
  │  │  methods: [GET]                                         │    │
  │  │                                                         │    │
  │  │  MatchResource("/api/payments", "/api/public/**") = NO  │    │
  │  └─── skip ───────────────────────────────────────────────┘    │
  │                                                                  │
  │  ┌─── Policy 2: payments ──────────────────────────────────┐    │
  │  │  resources: [/api/payments/**]                          │    │
  │  │  methods: [POST, PUT, DELETE]                           │    │
  │  │                                                         │    │
  │  │  MatchResource("/api/payments/charge", "...") = YES ✓   │    │
  │  │  MatchMethod("POST", [POST,PUT,DELETE]) = YES ✓         │    │
  │  │                                                         │    │
  │  │  ┌── MATCHED — evaluate requirements ─────────────┐    │    │
  │  │  │                                                │    │    │
  │  │  │  1. Check scopes: [payments:write] ∈ token? ✓  │    │    │
  │  │  │                                                │    │    │
  │  │  │  2. Check ACR:                                 │    │    │
  │  │  │     acr_levels = [bronze(0), silver(1), gold(2)]│   │    │
  │  │  │     token.ACR = "silver" → index 1             │    │    │
  │  │  │     required = "silver" → index 1              │    │    │
  │  │  │     1 ≥ 1 → PASS ✓                            │    │    │
  │  │  │                                                │    │    │
  │  │  │  3. Check max_age:                             │    │    │
  │  │  │     auth_age = 45s < max_age = 300s → PASS ✓  │    │    │
  │  │  │                                                │    │    │
  │  │  │  4. Check MFA: require_mfa = false → skip ✓   │    │    │
  │  │  │                                                │    │    │
  │  │  │  → PolicyResult { Allowed: true }              │    │    │
  │  │  └────────────────────────────────────────────────┘    │    │
  │  └─────────────────────────────────────────────────────────┘    │
  │                                                                  │
  │  (không đọc policy tiếp theo — first match wins)                │
  └──────────────────────────────────────────────────────────────────┘

  Path matching rules:
    /api/**           → prefix match (bất kỳ depth)
    /api/users/*      → path.Match (1 segment)
    /api/users        → exact match
    /**               → match everything
```

---

## 7. Multi-Tenant Architecture

```
                    Incoming Requests
                          │
          ┌───────────────┼───────────────┐
          │               │               │
  acme.api.app.com  api.app.com    corp.api.app.com
  X-Tenant-ID:acme  (no header)   X-Tenant-ID:corp
          │               │               │
          ▼               ▼               ▼
  ┌───────────────────────────────────────────────┐
  │              ChainResolver                    │
  │                                               │
  │  1. SubdomainResolver("api.app.com")          │
  │     acme.api.app.com → "acme" ✓              │
  │     api.app.com      → error                  │
  │                                               │
  │  2. HeaderResolver("X-Tenant-ID")             │
  │     X-Tenant-ID: corp → "corp" ✓             │
  │     (no header)       → error                 │
  │                                               │
  │  3. defaultTenantResolver (fallback)          │
  │     → "default"                               │
  └───────────────────┬───────────────────────────┘
                      │
                      ▼ tenantID string
  ┌───────────────────────────────────────────────┐
  │              ProviderRegistry                 │
  │  (thread-safe RWMutex map)                   │
  │                                               │
  │  "acme"    → KeycloakAdapter                  │
  │               BaseURL: keycloak-acme.com      │
  │               Realm: acme-prod                │
  │                                               │
  │  "corp"    → Auth0Adapter                     │
  │               Domain: corp.us.auth0.com       │
  │                                               │
  │  "default" → GenericOIDCAdapter               │
  │               DiscoveryURL: ...               │
  │                                               │
  │  registry.Register(id, provider) — runtime   │
  │  registry.Unregister(id)         — runtime   │
  │  registry.RefreshAll(ctx)        — periodic  │
  └───────────────────┬───────────────────────────┘
                      │
                      ▼ Provider
              Introspect(token)
                      │
                      ▼
              CommonClaims + TenantID in ctx
```

---

## 8. Observability Stack

```
  Every request through IAM
          │
          ├── LOGGING (slog, structured)
          │   ┌───────────────────────────────────────────────────┐
          │   │ level=INFO msg="audit"                            │
          │   │   event_type=iam.policy.denied                    │
          │   │   tenant_id=acme                                  │
          │   │   sub=alice@example.com                           │
          │   │   resource=/api/admin/users                       │
          │   │   method=POST                                      │
          │   │   required_acr=urn:mace:incommon:iap:gold         │
          │   │   trace_id=4bf92f3577b34da6a3ce929d0e0e4736       │
          │   └───────────────────────────────────────────────────┘
          │
          ├── METRICS (Prometheus → /metrics)
          │   ┌───────────────────────────────────────────────────┐
          │   │ iam_stepup_challenges_total                        │
          │   │   {tenant="acme",required_acr="...gold",           │
          │   │    method="POST"} 42                               │
          │   │                                                    │
          │   │ iam_token_validation_duration_seconds              │
          │   │   {tenant="acme",provider="keycloak",              │
          │   │    cache_hit="true"} p50=0.0001 p99=0.002          │
          │   │                                                    │
          │   │ iam_policy_denied_total                            │
          │   │   {tenant="acme",policy_name="admin",              │
          │   │    reason="ACR insufficient"} 17                   │
          │   │                                                    │
          │   │ iam_token_cache_total                              │
          │   │   {tenant="acme",result="hit"} 9831                │
          │   │   {tenant="acme",result="miss"} 201                │
          │   │                                                    │
          │   │ iam_active_tenants 3                               │
          │   └───────────────────────────────────────────────────┘
          │
          ├── TRACING (OpenTelemetry)
          │   ┌───────────────────────────────────────────────────┐
          │   │ Trace: gateway.Guard.ServeHTTP                    │
          │   │   span.tenant_id = "acme"                         │
          │   │   span.sub = "alice"                              │
          │   │   span.acr = "urn:mace:incommon:iap:silver"       │
          │   │   → compatible với Jaeger, Tempo, Zipkin          │
          │   └───────────────────────────────────────────────────┘
          │
          └── AUDIT (RFC 8417 Security Event Token)
              ┌───────────────────────────────────────────────────┐
              │ AuditEvent types:                                 │
              │   iam.token.validated                             │
              │   iam.token.rejected                              │
              │   iam.stepup.challenge_issued  ← RFC 9470         │
              │   iam.stepup.completed                            │
              │   iam.stepup.failed                               │
              │   iam.policy.allowed                              │
              │   iam.policy.denied                               │
              │   iam.token.revoked                               │
              │   iam.tenant.registered                           │
              └───────────────────────────────────────────────────┘
```

---

## 9. DevKit — Developer Tools

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                           DevKit                                    │
  │                                                                     │
  │  ┌─────────────────────────────────────────────────────────────┐   │
  │  │  LocalAS (pkg/devkit/localas)                               │   │
  │  │                                                             │   │
  │  │  In-process HTTP server, random port, zero config           │   │
  │  │                                                             │   │
  │  │  GET  /.well-known/openid-configuration  ← OIDC discovery   │   │
  │  │  GET  /jwks                              ← public key        │   │
  │  │  POST /token                             ← issue token       │   │
  │  │  POST /introspect                        ← RFC 7662          │   │
  │  │  POST /revoke                            ← revocation        │   │
  │  │                                                             │   │
  │  │  as, _ := localas.New()                                     │   │
  │  │  baseURL, _ := as.Start()   // http://127.0.0.1:<random>    │   │
  │  │  token, _ := as.IssueToken(TokenOptions{...})               │   │
  │  └─────────────────────────────────────────────────────────────┘   │
  │                                                                     │
  │  ┌─────────────────────────────────────────────────────────────┐   │
  │  │  TokenFactory (pkg/devkit/tokenfactory)                     │   │
  │  │                                                             │   │
  │  │  RSA-2048 key gen on first use                              │   │
  │  │                                                             │   │
  │  │  factory.Generate(TokenOptions{                             │   │
  │  │    Subject:   "alice",                                      │   │
  │  │    ACR:       "urn:mace:incommon:iap:gold",                 │   │
  │  │    AMR:       []string{"mfa", "hwk"},                       │   │
  │  │    Scopes:    []string{"openid", "admin"},                   │   │
  │  │    AuthTime:  time.Now().Add(-2*time.Minute),               │   │
  │  │    ExpiresIn: time.Hour,                                    │   │
  │  │  })                                                         │   │
  │  │                                                             │   │
  │  │  factory.JWKS()  → JSON Web Key Set                        │   │
  │  └─────────────────────────────────────────────────────────────┘   │
  │                                                                     │
  │  ┌─────────────────────────────────────────────────────────────┐   │
  │  │  PolicySimulator (pkg/devkit/simulator)                     │   │
  │  │                                                             │   │
  │  │  sim.RunTable([]Request{                                    │   │
  │  │    {Method:"GET",  Path:"/api/users",    ACR:"bronze"},     │   │
  │  │    {Method:"POST", Path:"/api/payments", ACR:"silver"},     │   │
  │  │    {Method:"POST", Path:"/api/admin",    ACR:"silver"},     │   │
  │  │  })                                                         │   │
  │  │                                                             │   │
  │  │  METHOD   PATH              ACR     ALLOWED  REASON         │   │
  │  │  GET      /api/users        bronze  YES                     │   │
  │  │  POST     /api/payments     silver  YES                     │   │
  │  │  POST     /api/admin        silver  NO       need gold      │   │
  │  └─────────────────────────────────────────────────────────────┘   │
  │                                                                     │
  │  ┌─────────────────────────────────────────────────────────────┐   │
  │  │  CLI (cmd/iam-cli)                                          │   │
  │  │                                                             │   │
  │  │  inspect-token  <jwt>         Decode claims + RFC 9470 ctx  │   │
  │  │  test-policy    [flags]       Dry-run policy (no server)    │   │
  │  │  issue-token    [flags]       Generate signed test JWT      │   │
  │  │  parse-challenge <header>     Parse WWW-Authenticate        │   │
  │  └─────────────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## 10. DPoP — Proof of Possession (RFC 9449)

```
  Vấn đề với Bearer token thông thường:
  ┌────────────────────────────────────────────────────────┐
  │  Attacker sniffs Bearer token → có thể dùng token đó  │
  │  từ bất kỳ máy nào, bất kỳ IP nào                    │
  └────────────────────────────────────────────────────────┘

  DPoP giải quyết: token bị BIND với client's private key

  ┌────────────────────────────────────────────────────────────────┐
  │  Client tạo DPoP proof JWT mỗi request:                        │
  │                                                                │
  │  Header: { "typ": "dpop+jwt", "alg": "ES256",                 │
  │            "jwk": { public key } }                             │
  │  Payload: { "htm": "POST",                                     │
  │             "htu": "https://api.example.com/pay",              │
  │             "iat": 1234567890,                                  │
  │             "jti": "unique-proof-id",                          │
  │             "ath": base64url(SHA256(access_token)) }           │
  │                                                                │
  │  Headers gửi lên:                                              │
  │    Authorization: DPoP <access_token>                          │
  │    DPoP: <signed_dpop_proof>                                   │
  └────────────────────────────────────────────────────────────────┘

  IAM validation (pkg/core/token/dpop.go):

    ValidateDPoP(r, accessToken, cfg)
          │
          ├── Parse DPoP JWT (header + payload)
          ├── Verify typ = "dpop+jwt"
          ├── Verify htm = request method
          ├── Verify htu = request URI
          ├── Verify iat freshness (max 60s old)
          ├── Verify ath = base64url(SHA256(token)) ← key binding
          └── [TODO] Verify signature against embedded JWK
```

---

## 11. Token Revocation Flow

```
  User logout / token compromise detected
          │
          ▼
  Authorization Server
          │
          │── POST /webhook/revoke ──────────────────────────▶ IAM Gateway
          │   Content-Type: application/json
          │   {
          │     "token_hash": "sha256-of-token",    ← revoke specific token
          │     "jti": "jwt-id",                    ← OR by JWT ID
          │     "sub": "user-id",                   ← OR all for user
          │     "revoke_all": true
          │   }
          │                                                    │
          │                                          RevocationHandler
          │                                                    │
          │                                          Cache.Delete(hash)
          │                                                    │
          │                                          Next request with
          │                                          revoked token:
          │                                            Cache miss
          │                                            → Introspect AS
          │                                            → {active: false}
          │                                            → 401
```

---

## 12. CommonClaims — normalized cross-provider claims

```
  Token từ bất kỳ provider nào
          │
          ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  ClaimsMapper (pkg/providers/claims_mapper.go)                   │
  │                                                                  │
  │  Keycloak                 Auth0                  Generic OIDC    │
  │  realm_access.roles  →    /roles (namespaced) →  roles claim     │
  │  preferred_username  →    nickname            →  username        │
  │  sid (session ID)   →    sid                 →  sid             │
  │  tenant_id          →    org_id              →  tenant_id / tid  │
  └────────────────────────────┬─────────────────────────────────────┘
                               │
                               ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  CommonClaims                                                    │
  │                                                                  │
  │  Subject    string        "alice@acme.com"                       │
  │  Issuer     string        "https://keycloak.acme.com/realms/..."  │
  │  Audience   []string      ["api.acme.com", "iam-rs"]             │
  │  ExpiresAt  time.Time     2026-03-04 15:00:00                    │
  │  IssuedAt   time.Time     2026-03-04 14:00:00                    │
  │  ACR        string        "urn:mace:incommon:iap:silver"          │
  │  AMR        []string      ["pwd", "otp"]                         │
  │  SessionID  string        "sess-abc123"                          │
  │  AuthTime   time.Time     2026-03-04 14:00:00  ← for max_age     │
  │  Email      string        "alice@acme.com"                       │
  │  Username   string        "alice"                                │
  │  Roles      []string      ["user", "payment-admin"]              │
  │  Scopes     []string      ["openid", "profile", "payments:write"] │
  │  TenantID   string        "acme"                                 │
  │  Active     bool          true                                   │
  │  Extra      map[...]      {"custom_claim": "value"}              │
  │                                                                  │
  │  AuthAge()  time.Duration  time.Since(AuthTime)                  │
  │  HasScope("payments:write") bool                                 │
  │  HasRole("admin") bool                                           │
  └──────────────────────────────────────────────────────────────────┘
```

---

## 13. Deployment Patterns

```
  PATTERN 1: Library — auth embedded trong service
  ┌─────────────────────────────────────────────────────────────┐
  │                    Your Go Service                           │
  │                                                             │
  │  main.go                                                    │
  │    provider := keycloak.New(...)                            │
  │    engine   := policy.New(cfg)                              │
  │                                                             │
  │  router.go                                                  │
  │    r.Use(iamgin.Middleware({provider, engine}))             │
  │                                                             │
  │    r.GET("/api/me", func(c *gin.Context) {                  │
  │        claims, _ := iamgin.ClaimsFromContext(c)             │
  │        // business logic với claims                         │
  │    })                                                       │
  └─────────────────────────────────────────────────────────────┘

  PATTERN 2: Sidecar Gateway — auth tách biệt hoàn toàn
  ┌─────────────────┐        ┌─────────────────────────────────┐
  │  IAM Gateway    │        │    Your Backend (any language)  │
  │  :8080          │───────▶│    :3000                        │
  │                 │        │                                 │
  │  - auth         │        │  - business logic only          │
  │  - policy       │        │  - no token handling            │
  │  - multi-tenant │        │  - reads X-Tenant-ID from       │
  │  - metrics      │        │    forwarded headers            │
  └─────────────────┘        └─────────────────────────────────┘
        ▲                              (no auth code needed)
        │
  Internet

  PATTERN 3: Multi-tenant SaaS
  ┌──────────────────────────────────────────────────────────────┐
  │                                                              │
  │  acme.api.app.com ──▶ IAM [:8080] ──▶ Backend (tenant=acme) │
  │  corp.api.app.com ──▶ IAM [:8080] ──▶ Backend (tenant=corp) │
  │                                                              │
  │  Mỗi tenant dùng AS riêng:                                   │
  │    acme → Keycloak realm "acme-prod"                         │
  │    corp → Auth0 tenant "corp.us.auth0.com"                   │
  │                                                              │
  │  Policy YAML chung, hoặc per-tenant policy                   │
  └──────────────────────────────────────────────────────────────┘
```

---

## 14. ACR Level Hierarchy

```
  Định nghĩa trong policy.yaml:
  acr_levels:
    - "urn:mace:incommon:iap:bronze"   ← index 0 (thấp nhất)
    - "urn:mace:incommon:iap:silver"   ← index 1
    - "urn:mace:incommon:iap:gold"     ← index 2 (cao nhất)

  So sánh:
                    BRONZE  SILVER  GOLD
  satisfy BRONZE  [  YES     YES    YES  ]
  satisfy SILVER  [  NO      YES    YES  ]
  satisfy GOLD    [  NO      NO     YES  ]

  Cách dùng điển hình:

  BRONZE → Basic login: username + password
           ACR value: "urn:mace:incommon:iap:bronze"
           Use case: đọc profile, xem list

  SILVER → Step-up: TOTP / SMS OTP / push notification
           ACR value: "urn:mace:incommon:iap:silver"
           Use case: giao dịch nhỏ, thay đổi thông tin

  GOLD   → Hardware: YubiKey / FIDO2 / WebAuthn passkey
           ACR value: "urn:mace:incommon:iap:gold"
           Use case: admin, giao dịch lớn, xuất dữ liệu

  ─────────────────────────────────────────────────────────
  Custom hierarchy (bất kỳ scheme nào):

  acr_levels:
    - "http://eidas.europa.eu/LoA/low"           # eIDAS Low
    - "http://eidas.europa.eu/LoA/substantial"   # eIDAS Substantial
    - "http://eidas.europa.eu/LoA/high"          # eIDAS High

  acr_levels:
    - "nist-sp800-63-aal1"    # NIST SP 800-63 AAL1
    - "nist-sp800-63-aal2"    # NIST SP 800-63 AAL2
    - "nist-sp800-63-aal3"    # NIST SP 800-63 AAL3
```

---

## 15. Roadmap — Features chưa implement

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  PHASE 1 (done ✓)                                                   │
  │    RFC 9470 core engine          ✓                                  │
  │    Policy-as-config YAML         ✓                                  │
  │    Keycloak / Auth0 / OIDC       ✓                                  │
  │    Gin / Echo / stdlib middleware ✓                                  │
  │    Multi-tenant registry         ✓                                  │
  │    Token cache (memory + Redis)  ✓                                  │
  │    Revocation webhook            ✓                                  │
  │    Prometheus + OTel + slog      ✓                                  │
  │    DevKit (LocalAS, factory, sim) ✓                                 │
  │    CLI (inspect, test, issue)    ✓                                  │
  │    Standalone gateway + Docker   ✓                                  │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  PHASE 2 (near-term)                                                │
  │                                                                     │
  │  DPoP full signature verification (RFC 9449)                        │
  │    File: pkg/core/token/dpop.go                                     │
  │    Add: lestrrat-go/jwx/v2 for JWK → crypto.PublicKey              │
  │                                                                     │
  │  Local JWT validation (skip introspection, use JWKS)                │
  │    File: pkg/core/token/jwtvalidator.go (new)                       │
  │    Use: lestrrat-go/jwx/v2 JWT parse + verify                       │
  │                                                                     │
  │  Admin API authentication                                           │
  │    File: internal/admin/handler.go                                  │
  │    Add: Bearer token middleware on /admin/* routes                  │
  │                                                                     │
  │  go-redis adapter wiring (RedisCache đã có, cần bridge)             │
  │    File: cmd/iam-service/main.go                                    │
  │    Add: IAM_REDIS_ADDR env var → redis.NewClient → adapter          │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  PHASE 3 (medium-term)                                              │
  │                                                                     │
  │  RAR — Rich Authorization Requests (RFC 9396)                       │
  │    authorization_details claim trong policy                         │
  │                                                                     │
  │  gRPC interceptor                                                   │
  │    pkg/middleware/grpc/interceptor.go                               │
  │                                                                     │
  │  WebAuthn / Passkey AMR support                                     │
  │    require_passkey: true in policy                                  │
  │                                                                     │
  │  Token Exchange (RFC 8693)                                          │
  │    Actor tokens, delegation tokens                                  │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  PHASE 4 (long-term)                                                │
  │                                                                     │
  │  FAPI 2.0 profile (financial-grade API)                             │
  │    PAR — Pushed Authorization Requests (RFC 9126)                   │
  │    mTLS sender-constrained tokens                                   │
  │                                                                     │
  │  Policy UI — web editor hot-reload                                  │
  │                                                                     │
  │  Audit log sinks: Elasticsearch / S3 / PostgreSQL                   │
  │    pkg/telemetry/audit.go: AuditSink interface                      │
  └─────────────────────────────────────────────────────────────────────┘
```
