# Extending common-iam

This document describes how to add new features to the project, what's already wired up, and the planned roadmap.

---

## Project Conventions

### Package layout

| Layer | Location | Rule |
|---|---|---|
| Public API | `pkg/` | Everything here is importable by users |
| Internal | `internal/` | Only for the standalone service — not part of the library |
| Interfaces | `pkg/providers/provider.go`, `pkg/tenant/resolver.go` | Define here, implement in subdirs |
| Tests | next to source file (`_test.go`) | Unit tests live with the code they test |
| Integration tests | `tests/integration/` _(create when needed)_ | Require external services |

### Adding a new feature

1. **Define the interface/struct** in the appropriate `pkg/` package
2. **Implement** in a sub-package or the same file
3. **Wire** into the service in `cmd/iam-service/main.go` (if service-level)
4. **Add CLI command** in `cmd/iam-cli/main.go` (if user-facing)
5. **Update policy YAML** if the feature adds new policy fields
6. **Document** in `docs/`

---

## Planned Features (Roadmap)

### Near-term

#### 1. DPoP Full Validation (RFC 9449)
**File:** [pkg/core/token/dpop.go](../pkg/core/token/dpop.go)

The skeleton is in place. What's missing:
- Full JWK → `crypto.PublicKey` extraction using `lestrrat-go/jwx/v2`
- JWT signature verification against the embedded public key
- `cnf.jkt` claim extraction from the access token to match DPoP proof key

```go
// To implement: pkg/core/token/dpop.go
import "github.com/lestrrat-go/jwx/v2/jwk"

func VerifyDPoPSignature(proof *DPoPProof, rawJWT string) error {
    key, err := jwk.ParseKey(proof.JWK, ...)
    // verify signature of the DPoP JWT
}
```

Enable in middleware by setting `EnableDPoP: true` in `Config`.

---

#### 2. Local JWT Validation (skip introspection)
**New file:** `pkg/core/token/jwtvalidator.go`

Currently all tokens go through RFC 7662 introspection. Add a local validator using JWKS:

```go
type JWTValidator struct {
    jwks *jwk.Set
}

func (v *JWTValidator) Validate(ctx context.Context, rawToken string) (*CommonClaims, error) {
    // parse + verify signature using lestrrat-go/jwx
    // extract claims → MapToCommon
}
```

Use case: High-throughput services where remote introspection is too slow.

---

#### 3. RAR — Rich Authorization Requests (RFC 9396)
**New file:** `pkg/core/rar/types.go`

Add `authorization_details` claim support in policy evaluation:

```yaml
# Policy YAML extension
policies:
  - name: account-transfer
    resources: [/api/transfer]
    require_authorization_details:
      - type: account_transfer
        min_amount: 0
        max_amount: 10000
```

---

#### 4. JAR — JWT-Secured Authorization Requests (RFC 9101)
**New file:** `pkg/core/jar/`

For services that need to send signed authorization requests to the AS.

---

#### 5. Admin API Authentication
**File:** [internal/admin/handler.go](../internal/admin/handler.go)

Currently the `/admin/` API has no authentication. Add:
- Bearer token validation
- IP allowlist middleware
- Optional mTLS

```go
// internal/admin/handler.go
func (h *Handler) routes() {
    h.mux.Handle("/tenants", requireAdminToken(h.handleTenants))
    // ...
}
```

---

#### 6. Redis Cache with go-redis (complete wiring)
**File:** [pkg/core/token/cache.go](../pkg/core/token/cache.go)

The `RedisCache` struct and `RedisClient` interface are defined, but not wired into the service. To complete:

```go
// cmd/iam-service/main.go
import "github.com/redis/go-redis/v9"

rdb := redis.NewClient(&redis.Options{
    Addr: os.Getenv("REDIS_ADDR"),
})

// Adapt go-redis to our RedisClient interface
cache := token.NewRedisCache(&redisAdapter{rdb}, "iam:token:")
```

The `redisAdapter` just needs to bridge `go-redis` method signatures to `RedisClient`.

---

### Medium-term

#### 7. WebAuthn / Passkey Support
Add passkey as an AMR value and policy option:

```yaml
require_passkey: true  # AMR must include "hwk" or "fido"
```

#### 8. Consent Tracking
Track which scopes users have consented to and enforce at the resource level.

#### 9. Token Exchange (RFC 8693)
Allow services to exchange tokens for narrower-scoped tokens (actor tokens, delegation).

#### 10. SCIM Integration
Auto-sync users/groups from the AS when a tenant is registered.

---

### Long-term

#### 11. Policy UI
A web-based policy editor that writes `policy.yaml` and triggers hot-reload.

#### 12. Audit Log Storage
Currently audit events are written to `slog`. Add pluggable sinks:
- Elasticsearch
- S3 (JSONL)
- PostgreSQL

**New interface:** `pkg/telemetry/audit.go`
```go
type AuditSink interface {
    Write(ctx context.Context, event *AuditEvent) error
}
```

#### 13. gRPC Middleware
```go
// pkg/middleware/grpc/interceptor.go
func UnaryServerInterceptor(cfg Config) grpc.UnaryServerInterceptor
func StreamServerInterceptor(cfg Config) grpc.StreamServerInterceptor
```

#### 14. FAPI 2.0 Compliance
Financial-grade API profile — add PAR (RFC 9126), mTLS sender-constrained tokens.

---

## How to Add a New Provider

1. Create `pkg/providers/myprovider/adapter.go`
2. Embed `generic.Adapter` (or implement `providers.Provider` from scratch)
3. Build the discovery URL for your provider
4. Add claims mapping in `pkg/providers/claims_mapper.go` if needed
5. Add a test using `localas` as the mock
6. Document in `docs/providers.md`

---

## How to Add a New TenantResolver

1. Add to `pkg/tenant/resolver.go`
2. Implement `tenant.Resolver` interface (one method: `Resolve(*http.Request) (string, error)`)
3. Add to `NewChainResolver` usage example in docs

---

## How to Add a New Policy Field

1. Add field to `Policy` struct in `pkg/core/policy/types.go`
2. Add check in `engine.check()` in `pkg/core/policy/engine.go`
3. Add the corresponding `PolicyRequest` field in `types.go`
4. Update YAML tag + docs
5. Add a test case in the simulator

---

## Testing Philosophy

- **Unit tests**: Use `tokenfactory` to generate tokens with specific claims. No network calls.
- **Integration tests**: Use `localas` as the AS. No external dependencies.
- **Policy tests**: Use `simulator.RunTable()` for a clear, readable test matrix.
- **E2E tests**: Spin up `localas` + your service + test client in the same test process.

```go
// Pattern: full E2E in a single test function
func TestFullFlow(t *testing.T) {
    as, _ := localas.New()
    baseURL, _ := as.Start()
    defer as.Stop(ctx)

    // setup provider → middleware → handler
    // issue token from localas
    // make HTTP request
    // assert response
}
```
