# Development Plan — stepper (common-iam)

_Audit date: 2026-06-24. Headroom audit hash: `94d8f2a261e0acfae0d4c5b3` (retrieve for full findings)._

---

## Current Status Summary

42 Go files across the codebase. Core library packages are largely **complete**. The project cannot ship yet because the service entrypoint doesn't exist and there are two security bugs in code that is otherwise well-written.

### What is complete ✅
- RFC 7662 token introspection
- RFC 9449 DPoP crypto (parsing + signature verification)
- RFC 9470 challenge generation + state machine structs
- Policy engine (YAML, ACR hierarchy, hot-reload, first-match)
- Token cache (MemoryCache working; RedisCache defined but unwired)
- JWT local validator (JWKS cache, claims mapping)
- All 3 middleware adapters: gin, echo, stdlib
- Providers: Keycloak, Auth0, generic OIDC
- Tenant: Header/Subdomain/Path/Chain resolvers + Registry
- Telemetry: slog, Prometheus, OpenTelemetry, audit events
- DevKit: LocalAS, TokenFactory, PolicySimulator
- Admin API (tenant list, policy summary/reload, bearer auth)
- Reverse proxy + graceful server + router

---

## Priority 0 — Blockers (ship-critical)

### TASK-01: `cmd/iam-service/main.go` — service entrypoint
**Files to create:** `cmd/iam-service/main.go`
**What to wire:**
1. Parse env vars: `IAM_ADDR`, `IAM_REALM`, `IAM_POLICY_FILE`, `IAM_UPSTREAM_URL`, `IAM_OIDC_DISCOVERY_URL`, `IAM_OIDC_CLIENT_ID`, `IAM_OIDC_CLIENT_SECRET`, `IAM_LOG_FORMAT`, `REDIS_ADDR`, `IAM_ADMIN_TOKEN`, `IAM_WEBHOOK_SECRET`
2. Build logger (`telemetry.NewLogger`)
3. Load policy from file (`policy.LoadFromFile`)
4. Initialize provider (generic OIDC from discovery URL; or LocalAS if `IAM_OIDC_DISCOVERY_URL` is empty)
5. Initialize cache: if `REDIS_ADDR` set → `token.NewRedisCache(goredisAdapter, "iam:token:")`, else `token.NewMemoryCache()`
6. Build tenant registry + resolver (default: header resolver)
7. Build metrics + audit logger + OTel tracer
8. Build Guard (`gateway.NewGuard(cfg)`)
9. Build admin handler (`admin.New(cfg)`) with `IAM_ADMIN_TOKEN`
10. Build router (`server.NewRouter(cfg)`)
11. Wire signal handling (SIGINT/SIGTERM → graceful shutdown)
12. Start server

**Pattern:** Follow `internal/server/server.go` + `router.go`. Use `os.Signal` channel + `context.WithCancel`.

---

### TASK-02: Fix default-allow policy bug
**File:** `pkg/core/policy/engine.go:40`

Change:
```go
// No policy matched = allow by default
return &PolicyResult{Allowed: true}, nil
```
To:
```go
// No policy matched = deny by default (defence-in-depth)
return &PolicyResult{Allowed: false, Reason: "no matching policy"}, nil
```

**Impact:** Any request not covered by a policy will now get a 401 instead of passing through. Update `config/policy.example.yaml` to add a catch-all public rule if needed for existing routes. Add test case.

---

## Priority 1 — Security Gaps

### TASK-03: Wire DPoP enforcement in middleware + guard
**Files:** `pkg/middleware/gin/middleware.go`, `pkg/middleware/echo/middleware.go`, `pkg/middleware/stdlib/middleware.go`, `internal/gateway/guard.go`

In each middleware, add after token extraction:
```go
if cfg.EnableDPoP {
    if _, err := token.ValidateDPoP(r.Request, rawToken, token.DefaultDPoPConfig()); err != nil {
        issueChallenge(c, cfg.Realm, stepup.ErrCodeInvalidToken, "DPoP validation failed: "+err.Error(), "", 0)
        return
    }
}
```

In `GuardConfig`, add `EnableDPoP bool` field. Wire in `ServeHTTP` the same way.

**Acceptance:** Test with `pkg/core/token/dpop_test.go` patterns + a new middleware test.

---

### TASK-04: HMAC verification for revocation webhook
**File:** `pkg/core/token/revocation.go`

In `ServeHTTP`, before decoding the body, verify HMAC-SHA256 of the raw body against `X-Hub-Signature-256` header (GitHub-style webhook signature):
```go
if h.secret != "" {
    sig := r.Header.Get("X-Hub-Signature-256")
    if !verifyHMACSHA256(sig, body, h.secret) {
        http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
        return
    }
}
```

Also fix `internal/gateway/guard.go:165` — add `webhookSecret string` to `GuardConfig` and pass it:
```go
return token.NewRevocationHandler(c, g.webhookSecret, g.logger)
```

---

## Priority 2 — Feature Completeness

### TASK-05: `cmd/iam-cli/main.go` — CLI binary
**Files to create:** `cmd/iam-cli/main.go`, use `github.com/spf13/cobra` (already in go.mod)

**Subcommands:**
- `iam-cli token inspect <raw_jwt>` — decode + pretty-print claims (no validation)
- `iam-cli token issue --sub alice --acr silver --scope openid --expires 1h` — issue via LocalAS
- `iam-cli policy check --file policy.yaml --path /api/payments --method POST --acr bronze` — dry-run using simulator
- `iam-cli policy validate --file policy.yaml` — validate YAML, report conflicts

---

### TASK-06: Wire Redis cache from environment
**File:** `cmd/iam-service/main.go` (created in TASK-01)

Already covered in TASK-01 wiring. The `goredis/adapter.go` is complete — just needs instantiation:
```go
if addr := os.Getenv("REDIS_ADDR"); addr != "" {
    rdb := redis.NewClient(&redis.Options{Addr: addr})
    cache = token.NewRedisCache(&goredis.Adapter{Client: rdb}, "iam:token:")
}
```

---

### TASK-07: Per-request step-up state persistence
**Scope:** The `StateMachine` currently creates ephemeral `FlowState` that is discarded. For a complete RFC 9470 flow, the original request must survive the re-auth redirect.

**Approach (cookie-based, stateless):**
1. On challenge: encode `SavedRequest` (already has `Encode()` method) → set signed cookie `iam_stepup_state`
2. After successful re-auth: client sends new token + original request; guard detects the cookie, decodes it, verifies the new token satisfies the required ACR, clears the cookie, and forwards the original request
3. Cookie should be `HttpOnly; Secure; SameSite=Lax; MaxAge=600`

**Files to modify:** `internal/gateway/guard.go` (add cookie handling logic), `pkg/core/stepup/statemachine.go` (add cookie signing helpers using `crypto/hmac`)

---

## Priority 3 — Test Coverage ✅ COMPLETE

### TASK-08: Policy engine tests ✅
**File:** `pkg/core/policy/engine_test.go` — 10 tests (default-deny, nil config, ACR hierarchy, max_age, MFA, scopes, hot-reload)

### TASK-09: Middleware tests (gin, echo, stdlib) ✅
**Files:** `pkg/middleware/gin/middleware_test.go`, `pkg/middleware/echo/middleware_test.go`, `pkg/middleware/stdlib/middleware_test.go` — 4 tests each

### TASK-10: Guard integration tests ✅
**File:** `internal/gateway/guard_test.go` — 8 tests (valid, missing token, RFC 9470 challenge, cache hit, revocation webhook, DPoP required, cookie on challenge, multi-tenant)

### TASK-11: Integration test suite ✅
**Directory:** `tests/integration/e2e_test.go` — 8 tests (health, metrics, step-up flow, revocation flow, multi-tenant, admin unauthorized, admin list tenants, admin policy reload)

---

## Priority 4 — Medium-term Features

### TASK-12: AuditSink interface ✅ COMPLETE
**File:** `pkg/telemetry/audit.go` — Added `AuditSink` interface, fan-out `AuditLogger`, built-in `slogSink` + `FileSink` (NDJSON append). Tests in `audit_test.go` (8 tests).

**Key design:**
- `AuditSink interface { Write(ctx, *AuditEvent) error }`
- `AuditLogger.AddSink(AuditSink)` — attach at runtime
- Sink failures are logged but don't abort other sinks
- `FileSink` → NDJSON append (0600, thread-safe)

### TASK-13: RAR — Rich Authorization Requests (RFC 9396)
**Files to create:** `pkg/core/rar/types.go`, extend `pkg/core/policy/types.go`

Add `authorization_details` claim parsing in `CommonClaims.Extra`. Add `RequireAuthorizationDetails []AuthorizationDetail` to `Policy`. Add evaluation in `engine.check()`.

### TASK-14: gRPC middleware
**Files to create:** `pkg/middleware/grpc/interceptor.go`

```go
func UnaryServerInterceptor(cfg Config) grpc.UnaryServerInterceptor
func StreamServerInterceptor(cfg Config) grpc.StreamServerInterceptor
```
Extract bearer token from gRPC metadata (`authorization` key). Re-use same core logic as existing middleware.

---

## Priority 5 — Long-term

### TASK-15: Token Exchange (RFC 8693)
Allow services to exchange tokens for narrower-scoped delegation tokens. New package: `pkg/core/tokenexchange/`.

### TASK-16: FAPI 2.0
PAR (RFC 9126) + mTLS sender-constrained tokens. Requires TLS client certificate extraction in middleware.

### TASK-17: Policy UI
Web-based editor at `/admin/ui` that reads/writes `policy.yaml` and calls `POST /admin/policy/reload`. Build as embedded `http.FS` in the binary.

---

## Recommended Execution Order

```
Week 1:  TASK-01 + TASK-02          → service runs, policies are safe
Week 1:  TASK-03 + TASK-04          → DPoP wired, webhook secured
Week 2:  TASK-05 + TASK-06          → CLI works, Redis wired
Week 2:  TASK-08 + TASK-09 + TASK-10 → core test coverage
Week 3:  TASK-07 + TASK-11          → step-up state, integration tests
Week 4+: TASK-12 → TASK-14          → medium-term features
```

---

## Headroom References

| Hash | Content |
|------|---------|
| `cfc1113fd26ada297c1cf389` | Full architecture snapshot (packages, interfaces, env vars) |
| `94d8f2a261e0acfae0d4c5b3` | Feature audit findings (all gaps + what is complete) |
