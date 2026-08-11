# Production Readiness — Core Feature Checklist

> Cập nhật: 2026-08-01. Đánh giá dựa trên: build/test toàn bộ (`go test ./... -race`, 25/25 package pass),
> test coverage per-package, security review, và RFC compliance audit.
>
> **Grade key:** `A` = production-ready · `B` = production-ready sau khi vá lỗi nhỏ ·
> `C` = có gap chặn production · `D` = không dùng được trong production ở trạng thái hiện tại.

---

## Tổng quan

| # | Feature | Package | RFC | Coverage | Grade | Production? |
|---|---|---|---|---|---|---|
| 1 | PKCE | `pkg/core/pkce` | RFC 7636 | 90.0% | **A** | ✅ Sẵn sàng |
| 2 | Rich Authorization Requests (RAR) | `pkg/core/rar` | RFC 9396 | 87.7% | **A** | ✅ Sẵn sàng |
| 3 | Token Exchange | `pkg/core/tokenexchange` | RFC 8693 | 85.7% | **A-** | ✅ Sẵn sàng (client role) |
| 4 | Provider adapters (Keycloak/Auth0/Generic) | `pkg/providers/*` | OIDC | 93–100% | **A** | ✅ Sẵn sàng |
| 5 | Multi-tenant registry & resolver chain | `pkg/tenant` | — | 100% | **B** | ✅ Issuer binding + fail-closed (M3.2/M3.4) |
| 6 | Middleware (gin/echo/stdlib/grpc) | `pkg/middleware/*` | — | 75–92% | **B** | ✅ Sẵn sàng |
| 7 | Telemetry (slog/Prometheus/OTel/audit) | `pkg/telemetry` | RFC 8417 | 61.9% | **B** | ✅ Sẵn sàng |
| 8 | DevKit (LocalAS/TokenFactory/Simulator) | `pkg/devkit/*` | — | 83–96% | **A** | ✅ Dev/test only |
| 9 | Step-up challenge (WWW-Authenticate) | `pkg/core/stepup` | RFC 9470 | 97.1% | **B** | ✅ State machine + CSRF StateID wired (M3.5) |
| 10 | Policy engine (YAML, ACR hierarchy) | `pkg/core/policy` | — | ~76% | **B** | ✅ `**` glob + max_age đã vá (M1.4/M1.5) |
| 11 | Token introspection | `pkg/core/token` | RFC 7662 | ~66% | **B** | ✅ `aud`/`cnf`/`nonce` mapped (M3.2/M3.6) |
| 12 | JWT validation | `pkg/core/token` | — | ~66% | **B** | ✅ iss/aud/alg allowlist (M3.2) |
| 13 | Token cache (memory/Redis) | `pkg/core/token` + `goredis` | — | 81% / env-gated | **B** | ✅ TTL clamp (M3.1) + Redis integration test (M4.6) |
| 14 | Token revocation webhook | `pkg/core/token` | RFC 7009 | ~66% | **B** | ✅ JTI/subject index đã vá (M1.3) |
| 15 | DPoP proof-of-possession | `pkg/core/token` | RFC 9449 | 81% | **A-** | ✅ Bind `cnf.jkt` + replay + server nonce §8 (M1.2/M4.4) |
| 16 | FAPI 2.0 + PAR | `pkg/core/fapi` | RFC 9126 | 90.0% | **B** | ✅ Wired vào guard qua `FAPIProfile` (M3.6) |
| 17 | Gateway guard + reverse proxy | `internal/gateway` | — | ~82% | **B** | ✅ Bypass/TTL/tenant/headers/issuer đã vá (M1.1/M3.x) |
| 18 | Admin API + UI | `internal/admin` | — | 68.1% | **B** | ✅ Bearer authz constant-time (M4.2) |
| 19 | HTTP server (graceful shutdown) | `internal/server` | — | 100% | **A** | ✅ Sẵn sàng |
| 20 | Standalone binaries (`cmd/`) | `cmd/iam-{service,cli}` | — | config test | **B** | ✅ Đã tạo + wiring env (M2) |

---

## ✅ Đã grade PRODUCTION (dùng ngay được)

Những feature dưới đây đã pass test, đúng RFC, không có gap chặn production:

- [x] **PKCE (RFC 7636)** — verifier 43–128 ký tự đúng charset, S256, so sánh constant-time; hỗ trợ cấm `plain` cho FAPI 2.0. *Package hoàn chỉnh nhất.*
- [x] **RAR (RFC 9396)** — round-trip `authorization_details`, filter matching (type + actions + field subset), wired end-to-end tới policy engine.
- [x] **Token Exchange (RFC 8693)** — client role đầy đủ, validate 3 field response bắt buộc.
- [x] **Provider adapters** — Keycloak & Auth0 coverage 100%, Generic 93.6%, claims mapper riêng.
- [x] **Middleware gin/echo/stdlib/grpc** — thin wrapper, coverage 75–92%.
- [x] **Telemetry** — slog + Prometheus + OpenTelemetry + audit log, emit trên cả allow/deny.
- [x] **DevKit** — LocalAS mock, TokenFactory, PolicySimulator (chỉ dùng dev/test, không production runtime).
- [x] **HTTP server** — graceful shutdown, coverage 100%.

---

## ✅ Milestone 1 + 3 — ĐÃ VÁ (security & hardening)

> M1 (5 security blocker) + M3 (hardening & RFC gaps) đã fix + test,
> `go test ./... -race` xanh. Xem [`docs/design-roadmap.md`](design-roadmap.md) cho thiết kế.
> Còn lại: DPoP server-issued nonce (RFC 9449 §8) → M4.

### DPoP (RFC 9449) — Grade D → **B** (M1.2)
- [x] **CRITICAL:** So `cnf.jkt` thumbprint (RFC 7638) của proof với access token — `DPoPProof.VerifyBinding`; kẻ có bearer token bị đánh cắp + keypair riêng nay bị reject. `CommonClaims`/`IntrospectionResponse` có field `CNF`.
- [x] **CRITICAL:** `MemoryReplayGuard` chống replay `jti` trong cửa sổ `MaxAge`.
- [x] **HIGH:** `ath` bắt buộc trong `VerifyBinding`.
- [x] `RequireHTTPS` được enforce trên `htu`.
- [ ] Server-issued nonce (RFC 9449 §8) — còn lại ở **M4**.

### Gateway guard — Grade D → **B** (M1.1 + M3.x)
- [x] **CRITICAL:** Policy giờ chấm đúng **effective (served) path** trước khi replay → bronze token + cookie trỏ resource cao bị re-challenge. Có regression test `TestGuard_StepUpCookieReplay_NoBypass`.
- [x] **HIGH:** Cache TTL clamp — không cache khi `ttl <= 0`, clamp theo remaining lifetime (M3.1).
- [x] **MEDIUM:** Tenant resolve fail-closed — bỏ fallback ngầm, opt-in `DefaultTenant` (M3.4).
- [x] **MEDIUM:** Strip `X-Tenant-ID` client gửi + inject `X-Iam-*` đã verify (M3.3).

### Token revocation (RFC 7009) — Grade D → **B** (M1.3)
- [x] **HIGH:** `TokenIndex` (jti/subject → tokenHash); revoke theo `jti` nay xóa đúng cache entry (không còn no-op). Không index → trả lỗi thay vì no-op.
- [x] **HIGH:** `RevokeAll` theo subject xóa đúng token của subject đó (bỏ `Flush()` toàn cục); test xác nhận không đụng subject khác.

### Policy engine — Grade C → **B** (M1.4 + M1.5)
- [x] **CRITICAL:** `**` glob yêu cầu ranh giới `/` → `/public/**` không còn khớp `/publicSECRET/admin`. Có bảng test bypass.
- [x] **HIGH:** `max_age` fail-closed — thiếu `auth_time` mà policy yêu cầu max_age → deny. `PolicyRequest.HasAuthTime` set ở guard + 4 middleware + simulator.

### JWT / introspection / cache — Grade C → **B** (M3.1 + M3.2)
- [x] **MEDIUM:** `IntrospectionResponse.Aud` (`Audience` unmarshal string/array) → `CommonClaims.Audience`.
- [x] **MEDIUM:** JWT validate truyền `jwt.WithIssuer`/`WithAudience` (tùy chọn qua config).
- [x] **MEDIUM:** `jwt.WithValidMethods` allowlist asymmetric-only (chặn RS256→HS256 + none).
- [x] **MEDIUM:** `CachedIntrospector` clamp TTL theo `claims.ExpiresAt`, không cache khi hết hạn.

### Step-up state machine — Grade B- → **B** (M3.5)
- [x] **HIGH:** Guard gọi `Complete()`/`Fail()` khi replay → transition guarantee có tác dụng runtime.
- [x] **MEDIUM:** `BeginChallenge` set `saved.StateID` (CSRF).

### FAPI 2.0 + PAR — Grade C → **B** (M3.6)
- [x] `CommonClaims` implement `fapi.TokenClaims`; guard gọi `fapi.ValidateRequest` gate bằng `FAPIProfile`. Test xác nhận token thường bị reject khi bật.

### Multi-tenant — Grade C → **B** (M3.2 + M3.4)
- [x] **HIGH:** Guard cross-check `claims.Issuer == provider.Issuer()` → token tenant A + header `X-Tenant-ID: B` bị reject.

---

## Còn lại

- [x] **`cmd/iam-service`** (M2) — entrypoint gateway standalone; dev mode tự khởi động LocalAS + in demo token; graceful shutdown. Smoke-test: bronze token được phép ở tier của nó, bị step-up challenge đúng RFC 9470 khi POST payments.
- [x] **`cmd/iam-cli`** (M2) — `policy-check`, `token issue`, `introspect`, `version`.
- [x] **Env-var wiring** (M2) — `cmd/iam-service/config.go` đọc `IAM_ADDR`, `IAM_REALM`, `IAM_POLICY_FILE`, `IAM_UPSTREAM_URL`, `IAM_OIDC_*`, `IAM_LOG_FORMAT`, `IAM_COOKIE_SECRET`, `IAM_WEBHOOK_SECRET`, `IAM_ADMIN_TOKEN`, `IAM_ENABLE_DPOP`.
- [x] Redis adapter (`goredis`) — env-gated integration test (`IAM_TEST_REDIS_ADDR`) + `fakeRedis` unit test (M4.6).
- [x] DPoP server-issued nonce (RFC 9449 §8) — `NonceService` + guard `use_dpop_nonce` (M4.4).
- [x] Rate limiting — token-bucket per client IP, 429 (M4.3).
- [x] CI — GitHub Actions: build + vet + race test + coverage + gofmt + golangci-lint (M4.5).
- [ ] Load test end-to-end — cần môi trường tải riêng.
- [ ] Public-path policy không thể đạt tới nếu không có token (guard extract token trước policy) — cân nhắc thiết kế.
