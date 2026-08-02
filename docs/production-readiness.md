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
| 5 | Multi-tenant registry & resolver chain | `pkg/tenant` | — | 100% | **C** | ⚠️ Thiếu issuer binding |
| 6 | Middleware (gin/echo/stdlib/grpc) | `pkg/middleware/*` | — | 75–92% | **B** | ✅ Sẵn sàng |
| 7 | Telemetry (slog/Prometheus/OTel/audit) | `pkg/telemetry` | RFC 8417 | 61.9% | **B** | ✅ Sẵn sàng |
| 8 | DevKit (LocalAS/TokenFactory/Simulator) | `pkg/devkit/*` | — | 83–96% | **A** | ✅ Dev/test only |
| 9 | Step-up challenge (WWW-Authenticate) | `pkg/core/stepup` | RFC 9470 | 97.1% | **B-** | ⚠️ Challenge OK, state machine chưa wired |
| 10 | Policy engine (YAML, ACR hierarchy) | `pkg/core/policy` | — | ~76% | **B** | ✅ `**` glob + max_age đã vá (M1.4/M1.5) |
| 11 | Token introspection | `pkg/core/token` | RFC 7662 | 62.0% | **B-** | ⚠️ Thiếu `aud` enforcement (M3) |
| 12 | JWT validation | `pkg/core/token` | — | 62.0% | **C** | ⚠️ Thiếu iss/aud/alg allowlist (M3) |
| 13 | Token cache (memory/Redis) | `pkg/core/token` + `goredis` | — | 62% / 0% | **C** | ⚠️ TTL không clamp theo exp (M3) |
| 14 | Token revocation webhook | `pkg/core/token` | RFC 7009 | 62.0% | **B** | ✅ JTI/subject index đã vá (M1.3) |
| 15 | DPoP proof-of-possession | `pkg/core/token` | RFC 9449 | 62.0% | **B** | ✅ Bind `cnf.jkt` + chống replay (M1.2); còn thiếu nonce (M3) |
| 16 | FAPI 2.0 + PAR | `pkg/core/fapi` | RFC 9126 | 90.0% | **C** | ⚠️ Viết đúng nhưng chưa gọi từ gateway (M3) |
| 17 | Gateway guard + reverse proxy | `internal/gateway` | — | ~80% | **B-** | ✅ Cookie replay bypass đã vá (M1.1); còn TTL/tenant fallback (M3) |
| 18 | Admin API + UI | `internal/admin` | — | 68.1% | **B** | ✅ Sẵn sàng (cần authz) |
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

## ✅ Milestone 1 — ĐÃ VÁ (security blockers)

> Tất cả 5 security blocker đã fix + test, `go test ./... -race` xanh. Xem
> [`docs/design-roadmap.md`](design-roadmap.md) cho thiết kế.

### DPoP (RFC 9449) — Grade D → **B** (M1.2)
- [x] **CRITICAL:** So `cnf.jkt` thumbprint (RFC 7638) của proof với access token — `DPoPProof.VerifyBinding`; kẻ có bearer token bị đánh cắp + keypair riêng nay bị reject. `CommonClaims`/`IntrospectionResponse` có field `CNF`.
- [x] **CRITICAL:** `MemoryReplayGuard` chống replay `jti` trong cửa sổ `MaxAge`.
- [x] **HIGH:** `ath` bắt buộc trong `VerifyBinding`.
- [x] `RequireHTTPS` được enforce trên `htu`.
- [ ] Server-issued nonce (RFC 9449 §8) — còn lại ở **M3**.

### Gateway guard — Grade D → **B-** (M1.1)
- [x] **CRITICAL:** Policy giờ chấm đúng **effective (served) path** trước khi replay → bronze token + cookie trỏ resource cao bị re-challenge. Có regression test `TestGuard_StepUpCookieReplay_NoBypass`.
- [ ] **HIGH:** Cache TTL `ttl <= 0` vẫn cache 30s — còn lại ở **M3**. *(guard.go)*
- [ ] **MEDIUM:** Tenant resolve fail-open `"default"` — **M3**.
- [ ] **MEDIUM:** Proxy không strip `X-Tenant-ID` client gửi — **M3**.

### Token revocation (RFC 7009) — Grade D → **B** (M1.3)
- [x] **HIGH:** `TokenIndex` (jti/subject → tokenHash); revoke theo `jti` nay xóa đúng cache entry (không còn no-op). Không index → trả lỗi thay vì no-op.
- [x] **HIGH:** `RevokeAll` theo subject xóa đúng token của subject đó (bỏ `Flush()` toàn cục); test xác nhận không đụng subject khác.

### Policy engine — Grade C → **B** (M1.4 + M1.5)
- [x] **CRITICAL:** `**` glob yêu cầu ranh giới `/` → `/public/**` không còn khớp `/publicSECRET/admin`. Có bảng test bypass.
- [x] **HIGH:** `max_age` fail-closed — thiếu `auth_time` mà policy yêu cầu max_age → deny. `PolicyRequest.HasAuthTime` set ở guard + 4 middleware + simulator.

### JWT / introspection / cache — Grade C
- [ ] **MEDIUM:** Introspection response không có field `aud`, không enforce audience. *(introspect.go:17-34)*
- [ ] **MEDIUM:** JWT validate không truyền `jwt.WithIssuer`/`WithAudience`. *(jwtvalidator.go:59-62)*
- [ ] **MEDIUM:** Không có `jwt.WithValidMethods` allowlist thuật toán (chống RS256→HS256 confusion đang dựa vào type assertion). *(jwtvalidator.go:59-62)*
- [ ] **MEDIUM:** `CachedIntrospector` TTL cố định, không clamp theo `claims.ExpiresAt`. *(cache.go:159-185)*

### Step-up state machine — Grade B-
- [ ] **HIGH:** `Complete()`/`Fail()` không bao giờ được gọi từ guard → bảo vệ "no backward transition" không có tác dụng runtime.
- [ ] **MEDIUM:** CSRF `StateID` được sinh nhưng `BeginChallenge` không set. *(statemachine.go:59,113-120)*

### FAPI 2.0 + PAR — Grade C
- [ ] `fapi.ValidateRequest` viết đúng nhưng `CommonClaims` không implement interface → không được gọi từ gateway. "FAPI mode" hiện không enforce gì cả. *(profile.go:22-38)*

### Multi-tenant — Grade C
- [ ] **HIGH:** Không cross-check `claims.Issuer` với issuer của tenant đã resolve → token tenant A + header `X-Tenant-ID: B` có thể bị đánh giá theo policy tenant B. *(resolver.go:29-35, guard.go:100-104)*

---

## Còn lại

- [x] **`cmd/iam-service`** (M2) — entrypoint gateway standalone; dev mode tự khởi động LocalAS + in demo token; graceful shutdown. Smoke-test: bronze token được phép ở tier của nó, bị step-up challenge đúng RFC 9470 khi POST payments.
- [x] **`cmd/iam-cli`** (M2) — `policy-check`, `token issue`, `introspect`, `version`.
- [x] **Env-var wiring** (M2) — `cmd/iam-service/config.go` đọc `IAM_ADDR`, `IAM_REALM`, `IAM_POLICY_FILE`, `IAM_UPSTREAM_URL`, `IAM_OIDC_*`, `IAM_LOG_FORMAT`, `IAM_COOKIE_SECRET`, `IAM_WEBHOOK_SECRET`, `IAM_ADMIN_TOKEN`, `IAM_ENABLE_DPOP`.
- [ ] Redis adapter (`goredis`) coverage 0% — chỉ có mock test, chưa có integration test với Redis thật (**M4**).
- [ ] Public-path policy không thể đạt tới nếu không có token (guard extract token trước policy) — cân nhắc ở **M3**.
