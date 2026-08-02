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
| 10 | Policy engine (YAML, ACR hierarchy) | `pkg/core/policy` | — | 73.6% | **C** | ⚠️ `**` glob + max_age fail-open |
| 11 | Token introspection | `pkg/core/token` | RFC 7662 | 56.1% | **B-** | ⚠️ Thiếu `aud` enforcement |
| 12 | JWT validation | `pkg/core/token` | — | 56.1% | **C** | ⚠️ Thiếu iss/aud/alg allowlist |
| 13 | Token cache (memory/Redis) | `pkg/core/token` + `goredis` | — | 56% / 0% | **C** | ⚠️ TTL không clamp theo exp |
| 14 | Token revocation webhook | `pkg/core/token` | RFC 7009 | 56.1% | **D** | ❌ JTI revoke là no-op |
| 15 | DPoP proof-of-possession | `pkg/core/token` | RFC 9449 | 56.1% | **D** | ❌ Không bind `cnf.jkt`, không chống replay |
| 16 | FAPI 2.0 + PAR | `pkg/core/fapi` | RFC 9126 | 90.0% | **C** | ⚠️ Viết đúng nhưng chưa gọi từ gateway |
| 17 | Gateway guard + reverse proxy | `internal/gateway` | — | 78.3% | **D** | ❌ Cookie replay bypass step-up |
| 18 | Admin API + UI | `internal/admin` | — | 68.1% | **B** | ✅ Sẵn sàng (cần authz) |
| 19 | HTTP server (graceful shutdown) | `internal/server` | — | 100% | **A** | ✅ Sẵn sàng |
| 20 | Standalone binaries (`cmd/`) | — | — | ∅ | **F** | ❌ Chưa tồn tại |

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

## ⚠️ Có code nhưng CHẶN production (cần vá)

### DPoP (RFC 9449) — Grade D — **security theater ở trạng thái hiện tại**
- [ ] **CRITICAL:** Không so `cnf.jkt` thumbprint của proof với access token → kẻ có bearer token bị đánh cắp tự tạo keypair vẫn pass. `CommonClaims` không có field `cnf`/`jkt`. *(dpop.go:53-101, claims.go)*
- [ ] **CRITICAL:** Không có replay cache cho `jti` → proof bị bắt lại có thể replay trong cửa sổ `MaxAge`. *(dpop.go:41,132-145)*
- [ ] **HIGH:** `ath` chỉ check khi non-empty → bỏ `ath` là bỏ qua check. *(dpop.go:92-98)*
- [ ] `DPoPConfig.RequireHTTPS` được document nhưng **không bao giờ đọc** — no-op. *(dpop.go:22-31)*
- [ ] Thiếu server-issued nonce (RFC 9449 §8).

### Gateway guard — Grade D — **step-up bypass**
- [ ] **CRITICAL:** Cookie step-up được rewrite path sang saved path **sau khi** policy đã check path hiện tại, không re-evaluate → bronze token với tới được resource yêu cầu step-up. *(guard.go:130-178)*
- [ ] **HIGH:** Cache TTL: token đã hết hạn (`ttl <= 0`) vẫn cache 30s như token bình thường. *(guard.go:196-201)*
- [ ] **MEDIUM:** Tenant resolve lỗi → fallback `"default"` (fail-open). *(guard.go:94-97)*
- [ ] **MEDIUM:** Reverse proxy không strip header `X-Tenant-ID` do client gửi trước khi forward. *(proxy.go:12-26)*

### Token revocation (RFC 7009) — Grade D
- [ ] **HIGH:** Revoke theo `jti` dùng raw JTI làm cache key, nhưng cache key thực là `sha256(token)` → **không bao giờ match**, revoke là no-op. Đây lại là path phổ biến nhất từ AS webhook. *(revocation.go:115-119)*
- [ ] **HIGH:** `RevokeAll` cho 1 subject gọi `Flush()` → xóa cache toàn bộ tenant/user (DoS/stampede). *(revocation.go:121-126)*

### Policy engine — Grade C
- [ ] **CRITICAL:** `**` glob chỉ dùng `strings.HasPrefix` không có ranh giới `/` → `/public/**` khớp cả `/publicSECRET/admin`. *(matcher.go:22-30)*
- [ ] **HIGH:** `max_age` bị bỏ qua hoàn toàn khi token không có `auth_time` (`req.AuthAge == 0`) — fail-open, đúng thứ RFC 9470 muốn ngăn. *(engine.go:86-94)*

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

## ❌ Chưa tồn tại

- [ ] **`cmd/iam-service/main.go`** — entrypoint gateway standalone. README Quickstart + `make service` đang trỏ tới đây.
- [ ] **`cmd/iam-cli/main.go`** — CLI. `make cli` đang fail.
- [ ] **Env-var wiring** (`IAM_ADDR`, `IAM_POLICY_FILE`, `IAM_UPSTREAM_URL`, ...) — cả bảng env trong CLAUDE.md/README chưa được đọc ở đâu trong code (chỉ có logic ở `internal/`, thiếu `main.go` nối vào).
- [ ] Redis adapter (`goredis`) coverage 0% — chỉ có mock test, chưa có integration test với Redis thật.
