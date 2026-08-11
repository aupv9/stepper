# Roadmap

Lộ trình đưa **common-iam (stepper)** từ "library đầy đủ tính năng" thành "gateway production-ready".
Xem chi tiết grade từng feature ở [`docs/production-readiness.md`](docs/production-readiness.md).

Nguyên tắc ưu tiên: **security-blocking trước, wiring sau, tính năng mới cuối.**

---

## ✅ Milestone 1 — Chặn security (HOÀN TẤT)

Đây là các lỗi khiến gateway *không an toàn* để chạy production. Đã vá toàn bộ + test,
`go test ./... -race` xanh. Thiết kế: [`docs/design-roadmap.md`](docs/design-roadmap.md).

- [x] **Vá step-up cookie replay bypass** (M1.1) — guard chấm policy trên **effective (served) path**
  trước khi replay; regression test `TestGuard_StepUpCookieReplay_NoBypass`.
- [x] **DPoP binding thật** (M1.2) — `cnf.jkt` trong `CommonClaims`/`IntrospectionResponse`;
  `JWKThumbprint` (RFC 7638, verify bằng test vector); `VerifyBinding` (ath bắt buộc + jkt khớp,
  constant-time); `MemoryReplayGuard` chống replay jti; enforce `RequireHTTPS`.
- [x] **Vá revocation** (M1.3) — `TokenIndex` (jti/subject → tokenHash); revoke đúng cache entry;
  `RevokeAll` scoped theo subject, bỏ `Flush()` toàn cục.
- [x] **Vá `**` glob** (M1.4) — yêu cầu ranh giới `/`.
- [x] **max_age fail-closed** (M1.5) — thiếu `auth_time` mà policy yêu cầu max_age → deny;
  `PolicyRequest.HasAuthTime`.

**Còn lại (chuyển M3, defense-in-depth):** wire `StateMachine.Complete/Fail`, DPoP server nonce.
**Đề xuất tiếp:** chạy lại security review để xác nhận 0 finding Critical/High.

---

## ✅ Milestone 2 — Chạy được standalone (HOÀN TẤT)

Trước đây không có `cmd/`, gateway mode trong README/CLAUDE.md không build được.

- [x] **`cmd/iam-service`** — wiring đầy đủ: đọc env (`config.go`), dev mode tự khởi động LocalAS +
  in demo token khi thiếu `IAM_OIDC_DISCOVERY_URL`, nối guard + proxy/echo + admin + telemetry +
  graceful shutdown (SIGINT/SIGTERM).
- [x] **`cmd/iam-cli`** — `policy-check`, `token issue`, `introspect`, `version`.
- [x] `make service` / `make cli` / `make binaries` chạy được (đổi sang dạng package vì service có nhiều file).
- [x] Smoke-test thủ công: `./iam-service` boot dev mode; bronze token được phép ở tier của nó và bị
  step-up challenge đúng RFC 9470 (`insufficient_user_authentication`, `acr_values=silver`, `max_age=300`)
  khi POST `/api/payments/**`.

**Đã đạt:** `go build ./cmd/...` pass; `./iam-service` boot dev mode; Quickstart README reproduce được.
**Lưu ý:** sửa được một bug `.gitignore` (`iam-service`/`iam-cli` không anchor → ignore luôn thư mục `cmd/`).

---

## ✅ Milestone 3 — Hardening & đóng gap RFC (gần xong)

- [x] **Audience/issuer/alg enforcement** (M3.2) — `aud` trong `IntrospectionResponse` (`Audience` unmarshal string/array); `JWTValidator` truyền `WithValidMethods` (asymmetric-only, chặn HMAC alg-confusion + none) + `WithIssuer`/`WithAudience` tùy chọn.
- [x] **Cross-tenant binding** (M3.2) — guard reject khi `claims.Issuer != provider.Issuer()`.
- [x] **Cache TTL clamp** (M3.1) — không cache khi `ttl <= 0`; clamp theo remaining lifetime (cả `guard.go` lẫn `CachedIntrospector`).
- [x] **Proxy header hygiene** (M3.3) — strip `X-Tenant-ID` client gửi, inject `X-Iam-Tenant-Id`/`X-Iam-Subject` đã verify.
- [x] **Wire FAPI 2.0** (M3.6) — `CommonClaims` implement `fapi.TokenClaims`; guard gọi `fapi.ValidateRequest` gate bằng `FAPIProfile`.
- [x] **CSRF StateID** (M3.5) — `BeginChallenge` set `saved.StateID`.
- [x] **Tenant resolve fail-closed** (M3.4) — bỏ fallback ngầm; opt-in `DefaultTenant`.
- [x] **Wire state machine** (M3.5) — guard gọi `Complete`/`Fail` (hết dead-code).
- [ ] **DPoP nonce** — server-issued nonce (RFC 9449 §8) — *còn lại, chuyển M4*.

---

## 🟢 Milestone 4 — Chất lượng & vận hành

- [ ] Nâng coverage `pkg/core/token` (56% → ≥80%) — trọng tâm dpop/revocation/cache sau khi vá.
- [ ] Integration test Redis thật cho `goredis` (hiện 0%, chỉ mock).
- [ ] Authz cho Admin API/UI (hiện chưa có lớp bảo vệ endpoint admin).
- [ ] Rate limiting ở guard.
- [ ] Load test + benchmark introspection cache hit path.
- [ ] `token_type_hint` cho introspection (RFC 7662 SHOULD).
- [ ] DPoP server-issued nonce (RFC 9449 §8) — chuyển từ M3.
- [ ] CI: `make lint` + `make test` gate; publish coverage.

---

## Trạng thái nhanh

| Milestone | Nội dung | Trạng thái |
|---|---|---|
| M1 | Security blockers | ✅ Hoàn tất |
| M2 | Standalone binaries | ✅ Hoàn tất |
| M3 | Hardening & RFC gaps | ✅ Hoàn tất (trừ DPoP nonce) |
| M4 | Quality & ops | ⬜ Chưa bắt đầu |

> Library primitives (PKCE, RAR, Token Exchange, providers, middleware, telemetry, devkit) **đã production-ready** và không nằm trong critical path của các milestone trên.
