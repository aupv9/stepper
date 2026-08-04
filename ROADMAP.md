# Roadmap

Lộ trình đưa **common-iam (stepper)** từ "library đầy đủ tính năng" thành "gateway production-ready".
Xem chi tiết grade từng feature ở [`docs/production-readiness.md`](docs/production-readiness.md).

Nguyên tắc ưu tiên: **security-blocking trước, wiring sau, tính năng mới cuối.**

---

## 🔴 Milestone 1 — Chặn security (bắt buộc trước khi release)

Đây là các lỗi khiến gateway hiện tại *không an toàn* để chạy production. Làm trước tất cả.

- [x] **Vá step-up cookie replay bypass** — `internal/gateway/guard.go:130-178`
  - Re-evaluate policy trên saved path *sau khi* rewrite, và chỉ replay khi flow đạt `StateCompleted`.
  - Wire `StateMachine.Complete()`/`Fail()` vào guard (hiện không được gọi).
- [x] **DPoP binding thật** — `pkg/core/token/dpop.go`, `claims.go`
  - Thêm `cnf.jkt` vào `CommonClaims` + `IntrospectionResponse`.
  - Implement RFC 7638 JWK thumbprint, so với `jkt` sau introspection; reject nếu lệch.
  - Bắt buộc `ath` (không còn optional).
  - Thêm replay cache cho `jti` (TTL = `MaxAge`), tái dùng `token.Cache`.
- [x] **Vá revocation** — `pkg/core/token/revocation.go`
  - JTI revoke: thêm secondary index `jti → tokenHash` để Delete đúng key.
  - `RevokeAll`: xóa theo prefix per-subject/per-tenant, bỏ `Flush()` toàn cục.
- [x] **Vá `**` glob** — `pkg/core/policy/matcher.go:22-30`
  - Yêu cầu ranh giới: `path == prefix || strings.HasPrefix(path, prefix+"/")`.
- [x] **max_age fail-closed** — `pkg/core/policy/engine.go:86-94`
  - Khi `p.MaxAge > 0` mà không có `auth_time` → deny (không skip).

**Exit criteria:** security review chạy lại không còn finding Critical/High; test regression cho từng bypass.

---

## 🟠 Milestone 2 — Chạy được standalone

Không có `cmd/`, gateway mode trong README/CLAUDE.md không thể build. Đây là gap "chức năng" lớn nhất.

- [x] **`cmd/iam-service/main.go`** — wiring đầy đủ:
  - Đọc env (`IAM_ADDR`, `IAM_REALM`, `IAM_POLICY_FILE`, `IAM_UPSTREAM_URL`, `IAM_OIDC_*`, `IAM_LOG_FORMAT`).
  - Dev mode tự khởi động LocalAS khi thiếu `IAM_OIDC_DISCOVERY_URL` (đúng như README mô tả).
  - Nối guard + proxy + admin + telemetry + graceful server.
- [x] **`cmd/iam-cli/main.go`** — CLI cho policy-check, token-factory, introspect.
- [x] Cập nhật `make service` / `make cli` chạy được; smoke test trong `tests/integration`.

**Exit criteria:** `go build ./cmd/...` pass; `./iam-service` boot ở dev mode; Quickstart trong README reproduce được.

---

## 🟡 Milestone 3 — Hardening & đóng gap RFC còn lại

- [x] **Audience/issuer enforcement** — thêm `aud` vào `IntrospectionResponse`; truyền `jwt.WithIssuer`/`WithAudience`/`WithValidMethods` vào JWT validator.
- [x] **Cross-tenant binding** — assert `claims.Issuer == provider.Issuer()` sau introspection; document `HeaderResolver` chỉ dùng sau trusted edge.
- [x] **Cache TTL clamp** — `min(configuredTTL, time.Until(exp))`, không cache khi `ttl <= 0` (cả `guard.go` lẫn `CachedIntrospector`).
- [x] **Proxy header hygiene** — strip `X-Tenant-ID` client gửi, re-inject `X-Iam-*` từ context đã verify.
- [x] **Wire FAPI 2.0** — `CommonClaims` implement interface FAPI; gọi `fapi.ValidateRequest` từ guard sau introspection, gate bằng config.
- [x] **CSRF StateID** — `saved.StateID` được sinh trong `BeginChallenge` và lưu trong cookie ký HMAC. (Việc propagate làm OAuth `state` là client-driven — gateway không tự redirect tới AS; cookie ký + re-evaluate policy khi replay đã chặn CSRF-driven replay.)
- [x] **Tenant resolve fail-closed** — bỏ fallback `"default"` ngầm; chỉ opt-in cho single-tenant.
- [x] **DPoP nonce** — server-issued nonce (RFC 9449 §8).

---

## 🟢 Milestone 4 — Chất lượng & vận hành

- [x] Nâng coverage `pkg/core/token` (56% → ≥80%) — trọng tâm dpop/revocation/cache sau khi vá.
- [x] Integration test Redis thật cho `goredis` (hiện 0%, chỉ mock).
- [x] Authz cho Admin API/UI (hiện chưa có lớp bảo vệ endpoint admin).
- [x] Rate limiting ở guard.
- [x] Benchmark introspection cache-hit path (`BenchmarkCachedIntrospector_CacheHit`, ~510ns/op). Load test end-to-end vẫn nên chạy trước release thật.
- [x] `token_type_hint` cho introspection (RFC 7662 SHOULD).
- [x] CI: `make lint` + `make test` gate; publish coverage.

---

## Trạng thái nhanh

| Milestone | Nội dung | Trạng thái |
|---|---|---|
| M1 | Security blockers | ✅ Hoàn thành |
| M2 | Standalone binaries | ✅ Hoàn thành |
| M3 | Hardening & RFC gaps | ✅ Hoàn thành |
| M4 | Quality & ops | ✅ Hoàn thành |

> Library primitives (PKCE, RAR, Token Exchange, providers, middleware, telemetry, devkit) **đã production-ready** và không nằm trong critical path của các milestone trên.
