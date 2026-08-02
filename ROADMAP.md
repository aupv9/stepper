# Roadmap

Lộ trình đưa **common-iam (stepper)** từ "library đầy đủ tính năng" thành "gateway production-ready".
Xem chi tiết grade từng feature ở [`docs/production-readiness.md`](docs/production-readiness.md).

Nguyên tắc ưu tiên: **security-blocking trước, wiring sau, tính năng mới cuối.**

---

## 🔴 Milestone 1 — Chặn security (bắt buộc trước khi release)

Đây là các lỗi khiến gateway hiện tại *không an toàn* để chạy production. Làm trước tất cả.

- [ ] **Vá step-up cookie replay bypass** — `internal/gateway/guard.go:130-178`
  - Re-evaluate policy trên saved path *sau khi* rewrite, và chỉ replay khi flow đạt `StateCompleted`.
  - Wire `StateMachine.Complete()`/`Fail()` vào guard (hiện không được gọi).
- [ ] **DPoP binding thật** — `pkg/core/token/dpop.go`, `claims.go`
  - Thêm `cnf.jkt` vào `CommonClaims` + `IntrospectionResponse`.
  - Implement RFC 7638 JWK thumbprint, so với `jkt` sau introspection; reject nếu lệch.
  - Bắt buộc `ath` (không còn optional).
  - Thêm replay cache cho `jti` (TTL = `MaxAge`), tái dùng `token.Cache`.
- [ ] **Vá revocation** — `pkg/core/token/revocation.go`
  - JTI revoke: thêm secondary index `jti → tokenHash` để Delete đúng key.
  - `RevokeAll`: xóa theo prefix per-subject/per-tenant, bỏ `Flush()` toàn cục.
- [ ] **Vá `**` glob** — `pkg/core/policy/matcher.go:22-30`
  - Yêu cầu ranh giới: `path == prefix || strings.HasPrefix(path, prefix+"/")`.
- [ ] **max_age fail-closed** — `pkg/core/policy/engine.go:86-94`
  - Khi `p.MaxAge > 0` mà không có `auth_time` → deny (không skip).

**Exit criteria:** security review chạy lại không còn finding Critical/High; test regression cho từng bypass.

---

## 🟠 Milestone 2 — Chạy được standalone

Không có `cmd/`, gateway mode trong README/CLAUDE.md không thể build. Đây là gap "chức năng" lớn nhất.

- [ ] **`cmd/iam-service/main.go`** — wiring đầy đủ:
  - Đọc env (`IAM_ADDR`, `IAM_REALM`, `IAM_POLICY_FILE`, `IAM_UPSTREAM_URL`, `IAM_OIDC_*`, `IAM_LOG_FORMAT`).
  - Dev mode tự khởi động LocalAS khi thiếu `IAM_OIDC_DISCOVERY_URL` (đúng như README mô tả).
  - Nối guard + proxy + admin + telemetry + graceful server.
- [ ] **`cmd/iam-cli/main.go`** — CLI cho policy-check, token-factory, introspect.
- [ ] Cập nhật `make service` / `make cli` chạy được; smoke test trong `tests/integration`.

**Exit criteria:** `go build ./cmd/...` pass; `./iam-service` boot ở dev mode; Quickstart trong README reproduce được.

---

## 🟡 Milestone 3 — Hardening & đóng gap RFC còn lại

- [ ] **Audience/issuer enforcement** — thêm `aud` vào `IntrospectionResponse`; truyền `jwt.WithIssuer`/`WithAudience`/`WithValidMethods` vào JWT validator.
- [ ] **Cross-tenant binding** — assert `claims.Issuer == provider.Issuer()` sau introspection; document `HeaderResolver` chỉ dùng sau trusted edge.
- [ ] **Cache TTL clamp** — `min(configuredTTL, time.Until(exp))`, không cache khi `ttl <= 0` (cả `guard.go` lẫn `CachedIntrospector`).
- [ ] **Proxy header hygiene** — strip `X-Tenant-ID` client gửi, re-inject `X-Iam-*` từ context đã verify.
- [ ] **Wire FAPI 2.0** — `CommonClaims` implement interface FAPI; gọi `fapi.ValidateRequest` từ guard sau introspection, gate bằng config.
- [ ] **CSRF StateID** — set `saved.StateID` trong `BeginChallenge`, propagate làm OAuth `state`, verify khi quay lại.
- [ ] **Tenant resolve fail-closed** — bỏ fallback `"default"` ngầm; chỉ opt-in cho single-tenant.
- [ ] **DPoP nonce** — server-issued nonce (RFC 9449 §8).

---

## 🟢 Milestone 4 — Chất lượng & vận hành

- [ ] Nâng coverage `pkg/core/token` (56% → ≥80%) — trọng tâm dpop/revocation/cache sau khi vá.
- [ ] Integration test Redis thật cho `goredis` (hiện 0%, chỉ mock).
- [ ] Authz cho Admin API/UI (hiện chưa có lớp bảo vệ endpoint admin).
- [ ] Rate limiting ở guard.
- [ ] Load test + benchmark introspection cache hit path.
- [ ] `token_type_hint` cho introspection (RFC 7662 SHOULD).
- [ ] CI: `make lint` + `make test` gate; publish coverage.

---

## Trạng thái nhanh

| Milestone | Nội dung | Trạng thái |
|---|---|---|
| M1 | Security blockers | ⬜ Chưa bắt đầu |
| M2 | Standalone binaries | ⬜ Chưa bắt đầu |
| M3 | Hardening & RFC gaps | ⬜ Chưa bắt đầu |
| M4 | Quality & ops | ⬜ Chưa bắt đầu |

> Library primitives (PKCE, RAR, Token Exchange, providers, middleware, telemetry, devkit) **đã production-ready** và không nằm trong critical path của các milestone trên.
