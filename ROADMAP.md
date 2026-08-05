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

# Giai đoạn 2 — Từ "production-ready" thành "production-grade at scale"

Giai đoạn 1 (M1–M4) đã xong: gateway an toàn, chạy standalone, có CI. Giai đoạn 2 tập trung
**vận hành thật ở scale** (HA, TLS, config), **đào sâu chuẩn** (RFC 8693/8705, local JWT mode),
**policy engine v2**, và **DX/hệ sinh thái**.

Nguyên tắc ưu tiên giữ nguyên: những gì chặn deploy thật trước, tính năng mới sau.

---

## 🔴 Milestone 5 — Vận hành thật & HA (chặn deploy multi-instance)

Hiện `iam-service` chỉ chạy đúng khi single-instance (memory cache, không TLS, config toàn env).

- [x] **TLS termination** — `internal/server`: `IAM_TLS_CERT_FILE`/`IAM_TLS_KEY_FILE` → `ListenAndServeTLS`; bật `Secure` cho step-up cookie khi có TLS; tùy chọn mTLS client-cert (`IAM_TLS_CLIENT_CA`) làm nền cho RFC 8705 ở M6.
- [x] **Wire Redis vào service** — `IAM_REDIS_ADDR` → `goredis` adapter cho: token cache, DPoP jti replay cache, revocation index. Không có Redis + nhiều replica = revocation/replay-protection chỉ có hiệu lực per-instance (phải log warning).
- [x] **Config file đa tenant** — `iam.yaml`: danh sách tenants (mỗi tenant: provider type, discovery URL, client credentials, resolver rules), thay cho single-tenant-qua-env. Env vẫn override được. Schema validate khi boot.
- [x] **Hot-reload** — file watcher (hoặc SIGHUP) cho policy file + tenant config; đã có `POST /admin/policy/reload`, thêm reload tenants.
- [x] **Distributed rate limiting** — limiter hiện tại là in-memory per-instance; thêm biến thể Redis (INCR + EXPIRE hoặc sliding window) khi có `IAM_REDIS_ADDR`.
- [x] **Readiness tách khỏi liveness** — `/health/live` (process ok) vs `/health/ready` (AS discovery + Redis reachable); K8s probe được đúng.

**Exit criteria:** 2 replica iam-service sau LB chia sẻ revocation + DPoP replay state qua Redis; boot từ `iam.yaml` với ≥2 tenants; chạy TLS end-to-end trong docker-compose.

---

## 🟠 Milestone 6 — Đào sâu chuẩn OAuth/OIDC

- [x] **Local JWT validation mode** — per-tenant option dùng `JWTValidator` (JWKS) thay introspection round-trip; bắt buộc set `ExpectedIssuer`/`ExpectedAudience`; fallback introspection cho opaque token. Trade-off revocation-lag phải document.
- [x] **Wire Token Exchange (RFC 8693)** — lib `pkg/core/tokenexchange` đã có `Client.Exchange`; thêm endpoint `/token/exchange` ở gateway (delegation/impersonation có policy gate: scope `token:exchange` + audit event riêng).
- [x] **mTLS sender-constrained tokens (RFC 8705)** — verify `cnf.x5t#S256` với client cert từ TLS handshake, là alternative cho DPoP; `fapi.ValidateTokenBinding` đã có sẵn hook `allowMTLS`.
- [x] **OIDC Back-Channel Logout** — parse logout token (JWT, event `http://schemas.openid.net/event/backchannel-logout`) trên `/webhook/revoke`, map `sid`/`sub` vào revocation index hiện có.
- [x] **Resource Indicators (RFC 8707)** — policy per-resource `aud` check: request tới upstream X yêu cầu token có `aud` chứa X.
- [x] **JWKS rotation hardening** — refresh theo `Cache-Control`, retry với backoff, metric `iam_jwks_refresh_failures_total`.

**Exit criteria:** rfc-compliance audit pass cho RFC 8693/8705/8707 + back-channel logout; local-JWT mode đo được p99 < 1ms trên benchmark (thực đo ~48µs/op).

---

## 🟡 Milestone 7 — Policy engine v2

- [ ] **Điều kiện mở rộng** — `require_roles`, IP CIDR allowlist/denylist, time-window (giờ làm việc), match theo request header.
- [ ] **Tenant-scoped policies** — policy có field `tenants: [...]`; engine nhận `TenantID` trong `PolicyRequest`.
- [ ] **Explicit deny + priority** — rule `effect: deny` thắng allow; sort theo `priority` thay vì thứ tự file.
- [ ] **Policy test framework** — `iam-cli policy-test <policy.yaml> <tests.yaml>`: bảng test case (request → expected) chạy trong CI của người dùng; xuất diff khi đổi policy.
- [ ] **Plugin interface cho external PDP** — interface `Evaluator` để cắm CEL expression hoặc OPA sidecar mà không đổi guard.
- [ ] **Admin API v2** — CRUD policy qua API (hiện chỉ reload cả file), version + rollback, OpenAPI spec.

**Exit criteria:** policy có deny/priority/tenant-scope chạy đúng bộ policy-test; simulator + CLI hỗ trợ đủ field mới.

---

## 🟢 Milestone 8 — DX & hệ sinh thái

- [ ] **Quickstart docker-compose thật** — gateway + Keycloak + demo upstream + Grafana/Prometheus; README walkthrough 5 phút.
- [ ] **Helm chart / K8s manifests** — deployment (sidecar mode + gateway mode), HPA, probes từ M5.
- [ ] **Grafana dashboard JSON** — introspection latency, cache hit ratio, step-up rate, policy denials, rate-limit drops.
- [ ] **Audit sink mở rộng** — file rotation, webhook sink, ví dụ Kafka producer; schema audit event version hóa.
- [ ] **Middleware bổ sung** — `chi`, `fiber` adapter (theo pattern gin/echo, ~thin wrapper); streaming interceptor cho gRPC.
- [ ] **Load test harness** — k6 script + make target `make loadtest`; ngưỡng p99 làm gate CI (nightly, không chặn PR).
- [ ] **Docs giai đoạn 2** — `docs/deployment.md` update (TLS/Redis/multi-tenant config), `docs/token-exchange.md`, `docs/policy-v2.md`.

**Exit criteria:** người mới clone repo → chạy quickstart → thấy step-up flow hoạt động trong <10 phút; chart deploy được lên kind/minikube.

---

## Trạng thái nhanh

| Milestone | Nội dung | Trạng thái |
|---|---|---|
| M1 | Security blockers | ✅ Hoàn thành |
| M2 | Standalone binaries | ✅ Hoàn thành |
| M3 | Hardening & RFC gaps | ✅ Hoàn thành |
| M4 | Quality & ops | ✅ Hoàn thành |
| M5 | Vận hành thật & HA | ✅ Hoàn thành |
| M6 | Đào sâu chuẩn OAuth/OIDC | ✅ Hoàn thành |
| M7 | Policy engine v2 | ⬜ Chưa bắt đầu |
| M8 | DX & hệ sinh thái | ⬜ Chưa bắt đầu |

> Library primitives (PKCE, RAR, Token Exchange, providers, middleware, telemetry, devkit) **đã production-ready**. Token Exchange/mTLS binding đã có lib primitives — M6 chỉ là wiring vào gateway.
