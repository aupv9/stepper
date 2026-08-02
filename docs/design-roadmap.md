# Design — Roadmap Implementation

Thiết kế kỹ thuật cho các milestone trong [`ROADMAP.md`](../ROADMAP.md). Mỗi mục nêu:
**bug hiện tại → thiết kế → thay đổi file/API cụ thể → test plan.** Signature bám sát code thật
(đã đọc `dpop.go`, `guard.go`, `claims.go`, `engine.go`, `matcher.go`, `revocation.go`,
`statemachine.go`, `cache.go`, `introspect.go`, `registry.go`, `server.go`).

Thứ tự thực thi khuyến nghị: **M1.1 → M1.4 → M1.5 (nhanh, ít rủi ro) → M1.2 → M1.3 → M2**.

---

## M1 — Security blockers

### M1.1 — Vá step-up cookie replay bypass

**Bug** (`internal/gateway/guard.go:130-178`): policy evaluate trên `r.URL.Path` (path A), *sau đó*
đọc cookie rồi rewrite request sang `saved.Path` (path B) và forward **không re-evaluate**. Cookie set
trên *mọi* denial với `Path:"/"` → attacker gửi request tới path A (thấp, allowed) mang cookie trỏ path B
(admin) → được phục vụ path B.

**Nguyên nhân gốc:** "evaluate path A, serve path B". Fix = luôn evaluate đúng path sẽ serve.

**Thiết kế:** Xác định `effectivePath`/`effectiveMethod` *trước* policy eval; policy luôn chấm path sẽ
forward; chỉ replay khi token hiện tại thực sự pass policy của saved path.

```go
// guard.go — thay block 130-178
effReq := policy.PolicyRequest{
    Method: r.Method, Path: r.URL.Path,
    TokenACR: claims.ACR, TokenAMR: claims.AMR,
    TokenScopes: claims.Scopes,
    AuthAge: claims.AuthAge(), HasAuthTime: !claims.AuthTime.IsZero(),
    AuthorizationDetails: claims.AuthorizationDetails,
}
var saved *stepup.SavedRequest
if g.cookieSecret != "" {
    if s, err := stepup.ReadStateCookie(r, g.cookieSecret); err == nil && s != nil && s.Path != "" {
        saved = s
        effReq.Method, effReq.Path = s.Method, s.Path // chấm policy trên path sẽ serve
    }
}
result, evalErr := g.policyEngine.Evaluate(&effReq)
if evalErr != nil { http.Error(w, "policy evaluation error", 500); return }
if !result.Allowed {
    g.handleDenial(ctx, w, r, claims.Subject, tenantID, result) // re-challenge cho effective path
    return
}
// Allowed → nếu có saved thì rewrite sang saved path, rồi clear cookie, forward.
if saved != nil {
    r = r.Clone(r.Context())
    r.URL.Path, r.URL.RawQuery, r.Method = saved.Path, saved.Query, saved.Method
    r.RequestURI = saved.Path
    if saved.Query != "" { r.RequestURI += "?" + saved.Query }
}
if g.cookieSecret != "" { stepup.ClearStateCookie(w) }
```

**Wire state machine (defense-in-depth):** thêm `State` vào `SavedRequest`; `handleDenial` set
`State=StateChallenge`; chỉ replay khi re-eval pass (tương đương `Complete()`). Gọi `sm.Complete(flow)`/
`sm.Fail(flow)` để state machine không còn dead-code — hiện `Complete/Fail` không có caller ngoài test.

**Test:** regression cho kịch bản exploit (bronze token + cookie path admin → phải 401 với challenge của
path admin, không phải 200); test replay hợp lệ (token gold + cookie → serve saved path); test không cookie.

---

### M1.2 — DPoP binding thật (RFC 9449)

**Bug** (`dpop.go:53-101`, `claims.go`): `ValidateDPoP` chỉ verify proof self-consistent; **không so
`cnf.jkt`** (CommonClaims/IntrospectionResponse không có field `cnf`), `ath` chỉ check khi non-empty
(`dpop.go:92-98`), không có replay store cho `jti`, `RequireHTTPS` không được đọc.

**Thiết kế — tách 2 pha** (vì binding cần claims, mà DPoP hiện chạy *trước* introspection ở `guard.go:114`):

1. **Pha 1 — self-consistency** (trước introspection): parse, verify sig, htm/htu/iat, RequireHTTPS.
2. **Pha 2 — bind** (sau introspection, khi biết `claims.CNF`): `ath` bắt buộc + `jkt` khớp + replay.

```go
// claims.go
type Confirmation struct { JKT string `json:"jkt"` } // RFC 7638 JWK SHA-256 thumbprint
// CommonClaims: thêm
CNF *Confirmation `json:"cnf,omitempty"`
JTI string        `json:"jti,omitempty"` // dùng cho revocation index (M1.3)

// introspect.go: IntrospectionResponse thêm  CNF *Confirmation `json:"cnf"`
// introToCommonClaims: map c.CNF = r.CNF; c.JTI = r.JTI

// dpop.go — API mới
func VerifyProof(r *http.Request, cfg DPoPConfig) (*DPoPProof, error) // pha 1 (đổi tên ValidateDPoP)
func JWKThumbprint(jwk map[string]interface{}) (string, error)        // RFC 7638

func (p *DPoPProof) VerifyBinding(accessToken string, cnf *Confirmation) error {
    if p.ATH == "" { return ErrDPoPMissingATH }                       // ath giờ bắt buộc
    if !constEq(p.ATH, hashTokenForDPoP(accessToken)) { return ErrDPoPBindingMismatch }
    if cnf == nil || cnf.JKT == "" { return ErrDPoPNoCnf }
    thumb, err := JWKThumbprint(p.JWK)
    if err != nil { return err }
    if !constEq(thumb, cnf.JKT) { return ErrDPoPBindingMismatch }     // proof key == token key
    return nil
}
```

`JWKThumbprint` theo RFC 7638: chỉ các member bắt buộc, thứ tự lexicographic, JSON không whitespace,
SHA-256, base64url. EC → `{"crv","kty","x","y"}`; RSA → `{"e","kty","n"}`.

**Replay store** — primitive atomic riêng (không nhét vào `Cache` vốn chứa `*CommonClaims`):

```go
// pkg/core/token/replay.go
type ReplayGuard interface {
    // CheckAndSet ghi jti; trả seen=true nếu đã thấy trong ttl (atomic).
    CheckAndSet(ctx context.Context, jti string, ttl time.Duration) (seen bool, err error)
}
// MemoryReplayGuard: map[string]time.Time + mutex + cleanup loop
// RedisReplayGuard: SET key NX PX=ttl → seen = !ok
```

**Guard wiring** (`guard.go`):
```go
// 3a (trước introspect): proof, err := token.VerifyProof(r, dpopCfg)
// sau introspect (sau line 122):
if g.enableDPoP {
    if seen, _ := g.replay.CheckAndSet(ctx, proof.JTI, dpopCfg.MaxAge); seen {
        g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "DPoP proof replayed", "", 0); return
    }
    if err := proof.VerifyBinding(rawToken, claims.CNF); err != nil {
        g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "DPoP binding failed", "", 0); return
    }
}
```
`RequireHTTPS`: enforce trong `htuMatches`/`VerifyProof` (reject khi scheme != https và cfg bật).

**Test:** stolen bearer + attacker keypair → reject (jkt mismatch); proof thiếu `ath` → reject; replay
cùng `jti` → lần 2 reject; happy path DPoP hợp lệ; vector RFC 7638 (JWK mẫu → thumbprint đã biết).

---

### M1.3 — Vá revocation (`revocation.go`)

**Bug:** revoke theo `jti` dùng raw JTI làm cache key nhưng cache key thực là `sha256(token)` → no-op
(`:115-119`); `RevokeAll` gọi `Flush()` xóa toàn bộ cache mọi tenant (`:121-126`).

**Thiết kế — secondary index** (introspection cache chỉ có tokenHash; jti/subject nằm *trong* claims):

```go
// pkg/core/token/index.go
type TokenIndex interface {
    Add(ctx context.Context, tokenHash, jti, subject string, ttl time.Duration) error
    KeysByJTI(ctx context.Context, jti string) ([]string, error)
    KeysBySubject(ctx context.Context, subject string) ([]string, error)
}
// MemoryTokenIndex: map[jti]set<hash>, map[subject]set<hash> + expiry
// RedisTokenIndex: SADD iam:idx:jti:<jti> / iam:idx:sub:<sub>, EXPIRE
```

- **Guard cache-set** (`guard.go:196-201`): sau `cache.Set(tokenHash, claims, ttl)` gọi
  `index.Add(ctx, tokenHash, claims.JTI, claims.Subject, ttl)`.
- **RevocationHandler** nhận thêm `index TokenIndex`:
  - `event.JTI != ""` → `hashes := index.KeysByJTI(jti)` → `cache.Delete` từng hash (không còn dùng jti làm key).
  - `event.RevokeAll && event.Subject != ""` → `KeysBySubject` → delete từng hash (bỏ `Flush()` toàn cục).
  - `event.TokenHash != ""` → giữ nguyên (đã đúng).

**Test:** cache 1 token có jti → revoke by jti → entry biến mất, request kế bị introspect lại; RevokeAll
cho subject A không xóa token subject B; token hash trực tiếp vẫn hoạt động.

---

### M1.4 — Vá `**` glob boundary (`matcher.go:22-30`)

**Bug:** `strings.HasPrefix(path, prefix)` không ranh giới → `/public/**` khớp `/publicSECRET/admin`.

**Thiết kế:**
```go
if strings.Contains(pattern, "**") {
    prefix := strings.TrimRight(strings.SplitN(pattern, "**", 2)[0], "/")
    if prefix == "" { return true }
    return requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/")
}
```
**Test:** bảng `(pattern, path, want)` gồm chính các bypass đã phát hiện + case hợp lệ
(`/public/**` khớp `/public`, `/public/x/y`; **không** khớp `/publicSECRET/admin`).

---

### M1.5 — max_age fail-closed (`engine.go:87` + `types.go` + `claims.go`)

**Bug:** `if p.MaxAge > 0 && req.AuthAge > 0` → thiếu `auth_time` (AuthAge==0) thì skip check hoàn toàn.

**Thiết kế:** phân biệt "không có auth_time" với "AuthAge==0".
```go
// policy/types.go — PolicyRequest thêm
HasAuthTime bool
// engine.go:86-94
if p.MaxAge > 0 {
    if !req.HasAuthTime { deny "authentication time unknown; max_age required" }
    if req.AuthAge > time.Duration(p.MaxAge)*time.Second { deny "auth too old" }
}
```
Caller set `HasAuthTime: !claims.AuthTime.IsZero()` (guard + 4 middleware adapter). *Lưu ý cập nhật
`engine_test.go:96-101` — test hiện đang assert hành vi fail-open sai.*

**Test:** MaxAge>0 + không auth_time → deny; + auth_time cũ → deny; + auth_time mới → allow; MaxAge==0 → bỏ qua.

---

## M2 — Standalone binaries (`cmd/`)

**Gap:** `cmd/` chưa tồn tại; `make service`/`make cli` fail; bảng env trong CLAUDE.md không được đọc.
Toàn bộ building block đã có (`internal/server`, `internal/gateway`, `tenant.Registry`,
`providers/generic`, `devkit/localas`, `policy.LoadFromFile`).

### M2.1 — `cmd/iam-service/main.go`

**Thiết kế bootstrap:**
```
1. cfg := config.FromEnv()                      // đọc IAM_* (bảng dưới)
2. logger := telemetry.NewLogger(cfg.LogFormat)
3. engine := policy.New(policy.LoadFromFile(cfg.PolicyFile))
4. registry := tenant.NewRegistry()
   if cfg.OIDCDiscoveryURL != "":               // PROD
       p := generic.New(generic.Config{DiscoveryURL, ClientID, ClientSecret}); p.RefreshConfig(ctx)
       registry.Register("default", p)
   else:                                        // DEV — LocalAS
       as, _ := localas.New(); url, _ := as.Start()
       p := generic.New(generic.Config{DiscoveryURL: url+"/.well-known/openid-configuration"}); p.RefreshConfig(ctx)
       registry.Register("default", p)
       tok, _ := as.IssueToken(...); logger.Info("demo token ready", "token", tok)
5. resolver := tenant.NewChainResolver(HeaderResolver, SubdomainResolver, PathResolver) // fallback "default"
6. cache := MemoryCache | RedisCache(goredis)   // theo IAM_REDIS_URL
7. var upstream http.Handler = echoHandler | proxy.New(cfg.UpstreamURL)
8. guard := gateway.NewGuard(GuardConfig{Registry, Resolver, PolicyEngine: engine, Realm,
      Audit, Metrics, Upstream: upstream, Cache: cache, CookieSecret: cfg.CookieSecret,
      WebhookSecret: cfg.WebhookSecret, EnableDPoP: cfg.EnableDPoP})
9. router := server.NewRouter(RouterConfig{Gateway: guard, AdminHandler: adminHandler})
10. srv := server.New(router, server.Config{Addr: cfg.Addr, ...})
11. graceful: go srv.Start(); <-SIGINT/SIGTERM; srv.Shutdown(ctx 10s); as.Stop()
```

**`config` package** (`cmd/iam-service/config.go` hoặc `internal/config`):
| Env | Field | Default |
|---|---|---|
| `IAM_ADDR` | Addr | `:8080` |
| `IAM_REALM` | Realm | `IAM` |
| `IAM_POLICY_FILE` | PolicyFile | `config/policy.example.yaml` |
| `IAM_UPSTREAM_URL` | UpstreamURL | _(empty = echo)_ |
| `IAM_OIDC_DISCOVERY_URL` | OIDCDiscoveryURL | _(empty = LocalAS dev)_ |
| `IAM_OIDC_CLIENT_ID` / `_SECRET` | ClientID/Secret | — |
| `IAM_LOG_FORMAT` | LogFormat | `text` |
| `IAM_COOKIE_SECRET` | CookieSecret | _(empty = no replay)_ |
| `IAM_WEBHOOK_SECRET` | WebhookSecret | _(empty = dev)_ |
| `IAM_REDIS_URL` | RedisURL | _(empty = memory)_ |
| `IAM_ENABLE_DPOP` | EnableDPoP | `false` |

### M2.2 — `cmd/iam-cli/main.go`

Subcommands (flag stdlib, không thêm dependency):
- `policy-check <path> <method> <acr>` → dùng `devkit/simulator` (đã có), in allow/deny + reason.
- `token issue [--acr --sub --sid]` → `devkit/tokenfactory`, in JWT.
- `introspect <token> --endpoint --client-id --client-secret` → `token.NewIntrospector`, in claims JSON.
- `version`.

### M2.3 — Makefile + smoke test

`make service`/`make cli` build được; thêm smoke test trong `tests/integration`: boot dev mode, lấy demo
token, gọi endpoint được bảo vệ → 200; token bronze vào path gold → 401 + `WWW-Authenticate`.

**Exit M2:** `go build ./cmd/...` pass; `./iam-service` boot dev mode reproduce Quickstart README.

---

## M3 — Hardening & RFC gaps (tóm tắt thiết kế)

- **Audience/issuer enforcement:** thêm `Aud []string` vào `IntrospectionResponse`, map sang
  `CommonClaims.Audience`; JWT validator truyền `jwt.WithIssuer/WithAudience/WithValidMethods`;
  guard assert `claims.Issuer == provider.Issuer()` sau introspect (đóng luôn cross-tenant M3 tenant binding).
- **Cache TTL clamp:** `guard.go:196-201` + `CachedIntrospector` → `if ttl <= 0 { return /* no cache */ }
  else if ttl > cap { ttl = cap }`.
- **Proxy header hygiene** (`proxy.go`): trong `Director` xóa `X-Tenant-ID` client gửi, re-inject
  `X-Iam-Tenant-Id`/`X-Iam-Subject` từ context đã verify.
- **Wire FAPI 2.0:** thêm method `HasDPoP/HasPARRequestURI/GetAuthAge/GetNonce` cho `CommonClaims`
  (implement interface `fapi.TokenClaims`); guard gọi `fapi.ValidateRequest` sau introspect, gate bằng
  `GuardConfig.FAPIProfile`.
- **CSRF StateID:** `BeginChallenge` set `saved.StateID = newStateID()`; propagate làm OAuth `state`; verify khi callback.
- **Tenant resolve fail-closed:** bỏ fallback `"default"` ngầm ở `guard.go:94-97`; chỉ opt-in qua config single-tenant.
- **DPoP nonce** (RFC 9449 §8): thêm hook phát/verify `DPoP-Nonce` trong `DPoPConfig`.

---

## Ma trận rủi ro / breaking change

| Thay đổi | Breaking? | Ghi chú |
|---|---|---|
| `ValidateDPoP` → `VerifyProof` + `VerifyBinding` | ⚠️ API | Đổi chữ ký hàm exported; giữ shim `ValidateDPoP` deprecated 1 minor. |
| `PolicyRequest.HasAuthTime` | Không | Field mới, zero-value an toàn (nhưng phải set ở caller để hết fail-open). |
| `CommonClaims.CNF/JTI` | Không | Field mới. |
| `RevocationHandler` nhận `TokenIndex` | ⚠️ API | Thêm tham số constructor; `NewRevocationHandler` nil-safe nếu index nil. |
| `NewGuard` thêm `ReplayGuard`/`TokenIndex` | ⚠️ API | Optional, nil = giữ hành vi cũ (nhưng DPoP replay/jti-revoke tắt). |
| `engine_test.go:96-101` | Test | Sửa test đang khoá hành vi fail-open. |

## Thứ tự & DoD

1. **M1.4, M1.5** (nhỏ, ít rủi ro) — 1 PR.
2. **M1.1** (cookie replay) + wire state machine — 1 PR, kèm regression exploit.
3. **M1.3** (revocation index) — 1 PR.
4. **M1.2** (DPoP binding + replay) — 1 PR, package `replay.go` + RFC 7638.
5. **M2** (cmd/ + config + smoke) — 1 PR.

**Definition of Done M1:** security review chạy lại 0 finding Critical/High; `go test ./... -race` xanh;
coverage `pkg/core/token` ≥ 80%.
