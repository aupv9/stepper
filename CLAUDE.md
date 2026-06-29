# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make build        # go build ./...
make test         # go test ./... -v -race
make lint         # golangci-lint run ./...
make fmt          # gofmt -w .
make tidy         # go mod tidy
make service      # go run cmd/iam-service/main.go
make cli          # go run cmd/iam-cli/main.go
make docker-build # docker build -f deployments/Dockerfile -t common-iam:latest .
```

Run a single test:
```bash
go test ./pkg/core/token/... -run TestJWTValidator -v -race
```

## Architecture

This is a Go 1.25 IAM library implementing [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) (OAuth 2.0 Step Up Authentication Challenge Protocol), RFC 7662 (token introspection), and RFC 9449 (DPoP proof-of-possession).

**Two deployment modes:**
1. **Library** — import `pkg/middleware/{gin,echo,stdlib}` into any Go service
2. **Gateway** — standalone reverse proxy (`cmd/iam-service`) that centralizes auth

### Package Layout

```
pkg/                      ← exported, importable by users
  core/
    policy/               ← YAML-based policy engine; first-match wins, glob paths
    stepup/               ← RFC 9470 challenge generation and state machine
    token/                ← introspection (RFC 7662), JWT validation, DPoP, cache, revocation
  middleware/{gin,echo,stdlib}  ← framework adapters, all thin wrappers over core
  providers/{keycloak,auth0,generic}  ← OIDC adapters implementing Provider interface
  tenant/                 ← resolver chain (header → subdomain → path), registry, context
  telemetry/              ← slog logger, Prometheus metrics, OpenTelemetry tracing, audit log
  devkit/
    localas/              ← in-process mock Authorization Server (no external AS needed)
    tokenfactory/         ← generate signed test JWTs
    simulator/            ← dry-run policy evaluation without HTTP

internal/                 ← gateway-only internals, not exported
  gateway/                ← ResourceServerGuard (guard.go) + reverse proxy (proxy.go)
  admin/                  ← REST API: tenant CRUD, policy reload
  server/                 ← graceful HTTP server + router

cmd/                      ← binaries (planned, not yet created)
  iam-service/
  iam-cli/
```

### Request Flow (Gateway Mode)

```
Client Request → Router
  /health, /metrics, /admin/*, /webhook/revoke → dedicated handlers
  /* → ResourceServerGuard (internal/gateway/guard.go)
         1. Tenant resolver (header / subdomain / path)
         2. Provider registry lookup → OIDC adapter
         3. Token extraction + introspection (with cache)
         4. Policy evaluation (pkg/core/policy)
         5a. ALLOWED → proxy to upstream
         5b. DENIED → RFC 9470 WWW-Authenticate challenge (401)
```

### Key Design Patterns

- **Interface-based extensibility:** `Provider`, `Cache`, `Resolver` are all interfaces; concrete implementations are in dedicated sub-packages.
- **Policy engine:** YAML config (`config/policy.example.yaml`), priority-ordered, hot-reloadable via `POST /admin/policy/reload`. ACR levels form a hierarchy (bronze < silver < gold).
- **Token cache:** `pkg/core/token` defines a `Cache` interface; `MemoryCache` is built-in; Redis via `pkg/core/token/goredis`.
- **Multi-tenancy:** Resolver chain is composable — `HeaderResolver`, `SubdomainResolver`, `PathResolver` can be chained.
- **Middleware adapters:** Each framework middleware (`gin`, `echo`, `stdlib`) calls the same underlying `core` logic; they are intentionally thin.

### Environment Variables (Gateway Mode)

| Variable | Default | Purpose |
|---|---|---|
| `IAM_ADDR` | `:8080` | Listen address |
| `IAM_REALM` | `IAM` | WWW-Authenticate realm |
| `IAM_POLICY_FILE` | `config/policy.example.yaml` | Policy YAML path |
| `IAM_UPSTREAM_URL` | _(empty = echo mode)_ | Proxy target |
| `IAM_OIDC_DISCOVERY_URL` | _(empty = LocalAS dev mode)_ | OIDC discovery URL |
| `IAM_OIDC_CLIENT_ID` | — | OIDC client ID |
| `IAM_OIDC_CLIENT_SECRET` | — | OIDC client secret |
| `IAM_LOG_FORMAT` | `text` | `text` or `json` |

### Docs

Detailed documentation lives in `docs/`: `design.md` (architecture diagrams), `policy-configuration.md`, `providers.md`, `middleware.md`, `multi-tenancy.md`, `devkit.md`, `deployment.md`, `extending.md`.
