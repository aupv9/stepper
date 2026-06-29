---
description: Scaffold a new OIDC provider adapter following the existing Keycloak/Auth0 pattern. Usage: /add-provider <name> — e.g. /add-provider okta
argument-hint: "<provider-name>  — e.g. okta, azure-ad, cognito"
---

# Add OIDC Provider

Scaffold a new provider adapter for: $ARGUMENTS

## Phase 1 — Understand the Provider Interface

Read these files first:
- `pkg/providers/provider.go` — the `Provider` interface and `ProviderConfig` struct
- `pkg/providers/claims_mapper.go` — how claims are normalized to `CommonClaims`
- `pkg/providers/keycloak/adapter.go` — reference implementation (most complete)
- `pkg/providers/auth0/adapter.go` — alternative style
- `pkg/providers/generic/adapter.go` — OIDC discovery-based generic adapter

Summarize the interface methods that must be implemented.

## Phase 2 — Ask Clarifying Questions

Before generating code, ask the user:
1. Does this provider have a standard OIDC discovery endpoint (`/.well-known/openid-configuration`)? If yes, the generic adapter may already work — confirm before scaffolding.
2. Does it use non-standard claims that need mapping (e.g., custom `roles` claim instead of standard `scope`)?
3. Does it support RFC 7662 token introspection, or only JWKS-based local validation?
4. Any tenant/realm isolation at the URL level (like Keycloak's `/realms/{realm}`)?

## Phase 3 — Scaffold the Adapter

Create `pkg/providers/<name>/adapter.go` following this structure:

```go
package <name>

import (
    "context"
    "github.com/your-module/pkg/providers"
    "github.com/your-module/pkg/core/token"
)

type Config struct {
    // provider-specific config fields
}

type Adapter struct {
    config Config
    // http client, cached discovery doc, etc.
}

func New(cfg Config) *Adapter { ... }

// Implement providers.Provider interface:
func (a *Adapter) Introspect(ctx context.Context, tok string) (*token.CommonClaims, error) { ... }
func (a *Adapter) JWKS(ctx context.Context) ([]byte, error) { ... }
func (a *Adapter) RefreshConfig(ctx context.Context) error { ... }
```

Match the code style of `keycloak/adapter.go` exactly (error wrapping, context propagation, no panics).

## Phase 4 — Write a Claims Mapper

If the provider uses non-standard claims, add a mapper in the adapter file:

```go
func mapClaims(raw map[string]any) token.CommonClaims { ... }
```

Reference `pkg/providers/claims_mapper.go` for the standard field names.

## Phase 5 — Write a Test File

Create `pkg/providers/<name>/adapter_test.go` using the DevKit `localas` package:
- `pkg/devkit/localas/server.go` — in-process mock AS
- `pkg/devkit/tokenfactory/factory.go` — generate test tokens

Test at minimum: successful introspection, expired token rejection, invalid signature rejection.

## Phase 6 — Update Registration

Check `pkg/providers/provider.go` or wherever providers are registered. Add the new adapter. Show the diff to the user and confirm before writing.

## Phase 7 — Summary

List:
- Files created
- Interface methods implemented
- Non-standard claims mapped
- Tests written
- Registration change (if any)
