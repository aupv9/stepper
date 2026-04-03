# Policy Configuration

Policies define **what level of authentication is required** to access each resource. They are loaded from a YAML file and can be hot-reloaded at runtime via the Admin API.

---

## Full YAML Reference

```yaml
# Schema version (currently "1")
version: "1"

# Realm name shown in WWW-Authenticate challenges
realm: "MyApp"

# ACR level hierarchy — order matters!
# Lower index = lower assurance, higher index = higher assurance.
# A token with acr=silver satisfies a policy requiring acr=bronze or acr=silver,
# but NOT acr=gold.
acr_levels:
  - "urn:mace:incommon:iap:bronze"   # password-only
  - "urn:mace:incommon:iap:silver"   # step-up or soft MFA
  - "urn:mace:incommon:iap:gold"     # hardware key / strongest MFA

policies:
  - name: string              # human-readable policy name (used in logs/metrics)
    enabled: true             # set false to disable without removing
    resources:                # list of path patterns (see Path Matching)
      - /api/payments/**
    methods:                  # HTTP methods; empty list = all methods
      - POST
      - PUT
    require_acr: string       # minimum ACR value required
    max_age: 300              # max auth age in seconds (0 = no limit)
    require_mfa: false        # AMR must contain "mfa", "otp", or "hwk"
    require_scopes:           # all listed scopes must be in the token
      - payments:write
```

---

## Path Matching

| Pattern | Matches | Does NOT match |
|---|---|---|
| `/api/users` | `/api/users` | `/api/users/me` |
| `/api/users/*` | `/api/users/123` | `/api/users/123/profile` |
| `/api/users/**` | `/api/users/123`, `/api/users/123/profile` | `/api/orders` |
| `/**` | everything | — |
| `/health` | `/health` | `/healthz` |

**Rules:**
- `*` matches a single path segment (no `/`)
- `**` matches zero or more path segments including nested
- Pattern matching is case-sensitive
- Trailing slashes are stripped before comparison

---

## ACR Levels

The `acr_levels` list defines the trust hierarchy. Levels are compared by **index position** — higher index = higher assurance.

```yaml
acr_levels:
  - "urn:mace:incommon:iap:bronze"   # index 0 (lowest)
  - "urn:mace:incommon:iap:silver"   # index 1
  - "urn:mace:incommon:iap:gold"     # index 2 (highest)
```

A token with `acr=silver` satisfies `require_acr=bronze` and `require_acr=silver`, but **not** `require_acr=gold`.

If the token's ACR value is not in the `acr_levels` list, exact string comparison is used as a fallback.

### Common ACR schemes

| Provider | Bronze | Silver | Gold |
|---|---|---|---|
| InCommon | `urn:mace:incommon:iap:bronze` | `...iap:silver` | `...iap:gold` |
| eIDAS | `http://eidas.europa.eu/LoA/low` | `...LoA/substantial` | `...LoA/high` |
| NIST SP 800-63 | `nist-sp800-63-aal1` | `nist-sp800-63-aal2` | `nist-sp800-63-aal3` |
| Custom | any string | any string | any string |

---

## max_age

`max_age` enforces **how fresh the authentication must be**. It uses the `auth_time` claim from the token.

```yaml
- name: sensitive-operations
  resources: [/api/transfer/**]
  require_acr: "urn:mace:incommon:iap:silver"
  max_age: 300   # user must have authenticated within the last 5 minutes
```

If `auth_time + max_age < now`, the request is denied with a step-up challenge that includes `max_age=300` in the `WWW-Authenticate` header.

**Note:** If the token doesn't contain `auth_time`, the `max_age` check is skipped.

---

## require_mfa

```yaml
require_mfa: true
```

When true, the token's `amr` (Authentication Methods References) claim must contain at least one of: `mfa`, `otp`, `hwk` (hardware key).

This is independent of `require_acr`. You can require MFA without requiring a specific ACR level.

---

## Policy Evaluation Order

1. Policies are evaluated **in order** (top to bottom)
2. The **first matching policy** is applied
3. If **no policy matches**, the request is **allowed by default**

> To deny by default, add a catch-all policy at the end:
> ```yaml
> - name: deny-all
>   enabled: true
>   resources: ["/**"]
>   require_acr: "urn:mace:incommon:iap:bronze"  # at minimum logged-in
> ```

---

## Hot Reload via Admin API

Reload policies at runtime without restarting:

```bash
curl -X POST http://localhost:8080/admin/policy/reload \
  -H "Content-Type: application/json" \
  -d "{\"yaml\": $(cat policy.yaml | jq -Rs .)}"
```

Or check current policy summary:

```bash
curl http://localhost:8080/admin/policy/summary
```

---

## Dry-Run with CLI

Test any request against your policy file before deploying:

```bash
# Test with gold ACR — should pass admin policy
go run cmd/iam-cli/main.go test-policy \
  -c config/policy.example.yaml \
  -m POST -p /api/admin/settings \
  -a "urn:mace:incommon:iap:gold" \
  -s "openid admin" \
  --auth-age 120

# Test with expired auth age — should fail max_age check
go run cmd/iam-cli/main.go test-policy \
  -c config/policy.example.yaml \
  -m POST -p /api/payments/transfer \
  -a "urn:mace:incommon:iap:silver" \
  -s "openid payments:write payments:transfer" \
  --auth-age 600   # 10 minutes, but policy requires max 60s
```

---

## Example: Tiered Access Policy

```yaml
version: "1"
realm: "BankingApp"

acr_levels:
  - "urn:mace:incommon:iap:bronze"
  - "urn:mace:incommon:iap:silver"
  - "urn:mace:incommon:iap:gold"

policies:
  # No auth needed for public docs
  - name: public
    enabled: true
    resources: [/api/public/**, /docs/**, /health]

  # Basic login required for read operations
  - name: read-only
    enabled: true
    resources: [/api/**]
    methods: [GET, HEAD, OPTIONS]
    require_acr: "urn:mace:incommon:iap:bronze"
    require_scopes: [openid]

  # Step-up for writes
  - name: write-operations
    enabled: true
    resources: [/api/**]
    methods: [POST, PUT, PATCH, DELETE]
    require_acr: "urn:mace:incommon:iap:silver"
    require_scopes: [openid, write]

  # Strongest auth for financial operations
  - name: financial
    enabled: true
    resources: [/api/payments/**, /api/transfers/**]
    methods: [POST, PUT, DELETE]
    require_acr: "urn:mace:incommon:iap:gold"
    max_age: 300
    require_mfa: true
    require_scopes: [openid, payments:write]

  # Admin panel - gold + very fresh
  - name: admin
    enabled: true
    resources: [/admin/**]
    require_acr: "urn:mace:incommon:iap:gold"
    max_age: 900
    require_mfa: true
    require_scopes: [openid, admin]
```
