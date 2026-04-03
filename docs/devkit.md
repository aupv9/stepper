# DevKit — Testing & Developer Tools

The `pkg/devkit` package provides everything you need to develop and test IAM-integrated services **without needing a real Authorization Server**.

---

## Components

| Component | Package | Purpose |
|---|---|---|
| `LocalAS` | `pkg/devkit/localas` | In-process mock Authorization Server |
| `TokenFactory` | `pkg/devkit/tokenfactory` | Generate signed JWTs with custom claims |
| `PolicySimulator` | `pkg/devkit/simulator` | Dry-run policy without HTTP |
| `iam-cli` | `cmd/iam-cli` | Command-line developer tools |

---

## LocalAS — Mock Authorization Server

A lightweight HTTP server that implements OIDC discovery, JWKS, token issuance, introspection, and revocation. Starts in-process — no Docker, no external dependencies.

### In tests

```go
import "github.com/common-iam/iam/pkg/devkit/localas"

func TestMyHandler(t *testing.T) {
    // Start mock AS
    as, err := localas.New()
    require.NoError(t, err)

    baseURL, err := as.Start()
    require.NoError(t, err)
    defer as.Stop(context.Background())

    // Issue a test token
    token, err := as.IssueToken(tokenfactory.TokenOptions{
        Subject:   "alice",
        ACR:       "urn:mace:incommon:iap:silver",
        Scopes:    []string{"openid", "payments:write"},
        ExpiresIn: time.Hour,
    })
    require.NoError(t, err)

    // Use baseURL as the OIDC discovery endpoint
    // e.g. http://127.0.0.1:PORT/.well-known/openid-configuration
    provider := generic.New(generic.Config{
        DiscoveryURL: baseURL + "/.well-known/openid-configuration",
    })
    provider.RefreshConfig(context.Background())

    // Run your test
    req := httptest.NewRequest("POST", "/api/payments", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    // ...
}
```

### LocalAS endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/.well-known/openid-configuration` | OIDC discovery document |
| GET | `/jwks` | JSON Web Key Set |
| POST | `/token` | Issue token (password grant: `username`, `acr_values` params) |
| POST | `/introspect` | RFC 7662 token introspection |
| POST | `/revoke` | Token revocation |

---

## TokenFactory — Generate Test JWTs

Generate signed JWTs with any claims combination for unit tests.

```go
import "github.com/common-iam/iam/pkg/devkit/tokenfactory"

factory, err := tokenfactory.New()  // creates fresh RSA-2048 key pair
require.NoError(t, err)

// Basic token
token, err := factory.Generate(tokenfactory.TokenOptions{
    Subject:   "alice",
    ExpiresIn: time.Hour,
})

// Full token with auth context
token, err = factory.Generate(tokenfactory.TokenOptions{
    Subject:   "bob",
    Issuer:    "https://test-as.example.com",
    ACR:       "urn:mace:incommon:iap:gold",
    AMR:       []string{"mfa", "hwk"},
    Scopes:    []string{"openid", "admin"},
    Roles:     []string{"admin", "superuser"},
    TenantID:  "acme",
    SessionID: "sess-123",
    AuthTime:  time.Now().Add(-2 * time.Minute),
    ExpiresIn: time.Hour,
    Extra: map[string]interface{}{
        "custom_claim": "value",
    },
})

// Get JWKS for validation
jwks, _ := factory.JWKS()
```

### Expired token (test error paths)

```go
expiredToken, _ := factory.Generate(tokenfactory.TokenOptions{
    Subject:   "alice",
    ExpiresIn: -time.Minute,   // already expired
})
```

### Old auth_time (test max_age violations)

```go
oldAuthToken, _ := factory.Generate(tokenfactory.TokenOptions{
    Subject:   "alice",
    ACR:       "urn:mace:incommon:iap:silver",
    AuthTime:  time.Now().Add(-10 * time.Minute), // authenticated 10 min ago
    ExpiresIn: time.Hour,
})
```

---

## PolicySimulator — Dry-Run Policy

Test policy rules in code without making HTTP requests.

```go
import (
    "github.com/common-iam/iam/pkg/core/policy"
    "github.com/common-iam/iam/pkg/devkit/simulator"
)

cfg, _ := policy.LoadFromFile("policy.yaml")
engine := policy.New(cfg)
sim := simulator.New(engine)

// Single simulation
result, err := sim.Simulate(simulator.Request{
    Method:  "POST",
    Path:    "/api/payments/transfer",
    ACR:     "urn:mace:incommon:iap:silver",
    Scopes:  []string{"openid", "payments:write", "payments:transfer"},
    AuthAge: 30 * time.Second,
})
// result.Allowed, result.PolicyName, result.Reason, result.RequiredACR

// Table output (useful in CI logs)
table := sim.RunTable([]simulator.Request{
    {Method: "GET",  Path: "/api/users",   ACR: "urn:mace:incommon:iap:bronze"},
    {Method: "POST", Path: "/api/payments", ACR: "urn:mace:incommon:iap:silver"},
    {Method: "POST", Path: "/api/admin",    ACR: "urn:mace:incommon:iap:silver"},
})
fmt.Println(table)
// METHOD   PATH                           ACR        ALLOWED    REASON
// -----------------------------------------------------------------------
// GET      /api/users                     ...bronze  YES
// POST     /api/payments                  ...silver  YES
// POST     /api/admin                     ...silver  NO         ACR "silver" does not satisfy required "gold"
```

---

## CLI Tool (`iam-cli`)

### inspect-token

Decode and display a JWT's claims and RFC 9470 context fields (no signature verification):

```bash
go run cmd/iam-cli/main.go inspect-token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

# Output:
# === HEADER ===
# {"alg":"RS256","kid":"devkit-key-1","typ":"JWT"}
#
# === PAYLOAD ===
# {"acr":"urn:mace:incommon:iap:silver","active":true,"sub":"alice",...}
#
# === RFC 9470 CONTEXT ===
#   acr:       urn:mace:incommon:iap:silver
#   amr:       [mfa otp]
#   auth_time: 2026-03-04T10:00:00+07:00 (age: 5m0s)
#   exp:       2026-03-04T11:00:00+07:00 (valid, 55m0s)
```

### test-policy

Dry-run a request against your policy file:

```bash
# Test a request (MSYS_NO_PATHCONV=1 on Windows/Git Bash)
MSYS_NO_PATHCONV=1 go run cmd/iam-cli/main.go test-policy \
  --config config/policy.example.yaml \
  --method POST \
  --path /api/payments/transfer \
  --acr "urn:mace:incommon:iap:gold" \
  --scopes "openid payments:write payments:transfer" \
  --auth-age 30

# Flags:
#   -c, --config     Policy YAML file (default: config/policy.example.yaml)
#   -m, --method     HTTP method (default: GET)
#   -p, --path       Request path (default: /)
#   -a, --acr        Token ACR value
#   -s, --scopes     Space-separated scopes (default: openid)
#       --auth-age   Authentication age in seconds (default: 0)
```

### issue-token

Generate a signed test JWT (development only — uses a fresh key pair):

```bash
go run cmd/iam-cli/main.go issue-token \
  --subject alice \
  --acr "urn:mace:incommon:iap:gold" \
  --scopes "openid admin" \
  --roles "admin" \
  --tenant acme \
  --ttl 3600

# Flags:
#   -s, --subject   Token subject (default: test-user)
#   -a, --acr       ACR value (default: urn:mace:incommon:iap:bronze)
#       --scopes    Space-separated scopes (default: openid profile)
#       --roles     Space-separated roles
#   -t, --tenant    Tenant ID
#       --ttl       Token TTL in seconds (default: 3600)
```

### parse-challenge

Parse and display a `WWW-Authenticate` step-up challenge header:

```bash
go run cmd/iam-cli/main.go parse-challenge \
  'Bearer realm="MyApp", error="insufficient_user_authentication", acr_values="urn:mace:incommon:iap:silver", max_age=300'

# Output:
# === Step-Up Challenge ===
#   Realm:       MyApp
#   Error:       insufficient_user_authentication
#   Description:
#   ACR Values:  urn:mace:incommon:iap:silver
#   Max Age:     300s
```

---

## Testing Patterns

### Table-driven test with LocalAS

```go
func TestPaymentsEndpoint(t *testing.T) {
    as, _ := localas.New()
    baseURL, _ := as.Start()
    defer as.Stop(context.Background())

    factory, _ := tokenfactory.New()

    tests := []struct {
        name       string
        acr        string
        scopes     []string
        authAgeSec int
        wantStatus int
    }{
        {"bronze token → denied", "urn:mace:incommon:iap:bronze", []string{"openid"}, 0, 401},
        {"silver token → allowed", "urn:mace:incommon:iap:silver", []string{"openid", "payments:write"}, 0, 200},
        {"silver + old auth → denied", "urn:mace:incommon:iap:silver", []string{"openid", "payments:write"}, 600, 401},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tok, _ := factory.Generate(tokenfactory.TokenOptions{
                Subject:   "alice",
                ACR:       tt.acr,
                Scopes:    tt.scopes,
                AuthTime:  time.Now().Add(-time.Duration(tt.authAgeSec) * time.Second),
                ExpiresIn: time.Hour,
            })
            // make request with token, assert status code...
        })
    }
}
```
