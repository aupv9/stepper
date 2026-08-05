# Token Exchange (RFC 8693)

The gateway can broker OAuth 2.0 Token Exchange: a service holding a valid
access token asks the gateway for a new token scoped to a downstream audience
(impersonation) or acting on a user's behalf (delegation). The gateway
forwards the exchange to the resolved tenant's token endpoint using that
tenant's client credentials — callers never hold the AS client secret.

## Enabling

```yaml
# iam.yaml
enable_token_exchange: true
tenants:
  - id: acme
    provider: keycloak
    base_url: https://keycloak.example.com
    realm: acme
    client_id: iam-gateway        # used to authenticate the exchange
    client_secret: "..."
```

or `IAM_ENABLE_TOKEN_EXCHANGE=true`.

## Calling

The caller must present a valid bearer token carrying the `token:exchange`
scope. `subject_token` and `subject_token_type` are required (RFC 8693 §2.1).

```bash
curl -X POST http://gateway:8080/token/exchange \
  -H "Authorization: Bearer $CALLER_TOKEN" \
  -H "X-Tenant-ID: acme" \
  -d subject_token="$CALLER_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=downstream-api \
  -d scope="read:orders"
```

Response (RFC 8693 §2.2.1 — validated by the gateway before relay):

```json
{
  "access_token": "…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300
}
```

Delegation adds `actor_token` / `actor_token_type` form fields.

## Semantics & safeguards

- **Scope gate**: callers without `token:exchange` get `403 insufficient_scope`.
- **Tenant binding**: the exchange goes to the *resolved tenant's* token
  endpoint only; per-tenant credentials come from `iam.yaml`.
- **Audit**: every exchange emits an `iam.token.exchanged` audit event with
  subject, tenant, and target audience.
- **Errors**: AS error responses (RFC 6749 format) are relayed as
  `400 {error, error_description}`; transport failures map to `502
  server_error`; responses missing REQUIRED fields are rejected, never relayed.

The AS itself must support the token-exchange grant (Keycloak: enable the
`token-exchange` feature; Auth0: custom actions).
