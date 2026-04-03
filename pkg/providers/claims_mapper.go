package providers

import (
	"strings"
	"time"

	"github.com/common-iam/iam/pkg/core/token"
)

// RawClaims is a raw map of JWT/introspection claims from any provider.
type RawClaims map[string]interface{}

// MapToCommon normalizes provider-specific raw claims into CommonClaims.
// Handles differences between Keycloak, Auth0, and generic OIDC providers.
func MapToCommon(raw RawClaims) *token.CommonClaims {
	c := &token.CommonClaims{
		Extra: make(map[string]interface{}),
	}

	// Standard fields
	c.Subject = stringClaim(raw, "sub")
	c.Issuer = stringClaim(raw, "iss")
	c.ACR = stringClaim(raw, "acr")
	c.SessionID = stringClaim(raw, "sid")
	c.Email = stringClaim(raw, "email")
	c.Username = firstNonEmpty(
		stringClaim(raw, "preferred_username"),
		stringClaim(raw, "username"),
		stringClaim(raw, "nickname"),
	)

	// AMR
	if amr, ok := raw["amr"]; ok {
		c.AMR = toStringSlice(amr)
	}

	// Audience
	if aud, ok := raw["aud"]; ok {
		c.Audience = toStringSlice(aud)
	}

	// Time fields
	c.ExpiresAt = unixTimeClaim(raw, "exp")
	c.IssuedAt = unixTimeClaim(raw, "iat")
	c.AuthTime = unixTimeClaim(raw, "auth_time")

	// Active (introspection)
	if active, ok := raw["active"].(bool); ok {
		c.Active = active
	} else {
		// If not from introspection, assume active if not expired
		c.Active = c.ExpiresAt.IsZero() || time.Now().Before(c.ExpiresAt)
	}

	// Scopes
	if scope, ok := raw["scope"].(string); ok && scope != "" {
		c.Scopes = strings.Fields(scope)
	}

	// Roles - try common claim locations
	c.Roles = extractRoles(raw)

	// Tenant
	c.TenantID = firstNonEmpty(
		stringClaim(raw, "tenant_id"),
		stringClaim(raw, "tid"),       // Azure AD style
		stringClaim(raw, "org_id"),    // Auth0 style
	)

	// Remaining claims go into Extra
	known := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true, "iat": true,
		"auth_time": true, "acr": true, "amr": true, "sid": true,
		"email": true, "preferred_username": true, "username": true,
		"nickname": true, "scope": true, "active": true, "tenant_id": true,
		"tid": true, "org_id": true,
	}
	for k, v := range raw {
		if !known[k] {
			c.Extra[k] = v
		}
	}

	return c
}

// extractRoles tries multiple provider-specific claim paths for roles.
func extractRoles(raw RawClaims) []string {
	// Keycloak: realm_access.roles
	if ra, ok := raw["realm_access"].(map[string]interface{}); ok {
		if roles, ok := ra["roles"]; ok {
			return toStringSlice(roles)
		}
	}
	// Auth0: https://example.com/roles (namespaced claim)
	for k, v := range raw {
		if strings.Contains(k, "/roles") || strings.HasSuffix(k, "roles") {
			return toStringSlice(v)
		}
	}
	// Generic: roles claim
	if roles, ok := raw["roles"]; ok {
		return toStringSlice(roles)
	}
	return nil
}

func stringClaim(raw RawClaims, key string) string {
	if v, ok := raw[key].(string); ok {
		return v
	}
	return ""
}

func unixTimeClaim(raw RawClaims, key string) time.Time {
	switch v := raw[key].(type) {
	case float64:
		return time.Unix(int64(v), 0)
	case int64:
		return time.Unix(v, 0)
	case int:
		return time.Unix(int64(v), 0)
	}
	return time.Time{}
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return val
	case string:
		return []string{val}
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
