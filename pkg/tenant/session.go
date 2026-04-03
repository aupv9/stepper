package tenant

import (
	"context"
)

type sessionKey struct{ tenantID string }

// WithTenantID stores the resolved tenant ID in the request context.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, sessionKey{tenantID: "current"}, tenantID)
}

// TenantIDFromContext retrieves the tenant ID stored by the middleware.
func TenantIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(sessionKey{tenantID: "current"}).(string)
	return id, ok && id != ""
}
