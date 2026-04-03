package tenant

import (
	"context"
	"fmt"
	"sync"

	"github.com/common-iam/iam/pkg/providers"
)

// TenantConfig holds the configuration for a single tenant.
type TenantConfig struct {
	ID       string
	Provider providers.Provider
}

// Registry manages provider instances per tenant.
// Thread-safe for concurrent access.
type Registry struct {
	mu      sync.RWMutex
	tenants map[string]*TenantConfig
}

// NewRegistry creates an empty tenant registry.
func NewRegistry() *Registry {
	return &Registry{tenants: make(map[string]*TenantConfig)}
}

// Register adds or replaces a tenant's provider.
func (r *Registry) Register(tenantID string, provider providers.Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenants[tenantID] = &TenantConfig{
		ID:       tenantID,
		Provider: provider,
	}
}

// Unregister removes a tenant from the registry.
func (r *Registry) Unregister(tenantID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tenants, tenantID)
}

// Get returns the provider for the given tenant ID.
func (r *Registry) Get(tenantID string) (providers.Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg, ok := r.tenants[tenantID]
	if !ok {
		return nil, fmt.Errorf("tenant %q not found in registry", tenantID)
	}
	return cfg.Provider, nil
}

// List returns all registered tenant IDs.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.tenants))
	for id := range r.tenants {
		ids = append(ids, id)
	}
	return ids
}

// RefreshAll calls RefreshConfig on all registered providers.
// Useful for periodic OIDC discovery refresh.
func (r *Registry) RefreshAll(ctx context.Context) map[string]error {
	r.mu.RLock()
	snapshot := make(map[string]providers.Provider, len(r.tenants))
	for id, cfg := range r.tenants {
		snapshot[id] = cfg.Provider
	}
	r.mu.RUnlock()

	errors := make(map[string]error)
	for id, p := range snapshot {
		if err := p.RefreshConfig(ctx); err != nil {
			errors[id] = err
		}
	}
	return errors
}
