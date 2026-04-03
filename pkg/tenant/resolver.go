package tenant

import (
	"fmt"
	"net/http"
	"strings"
)

// Resolver determines the tenant ID from an incoming HTTP request.
type Resolver interface {
	Resolve(r *http.Request) (tenantID string, err error)
}

// --- Header Resolver ---

// HeaderResolver reads the tenant ID from a request header.
// Default header: X-Tenant-ID
type HeaderResolver struct {
	Header string
}

func NewHeaderResolver(header string) *HeaderResolver {
	if header == "" {
		header = "X-Tenant-ID"
	}
	return &HeaderResolver{Header: header}
}

func (h *HeaderResolver) Resolve(r *http.Request) (string, error) {
	id := r.Header.Get(h.Header)
	if id == "" {
		return "", fmt.Errorf("missing tenant header %q", h.Header)
	}
	return id, nil
}

// --- Subdomain Resolver ---

// SubdomainResolver extracts the tenant ID from the request subdomain.
// e.g. "acme.api.example.com" → "acme"
type SubdomainResolver struct {
	// BaseDomain is the domain to strip, e.g. "api.example.com"
	BaseDomain string
}

func NewSubdomainResolver(baseDomain string) *SubdomainResolver {
	return &SubdomainResolver{BaseDomain: baseDomain}
}

func (s *SubdomainResolver) Resolve(r *http.Request) (string, error) {
	host := r.Host
	// Strip port
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	suffix := "." + s.BaseDomain
	if !strings.HasSuffix(host, suffix) {
		return "", fmt.Errorf("host %q is not a subdomain of %q", host, s.BaseDomain)
	}
	tenant := strings.TrimSuffix(host, suffix)
	if tenant == "" {
		return "", fmt.Errorf("empty tenant in subdomain")
	}
	return tenant, nil
}

// --- Path Resolver ---

// PathResolver extracts the tenant ID from a path segment.
// Pattern: /{tenantSegment}/... e.g. /acme/api/users → "acme" (segment=0)
type PathResolver struct {
	Segment int // 0-indexed path segment position after splitting on /
}

func NewPathResolver(segment int) *PathResolver {
	return &PathResolver{Segment: segment}
}

func (p *PathResolver) Resolve(r *http.Request) (string, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if p.Segment >= len(parts) || parts[p.Segment] == "" {
		return "", fmt.Errorf("no tenant found at path segment %d", p.Segment)
	}
	return parts[p.Segment], nil
}

// --- Chain Resolver ---

// ChainResolver tries multiple resolvers in order, returning the first success.
type ChainResolver struct {
	resolvers []Resolver
}

func NewChainResolver(resolvers ...Resolver) *ChainResolver {
	return &ChainResolver{resolvers: resolvers}
}

func (c *ChainResolver) Resolve(r *http.Request) (string, error) {
	var lastErr error
	for _, resolver := range c.resolvers {
		id, err := resolver.Resolve(r)
		if err == nil && id != "" {
			return id, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no resolver could determine tenant")
}
