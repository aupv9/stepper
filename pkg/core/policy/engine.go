package policy

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/common-iam/iam/pkg/core/rar"
)

// Evaluator is the policy decision point interface. Engine is the built-in
// YAML implementation; external PDPs (CEL, OPA sidecar, …) can be plugged in
// anywhere an Evaluator is accepted (e.g. the gateway guard).
type Evaluator interface {
	Evaluate(req *PolicyRequest) (*PolicyResult, error)
}

// Engine evaluates access policies against incoming requests.
type Engine struct {
	mu     sync.RWMutex
	config *Config
	// order holds policy indices sorted by priority (desc), stable in file order.
	order []int
}

var _ Evaluator = (*Engine)(nil)

// New creates a new Engine with the given config.
func New(cfg *Config) *Engine {
	e := &Engine{}
	e.Reload(cfg)
	return e
}

// Evaluate checks whether the given request satisfies all applicable policies.
// Policies apply in priority order (higher first, file order within equal
// priority); the first policy whose scope AND conditions match decides:
// effect deny rejects outright, effect allow (default) evaluates requirements.
func (e *Engine) Evaluate(req *PolicyRequest) (*PolicyResult, error) {
	e.mu.RLock()
	cfg, order := e.config, e.order
	e.mu.RUnlock()

	if cfg == nil {
		return &PolicyResult{Allowed: false, Reason: "no policy config loaded"}, nil
	}

	for _, i := range order {
		p := &cfg.Policies[i]
		if !p.Enabled {
			continue
		}
		if !e.matchesPolicy(p, req) {
			continue
		}

		if p.Effect == "deny" {
			return &PolicyResult{
				Allowed:       false,
				MatchedPolicy: p,
				Reason:        fmt.Sprintf("denied by policy %q", p.Name),
			}, nil
		}

		// Policy matched - evaluate requirements
		return e.check(p, req), nil
	}

	// No policy matched = deny by default (defence-in-depth)
	return &PolicyResult{Allowed: false, Reason: "no matching policy"}, nil
}

// matchesPolicy returns true if this request falls under the policy's scope
// (methods, resources, tenants, and when-conditions).
func (e *Engine) matchesPolicy(p *Policy, req *PolicyRequest) bool {
	if !MatchMethod(p.Methods, req.Method) {
		return false
	}
	if len(p.Tenants) > 0 && !containsString(p.Tenants, req.TenantID) {
		return false
	}
	if !MatchCondition(p.When, req) {
		return false
	}
	for _, resource := range p.Resources {
		if MatchResource(resource, req.Path) {
			return true
		}
	}
	return false
}

// check evaluates a matched policy against the token claims.
func (e *Engine) check(p *Policy, req *PolicyRequest) *PolicyResult {
	result := &PolicyResult{
		MatchedPolicy:  p,
		RequiredACR:    p.RequireACR,
		RequiredMaxAge: p.MaxAge,
	}

	// Check scopes
	if len(p.RequireScopes) > 0 {
		for _, scope := range p.RequireScopes {
			if !containsString(req.TokenScopes, scope) {
				result.Allowed = false
				result.Reason = fmt.Sprintf("missing required scope: %s", scope)
				return result
			}
		}
	}

	// Check audience (RFC 8707 resource indicators). Fail closed: a policy
	// that names an audience cannot be satisfied by a token without aud.
	if len(p.RequireAudience) > 0 {
		for _, aud := range p.RequireAudience {
			if !containsString(req.TokenAudience, aud) {
				result.Allowed = false
				result.Reason = fmt.Sprintf("token audience does not include required %q", aud)
				return result
			}
		}
	}

	// Check ACR
	if p.RequireACR != "" {
		if !ACRSatisfies(req.TokenACR, p.RequireACR, e.config.ACRLevels) {
			result.Allowed = false
			result.Reason = fmt.Sprintf("ACR %q does not satisfy required %q", req.TokenACR, p.RequireACR)
			return result
		}
	}

	// Check max_age (auth time freshness). Fail closed: a policy that
	// demands auth freshness cannot be satisfied by a token that carries
	// no auth_time claim at all (AuthAge == 0 means "unknown").
	if p.MaxAge > 0 {
		if req.AuthAge <= 0 {
			result.Allowed = false
			result.Reason = "policy requires max_age but token has no auth_time claim"
			return result
		}
		maxAge := time.Duration(p.MaxAge) * time.Second
		if req.AuthAge > maxAge {
			result.Allowed = false
			result.Reason = fmt.Sprintf("authentication is %s old, max allowed is %s", req.AuthAge.Round(time.Second), maxAge)
			return result
		}
	}

	// Check roles
	if len(p.RequireRoles) > 0 {
		for _, role := range p.RequireRoles {
			if !containsString(req.TokenRoles, role) {
				result.Allowed = false
				result.Reason = fmt.Sprintf("missing required role: %s", role)
				return result
			}
		}
	}

	// Check MFA
	if p.RequireMFA {
		if !containsString(req.TokenAMR, "mfa") && !containsString(req.TokenAMR, "otp") && !containsString(req.TokenAMR, "hwk") {
			result.Allowed = false
			result.Reason = "MFA authentication method required"
			return result
		}
	}

	// Check RFC 9396 authorization_details
	if len(p.RequireAuthorizationDetails) > 0 {
		if ok, missing := rar.MatchAll(p.RequireAuthorizationDetails, req.AuthorizationDetails); !ok {
			result.Allowed = false
			result.Reason = "authorization_details insufficient: " + missing
			return result
		}
	}

	result.Allowed = true
	return result
}

// Reload replaces the policy config at runtime (hot-reload) and rebuilds the
// priority-sorted evaluation order.
func (e *Engine) Reload(cfg *Config) {
	var order []int
	if cfg != nil {
		order = make([]int, len(cfg.Policies))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool {
			return cfg.Policies[order[a]].Priority > cfg.Policies[order[b]].Priority
		})
	}

	e.mu.Lock()
	e.config = cfg
	e.order = order
	e.mu.Unlock()
}

// Config returns the currently loaded configuration (for admin listing).
func (e *Engine) Config() *Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// Summary returns a human-readable summary of loaded policies.
func (e *Engine) Summary() string {
	cfg := e.Config()
	if cfg == nil {
		return "no policies loaded"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "realm=%s, policies=%d, acr_levels=%d\n",
		cfg.Realm, len(cfg.Policies), len(cfg.ACRLevels))
	for _, p := range cfg.Policies {
		status := "enabled"
		if !p.Enabled {
			status = "disabled"
		}
		fmt.Fprintf(&sb, "  - %s [%s]: resources=%v require_acr=%s\n",
			p.Name, status, p.Resources, p.RequireACR)
	}
	return sb.String()
}

func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
