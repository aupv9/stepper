package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/common-iam/iam/pkg/core/rar"
)

// Engine evaluates access policies against incoming requests.
type Engine struct {
	config *Config
}

// New creates a new Engine with the given config.
func New(cfg *Config) *Engine {
	return &Engine{config: cfg}
}

// Evaluate checks whether the given request satisfies all applicable policies.
// Returns a PolicyResult indicating if access is allowed and what is required.
func (e *Engine) Evaluate(req *PolicyRequest) (*PolicyResult, error) {
	if e.config == nil {
		return &PolicyResult{Allowed: false, Reason: "no policy config loaded"}, nil
	}

	for i := range e.config.Policies {
		p := &e.config.Policies[i]
		if !p.Enabled {
			continue
		}
		if !e.matchesPolicy(p, req) {
			continue
		}

		// Policy matched - evaluate requirements
		return e.check(p, req), nil
	}

	// No policy matched = deny by default (defence-in-depth)
	return &PolicyResult{Allowed: false, Reason: "no matching policy"}, nil
}

// matchesPolicy returns true if this request falls under the policy's scope.
func (e *Engine) matchesPolicy(p *Policy, req *PolicyRequest) bool {
	if !MatchMethod(p.Methods, req.Method) {
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
		MatchedPolicy: p,
		RequiredACR:   p.RequireACR,
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

	// Check ACR
	if p.RequireACR != "" {
		if !ACRSatisfies(req.TokenACR, p.RequireACR, e.config.ACRLevels) {
			result.Allowed = false
			result.Reason = fmt.Sprintf("ACR %q does not satisfy required %q", req.TokenACR, p.RequireACR)
			return result
		}
	}

	// Check max_age (auth time freshness)
	if p.MaxAge > 0 && req.AuthAge > 0 {
		maxAge := time.Duration(p.MaxAge) * time.Second
		if req.AuthAge > maxAge {
			result.Allowed = false
			result.Reason = fmt.Sprintf("authentication is %s old, max allowed is %s", req.AuthAge.Round(time.Second), maxAge)
			return result
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

// Reload replaces the policy config at runtime (hot-reload).
func (e *Engine) Reload(cfg *Config) {
	e.config = cfg
}

// Summary returns a human-readable summary of loaded policies.
func (e *Engine) Summary() string {
	if e.config == nil {
		return "no policies loaded"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "realm=%s, policies=%d, acr_levels=%d\n",
		e.config.Realm, len(e.config.Policies), len(e.config.ACRLevels))
	for _, p := range e.config.Policies {
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
