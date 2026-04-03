package simulator

import (
	"fmt"
	"strings"
	"time"

	"github.com/common-iam/iam/pkg/core/policy"
)

// Request represents a simulated HTTP request for policy dry-run.
type Request struct {
	Method      string
	Path        string
	ACR         string
	AMR         []string
	Scopes      []string
	AuthAge     time.Duration
}

// Result is the simulation outcome.
type Result struct {
	Allowed       bool
	PolicyName    string
	Reason        string
	RequiredACR   string
	RequiredMaxAge int
}

// Simulator runs policy evaluations without a real token or HTTP request.
type Simulator struct {
	engine *policy.Engine
}

// New creates a Simulator with a loaded policy engine.
func New(engine *policy.Engine) *Simulator {
	return &Simulator{engine: engine}
}

// Simulate evaluates the given request against all policies.
func (s *Simulator) Simulate(req Request) (*Result, error) {
	result, err := s.engine.Evaluate(&policy.PolicyRequest{
		Method:      req.Method,
		Path:        req.Path,
		TokenACR:    req.ACR,
		TokenAMR:    req.AMR,
		TokenScopes: req.Scopes,
		AuthAge:     req.AuthAge,
	})
	if err != nil {
		return nil, fmt.Errorf("policy evaluation: %w", err)
	}

	out := &Result{
		Allowed: result.Allowed,
		Reason:  result.Reason,
		RequiredACR: result.RequiredACR,
		RequiredMaxAge: result.RequiredMaxAge,
	}
	if result.MatchedPolicy != nil {
		out.PolicyName = result.MatchedPolicy.Name
	}
	return out, nil
}

// RunTable simulates multiple requests and prints a table of results.
// Useful for CLI dry-run output.
func (s *Simulator) RunTable(requests []Request) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-8s %-30s %-10s %-10s %s\n", "METHOD", "PATH", "ACR", "ALLOWED", "REASON")
	fmt.Fprintf(&sb, "%s\n", strings.Repeat("-", 80))

	for _, req := range requests {
		result, err := s.Simulate(req)
		if err != nil {
			fmt.Fprintf(&sb, "%-8s %-30s %-10s ERROR    %v\n", req.Method, req.Path, req.ACR, err)
			continue
		}
		allowed := "YES"
		if !result.Allowed {
			allowed = "NO"
		}
		reason := result.Reason
		if reason == "" && !result.Allowed && result.RequiredACR != "" {
			reason = fmt.Sprintf("need acr=%s", result.RequiredACR)
		}
		fmt.Fprintf(&sb, "%-8s %-30s %-10s %-10s %s\n",
			req.Method, req.Path, req.ACR, allowed, reason)
	}

	return sb.String()
}
