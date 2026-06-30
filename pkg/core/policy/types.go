package policy

import (
	"time"

	"github.com/common-iam/iam/pkg/core/rar"
)

// Config is the top-level policy configuration loaded from YAML.
type Config struct {
	Version  string   `yaml:"version"`
	Realm    string   `yaml:"realm"`
	Policies []Policy `yaml:"policies"`

	// ACRLevels defines the hierarchy for ACR comparison.
	// Higher index = higher assurance.
	// e.g. ["urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:gold"]
	ACRLevels []string `yaml:"acr_levels"`
}

// Policy defines the access requirements for a set of resources.
type Policy struct {
	Name          string   `yaml:"name"`
	Resources     []string `yaml:"resources"`    // glob patterns, e.g. /api/payments/**
	Methods       []string `yaml:"methods"`      // HTTP methods, empty = all
	RequireACR    string   `yaml:"require_acr"`  // minimum acr_values required
	MaxAge        int      `yaml:"max_age"`      // max auth age in seconds, 0 = unlimited
	RequireMFA    bool     `yaml:"require_mfa"`  // AMR must include mfa
	RequireScopes []string `yaml:"require_scopes"`

	// RequireAuthorizationDetails enforces RFC 9396 authorization_details.
	// All listed filters must be satisfied by the token's authorization_details claim.
	RequireAuthorizationDetails []rar.AuthorizationDetailFilter `yaml:"require_authorization_details,omitempty"`

	Enabled bool `yaml:"enabled"`
}

// PolicyRequest is the input to the policy engine.
type PolicyRequest struct {
	Method      string
	Path        string
	TokenACR    string
	TokenAMR    []string
	TokenScopes []string
	AuthAge     time.Duration // how long ago the user authenticated

	// AuthorizationDetails carries RFC 9396 details extracted from the token.
	AuthorizationDetails []rar.AuthorizationDetail
}

// PolicyResult is the output of policy evaluation.
type PolicyResult struct {
	Allowed      bool
	MatchedPolicy *Policy

	// If not allowed, these fields describe what is needed:
	RequiredACR  string
	RequiredMaxAge int
	Reason       string
}
