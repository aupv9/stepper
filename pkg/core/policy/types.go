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
	Resources     []string `yaml:"resources"`   // glob patterns, e.g. /api/payments/**
	Methods       []string `yaml:"methods"`     // HTTP methods, empty = all
	RequireACR    string   `yaml:"require_acr"` // minimum acr_values required
	MaxAge        int      `yaml:"max_age"`     // max auth age in seconds, 0 = unlimited
	RequireMFA    bool     `yaml:"require_mfa"` // AMR must include mfa
	RequireScopes []string `yaml:"require_scopes"`

	// RequireRoles: the token must carry every listed role.
	RequireRoles []string `yaml:"require_roles,omitempty"`

	// Effect is "allow" (default) or "deny". A matched deny policy rejects
	// the request outright — requirements (require_*) are not evaluated.
	Effect string `yaml:"effect,omitempty"`

	// Priority orders evaluation: higher first. Policies with equal priority
	// keep their file order. Default 0.
	Priority int `yaml:"priority,omitempty"`

	// Tenants scopes the policy to specific tenant IDs. Empty = all tenants.
	Tenants []string `yaml:"tenants,omitempty"`

	// When adds request-context match conditions. A policy whose conditions
	// don't match simply does not apply (evaluation falls through).
	When *Condition `yaml:"when,omitempty"`

	// RequireAudience enforces RFC 8707 resource indicators: the token's aud
	// claim must contain every listed value. Fails closed when the token
	// carries no aud claim.
	RequireAudience []string `yaml:"require_audience,omitempty"`

	// RequireAuthorizationDetails enforces RFC 9396 authorization_details.
	// All listed filters must be satisfied by the token's authorization_details claim.
	RequireAuthorizationDetails []rar.AuthorizationDetailFilter `yaml:"require_authorization_details,omitempty"`

	Enabled bool `yaml:"enabled"`
}

// Condition is a request-context match clause (part of policy matching, not
// a requirement: a non-matching condition makes the policy fall through).
type Condition struct {
	// IPCIDR matches when the client IP falls inside ANY listed CIDR
	// (or equals a bare IP entry).
	IPCIDR []string `yaml:"ip_cidr,omitempty"`

	// TimeWindow matches when the evaluation time falls inside the window.
	TimeWindow *TimeWindow `yaml:"time_window,omitempty"`

	// Headers matches when every listed request header equals the given
	// value (exact match, header names case-insensitive).
	Headers map[string]string `yaml:"headers,omitempty"`
}

// TimeWindow is a daily time range with optional day-of-week restriction.
type TimeWindow struct {
	Start string   `yaml:"start"`          // "08:00"
	End   string   `yaml:"end"`            // "18:00"
	Days  []string `yaml:"days,omitempty"` // mon..sun, empty = every day
	TZ    string   `yaml:"tz,omitempty"`   // IANA zone, default UTC
}

// PolicyRequest is the input to the policy engine.
type PolicyRequest struct {
	Method        string
	Path          string
	TenantID      string // resolved tenant (for tenant-scoped policies)
	TokenACR      string
	TokenAMR      []string
	TokenScopes   []string
	TokenRoles    []string      // token roles (for require_roles)
	TokenAudience []string      // token aud claim (for require_audience)
	AuthAge       time.Duration // how long ago the user authenticated

	// ClientIP is the request's client IP (for when.ip_cidr conditions).
	ClientIP string

	// Headers carries request headers relevant to when.headers conditions.
	Headers map[string]string

	// Now is the evaluation time for when.time_window; zero means time.Now().
	Now time.Time

	// AuthorizationDetails carries RFC 9396 details extracted from the token.
	AuthorizationDetails []rar.AuthorizationDetail
}

// PolicyResult is the output of policy evaluation.
type PolicyResult struct {
	Allowed       bool
	MatchedPolicy *Policy

	// If not allowed, these fields describe what is needed:
	RequiredACR    string
	RequiredMaxAge int
	Reason         string
}
