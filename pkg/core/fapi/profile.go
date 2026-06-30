package fapi

import (
	"fmt"
	"net/http"
	"time"
)

// FAPIMaxAuthAge is the maximum authentication age mandated by FAPI 2.0 Security Profile.
const FAPIMaxAuthAge = 60 * time.Second

// ProfileError is returned when a request fails FAPI 2.0 profile validation.
type ProfileError struct {
	Requirement string
	Detail      string
}

func (e *ProfileError) Error() string {
	return fmt.Sprintf("FAPI 2.0 profile violation [%s]: %s", e.Requirement, e.Detail)
}

// TokenClaims is a minimal interface over token claims needed for profile validation.
// Concrete implementations (CommonClaims) satisfy this via their exported fields.
type TokenClaims interface {
	// HasDPoP returns true if the token was bound via DPoP proof-of-possession.
	HasDPoP() bool

	// HasPARRequestURI returns true if the token's authorization was initiated
	// via a Pushed Authorization Request (claim "request_uri" or "par_id" present).
	HasPARRequestURI() bool

	// GetAuthAge returns the time elapsed since the user authenticated.
	// Zero means the auth_time claim is absent.
	GetAuthAge() time.Duration

	// GetNonce returns the nonce claim value.
	GetNonce() string
}

// ValidateRequest validates an incoming resource request against the FAPI 2.0
// Security Profile requirements. Call this after token introspection, before
// forwarding to the upstream service.
//
// cfg should be DefaultFAPI2Config() for strict FAPI 2.0 compliance, or a
// customized config for relaxed profiles.
//
// claims is the validated token's claims. r is the incoming HTTP request.
func ValidateRequest(r *http.Request, claims TokenClaims, cfg ValidationConfig) error {
	// FAPI 2.0 §5.3.2: DPoP REQUIRED.
	if cfg.RequireDPoP && !claims.HasDPoP() {
		return &ProfileError{
			Requirement: "DPoP",
			Detail:      "token must be DPoP-bound; missing DPoP proof",
		}
	}

	// FAPI 2.0 §5.3.3: Authorization MUST have been pushed via PAR.
	if cfg.RequireRequestURI && !claims.HasPARRequestURI() {
		return &ProfileError{
			Requirement: "PAR",
			Detail:      "authorization must be initiated via Pushed Authorization Request",
		}
	}

	// FAPI 2.0 §5.3.2: Nonce REQUIRED (issued by AS; must be present in token).
	if claims.GetNonce() == "" {
		return &ProfileError{
			Requirement: "nonce",
			Detail:      "token must contain a nonce claim",
		}
	}

	// FAPI 2.0 §5.3.3: auth_time freshness — if auth_time is present it must
	// be within FAPIMaxAuthAge (60 seconds). If absent (age = 0), we cannot
	// enforce this requirement and skip it (lenient mode for non-FAPI AS).
	if authAge := claims.GetAuthAge(); authAge > 0 && authAge > FAPIMaxAuthAge {
		return &ProfileError{
			Requirement: "auth_time",
			Detail: fmt.Sprintf("authentication is too old (%s > %s max)",
				authAge.Round(time.Second), FAPIMaxAuthAge),
		}
	}

	return nil
}

// ValidateTokenBinding checks FAPI 2.0 §5.3.2 token binding requirements:
// the token must be sender-constrained (DPoP or mTLS certificate binding).
// This is a standalone check used when you already know DPoP is enabled but
// want to verify certificate binding as a fallback.
func ValidateTokenBinding(r *http.Request, claims TokenClaims, allowMTLS bool) error {
	if claims.HasDPoP() {
		return nil
	}
	if allowMTLS && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return nil
	}
	return &ProfileError{
		Requirement: "token-binding",
		Detail:      "token must be sender-constrained via DPoP or mTLS certificate",
	}
}
