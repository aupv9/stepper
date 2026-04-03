package stepup

import "errors"

// RFC 9470 error codes for WWW-Authenticate Bearer challenges.
const (
	// ErrCodeInsufficientUserAuthentication is returned when the current
	// authentication level is lower than required by policy.
	ErrCodeInsufficientUserAuthentication = "insufficient_user_authentication"

	// ErrCodeInvalidToken is returned when the token is missing or malformed.
	ErrCodeInvalidToken = "invalid_token"

	// ErrCodeInsufficientScope is returned when the token lacks required scopes.
	ErrCodeInsufficientScope = "insufficient_scope"
)

// Sentinel errors.
var (
	ErrMissingToken        = errors.New("missing bearer token")
	ErrTokenExpired        = errors.New("token has expired")
	ErrTokenInactive       = errors.New("token is not active")
	ErrInsufficientACR     = errors.New("insufficient authentication context level")
	ErrAuthTooOld          = errors.New("authentication is too old (max_age exceeded)")
	ErrDPoPBindingMismatch = errors.New("dpop proof does not match token binding")
	ErrTenantNotFound      = errors.New("tenant not found")
	ErrProviderUnavailable = errors.New("identity provider unavailable")
)

// StepUpError represents a structured step-up authentication error
// that can be serialized into a WWW-Authenticate header.
type StepUpError struct {
	Code        string // one of the ErrCode* constants
	Description string
	ACRValues   string // required acr_values hint
	MaxAge      int    // required max_age hint (seconds), 0 = not set
}

func (e *StepUpError) Error() string {
	return e.Description
}

// NewInsufficientACRError creates a StepUpError for insufficient authentication level.
func NewInsufficientACRError(requiredACR string, maxAge int) *StepUpError {
	return &StepUpError{
		Code:        ErrCodeInsufficientUserAuthentication,
		Description: "higher authentication level required",
		ACRValues:   requiredACR,
		MaxAge:      maxAge,
	}
}
