package stepup

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// CookieName is the cookie used to carry SavedRequest state across the re-auth redirect.
	CookieName = "iam_stepup_state"
	cookieMaxAge = 600 // 10 minutes
)

// State represents the current step in the step-up authentication flow.
type State int

const (
	StateIdle       State = iota // No challenge in progress
	StateChallenge               // Challenge issued, waiting for re-auth
	StateCompleted               // Re-authentication successful
	StateFailed                  // Re-authentication failed or timed out
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateChallenge:
		return "challenge"
	case StateCompleted:
		return "completed"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// contextKey is unexported to prevent collisions.
type contextKey int

const stepUpStateKey contextKey = iota

// SavedRequest captures the original request before the step-up challenge,
// so it can be replayed after successful re-authentication.
type SavedRequest struct {
	Method   string
	Path     string
	Query    string
	StateID  string    // random opaque value for CSRF protection
	SavedAt  time.Time
	ACRHint  string    // acr_values that triggered this challenge
	MaxAge   int
}

// Encode serializes the SavedRequest to a base64 string (for state param / cookie).
func (sr *SavedRequest) Encode() (string, error) {
	b, err := json.Marshal(sr)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// DecodeSavedRequest decodes a base64-encoded SavedRequest.
func DecodeSavedRequest(encoded string) (*SavedRequest, error) {
	b, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid encoded state: %w", err)
	}
	var sr SavedRequest
	if err := json.Unmarshal(b, &sr); err != nil {
		return nil, fmt.Errorf("invalid state payload: %w", err)
	}
	return &sr, nil
}

// FlowState holds the complete step-up flow context.
type FlowState struct {
	State        State
	Challenge    *StepUpChallenge
	SavedRequest *SavedRequest
	StartedAt    time.Time
	CompletedAt  time.Time
}

// StateMachine manages the step-up authentication flow lifecycle.
type StateMachine struct {
	// Timeout is how long a challenge can remain open before expiring.
	// Default: 10 minutes.
	Timeout time.Duration
}

// NewStateMachine creates a StateMachine with defaults.
func NewStateMachine() *StateMachine {
	return &StateMachine{
		Timeout: 10 * time.Minute,
	}
}

// BeginChallenge transitions from Idle → Challenge.
// Saves the original request and returns the FlowState.
func (sm *StateMachine) BeginChallenge(r *http.Request, challenge *StepUpChallenge) (*FlowState, error) {
	saved := &SavedRequest{
		Method:  r.Method,
		Path:    r.URL.Path,
		Query:   r.URL.RawQuery,
		SavedAt: time.Now(),
		ACRHint: challenge.ACRValues,
		MaxAge:  challenge.MaxAge,
	}

	return &FlowState{
		State:        StateChallenge,
		Challenge:    challenge,
		SavedRequest: saved,
		StartedAt:    time.Now(),
	}, nil
}

// Complete transitions from Challenge → Completed.
func (sm *StateMachine) Complete(flow *FlowState) error {
	if flow.State != StateChallenge {
		return fmt.Errorf("cannot complete flow in state %s", flow.State)
	}
	if time.Since(flow.StartedAt) > sm.Timeout {
		flow.State = StateFailed
		return fmt.Errorf("step-up challenge timed out")
	}
	flow.State = StateCompleted
	flow.CompletedAt = time.Now()
	return nil
}

// Fail transitions to Failed state.
func (sm *StateMachine) Fail(flow *FlowState) {
	flow.State = StateFailed
}

// WithFlowState stores FlowState in context.
func WithFlowState(ctx context.Context, flow *FlowState) context.Context {
	return context.WithValue(ctx, stepUpStateKey, flow)
}

// FlowStateFromContext retrieves FlowState from context.
func FlowStateFromContext(ctx context.Context) (*FlowState, bool) {
	flow, ok := ctx.Value(stepUpStateKey).(*FlowState)
	return flow, ok
}

// --- Cookie-based step-up state (stateless, HMAC-signed) ---

// SetStateCookie writes the SavedRequest into a signed, HttpOnly cookie on the response.
// The cookie survives the redirect to the AS and back, letting the guard replay the
// original request once the new token satisfies the required ACR.
// signingKey should be a random secret shared across service instances (e.g. IAM_COOKIE_SECRET).
func SetStateCookie(w http.ResponseWriter, saved *SavedRequest, signingKey string) error {
	payload, err := saved.Encode()
	if err != nil {
		return fmt.Errorf("encoding saved request: %w", err)
	}

	// Append HMAC so the client cannot tamper with the state.
	sig := signPayload(payload, signingKey)
	value := payload + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		MaxAge:   cookieMaxAge,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure is enforced by the caller (set to true in production via TLS).
	})
	return nil
}

// ClearStateCookie removes the step-up cookie after a successful re-authentication.
func ClearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	})
}

// ReadStateCookie reads and verifies the step-up cookie from the request.
// Returns nil, nil when the cookie is absent.
func ReadStateCookie(r *http.Request, signingKey string) (*SavedRequest, error) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return nil, nil // absent
	}

	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed step-up cookie")
	}
	payload, sig := parts[0], parts[1]

	expected := signPayload(payload, signingKey)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return nil, fmt.Errorf("invalid step-up cookie signature")
	}

	saved, err := DecodeSavedRequest(payload)
	if err != nil {
		return nil, fmt.Errorf("decoding step-up cookie: %w", err)
	}

	// Reject expired cookies regardless of MaxAge header (defence in depth).
	if time.Since(saved.SavedAt) > cookieMaxAge*time.Second {
		return nil, fmt.Errorf("step-up cookie expired")
	}
	return saved, nil
}

// newStateID generates a random opaque state ID for CSRF protection.
func newStateID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

func signPayload(payload, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
