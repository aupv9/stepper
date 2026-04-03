package stepup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
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
