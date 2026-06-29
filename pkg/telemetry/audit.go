package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// AuditEventType represents an RFC 8417 Security Event Token event type.
type AuditEventType string

const (
	AuditTokenValidated     AuditEventType = "iam.token.validated"
	AuditTokenRejected      AuditEventType = "iam.token.rejected"
	AuditStepUpIssued       AuditEventType = "iam.stepup.challenge_issued"
	AuditStepUpCompleted    AuditEventType = "iam.stepup.completed"
	AuditStepUpFailed       AuditEventType = "iam.stepup.failed"
	AuditPolicyDenied       AuditEventType = "iam.policy.denied"
	AuditPolicyAllowed      AuditEventType = "iam.policy.allowed"
	AuditTokenRevoked       AuditEventType = "iam.token.revoked"
	AuditTenantRegistered   AuditEventType = "iam.tenant.registered"
	AuditTenantUnregistered AuditEventType = "iam.tenant.unregistered"
)

// AuditEvent is a structured security audit event (inspired by RFC 8417 SET).
type AuditEvent struct {
	// Event metadata
	EventID   string         `json:"jti"`
	Type      AuditEventType `json:"event_type"`
	Timestamp time.Time      `json:"iat"`

	// Request context
	TraceID  string `json:"trace_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	Resource string `json:"resource,omitempty"`
	Method   string `json:"method,omitempty"`

	// Token context
	Subject   string   `json:"sub,omitempty"`
	ACR       string   `json:"acr,omitempty"`
	AMR       []string `json:"amr,omitempty"`
	SessionID string   `json:"sid,omitempty"`

	// Policy context
	PolicyName  string `json:"policy_name,omitempty"`
	RequiredACR string `json:"required_acr,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Allowed     bool   `json:"allowed"`
}

// AuditSink is the backend interface for audit event delivery.
// Implementations must be safe for concurrent use.
type AuditSink interface {
	Write(ctx context.Context, event *AuditEvent) error
}

// AuditLogger fans out structured security audit events to one or more AuditSinks.
// The zero value is unusable; construct with NewAuditLogger.
type AuditLogger struct {
	mu    sync.RWMutex
	sinks []AuditSink
}

// NewAuditLogger creates an AuditLogger backed by the given slog.Logger.
// Callers may attach additional sinks with AddSink.
func NewAuditLogger(logger *slog.Logger) *AuditLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuditLogger{sinks: []AuditSink{&slogSink{logger: logger}}}
}

// AddSink attaches an additional AuditSink. Safe to call concurrently.
func (a *AuditLogger) AddSink(sink AuditSink) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sinks = append(a.sinks, sink)
}

// Emit dispatches event to every registered sink.
// A failure in one sink is logged to slog.Default() but does not prevent
// delivery to the remaining sinks.
func (a *AuditLogger) Emit(ctx context.Context, event *AuditEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.TraceID == "" {
		event.TraceID = TraceIDFromContext(ctx)
	}

	a.mu.RLock()
	sinks := make([]AuditSink, len(a.sinks))
	copy(sinks, a.sinks)
	a.mu.RUnlock()

	for _, s := range sinks {
		if err := s.Write(ctx, event); err != nil {
			slog.Default().ErrorContext(ctx, "audit sink write error",
				"sink", fmt.Sprintf("%T", s), "error", err)
		}
	}
}

// EmitStepUpChallenge emits an audit event when a step-up challenge is issued.
func (a *AuditLogger) EmitStepUpChallenge(ctx context.Context, sub, tenantID, resource, method, requiredACR string) {
	a.Emit(ctx, &AuditEvent{
		EventID:     newEventID(),
		Type:        AuditStepUpIssued,
		TenantID:    tenantID,
		Subject:     sub,
		Resource:    resource,
		Method:      method,
		RequiredACR: requiredACR,
		Allowed:     false,
	})
}

// EmitPolicyDecision emits an audit event for a policy allow/deny decision.
func (a *AuditLogger) EmitPolicyDecision(ctx context.Context, sub, tenantID, resource, method, policyName, reason string, allowed bool) {
	eventType := AuditPolicyAllowed
	if !allowed {
		eventType = AuditPolicyDenied
	}
	a.Emit(ctx, &AuditEvent{
		EventID:    newEventID(),
		Type:       eventType,
		TenantID:   tenantID,
		Subject:    sub,
		Resource:   resource,
		Method:     method,
		PolicyName: policyName,
		Reason:     reason,
		Allowed:    allowed,
	})
}

// --- slogSink (built-in, unexported) ---

type slogSink struct {
	logger *slog.Logger
}

func (s *slogSink) Write(ctx context.Context, event *AuditEvent) error {
	b, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshaling audit event: %w", err)
	}
	s.logger.InfoContext(ctx, "audit",
		"event_type", string(event.Type),
		"payload", string(b),
	)
	return nil
}

// --- FileSink ---

// FileSink writes NDJSON-encoded audit events to a file, one event per line.
// Thread-safe; use NewFileSink to construct, Close when done.
type FileSink struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

// NewFileSink opens (or creates) the file at path for append-only NDJSON writes.
// File permissions are 0600.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit file %q: %w", path, err)
	}
	return &FileSink{f: f, enc: json.NewEncoder(f)}, nil
}

// Write appends the event as a single JSON line to the file.
func (fs *FileSink) Write(_ context.Context, event *AuditEvent) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if err := fs.enc.Encode(event); err != nil {
		return fmt.Errorf("writing audit event: %w", err)
	}
	return nil
}

// Close flushes OS buffers and closes the underlying file.
func (fs *FileSink) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.f.Close()
}

func newEventID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
