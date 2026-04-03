package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

// AuditLogger emits structured security audit events.
type AuditLogger struct {
	logger *slog.Logger
}

// NewAuditLogger creates an audit logger writing to the given slog logger.
func NewAuditLogger(logger *slog.Logger) *AuditLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuditLogger{logger: logger}
}

// Emit records an audit event.
func (a *AuditLogger) Emit(ctx context.Context, event *AuditEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.TraceID == "" {
		event.TraceID = TraceIDFromContext(ctx)
	}

	b, err := json.Marshal(event)
	if err != nil {
		a.logger.ErrorContext(ctx, "failed to marshal audit event", "error", err)
		return
	}

	a.logger.InfoContext(ctx, "audit",
		"event_type", string(event.Type),
		"payload", string(b),
	)
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

func newEventID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
