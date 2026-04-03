package telemetry

import (
	"context"
	"log/slog"
	"os"
)

// NewLogger creates a structured slog logger.
// format: "json" (default) or "text"
func NewLogger(format string, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

// contextLogKey is used to store logger in context.
type contextLogKey struct{}

// WithLogger stores a logger in the context.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, contextLogKey{}, logger)
}

// LoggerFromContext retrieves the logger from context, falling back to the default logger.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(contextLogKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// IAMEvent is a structured log event for IAM operations.
type IAMEvent struct {
	Event     string // e.g. "token.validated", "stepup.challenge_issued"
	TenantID  string
	Subject   string
	ACR       string
	Resource  string
	Method    string
	Allowed   bool
	Reason    string
	TraceID   string
}

// Log emits the IAMEvent as a structured slog record.
func (e *IAMEvent) Log(ctx context.Context) {
	logger := LoggerFromContext(ctx)
	logger.InfoContext(ctx, e.Event,
		"tenant_id", e.TenantID,
		"sub", e.Subject,
		"acr", e.ACR,
		"resource", e.Resource,
		"method", e.Method,
		"allowed", e.Allowed,
		"reason", e.Reason,
		"trace_id", e.TraceID,
	)
}
