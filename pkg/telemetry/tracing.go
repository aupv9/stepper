package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/common-iam/iam"

// Tracer returns the IAM OpenTelemetry tracer.
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// StartSpan starts a new span for an IAM operation.
func StartSpan(ctx context.Context, operation string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return Tracer().Start(ctx, operation, trace.WithAttributes(attrs...))
}

// SpanFromToken adds token-related attributes to the current span.
func SpanFromToken(span trace.Span, sub, acr, tenantID string) {
	span.SetAttributes(
		attribute.String("iam.subject", sub),
		attribute.String("iam.acr", acr),
		attribute.String("iam.tenant_id", tenantID),
	)
}

// SpanFail records an error on the span.
func SpanFail(span trace.Span, err error) {
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// TraceIDFromContext extracts the trace ID string from the current context.
func TraceIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}
	return span.SpanContext().TraceID().String()
}
