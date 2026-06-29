package telemetry_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/common-iam/iam/pkg/telemetry"
)

// captureSink records every event written to it.
type captureSink struct {
	mu     sync.Mutex
	events []*telemetry.AuditEvent
}

func (c *captureSink) Write(_ context.Context, event *telemetry.AuditEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
	return nil
}

func (c *captureSink) all() []*telemetry.AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*telemetry.AuditEvent, len(c.events))
	copy(out, c.events)
	return out
}

// errorSink always returns an error on Write.
type errorSink struct{}

func (e *errorSink) Write(_ context.Context, _ *telemetry.AuditEvent) error {
	return os.ErrInvalid
}

func TestAuditLogger_DefaultSlogSink(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	al := telemetry.NewAuditLogger(logger)

	// Should not panic and should not error.
	al.Emit(context.Background(), &telemetry.AuditEvent{
		Type:    telemetry.AuditTokenValidated,
		Subject: "alice",
	})
}

func TestAuditLogger_AddSink_FanOut(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	al := telemetry.NewAuditLogger(logger)

	sink1 := &captureSink{}
	sink2 := &captureSink{}
	al.AddSink(sink1)
	al.AddSink(sink2)

	al.Emit(context.Background(), &telemetry.AuditEvent{
		Type:    telemetry.AuditPolicyDenied,
		Subject: "bob",
	})

	if len(sink1.all()) != 1 {
		t.Errorf("sink1: expected 1 event, got %d", len(sink1.all()))
	}
	if len(sink2.all()) != 1 {
		t.Errorf("sink2: expected 1 event, got %d", len(sink2.all()))
	}
	if sink1.all()[0].Subject != "bob" {
		t.Errorf("expected subject=bob, got %q", sink1.all()[0].Subject)
	}
}

func TestAuditLogger_SinkError_DoesNotHaltOtherSinks(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	al := telemetry.NewAuditLogger(logger)

	// errorSink is registered before captureSink — its error must not stop delivery.
	al.AddSink(&errorSink{})
	good := &captureSink{}
	al.AddSink(good)

	al.Emit(context.Background(), &telemetry.AuditEvent{Type: telemetry.AuditTokenRejected})

	if len(good.all()) != 1 {
		t.Errorf("good sink should have received the event despite errorSink failure")
	}
}

func TestAuditLogger_TimestampPopulatedIfZero(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	al := telemetry.NewAuditLogger(logger)

	sink := &captureSink{}
	al.AddSink(sink)

	al.Emit(context.Background(), &telemetry.AuditEvent{Type: telemetry.AuditTokenValidated})

	events := sink.all()
	if len(events) == 0 {
		t.Fatal("no events captured")
	}
	if events[0].Timestamp.IsZero() {
		t.Error("Timestamp should be set when not provided")
	}
}

func TestAuditLogger_EmitPolicyDecision(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	al := telemetry.NewAuditLogger(logger)

	sink := &captureSink{}
	al.AddSink(sink)

	al.EmitPolicyDecision(context.Background(), "carol", "acme", "/api/data", "GET", "need-silver", "acr too low", false)

	events := sink.all()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Type != telemetry.AuditPolicyDenied {
		t.Errorf("expected AuditPolicyDenied, got %q", ev.Type)
	}
	if ev.Subject != "carol" || ev.TenantID != "acme" || ev.Allowed {
		t.Errorf("unexpected event fields: %+v", ev)
	}
}

func TestFileSink_WritesNDJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	fs, err := telemetry.NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer fs.Close() //nolint:errcheck

	events := []*telemetry.AuditEvent{
		{Type: telemetry.AuditTokenValidated, Subject: "user-1"},
		{Type: telemetry.AuditPolicyDenied, Subject: "user-2"},
	}
	for _, e := range events {
		if err := fs.Write(context.Background(), e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read back and verify NDJSON.
	f, _ := os.Open(path)
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	var decoded []telemetry.AuditEvent
	for scanner.Scan() {
		var ev telemetry.AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("decode line: %v", err)
		}
		decoded = append(decoded, ev)
	}

	if len(decoded) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(decoded))
	}
	if decoded[0].Subject != "user-1" || decoded[1].Subject != "user-2" {
		t.Errorf("unexpected decoded events: %+v", decoded)
	}
}

func TestFileSink_ConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.ndjson")
	fs, err := telemetry.NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer fs.Close() //nolint:errcheck

	const goroutines = 10
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fs.Write(context.Background(), &telemetry.AuditEvent{Type: telemetry.AuditTokenValidated}) //nolint:errcheck
		}()
	}
	wg.Wait()
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, _ := os.Open(path)
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	if count != goroutines {
		t.Errorf("expected %d lines, got %d", goroutines, count)
	}
}

func TestAuditLogger_AddSink_Integration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	fileSink, err := telemetry.NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer fileSink.Close() //nolint:errcheck

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	al := telemetry.NewAuditLogger(logger)
	al.AddSink(fileSink)

	captureSk := &captureSink{}
	al.AddSink(captureSk)

	al.EmitStepUpChallenge(context.Background(), "dave", "acme", "/api/admin", "GET", "urn:mace:incommon:iap:silver")

	// Both sinks received the event.
	if len(captureSk.all()) != 1 {
		t.Errorf("capture sink: expected 1 event, got %d", len(captureSk.all()))
	}

	fileSink.Close() //nolint:errcheck

	f, _ := os.Open(path)
	defer f.Close() //nolint:errcheck
	scanner := bufio.NewScanner(f)
	lines := 0
	for scanner.Scan() {
		lines++
	}
	if lines != 1 {
		t.Errorf("file sink: expected 1 line, got %d", lines)
	}
}
