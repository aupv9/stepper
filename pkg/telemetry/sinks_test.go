package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingFileSink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.ndjson")

	// Tiny max size forces a rotation after a couple of events.
	sink, err := NewRotatingFileSink(path, 300, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := sink.Write(ctx, &AuditEvent{
			EventID: "e", Type: AuditPolicyDenied, Subject: "alice",
			Reason: strings.Repeat("x", 100),
		}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("current file missing: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected at least one rotation: %v", err)
	}
	// Backups capped at 3.
	if _, err := os.Stat(path + ".4"); err == nil {
		t.Error("backup count must be capped")
	}
}

func TestWebhookSink(t *testing.T) {
	var gotSig string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Hub-Signature-256")
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = buf
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	sink := NewWebhookSink(srv.URL, "hmac-secret", nil)
	err := sink.Write(context.Background(), &AuditEvent{EventID: "e1", Type: AuditTokenRevoked, Subject: "bob"})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Errorf("expected HMAC signature header, got %q", gotSig)
	}
	if !strings.Contains(string(gotBody), `"sub":"bob"`) {
		t.Errorf("body = %s", gotBody)
	}

	// Non-2xx is an error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(bad.Close)
	if err := NewWebhookSink(bad.URL, "", nil).Write(context.Background(), &AuditEvent{}); err == nil {
		t.Error("expected error for 502 response")
	}
}
