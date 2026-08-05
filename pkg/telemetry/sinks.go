package telemetry

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// --- RotatingFileSink ---

// RotatingFileSink writes NDJSON audit events with size-based rotation:
// when the current file exceeds MaxBytes it is renamed to <path>.1 (shifting
// older rotations up to MaxBackups) and a fresh file is opened.
type RotatingFileSink struct {
	path       string
	maxBytes   int64
	maxBackups int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// NewRotatingFileSink creates a rotating NDJSON sink. maxBytes defaults to
// 100 MiB, maxBackups to 5.
func NewRotatingFileSink(path string, maxBytes int64, maxBackups int) (*RotatingFileSink, error) {
	if maxBytes <= 0 {
		maxBytes = 100 << 20
	}
	if maxBackups <= 0 {
		maxBackups = 5
	}
	s := &RotatingFileSink{path: path, maxBytes: maxBytes, maxBackups: maxBackups}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *RotatingFileSink) open() error {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening audit file %q: %w", s.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	s.f = f
	s.size = info.Size()
	return nil
}

// Write appends the event, rotating first when the file is full.
func (s *RotatingFileSink) Write(_ context.Context, event *AuditEvent) error {
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshaling audit event: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.size+int64(len(line)) > s.maxBytes {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	n, err := s.f.Write(line)
	s.size += int64(n)
	return err
}

// rotate shifts path.(N-1) → path.N, path → path.1, then reopens path.
func (s *RotatingFileSink) rotate() error {
	if err := s.f.Close(); err != nil {
		return err
	}
	for i := s.maxBackups - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", s.path, i), fmt.Sprintf("%s.%d", s.path, i+1)) //nolint:errcheck
	}
	if err := os.Rename(s.path, s.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return s.open()
}

// Close closes the current file.
func (s *RotatingFileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// --- WebhookSink ---

// WebhookSink POSTs each audit event as JSON to an HTTP endpoint (e.g. a SIEM
// collector or a Kafka REST proxy). When a secret is configured, requests are
// signed with X-Hub-Signature-256: sha256=<hmac-sha256(secret, body)> — the
// same scheme the gateway itself accepts on /webhook/revoke.
type WebhookSink struct {
	url        string
	secret     string
	httpClient *http.Client
}

// NewWebhookSink creates a webhook audit sink.
func NewWebhookSink(url, secret string, httpClient *http.Client) *WebhookSink {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &WebhookSink{url: url, secret: secret, httpClient: httpClient}
}

// Write delivers one event. Delivery failures are returned to the AuditLogger,
// which logs them without blocking other sinks.
func (s *WebhookSink) Write(ctx context.Context, event *AuditEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshaling audit event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.secret != "" {
		mac := hmac.New(sha256.New, []byte(s.secret))
		mac.Write(body)
		req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delivering audit event: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("audit webhook returned %d", resp.StatusCode)
	}
	return nil
}
