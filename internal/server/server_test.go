package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Addr", cfg.Addr, ":8080"},
		{"ReadTimeout", cfg.ReadTimeout, 15 * time.Second},
		{"WriteTimeout", cfg.WriteTimeout, 30 * time.Second},
		{"IdleTimeout", cfg.IdleTimeout, 60 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestNew_PropagatesConfig(t *testing.T) {
	cfg := Config{
		Addr:         "127.0.0.1:12345",
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 2 * time.Second,
		IdleTimeout:  3 * time.Second,
	}
	handler := http.NewServeMux()
	s := New(handler, cfg)

	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.addr != cfg.Addr {
		t.Errorf("addr = %q, want %q", s.addr, cfg.Addr)
	}
	if s.httpSrv == nil {
		t.Fatal("httpSrv is nil")
	}
	if s.httpSrv.Addr != cfg.Addr {
		t.Errorf("httpSrv.Addr = %q, want %q", s.httpSrv.Addr, cfg.Addr)
	}
	if s.httpSrv.ReadTimeout != cfg.ReadTimeout {
		t.Errorf("ReadTimeout = %v, want %v", s.httpSrv.ReadTimeout, cfg.ReadTimeout)
	}
	if s.httpSrv.WriteTimeout != cfg.WriteTimeout {
		t.Errorf("WriteTimeout = %v, want %v", s.httpSrv.WriteTimeout, cfg.WriteTimeout)
	}
	if s.httpSrv.IdleTimeout != cfg.IdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", s.httpSrv.IdleTimeout, cfg.IdleTimeout)
	}
	if s.httpSrv.Handler == nil {
		t.Error("handler not propagated to httpSrv")
	}
}

// freeAddr returns a loopback address with an OS-assigned free port. There is a
// small window between closing the listener and the server re-binding, but it is
// the standard approach for getting an ephemeral port for a server that binds
// internally via ListenAndServe.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("closing reservation listener: %v", err)
	}
	return addr
}

// TestServer_StartServeShutdown exercises the full lifecycle: Start binds and
// serves, a real GET succeeds, then Shutdown(ctx) returns without error and the
// server stops accepting connections.
func TestServer_StartServeShutdown(t *testing.T) {
	addr := freeAddr(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("served"))
	})
	s := New(handler, Config{Addr: addr})

	// Start blocks until the server stops, so run it in a goroutine and capture
	// its terminal error.
	startErr := make(chan error, 1)
	go func() { startErr <- s.Start() }()

	url := "http://" + addr + "/"

	// Poll until the listener is up (bounded; no fixed long sleep).
	client := &http.Client{Timeout: 2 * time.Second}
	if !waitForServe(t, client, url) {
		// Best-effort shutdown before failing so the goroutine can exit.
		_ = s.Shutdown(context.Background())
		<-startErr
		t.Fatal("server did not start serving within deadline")
	}

	// Confirm it actually serves our handler.
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET after start: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "served" {
		t.Errorf("body = %q, want %q", string(body), "served")
	}

	// Graceful shutdown must return without error.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}

	// Start must return http.ErrServerClosed after a graceful shutdown.
	select {
	case err := <-startErr:
		if err != http.ErrServerClosed {
			t.Errorf("Start returned %v, want http.ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start did not return after Shutdown")
	}

	// The server must no longer serve requests.
	if _, err := client.Get(url); err == nil {
		t.Error("expected connection error after shutdown, got nil")
	}
}

// TestServer_ShutdownBeforeStart verifies Shutdown is safe to call on a server
// that was never started: net/http returns nil in that case.
func TestServer_ShutdownBeforeStart(t *testing.T) {
	s := New(http.NewServeMux(), Config{Addr: "127.0.0.1:0"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown before Start returned %v, want nil", err)
	}
}

// waitForServe polls the URL until the server responds or a deadline passes.
func waitForServe(t *testing.T, client *http.Client, url string) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return true
		}
		// Connection refused while the listener spins up is expected; retry.
		if !strings.Contains(err.Error(), "connection refused") &&
			!strings.Contains(err.Error(), "connection reset") {
			// Unexpected error; surface it but keep polling until deadline.
			t.Logf("transient GET error while waiting: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
