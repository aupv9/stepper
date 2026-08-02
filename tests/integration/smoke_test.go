package integration

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestSmoke_ServiceBinaryBoots builds cmd/iam-service, boots it in LocalAS dev
// mode, waits for /health, and shuts it down gracefully. This guards the
// README quickstart: `make service` must actually start.
func TestSmoke_ServiceBinaryBoots(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary smoke test in -short mode")
	}

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "iam-service")

	build := exec.Command("go", "build", "-o", bin, "./cmd/iam-service")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/iam-service: %v\n%s", err, out)
	}

	// Pick a free port, then hand it to the service.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cmd := exec.Command(bin)
	cmd.Dir = repoRoot // so the default IAM_POLICY_FILE path resolves
	cmd.Env = append(cmd.Environ(), "IAM_ADDR="+addr)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting iam-service: %v", err)
	}
	defer cmd.Process.Kill() //nolint:errcheck

	healthURL := fmt.Sprintf("http://%s/health", addr)
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("service did not become healthy within 15s")
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Unauthenticated request must be challenged with RFC 9470 headers.
	resp, err := http.Get(fmt.Sprintf("http://%s/api/anything", addr))
	if err != nil {
		t.Fatalf("guarded request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated request, got %d", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate challenge header")
	}

	// Graceful shutdown on SIGTERM.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("sending SIGTERM: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("service exited with error after SIGTERM: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("service did not exit within 10s of SIGTERM")
	}
}
