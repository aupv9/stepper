package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/devkit/localas"
	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
)

// TestHA_MultiTenantConfig_SharedRedis is the M5 exit-criteria test:
//   - two iam-service replicas boot from an iam.yaml declaring two tenants
//   - both share revocation state through Redis
//   - SIGHUP hot-reloads the policy file
//
// Requires REDIS_ADDR (skipped otherwise, like the goredis integration test).
func TestHA_MultiTenantConfig_SharedRedis(t *testing.T) {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		t.Skip("set REDIS_ADDR to run the HA integration test")
	}
	if testing.Short() {
		t.Skip("skipping HA integration test in -short mode")
	}

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	// --- Two in-process LocalAS = two tenants' Authorization Servers ---
	as1 := startAS(t) // tenant acme
	as2 := startAS(t) // tenant bravo

	// --- Config + policy files ---
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	writeFile(t, policyFile, `
realm: HA
policies:
  - name: allow-all
    resources: ["/**"]
    enabled: true
`)
	configFile := filepath.Join(dir, "iam.yaml")
	writeFile(t, configFile, fmt.Sprintf(`
realm: HA
policy_file: %q
log_format: json
default_tenant: acme
redis:
  addr: %q
tenants:
  - id: acme
    provider: generic
    discovery_url: %q
  - id: bravo
    provider: generic
    discovery_url: %q
resolvers:
  - type: header
    header: X-Tenant-ID
  - type: static
    tenant: acme
`, policyFile, redisAddr, as1.discovery, as2.discovery))

	// --- Build the binary once, boot two replicas ---
	bin := filepath.Join(dir, "iam-service")
	build := exec.Command("go", "build", "-o", bin, "./cmd/iam-service")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	replicaA := startReplica(t, bin, repoRoot, configFile)
	replicaB := startReplica(t, bin, repoRoot, configFile)

	// --- Tokens ---
	acmeToken := issueToken(t, as1.server, "alice")
	bravoToken := issueToken(t, as2.server, "bob")

	// 1. Multi-tenant boot from file: each tenant's token works on its own
	// tenant, and cross-tenant use is rejected.
	if code := doGet(t, replicaA.url+"/api/x", acmeToken, "acme"); code != http.StatusOK {
		t.Errorf("acme token on acme tenant: got %d, want 200", code)
	}
	if code := doGet(t, replicaA.url+"/api/x", bravoToken, "bravo"); code != http.StatusOK {
		t.Errorf("bravo token on bravo tenant: got %d, want 200", code)
	}
	if code := doGet(t, replicaA.url+"/api/x", acmeToken, "bravo"); code != http.StatusUnauthorized {
		t.Errorf("acme token on bravo tenant: got %d, want 401", code)
	}

	// 2. Shared revocation through Redis: warm the cache on replica B, revoke
	// at the AS, deliver the webhook ONLY to replica A. Replica B must see the
	// eviction via the shared cache and re-introspect → 401.
	if code := doGet(t, replicaB.url+"/api/x", acmeToken, "acme"); code != http.StatusOK {
		t.Fatalf("warming replica B cache: got %d", code)
	}
	as1.server.Revoke(acmeToken)
	webhookRevoke(t, replicaA.url, acmeToken)

	deadline := time.Now().Add(5 * time.Second)
	for {
		code := doGet(t, replicaB.url+"/api/x", acmeToken, "acme")
		if code == http.StatusUnauthorized {
			break // revocation propagated across replicas
		}
		if time.Now().After(deadline) {
			t.Fatalf("revocation did not propagate to replica B (still %d)", code)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 3. Hot reload: flip the policy to deny-all, SIGHUP replica A only.
	writeFile(t, policyFile, `
realm: HA
policies:
  - name: deny-all
    resources: ["/**"]
    require_acr: "urn:mace:incommon:iap:gold"
    enabled: true
`)
	if err := replicaA.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("SIGHUP: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		code := doGet(t, replicaA.url+"/api/x", bravoToken, "bravo")
		if code == http.StatusUnauthorized {
			break // new policy active on A
		}
		if time.Now().After(deadline) {
			t.Fatalf("SIGHUP policy reload did not take effect (still %d)", code)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Replica B was not reloaded and must still allow.
	if code := doGet(t, replicaB.url+"/api/x", bravoToken, "bravo"); code != http.StatusOK {
		t.Errorf("replica B (not reloaded): got %d, want 200", code)
	}

	// 4. Readiness probe reports ready with Redis + discovery loaded.
	resp, err := http.Get(replicaA.url + "/health/ready")
	if err != nil {
		t.Fatalf("ready probe: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health/ready: got %d, want 200", resp.StatusCode)
	}
}

// --- helpers ---

type asHandle struct {
	server    *localas.Server
	discovery string
}

func startAS(t *testing.T) asHandle {
	t.Helper()
	as, err := localas.New()
	if err != nil {
		t.Fatal(err)
	}
	base, err := as.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { as.Stop(context.Background()) }) //nolint:errcheck
	return asHandle{server: as, discovery: base + "/.well-known/openid-configuration"}
}

type replica struct {
	cmd *exec.Cmd
	url string
}

func startReplica(t *testing.T, bin, dir, configFile string) replica {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(),
		"IAM_CONFIG_FILE="+configFile,
		"IAM_ADDR="+addr,
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() }) //nolint:errcheck

	base := "http://" + addr
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get(base + "/health/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return replica{cmd: cmd, url: base}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("replica at %s never became ready", addr)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func issueToken(t *testing.T, as *localas.Server, sub string) string {
	t.Helper()
	tok, err := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   sub,
		ACR:       "urn:mace:incommon:iap:silver",
		Scopes:    []string{"openid"},
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func doGet(t *testing.T, rawURL, token, tenantID string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// webhookRevoke posts a token-hash revocation event to a replica's webhook.
func webhookRevoke(t *testing.T, baseURL, rawToken string) {
	t.Helper()
	body := fmt.Sprintf(`{"token_hash":%q}`, token.HashToken(rawToken))
	resp, err := http.Post(baseURL+"/webhook/revoke", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("webhook: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("webhook: got %d", resp.StatusCode)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
