package simulator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/common-iam/iam/pkg/core/policy"
)

func TestRunTestFile(t *testing.T) {
	engine := policy.New(&policy.Config{
		ACRLevels: []string{"bronze", "silver"},
		Policies: []policy.Policy{
			{Name: "block-legacy", Resources: []string{"/legacy/**"}, Effect: "deny", Priority: 10, Enabled: true},
			{Name: "payments", Resources: []string{"/api/payments/**"}, RequireACR: "silver", Enabled: true},
			{Name: "public", Resources: []string{"/public/**"}, Enabled: true},
		},
	})

	dir := t.TempDir()
	testsPath := filepath.Join(dir, "tests.yaml")
	if err := os.WriteFile(testsPath, []byte(`
tests:
  - name: payments need silver
    request: {method: POST, path: /api/payments/transfer, acr: bronze}
    expect: {allowed: false, policy: payments, reason_contains: ACR}
  - name: silver passes payments
    request: {method: POST, path: /api/payments/transfer, acr: silver}
    expect: {allowed: true, policy: payments}
  - name: legacy denied outright
    request: {path: /legacy/old}
    expect: {allowed: false, policy: block-legacy}
  - name: public open
    request: {path: /public/docs}
    expect: {allowed: true}
  - name: unmatched path default deny
    request: {path: /nowhere}
    expect: {allowed: false, reason_contains: no matching policy}
`), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := RunTestFile(engine, testsPath)
	if err != nil {
		t.Fatalf("RunTestFile: %v", err)
	}
	if !report.Passed() {
		t.Errorf("expected all cases to pass:\n%s", report.String())
	}
	if len(report.Results) != 5 {
		t.Errorf("got %d results, want 5", len(report.Results))
	}
}

func TestRunTestFile_FailureDetected(t *testing.T) {
	engine := policy.New(&policy.Config{
		Policies: []policy.Policy{
			{Name: "open", Resources: []string{"/**"}, Enabled: true},
		},
	})

	dir := t.TempDir()
	testsPath := filepath.Join(dir, "tests.yaml")
	if err := os.WriteFile(testsPath, []byte(`
tests:
  - name: wrong expectation
    request: {path: /anything}
    expect: {allowed: false}
`), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := RunTestFile(engine, testsPath)
	if err != nil {
		t.Fatalf("RunTestFile: %v", err)
	}
	if report.Passed() {
		t.Error("report must fail when expectations do not hold")
	}
}
