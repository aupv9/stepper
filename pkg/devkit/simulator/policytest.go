package simulator

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/common-iam/iam/pkg/core/policy"
)

// TestFile is a policy test suite (tests.yaml) for `iam-cli policy-test`.
type TestFile struct {
	Tests []TestCase `yaml:"tests"`
}

// TestCase is one request → expectation pair.
type TestCase struct {
	Name    string      `yaml:"name"`
	Request TestRequest `yaml:"request"`
	Expect  Expectation `yaml:"expect"`
}

// TestRequest mirrors simulator.Request in YAML form.
type TestRequest struct {
	Method   string            `yaml:"method"`
	Path     string            `yaml:"path"`
	Tenant   string            `yaml:"tenant"`
	ACR      string            `yaml:"acr"`
	AMR      []string          `yaml:"amr"`
	Scopes   []string          `yaml:"scopes"`
	Roles    []string          `yaml:"roles"`
	Audience []string          `yaml:"audience"`
	AuthAge  time.Duration     `yaml:"auth_age"` // e.g. 30s, 5m
	IP       string            `yaml:"ip"`
	Headers  map[string]string `yaml:"headers"`
	Now      string            `yaml:"now"` // RFC3339, empty = time.Now()
}

// Expectation describes the required outcome.
type Expectation struct {
	Allowed        bool   `yaml:"allowed"`
	Policy         string `yaml:"policy"`          // matched policy name, empty = don't care
	ReasonContains string `yaml:"reason_contains"` // substring of the denial reason
}

// TestResult is the outcome of one test case.
type TestResult struct {
	Name    string
	Passed  bool
	Detail  string // failure explanation
	Outcome *Result
}

// Report aggregates a test run.
type Report struct {
	Results []TestResult
}

// Passed reports whether every test case passed.
func (r *Report) Passed() bool {
	for _, t := range r.Results {
		if !t.Passed {
			return false
		}
	}
	return true
}

// String renders a human-readable summary table.
func (r *Report) String() string {
	var sb strings.Builder
	passed := 0
	for _, t := range r.Results {
		status := "PASS"
		if !t.Passed {
			status = "FAIL"
		} else {
			passed++
		}
		fmt.Fprintf(&sb, "%-4s %s\n", status, t.Name)
		if !t.Passed {
			fmt.Fprintf(&sb, "     %s\n", t.Detail)
		}
	}
	fmt.Fprintf(&sb, "\n%d/%d passed\n", passed, len(r.Results))
	return sb.String()
}

// RunTestFile evaluates every test case in a tests.yaml against the engine.
func RunTestFile(engine *policy.Engine, path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading test file: %w", err)
	}
	var tf TestFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("parsing test file %s: %w", path, err)
	}
	if len(tf.Tests) == 0 {
		return nil, fmt.Errorf("test file %s contains no tests", path)
	}

	sim := New(engine)
	report := &Report{}
	for i, tc := range tf.Tests {
		name := tc.Name
		if name == "" {
			name = fmt.Sprintf("test[%d]", i)
		}

		req := Request{
			Method:   strings.ToUpper(defaultStr(tc.Request.Method, "GET")),
			Path:     tc.Request.Path,
			Tenant:   tc.Request.Tenant,
			ACR:      tc.Request.ACR,
			AMR:      tc.Request.AMR,
			Scopes:   tc.Request.Scopes,
			Roles:    tc.Request.Roles,
			Audience: tc.Request.Audience,
			AuthAge:  tc.Request.AuthAge,
			ClientIP: tc.Request.IP,
			Headers:  tc.Request.Headers,
		}
		if tc.Request.Now != "" {
			now, err := time.Parse(time.RFC3339, tc.Request.Now)
			if err != nil {
				return nil, fmt.Errorf("%s: invalid now timestamp %q: %w", name, tc.Request.Now, err)
			}
			req.Now = now
		}

		outcome, err := sim.Simulate(req)
		if err != nil {
			report.Results = append(report.Results, TestResult{
				Name: name, Passed: false, Detail: "evaluation error: " + err.Error(),
			})
			continue
		}

		report.Results = append(report.Results, judge(name, tc.Expect, outcome))
	}
	return report, nil
}

func judge(name string, want Expectation, got *Result) TestResult {
	if got.Allowed != want.Allowed {
		return TestResult{Name: name, Outcome: got, Detail: fmt.Sprintf(
			"allowed = %v, want %v (policy=%s reason=%s)", got.Allowed, want.Allowed, got.PolicyName, got.Reason)}
	}
	if want.Policy != "" && got.PolicyName != want.Policy {
		return TestResult{Name: name, Outcome: got, Detail: fmt.Sprintf(
			"matched policy = %q, want %q", got.PolicyName, want.Policy)}
	}
	if want.ReasonContains != "" && !strings.Contains(got.Reason, want.ReasonContains) {
		return TestResult{Name: name, Outcome: got, Detail: fmt.Sprintf(
			"reason %q does not contain %q", got.Reason, want.ReasonContains)}
	}
	return TestResult{Name: name, Passed: true, Outcome: got}
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
