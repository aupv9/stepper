package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/tenant"
)

func newVersionsTestHandler() *Handler {
	engine := policy.New(&policy.Config{
		Policies: []policy.Policy{{Name: "v0", Resources: []string{"/**"}, Enabled: true}},
	})
	return New(Config{Registry: tenant.NewRegistry(), Engine: engine})
}

func uploadPolicy(t *testing.T, h *Handler, name string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"yaml": "policies:\n  - name: " + name + "\n    resources: [\"/**\"]\n    enabled: true\n",
	})
	req := httptest.NewRequest(http.MethodPost, "/policy/reload", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("reload %s: got %d: %s", name, rr.Code, rr.Body.String())
	}
}

func TestAdmin_PolicyVersionsAndRollback(t *testing.T) {
	h := newVersionsTestHandler()

	uploadPolicy(t, h, "v1")
	uploadPolicy(t, h, "v2")

	// Versions listed.
	req := httptest.NewRequest(http.MethodGet, "/policy/versions", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var versions struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &versions); err != nil || versions.Count != 2 {
		t.Fatalf("versions = %s", rr.Body.String())
	}

	// Current config is v2.
	if s := h.engine.Summary(); !contains(s, "v2") {
		t.Fatalf("expected v2 active, got: %s", s)
	}

	// Rollback → v1 active.
	req = httptest.NewRequest(http.MethodPost, "/policy/rollback", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rollback: got %d: %s", rr.Code, rr.Body.String())
	}
	if s := h.engine.Summary(); !contains(s, "v1") || contains(s, "v2") {
		t.Errorf("expected v1 active after rollback, got: %s", s)
	}

	// Second rollback has nothing older → 409.
	req = httptest.NewRequest(http.MethodPost, "/policy/rollback", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 when no previous version, got %d", rr.Code)
	}
}

func TestAdmin_ListPolicies(t *testing.T) {
	h := newVersionsTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/policies", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d", rr.Code)
	}
	var cfg policy.Config
	if err := json.Unmarshal(rr.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("unmarshal: %v — %s", err, rr.Body.String())
	}
	if len(cfg.Policies) != 1 || cfg.Policies[0].Name != "v0" {
		t.Errorf("policies = %+v", cfg.Policies)
	}
}

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}
