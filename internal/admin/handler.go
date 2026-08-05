package admin

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/tenant"
)

// Config holds Admin API dependencies and options.
type Config struct {
	Registry *tenant.Registry
	Engine   *policy.Engine

	// AdminToken, if non-empty, requires all /admin/* requests to carry
	// "Authorization: Bearer <AdminToken>". Leave empty to allow unauthenticated
	// access (suitable for dev/local environments).
	AdminToken string

	// ReloadFunc, when set, backs POST /admin/reload: it re-reads the policy
	// file and tenant configuration from disk (same effect as SIGHUP).
	ReloadFunc func() error
}

// Handler provides the Admin REST API for managing policies and tenants at runtime.
type Handler struct {
	registry   *tenant.Registry
	engine     *policy.Engine
	adminToken string
	reloadFunc func() error
	mux        *http.ServeMux

	// Policy version history for API-driven reloads (rollback support).
	mu       sync.Mutex
	versions []policyVersion
}

// policyVersion is one API-uploaded policy revision.
type policyVersion struct {
	YAML       string    `json:"-"`
	UploadedAt time.Time `json:"uploaded_at"`
	Summary    string    `json:"summary"`
}

const maxPolicyVersions = 10

// New creates an Admin API handler.
func New(cfg Config) *Handler {
	h := &Handler{
		registry:   cfg.Registry,
		engine:     cfg.Engine,
		adminToken: cfg.AdminToken,
		reloadFunc: cfg.ReloadFunc,
		mux:        http.NewServeMux(),
	}
	h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The UI page itself is served without Bearer auth — it prompts the user
	// for the token in-browser and uses it for subsequent API calls.
	if r.URL.Path == "/ui" || r.URL.Path == "/ui/" {
		UIHandler().ServeHTTP(w, r)
		return
	}
	if h.adminToken != "" && !h.checkBearer(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="IAM Admin"`)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	h.mux.ServeHTTP(w, r)
}

// checkBearer validates that the request carries the expected admin bearer token.
func (h *Handler) checkBearer(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(token), []byte(h.adminToken)) == 1
}

func (h *Handler) routes() {
	h.mux.HandleFunc("/tenants", h.handleTenants)
	h.mux.HandleFunc("/policies", h.handlePolicies)
	h.mux.HandleFunc("/policy/summary", h.handlePolicySummary)
	h.mux.HandleFunc("/policy/reload", h.handlePolicyReload)
	h.mux.HandleFunc("/policy/versions", h.handlePolicyVersions)
	h.mux.HandleFunc("/policy/rollback", h.handlePolicyRollback)
	h.mux.HandleFunc("/reload", h.handleReload)
}

// GET /admin/policies — full policy configuration as JSON
func (h *Handler) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := h.engine.Config()
	if cfg == nil {
		writeJSON(w, map[string]interface{}{"policies": []struct{}{}})
		return
	}
	writeJSON(w, cfg)
}

// GET /admin/policy/versions — API-uploaded policy revision history
func (h *Handler) handlePolicyVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.Lock()
	out := make([]policyVersion, len(h.versions))
	copy(out, h.versions)
	h.mu.Unlock()
	writeJSON(w, map[string]interface{}{
		"count":    len(out),
		"versions": out,
	})
}

// POST /admin/policy/rollback — revert to the previous API-uploaded revision
func (h *Handler) handlePolicyRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.Lock()
	if len(h.versions) < 2 {
		h.mu.Unlock()
		http.Error(w, `{"error":"no previous version to roll back to"}`, http.StatusConflict)
		return
	}
	// Drop the current version; the previous one becomes active.
	h.versions = h.versions[:len(h.versions)-1]
	target := h.versions[len(h.versions)-1]
	h.mu.Unlock()

	cfg, err := policy.LoadFromBytes([]byte(target.YAML))
	if err != nil {
		http.Error(w, `{"error":"stored version no longer parses: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	h.engine.Reload(cfg)
	writeJSON(w, map[string]interface{}{
		"status":      "rolled back",
		"uploaded_at": target.UploadedAt,
		"summary":     h.engine.Summary(),
	})
}

// POST /admin/reload — re-read policy + tenant config from disk (same as SIGHUP)
func (h *Handler) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.reloadFunc == nil {
		http.Error(w, `{"error":"reload not configured"}`, http.StatusNotImplemented)
		return
	}
	if err := h.reloadFunc(); err != nil {
		http.Error(w, `{"error":"reload failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"status":  "reloaded",
		"tenants": h.registry.List(),
		"summary": h.engine.Summary(),
	})
}

// GET /admin/tenants — list registered tenants
func (h *Handler) handleTenants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ids := h.registry.List()
	writeJSON(w, map[string]interface{}{
		"tenants": ids,
		"count":   len(ids),
	})
}

// GET /admin/policy/summary — current policy summary
func (h *Handler) handlePolicySummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{
		"summary": h.engine.Summary(),
	})
}

// POST /admin/policy/reload — reload policy from uploaded YAML body
func (h *Handler) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	cfg, err := policy.LoadFromBytes([]byte(body.YAML))
	if err != nil {
		http.Error(w, "invalid policy YAML: "+err.Error(), http.StatusBadRequest)
		return
	}
	h.engine.Reload(cfg)

	// Record the revision for rollback.
	h.mu.Lock()
	h.versions = append(h.versions, policyVersion{
		YAML:       body.YAML,
		UploadedAt: time.Now(),
		Summary:    fmt.Sprintf("policies=%d realm=%s", len(cfg.Policies), cfg.Realm),
	})
	if len(h.versions) > maxPolicyVersions {
		h.versions = h.versions[len(h.versions)-maxPolicyVersions:]
	}
	h.mu.Unlock()

	writeJSON(w, map[string]interface{}{
		"status":  "reloaded",
		"summary": h.engine.Summary(),
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
