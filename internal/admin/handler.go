package admin

import (
	"encoding/json"
	"net/http"
	"strings"

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
}

// Handler provides the Admin REST API for managing policies and tenants at runtime.
type Handler struct {
	registry   *tenant.Registry
	engine     *policy.Engine
	adminToken string
	mux        *http.ServeMux
}

// New creates an Admin API handler.
func New(cfg Config) *Handler {
	h := &Handler{
		registry:   cfg.Registry,
		engine:     cfg.Engine,
		adminToken: cfg.AdminToken,
		mux:        http.NewServeMux(),
	}
	h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	return ok && token == h.adminToken
}

func (h *Handler) routes() {
	h.mux.HandleFunc("/tenants", h.handleTenants)
	h.mux.HandleFunc("/policy/summary", h.handlePolicySummary)
	h.mux.HandleFunc("/policy/reload", h.handlePolicyReload)
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
	writeJSON(w, map[string]interface{}{
		"status":  "reloaded",
		"summary": h.engine.Summary(),
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
