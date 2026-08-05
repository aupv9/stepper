package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/common-iam/iam/internal/admin"
	"github.com/common-iam/iam/internal/gateway"
)

// RouterConfig holds dependencies for route setup.
type RouterConfig struct {
	Gateway      *gateway.Guard
	AdminHandler *admin.Handler

	// ReadyCheck, when set, backs /health/ready: it should verify external
	// dependencies (AS discovery loaded, Redis reachable) and return an error
	// when the instance must not receive traffic yet.
	ReadyCheck func(ctx context.Context) error
}

// NewRouter builds and returns the main HTTP router.
func NewRouter(cfg RouterConfig) http.Handler {
	mux := http.NewServeMux()

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Liveness: the process is up. /health kept as an alias for backward compat.
	live := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck
	}
	mux.HandleFunc("/health", live)
	mux.HandleFunc("/health/live", live)

	// Readiness: external dependencies are reachable.
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg.ReadyCheck != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			if err := cfg.ReadyCheck(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"status": "not ready",
					"error":  err.Error(),
				})
				return
			}
		}
		w.Write([]byte(`{"status":"ready"}`)) //nolint:errcheck
	})

	// Admin API
	if cfg.AdminHandler != nil {
		mux.Handle("/admin/", http.StripPrefix("/admin", cfg.AdminHandler))
	}

	// Token revocation webhook
	mux.Handle("/webhook/revoke", cfg.Gateway.RevocationHandler())

	// All other traffic goes through the auth gateway
	mux.Handle("/", cfg.Gateway)

	return mux
}
