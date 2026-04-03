package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/common-iam/iam/internal/admin"
	"github.com/common-iam/iam/internal/gateway"
)

// RouterConfig holds dependencies for route setup.
type RouterConfig struct {
	Gateway     *gateway.Guard
	AdminHandler *admin.Handler
}

// NewRouter builds and returns the main HTTP router.
func NewRouter(cfg RouterConfig) http.Handler {
	mux := http.NewServeMux()

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Health / readiness probes
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck
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
