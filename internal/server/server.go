package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Server wraps an HTTP server with graceful shutdown and optional TLS.
type Server struct {
	httpSrv  *http.Server
	addr     string
	certFile string
	keyFile  string
}

// Config holds server configuration.
type Config struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// CertFile/KeyFile enable TLS termination when both are set.
	CertFile string
	KeyFile  string

	// ClientCAFile, when set (requires TLS), enables optional mTLS: client
	// certificates are verified against this CA when presented. Presenting a
	// cert stays optional so bearer-only clients keep working; RFC 8705
	// certificate-bound tokens build on top of this.
	ClientCAFile string
}

// DefaultConfig returns sensible server defaults.
func DefaultConfig() Config {
	return Config{
		Addr:         ":8080",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// New creates a Server with the given handler and config.
func New(handler http.Handler, cfg Config) (*Server, error) {
	srv := &Server{
		addr:     cfg.Addr,
		certFile: cfg.CertFile,
		keyFile:  cfg.KeyFile,
		httpSrv: &http.Server{
			Addr:         cfg.Addr,
			Handler:      handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},
	}

	if cfg.ClientCAFile != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, fmt.Errorf("client_ca_file requires cert_file and key_file")
		}
		caPEM, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading client CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certificates in client CA file %s", cfg.ClientCAFile)
		}
		srv.httpSrv.TLSConfig = &tls.Config{
			ClientCAs:  pool,
			ClientAuth: tls.VerifyClientCertIfGiven,
			MinVersion: tls.VersionTLS12,
		}
	} else if cfg.CertFile != "" {
		srv.httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	return srv, nil
}

// TLSEnabled reports whether the server terminates TLS itself.
func (s *Server) TLSEnabled() bool {
	return s.certFile != "" && s.keyFile != ""
}

// Start begins listening and serving. Blocks until error.
func (s *Server) Start() error {
	if s.TLSEnabled() {
		fmt.Printf("IAM service listening on %s (TLS)\n", s.addr)
		return s.httpSrv.ListenAndServeTLS(s.certFile, s.keyFile)
	}
	fmt.Printf("IAM service listening on %s\n", s.addr)
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}
