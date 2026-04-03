package server

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Server wraps an HTTP server with graceful shutdown.
type Server struct {
	httpSrv *http.Server
	addr    string
}

// Config holds server configuration.
type Config struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
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
func New(handler http.Handler, cfg Config) *Server {
	return &Server{
		addr: cfg.Addr,
		httpSrv: &http.Server{
			Addr:         cfg.Addr,
			Handler:      handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},
	}
}

// Start begins listening and serving. Blocks until error.
func (s *Server) Start() error {
	fmt.Printf("IAM service listening on %s\n", s.addr)
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}
