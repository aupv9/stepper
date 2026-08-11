// Command iam-service is the standalone IAM gateway: a reverse proxy that
// centralizes RFC 9470 step-up authentication, RFC 7662 introspection, policy
// evaluation, and multi-tenant provider dispatch in front of a backend.
//
// With no external Authorization Server configured (IAM_OIDC_DISCOVERY_URL
// unset) it boots an in-process LocalAS and prints a demo token, so it runs
// with zero external dependencies for local development.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/common-iam/iam/internal/admin"
	"github.com/common-iam/iam/internal/gateway"
	"github.com/common-iam/iam/internal/server"
	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/devkit/localas"
	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
	"github.com/common-iam/iam/pkg/providers"
	"github.com/common-iam/iam/pkg/providers/generic"
	"github.com/common-iam/iam/pkg/telemetry"
	"github.com/common-iam/iam/pkg/tenant"
)

func main() {
	cfg := LoadConfig()
	logger := telemetry.NewLogger(cfg.LogFormat, slog.LevelInfo)

	if err := run(cfg, logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(cfg Config, logger *slog.Logger) error {
	ctx := context.Background()

	// 1. Policy engine.
	policyCfg, err := policy.LoadFromFile(cfg.PolicyFile)
	if err != nil {
		return err
	}
	engine := policy.New(policyCfg)
	logger.Info("policy loaded", "file", cfg.PolicyFile, "policies", len(policyCfg.Policies))

	// 2. Tenant registry + provider. In dev mode we spin up a LocalAS so the
	// gateway has a working Authorization Server with no external dependency.
	registry := tenant.NewRegistry()
	var as *localas.Server
	if cfg.DevMode() {
		as, err = localas.New()
		if err != nil {
			return err
		}
		asURL, startErr := as.Start()
		if startErr != nil {
			return startErr
		}
		defer as.Stop(context.Background()) //nolint:errcheck

		provider := generic.New(generic.Config{DiscoveryURL: asURL + "/.well-known/openid-configuration"})
		if rerr := provider.RefreshConfig(ctx); rerr != nil {
			return rerr
		}
		registry.Register("default", provider)
		logger.Info("LocalAS running (dev mode)", "url", asURL)
		printDemoToken(as, logger)
	} else {
		provider := generic.New(generic.Config{
			DiscoveryURL: cfg.OIDCDiscoveryURL,
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
		})
		if rerr := provider.RefreshConfig(ctx); rerr != nil {
			return rerr
		}
		registry.Register("default", provider)
		logger.Info("provider configured", "issuer", providerIssuer(provider))
	}

	// 3. Tenant resolver: X-Tenant-ID header when present, otherwise the guard
	// falls back to the "default" tenant. (Subdomain/path resolvers are opt-in
	// for multi-tenant routing; enabling PathResolver here would mis-read the
	// first path segment of every request as a tenant id.)
	resolver := tenant.NewChainResolver(
		tenant.NewHeaderResolver("X-Tenant-ID"),
	)

	// 4. Telemetry.
	metrics := telemetry.NewMetrics(prometheus.DefaultRegisterer)
	audit := telemetry.NewAuditLogger(logger)

	// 5. Upstream: reverse proxy when configured, otherwise an echo handler.
	upstream, err := buildUpstream(cfg, logger)
	if err != nil {
		return err
	}

	// 6. Guard (optional per-IP rate limiter).
	var limiter gateway.RateLimiter
	if cfg.RateLimitPerSec > 0 {
		limiter = gateway.NewTokenBucketLimiter(cfg.RateLimitPerSec, cfg.RateBurst)
		logger.Info("rate limiting enabled", "per_sec", cfg.RateLimitPerSec, "burst", cfg.RateBurst)
	}
	guard := gateway.NewGuard(gateway.GuardConfig{
		Registry:      registry,
		Resolver:      resolver,
		PolicyEngine:  engine,
		Realm:         cfg.Realm,
		Audit:         audit,
		Metrics:       metrics,
		Upstream:      upstream,
		Cache:         token.NewMemoryCache(),
		EnableDPoP:    cfg.EnableDPoP,
		WebhookSecret: cfg.WebhookSecret,
		CookieSecret:  cfg.CookieSecret,
		// Single-tenant standalone: fall back to "default" when no tenant header
		// is present. Multi-tenant deployments should leave this empty (fail closed).
		DefaultTenant: "default",
		RateLimiter:   limiter,
	})

	// 7. Admin API + router + server.
	adminHandler := admin.New(admin.Config{Registry: registry, Engine: engine, AdminToken: cfg.AdminToken})
	router := server.NewRouter(server.RouterConfig{Gateway: guard, AdminHandler: adminHandler})
	srvCfg := server.DefaultConfig()
	srvCfg.Addr = cfg.Addr
	srv := server.New(router, srvCfg)

	// 8. Serve with graceful shutdown on SIGINT/SIGTERM.
	errCh := make(chan error, 1)
	go func() {
		logger.Info("ready", "addr", cfg.Addr, "upstream", upstreamDesc(cfg))
		if serveErr := srv.Start(); serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- serveErr
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case serveErr := <-errCh:
		return serveErr
	case sig := <-stop:
		logger.Info("shutting down", "signal", sig.String())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// buildUpstream returns the reverse proxy to the configured backend, or an echo
// handler that reflects request metadata when no upstream is set.
func buildUpstream(cfg Config, logger *slog.Logger) (http.Handler, error) {
	if cfg.UpstreamURL == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","echo":{"method":"` + r.Method + `","path":"` + r.URL.Path + `"}}`))
		}), nil
	}
	proxy, err := gateway.NewReverseProxy(cfg.UpstreamURL)
	if err != nil {
		return nil, err
	}
	logger.Info("reverse proxy configured", "upstream", cfg.UpstreamURL)
	return proxy, nil
}

func upstreamDesc(cfg Config) string {
	if cfg.UpstreamURL == "" {
		return "echo"
	}
	return cfg.UpstreamURL
}

func providerIssuer(p providers.Provider) string { return p.Issuer() }

// printDemoToken issues a bronze demo token from the dev LocalAS so a developer
// can immediately exercise the gateway.
func printDemoToken(as *localas.Server, logger *slog.Logger) {
	tok, err := as.IssueToken(tokenfactory.TokenOptions{
		Subject:   "demo-user",
		ACR:       "urn:mace:incommon:iap:bronze",
		Scopes:    []string{"openid", "profile"},
		ExpiresIn: time.Hour,
	})
	if err != nil {
		logger.Warn("could not issue demo token", "error", err)
		return
	}
	logger.Info("demo token ready", "token", tok)
}
