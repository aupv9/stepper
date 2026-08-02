package main

import (
	"os"
	"strconv"
)

// Config is the gateway's runtime configuration, populated from environment
// variables. See docs/production-readiness.md and CLAUDE.md for the full table.
type Config struct {
	Addr             string
	Realm            string
	PolicyFile       string
	UpstreamURL      string // empty = echo mode
	OIDCDiscoveryURL string // empty = LocalAS dev mode
	OIDCClientID     string
	OIDCClientSecret string
	LogFormat        string // "text" | "json"
	CookieSecret     string // empty = no step-up replay
	WebhookSecret    string // empty = unauthenticated revocation webhook (dev)
	AdminToken       string // empty = unauthenticated /admin (dev)
	EnableDPoP       bool
}

// LoadConfig reads configuration from IAM_* environment variables, applying
// sensible defaults for anything unset.
func LoadConfig() Config {
	return Config{
		Addr:             env("IAM_ADDR", ":8080"),
		Realm:            env("IAM_REALM", "IAM"),
		PolicyFile:       env("IAM_POLICY_FILE", "config/policy.example.yaml"),
		UpstreamURL:      env("IAM_UPSTREAM_URL", ""),
		OIDCDiscoveryURL: env("IAM_OIDC_DISCOVERY_URL", ""),
		OIDCClientID:     env("IAM_OIDC_CLIENT_ID", ""),
		OIDCClientSecret: env("IAM_OIDC_CLIENT_SECRET", ""),
		LogFormat:        env("IAM_LOG_FORMAT", "text"),
		CookieSecret:     env("IAM_COOKIE_SECRET", ""),
		WebhookSecret:    env("IAM_WEBHOOK_SECRET", ""),
		AdminToken:       env("IAM_ADMIN_TOKEN", ""),
		EnableDPoP:       envBool("IAM_ENABLE_DPOP", false),
	}
}

// DevMode reports whether the service should start its own in-process LocalAS
// (no external Authorization Server configured).
func (c Config) DevMode() bool {
	return c.OIDCDiscoveryURL == ""
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
