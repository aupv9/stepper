// Package config loads the iam-service configuration from an optional YAML
// file (IAM_CONFIG_FILE) overlaid with environment variables. Environment
// variables always win, so existing env-only deployments keep working.
package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// File is the root iam.yaml schema.
type File struct {
	Addr          string `yaml:"addr"`
	Realm         string `yaml:"realm"`
	PolicyFile    string `yaml:"policy_file"`
	UpstreamURL   string `yaml:"upstream_url"`
	LogFormat     string `yaml:"log_format"`
	DefaultTenant string `yaml:"default_tenant"`
	AdminToken    string `yaml:"admin_token"`
	WebhookSecret string `yaml:"webhook_secret"`
	CookieSecret  string `yaml:"cookie_secret"`
	EnableFAPI    bool   `yaml:"enable_fapi"`

	// EnableTokenExchange serves RFC 8693 token exchange on /token/exchange,
	// brokered to each tenant's token endpoint. Callers need scope
	// "token:exchange".
	EnableTokenExchange bool `yaml:"enable_token_exchange"`

	TLS       TLS       `yaml:"tls"`
	Redis     Redis     `yaml:"redis"`
	RateLimit RateLimit `yaml:"rate_limit"`
	DPoP      DPoP      `yaml:"dpop"`

	// Tenants declares the providers to register. Empty + no IAM_OIDC_* env
	// means LocalAS dev mode.
	Tenants []Tenant `yaml:"tenants"`

	// Resolvers declares the tenant resolution chain, tried in order.
	// Empty means: header X-Tenant-ID, then static default_tenant.
	Resolvers []Resolver `yaml:"resolvers"`
}

// TLS enables HTTPS termination and optional mTLS.
type TLS struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientCAFile string `yaml:"client_ca_file"`
}

// Redis enables the shared distributed cache (token cache, DPoP replay,
// revocation index, distributed rate limiting).
type Redis struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// RateLimit configures the per-client-IP limiter.
type RateLimit struct {
	RPS   float64 `yaml:"rps"`
	Burst int     `yaml:"burst"`
}

// DPoP configures RFC 9449 enforcement.
type DPoP struct {
	Enabled     bool   `yaml:"enabled"`
	NonceSecret string `yaml:"nonce_secret"`
}

// Tenant declares one tenant → provider mapping.
type Tenant struct {
	ID       string `yaml:"id"`
	Provider string `yaml:"provider"` // generic | keycloak | auth0

	// Validation selects how access tokens are checked:
	//   "introspection" (default) — RFC 7662 round-trip to the AS
	//   "jwt" — local JWS validation against the provider's JWKS; opaque
	//   tokens still fall back to introspection. Faster, but AS-side
	//   revocation is invisible until the token expires.
	Validation string `yaml:"validation"`

	// generic
	DiscoveryURL string `yaml:"discovery_url"`

	// keycloak
	BaseURL string `yaml:"base_url"`
	Realm   string `yaml:"realm"`

	// auth0
	Domain   string `yaml:"domain"`
	Audience string `yaml:"audience"`

	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// Resolver declares one element of the tenant resolution chain.
type Resolver struct {
	Type       string `yaml:"type"` // header | subdomain | path | static
	Header     string `yaml:"header"`
	BaseDomain string `yaml:"base_domain"`
	Segment    int    `yaml:"segment"`
	Tenant     string `yaml:"tenant"`
}

// Default returns the built-in defaults (matches the pre-config-file behavior).
func Default() *File {
	return &File{
		Addr:          ":8080",
		Realm:         "IAM",
		PolicyFile:    "config/policy.example.yaml",
		LogFormat:     "text",
		DefaultTenant: "default",
	}
}

// Load builds the effective configuration: defaults ← YAML file (optional)
// ← environment variables. path may be empty (no file).
func Load(path string) (*File, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file %s: %w", path, err)
		}
	}

	cfg.applyEnv()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// applyEnv overlays IAM_* environment variables (env wins over file).
func (f *File) applyEnv() {
	setStr(&f.Addr, "IAM_ADDR")
	setStr(&f.Realm, "IAM_REALM")
	setStr(&f.PolicyFile, "IAM_POLICY_FILE")
	setStr(&f.UpstreamURL, "IAM_UPSTREAM_URL")
	setStr(&f.LogFormat, "IAM_LOG_FORMAT")
	setStr(&f.DefaultTenant, "IAM_DEFAULT_TENANT")
	setStr(&f.AdminToken, "IAM_ADMIN_TOKEN")
	setStr(&f.WebhookSecret, "IAM_WEBHOOK_SECRET")
	setStr(&f.CookieSecret, "IAM_COOKIE_SECRET")
	setBool(&f.EnableFAPI, "IAM_ENABLE_FAPI")
	setBool(&f.EnableTokenExchange, "IAM_ENABLE_TOKEN_EXCHANGE")

	setStr(&f.TLS.CertFile, "IAM_TLS_CERT_FILE")
	setStr(&f.TLS.KeyFile, "IAM_TLS_KEY_FILE")
	setStr(&f.TLS.ClientCAFile, "IAM_TLS_CLIENT_CA")

	setStr(&f.Redis.Addr, "IAM_REDIS_ADDR")
	setStr(&f.Redis.Password, "IAM_REDIS_PASSWORD")

	setFloat(&f.RateLimit.RPS, "IAM_RATE_LIMIT_RPS")
	setInt(&f.RateLimit.Burst, "IAM_RATE_LIMIT_BURST")

	setBool(&f.DPoP.Enabled, "IAM_ENABLE_DPOP")
	setStr(&f.DPoP.NonceSecret, "IAM_DPOP_NONCE_SECRET")

	// IAM_OIDC_* declares (or overrides) the default tenant's provider,
	// preserving the original single-tenant env interface.
	if disc := os.Getenv("IAM_OIDC_DISCOVERY_URL"); disc != "" {
		t := Tenant{
			ID:           f.DefaultTenant,
			Provider:     "generic",
			DiscoveryURL: disc,
			ClientID:     os.Getenv("IAM_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("IAM_OIDC_CLIENT_SECRET"),
		}
		replaced := false
		for i := range f.Tenants {
			if f.Tenants[i].ID == t.ID {
				f.Tenants[i] = t
				replaced = true
				break
			}
		}
		if !replaced {
			f.Tenants = append(f.Tenants, t)
		}
	}
}

// Validate checks structural correctness before any network wiring happens.
func (f *File) Validate() error {
	seen := make(map[string]bool, len(f.Tenants))
	for i, t := range f.Tenants {
		if t.ID == "" {
			return fmt.Errorf("tenants[%d]: id is required", i)
		}
		if seen[t.ID] {
			return fmt.Errorf("tenants[%d]: duplicate tenant id %q", i, t.ID)
		}
		seen[t.ID] = true

		switch t.Provider {
		case "generic", "":
			if t.DiscoveryURL == "" {
				return fmt.Errorf("tenant %q: discovery_url is required for the generic provider", t.ID)
			}
		case "keycloak":
			if t.BaseURL == "" || t.Realm == "" {
				return fmt.Errorf("tenant %q: base_url and realm are required for the keycloak provider", t.ID)
			}
		case "auth0":
			if t.Domain == "" {
				return fmt.Errorf("tenant %q: domain is required for the auth0 provider", t.ID)
			}
		default:
			return fmt.Errorf("tenant %q: unknown provider %q (want generic, keycloak, or auth0)", t.ID, t.Provider)
		}

		switch t.Validation {
		case "", "introspection", "jwt":
		default:
			return fmt.Errorf("tenant %q: unknown validation mode %q (want introspection or jwt)", t.ID, t.Validation)
		}
	}

	for i, r := range f.Resolvers {
		switch r.Type {
		case "header", "subdomain", "path":
			// header/base_domain/segment all have sensible zero-value defaults
		case "static":
			if r.Tenant == "" {
				return fmt.Errorf("resolvers[%d]: static resolver requires tenant", i)
			}
		default:
			return fmt.Errorf("resolvers[%d]: unknown type %q (want header, subdomain, path, or static)", i, r.Type)
		}
	}

	if (f.TLS.CertFile == "") != (f.TLS.KeyFile == "") {
		return fmt.Errorf("tls: cert_file and key_file must be set together")
	}
	if f.TLS.ClientCAFile != "" && f.TLS.CertFile == "" {
		return fmt.Errorf("tls: client_ca_file requires cert_file and key_file")
	}

	if f.RateLimit.RPS < 0 {
		return fmt.Errorf("rate_limit: rps must be >= 0")
	}
	return nil
}

func setStr(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

func setBool(dst *bool, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v == "true" || v == "1"
	}
}

func setFloat(dst *float64, key string) {
	if v := os.Getenv(key); v != "" {
		if x, err := strconv.ParseFloat(v, 64); err == nil {
			*dst = x
		}
	}
}

func setInt(dst *int, key string) {
	if v := os.Getenv(key); v != "" {
		if x, err := strconv.Atoi(v); err == nil {
			*dst = x
		}
	}
}
