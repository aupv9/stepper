package main

import "testing"

func TestLoadConfig_Defaults(t *testing.T) {
	// Ensure a clean environment for the keys we care about.
	for _, k := range []string{
		"IAM_ADDR", "IAM_REALM", "IAM_POLICY_FILE", "IAM_UPSTREAM_URL",
		"IAM_OIDC_DISCOVERY_URL", "IAM_LOG_FORMAT", "IAM_ENABLE_DPOP",
	} {
		t.Setenv(k, "")
	}

	cfg := LoadConfig()
	if cfg.Addr != ":8080" {
		t.Errorf("Addr default = %q, want :8080", cfg.Addr)
	}
	if cfg.Realm != "IAM" {
		t.Errorf("Realm default = %q, want IAM", cfg.Realm)
	}
	if cfg.PolicyFile != "config/policy.example.yaml" {
		t.Errorf("PolicyFile default = %q", cfg.PolicyFile)
	}
	if cfg.EnableDPoP {
		t.Error("EnableDPoP should default to false")
	}
	if !cfg.DevMode() {
		t.Error("DevMode should be true when IAM_OIDC_DISCOVERY_URL is unset")
	}
}

func TestLoadConfig_FromEnv(t *testing.T) {
	t.Setenv("IAM_ADDR", ":9090")
	t.Setenv("IAM_REALM", "MyApp")
	t.Setenv("IAM_OIDC_DISCOVERY_URL", "https://as.example.com/.well-known/openid-configuration")
	t.Setenv("IAM_ENABLE_DPOP", "true")

	cfg := LoadConfig()
	if cfg.Addr != ":9090" {
		t.Errorf("Addr = %q, want :9090", cfg.Addr)
	}
	if cfg.Realm != "MyApp" {
		t.Errorf("Realm = %q, want MyApp", cfg.Realm)
	}
	if !cfg.EnableDPoP {
		t.Error("EnableDPoP should be true")
	}
	if cfg.DevMode() {
		t.Error("DevMode should be false when a discovery URL is set")
	}
}
