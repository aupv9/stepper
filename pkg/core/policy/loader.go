package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFromFile reads and parses a policy YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file %s: %w", path, err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses policy YAML from raw bytes.
func LoadFromBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid policy config: %w", err)
	}
	return &cfg, nil
}

// validate performs basic sanity checks on the loaded config.
func validate(cfg *Config) error {
	for i, p := range cfg.Policies {
		if len(p.Resources) == 0 {
			return fmt.Errorf("policy[%d] %q: resources must not be empty", i, p.Name)
		}
	}
	return nil
}
