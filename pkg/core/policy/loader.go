package policy

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

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
		switch p.Effect {
		case "", "allow", "deny":
		default:
			return fmt.Errorf("policy[%d] %q: unknown effect %q (want allow or deny)", i, p.Name, p.Effect)
		}
		if p.When != nil {
			for _, entry := range p.When.IPCIDR {
				if strings.Contains(entry, "/") {
					if _, _, err := net.ParseCIDR(entry); err != nil {
						return fmt.Errorf("policy[%d] %q: invalid CIDR %q", i, p.Name, entry)
					}
				} else if net.ParseIP(entry) == nil {
					return fmt.Errorf("policy[%d] %q: invalid IP %q", i, p.Name, entry)
				}
			}
			if w := p.When.TimeWindow; w != nil {
				if _, err := time.Parse("15:04", w.Start); err != nil {
					return fmt.Errorf("policy[%d] %q: invalid time_window start %q", i, p.Name, w.Start)
				}
				if _, err := time.Parse("15:04", w.End); err != nil {
					return fmt.Errorf("policy[%d] %q: invalid time_window end %q", i, p.Name, w.End)
				}
				if w.TZ != "" {
					if _, err := time.LoadLocation(w.TZ); err != nil {
						return fmt.Errorf("policy[%d] %q: unknown time zone %q", i, p.Name, w.TZ)
					}
				}
			}
		}
	}
	return nil
}
