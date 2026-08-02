// Command iam-cli is a developer tool for the common-iam stack. It can dry-run
// policy decisions, mint signed test JWTs, and introspect tokens against an AS.
//
// Usage:
//
//	iam-cli policy-check <path> <method> <acr> [--policy FILE] [--scopes a,b]
//	iam-cli token issue [--sub S] [--acr A] [--scopes a,b] [--ttl 1h]
//	iam-cli introspect <token> --endpoint URL [--client-id ID] [--client-secret S]
//	iam-cli version
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/devkit/simulator"
	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "policy-check":
		err = cmdPolicyCheck(args)
	case "token":
		err = cmdToken(args)
	case "introspect":
		err = cmdIntrospect(args)
	case "version", "-v", "--version":
		fmt.Printf("iam-cli %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `iam-cli — developer tool for common-iam

Commands:
  policy-check <path> <method> <acr>   Dry-run a request through the policy engine
      --policy FILE    policy YAML (default: config/policy.example.yaml)
      --scopes a,b     token scopes
      --amr a,b        authentication methods (e.g. pwd,otp)
      --auth-age DUR   how long ago the user authenticated (e.g. 30s)

  token issue                          Mint a signed test JWT
      --sub S          subject (default: test-user)
      --acr A          acr value
      --scopes a,b     scopes
      --sid S          session id
      --ttl DUR        lifetime (default: 1h)

  introspect <token>                   Introspect a token against an AS (RFC 7662)
      --endpoint URL   introspection endpoint (required)
      --client-id ID
      --client-secret S

  version                              Print version
`)
}

func cmdPolicyCheck(args []string) error {
	// Positional args come first (path method acr); Go's flag package stops at
	// the first non-flag, so pull them off the front before parsing flags.
	if len(args) < 3 {
		return fmt.Errorf("usage: policy-check <path> <method> <acr> [flags]")
	}
	path, method, acr := args[0], args[1], args[2]

	fs := flag.NewFlagSet("policy-check", flag.ExitOnError)
	policyFile := fs.String("policy", "config/policy.example.yaml", "policy YAML file")
	scopes := fs.String("scopes", "", "comma-separated token scopes")
	amr := fs.String("amr", "", "comma-separated authentication methods")
	authAge := fs.Duration("auth-age", 0, "how long ago the user authenticated")
	_ = fs.Parse(args[3:])

	cfg, err := policy.LoadFromFile(*policyFile)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}
	sim := simulator.New(policy.New(cfg))

	res, err := sim.Simulate(simulator.Request{
		Method:      method,
		Path:        path,
		ACR:         acr,
		AMR:         splitCSV(*amr),
		Scopes:      splitCSV(*scopes),
		AuthAge:     *authAge,
		HasAuthTime: *authAge > 0,
	})
	if err != nil {
		return err
	}

	decision := "DENY"
	if res.Allowed {
		decision = "ALLOW"
	}
	fmt.Printf("%s  %s %s (acr=%s)\n", decision, method, path, acr)
	if res.PolicyName != "" {
		fmt.Printf("  policy:   %s\n", res.PolicyName)
	}
	if !res.Allowed {
		fmt.Printf("  reason:   %s\n", res.Reason)
		if res.RequiredACR != "" {
			fmt.Printf("  required: acr=%s max_age=%ds\n", res.RequiredACR, res.RequiredMaxAge)
		}
	}
	if !res.Allowed {
		os.Exit(1)
	}
	return nil
}

func cmdToken(args []string) error {
	if len(args) < 1 || args[0] != "issue" {
		return fmt.Errorf("usage: token issue [flags]")
	}
	fs := flag.NewFlagSet("token issue", flag.ExitOnError)
	sub := fs.String("sub", "test-user", "subject")
	acr := fs.String("acr", "", "acr value")
	scopes := fs.String("scopes", "", "comma-separated scopes")
	sid := fs.String("sid", "", "session id")
	ttl := fs.Duration("ttl", time.Hour, "token lifetime")
	_ = fs.Parse(args[1:])

	factory, err := tokenfactory.New()
	if err != nil {
		return fmt.Errorf("creating token factory: %w", err)
	}
	tok, err := factory.Generate(tokenfactory.TokenOptions{
		Subject:   *sub,
		ACR:       *acr,
		Scopes:    splitCSV(*scopes),
		SessionID: *sid,
		ExpiresIn: *ttl,
	})
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func cmdIntrospect(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: introspect <token> --endpoint URL")
	}
	tok := args[0]

	fs := flag.NewFlagSet("introspect", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "introspection endpoint URL (required)")
	clientID := fs.String("client-id", "", "client id")
	clientSecret := fs.String("client-secret", "", "client secret")
	_ = fs.Parse(args[1:])

	if *endpoint == "" {
		return fmt.Errorf("--endpoint is required")
	}

	intro := token.NewIntrospector(token.IntrospectorConfig{
		Endpoint:     *endpoint,
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
	})
	claims, err := intro.Introspect(context.Background(), tok)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Println(string(out))
	if !claims.Active {
		os.Exit(1)
	}
	return nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
