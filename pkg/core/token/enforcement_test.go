package token

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
)

func TestAudience_UnmarshalStringOrArray(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`"single"`, []string{"single"}},
		{`["a","b"]`, []string{"a", "b"}},
		{`""`, nil},
		{`null`, nil},
	}
	for _, c := range cases {
		var got Audience
		if err := json.Unmarshal([]byte(c.in), &got); err != nil {
			t.Fatalf("Unmarshal(%s): %v", c.in, err)
		}
		if len(got) != len(c.want) {
			t.Errorf("Unmarshal(%s) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("Unmarshal(%s)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestJWTValidator_EnforcesIssuer(t *testing.T) {
	factory, _ := tokenfactory.New()
	jwksSrv := startJWKSServer(t, factory)

	tok, _ := factory.Generate(tokenfactory.TokenOptions{
		Subject: "u", Issuer: "https://good.example", ExpiresIn: time.Hour,
	})

	v := NewJWTValidator(JWTValidatorConfig{JWKSURL: jwksSrv.URL, ExpectedIssuer: "https://evil.example"})
	if _, err := v.Validate(context.Background(), tok); err == nil {
		t.Fatal("expected rejection when issuer does not match ExpectedIssuer")
	}

	v2 := NewJWTValidator(JWTValidatorConfig{JWKSURL: jwksSrv.URL, ExpectedIssuer: "https://good.example"})
	if _, err := v2.Validate(context.Background(), tok); err != nil {
		t.Fatalf("expected acceptance for matching issuer, got: %v", err)
	}
}

func TestJWTValidator_EnforcesAudience(t *testing.T) {
	factory, _ := tokenfactory.New()
	jwksSrv := startJWKSServer(t, factory)

	tok, _ := factory.Generate(tokenfactory.TokenOptions{
		Subject: "u", Audience: []string{"api://orders"}, ExpiresIn: time.Hour,
	})

	v := NewJWTValidator(JWTValidatorConfig{JWKSURL: jwksSrv.URL, ExpectedAudience: "api://payments"})
	if _, err := v.Validate(context.Background(), tok); err == nil {
		t.Fatal("expected rejection when audience does not match")
	}

	v2 := NewJWTValidator(JWTValidatorConfig{JWKSURL: jwksSrv.URL, ExpectedAudience: "api://orders"})
	if _, err := v2.Validate(context.Background(), tok); err != nil {
		t.Fatalf("expected acceptance for matching audience, got: %v", err)
	}
}
