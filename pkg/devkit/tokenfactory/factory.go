package tokenfactory

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenOptions configures the JWT to generate.
type TokenOptions struct {
	Subject   string
	Issuer    string
	Audience  []string
	ExpiresIn time.Duration
	ACR       string
	AMR       []string
	Scopes    []string
	Roles     []string
	TenantID  string
	SessionID string
	AuthTime  time.Time
	Extra     map[string]interface{}
}

// Factory generates signed JWTs for testing and development.
type Factory struct {
	privateKey *rsa.PrivateKey
	keyID      string
}

// New creates a Factory with a fresh RSA-2048 key pair.
func New() (*Factory, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}
	return &Factory{privateKey: key, keyID: "devkit-key-1"}, nil
}

// NewWithKey creates a Factory with a provided RSA private key.
func NewWithKey(key *rsa.PrivateKey, keyID string) *Factory {
	return &Factory{privateKey: key, keyID: keyID}
}

// Generate creates a signed JWT with the given options.
func (f *Factory) Generate(opts TokenOptions) (string, error) {
	if opts.ExpiresIn == 0 {
		opts.ExpiresIn = time.Hour
	}
	if opts.Issuer == "" {
		opts.Issuer = "http://localhost:8080/devkit"
	}
	if opts.AuthTime.IsZero() {
		opts.AuthTime = time.Now()
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       opts.Subject,
		"iss":       opts.Issuer,
		"iat":       now.Unix(),
		"exp":       now.Add(opts.ExpiresIn).Unix(),
		"auth_time": opts.AuthTime.Unix(),
		"active":    true,
	}

	if len(opts.Audience) > 0 {
		claims["aud"] = opts.Audience
	}
	if opts.ACR != "" {
		claims["acr"] = opts.ACR
	}
	if len(opts.AMR) > 0 {
		claims["amr"] = opts.AMR
	}
	if len(opts.Scopes) > 0 {
		scope := ""
		for i, s := range opts.Scopes {
			if i > 0 {
				scope += " "
			}
			scope += s
		}
		claims["scope"] = scope
	}
	if len(opts.Roles) > 0 {
		claims["realm_access"] = map[string]interface{}{"roles": opts.Roles}
	}
	if opts.TenantID != "" {
		claims["tenant_id"] = opts.TenantID
	}
	if opts.SessionID != "" {
		claims["sid"] = opts.SessionID
	}
	for k, v := range opts.Extra {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = f.keyID

	return token.SignedString(f.privateKey)
}

// PublicKeyJSON returns the RSA public key as a JSON Web Key (JWK).
func (f *Factory) PublicKeyJSON() ([]byte, error) {
	pub := &f.privateKey.PublicKey
	n := pub.N.Bytes()
	e := make([]byte, 4)
	e[3] = byte(pub.E)
	e[2] = byte(pub.E >> 8)
	e[1] = byte(pub.E >> 16)
	e[0] = byte(pub.E >> 24)

	// Trim leading zeros from e
	for len(e) > 1 && e[0] == 0 {
		e = e[1:]
	}

	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": f.keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   encodeBase64URL(n),
		"e":   encodeBase64URL(e),
	}
	return json.Marshal(jwk)
}

// JWKS returns a JWKS document containing the public key.
func (f *Factory) JWKS() ([]byte, error) {
	key, err := f.PublicKeyJSON()
	if err != nil {
		return nil, err
	}
	var keyMap map[string]interface{}
	if err := json.Unmarshal(key, &keyMap); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]interface{}{
		"keys": []interface{}{keyMap},
	})
}

func encodeBase64URL(b []byte) string {
	const base64URLChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, 0, (len(b)*4+2)/3)
	for i := 0; i < len(b); i += 3 {
		var b0, b1, b2 byte
		b0 = b[i]
		if i+1 < len(b) {
			b1 = b[i+1]
		}
		if i+2 < len(b) {
			b2 = b[i+2]
		}
		result = append(result, base64URLChars[b0>>2])
		result = append(result, base64URLChars[((b0&3)<<4)|(b1>>4)])
		if i+1 < len(b) {
			result = append(result, base64URLChars[((b1&15)<<2)|(b2>>6)])
		}
		if i+2 < len(b) {
			result = append(result, base64URLChars[b2&63])
		}
	}
	return string(result)
}
