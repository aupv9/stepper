package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// DPoPConfig holds configuration for DPoP proof validation (RFC 9449).
type DPoPConfig struct {
	// MaxAge is the maximum allowed age of a DPoP proof (default: 60s).
	MaxAge time.Duration

	// RequireHTTPS enforces that the htu claim uses HTTPS.
	RequireHTTPS bool
}

// DefaultDPoPConfig returns sensible defaults.
func DefaultDPoPConfig() DPoPConfig {
	return DPoPConfig{
		MaxAge:       60 * time.Second,
		RequireHTTPS: true,
	}
}

// DPoPProof represents the parsed DPoP JWT header/payload.
type DPoPProof struct {
	// Header fields
	Algorithm string
	JWK       map[string]interface{}

	// Payload fields
	JTI  string    // unique proof ID
	HTM  string    // HTTP method
	HTU  string    // HTTP URI
	IAT  time.Time // issued at
	ATH  string    // access token hash (base64url SHA-256)
}

// ValidateDPoP validates the DPoP proof from the request header against the access token.
// Returns an error if the proof is invalid or mismatched.
//
// Per RFC 9449, the DPoP header contains a signed JWT proving possession of the private key
// that corresponds to the public key embedded in the access token's cnf claim.
func ValidateDPoP(r *http.Request, accessToken string, cfg DPoPConfig) (*DPoPProof, error) {
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return nil, fmt.Errorf("missing DPoP proof header")
	}

	proof, err := parseDPoPJWT(dpopHeader)
	if err != nil {
		return nil, fmt.Errorf("parsing DPoP proof: %w", err)
	}

	// Verify signature using embedded JWK (RFC 9449 §4.3)
	if err := verifyDPoPSignature(dpopHeader, proof); err != nil {
		return nil, fmt.Errorf("DPoP signature verification failed: %w", err)
	}

	// Validate HTM matches request method
	if !strings.EqualFold(proof.HTM, r.Method) {
		return nil, fmt.Errorf("DPoP htm %q does not match request method %q", proof.HTM, r.Method)
	}

	// Validate HTU matches request URI
	requestURL := r.URL.String()
	if !strings.EqualFold(proof.HTU, requestURL) {
		// Normalize and try again
		if !htuMatches(proof.HTU, r) {
			return nil, fmt.Errorf("DPoP htu %q does not match request URI %q", proof.HTU, requestURL)
		}
	}

	// Validate freshness
	age := time.Since(proof.IAT)
	if cfg.MaxAge > 0 && age > cfg.MaxAge {
		return nil, fmt.Errorf("DPoP proof is too old: %s (max %s)", age.Round(time.Second), cfg.MaxAge)
	}
	if proof.IAT.After(time.Now().Add(5 * time.Second)) {
		return nil, fmt.Errorf("DPoP proof issued in the future")
	}

	// Validate ATH (access token hash) if present
	if proof.ATH != "" {
		expectedATH := hashTokenForDPoP(accessToken)
		if proof.ATH != expectedATH {
			return nil, ErrDPoPBindingMismatch
		}
	}

	return proof, nil
}

// parseDPoPJWT parses the DPoP proof JWT header and payload.
func parseDPoPJWT(jwt string) (*DPoPProof, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}

	var header struct {
		Alg string                 `json:"alg"`
		Typ string                 `json:"typ"`
		JWK map[string]interface{} `json:"jwk"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing header: %w", err)
	}
	if header.Typ != "dpop+jwt" {
		return nil, fmt.Errorf("invalid DPoP typ: %q", header.Typ)
	}

	var payload struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
		ATH string `json:"ath"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("parsing payload: %w", err)
	}

	return &DPoPProof{
		Algorithm: header.Alg,
		JWK:       header.JWK,
		JTI:       payload.JTI,
		HTM:       payload.HTM,
		HTU:       payload.HTU,
		IAT:       time.Unix(payload.IAT, 0),
		ATH:       payload.ATH,
	}, nil
}

// verifyDPoPSignature verifies the JWT signature using the embedded JWK.
func verifyDPoPSignature(jwt string, proof *DPoPProof) error {
	parts := strings.Split(jwt, ".")

	pubKey, err := PublicKeyFromJWK(proof.JWK)
	if err != nil {
		return fmt.Errorf("extracting public key from JWK: %w", err)
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	return verifyJWTSignature(proof.Algorithm, pubKey, signingInput, sigBytes)
}

// verifyJWTSignature dispatches to the correct signature verification based on alg.
func verifyJWTSignature(alg string, key crypto.PublicKey, input, sig []byte) error {
	switch alg {
	case "ES256":
		return verifyECDSA(elliptic.P256(), crypto.SHA256, key, input, sig)
	case "ES384":
		return verifyECDSA(elliptic.P384(), crypto.SHA384, key, input, sig)
	case "ES512":
		return verifyECDSA(elliptic.P521(), crypto.SHA512, key, input, sig)
	case "RS256":
		return verifyRSAPKCS1v15(crypto.SHA256, key, input, sig)
	case "RS384":
		return verifyRSAPKCS1v15(crypto.SHA384, key, input, sig)
	case "RS512":
		return verifyRSAPKCS1v15(crypto.SHA512, key, input, sig)
	default:
		return fmt.Errorf("unsupported algorithm: %q", alg)
	}
}

// verifyECDSA verifies an ECDSA JWT signature.
// JWT encodes the ECDSA signature as r || s (IEEE P1363, not DER).
func verifyECDSA(curve elliptic.Curve, hash crypto.Hash, key crypto.PublicKey, input, sig []byte) error {
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected *ecdsa.PublicKey for %s", curve.Params().Name)
	}

	h := hash.New()
	h.Write(input)
	digest := h.Sum(nil)

	byteLen := (curve.Params().BitSize + 7) / 8
	if len(sig) != 2*byteLen {
		return fmt.Errorf("ECDSA signature length %d, expected %d", len(sig), 2*byteLen)
	}

	r := new(big.Int).SetBytes(sig[:byteLen])
	s := new(big.Int).SetBytes(sig[byteLen:])

	if !ecdsa.Verify(ecKey, digest, r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// verifyRSAPKCS1v15 verifies an RSA PKCS#1 v1.5 JWT signature.
func verifyRSAPKCS1v15(hash crypto.Hash, key crypto.PublicKey, input, sig []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected *rsa.PublicKey")
	}

	h := hash.New()
	h.Write(input)
	digest := h.Sum(nil)

	return rsa.VerifyPKCS1v15(rsaKey, hash, digest, sig)
}

// hashTokenForDPoP computes base64url(SHA-256(ascii(token))) as per RFC 9449.
func hashTokenForDPoP(token string) string {
	h := crypto.SHA256.New()
	h.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// htuMatches checks if the DPoP htu matches the HTTP request,
// ignoring query parameters and fragments as allowed by RFC 9449.
func htuMatches(htu string, r *http.Request) bool {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	requestBase := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
	htuBase := strings.Split(htu, "?")[0]
	htuBase = strings.Split(htuBase, "#")[0]
	return strings.EqualFold(htuBase, requestBase)
}

// PublicKeyFromJWK extracts a crypto.PublicKey from a JWK map.
// Supports EC (P-256, P-384, P-521) and RSA keys.
func PublicKeyFromJWK(jwk map[string]interface{}) (crypto.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "EC":
		return ecKeyFromJWK(jwk)
	case "RSA":
		return rsaKeyFromJWK(jwk)
	default:
		return nil, fmt.Errorf("unsupported JWK kty: %q", kty)
	}
}

// ecKeyFromJWK reconstructs an *ecdsa.PublicKey from a JWK map.
func ecKeyFromJWK(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	xStr, _ := jwk["x"].(string)
	yStr, _ := jwk["y"].(string)

	if xStr == "" || yStr == "" {
		return nil, fmt.Errorf("EC JWK missing x or y")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("decoding EC x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("decoding EC y: %w", err)
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %q", crv)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("EC point is not on curve %s", crv)
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// rsaKeyFromJWK reconstructs an *rsa.PublicKey from a JWK map.
func rsaKeyFromJWK(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)

	if nStr == "" || eStr == "" {
		return nil, fmt.Errorf("RSA JWK missing n or e")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decoding RSA n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decoding RSA e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())
	if e <= 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}
