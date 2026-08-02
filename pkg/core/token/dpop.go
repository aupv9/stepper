package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DPoP sentinel errors.
var (
	// ErrDPoPReplay indicates a DPoP proof jti was seen before (RFC 9449 §11.1).
	ErrDPoPReplay = errors.New("dpop proof replay detected")

	// ErrDPoPNonceRequired indicates the server requires a fresh nonce; respond
	// with 401, error="use_dpop_nonce" and a DPoP-Nonce header (RFC 9449 §8).
	ErrDPoPNonceRequired = errors.New("dpop nonce required")

	// ErrDPoPMissingATH indicates the proof lacks the mandatory ath claim.
	ErrDPoPMissingATH = errors.New("dpop proof missing ath (access token hash) claim")
)

// DPoPConfig holds configuration for DPoP proof validation (RFC 9449).
type DPoPConfig struct {
	// MaxAge is the maximum allowed age of a DPoP proof (default: 60s).
	MaxAge time.Duration

	// RequireHTTPS enforces that the htu claim uses HTTPS.
	RequireHTTPS bool

	// Nonce, when set, requires proofs to carry a valid server-issued nonce
	// claim (RFC 9449 §8). Proofs without one fail with ErrDPoPNonceRequired.
	Nonce *NonceProvider
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
	JTI   string    // unique proof ID
	HTM   string    // HTTP method
	HTU   string    // HTTP URI
	IAT   time.Time // issued at
	ATH   string    // access token hash (base64url SHA-256)
	Nonce string    // server-issued nonce (RFC 9449 §8)
}

// Thumbprint computes the RFC 7638 SHA-256 thumbprint (base64url, no padding)
// of the proof's embedded JWK. Compare it against the access token's cnf.jkt
// to enforce key binding (RFC 9449 §6.1).
func (p *DPoPProof) Thumbprint() (string, error) {
	return JWKThumbprint(p.JWK)
}

// JWKThumbprint computes the RFC 7638 JWK SHA-256 thumbprint: the required
// members of the key (per key type) serialized in lexicographic order with no
// whitespace, hashed with SHA-256 and base64url-encoded without padding.
func JWKThumbprint(jwk map[string]interface{}) (string, error) {
	kty, _ := jwk["kty"].(string)
	var members []string
	switch kty {
	case "EC":
		members = []string{"crv", "kty", "x", "y"}
	case "RSA":
		members = []string{"e", "kty", "n"}
	case "OKP":
		members = []string{"crv", "kty", "x"}
	default:
		return "", fmt.Errorf("unsupported JWK kty for thumbprint: %q", kty)
	}
	sort.Strings(members)

	var sb strings.Builder
	sb.WriteByte('{')
	for i, m := range members {
		v, ok := jwk[m].(string)
		if !ok || v == "" {
			return "", fmt.Errorf("JWK missing required member %q for thumbprint", m)
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		// Required members are all string-valued; encode via json.Marshal to
		// handle any escaping correctly.
		kb, _ := json.Marshal(m)
		vb, _ := json.Marshal(v)
		sb.Write(kb)
		sb.WriteByte(':')
		sb.Write(vb)
	}
	sb.WriteByte('}')

	sum := sha256.Sum256([]byte(sb.String()))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
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

	// Validate ATH (access token hash) — mandatory. A proof that does not
	// commit to the access token can be replayed with any stolen token.
	if proof.ATH == "" {
		return nil, ErrDPoPMissingATH
	}
	if proof.ATH != hashTokenForDPoP(accessToken) {
		return nil, ErrDPoPBindingMismatch
	}

	// Validate server-issued nonce when required (RFC 9449 §8).
	if cfg.Nonce != nil && !cfg.Nonce.Valid(proof.Nonce) {
		return nil, ErrDPoPNonceRequired
	}

	return proof, nil
}

// DPoPValidator validates DPoP proofs with jti replay protection.
// The replay cache records each seen jti for the proof MaxAge window;
// a second proof with the same jti is rejected (RFC 9449 §11.1).
type DPoPValidator struct {
	cfg   DPoPConfig
	cache Cache
}

const dpopJTIPrefix = "dpop:jti:"

// NewDPoPValidator creates a validator. If cache is nil an in-memory cache is
// used (single-instance replay protection only — pass a shared cache in
// multi-instance deployments).
func NewDPoPValidator(cfg DPoPConfig, cache Cache) *DPoPValidator {
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 60 * time.Second
	}
	if cache == nil {
		cache = NewMemoryCache()
	}
	return &DPoPValidator{cfg: cfg, cache: cache}
}

// Validate runs full proof validation (ValidateDPoP) plus jti replay detection.
func (v *DPoPValidator) Validate(r *http.Request, accessToken string) (*DPoPProof, error) {
	proof, err := ValidateDPoP(r, accessToken, v.cfg)
	if err != nil {
		return nil, err
	}

	if proof.JTI == "" {
		return nil, fmt.Errorf("dpop proof missing jti claim")
	}
	ctx := r.Context()
	key := dpopJTIPrefix + proof.JTI
	if _, seen := v.cache.Get(ctx, key); seen {
		return nil, ErrDPoPReplay
	}
	// Record the jti for the proof acceptance window; entries expire with it.
	_ = v.cache.Set(ctx, key, &CommonClaims{}, v.cfg.MaxAge)

	return proof, nil
}

// NonceProvider issues and validates server DPoP nonces (RFC 9449 §8).
// Nonces are HMAC(secret, time-window) so they need no storage and stay valid
// across instances sharing the secret. The current and previous windows are
// both accepted, giving clients between Window and 2×Window to use a nonce.
type NonceProvider struct {
	secret []byte
	window time.Duration
}

// NewNonceProvider creates a nonce provider. Window defaults to 5 minutes.
func NewNonceProvider(secret string, window time.Duration) *NonceProvider {
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &NonceProvider{secret: []byte(secret), window: window}
}

// Current returns the nonce for the current time window; send it to clients
// in the DPoP-Nonce response header.
func (n *NonceProvider) Current() string {
	return n.forWindow(time.Now().UnixNano() / int64(n.window))
}

// Valid reports whether nonce matches the current or previous window.
func (n *NonceProvider) Valid(nonce string) bool {
	if nonce == "" {
		return false
	}
	w := time.Now().UnixNano() / int64(n.window)
	return hmac.Equal([]byte(nonce), []byte(n.forWindow(w))) ||
		hmac.Equal([]byte(nonce), []byte(n.forWindow(w-1)))
}

func (n *NonceProvider) forWindow(w int64) string {
	mac := hmac.New(sha256.New, n.secret)
	fmt.Fprintf(mac, "%d", w)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyDPoPBinding enforces RFC 9449 §6.1 key binding: the access token's
// cnf.jkt thumbprint must equal the RFC 7638 thumbprint of the proof's JWK.
func VerifyDPoPBinding(proof *DPoPProof, claims *CommonClaims) error {
	if claims.Confirmation == nil || claims.Confirmation.JKT == "" {
		return fmt.Errorf("access token is not DPoP-bound (no cnf.jkt claim)")
	}
	thumb, err := proof.Thumbprint()
	if err != nil {
		return fmt.Errorf("computing proof JWK thumbprint: %w", err)
	}
	if !hmac.Equal([]byte(thumb), []byte(claims.Confirmation.JKT)) {
		return ErrDPoPBindingMismatch
	}
	return nil
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
		JTI   string `json:"jti"`
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		IAT   int64  `json:"iat"`
		ATH   string `json:"ath"`
		Nonce string `json:"nonce"`
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
		Nonce:     payload.Nonce,
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
