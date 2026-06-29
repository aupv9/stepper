package token

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// RevocationEvent represents a token revocation notification.
type RevocationEvent struct {
	// TokenHash is the SHA-256 of the revoked token (never store raw token).
	TokenHash string `json:"token_hash,omitempty"`

	// JTI is the JWT ID of the revoked token (if known).
	JTI string `json:"jti,omitempty"`

	// Subject is the user subject whose tokens were revoked.
	Subject string `json:"sub,omitempty"`

	// SessionID - if set, all tokens for this session are revoked.
	SessionID string `json:"sid,omitempty"`

	// RevokeAll - if true, all tokens for the Subject are revoked.
	RevokeAll bool `json:"revoke_all,omitempty"`
}

// RevocationHandler is an HTTP handler that receives revocation webhook events
// and invalidates the corresponding cache entries.
type RevocationHandler struct {
	cache  Cache
	logger *slog.Logger
	secret string // optional HMAC secret for webhook auth
}

// NewRevocationHandler creates a revocation webhook handler.
func NewRevocationHandler(cache Cache, webhookSecret string, logger *slog.Logger) *RevocationHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &RevocationHandler{
		cache:  cache,
		logger: logger,
		secret: webhookSecret,
	}
}

// ServeHTTP handles POST /revoke webhook events.
func (h *RevocationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the full body once so we can both verify the HMAC and decode the JSON.
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB max
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}

	// Verify HMAC-SHA256 signature when a secret is configured.
	// Header format: X-Hub-Signature-256: sha256=<hex>
	if h.secret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if !verifyHMACSHA256(sig, body, h.secret) {
			http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
			return
		}
	}

	var event RevocationEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if err := h.process(r.Context(), &event); err != nil {
		h.logger.Error("processing revocation event", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// verifyHMACSHA256 checks that sig == "sha256=<hmac-sha256(secret, body)>".
func verifyHMACSHA256(sig string, body []byte, secret string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(sig, prefix) {
		return false
	}
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(sig, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(sigBytes, expected)
}

func (h *RevocationHandler) process(ctx context.Context, event *RevocationEvent) error {
	if event.TokenHash != "" {
		h.logger.Info("revoking token by hash", "token_hash", event.TokenHash)
		return h.cache.Delete(ctx, event.TokenHash)
	}

	if event.JTI != "" {
		h.logger.Info("revoking token by JTI", "jti", event.JTI)
		// JTI is used as cache key when token hash is not available
		return h.cache.Delete(ctx, event.JTI)
	}

	if event.RevokeAll && event.Subject != "" {
		// For flush-all scenarios, we clear the entire cache.
		// Production systems should use a more targeted approach (e.g., per-user key prefix).
		h.logger.Warn("flushing all cache entries for subject", "sub", event.Subject)
		return h.cache.Flush(ctx)
	}

	return fmt.Errorf("revocation event has no identifiable token reference")
}
