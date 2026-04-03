package token

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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

	var event RevocationEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
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
