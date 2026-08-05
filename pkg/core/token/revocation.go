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
	"time"
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
		// Resolve the jti to its token hash via the secondary index so the
		// actual cache entry is evicted, then drop the index entry itself.
		if hash, ok := lookupIndexHash(ctx, h.cache, jtiIndexPrefix+event.JTI); ok {
			_ = h.cache.Delete(ctx, jtiIndexPrefix+event.JTI)
			return h.cache.Delete(ctx, hash)
		}
		// Legacy fallback: some callers cached directly under the jti.
		return h.cache.Delete(ctx, event.JTI)
	}

	if event.SessionID != "" {
		h.logger.Info("revoking tokens by session", "sid", event.SessionID)
		return deleteIndexedTokens(ctx, h.cache, sidIndexPrefix+event.SessionID)
	}

	if event.RevokeAll && event.Subject != "" {
		// Targeted eviction: delete only the cached tokens recorded for this
		// subject instead of flushing the whole (shared, multi-tenant) cache.
		h.logger.Info("revoking all cached tokens for subject", "sub", event.Subject)
		return deleteIndexedTokens(ctx, h.cache, subIndexPrefix+event.Subject)
	}

	return fmt.Errorf("revocation event has no identifiable token reference")
}

// RevokeBySubject evicts every cached token recorded for a subject.
func RevokeBySubject(ctx context.Context, c Cache, subject string) error {
	return deleteIndexedTokens(ctx, c, subIndexPrefix+subject)
}

// RevokeBySession evicts every cached token recorded for a session ID.
func RevokeBySession(ctx context.Context, c Cache, sessionID string) error {
	return deleteIndexedTokens(ctx, c, sidIndexPrefix+sessionID)
}

// --- Secondary index (jti / subject / session → token hash) ---
//
// The index reuses the claims Cache itself so it works with any Cache
// implementation (memory, Redis, user-provided). Index entries are stored as
// CommonClaims whose Extra["hashes"] holds the token hashes.

const (
	jtiIndexPrefix = "idx:jti:"
	subIndexPrefix = "idx:sub:"
	sidIndexPrefix = "idx:sid:"
)

// IndexClaims records secondary index entries for a cached token so later
// revocation events (by jti, subject, or session) can evict the exact cache
// entries instead of flushing the whole cache. Call it right after caching
// introspection results; ttl should match (or exceed) the cache entry's TTL.
func IndexClaims(ctx context.Context, c Cache, tokenHash string, claims *CommonClaims, ttl time.Duration) {
	if c == nil || claims == nil || tokenHash == "" || ttl <= 0 {
		return
	}
	if claims.JTI != "" {
		entry := &CommonClaims{Extra: map[string]interface{}{"hashes": []string{tokenHash}}}
		_ = c.Set(ctx, jtiIndexPrefix+claims.JTI, entry, ttl)
	}
	if claims.Subject != "" {
		appendIndexHash(ctx, c, subIndexPrefix+claims.Subject, tokenHash, ttl)
	}
	if claims.SessionID != "" {
		appendIndexHash(ctx, c, sidIndexPrefix+claims.SessionID, tokenHash, ttl)
	}
}

// appendIndexHash adds tokenHash to the index entry at key (read-modify-write).
func appendIndexHash(ctx context.Context, c Cache, key, tokenHash string, ttl time.Duration) {
	hashes := indexHashes(ctx, c, key)
	for _, h := range hashes {
		if h == tokenHash {
			return
		}
	}
	hashes = append(hashes, tokenHash)
	entry := &CommonClaims{Extra: map[string]interface{}{"hashes": hashes}}
	_ = c.Set(ctx, key, entry, ttl)
}

// indexHashes returns the token hashes recorded under an index key.
func indexHashes(ctx context.Context, c Cache, key string) []string {
	entry, ok := c.Get(ctx, key)
	if !ok || entry == nil || entry.Extra == nil {
		return nil
	}
	switch v := entry.Extra["hashes"].(type) {
	case []string:
		return v
	case []interface{}: // after a JSON round-trip (e.g. Redis)
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// lookupIndexHash returns the single token hash stored under an index key.
func lookupIndexHash(ctx context.Context, c Cache, key string) (string, bool) {
	hashes := indexHashes(ctx, c, key)
	if len(hashes) == 0 {
		return "", false
	}
	return hashes[0], true
}

// deleteIndexedTokens evicts every token hash recorded under an index key,
// then removes the index entry itself.
func deleteIndexedTokens(ctx context.Context, c Cache, key string) error {
	var firstErr error
	for _, hash := range indexHashes(ctx, c, key) {
		if err := c.Delete(ctx, hash); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := c.Delete(ctx, key); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
