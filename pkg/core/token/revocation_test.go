package token

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRevocationHandler_NoSecret(t *testing.T) {
	cache := NewMemoryCache()
	h := NewRevocationHandler(cache, "", nil)

	// Seed a token in the cache.
	hash := HashToken("mytoken")
	_ = cache.Set(context.Background(), hash, &CommonClaims{Active: true}, time.Minute)

	body, _ := json.Marshal(RevocationEvent{TokenHash: hash})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if _, ok := cache.Get(context.Background(), hash); ok {
		t.Error("token should have been evicted from cache")
	}
}

func TestRevocationHandler_ValidHMAC(t *testing.T) {
	const secret = "supersecret"
	cache := NewMemoryCache()
	h := NewRevocationHandler(cache, secret, nil)

	hash := HashToken("tok2")
	_ = cache.Set(context.Background(), hash, &CommonClaims{Active: true}, time.Minute)

	body, _ := json.Marshal(RevocationEvent{TokenHash: hash})
	sig := computeSig(secret, body)

	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", "sha256="+sig)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRevocationHandler_InvalidHMAC(t *testing.T) {
	const secret = "supersecret"
	cache := NewMemoryCache()
	h := NewRevocationHandler(cache, secret, nil)

	body, _ := json.Marshal(RevocationEvent{TokenHash: "abc"})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", "sha256=deaddead")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong sig, got %d", rr.Code)
	}
}

func TestRevocationHandler_MissingHMAC_WhenSecretRequired(t *testing.T) {
	cache := NewMemoryCache()
	h := NewRevocationHandler(cache, "secret", nil)

	body, _ := json.Marshal(RevocationEvent{TokenHash: "abc"})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	// No X-Hub-Signature-256 header
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no sig provided, got %d", rr.Code)
	}
}

func TestRevocationHandler_RevokeByJTI(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache()
	index := NewMemoryTokenIndex()
	h := NewRevocationHandler(cache, "", nil, index)

	// The cache is keyed by token hash; the index maps jti -> hash.
	hash := HashToken("realtoken")
	_ = cache.Set(ctx, hash, &CommonClaims{Active: true, JTI: "jti-abc"}, time.Minute)
	_ = index.Add(ctx, hash, "jti-abc", "grace", time.Minute)

	body, _ := json.Marshal(RevocationEvent{JTI: "jti-abc"})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if _, ok := cache.Get(ctx, hash); ok {
		t.Error("token should have been evicted from cache by jti revocation")
	}
}

func TestRevocationHandler_RevokeByJTI_NoIndex(t *testing.T) {
	// Without an index, jti-based revocation cannot target the cache key and
	// must surface an error instead of silently no-op'ing.
	cache := NewMemoryCache()
	h := NewRevocationHandler(cache, "", nil)

	body, _ := json.Marshal(RevocationEvent{JTI: "jti-x"})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 without index, got %d", rr.Code)
	}
}

func TestRevocationHandler_RevokeAllBySubject_IsScoped(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache()
	index := NewMemoryTokenIndex()
	h := NewRevocationHandler(cache, "", nil, index)

	// Two subjects cached; revoking all of "alice" must not touch "bob".
	aliceHash := HashToken("alice-token")
	bobHash := HashToken("bob-token")
	_ = cache.Set(ctx, aliceHash, &CommonClaims{Active: true, Subject: "alice"}, time.Minute)
	_ = cache.Set(ctx, bobHash, &CommonClaims{Active: true, Subject: "bob"}, time.Minute)
	_ = index.Add(ctx, aliceHash, "jti-a", "alice", time.Minute)
	_ = index.Add(ctx, bobHash, "jti-b", "bob", time.Minute)

	body, _ := json.Marshal(RevocationEvent{RevokeAll: true, Subject: "alice"})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if _, ok := cache.Get(ctx, aliceHash); ok {
		t.Error("alice's token should have been revoked")
	}
	if _, ok := cache.Get(ctx, bobHash); !ok {
		t.Error("bob's token must NOT be revoked by a subject-scoped event for alice")
	}
}

func computeSig(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return fmt.Sprintf("%s", hex.EncodeToString(mac.Sum(nil)))
}
