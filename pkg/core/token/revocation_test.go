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
	cache := NewMemoryCache()
	h := NewRevocationHandler(cache, "", nil)

	_ = cache.Set(context.Background(), "jti-abc", &CommonClaims{Active: true}, time.Minute)

	body, _ := json.Marshal(RevocationEvent{JTI: "jti-abc"})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func computeSig(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return fmt.Sprintf("%s", hex.EncodeToString(mac.Sum(nil)))
}
