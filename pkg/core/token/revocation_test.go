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
	h := NewRevocationHandler(cache, "", nil)

	// Cache a token under its hash and index it by jti, as the guard does.
	hash := HashToken("access-token-1")
	claims := &CommonClaims{Active: true, JTI: "jti-abc", Subject: "alice"}
	_ = cache.Set(ctx, hash, claims, time.Minute)
	IndexClaims(ctx, cache, hash, claims, time.Minute)

	body, _ := json.Marshal(RevocationEvent{JTI: "jti-abc"})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if _, ok := cache.Get(ctx, hash); ok {
		t.Error("jti revocation must evict the token's actual cache entry")
	}
}

func TestRevocationHandler_RevokeAllForSubject_Targeted(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache()
	h := NewRevocationHandler(cache, "", nil)

	// Two tokens for alice, one for bob.
	aliceHash1 := HashToken("alice-tok-1")
	aliceHash2 := HashToken("alice-tok-2")
	bobHash := HashToken("bob-tok")
	alice1 := &CommonClaims{Active: true, Subject: "alice", JTI: "a1"}
	alice2 := &CommonClaims{Active: true, Subject: "alice", JTI: "a2"}
	bob := &CommonClaims{Active: true, Subject: "bob", JTI: "b1"}
	for _, e := range []struct {
		hash   string
		claims *CommonClaims
	}{{aliceHash1, alice1}, {aliceHash2, alice2}, {bobHash, bob}} {
		_ = cache.Set(ctx, e.hash, e.claims, time.Minute)
		IndexClaims(ctx, cache, e.hash, e.claims, time.Minute)
	}

	body, _ := json.Marshal(RevocationEvent{Subject: "alice", RevokeAll: true})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if _, ok := cache.Get(ctx, aliceHash1); ok {
		t.Error("alice token 1 should be evicted")
	}
	if _, ok := cache.Get(ctx, aliceHash2); ok {
		t.Error("alice token 2 should be evicted")
	}
	if _, ok := cache.Get(ctx, bobHash); !ok {
		t.Error("bob's token must NOT be evicted by alice's revoke-all")
	}
}

func TestRevocationHandler_RevokeBySession(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryCache()
	h := NewRevocationHandler(cache, "", nil)

	hash := HashToken("sess-tok")
	claims := &CommonClaims{Active: true, Subject: "alice", SessionID: "sess-1"}
	_ = cache.Set(ctx, hash, claims, time.Minute)
	IndexClaims(ctx, cache, hash, claims, time.Minute)

	body, _ := json.Marshal(RevocationEvent{SessionID: "sess-1"})
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if _, ok := cache.Get(ctx, hash); ok {
		t.Error("session revocation must evict the token's cache entry")
	}
}

func computeSig(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return fmt.Sprintf("%s", hex.EncodeToString(mac.Sum(nil)))
}
