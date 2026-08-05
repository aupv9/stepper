package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRouter_LivenessAndReadiness(t *testing.T) {
	cfg := newTestRouterConfig(t)

	t.Run("live always ok", func(t *testing.T) {
		h := NewRouter(cfg)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health/live", nil))
		if rr.Code != http.StatusOK {
			t.Errorf("live: got %d", rr.Code)
		}
	})

	t.Run("ready without check is ok", func(t *testing.T) {
		h := NewRouter(cfg)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		if rr.Code != http.StatusOK {
			t.Errorf("ready: got %d", rr.Code)
		}
	})

	t.Run("ready check passing", func(t *testing.T) {
		c := cfg
		c.ReadyCheck = func(context.Context) error { return nil }
		h := NewRouter(c)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		if rr.Code != http.StatusOK {
			t.Errorf("ready: got %d", rr.Code)
		}
	})

	t.Run("ready check failing returns 503", func(t *testing.T) {
		c := cfg
		c.ReadyCheck = func(context.Context) error { return errors.New("redis down") }
		h := NewRouter(c)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("ready: got %d, want 503", rr.Code)
		}
	})
}
