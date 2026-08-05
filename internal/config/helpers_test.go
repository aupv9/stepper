package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRequest(t *testing.T) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, "http://gateway.local/resource", nil)
}
