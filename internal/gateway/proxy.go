package gateway

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// NewReverseProxy creates an HTTP reverse proxy to the upstream URL.
// Used when the IAM service acts as a sidecar/gateway in front of backend services.
func NewReverseProxy(upstreamURL string) (http.Handler, error) {
	target, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream URL %q: %w", upstreamURL, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize error handling
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
	}

	return proxy, nil
}
