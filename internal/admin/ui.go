package admin

import (
	_ "embed"
	"net/http"
)

//go:embed ui/index.html
var policyEditorHTML []byte

// UIHandler serves the embedded policy editor at /admin/ui.
func UIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		w.Write(policyEditorHTML) //nolint:errcheck
	})
}
