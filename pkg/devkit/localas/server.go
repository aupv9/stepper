package localas

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/common-iam/iam/pkg/devkit/tokenfactory"
)

// Server is a lightweight mock Authorization Server for local development and testing.
// It implements:
//   - GET  /.well-known/openid-configuration  (OIDC discovery)
//   - GET  /jwks                              (JWKS endpoint)
//   - POST /token                             (token endpoint - password grant)
//   - POST /introspect                        (RFC 7662 introspection)
//   - POST /revoke                            (token revocation)
type Server struct {
	factory  *tokenfactory.Factory
	mu       sync.RWMutex
	tokens   map[string]*tokenEntry // rawToken → claims
	issuer   string
	httpSrv  *http.Server
	listener net.Listener
}

type tokenEntry struct {
	raw       string
	subject   string
	scopes    []string
	acr       string
	expiresAt time.Time
	revoked   bool
}

// New creates a LocalAS. Call Start() to begin serving.
func New() (*Server, error) {
	factory, err := tokenfactory.New()
	if err != nil {
		return nil, fmt.Errorf("creating token factory: %w", err)
	}
	return &Server{
		factory: factory,
		tokens:  make(map[string]*tokenEntry),
	}, nil
}

// Start begins listening on a random port. Returns the base URL.
func (s *Server) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listening: %w", err)
	}
	s.listener = ln
	s.issuer = fmt.Sprintf("http://%s", ln.Addr().String())

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/introspect", s.handleIntrospect)
	mux.HandleFunc("/revoke", s.handleRevoke)

	s.httpSrv = &http.Server{Handler: mux}
	go s.httpSrv.Serve(ln) //nolint:errcheck
	return s.issuer, nil
}

// Stop shuts down the local AS.
func (s *Server) Stop(ctx context.Context) error {
	if s.httpSrv != nil {
		return s.httpSrv.Shutdown(ctx)
	}
	return nil
}

// IssueToken generates and registers a token with the given options.
func (s *Server) IssueToken(opts tokenfactory.TokenOptions) (string, error) {
	if opts.Issuer == "" {
		opts.Issuer = s.issuer
	}
	raw, err := s.factory.Generate(opts)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.tokens[raw] = &tokenEntry{
		raw:       raw,
		subject:   opts.Subject,
		scopes:    opts.Scopes,
		acr:       opts.ACR,
		expiresAt: time.Now().Add(opts.ExpiresIn),
	}
	s.mu.Unlock()

	return raw, nil
}

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	base := s.issuer
	writeJSON(w, map[string]interface{}{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"introspection_endpoint":                base + "/introspect",
		"revocation_endpoint":                   base + "/revoke",
		"jwks_uri":                              base + "/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "password"},
		"acr_values_supported":                  []string{"urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:gold"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwks, err := s.factory.JWKS()
	if err != nil {
		http.Error(w, "error generating JWKS", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jwks) //nolint:errcheck
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm() //nolint:errcheck
	sub := r.FormValue("username")
	if sub == "" {
		sub = "test-user"
	}
	acr := r.FormValue("acr_values")
	if acr == "" {
		acr = "urn:mace:incommon:iap:bronze"
	}

	raw, err := s.IssueToken(tokenfactory.TokenOptions{
		Subject:   sub,
		ACR:       acr,
		Scopes:    []string{"openid", "profile"},
		ExpiresIn: time.Hour,
	})
	if err != nil {
		http.Error(w, "error issuing token", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{
		"access_token": raw,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm() //nolint:errcheck
	raw := r.FormValue("token")

	s.mu.RLock()
	entry, ok := s.tokens[raw]
	s.mu.RUnlock()

	if !ok || entry.revoked || time.Now().After(entry.expiresAt) {
		writeJSON(w, map[string]interface{}{"active": false})
		return
	}

	writeJSON(w, map[string]interface{}{
		"active":  true,
		"sub":     entry.subject,
		"scope":   joinScopes(entry.scopes),
		"acr":     entry.acr,
		"exp":     entry.expiresAt.Unix(),
		"iss":     s.issuer,
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm() //nolint:errcheck
	raw := r.FormValue("token")

	s.mu.Lock()
	if entry, ok := s.tokens[raw]; ok {
		entry.revoked = true
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}
