package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/common-iam/iam/pkg/core/fapi"
	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/stepup"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/providers"
	"github.com/common-iam/iam/pkg/telemetry"
	"github.com/common-iam/iam/pkg/tenant"
)

// Guard is the ResourceServerGuard - the central auth enforcement point.
// It sits in front of all protected resources and handles:
//   - Token extraction + introspection
//   - Policy evaluation
//   - Step-up challenge issuance (RFC 9470)
//   - Multi-tenant provider dispatch
type Guard struct {
	registry      *tenant.Registry
	resolver      tenant.Resolver
	policyEngine  *policy.Engine
	realm         string
	sm            *stepup.StateMachine
	audit         *telemetry.AuditLogger
	metrics       *telemetry.Metrics
	next          http.Handler // upstream handler (proxy or direct)
	cache         token.Cache  // optional; nil = no caching
	enableDPoP    bool
	dpop          *token.DPoPValidator
	dpopNonce     *token.NonceProvider
	webhookSecret string
	cookieSecret  string
	fapiCfg       *fapi.ValidationConfig
	limiter       limiter
}

// GuardConfig holds Guard dependencies.
type GuardConfig struct {
	Registry     *tenant.Registry
	Resolver     tenant.Resolver
	PolicyEngine *policy.Engine
	Realm        string
	Audit        *telemetry.AuditLogger
	Metrics      *telemetry.Metrics
	Upstream     http.Handler

	// Cache is an optional token cache (MemoryCache or RedisCache).
	// When set, introspection results are cached and the RevocationHandler
	// uses the same cache so revocations take effect immediately.
	Cache token.Cache

	// EnableDPoP enforces RFC 9449 DPoP proof-of-possession on every request.
	// When true, requests without a valid DPoP proof header are rejected with 401,
	// proof jti values are checked against a replay cache, and the token's
	// cnf.jkt binding is verified against the proof's JWK thumbprint.
	EnableDPoP bool

	// DPoPNonceSecret, when set (and EnableDPoP is true), requires proofs to
	// carry a server-issued nonce (RFC 9449 §8). Clients that omit or send a
	// stale nonce get 401 error="use_dpop_nonce" with a fresh DPoP-Nonce header.
	DPoPNonceSecret string

	// WebhookSecret is the HMAC-SHA256 secret used to authenticate revocation webhook
	// calls on /webhook/revoke. Leave empty to disable signature verification (dev only).
	WebhookSecret string

	// CookieSecret signs the step-up state cookie so clients cannot tamper with it.
	// Leave empty to disable cookie-based step-up state (challenges will still be issued
	// but the original request won't be replayed automatically after re-auth).
	CookieSecret string

	// FAPI, when set, enforces the FAPI 2.0 Security Profile on every request
	// after introspection (fapi.DefaultFAPI2Config() for strict compliance).
	FAPI *fapi.ValidationConfig

	// RateLimitRPS, when > 0, limits each client IP to this many requests per
	// second (token bucket). Requests over the limit get 429.
	RateLimitRPS float64

	// RateLimitBurst is the bucket size (default: RateLimitRPS, minimum 1).
	RateLimitBurst int

	// RateCounter, when set together with RateLimitRPS, switches to a
	// distributed fixed-window limiter shared across instances (e.g. Redis
	// via goredis.Adapter). When nil, an in-memory per-instance limiter is used.
	RateCounter RateCounter
}

// NewGuard creates a ResourceServerGuard.
func NewGuard(cfg GuardConfig) *Guard {
	realm := cfg.Realm
	if realm == "" {
		realm = "IAM"
	}
	g := &Guard{
		registry:      cfg.Registry,
		resolver:      cfg.Resolver,
		policyEngine:  cfg.PolicyEngine,
		realm:         realm,
		sm:            stepup.NewStateMachine(),
		audit:         cfg.Audit,
		metrics:       cfg.Metrics,
		next:          cfg.Upstream,
		cache:         cfg.Cache,
		enableDPoP:    cfg.EnableDPoP,
		webhookSecret: cfg.WebhookSecret,
		cookieSecret:  cfg.CookieSecret,
		fapiCfg:       cfg.FAPI,
	}
	if cfg.RateLimitRPS > 0 {
		if cfg.RateCounter != nil {
			g.limiter = newDistributedRateLimiter(cfg.RateCounter, cfg.RateLimitRPS, cfg.RateLimitBurst)
		} else {
			g.limiter = newRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)
		}
	}
	if cfg.EnableDPoP {
		dpopCfg := token.DefaultDPoPConfig()
		if cfg.DPoPNonceSecret != "" {
			g.dpopNonce = token.NewNonceProvider(cfg.DPoPNonceSecret, 0)
			dpopCfg.Nonce = g.dpopNonce
		}
		// Reuse the guard cache for jti replay detection so protection is
		// shared across instances when a distributed cache is configured.
		g.dpop = token.NewDPoPValidator(dpopCfg, cfg.Cache)
	}
	return g
}

// ServeHTTP implements http.Handler - this is the main auth enforcement path.
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.StartSpan(r.Context(), "gateway.Guard.ServeHTTP")
	defer span.End()
	r = r.WithContext(ctx)

	// 0. Rate limiting (pre-auth, keyed by client IP).
	if g.limiter != nil && !g.limiter.allowRequest(r) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// 1. Resolve tenant — fail closed. Single-tenant deployments opt in to a
	// default by appending tenant.NewStaticResolver to their resolver chain.
	tenantID, err := g.resolver.Resolve(r)
	if err != nil {
		g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "tenant resolution failed", "", 0)
		return
	}

	// 2. Get provider for tenant
	provider, err := g.registry.Get(tenantID)
	if err != nil {
		g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "unknown tenant", "", 0)
		return
	}

	// 3. Extract bearer token
	rawToken, err := token.ExtractBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "missing or invalid bearer token", "", 0)
		return
	}

	// 3a. DPoP proof-of-possession (RFC 9449) — only when explicitly enabled
	var dpopProof *token.DPoPProof
	if g.enableDPoP {
		proof, dpopErr := g.dpop.Validate(r, rawToken)
		if dpopErr != nil {
			if errors.Is(dpopErr, token.ErrDPoPNonceRequired) && g.dpopNonce != nil {
				// RFC 9449 §8: tell the client which nonce to use next.
				w.Header().Set("DPoP-Nonce", g.dpopNonce.Current())
				g.issueChallenge(w, r, "use_dpop_nonce", "server requires a DPoP nonce", "", 0)
				return
			}
			g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "DPoP validation failed: "+dpopErr.Error(), "", 0)
			return
		}
		dpopProof = proof
	}

	// 4. Introspect token (cache-first when a cache is configured)
	claims, err := g.introspect(ctx, provider, rawToken)
	if err != nil || !claims.Active {
		g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "token inactive or validation failed", "", 0)
		return
	}

	// 4a. Cross-tenant binding: the token's issuer must match the resolved
	// tenant's provider. Otherwise a valid token from tenant A could be
	// presented under tenant B's header (with B's AS confirming nothing).
	// Fail closed: iss is OPTIONAL in RFC 7662 responses, but when the
	// provider declares an issuer, an introspection response without one
	// cannot prove the token belongs to this tenant — reject it.
	if iss := provider.Issuer(); iss != "" && claims.Issuer != iss {
		reason := "token issuer does not match tenant provider"
		if claims.Issuer == "" {
			reason = "introspection response missing iss; cannot bind token to tenant"
		}
		g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, reason, "", 0)
		return
	}

	// 4b. DPoP key binding (RFC 9449 §6.1): the token's cnf.jkt must match the
	// proof's JWK thumbprint, otherwise a stolen token can be used with the
	// thief's own key.
	if g.enableDPoP {
		if bindErr := token.VerifyDPoPBinding(dpopProof, claims); bindErr != nil {
			g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "DPoP binding failed: "+bindErr.Error(), "", 0)
			return
		}
	}

	// 4c. mTLS certificate binding (RFC 8705): tokens carrying cnf.x5t#S256
	// are only accepted from the TLS client that owns the bound certificate.
	if certErr := token.VerifyCertBinding(r, claims); certErr != nil {
		g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "certificate binding failed: "+certErr.Error(), "", 0)
		return
	}

	// 4d. FAPI 2.0 Security Profile enforcement, when configured.
	if g.fapiCfg != nil {
		if fapiErr := fapi.ValidateRequest(r, claims, *g.fapiCfg); fapiErr != nil {
			g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, fapiErr.Error(), "", 0)
			return
		}
	}

	telemetry.SpanFromToken(span, claims.Subject, claims.ACR, tenantID)

	// 5. Policy evaluation
	if g.policyEngine != nil {
		result, evalErr := g.policyEngine.Evaluate(&policy.PolicyRequest{
			Method:               r.Method,
			Path:                 r.URL.Path,
			TokenACR:             claims.ACR,
			TokenAMR:             claims.AMR,
			TokenScopes:          claims.Scopes,
			TokenAudience:        claims.Audience,
			AuthAge:              claims.AuthAge(),
			AuthorizationDetails: claims.AuthorizationDetails,
		})
		if evalErr != nil {
			http.Error(w, "policy evaluation error", http.StatusInternalServerError)
			return
		}
		if !result.Allowed {
			g.handleDenial(ctx, w, r, claims.Subject, tenantID, result)
			return
		}

		if g.audit != nil {
			g.audit.EmitPolicyDecision(ctx, claims.Subject, tenantID, r.URL.Path, r.Method, "", "", true)
		}
	}

	// 6. Step-up cookie replay: if the client returned with a new token from a
	// different path (e.g., /callback), replay the original saved request —
	// but only after re-evaluating policy against the SAVED path with the
	// current token. Without this check a low-assurance token authorized for
	// the landing path could be forwarded to the protected resource.
	if g.cookieSecret != "" {
		if saved, cookieErr := stepup.ReadStateCookie(r, g.cookieSecret); cookieErr == nil && saved != nil {
			if saved.Path != "" && saved.Path != r.URL.Path {
				replayed, ok := g.completeStepUp(ctx, w, r, saved, claims, tenantID)
				if !ok {
					return // challenge re-issued for the saved resource
				}
				r = replayed
			}
		}
		// Clear the pending step-up cookie now that auth succeeded.
		stepup.ClearStateCookie(w)
	}

	// 7. Header hygiene: drop identity headers the client may have spoofed,
	// then re-inject values derived from the verified token and tenant so the
	// upstream can trust X-Iam-* unconditionally.
	sanitizeForwardHeaders(r.Header)
	r.Header.Set("X-Iam-Subject", claims.Subject)
	r.Header.Set("X-Iam-Tenant", tenantID)
	if claims.ACR != "" {
		r.Header.Set("X-Iam-Acr", claims.ACR)
	}
	if len(claims.Scopes) > 0 {
		r.Header.Set("X-Iam-Scopes", strings.Join(claims.Scopes, " "))
	}

	// 8. Attach tenant + claims to context, pass to next handler.
	ctx = tenant.WithTenantID(ctx, tenantID)
	g.next.ServeHTTP(w, r.WithContext(ctx))
}

// sanitizeForwardHeaders removes client-supplied identity headers before the
// request is proxied upstream. X-Tenant-ID is resolution *input* and must not
// leak upstream as if it were verified; X-Iam-* are reserved for the gateway.
func sanitizeForwardHeaders(h http.Header) {
	h.Del("X-Tenant-ID")
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-iam-") {
			h.Del(name)
		}
	}
}

// completeStepUp finishes a pending step-up flow: it re-evaluates policy for
// the saved (original) request with the current token's claims and drives the
// stepup.StateMachine. Only a flow that reaches StateCompleted is replayed.
// Returns the rewritten request and true when the replay may proceed; when it
// returns false a challenge has already been written to w.
func (g *Guard) completeStepUp(ctx context.Context, w http.ResponseWriter, r *http.Request, saved *stepup.SavedRequest, claims *token.CommonClaims, tenantID string) (*http.Request, bool) {
	flow := &stepup.FlowState{
		State:        stepup.StateChallenge,
		SavedRequest: saved,
		StartedAt:    saved.SavedAt,
	}

	if g.policyEngine != nil {
		result, evalErr := g.policyEngine.Evaluate(&policy.PolicyRequest{
			Method:               saved.Method,
			Path:                 saved.Path,
			TokenACR:             claims.ACR,
			TokenAMR:             claims.AMR,
			TokenScopes:          claims.Scopes,
			TokenAudience:        claims.Audience,
			AuthAge:              claims.AuthAge(),
			AuthorizationDetails: claims.AuthorizationDetails,
		})
		if evalErr != nil {
			g.sm.Fail(flow)
			http.Error(w, "policy evaluation error", http.StatusInternalServerError)
			return nil, false
		}
		if !result.Allowed {
			// The new token still does not satisfy the original resource:
			// fail this flow and challenge again for the saved resource.
			g.sm.Fail(flow)
			if g.audit != nil {
				g.audit.EmitPolicyDecision(ctx, claims.Subject, tenantID, saved.Path, saved.Method, "", result.Reason, false)
			}
			stepup.ClearStateCookie(w)
			g.issueChallenge(w, r, stepup.ErrCodeInsufficientUserAuthentication,
				"step-up incomplete: "+result.Reason, result.RequiredACR, result.RequiredMaxAge)
			return nil, false
		}
	}

	if err := g.sm.Complete(flow); err != nil || flow.State != stepup.StateCompleted {
		// Timed-out or otherwise invalid flow — never replay it.
		stepup.ClearStateCookie(w)
		g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "step-up flow expired", saved.ACRHint, saved.MaxAge)
		return nil, false
	}

	replayed := r.Clone(r.Context())
	replayed.Method = saved.Method
	replayed.URL.Path = saved.Path
	replayed.URL.RawQuery = saved.Query
	replayed.RequestURI = saved.Path
	if saved.Query != "" {
		replayed.RequestURI += "?" + saved.Query
	}
	return replayed, true
}

// introspect fetches token claims, using the cache when available.
func (g *Guard) introspect(ctx context.Context, provider providers.Provider, rawToken string) (*token.CommonClaims, error) {
	if g.cache != nil {
		key := token.HashToken(rawToken)
		if cached, ok := g.cache.Get(ctx, key); ok {
			return cached, nil
		}
	}

	claims, err := provider.Introspect(ctx, rawToken)
	if err != nil {
		return nil, err
	}

	if g.cache != nil && claims.Active {
		// Clamp TTL to min(30s, remaining token lifetime); never cache a
		// token that is already expired.
		ttl := 30 * time.Second
		if !claims.ExpiresAt.IsZero() {
			if remaining := time.Until(claims.ExpiresAt); remaining < ttl {
				ttl = remaining
			}
		}
		if ttl > 0 {
			key := token.HashToken(rawToken)
			_ = g.cache.Set(ctx, key, claims, ttl)
			token.IndexClaims(ctx, g.cache, key, claims, ttl)
		}
	}

	return claims, nil
}

// RevocationHandler returns the HTTP handler for revocation webhooks.
// It shares the guard's cache so revocations take effect on the next request.
func (g *Guard) RevocationHandler() http.Handler {
	c := g.cache
	if c == nil {
		c = token.NewMemoryCache()
	}
	return token.NewRevocationHandler(c, g.webhookSecret, nil)
}

func (g *Guard) handleDenial(ctx context.Context, w http.ResponseWriter, r *http.Request, subject, tenantID string, result *policy.PolicyResult) {
	policyName := ""
	if result.MatchedPolicy != nil {
		policyName = result.MatchedPolicy.Name
	}

	if g.audit != nil {
		g.audit.EmitPolicyDecision(ctx, subject, tenantID,
			r.URL.Path, r.Method, policyName, result.Reason, false)
	}
	if g.metrics != nil {
		g.metrics.PolicyDeniedTotal.WithLabelValues(tenantID, policyName, result.Reason).Inc()
		g.metrics.StepUpTotal.WithLabelValues(tenantID, result.RequiredACR, r.Method).Inc()
	}

	stepErr := stepup.NewInsufficientACRError(result.RequiredACR, result.RequiredMaxAge)
	challenge := stepup.NewStepUpChallenge(stepErr, g.realm)
	flow, _ := g.sm.BeginChallenge(r, challenge)

	// Persist the original request in a signed cookie so it can be replayed
	// automatically once the client obtains a higher-assurance token.
	if g.cookieSecret != "" && flow != nil {
		stepup.SetStateCookie(w, flow.SavedRequest, g.cookieSecret, r.TLS != nil) //nolint:errcheck
	}

	challenge.WriteChallenge(w)
}

func (g *Guard) issueChallenge(w http.ResponseWriter, r *http.Request, errCode, desc, acrValues string, maxAge int) {
	ch := &stepup.StepUpChallenge{
		Error:            errCode,
		ErrorDescription: desc,
		ACRValues:        acrValues,
		MaxAge:           maxAge,
		Realm:            g.realm,
	}
	if g.audit != nil {
		g.audit.Emit(r.Context(), &telemetry.AuditEvent{
			Type:     telemetry.AuditTokenRejected,
			Resource: r.URL.Path,
			Method:   r.Method,
			Reason:   desc,
		})
	}
	ch.WriteChallenge(w)
}
