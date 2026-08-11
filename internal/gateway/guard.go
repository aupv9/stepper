package gateway

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/common-iam/iam/pkg/core/fapi"
	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/stepup"
	"github.com/common-iam/iam/pkg/core/token"
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
	next          http.Handler      // upstream handler (proxy or direct)
	cache         token.Cache       // optional; nil = no caching
	index         token.TokenIndex  // optional; jti/subject -> cache key, for revocation
	replay        token.ReplayGuard // DPoP jti replay guard (built when EnableDPoP)
	enableDPoP    bool
	fapiProfile   bool // enforce FAPI 2.0 profile on every request
	webhookSecret string
	cookieSecret  string
	defaultTenant string      // opt-in fallback tenant when resolution fails; "" = fail closed
	limiter       RateLimiter // optional per-client-IP rate limiter
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
	// When true, requests without a valid DPoP proof header are rejected with 401.
	EnableDPoP bool

	// FAPIProfile enforces the FAPI 2.0 Security Profile (DPoP-bound, PAR-
	// initiated, nonce present, 60s auth_time freshness) on every request.
	FAPIProfile bool

	// WebhookSecret is the HMAC-SHA256 secret used to authenticate revocation webhook
	// calls on /webhook/revoke. Leave empty to disable signature verification (dev only).
	WebhookSecret string

	// CookieSecret signs the step-up state cookie so clients cannot tamper with it.
	// Leave empty to disable cookie-based step-up state (challenges will still be issued
	// but the original request won't be replayed automatically after re-auth).
	CookieSecret string

	// DefaultTenant, when set, is used when the resolver cannot determine a
	// tenant (e.g. single-tenant deployments). Leave empty to fail closed:
	// unresolvable tenant context is rejected rather than silently mapped to a
	// default, preserving per-tenant isolation for untrusted clients.
	DefaultTenant string

	// RateLimiter, when set, rejects requests exceeding the limit (per client
	// IP) with 429 before introspection, protecting the AS and upstream.
	RateLimiter RateLimiter
}

// NewGuard creates a ResourceServerGuard.
func NewGuard(cfg GuardConfig) *Guard {
	realm := cfg.Realm
	if realm == "" {
		realm = "IAM"
	}
	// When a cache is configured, keep a revocation index so jti/subject-scoped
	// webhook events can target the exact cache entries.
	var index token.TokenIndex
	if cfg.Cache != nil {
		index = token.NewMemoryTokenIndex()
	}

	var replay token.ReplayGuard
	if cfg.EnableDPoP {
		replay = token.NewMemoryReplayGuard()
	}

	return &Guard{
		registry:      cfg.Registry,
		resolver:      cfg.Resolver,
		policyEngine:  cfg.PolicyEngine,
		realm:         realm,
		sm:            stepup.NewStateMachine(),
		audit:         cfg.Audit,
		metrics:       cfg.Metrics,
		next:          cfg.Upstream,
		cache:         cfg.Cache,
		index:         index,
		replay:        replay,
		enableDPoP:    cfg.EnableDPoP,
		fapiProfile:   cfg.FAPIProfile,
		webhookSecret: cfg.WebhookSecret,
		cookieSecret:  cfg.CookieSecret,
		defaultTenant: cfg.DefaultTenant,
		limiter:       cfg.RateLimiter,
	}
}

// ServeHTTP implements http.Handler - this is the main auth enforcement path.
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.StartSpan(r.Context(), "gateway.Guard.ServeHTTP")
	defer span.End()
	r = r.WithContext(ctx)

	// 0. Rate limit per client IP before doing any work (protects introspection).
	if g.limiter != nil && !g.limiter.Allow(clientIP(r)) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, `{"error":"rate_limited"}`, http.StatusTooManyRequests)
		return
	}

	// 1. Resolve tenant. Fail closed unless an explicit DefaultTenant is set:
	// silently mapping unresolvable requests to a default tenant would let a
	// client bypass per-tenant isolation.
	tenantID, err := g.resolver.Resolve(r)
	if err != nil || tenantID == "" {
		if g.defaultTenant == "" {
			g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "tenant could not be resolved", "", 0)
			return
		}
		tenantID = g.defaultTenant
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

	// 3a. DPoP proof-of-possession (RFC 9449) — only when explicitly enabled.
	// Phase 1 (here): verify the proof is self-consistent (signature, htm, htu,
	// freshness). Phase 2 (after introspection) binds it to the token's cnf.jkt
	// and checks for replay — that needs the token's claims.
	dpopCfg := token.DefaultDPoPConfig()
	var dpopProof *token.DPoPProof
	if g.enableDPoP {
		p, dpopErr := token.ValidateDPoP(r, rawToken, dpopCfg)
		if dpopErr != nil {
			g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "DPoP validation failed: "+dpopErr.Error(), "", 0)
			return
		}
		dpopProof = p
	}

	// 4. Introspect token (cache-first when a cache is configured)
	claims, err := g.introspect(ctx, provider, rawToken)
	if err != nil || !claims.Active {
		g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "token inactive or validation failed", "", 0)
		return
	}

	// 4a-issuer. Cross-tenant binding: the token's issuer must match the tenant's
	// provider. Without this, a valid token for tenant A paired with a spoofed
	// X-Tenant-ID: B header could be evaluated under tenant B's policies.
	if wantIss := provider.Issuer(); wantIss != "" && claims.Issuer != "" && claims.Issuer != wantIss {
		g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "token issuer does not match tenant", "", 0)
		return
	}

	// 4a. DPoP phase 2: reject replayed proofs, then bind the proof key to the
	// access token's cnf.jkt. This is what makes DPoP a real sender-constraint.
	if g.enableDPoP {
		if dpopProof.JTI == "" {
			g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "DPoP proof missing jti", "", 0)
			return
		}
		if g.replay != nil {
			if seen, _ := g.replay.CheckAndSet(ctx, dpopProof.JTI, dpopCfg.MaxAge); seen {
				g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "DPoP proof replayed", "", 0)
				return
			}
		}
		if bindErr := dpopProof.VerifyBinding(rawToken, claims.CNF); bindErr != nil {
			g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "DPoP binding failed: "+bindErr.Error(), "", 0)
			return
		}
	}

	// 4b. FAPI 2.0 profile enforcement (DPoP-bound, PAR-initiated, nonce, fresh auth).
	if g.fapiProfile {
		if fapiErr := fapi.ValidateRequest(r, claims, fapi.DefaultFAPI2Config()); fapiErr != nil {
			g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, fapiErr.Error(), "", 0)
			return
		}
	}

	telemetry.SpanFromToken(span, claims.Subject, claims.ACR, tenantID)

	// 5. Determine the *effective* request (the one we will actually serve).
	// Step-up replay: when the client returns with a higher-assurance token and a
	// signed cookie referencing the originally-denied resource, we intend to forward
	// to that saved path. Resolve it up-front so policy is evaluated against the path
	// we will serve — never evaluate one path and forward another (step-up bypass).
	effMethod, effPath, effQuery := r.Method, r.URL.Path, r.URL.RawQuery
	var saved *stepup.SavedRequest
	if g.cookieSecret != "" {
		if s, cookieErr := stepup.ReadStateCookie(r, g.cookieSecret); cookieErr == nil && s != nil && s.Path != "" {
			saved = s
			effMethod, effPath, effQuery = s.Method, s.Path, s.Query
		}
	}

	// 6. Policy evaluation — always against the effective (served) path.
	if g.policyEngine != nil {
		result, evalErr := g.policyEngine.Evaluate(&policy.PolicyRequest{
			Method:               effMethod,
			Path:                 effPath,
			TokenACR:             claims.ACR,
			TokenAMR:             claims.AMR,
			TokenScopes:          claims.Scopes,
			AuthAge:              claims.AuthAge(),
			HasAuthTime:          !claims.AuthTime.IsZero(),
			AuthorizationDetails: claims.AuthorizationDetails,
		})
		if evalErr != nil {
			http.Error(w, "policy evaluation error", http.StatusInternalServerError)
			return
		}
		if !result.Allowed {
			// The current token does not satisfy the effective path's policy.
			// Re-challenge for that path (mark the flow failed for the state machine).
			g.handleDenial(ctx, w, r, claims.Subject, tenantID, result)
			return
		}

		if g.audit != nil {
			g.audit.EmitPolicyDecision(ctx, claims.Subject, tenantID, effPath, effMethod, "", "", true)
		}
	}

	// 7. Policy passed for the effective path. If this was a replay, drive the
	// step-up state machine Challenge → Completed (enforcing the flow timeout)
	// before rewriting the request to the saved resource. A flow that has aged
	// past the state machine's timeout is failed and re-challenged.
	if saved != nil {
		flow := &stepup.FlowState{
			State:        stepup.StateChallenge,
			SavedRequest: saved,
			StartedAt:    saved.SavedAt,
		}
		if completeErr := g.sm.Complete(flow); completeErr != nil {
			g.sm.Fail(flow)
			if g.cookieSecret != "" {
				stepup.ClearStateCookie(w)
			}
			g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "step-up flow expired: "+completeErr.Error(), "", 0)
			return
		}
		r = r.Clone(r.Context())
		r.Method = effMethod
		r.URL.Path = effPath
		r.URL.RawQuery = effQuery
		r.RequestURI = effPath
		if effQuery != "" {
			r.RequestURI += "?" + effQuery
		}
	}

	// 8. Clear any pending step-up cookie now that auth succeeded.
	if g.cookieSecret != "" {
		stepup.ClearStateCookie(w)
	}

	// 9. Trust-boundary header hygiene: strip any client-supplied tenant/identity
	// headers and re-inject gateway-verified values, so the upstream can trust
	// X-Iam-* without re-validating and cannot be fooled by a spoofed X-Tenant-ID.
	sanitizeTrustHeaders(r, tenantID, claims.Subject)

	// 10. Attach tenant + claims to context, pass to next handler.
	ctx = tenant.WithTenantID(ctx, tenantID)
	g.next.ServeHTTP(w, r.WithContext(ctx))
}

// introspect fetches token claims, using the cache when available.
func (g *Guard) introspect(ctx context.Context, provider interface {
	Introspect(context.Context, string) (*token.CommonClaims, error)
}, rawToken string) (*token.CommonClaims, error) {
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
		// Clamp the cache TTL to the token's own lifetime: never cache an
		// already-expired (or exp-less) token as active, and never keep a
		// short-lived token cached past its expiry. Skip caching entirely
		// when the token has no positive remaining lifetime.
		ttl := time.Until(claims.ExpiresAt)
		if !claims.ExpiresAt.IsZero() && ttl > 0 {
			if ttl > 30*time.Second {
				ttl = 30 * time.Second
			}
			hash := token.HashToken(rawToken)
			_ = g.cache.Set(ctx, hash, claims, ttl)
			if g.index != nil {
				_ = g.index.Add(ctx, hash, claims.JTI, claims.Subject, ttl)
			}
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
	return token.NewRevocationHandler(c, g.webhookSecret, nil, g.index)
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
		stepup.SetStateCookie(w, flow.SavedRequest, g.cookieSecret) //nolint:errcheck
	}

	challenge.WriteChallenge(w)
}

// clientIP extracts the client IP from the request for rate-limit keying,
// preferring the direct connection address (RemoteAddr) so it can't be spoofed
// via headers. Deployments behind a trusted proxy should terminate rate
// limiting at the edge or set RemoteAddr from a trusted X-Forwarded-For.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sanitizeTrustHeaders removes client-supplied tenant/identity headers and sets
// the gateway-verified values. The upstream should trust only these X-Iam-*
// headers, never the raw client-supplied X-Tenant-ID.
func sanitizeTrustHeaders(r *http.Request, tenantID, subject string) {
	// Drop the raw resolver input so upstream can't read the unverified value.
	r.Header.Del("X-Tenant-ID")
	// Set overwrites any client-spoofed X-Iam-* values.
	r.Header.Set("X-Iam-Tenant-Id", tenantID)
	if subject != "" {
		r.Header.Set("X-Iam-Subject", subject)
	} else {
		r.Header.Del("X-Iam-Subject")
	}
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
