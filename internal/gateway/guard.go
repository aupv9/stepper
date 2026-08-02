package gateway

import (
	"context"
	"net/http"
	"time"

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
	webhookSecret string
	cookieSecret  string
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

	// WebhookSecret is the HMAC-SHA256 secret used to authenticate revocation webhook
	// calls on /webhook/revoke. Leave empty to disable signature verification (dev only).
	WebhookSecret string

	// CookieSecret signs the step-up state cookie so clients cannot tamper with it.
	// Leave empty to disable cookie-based step-up state (challenges will still be issued
	// but the original request won't be replayed automatically after re-auth).
	CookieSecret string
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
		webhookSecret: cfg.WebhookSecret,
		cookieSecret:  cfg.CookieSecret,
	}
}

// ServeHTTP implements http.Handler - this is the main auth enforcement path.
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.StartSpan(r.Context(), "gateway.Guard.ServeHTTP")
	defer span.End()
	r = r.WithContext(ctx)

	// 1. Resolve tenant
	tenantID, err := g.resolver.Resolve(r)
	if err != nil {
		tenantID = "default"
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

	// 7. Policy passed for the effective path. If this was a replay, rewrite the
	// request to the saved resource now (safe: policy above already covered it).
	if saved != nil {
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

	// 9. Attach tenant + claims to context, pass to next handler.
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
		ttl := time.Until(claims.ExpiresAt)
		if ttl <= 0 || ttl > 30*time.Second {
			ttl = 30 * time.Second
		}
		hash := token.HashToken(rawToken)
		_ = g.cache.Set(ctx, hash, claims, ttl)
		if g.index != nil {
			_ = g.index.Add(ctx, hash, claims.JTI, claims.Subject, ttl)
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
