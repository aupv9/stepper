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
	next          http.Handler // upstream handler (proxy or direct)
	cache         token.Cache  // optional; nil = no caching
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

	// 3a. DPoP proof-of-possession (RFC 9449) — only when explicitly enabled
	if g.enableDPoP {
		if _, dpopErr := token.ValidateDPoP(r, rawToken, token.DefaultDPoPConfig()); dpopErr != nil {
			g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "DPoP validation failed: "+dpopErr.Error(), "", 0)
			return
		}
	}

	// 4. Introspect token (cache-first when a cache is configured)
	claims, err := g.introspect(ctx, provider, rawToken)
	if err != nil || !claims.Active {
		g.issueChallenge(w, r, stepup.ErrCodeInvalidToken, "token inactive or validation failed", "", 0)
		return
	}

	telemetry.SpanFromToken(span, claims.Subject, claims.ACR, tenantID)

	// 5. Policy evaluation
	if g.policyEngine != nil {
		result, evalErr := g.policyEngine.Evaluate(&policy.PolicyRequest{
			Method:      r.Method,
			Path:        r.URL.Path,
			TokenACR:    claims.ACR,
			TokenAMR:    claims.AMR,
			TokenScopes: claims.Scopes,
			AuthAge:     claims.AuthAge(),
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

	// 6. Clear any pending step-up cookie now that auth succeeded.
	if g.cookieSecret != "" {
		stepup.ClearStateCookie(w)
	}

	// 7. Attach tenant + claims to context, pass to next handler.
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
		_ = g.cache.Set(ctx, token.HashToken(rawToken), claims, ttl)
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
