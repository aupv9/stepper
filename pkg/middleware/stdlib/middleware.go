package stdlib

import (
	"context"
	"net/http"

	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/stepup"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/providers"
)

type contextKey int

const claimsKey contextKey = iota

// Config configures the IAM middleware.
type Config struct {
	Provider       providers.Provider
	PolicyEngine   *policy.Engine
	Realm          string
	EnableDPoP     bool
}

// Middleware returns a standard net/http middleware that:
//  1. Extracts the Bearer token
//  2. Introspects / validates it
//  3. Evaluates the policy
//  4. Issues a step-up challenge if needed (RFC 9470)
func Middleware(cfg Config) func(http.Handler) http.Handler {
	sm := stepup.NewStateMachine()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawToken, err := token.ExtractBearerToken(r.Header.Get("Authorization"))
			if err != nil {
				challenge := &stepup.StepUpChallenge{
					Error:            stepup.ErrCodeInvalidToken,
					ErrorDescription: "missing or invalid bearer token",
					Realm:            cfg.Realm,
				}
				challenge.WriteChallenge(w)
				return
			}

			if cfg.EnableDPoP {
				if _, dpopErr := token.ValidateDPoP(r, rawToken, token.DefaultDPoPConfig()); dpopErr != nil {
					(&stepup.StepUpChallenge{
						Error:            stepup.ErrCodeInvalidToken,
						ErrorDescription: "DPoP validation failed: " + dpopErr.Error(),
						Realm:            cfg.Realm,
					}).WriteChallenge(w)
					return
				}
			}

			claims, err := cfg.Provider.Introspect(r.Context(), rawToken)
			if err != nil || !claims.Active {
				challenge := &stepup.StepUpChallenge{
					Error:            stepup.ErrCodeInvalidToken,
					ErrorDescription: "token inactive or validation failed",
					Realm:            cfg.Realm,
				}
				challenge.WriteChallenge(w)
				return
			}

			// Policy evaluation
			if cfg.PolicyEngine != nil {
				result, err := cfg.PolicyEngine.Evaluate(&policy.PolicyRequest{
					Method:               r.Method,
					Path:                 r.URL.Path,
					TokenACR:             claims.ACR,
					TokenAMR:             claims.AMR,
					TokenScopes:          claims.Scopes,
					AuthAge:              claims.AuthAge(),
					AuthorizationDetails: claims.AuthorizationDetails,
				})
				if err != nil {
					http.Error(w, "policy evaluation error", http.StatusInternalServerError)
					return
				}

				if !result.Allowed {
					// Issue step-up challenge
					stepErr := stepup.NewInsufficientACRError(result.RequiredACR, result.RequiredMaxAge)
					challenge := stepup.NewStepUpChallenge(stepErr, cfg.Realm)
					_, _ = sm.BeginChallenge(r, challenge)
					challenge.WriteChallenge(w)
					return
				}
			}

			// Attach claims to context for downstream handlers
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext retrieves CommonClaims stored by the middleware.
func ClaimsFromContext(ctx context.Context) (*token.CommonClaims, bool) {
	c, ok := ctx.Value(claimsKey).(*token.CommonClaims)
	return c, ok
}
