package echo

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/stepup"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/providers"
)

const claimsKey = "iam_claims"

// Config configures the Echo IAM middleware.
type Config struct {
	Provider     providers.Provider
	PolicyEngine *policy.Engine
	Realm        string
	EnableDPoP   bool
}

// Middleware returns an Echo middleware implementing RFC 9470 step-up.
func Middleware(cfg Config) echo.MiddlewareFunc {
	sm := stepup.NewStateMachine()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rawToken, err := token.ExtractBearerToken(c.Request().Header.Get("Authorization"))
			if err != nil {
				return echoChallenge(c, cfg.Realm, stepup.ErrCodeInvalidToken, "missing or invalid bearer token", "", 0)
			}

			claims, err := cfg.Provider.Introspect(c.Request().Context(), rawToken)
			if err != nil || !claims.Active {
				return echoChallenge(c, cfg.Realm, stepup.ErrCodeInvalidToken, "token inactive or validation failed", "", 0)
			}

			if cfg.PolicyEngine != nil {
				result, evalErr := cfg.PolicyEngine.Evaluate(&policy.PolicyRequest{
					Method:      c.Request().Method,
					Path:        c.Request().URL.Path,
					TokenACR:    claims.ACR,
					TokenAMR:    claims.AMR,
					TokenScopes: claims.Scopes,
					AuthAge:     claims.AuthAge(),
				})
				if evalErr != nil {
					return echo.ErrInternalServerError
				}
				if !result.Allowed {
					stepErr := stepup.NewInsufficientACRError(result.RequiredACR, result.RequiredMaxAge)
					challenge := stepup.NewStepUpChallenge(stepErr, cfg.Realm)
					_, _ = sm.BeginChallenge(c.Request(), challenge)
					return echoChallenge(c, cfg.Realm, challenge.Error, challenge.ErrorDescription,
						challenge.ACRValues, challenge.MaxAge)
				}
			}

			c.Set(claimsKey, claims)
			return next(c)
		}
	}
}

// ClaimsFromContext retrieves IAM claims from an Echo context.
func ClaimsFromContext(c echo.Context) (*token.CommonClaims, bool) {
	val := c.Get(claimsKey)
	if val == nil {
		return nil, false
	}
	claims, ok := val.(*token.CommonClaims)
	return claims, ok
}

func echoChallenge(c echo.Context, realm, errCode, desc, acrValues string, maxAge int) error {
	ch := &stepup.StepUpChallenge{
		Error:            errCode,
		ErrorDescription: desc,
		ACRValues:        acrValues,
		MaxAge:           maxAge,
		Realm:            realm,
	}
	c.Response().Header().Set("WWW-Authenticate", ch.WWWAuthenticateHeader())
	return c.JSON(http.StatusUnauthorized, map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}
