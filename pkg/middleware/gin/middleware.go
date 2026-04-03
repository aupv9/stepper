package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/stepup"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/providers"
)

const claimsKey = "iam_claims"

// Config configures the Gin IAM middleware.
type Config struct {
	Provider     providers.Provider
	PolicyEngine *policy.Engine
	Realm        string
	EnableDPoP   bool
}

// Middleware returns a Gin middleware handler implementing RFC 9470 step-up.
func Middleware(cfg Config) gin.HandlerFunc {
	sm := stepup.NewStateMachine()

	return func(c *gin.Context) {
		rawToken, err := token.ExtractBearerToken(c.GetHeader("Authorization"))
		if err != nil {
			issueChallenge(c, cfg.Realm, stepup.ErrCodeInvalidToken, "missing or invalid bearer token", "", 0)
			return
		}

		claims, err := cfg.Provider.Introspect(c.Request.Context(), rawToken)
		if err != nil || !claims.Active {
			issueChallenge(c, cfg.Realm, stepup.ErrCodeInvalidToken, "token inactive or validation failed", "", 0)
			return
		}

		if cfg.PolicyEngine != nil {
			result, err := cfg.PolicyEngine.Evaluate(&policy.PolicyRequest{
				Method:      c.Request.Method,
				Path:        c.Request.URL.Path,
				TokenACR:    claims.ACR,
				TokenAMR:    claims.AMR,
				TokenScopes: claims.Scopes,
				AuthAge:     claims.AuthAge(),
			})
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			if !result.Allowed {
				stepErr := stepup.NewInsufficientACRError(result.RequiredACR, result.RequiredMaxAge)
				challenge := stepup.NewStepUpChallenge(stepErr, cfg.Realm)
				_, _ = sm.BeginChallenge(c.Request, challenge)
				c.Header("WWW-Authenticate", challenge.WWWAuthenticateHeader())
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":             challenge.Error,
					"error_description": challenge.ErrorDescription,
				})
				return
			}
		}

		c.Set(claimsKey, claims)
		c.Next()
	}
}

// ClaimsFromContext retrieves IAM claims from a Gin context.
func ClaimsFromContext(c *gin.Context) (*token.CommonClaims, bool) {
	val, exists := c.Get(claimsKey)
	if !exists {
		return nil, false
	}
	claims, ok := val.(*token.CommonClaims)
	return claims, ok
}

func issueChallenge(c *gin.Context, realm, errCode, desc, acrValues string, maxAge int) {
	ch := &stepup.StepUpChallenge{
		Error:            errCode,
		ErrorDescription: desc,
		ACRValues:        acrValues,
		MaxAge:           maxAge,
		Realm:            realm,
	}
	c.Header("WWW-Authenticate", ch.WWWAuthenticateHeader())
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":             errCode,
		"error_description": desc,
	})
}
