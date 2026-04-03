# Middleware Integration

The middleware packages apply RFC 9470 step-up enforcement to your HTTP handlers. Three framework integrations are provided.

---

## Config Options (all frameworks)

```go
type Config struct {
    Provider     providers.Provider  // required: token introspection
    PolicyEngine *policy.Engine      // optional: nil = allow all authenticated
    Realm        string              // WWW-Authenticate realm (default "IAM")
    EnableDPoP   bool                // RFC 9449 DPoP proof validation (future)
}
```

---

## net/http (stdlib)

```go
import iamstdlib "github.com/common-iam/iam/pkg/middleware/stdlib"

middleware := iamstdlib.Middleware(iamstdlib.Config{
    Provider:     provider,
    PolicyEngine: engine,
    Realm:        "MyApp",
})

// Wrap your entire mux
http.ListenAndServe(":8080", middleware(yourMux))

// Or wrap specific routes
mux.Handle("/api/", middleware(http.HandlerFunc(apiHandler)))
```

**Reading claims in a handler:**

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := iamstdlib.ClaimsFromContext(r.Context())
    if !ok {
        http.Error(w, "no claims", 500)
        return
    }
    fmt.Fprintf(w, "Hello %s (acr=%s)", claims.Subject, claims.ACR)
}
```

---

## Gin

```go
import iamgin "github.com/common-iam/iam/pkg/middleware/gin"

r := gin.New()
r.Use(iamgin.Middleware(iamgin.Config{
    Provider:     provider,
    PolicyEngine: engine,
    Realm:        "MyApp",
}))

// Or apply to a group only
api := r.Group("/api")
api.Use(iamgin.Middleware(cfg))

api.GET("/profile", func(c *gin.Context) {
    claims, _ := iamgin.ClaimsFromContext(c)
    c.JSON(200, gin.H{
        "sub":  claims.Subject,
        "acr":  claims.ACR,
        "email": claims.Email,
    })
})
```

---

## Echo

```go
import iamecho "github.com/common-iam/iam/pkg/middleware/echo"

e := echo.New()
e.Use(iamecho.Middleware(iamecho.Config{
    Provider:     provider,
    PolicyEngine: engine,
    Realm:        "MyApp",
}))

// Or apply to a group
api := e.Group("/api")
api.Use(iamecho.Middleware(cfg))

api.GET("/profile", func(c echo.Context) error {
    claims, _ := iamecho.ClaimsFromContext(c)
    return c.JSON(200, map[string]string{
        "sub": claims.Subject,
        "acr": claims.ACR,
    })
})
```

---

## What the Middleware Does (Step by Step)

```
Incoming Request
      │
      ▼
1. Extract Bearer token from Authorization header
      │ missing/malformed → 401 + WWW-Authenticate (invalid_token)
      ▼
2. Introspect token (cache → AS)
      │ inactive/expired → 401 + WWW-Authenticate (invalid_token)
      ▼
3. Evaluate policy (if PolicyEngine is set)
      │ no match → pass through
      │ match, allowed → pass through
      │ match, denied → 401 + WWW-Authenticate (insufficient_user_authentication)
      │                     acr_values=<required>
      │                     max_age=<required>
      ▼
4. Attach CommonClaims to context
      ▼
5. Call next handler
```

---

## Response Format on Denial

**Headers:**
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="MyApp",
  error="insufficient_user_authentication",
  error_description="higher authentication level required",
  acr_values="urn:mace:incommon:iap:silver",
  max_age=300
Content-Type: application/json
```

**Body:**
```json
{
  "error": "insufficient_user_authentication",
  "error_description": "higher authentication level required"
}
```

---

## Handling Step-Up on the Client Side

When you receive a `401` with `error=insufficient_user_authentication`:

```javascript
// Browser / SPA example
async function callAPI(endpoint) {
    const response = await fetch(endpoint, {
        headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (response.status === 401) {
        const wwwAuth = response.headers.get('WWW-Authenticate');
        const challenge = parseChallenge(wwwAuth);
        // challenge.acr_values = "urn:mace:incommon:iap:silver"
        // challenge.max_age = 300

        // Save original request for later retry
        sessionStorage.setItem('pending_request', endpoint);

        // Redirect to AS with step-up hint
        window.location.href = buildAuthURL({
            acr_values: challenge.acr_values,
            max_age: challenge.max_age,
            prompt: 'login',
        });
        return;
    }

    return response.json();
}
```

---

## Bypassing Authentication (Skip Paths)

If you need unauthenticated paths alongside authenticated ones, use route grouping rather than path exclusions in the middleware. This is safer and more explicit:

```go
// Gin example
r := gin.New()

// Public routes — no middleware
r.GET("/health", healthHandler)
r.GET("/api/public/*path", publicHandler)

// Protected routes — with middleware
protected := r.Group("/api")
protected.Use(iamgin.Middleware(cfg))
protected.GET("/users", usersHandler)
protected.POST("/payments", paymentsHandler)
```

---

## Combining with Other Middleware

The IAM middleware should run **after** request ID / tracing middleware (so trace IDs are available) but **before** business logic:

```go
r := gin.New()
r.Use(gin.Logger())           // 1. logging
r.Use(requestid.New())        // 2. trace/request ID
r.Use(iamgin.Middleware(cfg)) // 3. auth enforcement  ← here
r.Use(rateLimiter())          // 4. rate limiting (optional, after auth)
// business handlers
```
