package stepup

import (
	"fmt"
	"net/http"
	"strings"
)

// StepUpChallenge represents an RFC 9470 step-up authentication challenge.
type StepUpChallenge struct {
	// ACRValues is the required Authentication Context Class Reference value(s).
	// Space-separated list, e.g. "urn:mace:incommon:iap:silver urn:mace:incommon:iap:gold"
	ACRValues string

	// MaxAge is the maximum acceptable authentication age in seconds.
	// 0 means no max_age constraint.
	MaxAge int

	// Error is the RFC 9470 error code.
	Error string

	// ErrorDescription is a human-readable description.
	ErrorDescription string

	// Realm is the protection space for the Bearer scheme.
	Realm string
}

// WWWAuthenticateHeader builds the WWW-Authenticate header value per RFC 9470.
//
// Example output:
//
//	Bearer realm="example", error="insufficient_user_authentication",
//	       acr_values="urn:mace:incommon:iap:silver", max_age=300
func (c *StepUpChallenge) WWWAuthenticateHeader() string {
	var parts []string

	realm := c.Realm
	if realm == "" {
		realm = "IAM"
	}
	parts = append(parts, fmt.Sprintf(`realm="%s"`, realm))

	if c.Error != "" {
		parts = append(parts, fmt.Sprintf(`error="%s"`, c.Error))
	}
	if c.ErrorDescription != "" {
		parts = append(parts, fmt.Sprintf(`error_description="%s"`, c.ErrorDescription))
	}
	if c.ACRValues != "" {
		parts = append(parts, fmt.Sprintf(`acr_values="%s"`, c.ACRValues))
	}
	if c.MaxAge > 0 {
		parts = append(parts, fmt.Sprintf("max_age=%d", c.MaxAge))
	}

	return "Bearer " + strings.Join(parts, ", ")
}

// WriteChallenge writes a 401 response with the WWW-Authenticate header.
func (c *StepUpChallenge) WriteChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", c.WWWAuthenticateHeader())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"error":%q,"error_description":%q}`, c.Error, c.ErrorDescription)
}

// ParseWWWAuthenticate parses a WWW-Authenticate header value into a StepUpChallenge.
// Handles the Bearer scheme with RFC 9470 parameters.
func ParseWWWAuthenticate(header string) (*StepUpChallenge, error) {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, fmt.Errorf("unsupported scheme, expected Bearer")
	}

	c := &StepUpChallenge{}
	params := strings.TrimPrefix(header, "Bearer ")

	for _, part := range strings.Split(params, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)

		switch key {
		case "realm":
			c.Realm = val
		case "error":
			c.Error = val
		case "error_description":
			c.ErrorDescription = val
		case "acr_values":
			c.ACRValues = val
		case "max_age":
			fmt.Sscanf(val, "%d", &c.MaxAge)
		}
	}

	return c, nil
}

// NewStepUpChallenge creates a challenge from a StepUpError.
func NewStepUpChallenge(err *StepUpError, realm string) *StepUpChallenge {
	return &StepUpChallenge{
		ACRValues:        err.ACRValues,
		MaxAge:           err.MaxAge,
		Error:            err.Code,
		ErrorDescription: err.Description,
		Realm:            realm,
	}
}
