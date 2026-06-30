package stepup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Challenge generation: WWW-Authenticate header formatting (RFC 9470 §3) ---

func TestWWWAuthenticateHeader(t *testing.T) {
	tests := []struct {
		name      string
		challenge *StepUpChallenge
		// substrings that MUST be present in the header value
		wantContains []string
		// substrings that MUST NOT be present
		wantAbsent []string
	}{
		{
			name: "full challenge",
			challenge: &StepUpChallenge{
				Realm:            "example",
				Error:            ErrCodeInsufficientUserAuthentication,
				ErrorDescription: "higher authentication level required",
				ACRValues:        "urn:mace:incommon:iap:silver",
				MaxAge:           300,
			},
			wantContains: []string{
				`realm="example"`,
				`error="insufficient_user_authentication"`,
				`error_description="higher authentication level required"`,
				`acr_values="urn:mace:incommon:iap:silver"`,
				`max_age=300`,
			},
		},
		{
			name:      "empty realm defaults to IAM",
			challenge: &StepUpChallenge{},
			wantContains: []string{
				`realm="IAM"`,
			},
			// no error / acr / max_age params when unset
			wantAbsent: []string{"error=", "acr_values=", "max_age=", "error_description="},
		},
		{
			name: "max_age zero omitted",
			challenge: &StepUpChallenge{
				Realm:  "r",
				Error:  ErrCodeInvalidToken,
				MaxAge: 0,
			},
			wantContains: []string{`error="invalid_token"`},
			wantAbsent:   []string{"max_age"},
		},
		{
			name: "acr only",
			challenge: &StepUpChallenge{
				ACRValues: "gold silver",
			},
			wantContains: []string{`acr_values="gold silver"`, `realm="IAM"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.challenge.WWWAuthenticateHeader()

			if !strings.HasPrefix(got, "Bearer ") {
				t.Errorf("header must start with %q, got %q", "Bearer ", got)
			}
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("header %q missing expected substring %q", got, want)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("header %q must not contain %q", got, absent)
				}
			}
		})
	}
}

func TestWWWAuthenticateHeader_ParameterOrder(t *testing.T) {
	// RFC 9470 does not mandate order, but the implementation builds parts in a
	// fixed order: realm, error, error_description, acr_values, max_age.
	// Assert current behaviour so regressions are caught.
	c := &StepUpChallenge{
		Realm:            "r",
		Error:            "e",
		ErrorDescription: "d",
		ACRValues:        "a",
		MaxAge:           60,
	}
	got := c.WWWAuthenticateHeader()
	want := `Bearer realm="r", error="e", error_description="d", acr_values="a", max_age=60`
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestWriteChallenge(t *testing.T) {
	c := &StepUpChallenge{
		Realm:            "myrealm",
		Error:            ErrCodeInsufficientUserAuthentication,
		ErrorDescription: "need silver",
		ACRValues:        "silver",
		MaxAge:           120,
	}
	rec := httptest.NewRecorder()
	c.WriteChallenge(rec)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", res.StatusCode, http.StatusUnauthorized)
	}
	if got := res.Header.Get("WWW-Authenticate"); got != c.WWWAuthenticateHeader() {
		t.Errorf("WWW-Authenticate header: got %q, want %q", got, c.WWWAuthenticateHeader())
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"error":"insufficient_user_authentication"`) {
		t.Errorf("body missing error code: %q", body)
	}
	if !strings.Contains(body, `"error_description":"need silver"`) {
		t.Errorf("body missing error_description: %q", body)
	}
}

func TestNewStepUpChallenge(t *testing.T) {
	err := NewInsufficientACRError("urn:gold", 90)
	c := NewStepUpChallenge(err, "tenant-realm")

	if c.Error != ErrCodeInsufficientUserAuthentication {
		t.Errorf("Error: got %q, want %q", c.Error, ErrCodeInsufficientUserAuthentication)
	}
	if c.ACRValues != "urn:gold" {
		t.Errorf("ACRValues: got %q, want %q", c.ACRValues, "urn:gold")
	}
	if c.MaxAge != 90 {
		t.Errorf("MaxAge: got %d, want 90", c.MaxAge)
	}
	if c.Realm != "tenant-realm" {
		t.Errorf("Realm: got %q, want %q", c.Realm, "tenant-realm")
	}
	if c.ErrorDescription != err.Description {
		t.Errorf("ErrorDescription: got %q, want %q", c.ErrorDescription, err.Description)
	}
}

// --- Round-trip: build header -> parse header ---

func TestParseWWWAuthenticate(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		orig := &StepUpChallenge{
			Realm:            "example",
			Error:            ErrCodeInsufficientUserAuthentication,
			ErrorDescription: "higher authentication level required",
			ACRValues:        "urn:mace:incommon:iap:silver",
			MaxAge:           300,
		}
		header := orig.WWWAuthenticateHeader()

		parsed, err := ParseWWWAuthenticate(header)
		if err != nil {
			t.Fatalf("ParseWWWAuthenticate: %v", err)
		}
		if parsed.Realm != orig.Realm {
			t.Errorf("Realm: got %q, want %q", parsed.Realm, orig.Realm)
		}
		if parsed.Error != orig.Error {
			t.Errorf("Error: got %q, want %q", parsed.Error, orig.Error)
		}
		if parsed.ErrorDescription != orig.ErrorDescription {
			t.Errorf("ErrorDescription: got %q, want %q", parsed.ErrorDescription, orig.ErrorDescription)
		}
		if parsed.ACRValues != orig.ACRValues {
			t.Errorf("ACRValues: got %q, want %q", parsed.ACRValues, orig.ACRValues)
		}
		if parsed.MaxAge != orig.MaxAge {
			t.Errorf("MaxAge: got %d, want %d", parsed.MaxAge, orig.MaxAge)
		}
	})

	t.Run("non-bearer scheme rejected", func(t *testing.T) {
		_, err := ParseWWWAuthenticate(`Basic realm="x"`)
		if err == nil {
			t.Error("expected error for non-Bearer scheme")
		}
	})

	t.Run("leading whitespace trimmed", func(t *testing.T) {
		parsed, err := ParseWWWAuthenticate(`  Bearer realm="r", error="invalid_token"`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.Realm != "r" || parsed.Error != ErrCodeInvalidToken {
			t.Errorf("got realm=%q error=%q", parsed.Realm, parsed.Error)
		}
	})

	t.Run("malformed params skipped", func(t *testing.T) {
		// "garbage" has no '=' and must be silently skipped (len(kv)!=2).
		parsed, err := ParseWWWAuthenticate(`Bearer garbage, realm="ok"`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.Realm != "ok" {
			t.Errorf("realm: got %q, want ok", parsed.Realm)
		}
	})

	t.Run("max_age parsed as int", func(t *testing.T) {
		parsed, err := ParseWWWAuthenticate(`Bearer max_age=42`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.MaxAge != 42 {
			t.Errorf("MaxAge: got %d, want 42", parsed.MaxAge)
		}
	})
}

// --- errors.go ---

func TestErrorConstants(t *testing.T) {
	if ErrCodeInsufficientUserAuthentication != "insufficient_user_authentication" {
		t.Errorf("ErrCodeInsufficientUserAuthentication = %q", ErrCodeInsufficientUserAuthentication)
	}
	if ErrCodeInvalidToken != "invalid_token" {
		t.Errorf("ErrCodeInvalidToken = %q", ErrCodeInvalidToken)
	}
	if ErrCodeInsufficientScope != "insufficient_scope" {
		t.Errorf("ErrCodeInsufficientScope = %q", ErrCodeInsufficientScope)
	}
}

func TestStepUpError_Error(t *testing.T) {
	e := &StepUpError{Code: ErrCodeInvalidToken, Description: "boom"}
	if e.Error() != "boom" {
		t.Errorf("Error(): got %q, want %q", e.Error(), "boom")
	}
}

func TestNewInsufficientACRError(t *testing.T) {
	e := NewInsufficientACRError("silver", 60)
	if e.Code != ErrCodeInsufficientUserAuthentication {
		t.Errorf("Code: got %q", e.Code)
	}
	if e.ACRValues != "silver" {
		t.Errorf("ACRValues: got %q", e.ACRValues)
	}
	if e.MaxAge != 60 {
		t.Errorf("MaxAge: got %d", e.MaxAge)
	}
	if e.Description == "" {
		t.Error("Description must not be empty")
	}
	// Ensure it satisfies the error interface.
	var _ error = e
}

func TestSentinelErrorsDistinct(t *testing.T) {
	sentinels := []error{
		ErrMissingToken,
		ErrTokenExpired,
		ErrTokenInactive,
		ErrInsufficientACR,
		ErrAuthTooOld,
		ErrDPoPBindingMismatch,
		ErrTenantNotFound,
		ErrProviderUnavailable,
	}
	seen := map[string]bool{}
	for _, e := range sentinels {
		if e == nil {
			t.Fatal("sentinel error is nil")
		}
		msg := e.Error()
		if msg == "" {
			t.Error("sentinel error has empty message")
		}
		if seen[msg] {
			t.Errorf("duplicate sentinel message: %q", msg)
		}
		seen[msg] = true
	}
}

// --- State type ---

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateIdle, "idle"},
		{StateChallenge, "challenge"},
		{StateCompleted, "completed"},
		{StateFailed, "failed"},
		{State(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

// --- SavedRequest round-trip ---

func TestSavedRequest_EncodeDecode(t *testing.T) {
	orig := &SavedRequest{
		Method:  http.MethodPost,
		Path:    "/api/payments",
		Query:   "amount=100&currency=usd",
		StateID: "abc123",
		SavedAt: time.Now().Truncate(time.Second),
		ACRHint: "urn:gold",
		MaxAge:  300,
	}

	encoded, err := orig.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded == "" {
		t.Fatal("encoded value is empty")
	}

	got, err := DecodeSavedRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeSavedRequest: %v", err)
	}

	if got.Method != orig.Method {
		t.Errorf("Method: got %q, want %q", got.Method, orig.Method)
	}
	if got.Path != orig.Path {
		t.Errorf("Path: got %q, want %q", got.Path, orig.Path)
	}
	if got.Query != orig.Query {
		t.Errorf("Query: got %q, want %q", got.Query, orig.Query)
	}
	if got.StateID != orig.StateID {
		t.Errorf("StateID: got %q, want %q", got.StateID, orig.StateID)
	}
	if got.ACRHint != orig.ACRHint {
		t.Errorf("ACRHint: got %q, want %q", got.ACRHint, orig.ACRHint)
	}
	if got.MaxAge != orig.MaxAge {
		t.Errorf("MaxAge: got %d, want %d", got.MaxAge, orig.MaxAge)
	}
	if !got.SavedAt.Equal(orig.SavedAt) {
		t.Errorf("SavedAt: got %v, want %v", got.SavedAt, orig.SavedAt)
	}
}

func TestSavedRequest_EmptyRoundTrip(t *testing.T) {
	orig := &SavedRequest{}
	encoded, err := orig.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeSavedRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeSavedRequest: %v", err)
	}
	if got.Method != "" || got.Path != "" || got.Query != "" {
		t.Errorf("expected empty fields, got %+v", got)
	}
}

func TestDecodeSavedRequest_Errors(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		_, err := DecodeSavedRequest("!!!not base64!!!")
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})
	t.Run("valid base64 but not JSON", func(t *testing.T) {
		// base64url of "not json{" -> decodes fine but unmarshal fails.
		bad := "bm90IGpzb257" // "not json{"
		_, err := DecodeSavedRequest(bad)
		if err == nil {
			t.Error("expected error for non-JSON payload")
		}
	})
	t.Run("empty string", func(t *testing.T) {
		// empty decodes to empty bytes -> json.Unmarshal of "" fails.
		_, err := DecodeSavedRequest("")
		if err == nil {
			t.Error("expected error for empty encoded payload")
		}
	})
}

// --- StateMachine ---

func newTestRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, target, nil)
}

func TestStateMachine_DefaultTimeout(t *testing.T) {
	sm := NewStateMachine()
	if sm.Timeout != 10*time.Minute {
		t.Errorf("default Timeout: got %v, want 10m", sm.Timeout)
	}
}

func TestStateMachine_BeginChallenge(t *testing.T) {
	sm := NewStateMachine()
	req := newTestRequest(t, http.MethodPost, "/api/payments?amount=5")
	challenge := &StepUpChallenge{ACRValues: "urn:gold", MaxAge: 200}

	flow, err := sm.BeginChallenge(req, challenge)
	if err != nil {
		t.Fatalf("BeginChallenge: %v", err)
	}
	if flow.State != StateChallenge {
		t.Errorf("State: got %s, want challenge", flow.State)
	}
	if flow.Challenge != challenge {
		t.Error("Challenge not stored on flow")
	}
	if flow.SavedRequest == nil {
		t.Fatal("SavedRequest is nil")
	}
	if flow.SavedRequest.Method != http.MethodPost {
		t.Errorf("saved Method: got %q", flow.SavedRequest.Method)
	}
	if flow.SavedRequest.Path != "/api/payments" {
		t.Errorf("saved Path: got %q", flow.SavedRequest.Path)
	}
	if flow.SavedRequest.Query != "amount=5" {
		t.Errorf("saved Query: got %q", flow.SavedRequest.Query)
	}
	if flow.SavedRequest.ACRHint != "urn:gold" {
		t.Errorf("saved ACRHint: got %q", flow.SavedRequest.ACRHint)
	}
	if flow.SavedRequest.MaxAge != 200 {
		t.Errorf("saved MaxAge: got %d", flow.SavedRequest.MaxAge)
	}
	if flow.StartedAt.IsZero() {
		t.Error("StartedAt not set")
	}
}

func TestStateMachine_Complete(t *testing.T) {
	t.Run("success from challenge", func(t *testing.T) {
		sm := NewStateMachine()
		flow := &FlowState{State: StateChallenge, StartedAt: time.Now()}
		if err := sm.Complete(flow); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if flow.State != StateCompleted {
			t.Errorf("State: got %s, want completed", flow.State)
		}
		if flow.CompletedAt.IsZero() {
			t.Error("CompletedAt not set")
		}
	})

	t.Run("cannot complete from idle", func(t *testing.T) {
		sm := NewStateMachine()
		flow := &FlowState{State: StateIdle}
		if err := sm.Complete(flow); err == nil {
			t.Error("expected error completing a non-challenge flow")
		}
		if flow.State != StateIdle {
			t.Errorf("State should be unchanged, got %s", flow.State)
		}
	})

	t.Run("timed out challenge fails", func(t *testing.T) {
		sm := &StateMachine{Timeout: time.Nanosecond}
		flow := &FlowState{State: StateChallenge, StartedAt: time.Now().Add(-time.Hour)}
		err := sm.Complete(flow)
		if err == nil {
			t.Error("expected timeout error")
		}
		if flow.State != StateFailed {
			t.Errorf("State: got %s, want failed after timeout", flow.State)
		}
	})
}

func TestStateMachine_Fail(t *testing.T) {
	sm := NewStateMachine()
	flow := &FlowState{State: StateChallenge}
	sm.Fail(flow)
	if flow.State != StateFailed {
		t.Errorf("State: got %s, want failed", flow.State)
	}
}

func TestStateMachine_FullLifecycle(t *testing.T) {
	sm := NewStateMachine()
	req := newTestRequest(t, http.MethodGet, "/secure")
	challenge := NewStepUpChallenge(NewInsufficientACRError("silver", 60), "r")

	flow, err := sm.BeginChallenge(req, challenge)
	if err != nil {
		t.Fatalf("BeginChallenge: %v", err)
	}
	if flow.State != StateChallenge {
		t.Fatalf("expected challenge state, got %s", flow.State)
	}
	if err := sm.Complete(flow); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if flow.State != StateCompleted {
		t.Fatalf("expected completed state, got %s", flow.State)
	}
}

// --- FlowState context helpers ---

func TestFlowStateContext(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		flow := &FlowState{State: StateChallenge}
		ctx := WithFlowState(context.Background(), flow)
		got, ok := FlowStateFromContext(ctx)
		if !ok {
			t.Fatal("FlowStateFromContext returned ok=false")
		}
		if got != flow {
			t.Error("retrieved flow does not match stored flow")
		}
	})

	t.Run("absent returns false", func(t *testing.T) {
		got, ok := FlowStateFromContext(context.Background())
		if ok {
			t.Error("expected ok=false for context without flow state")
		}
		if got != nil {
			t.Error("expected nil flow for empty context")
		}
	})
}

// --- Cookie helpers: HMAC-signed state cookie ---

const testSecret = "test-signing-secret-32-bytes-long!!"

func newSavedRequest() *SavedRequest {
	return &SavedRequest{
		Method:  http.MethodPost,
		Path:    "/api/transfer",
		Query:   "to=bob",
		StateID: "csrf-token",
		SavedAt: time.Now(),
		ACRHint: "urn:gold",
		MaxAge:  120,
	}
}

func TestStateCookie_RoundTrip(t *testing.T) {
	rec := httptest.NewRecorder()
	saved := newSavedRequest()

	if err := SetStateCookie(rec, saved, testSecret); err != nil {
		t.Fatalf("SetStateCookie: %v", err)
	}

	// Build a request carrying the Set-Cookie value back.
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])

	got, err := ReadStateCookie(req, testSecret)
	if err != nil {
		t.Fatalf("ReadStateCookie: %v", err)
	}
	if got == nil {
		t.Fatal("ReadStateCookie returned nil saved request")
	}
	if got.Path != saved.Path || got.Method != saved.Method || got.Query != saved.Query {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
	if got.ACRHint != saved.ACRHint {
		t.Errorf("ACRHint: got %q, want %q", got.ACRHint, saved.ACRHint)
	}
}

func TestStateCookie_Attributes(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := SetStateCookie(rec, newSavedRequest(), testSecret); err != nil {
		t.Fatalf("SetStateCookie: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]

	if c.Name != CookieName {
		t.Errorf("Name: got %q, want %q", c.Name, CookieName)
	}
	if !c.HttpOnly {
		t.Error("cookie must be HttpOnly")
	}
	if c.Path != "/" {
		t.Errorf("Path: got %q, want /", c.Path)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite: got %v, want Lax", c.SameSite)
	}
	if c.MaxAge != cookieMaxAge {
		t.Errorf("MaxAge: got %d, want %d", c.MaxAge, cookieMaxAge)
	}
	// Document current behaviour: Secure is intentionally NOT set here
	// (the source comment says it is enforced by the caller via TLS).
	if c.Secure {
		t.Error("Secure flag is set by SetStateCookie; source documents it as caller-enforced")
	}
	// HMAC signature is appended as payload.signature
	if !strings.Contains(c.Value, ".") {
		t.Errorf("cookie value should contain payload.signature, got %q", c.Value)
	}
}

func TestReadStateCookie_Absent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got, err := ReadStateCookie(req, testSecret)
	if err != nil {
		t.Errorf("absent cookie should return nil error, got %v", err)
	}
	if got != nil {
		t.Errorf("absent cookie should return nil saved request, got %+v", got)
	}
}

func TestReadStateCookie_Malformed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "no-dot-separator"})
	_, err := ReadStateCookie(req, testSecret)
	if err == nil {
		t.Error("expected error for cookie without payload.signature separator")
	}
}

func TestReadStateCookie_TamperedSignature(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := SetStateCookie(rec, newSavedRequest(), testSecret); err != nil {
		t.Fatalf("SetStateCookie: %v", err)
	}
	c := rec.Result().Cookies()[0]

	// Flip the signature part.
	parts := strings.SplitN(c.Value, ".", 2)
	tampered := parts[0] + "." + "AAAA" + parts[1]

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tampered})

	_, err := ReadStateCookie(req, testSecret)
	if err == nil {
		t.Error("expected error for tampered signature")
	}
}

func TestReadStateCookie_TamperedPayload(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := SetStateCookie(rec, newSavedRequest(), testSecret); err != nil {
		t.Fatalf("SetStateCookie: %v", err)
	}
	c := rec.Result().Cookies()[0]

	// Replace the payload with a different (validly-encoded) SavedRequest;
	// the original signature no longer matches.
	other := &SavedRequest{Method: "DELETE", Path: "/admin", SavedAt: time.Now()}
	otherPayload, err := other.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	parts := strings.SplitN(c.Value, ".", 2)
	tampered := otherPayload + "." + parts[1]

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tampered})

	_, err = ReadStateCookie(req, testSecret)
	if err == nil {
		t.Error("expected signature failure when payload swapped under old signature")
	}
}

func TestReadStateCookie_WrongSecret(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := SetStateCookie(rec, newSavedRequest(), testSecret); err != nil {
		t.Fatalf("SetStateCookie: %v", err)
	}
	c := rec.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)

	_, err := ReadStateCookie(req, "a-completely-different-secret")
	if err == nil {
		t.Error("expected error when verifying with a different secret")
	}
}

func TestReadStateCookie_Expired(t *testing.T) {
	// Manually craft a cookie whose SavedAt is older than cookieMaxAge.
	rec := httptest.NewRecorder()
	stale := newSavedRequest()
	stale.SavedAt = time.Now().Add(-(cookieMaxAge + 60) * time.Second)
	if err := SetStateCookie(rec, stale, testSecret); err != nil {
		t.Fatalf("SetStateCookie: %v", err)
	}
	c := rec.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)

	_, err := ReadStateCookie(req, testSecret)
	if err == nil {
		t.Error("expected error for expired (stale SavedAt) cookie")
	}
	if err != nil && !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expiry error, got: %v", err)
	}
}

func TestClearStateCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearStateCookie(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != CookieName {
		t.Errorf("Name: got %q, want %q", c.Name, CookieName)
	}
	if c.MaxAge >= 0 {
		t.Errorf("clear cookie MaxAge should be negative, got %d", c.MaxAge)
	}
	if c.Value != "" {
		t.Errorf("clear cookie value should be empty, got %q", c.Value)
	}
}

// --- signPayload determinism ---

func TestSignPayload(t *testing.T) {
	a := signPayload("hello", "key1")
	b := signPayload("hello", "key1")
	if a != b {
		t.Error("signPayload must be deterministic for same input")
	}
	if a == "" {
		t.Error("signature must not be empty")
	}
	if signPayload("hello", "key2") == a {
		t.Error("different keys must produce different signatures")
	}
	if signPayload("world", "key1") == a {
		t.Error("different payloads must produce different signatures")
	}
}

func TestNewStateID(t *testing.T) {
	a := newStateID()
	b := newStateID()
	if a == "" || b == "" {
		t.Fatal("state ID must not be empty")
	}
	if len(a) != 32 { // 16 random bytes hex-encoded
		t.Errorf("state ID length: got %d, want 32", len(a))
	}
	if a == b {
		t.Error("two state IDs should differ (random collision is astronomically unlikely)")
	}
}
