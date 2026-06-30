package grpc_test

import (
	"context"
	"testing"
	"time"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/rar"
	"github.com/common-iam/iam/pkg/core/token"
	iamgrpc "github.com/common-iam/iam/pkg/middleware/grpc"
	"github.com/common-iam/iam/pkg/providers"
)

// --- fake provider ---

type fakeProvider struct {
	claims *token.CommonClaims
	err    error
}

func (f *fakeProvider) Introspect(_ context.Context, _ string) (*token.CommonClaims, error) {
	return f.claims, f.err
}
func (f *fakeProvider) JWKS(_ context.Context) ([]byte, error)  { return nil, nil }
func (f *fakeProvider) RefreshConfig(_ context.Context) error    { return nil }
func (f *fakeProvider) Name() string                             { return "fake" }
func (f *fakeProvider) Issuer() string                           { return "https://fake.as" }

var _ providers.Provider = (*fakeProvider)(nil)

// --- fake stream ---

type fakeStream struct {
	grpclib.ServerStream
	ctx context.Context
}

func (f *fakeStream) Context() context.Context { return f.ctx }

// --- helpers ---

func ctxWithBearer(t *testing.T, tok string) context.Context {
	t.Helper()
	md := metadata.Pairs("authorization", "Bearer "+tok)
	return metadata.NewIncomingContext(context.Background(), md)
}

func activeClaims() *token.CommonClaims {
	return &token.CommonClaims{
		Subject:  "user-1",
		Active:   true,
		Scopes:   []string{"read"},
		ACR:      "silver",
		AuthTime: time.Now(),
	}
}

func allowAllEngine() *policy.Engine {
	return policy.New(&policy.Config{
		Policies: []policy.Policy{
			{Name: "allow-all", Resources: []string{"/**"}, Enabled: true},
		},
	})
}

// --- tests ---

func TestUnaryInterceptor_ValidToken(t *testing.T) {
	cfg := iamgrpc.Config{
		Provider:     &fakeProvider{claims: activeClaims()},
		PolicyEngine: allowAllEngine(),
	}
	interceptor := iamgrpc.UnaryInterceptor(cfg)

	called := false
	_, err := interceptor(
		ctxWithBearer(t, "valid-token"),
		nil,
		&grpclib.UnaryServerInfo{FullMethod: "/svc.Service/Read"},
		func(ctx context.Context, req interface{}) (interface{}, error) {
			called = true
			// Claims must be reachable from context.
			if _, ok := iamgrpc.ClaimsFromContext(ctx); !ok {
				t.Error("claims not in context")
			}
			return "ok", nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("handler was not called")
	}
}

func TestUnaryInterceptor_MissingToken(t *testing.T) {
	cfg := iamgrpc.Config{
		Provider: &fakeProvider{claims: activeClaims()},
	}
	interceptor := iamgrpc.UnaryInterceptor(cfg)

	// No metadata at all.
	_, err := interceptor(
		context.Background(),
		nil,
		&grpclib.UnaryServerInfo{FullMethod: "/svc.Service/Read"},
		func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil },
	)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got: %v", err)
	}
}

func TestUnaryInterceptor_InactiveToken(t *testing.T) {
	inactive := activeClaims()
	inactive.Active = false
	cfg := iamgrpc.Config{Provider: &fakeProvider{claims: inactive}}
	interceptor := iamgrpc.UnaryInterceptor(cfg)

	_, err := interceptor(
		ctxWithBearer(t, "inactive"),
		nil,
		&grpclib.UnaryServerInfo{FullMethod: "/svc.Service/Read"},
		func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil },
	)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got: %v", err)
	}
}

func TestUnaryInterceptor_PolicyDenied(t *testing.T) {
	cfg := iamgrpc.Config{
		Provider:     &fakeProvider{claims: activeClaims()},
		PolicyEngine: policy.New(&policy.Config{}), // deny all
	}
	interceptor := iamgrpc.UnaryInterceptor(cfg)

	_, err := interceptor(
		ctxWithBearer(t, "valid"),
		nil,
		&grpclib.UnaryServerInfo{FullMethod: "/svc.Service/Write"},
		func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil },
	)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got: %v", err)
	}
}

func TestStreamInterceptor_ValidToken(t *testing.T) {
	cfg := iamgrpc.Config{
		Provider:     &fakeProvider{claims: activeClaims()},
		PolicyEngine: allowAllEngine(),
	}
	interceptor := iamgrpc.StreamInterceptor(cfg)

	called := false
	err := interceptor(
		nil,
		&fakeStream{ctx: ctxWithBearer(t, "valid-token")},
		&grpclib.StreamServerInfo{FullMethod: "/svc.Service/Watch"},
		func(_ interface{}, stream grpclib.ServerStream) error {
			called = true
			if _, ok := iamgrpc.ClaimsFromContext(stream.Context()); !ok {
				t.Error("claims not in stream context")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("stream handler was not called")
	}
}

func TestStreamInterceptor_Unauthenticated(t *testing.T) {
	cfg := iamgrpc.Config{Provider: &fakeProvider{claims: activeClaims()}}
	interceptor := iamgrpc.StreamInterceptor(cfg)

	err := interceptor(
		nil,
		&fakeStream{ctx: context.Background()},
		&grpclib.StreamServerInfo{FullMethod: "/svc.Service/Watch"},
		func(_ interface{}, _ grpclib.ServerStream) error { return nil },
	)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got: %v", err)
	}
}

func TestUnaryInterceptor_ACRPolicyCheck(t *testing.T) {
	// Policy requires silver ACR. Token has bronze → denied.
	bronze := activeClaims()
	bronze.ACR = "bronze"

	cfg := iamgrpc.Config{
		Provider: &fakeProvider{claims: bronze},
		PolicyEngine: policy.New(&policy.Config{
			ACRLevels: []string{"bronze", "silver"},
			Policies: []policy.Policy{
				{Name: "secure", Resources: []string{"/**"}, RequireACR: "silver", Enabled: true},
			},
		}),
	}
	interceptor := iamgrpc.UnaryInterceptor(cfg)

	_, err := interceptor(
		ctxWithBearer(t, "bronze-token"),
		nil,
		&grpclib.UnaryServerInfo{FullMethod: "/svc.Service/Op"},
		func(_ context.Context, _ interface{}) (interface{}, error) { return nil, nil },
	)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for insufficient ACR, got: %v", err)
	}
}

func TestUnaryInterceptor_AuthorizationDetails(t *testing.T) {
	claims := activeClaims()
	claims.AuthorizationDetails = []rar.AuthorizationDetail{{Type: "payment_initiation"}}

	cfg := iamgrpc.Config{
		Provider: &fakeProvider{claims: claims},
		PolicyEngine: policy.New(&policy.Config{
			Policies: []policy.Policy{
				{
					Name:      "payments",
					Resources: []string{"/**"},
					Enabled:   true,
					RequireAuthorizationDetails: []rar.AuthorizationDetailFilter{
						{Type: "payment_initiation"},
					},
				},
			},
		}),
	}
	interceptor := iamgrpc.UnaryInterceptor(cfg)

	_, err := interceptor(
		ctxWithBearer(t, "payment-token"),
		nil,
		&grpclib.UnaryServerInfo{FullMethod: "/payments.Service/Initiate"},
		func(_ context.Context, _ interface{}) (interface{}, error) { return "done", nil },
	)
	if err != nil {
		t.Errorf("expected success with matching authorization_details: %v", err)
	}
}

func TestClaimsFromContext_Missing(t *testing.T) {
	_, ok := iamgrpc.ClaimsFromContext(context.Background())
	if ok {
		t.Error("should return false for context without claims")
	}
}
