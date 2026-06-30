// Package grpc provides gRPC server interceptors for IAM authentication and
// authorization. The interceptors mirror the HTTP middleware adapters (gin, echo,
// stdlib) but operate over gRPC metadata instead of HTTP headers.
//
// Usage:
//
//	grpc.NewServer(
//	    grpc.ChainUnaryInterceptor(iamgrpc.UnaryInterceptor(iamgrpc.Config{...})),
//	    grpc.ChainStreamInterceptor(iamgrpc.StreamInterceptor(iamgrpc.Config{...})),
//	)
package grpc

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/common-iam/iam/pkg/core/policy"
	"github.com/common-iam/iam/pkg/core/token"
	"github.com/common-iam/iam/pkg/providers"
)

type contextKey int

const claimsKey contextKey = iota

// Config configures the IAM gRPC interceptors.
type Config struct {
	// Provider performs token introspection / JWT validation.
	Provider providers.Provider

	// PolicyEngine evaluates access policy. Optional — if nil, all
	// authenticated requests are forwarded to the handler.
	PolicyEngine *policy.Engine

	// Realm is the WWW-Authenticate realm reported in error details.
	Realm string

	// EnableDPoP enforces RFC 9449 DPoP proof-of-possession.
	EnableDPoP bool
}

// UnaryInterceptor returns a gRPC UnaryServerInterceptor that authenticates and
// authorizes incoming unary RPCs using the configured IAM provider and policy engine.
func UnaryInterceptor(cfg Config) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		ctx, err := authenticate(ctx, info.FullMethod, cfg)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor returns a gRPC StreamServerInterceptor that authenticates and
// authorizes incoming streaming RPCs.
func StreamInterceptor(cfg Config) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx, err := authenticate(ss.Context(), info.FullMethod, cfg)
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ss, ctx})
	}
}

// ClaimsFromContext retrieves CommonClaims attached by the interceptor.
func ClaimsFromContext(ctx context.Context) (*token.CommonClaims, bool) {
	c, ok := ctx.Value(claimsKey).(*token.CommonClaims)
	return c, ok
}

// authenticate is the shared auth logic for unary and stream interceptors.
func authenticate(ctx context.Context, fullMethod string, cfg Config) (context.Context, error) {
	rawToken, err := extractBearerFromMetadata(ctx)
	if err != nil {
		return ctx, status.Errorf(codes.Unauthenticated, "missing or invalid bearer token: %v", err)
	}

	claims, err := cfg.Provider.Introspect(ctx, rawToken)
	if err != nil || !claims.Active {
		return ctx, status.Error(codes.Unauthenticated, "token inactive or validation failed")
	}

	if cfg.PolicyEngine != nil {
		// gRPC method path is used as the resource path; method maps to "RPC".
		result, pErr := cfg.PolicyEngine.Evaluate(&policy.PolicyRequest{
			Method:               "RPC",
			Path:                 fullMethod,
			TokenACR:             claims.ACR,
			TokenAMR:             claims.AMR,
			TokenScopes:          claims.Scopes,
			AuthAge:              claims.AuthAge(),
			AuthorizationDetails: claims.AuthorizationDetails,
		})
		if pErr != nil {
			return ctx, status.Error(codes.Internal, "policy evaluation error")
		}
		if !result.Allowed {
			msg := "access denied"
			if result.RequiredACR != "" {
				msg = "insufficient authentication context: acr=" + result.RequiredACR + " required"
			} else if result.Reason != "" {
				msg = result.Reason
			}
			return ctx, status.Error(codes.PermissionDenied, msg)
		}
	}

	ctx = context.WithValue(ctx, claimsKey, claims)
	return ctx, nil
}

// extractBearerFromMetadata extracts the Bearer token from incoming gRPC metadata.
// gRPC clients send the Authorization header as metadata key "authorization".
func extractBearerFromMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return token.ExtractBearerToken("") // returns the "missing" error
	}
	return token.ExtractBearerToken(vals[0])
}

// wrappedStream replaces the stream's Context with the authenticated context.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

// MethodToPath extracts the path component from a gRPC full method name.
// "/pkg.Service/Method" → "/pkg.Service/Method" (kept as-is for policy matching).
func MethodToPath(fullMethod string) string {
	return strings.TrimPrefix(fullMethod, "/")
}
