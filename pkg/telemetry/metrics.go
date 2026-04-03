package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the IAM system.
type Metrics struct {
	// StepUpTotal counts step-up challenges issued.
	// Labels: tenant, required_acr, method, resource
	StepUpTotal *prometheus.CounterVec

	// StepUpSuccessTotal counts successful step-up completions.
	StepUpSuccessTotal *prometheus.CounterVec

	// TokenValidationDuration tracks introspection latency.
	// Labels: tenant, provider, cache_hit
	TokenValidationDuration *prometheus.HistogramVec

	// TokenCacheHitTotal counts cache hits vs misses.
	// Labels: tenant, result (hit|miss)
	TokenCacheHitTotal *prometheus.CounterVec

	// PolicyEvalDuration tracks policy engine evaluation latency.
	PolicyEvalDuration *prometheus.HistogramVec

	// PolicyDeniedTotal counts policy denials.
	// Labels: tenant, policy_name, reason
	PolicyDeniedTotal *prometheus.CounterVec

	// ActiveTenants is a gauge of currently registered tenants.
	ActiveTenants prometheus.Gauge
}

// NewMetrics registers and returns all IAM metrics with the given Prometheus registerer.
// Pass prometheus.DefaultRegisterer for the global registry, or a custom one for isolation.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	factory := promauto.With(reg)

	return &Metrics{
		StepUpTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_stepup_challenges_total",
			Help: "Total number of step-up authentication challenges issued.",
		}, []string{"tenant", "required_acr", "method"}),

		StepUpSuccessTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_stepup_success_total",
			Help: "Total number of successful step-up authentication completions.",
		}, []string{"tenant"}),

		TokenValidationDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "iam_token_validation_duration_seconds",
			Help:    "Duration of token validation (introspection + cache lookup).",
			Buckets: prometheus.DefBuckets,
		}, []string{"tenant", "provider", "cache_hit"}),

		TokenCacheHitTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_token_cache_total",
			Help: "Token cache hits and misses.",
		}, []string{"tenant", "result"}),

		PolicyEvalDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "iam_policy_eval_duration_seconds",
			Help:    "Duration of policy evaluation.",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01},
		}, []string{"tenant", "matched_policy"}),

		PolicyDeniedTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_policy_denied_total",
			Help: "Total number of requests denied by policy.",
		}, []string{"tenant", "policy_name", "reason"}),

		ActiveTenants: factory.NewGauge(prometheus.GaugeOpts{
			Name: "iam_active_tenants",
			Help: "Number of currently registered tenants.",
		}),
	}
}
