// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// actionMetrics instruments the native action path. All methods accept a nil
// receiver so unit-built owners and clients need no metrics wiring.
type actionMetrics struct {
	calls    *prometheus.CounterVec
	duration *prometheus.HistogramVec
	poolWait *prometheus.HistogramVec
	held     *prometheus.CounterVec
	overflow prometheus.Counter
	pressure prometheus.Counter
}

var rpcBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}

func newActionMetrics(r prometheus.Registerer) *actionMetrics {
	f := promauto.With(r)
	return &actionMetrics{
		calls: f.NewCounterVec(prometheus.CounterOpts{
			Name: "alertmanager_oscar_native_calls_total",
			Help: "Native action journal calls to OSCAR by command and outcome.",
		}, []string{"command", "outcome"}),
		duration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "alertmanager_oscar_native_call_duration_seconds",
			Help:    "Duration of native action journal calls to OSCAR, including connection pool waits.",
			Buckets: rpcBuckets,
		}, []string{"command"}),
		poolWait: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "alertmanager_oscar_native_pool_wait_seconds",
			Help:    "Connection acquisition time (pool wait, dial and TLS) of native action calls to OSCAR, by pool (delivery or lease).",
			Buckets: rpcBuckets,
		}, []string{"pool"}),
		held: f.NewCounterVec(prometheus.CounterOpts{
			Name: "alertmanager_oscar_native_held_total",
			Help: "Native receiver members held for a later flush, by reason and member state.",
		}, []string{"reason", "state"}),
		overflow: f.NewCounter(prometheus.CounterOpts{
			Name: "alertmanager_oscar_native_handoff_overflow_total",
			Help: "Lifecycle hand-offs that overflowed their per-alert transition bound and held their source bucket.",
		}),
		pressure: f.NewCounter(prometheus.CounterOpts{
			Name: "alertmanager_oscar_native_handoff_backpressure_total",
			Help: "Enrollments refused (retryable NATIVE_UNAVAILABLE) because queued hand-offs reached their bound.",
		}),
	}
}

func (m *actionMetrics) observeCall(cmd, outcome string, d time.Duration) {
	if m != nil {
		m.calls.WithLabelValues(cmd, outcome).Inc()
		m.duration.WithLabelValues(cmd).Observe(d.Seconds())
	}
}

func (m *actionMetrics) observePoolWait(pool string, d time.Duration) {
	if m != nil {
		m.poolWait.WithLabelValues(pool).Observe(d.Seconds())
	}
}

func (m *actionMetrics) handoffOverflow() {
	if m != nil {
		m.overflow.Inc()
	}
}

func (m *actionMetrics) handoffBackpressure() {
	if m != nil {
		m.pressure.Inc()
	}
}

var heldCode = regexp.MustCompile(`^[A-Z][A-Z_]{0,63}$`)

// heldReason bounds label cardinality: protocol reason codes pass through,
// anything else (joined or free-text errors) is OTHER.
func heldReason(err error) string {
	var code actionError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT"
	case errors.Is(err, context.Canceled):
		return "CANCELED"
	case err != nil && heldCode.MatchString(err.Error()):
		return err.Error()
	case errors.As(err, &code) && heldCode.MatchString(code.reason):
		return code.reason // a wrapped protocol code
	}
	return "OTHER"
}

// transportOutcome labels a failed request or body read.
func transportOutcome(err error) string {
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	return "unavailable"
}

// CountHeld records one native receiver member held for a later flush.
func (o *nativeActionOwner) CountHeld(err error, resolved bool) {
	if o.metrics == nil {
		return
	}
	state := "firing"
	if resolved {
		state = "resolved"
	}
	o.metrics.held.WithLabelValues(heldReason(err), state).Inc()
}
