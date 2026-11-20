// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

package mem

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/store"
)

// This opt-in qualification gate records requirements for the proposed TL1
// managed path. It exercises the real provider, without a running service.
// A failure is evidence to investigate; it does not establish receiver/history
// behavior or authorize changing the ordinary Prometheus publication contract.
func TestTL1LifecycleQualification(t *testing.T) {
	if os.Getenv("OSCAR_TL1_LIFECYCLE_PROOF") != "1" {
		t.Skip("opt-in proposed TL1 lifecycle qualification; no service required")
	}
	newProvider := func(t *testing.T) *Alerts {
		p, err := NewAlerts(t.Context(), time.Hour, 0, noopCallback{}, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
		require.NoError(t, err)
		return p
	}
	newProblem := func(severity string, start, received time.Time) *alert.Alert {
		return alert.New(model.Alert{
			Labels: model.LabelSet{
				"alertname": "TL1 LOS", "source": "tl1", "integration": "tl1_probe",
				"correlation_key": "tl1:synthetic-alarm:synthetic-episode", "severity": model.LabelValue(severity),
			},
			StartsAt: start, EndsAt: received.Add(time.Hour),
		}, received, true)
	}
	requireInactive := func(t *testing.T, p *Alerts, fp model.Fingerprint) {
		t.Helper()
		stored, err := p.Get(fp)
		if errors.Is(err, store.ErrNotFound) {
			return
		}
		require.NoError(t, err)
		require.True(t, stored.Resolved(), "expected the native variant to be inactive")
	}
	t.Run("severity_update_retires_superseded_native_variant", func(t *testing.T) {
		p := newProvider(t)
		now := time.Now()
		critical := newProblem("critical", now.Add(-time.Minute), now.Add(-time.Second))
		minor := newProblem("minor", critical.StartsAt, now)
		require.NoError(t, p.Put(t.Context(), critical))
		first, err := p.Get(critical.Fingerprint())
		require.NoError(t, err)
		require.False(t, first.Resolved(), "fixture must establish an active critical problem")
		require.NoError(t, p.Put(t.Context(), minor))
		replacement, err := p.Get(minor.Fingerprint())
		require.NoError(t, err)
		require.False(t, replacement.Resolved(), "the replacement severity must be active")
		requireInactive(t, p, critical.Fingerprint())
	})
	t.Run("late_problem_cannot_reopen_successfully_cleared_episode", func(t *testing.T) {
		p := newProvider(t)
		now := time.Now()
		original := newProblem("critical", now.Add(-time.Minute), now.Add(-2*time.Second))
		require.NoError(t, p.Put(t.Context(), original))
		active, err := p.Get(original.Fingerprint())
		require.NoError(t, err)
		require.False(t, active.Resolved(), "fixture must establish an active original problem")
		cleared := alert.New(model.Alert{Labels: original.Labels.Clone(), StartsAt: original.StartsAt, EndsAt: now.Add(-time.Second)}, now.Add(-time.Second), false)
		require.NoError(t, p.Put(t.Context(), cleared))
		requireInactive(t, p, original.Fingerprint())
		late := newProblem("critical", original.StartsAt, now)
		// Rejection and harmless acceptance both satisfy the observable lifecycle contract.
		_ = p.Put(t.Context(), late)
		requireInactive(t, p, original.Fingerprint())
	})
}
