// Copyright 2018 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mem

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/eventrecorder"
)

func TestConversionResolutionCurrentOnly(t *testing.T) {
	t.Parallel()
	p, err := NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
	require.NoError(t, err)
	now := time.Now()
	start := now.Add(-time.Minute).Truncate(time.Microsecond)
	original := alert.New(model.Alert{
		Labels:      model.LabelSet{"alertname": "A", "host": "h"},
		Annotations: model.LabelSet{"__oscar_fingerprint_conversion": "producer-a", "summary": "unchanged"},
		StartsAt:    start, EndsAt: now.Add(time.Hour), GeneratorURL: "http://example.test",
	}, now, false)
	require.NoError(t, p.Put(context.Background(), original))
	clear := *original
	clear.Annotations = original.Annotations.Clone()
	clear.Annotations["__oscar_fingerprint_conversion_resolution"] = model.LabelValue(alert.ConversionResolutionReceipt(original))
	clear.StartsAt = start.Truncate(time.Millisecond) // actual native GET serialization.
	clear.EndsAt = now.Add(-time.Second)
	require.NoError(t, p.PutResolvedConversion(t.Context(), &clear))
	stored, err := p.Get(original.Fingerprint())
	require.NoError(t, err)
	require.True(t, stored.Resolved())
	require.Equal(t, original.Annotations, stored.Annotations)
	require.Equal(t, start, stored.StartsAt)
	for _, change := range []func(*alert.Alert){
		func(a *alert.Alert) { a.EndsAt = now.Add(time.Hour) },
		func(a *alert.Alert) { a.StartsAt = now.Add(-time.Hour) },
		func(a *alert.Alert) { a.Annotations = model.LabelSet{"__oscar_fingerprint_conversion": "producer-b"} },
		func(a *alert.Alert) { a.Labels = model.LabelSet{"alertname": "missing"} },
		func(a *alert.Alert) { a.GeneratorURL = "http://changed.test" },
	} {
		changed := clear
		change(&changed)
		require.Error(t, p.PutResolvedConversion(t.Context(), &changed))
	}
}

func TestConversionResolutionCannotResurrectReplacedOrDeletedState(t *testing.T) {
	t.Parallel()
	for _, action := range []string{"ordinary", "new-producer", "new-episode", "same-capsule-refresh", "removed"} {
		t.Run(action, func(t *testing.T) {
			p, err := NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
			require.NoError(t, err)
			now := time.Now()
			old := alert.New(model.Alert{
				Labels:      model.LabelSet{"alertname": "A"},
				Annotations: model.LabelSet{"__oscar_fingerprint_conversion": "old"},
				StartsAt:    now.Add(-time.Minute), EndsAt: now.Add(time.Hour),
			}, now, false)
			if action == "removed" {
				old.EndsAt = now.Add(-2 * time.Second)
			}
			require.NoError(t, p.Put(t.Context(), old))
			clear := *old
			clear.Annotations = old.Annotations.Clone()
			clear.Annotations["__oscar_fingerprint_conversion_resolution"] = model.LabelValue(alert.ConversionResolutionReceipt(old))
			clear.EndsAt = now.Add(-time.Second)
			// Hold the actual provider lock while a continuation queues behind a replacement/removal.
			p.mtx.Lock()
			done := make(chan error, 1)
			go func() { done <- p.PutResolvedConversion(t.Context(), &clear) }()
			replacement := *old
			replacement.Annotations = old.Annotations.Clone()
			switch action {
			case "ordinary":
				replacement.Annotations = model.LabelSet{}
			case "new-producer":
				replacement.Annotations["__oscar_fingerprint_conversion"] = "new"
			case "same-capsule-refresh":
				replacement.UpdatedAt = now.Add(time.Second)
			case "new-episode":
				replacement.StartsAt = now
				replacement.Annotations["__oscar_fingerprint_conversion"] = "new"
			}
			if action == "removed" {
				require.Len(t, p.alerts.GC(), 1)
			} else {
				require.NoError(t, p.alerts.Set(&replacement))
			}
			p.mtx.Unlock()
			require.Error(t, <-done)
			if action == "removed" {
				_, err = p.Get(old.Fingerprint())
				require.Error(t, err)
			} else {
				current, err := p.Get(old.Fingerprint())
				require.NoError(t, err)
				require.Equal(t, replacement.Annotations, current.Annotations)
				require.False(t, current.Resolved())
			}
		})
	}
}

func TestConversionResolutionClockTolerance(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested time.Duration
		accepted  bool
	}{
		{"past", -time.Nanosecond, true},
		{"now", 0, true},
		{"future-clamped", time.Nanosecond, true},
		{"five-seconds-clamped", 5 * time.Second, true},
		{"beyond-five-seconds", 5*time.Second + time.Nanosecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now()
				p, err := NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
				require.NoError(t, err)
				defer p.Close()
				old := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "A"}, Annotations: model.LabelSet{conversionAnnotation: "owned"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
				require.NoError(t, p.Put(t.Context(), old))
				incoming := *old
				incoming.Annotations = old.Annotations.Clone()
				incoming.Annotations["__oscar_fingerprint_conversion_resolution"] = model.LabelValue(alert.ConversionResolutionReceipt(old))
				incoming.EndsAt = now.Add(tc.requested)
				err = p.PutResolvedConversion(t.Context(), &incoming)
				current, lookup := p.Get(old.Fingerprint())
				require.NoError(t, lookup)
				if !tc.accepted {
					require.Error(t, err)
					require.Equal(t, old.EndsAt, current.EndsAt)
					return
				}
				require.NoError(t, err)
				require.False(t, current.EndsAt.After(now))
				require.Equal(t, old.StartsAt, current.StartsAt)
				require.Equal(t, old.Annotations, current.Annotations)
				if tc.requested > 0 {
					require.Equal(t, now, current.EndsAt)
				} else {
					require.Equal(t, incoming.EndsAt, current.EndsAt)
				}
			})
		})
	}
}

func TestConversionResolutionCannotExtendAlreadyResolvedEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		p, err := NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
		require.NoError(t, err)
		defer p.Close()
		old := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "A"}, Annotations: model.LabelSet{conversionAnnotation: "owned"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(-time.Second)}, now, false)
		require.NoError(t, p.Put(t.Context(), old))
		incoming := *old
		incoming.Annotations = old.Annotations.Clone()
		incoming.Annotations["__oscar_fingerprint_conversion_resolution"] = model.LabelValue(alert.ConversionResolutionReceipt(old))
		incoming.EndsAt = now.Add(time.Second)
		require.Error(t, p.PutResolvedConversion(t.Context(), &incoming))
		current, err := p.Get(old.Fingerprint())
		require.NoError(t, err)
		require.Equal(t, old.EndsAt, current.EndsAt)
	})
}
