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

package store

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
)

func intervalAlert(now time.Time, start, end time.Duration) *alert.Alert {
	return alert.New(model.Alert{Labels: model.LabelSet{"alertname": "same", "instance": "one"}, StartsAt: now.Add(start), EndsAt: now.Add(end)}, now, false)
}

func TestSetUnlessObsoleteResolved(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name              string
		current, incoming *alert.Alert
		applied           bool
	}{
		{"obsolete", intervalAlert(now, -time.Hour, time.Hour), intervalAlert(now, -3*time.Hour, -2*time.Hour), false},
		{"later resolved retained", intervalAlert(now, -time.Hour, -time.Minute), intervalAlert(now, -3*time.Hour, -2*time.Hour), false},
		{"current clear", intervalAlert(now, -time.Hour, time.Hour), intervalAlert(now, -time.Hour, -time.Minute), true},
		{"overlap", intervalAlert(now, -time.Hour, time.Hour), intervalAlert(now, -2*time.Hour, -time.Minute), true},
		{"equal boundary", intervalAlert(now, -time.Hour, time.Hour), intervalAlert(now, -2*time.Hour, -time.Hour), true},
		{"no current", nil, intervalAlert(now, -3*time.Hour, -2*time.Hour), true},
		{"earlier firing", intervalAlert(now, -time.Hour, time.Hour), intervalAlert(now, -3*time.Hour, 2*time.Hour), true},
		{"future end", intervalAlert(now, 2*time.Hour, 3*time.Hour), intervalAlert(now, -time.Hour, time.Hour), true},
		{"timeout", intervalAlert(now, -time.Hour, time.Hour), intervalAlert(now, -3*time.Hour, -2*time.Hour), true},
		{"zero end", intervalAlert(now, -time.Hour, time.Hour), intervalAlert(now, -3*time.Hour, -2*time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAlerts()
			if tc.current != nil {
				require.NoError(t, a.Set(tc.current))
			}
			if tc.name == "timeout" {
				tc.incoming.Timeout = true
			}
			if tc.name == "zero end" {
				tc.incoming.EndsAt = time.Time{}
			}
			applied, err := a.SetUnlessObsoleteResolved(tc.incoming)
			require.NoError(t, err)
			require.Equal(t, tc.applied, applied)
			got, err := a.Get(tc.incoming.Fingerprint())
			require.NoError(t, err)
			expected := tc.current
			if tc.applied {
				expected = tc.incoming
			}
			require.Same(t, expected, got)
		})
	}
}

func TestSetUnlessObsoleteResolvedLimitAndDestroyed(t *testing.T) {
	now := time.Now()
	a := NewAlerts().WithPerAlertLimit(1)
	current := intervalAlert(now, -time.Hour, time.Hour)
	late := intervalAlert(now, -3*time.Hour, -2*time.Hour)
	other := intervalAlert(now, -time.Hour, time.Hour)
	other.Labels = model.LabelSet{"alertname": "same", "instance": "two"}
	other = alert.New(other.Alert, other.UpdatedAt, other.Timeout)
	applied, err := a.SetUnlessObsoleteResolved(current)
	require.NoError(t, err)
	require.True(t, applied)
	applied, err = a.SetUnlessObsoleteResolved(late)
	require.NoError(t, err)
	require.False(t, applied)
	applied, err = a.SetUnlessObsoleteResolved(other)
	require.ErrorIs(t, err, ErrLimited)
	require.False(t, applied)
	require.Equal(t, 1, a.Len())
	require.Empty(t, a.GC())
	// A legitimate current resolution still expires its limit bucket and is GC-able.
	resolved := intervalAlert(now, -time.Hour, -time.Minute)
	applied, err = a.SetUnlessObsoleteResolved(resolved)
	require.NoError(t, err)
	require.True(t, applied)
	applied, err = a.SetUnlessObsoleteResolved(other)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, []*alert.Alert{resolved}, a.GC())
	require.NoError(t, a.DeleteIfNotModified(alert.AlertSlice{other}, true))
	require.True(t, a.Destroyed())
	applied, err = a.SetUnlessObsoleteResolved(late)
	require.ErrorIs(t, err, ErrDestroyed)
	require.False(t, applied)
	require.True(t, a.Empty())
}

func TestSetRemainsUnconditional(t *testing.T) {
	now := time.Now()
	a := NewAlerts()
	current := intervalAlert(now, -time.Hour, time.Hour)
	old := intervalAlert(now, -3*time.Hour, -2*time.Hour)
	require.NoError(t, a.Set(current))
	require.NoError(t, a.Set(old))
	got, err := a.Get(old.Fingerprint())
	require.NoError(t, err)
	require.Same(t, old, got)
}

func TestSetUnlessObsoleteResolvedConcurrentFlush(t *testing.T) {
	now := time.Now()
	a := NewAlerts()
	current := intervalAlert(now, -time.Hour, time.Hour)
	old := intervalAlert(now, -3*time.Hour, -2*time.Hour)
	old.UpdatedAt = now.Add(-time.Second)
	require.NoError(t, a.Set(current))
	var wg sync.WaitGroup
	errors := make(chan error, 50)
	for range 50 {
		wg.Go(func() {
			_, err := a.SetUnlessObsoleteResolved(old)
			if err != nil {
				errors <- err
			}
		})
		wg.Go(func() { a.DeleteIfNotModified(alert.AlertSlice{old}, true); a.GC() })
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	got, err := a.Get(current.Fingerprint())
	require.NoError(t, err)
	require.Same(t, current, got)
	require.False(t, a.Destroyed())
}
