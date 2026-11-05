// Copyright The Prometheus Authors
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
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/eventrecorder"
)

type clearCallback struct {
	noopCallback
	pre, post        int
	entered, release chan struct{}
}

func (c *clearCallback) PreStore(_ *alert.Alert, _ bool) error {
	c.pre++
	if c.entered != nil {
		entered, release := c.entered, c.release
		c.entered = nil
		close(entered)
		<-release
	}
	return nil
}
func (c *clearCallback) PostStore(_ *alert.Alert, _ bool) { c.post++ }

func clearProvider(t *testing.T, callback *clearCallback) *Alerts {
	t.Helper()
	a, err := NewAlerts(t.Context(), time.Hour, 0, callback, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(a.Close)
	return a
}
func clearInput(now time.Time, start, end time.Duration) *alert.Alert {
	return alert.New(model.Alert{
		Labels:      model.LabelSet{"alertname": "same", "instance": "one"},
		Annotations: model.LabelSet{"description": "original"},
		StartsAt:    now.Add(start), EndsAt: now.Add(end),
	}, now, false)
}

func TestObsoleteClearPreservesCurrentAndSubscribers(t *testing.T) {
	now := time.Now()
	cb := &clearCallback{}
	a := clearProvider(t, cb)
	// Real cycle: firing, explicit old resolution, disjoint new firing.
	oldFiring := clearInput(now, -3*time.Hour, time.Hour)
	oldClear := clearInput(now, -3*time.Hour, -2*time.Hour)
	current := clearInput(now, -time.Hour, time.Hour)
	require.NoError(t, a.Put(t.Context(), oldFiring, oldClear, current))
	it := a.Subscribe("test")
	defer it.Close()
	require.Same(t, current, (<-it.Next()).Data)
	beforePre, beforePost := cb.pre, cb.post
	duplicate := *oldClear
	duplicate.UpdatedAt = now.Add(time.Second)
	duplicate.Annotations = model.LabelSet{"description": "late clear"}
	require.NoError(t, a.Put(t.Context(), &duplicate))
	got, err := a.Get(current.Fingerprint())
	require.NoError(t, err)
	require.Same(t, current, got)
	require.Equal(t, beforePre, cb.pre)
	require.Equal(t, beforePost, cb.post)
	select {
	case msg := <-it.Next():
		t.Fatalf("obsolete clear reached subscriber: %v", msg.Data.EndsAt)
	default:
	}
	require.Empty(t, a.gcAlerts(), "obsolete clear must not make the current firing collectible")
	require.Equal(t, oldClear.StartsAt, duplicate.StartsAt)
	require.Equal(t, oldClear.EndsAt, duplicate.EndsAt)
}

func TestObsoleteClearCompatibility(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name              string
		current, incoming *alert.Alert
		merge             bool
	}{
		{"matched current clear", clearInput(now, -time.Hour, time.Hour), clearInput(now, -time.Hour, -time.Minute), true},
		{"overlapping clear", clearInput(now, -time.Hour, time.Hour), clearInput(now, -2*time.Hour, -time.Minute), true},
		{"equal boundary", clearInput(now, -time.Hour, time.Hour), clearInput(now, -2*time.Hour, -time.Hour), false},
		{"no current", nil, clearInput(now, -2*time.Hour, -time.Hour), false},
		{"earlier firing not rejected", clearInput(now, -time.Hour, time.Hour), clearInput(now, -2*time.Hour, 2*time.Hour), false},
		{"future explicit end", clearInput(now, 2*time.Hour, 4*time.Hour), clearInput(now, -time.Hour, time.Hour), false},
		{"implicit timeout", clearInput(now, -time.Hour, time.Hour), clearInput(now, -3*time.Hour, -2*time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cb := &clearCallback{}
			a := clearProvider(t, cb)
			if tc.name == "implicit timeout" {
				tc.incoming.Timeout = true
			}
			if tc.current != nil {
				require.NoError(t, a.Put(t.Context(), tc.current))
			}
			expected := tc.incoming
			if tc.merge {
				expected = tc.current.Merge(tc.incoming)
			}
			before := cb.post
			require.NoError(t, a.Put(t.Context(), tc.incoming))
			got, err := a.Get(tc.incoming.Fingerprint())
			require.NoError(t, err)
			require.NoError(t, alertDiff(expected, got))
			require.Equal(t, before+1, cb.post)
		})
	}
}

func TestObsoleteClearMixedBatch(t *testing.T) {
	now := time.Now()
	cb := &clearCallback{}
	a := clearProvider(t, cb)
	current := clearInput(now, -time.Hour, time.Hour)
	require.NoError(t, a.Put(t.Context(), current))
	it := a.Subscribe("test")
	defer it.Close()
	<-it.Next()
	late := clearInput(now, -3*time.Hour, -2*time.Hour)
	other := clearInput(now, -time.Hour, time.Hour)
	other.Labels = model.LabelSet{"alertname": "other"}
	other = alert.New(other.Alert, other.UpdatedAt, other.Timeout)
	matching := clearInput(now, -time.Hour, -time.Minute)
	require.NoError(t, a.Put(t.Context(), late, other, matching))
	require.Same(t, other, (<-it.Next()).Data)
	require.True(t, (<-it.Next()).Data.Resolved())
	select {
	case <-it.Next():
		t.Fatal("unexpected obsolete notification")
	default:
	}
	got, err := a.Get(current.Fingerprint())
	require.NoError(t, err)
	require.True(t, got.Resolved())
	require.Equal(t, matching.EndsAt, got.EndsAt)
}

func TestObsoleteClearConcurrentPutOrders(t *testing.T) {
	for _, clearFirst := range []bool{true, false} {
		name := "firing first"
		if clearFirst {
			name = "clear first"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			cb := &clearCallback{}
			a := clearProvider(t, cb)
			oldClear := clearInput(now, -3*time.Hour, -2*time.Hour)
			current := clearInput(now, -time.Hour, time.Hour)
			require.NoError(t, a.Put(t.Context(), oldClear))
			it := a.Subscribe("test")
			defer it.Close()
			<-it.Next()
			first, second := current, oldClear
			if clearFirst {
				first, second = oldClear, current
			}
			entered, release := make(chan struct{}), make(chan struct{})
			cb.entered, cb.release = entered, release
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			done := make(chan error, 2)
			go func() { done <- a.Put(context.Background(), first) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("first writer did not enter provider lock")
			}
			started := make(chan struct{})
			go func() { close(started); done <- a.Put(context.Background(), second) }()
			<-started
			releaseOnce.Do(func() { close(release) })
			for range 2 {
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(5 * time.Second):
					t.Fatal("writer did not join")
				}
			}
			got, err := a.Get(current.Fingerprint())
			require.NoError(t, err)
			require.Same(t, current, got)
			if clearFirst {
				require.Same(t, oldClear, (<-it.Next()).Data)
			}
			require.Same(t, current, (<-it.Next()).Data)
			select {
			case <-it.Next():
				t.Fatal("late clear followed current firing")
			default:
			}
		})
	}
}
