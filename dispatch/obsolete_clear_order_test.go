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

package dispatch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/provider/mem"
)

// Hold the actual dispatch worker at its existing pre-routing log call. The
// provider, subscription, worker loop, route, group insertion and group read
// remain real. This models scheduling delay without changing production code.
type obsoleteClearLogHold struct {
	old              *alert.Alert
	entered, release chan struct{}
	once             sync.Once
}

func (h *obsoleteClearLogHold) Enabled(context.Context, slog.Level) bool { return true }
func (h *obsoleteClearLogHold) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *obsoleteClearLogHold) WithGroup(string) slog.Handler            { return h }
func (h *obsoleteClearLogHold) Handle(_ context.Context, record slog.Record) error {
	if record.Message == "Received alert" {
		record.Attrs(func(attr slog.Attr) bool {
			if attr.Key == "alert" && attr.Value.Any() == h.old {
				h.once.Do(func() { close(h.entered); <-h.release })
			}
			return true
		})
	}
	return nil
}

func TestDispatcherQueuedObsoleteClearKeepsLaterInterval(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		name := "in_order"
		if delayed {
			name = "old_clear_delayed"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			old := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "same", "instance": "one"},
				StartsAt: now.Add(-3 * time.Hour), EndsAt: now.Add(-2 * time.Hour)}, now, false)
			current := alert.New(model.Alert{Labels: old.Labels, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}, now.Add(time.Second), false)
			hold := &obsoleteClearLogHold{old: old, entered: make(chan struct{}), release: make(chan struct{})}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(hold.release) }) }
			defer release()
			cfg, err := config.Load("receivers:\n- name: test\nroute:\n  receiver: test\n  group_by: ['alertname']\n  group_wait: 24h\n")
			require.NoError(t, err)
			registry := prometheus.NewRegistry()
			provider, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), registry, nil)
			require.NoError(t, err)
			defer provider.Close()
			dispatcher := NewDispatcher(provider, NewRoute(cfg.Route, nil), nil, nil, func(d time.Duration) time.Duration { return d },
				time.Hour, nil, slog.New(hold), eventrecorder.NopRecorder(), NewDispatcherMetrics(false, registry, nil), nil)
			require.GreaterOrEqual(t, dispatcher.concurrency, 2)
			// The real worker loop consumes now; the long group wait keeps notifications
			// dormant, so this asserts aggregation state rather than receiver delivery.
			go dispatcher.Run(now)
			defer func() {
				release()
				dispatcher.Stop()
				dispatcher.startTimer.Stop()
				for i := range dispatcher.routeGroupsSlice {
					dispatcher.routeGroupsSlice[i].groups.Range(func(_, value any) bool {
						group := value.(*aggrGroup)
						if group.running.Load() {
							group.stop()
						} else {
							group.cancel()
						}
						group.next.Stop()
						return true
					})
				}
			}()
			select {
			case <-dispatcher.LoadingDone():
			case <-time.After(5 * time.Second):
				t.Fatal("dispatcher did not subscribe")
			}
			read := func() *alert.Alert {
				groups, _, err := dispatcher.Groups(t.Context(), func(*Route) bool { return true }, func(*alert.Alert, time.Time) (alert.AlertStatus, bool) { return alert.AlertStatus{}, true })
				if err != nil || len(groups) != 1 || len(groups[0].Alerts) != 1 {
					return nil
				}
				return groups[0].Alerts[0]
			}
			require.NoError(t, provider.Put(t.Context(), old))
			select {
			case <-hold.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("old clear did not reach worker")
			}
			if !delayed {
				release()
				require.Eventually(t, func() bool { return read() == old }, 5*time.Second, time.Millisecond)
			}
			require.NoError(t, provider.Put(t.Context(), current))
			require.Eventually(t, func() bool { return read() == current }, 5*time.Second, time.Millisecond)
			stored, err := provider.Get(current.Fingerprint())
			require.NoError(t, err)
			require.Same(t, current, stored)
			release()
			// Joining the actual dispatch workers guarantees the held old operation has
			// finished before the safety assertion; no polling for a desired failure.
			dispatcher.Stop()
			got := read()
			require.NotNil(t, got)
			t.Logf("provider resolved=%v, aggregation resolved=%v", stored.Resolved(), got.Resolved())
			require.Equal(t, current.StartsAt, got.StartsAt, "queued old clear replaced newer aggregation interval")
			require.False(t, got.Resolved(), "queued old clear made active aggregation appear resolved")
		})
	}
}

func TestAggrGroupObsoleteClearSkipsSideEffects(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	recorder := eventrecorder.NewRecorderFromConfig(eventrecorder.Config{FileOutputs: []eventrecorder.FileOutputConfig{{Name: "events", Path: path}}}, "test", promslog.NewNopLogger(), nil)
	defer recorder.Close()
	route := &Route{RouteOpts: RouteOpts{Receiver: "test", GroupWait: time.Hour}}
	group := newAggrGroup(t.Context(), model.LabelSet{"alertname": "same"}, route, nil, recorder, promslog.NewNopLogger(), nil)
	defer group.cancel()
	defer group.next.Stop()
	current := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "same"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}, now, false)
	old := alert.New(model.Alert{Labels: current.Labels, StartsAt: now.Add(-3 * time.Hour), EndsAt: now.Add(-2 * time.Hour)}, now.Add(time.Second), false)
	ctx := eventrecorder.WithEventRecording(t.Context())
	require.True(t, group.insert(ctx, current))
	generation := group.routeLabelsGen.Load()
	require.True(t, group.insert(ctx, old))
	require.Equal(t, generation, group.routeLabelsGen.Load(), "ignored clear invalidated current route labels")
	resolved := *current
	resolved.EndsAt = now.Add(-time.Minute)
	resolved.UpdatedAt = now.Add(2 * time.Second)
	require.True(t, group.insert(ctx, &resolved))
	require.Equal(t, generation+1, group.routeLabelsGen.Load())
	require.NoError(t, recorder.Close())
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Len(t, strings.Split(strings.TrimSpace(string(raw)), "\n"), 2, "ignored clear recorded a grouped event")
	require.NoError(t, group.alerts.DeleteIfNotModified(alert.AlertSlice{&resolved}, true))
	require.False(t, group.insert(ctx, old), "destroyed group must still request replacement")
}

func TestAggrGroupIntervalCompatibility(t *testing.T) {
	for _, name := range []string{"current_clear", "overlap", "equal_boundary", "timeout", "earlier_firing", "no_current"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			route := &Route{RouteOpts: RouteOpts{Receiver: "test", GroupWait: time.Hour}}
			group := newAggrGroup(t.Context(), model.LabelSet{"alertname": "same"}, route, nil, eventrecorder.NopRecorder(), promslog.NewNopLogger(), nil)
			defer group.cancel()
			defer group.next.Stop()
			current := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "same", "instance": "one"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}, now, false)
			if name != "no_current" {
				require.True(t, group.insert(t.Context(), current))
			}
			incoming := *current
			incoming.EndsAt = now.Add(-time.Minute)
			switch name {
			case "overlap":
				incoming.StartsAt = now.Add(-2 * time.Hour)
			case "equal_boundary":
				incoming.StartsAt = now.Add(-2 * time.Hour)
				incoming.EndsAt = current.StartsAt
			case "timeout", "no_current":
				incoming.StartsAt = now.Add(-3 * time.Hour)
				incoming.EndsAt = now.Add(-2 * time.Hour)
				incoming.Timeout = name == "timeout"
			case "earlier_firing":
				incoming.StartsAt = now.Add(-3 * time.Hour)
				incoming.EndsAt = now.Add(2 * time.Hour)
			}
			require.True(t, group.insert(t.Context(), &incoming))
			got, err := group.alerts.Get(current.Fingerprint())
			require.NoError(t, err)
			require.Same(t, &incoming, got)
		})
	}
}

func TestAggrGroupMixedInputsContinueAfterObsoleteClear(t *testing.T) {
	now := time.Now()
	route := &Route{RouteOpts: RouteOpts{Receiver: "test", GroupWait: time.Hour}}
	group := newAggrGroup(t.Context(), model.LabelSet{"alertname": "same"}, route, nil, eventrecorder.NopRecorder(), promslog.NewNopLogger(), nil)
	defer group.cancel()
	defer group.next.Stop()
	current := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "same", "instance": "one"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}, now, false)
	old := *current
	old.StartsAt, old.EndsAt = now.Add(-3*time.Hour), now.Add(-2*time.Hour)
	sibling := *current
	sibling.Labels = model.LabelSet{"alertname": "same", "instance": "two"}
	sibling = *alert.New(sibling.Alert, sibling.UpdatedAt, sibling.Timeout)
	require.True(t, group.insert(t.Context(), current))
	for _, incoming := range []*alert.Alert{&old, &sibling} {
		require.True(t, group.insert(t.Context(), incoming))
	}
	got, err := group.alerts.Get(current.Fingerprint())
	require.NoError(t, err)
	require.Same(t, current, got)
	got, err = group.alerts.Get(sibling.Fingerprint())
	require.NoError(t, err)
	require.Same(t, &sibling, got)
	require.Equal(t, 2, group.alerts.Len())
}
