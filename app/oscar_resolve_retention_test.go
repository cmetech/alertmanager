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

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	v2 "github.com/prometheus/alertmanager/api/v2"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/provider/mem"
	"github.com/prometheus/alertmanager/store"
)

// OSC-137 AC-1/AC-2: the GC predicate keeps a resolve until the current
// graph's group has flushed it, including across a reload and while the
// resident is unknown.
func TestOscarActionKeepResolvedUntilGroupReleases(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now()
	s := alert.New(model.Alert{Labels: model.LabelSet{"host": "one"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(-time.Second)}, now, false)
	j := &recoveryFixture{classify: func(context.Context, uint64, *alert.Alert) (*v2.EpisodeProjection, error) { return nil, nil }}
	j.epoch.Store(1)
	a := newNativeActions(nil, nil, r.logger)
	r.actions = a
	require.NoError(t, a.Bind(j))
	a.ObserveSource("", s, false, false)
	require.True(t, a.keepResolved(s), "AC-1: kept before any graph is installed")
	cfg, err := config.Load("route:\n  receiver: base\n  group_wait: 1h\nreceivers:\n- name: base\n")
	require.NoError(t, err)
	require.NoError(t, r.reload(cfg))
	require.Eventually(t, func() bool { return a.snapshot().dispatcher.HoldsProjection(s) }, 5*time.Second, time.Millisecond)
	require.True(t, a.keepResolved(s), "AC-1: kept while the group holds it")

	a.snapshot().dispatcher.RetireProjection(s)
	require.False(t, a.keepResolved(s), "AC-2: released once the group no longer holds it")

	a.InvalidateSource(s)
	require.True(t, a.keepResolved(s), "AC-1: an unknown resident is kept")
	require.Eventually(t, func() bool { return a.snapshot().dispatcher.HoldsProjection(s) }, 5*time.Second, time.Millisecond)

	a.pause()
	require.True(t, a.keepResolved(s), "AC-1: kept in the reload window without a graph")
	require.NoError(t, r.reload(cfg))
	require.Eventually(t, func() bool { return a.snapshot().dispatcher.HoldsProjection(s) }, 5*time.Second, time.Millisecond)
	require.True(t, a.keepResolved(s), "the new dispatcher's group holds it again")

	other := alert.New(model.Alert{Labels: model.LabelSet{"host": "one"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(-time.Second)}, now, false)
	require.False(t, a.keepResolved(other), "a source the resident no longer follows is not kept")
	plain := newNativeActions(nil, nil, r.logger)
	require.NoError(t, plain.Bind(&terminalFixtureJournal{}))
	plain.ObserveSource("", s, false, false)
	require.False(t, plain.keepResolved(s), "without a recovery journal GC is unchanged")
}

// OSC-137 AC-1/AC-2/AC-3 end to end: provider GC, the dispatcher and the
// native reader. A held resolve survives GC cycles; once delivered, the
// next GC collects it.
func TestOscarActionGCKeepsHeldResolveUntilDelivered(t *testing.T) {
	var resolvedSeen, firingSeen atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var data struct{ Alerts []struct{ Status string } }
		if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
			t.Error(err)
			return
		}
		for _, m := range data.Alerts {
			if m.Status == "resolved" {
				resolvedSeen.Add(1)
			} else {
				firingSeen.Add(1)
			}
		}
	}))
	defer sink.Close()
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	reg := prometheus.NewRegistry()
	provider, err := mem.NewAlerts(t.Context(), 20*time.Millisecond, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), reg, nil)
	require.NoError(t, err)
	t.Cleanup(provider.Close)
	r.alerts = provider
	r.dispatchMaintenanceInterval = 10 * time.Millisecond
	a := newNativeActions(nil, nil, r.logger)
	a.version = 1
	r.actions = a
	j := &heldResolveJournal{a: a}
	j.classify = func(context.Context, uint64, *alert.Alert) (*v2.EpisodeProjection, error) { return nil, nil }
	j.epoch.Store(1)
	j.receipts.Store(true)
	require.NoError(t, a.Bind(j))
	provider.SetActionObserver(func(owner string, s *alert.Alert, closed bool) { a.ObserveSource(owner, s, closed, false) })
	provider.SetGCRetain(a.keepResolved)
	registerKeptResolveMetrics(reg, provider)
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\n  group_by: [alertname]\n  group_wait: 50ms\n  group_interval: 200ms\n  repeat_interval: 1h\nreceivers:\n- name: team\n  incidentio_configs:\n  - url: %s\n    send_resolved: true\n    alert_source_token: test\n", sink.URL))
	require.NoError(t, err)
	require.NoError(t, r.reload(cfg))
	require.Eventually(t, func() bool { return a.Version() == 1 }, 5*time.Second, time.Millisecond)

	now := time.Now()
	labels := model.LabelSet{"alertname": "Alarm", "host": "one"}
	require.NoError(t, provider.Put(t.Context(), alert.New(model.Alert{Labels: labels, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)))
	require.Eventually(t, func() bool { return firingSeen.Load() == 1 }, 5*time.Second, 5*time.Millisecond)

	j.held.Store(true)
	end := time.Now()
	require.NoError(t, provider.Put(t.Context(), alert.New(model.Alert{Labels: labels, StartsAt: now, EndsAt: end}, end, false)))
	fp := labels.Fingerprint()
	heldFrom := j.inspected.Load()
	require.Eventually(t, func() bool { return j.inspected.Load() >= heldFrom+2 }, 5*time.Second, 5*time.Millisecond, "the resolve is held across flushes")
	g := a.snapshot()
	require.Never(t, func() bool {
		g.sweepRetired.Store(true) // the retired sweep runs on every maintenance tick
		_, err := provider.Get(fp)
		return err != nil || !g.dispatcher.HoldsProjection(alert.New(model.Alert{Labels: labels}, end, false))
	}, 300*time.Millisecond, 5*time.Millisecond, "AC-1: GC and the retired sweep keep the held resolve and its group")
	require.Zero(t, resolvedSeen.Load())
	require.Equal(t, 1.0, gaugeValue(t, reg, "alertmanager_oscar_native_unconfirmed_resolves"), "AC-3")
	require.Positive(t, gaugeValue(t, reg, "alertmanager_oscar_native_unconfirmed_resolve_oldest_age_seconds"), "AC-3")

	j.held.Store(false)
	require.Eventually(t, func() bool { return resolvedSeen.Load() == 1 }, 5*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { _, err := provider.Get(fp); return errors.Is(err, store.ErrNotFound) }, 5*time.Second, 5*time.Millisecond, "AC-2: collected after delivery")
	require.Eventually(t, func() bool {
		return gaugeValue(t, reg, "alertmanager_oscar_native_unconfirmed_resolves") == 0
	}, 5*time.Second, 5*time.Millisecond)
	require.Zero(t, gaugeValue(t, reg, "alertmanager_oscar_native_unconfirmed_resolve_oldest_age_seconds"))
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("metric %s not registered", name)
	return 0
}

// heldResolveJournal issues untracked direct passes, or holds every member
// while held is set, as an unavailable OSCAR would.
type heldResolveJournal struct {
	recoveryFixture
	a         *nativeActions
	held      atomic.Bool
	inspected atomic.Int32
}

func (j *heldResolveJournal) InspectOrdinary(_ context.Context, s *alert.Alert) (*v2.EpisodeProjection, *v2.OrdinaryPass, error) {
	j.inspected.Add(1)
	if j.held.Load() {
		return nil, nil, errors.New("NATIVE_UNAVAILABLE")
	}
	key, token, entered := residentKey(s.ActionOwner(), s), &v2.DirectContact{}, false
	return nil, &v2.OrdinaryPass{
		Epoch:   j.epoch.Load(),
		Contact: token,
		Enter:   func() bool { entered = j.a.ChangeDirectContact(key, nil, token); return entered },
		Valid:   func() bool { return entered && j.a.DirectContact(key) == token },
		Finish: func(conclusive bool) {
			if entered && conclusive {
				j.a.ChangeDirectContact(key, token, nil)
			}
			entered = false
		},
	}, nil
}
