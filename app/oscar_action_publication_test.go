// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	v2 "github.com/prometheus/alertmanager/api/v2"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
)

type recoveryFixture struct {
	terminalFixtureJournal
	epoch     atomic.Uint64
	receipts  atomic.Bool
	candidate func(*alert.Alert) bool
	classify  func(context.Context, uint64, *alert.Alert) (*v2.EpisodeProjection, error)
}

func (j *recoveryFixture) RecoveryState() (uint64, bool) { return j.epoch.Load(), j.receipts.Load() }
func (j *recoveryFixture) MayHaveEpisode(_ uint64, s *alert.Alert) bool {
	return j.candidate != nil && j.candidate(s)
}
func (j *recoveryFixture) ClassifyResident(ctx context.Context, epoch uint64, s *alert.Alert) (*v2.EpisodeProjection, error) {
	return j.classify(ctx, epoch, s)
}

func restoredFixture(t *testing.T, s *alert.Alert) v2.EpisodeProjection {
	t.Helper()
	var p v2.EpisodeProjection
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"episode_ref":{"authority_id":"11111111-1111-4111-8111-111111111111","episode_id":"22222222-2222-4222-8222-222222222222","generation":1,"variant_revision":1},"native_variant":{"fingerprint":%q,"starts_at":%q},"lifecycle_seq":1,"active_since":%q,"state":"firing","source_severity":"major","floor":"critical","severity_revision":3}`, s.Fingerprint().String(), s.StartsAt.Format(time.RFC3339Nano), s.StartsAt.Format(time.RFC3339Nano))), &p))
	return p
}

func TestOscarActionFactoryCommissioningAndReceiptLoss(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			r := newTestReloader(t)
			t.Cleanup(func() { _ = r.stop() })
			opts := testOptions(t)
			owner, actions := configureNativeActions(opts, nil, r.logger)
			require.Nil(t, owner.Dispatch)
			require.Nil(t, actions)
			opts.ActionOwner.Enabled = true
			opts.ActionOwner.Scheme = scheme
			opts.ActionOwner.CAFile = "/home/ssl/ca.pem"
			opts.ConversionCallbackKey = []byte(strings.Repeat("k", 32))
			owner, actions = configureNativeActions(opts, nil, r.logger)
			require.Same(t, actions, owner.Dispatch)
			opts.ActionOwner.Dispatch = actions
			_, injected := configureNativeActions(opts, nil, r.logger)
			require.Same(t, actions, injected)
			j := &recoveryFixture{classify: func(context.Context, uint64, *alert.Alert) (*v2.EpisodeProjection, error) { return nil, nil }}
			require.NoError(t, actions.Bind(j))
			r.actions = actions
			cred := filepath.Join(t.TempDir(), "callback")
			require.NoError(t, os.WriteFile(cred, opts.ConversionCallbackKey, 0o600))
			tls := "insecure_skip_verify: true"
			if scheme == "https" {
				tls = "ca_file: /home/ssl/ca.pem"
			}
			yaml := fmt.Sprintf("route:\n  receiver: default\n  group_wait: 1h\nreceivers:\n- name: default\n  webhook_configs:\n  - url: %s://alertmanager-middleware:9400%s\n    send_resolved: true\n    http_config:\n      tls_config:\n        %s\n      follow_redirects: false\n      authorization:\n        type: Bearer\n        credentials_file: %s\n", scheme, alert.NativeCallbackPath, tls, cred)
			load := func(input string) *config.Config { c, e := config.Load(input); require.NoError(t, e); return c }
			require.NoError(t, r.reload(load(strings.Replace(yaml, "send_resolved: true", "send_resolved: false", 1))))
			require.Zero(t, actions.Version())
			require.NoError(t, r.reload(load(yaml)))
			g := actions.snapshot()
			require.NotNil(t, g)
			j.epoch.Store(1)
			now := time.Now()
			s := alert.New(model.Alert{Labels: model.LabelSet{"host": "one", "severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
			actions.ObserveSource("", s, false, false)
			require.Eventually(t, func() bool { return actions.ReadView(s) != nil }, 5*time.Second, time.Millisecond)
			require.Zero(t, actions.Version())
			wire := s.NotificationCopy(now)
			active := map[*alert.Alert]bool{wire: true}
			c := ordinaryContact{legacy: true, pass: &v2.OrdinaryPass{}, contact: plannedContact{integration: actionIntegration{canonical: true}}}
			check := func() bool {
				return actions.finalPublication(g, []*alert.Alert{wire}, []ordinaryContact{c}, active, func() {})
			}
			require.True(t, check(), "only a proven untracked pass can continue before commissioning")
			j.receipts.Store(true)
			require.Equal(t, 1, actions.Version())
			require.False(t, check(), "an earlier unsigned pass cannot enter after commissioning")
			j.receipts.Store(false)
			require.Zero(t, actions.Version())
			c.pass = nil
			c.legacy = false
			require.False(t, check(), "a tracked signed entry cannot downgrade")
			j.epoch.Store(0)
			c.pass = &v2.OrdinaryPass{}
			c.legacy = true
			require.False(t, check(), "there is no negative proof after lease loss")
		})
	}
}

func TestOscarActionRecoveryPublishesLateInhibitorBeforeEntry(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now()
	newSource := func(host, cluster, severity string) *alert.Alert {
		return alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(host), "cluster": model.LabelValue(cluster), "severity": model.LabelValue(severity)}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	}
	b, c, late := newSource("B", "one", "minor"), newSource("C", "two", "minor"), newSource("late", "one", "major")
	p := restoredFixture(t, late)
	started, release := make(chan struct{}), make(chan struct{})
	var stale atomic.Bool
	var calls atomic.Int64
	j := &recoveryFixture{candidate: func(s *alert.Alert) bool {
		i, err := strconv.Atoi(string(s.Labels["host"]))
		return s == late || err == nil && i < 300
	}, classify: func(ctx context.Context, epoch uint64, s *alert.Alert) (*v2.EpisodeProjection, error) {
		calls.Add(1)
		if s == late {
			if stale.CompareAndSwap(false, true) {
				close(started)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return &p, nil
		}
		return nil, nil
	}}
	actions := newNativeActions(nil, nil, r.logger)
	r.actions = actions
	require.NoError(t, actions.Bind(j))
	actions.ObserveSource("", b, false, true)
	actions.ObserveSource("", c, false, true)
	for i := range 4096 {
		actions.ObserveSource("", newSource(fmt.Sprint(i), "unrelated", "info"), false, true)
	}
	actions.ObserveSource("", late, false, true)
	cfg, e := config.Load("route:\n  receiver: base\n  group_wait: 1h\n  routes:\n  - receiver: escalated\n    matchers: ['severity=critical']\nreceivers:\n- name: base\n- name: escalated\ninhibit_rules:\n- source_matchers: ['severity=critical']\n  target_matchers: ['severity=minor']\n  equal: [cluster]\n")
	require.NoError(t, e)
	require.NoError(t, r.reload(cfg))
	j.epoch.Store(1)
	select {
	case <-started:
	case <-time.After(15 * time.Second):
		t.Fatal("late floor not inspected")
	}
	g := actions.snapshot()
	enter := func(g *actionGraph, m *alert.Alert) bool {
		return actions.finalPublication(g, []*alert.Alert{m}, []ordinaryContact{{pass: &v2.OrdinaryPass{}}}, map[*alert.Alert]bool{m: true}, func() {})
	}
	require.False(t, enter(g, b))
	require.True(t, enter(g, c), "unrelated delivery remains available during a blocked indexed proof")
	close(release)
	require.Eventually(t, func() bool { return actions.Version() == 1 && actions.ReadView(late) != nil }, 10*time.Second, time.Millisecond)
	require.Equal(t, model.LabelValue("critical"), actions.ReadView(late).Labels["severity"])
	groups, _, err := r.groups(t.Context(), func(*dispatch.Route) bool { return true }, func(m *alert.Alert, _ time.Time) (alert.AlertStatus, bool) {
		return alert.AlertStatus{}, m.ProviderSource() == late
	})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, "escalated", groups[0].Receiver)
	require.False(t, enter(g, b))
	require.True(t, enter(g, c))
	before := calls.Load()
	for range 100 {
		require.True(t, enter(g, c))
	}
	require.Equal(t, before, calls.Load(), "provider entry makes no inventory or classification read")
	actions.InvalidateSource(late)
	require.False(t, enter(g, b))
	require.True(t, enter(g, c))
	require.NoError(t, r.reload(cfg))
	require.False(t, enter(g, c), "an old graph cannot authorize a new entry")
	require.Eventually(t, func() bool { return actions.Version() == 1 }, 15*time.Second, time.Millisecond)
	require.False(t, enter(actions.snapshot(), b))
	j.epoch.Store(2)
	require.False(t, enter(actions.snapshot(), c), "takeover fences the old publication synchronously")
}

func TestOscarActionManagedReplacementDuringRecoveryRejectsLateGCAndSubscriber(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now()
	owner := strings.Repeat("e", 64)
	member := func(host string, gen int64) *alert.Alert {
		s := alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(host), "severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
		s.ManagedReceiver = true
		s.ManagedMember = alert.ManagedMembership{Episode: owner, Generation: gen}
		return s
	}
	old, next := member("old", 1), member("new", 2)
	oldRow, nextRow := restoredFixture(t, old), restoredFixture(t, next)
	nextRow.EpisodeRef.VariantRevision = 2
	nextRow.LifecycleSeq++
	started, release := make(chan struct{}), make(chan struct{})
	j := &recoveryFixture{candidate: func(*alert.Alert) bool { return true }, classify: func(ctx context.Context, _ uint64, s *alert.Alert) (*v2.EpisodeProjection, error) {
		if s == old {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &oldRow, nil
		}
		return &nextRow, nil
	}}
	j.epoch.Store(1)
	a := newNativeActions(nil, nil, r.logger)
	r.actions = a
	require.NoError(t, a.Bind(j))
	a.ObserveSource(owner, old, false, true)
	require.NoError(t, r.reload(mustConfig(t)))
	g := a.snapshot()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("initial proof did not begin")
	}
	a.ObserveSource(owner, next, false, true)
	a.ObserveSource(owner, old, true, true)
	close(release)
	require.Eventually(t, func() bool { return a.ReadView(next) != nil }, 5*time.Second, time.Millisecond)
	require.Nil(t, a.ReadView(old))
	require.Equal(t, model.LabelValue("critical"), a.ReadView(next).Labels["severity"])
	a.graphView(g, old, true, func(*alert.Alert) { t.Fatal("retired subscriber overwrote the successor") })
	require.NoError(t, r.reload(mustConfig(t)))
	a.graphView(g, next, false, func(*alert.Alert) { t.Fatal("cancelled graph subscriber ran") })
	a.ObserveSource(owner, nil, true, true)
	require.Nil(t, a.ReadView(next))
}
