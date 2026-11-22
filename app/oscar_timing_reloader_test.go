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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/route"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	v2 "github.com/prometheus/alertmanager/api/v2"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/config/receiver"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/labelset"
	"github.com/prometheus/alertmanager/nflog"
	"github.com/prometheus/alertmanager/nflog/nflogpb"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/notify/incidentio"
	"github.com/prometheus/alertmanager/notify/webhook"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/timeinterval"
)

func TestReloaderPublishesTimingAfterDispatcherLoads(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	require.NoError(t, r.alerts.Put(t.Context(), a))
	require.NoError(t, r.reload(mustConfig(t)))
	w := httptest.NewRecorder()
	r.apih.Register(route.New(), "").ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
	require.Equal(t, 200, w.Code, w.Body.String())
	var page struct {
		Timing map[string]struct {
			LookupState string            `json:"repeat_lookup_state"`
			Schedules   []json.RawMessage `json:"repeat_schedules"`
		} `json:"timing_by_fingerprint"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Equal(t, "ready", page.Timing[a.Fingerprint().String()].LookupState)
	require.Empty(t, page.Timing[a.Fingerprint().String()].Schedules)
	require.NoError(t, r.stop())
	w = httptest.NewRecorder()
	r.apih.Register(route.New(), "").ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
	require.Equal(t, 200, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Equal(t, "unavailable", page.Timing[a.Fingerprint().String()].LookupState)
}

func TestReloaderSuccessfulNativeDeliveryAppearsAsEstimatedTiming(t *testing.T) {
	webhookCalled := make(chan struct{}, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case webhookCalled <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(webhook.Close)
	r := newTestReloader(t)
	// Even an embedded caller supplying the dormant adapter retains the ordinary pipeline.
	r.actions = newNativeActions(nil, nil, r.logger)
	t.Cleanup(func() { _ = r.stop() })
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\n  group_by: [alertname]\n  group_wait: 1ms\n  group_interval: 1h\n  repeat_interval: 1h\nreceivers:\n- name: team\n  webhook_configs:\n  - url: %s\n", webhook.URL))
	require.NoError(t, err)
	now := time.Now()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	require.NoError(t, r.alerts.Put(t.Context(), a))
	require.NoError(t, r.reload(cfg))
	require.Nil(t, r.actions.snapshot())
	require.Nil(t, r.dispatcher.Load().Project)
	require.Nil(t, r.inhibitor.Load().Project)
	select {
	case <-webhookCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("native webhook was not called")
	}
	key := dispatch.GroupKeyForAlert(a, dispatch.NewRoute(cfg.Route, nil).Match(a.Labels)[0])
	recv := &nflogpb.Receiver{GroupName: "team", Integration: "webhook", Idx: 0}
	log := r.notificationLog.(*nflog.Log)
	var baseline time.Time
	require.Eventually(t, func() bool {
		lookup := log.LookupTiming(key, recv, []uint64{notify.HashAlert(a)}, 1)
		baseline = lookup.Timestamp
		return lookup.Found && lookup.Firing[notify.HashAlert(a)]
	}, 5*time.Second, 10*time.Millisecond)
	w := httptest.NewRecorder()
	r.apih.Register(route.New(), "").ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
	require.Equal(t, 200, w.Code, w.Body.String())
	var page struct {
		Timing map[string]struct {
			Schedules []struct {
				State string    `json:"state"`
				Next  time.Time `json:"next_repeat_eligible_at"`
			} `json:"repeat_schedules"`
		} `json:"timing_by_fingerprint"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	steps := page.Timing[a.Fingerprint().String()].Schedules
	require.Len(t, steps, 1)
	require.Equal(t, "estimated", steps[0].State)
	require.True(t, steps[0].Next.Equal(baseline.Add(time.Hour).Truncate(time.Millisecond)))
}

func TestReloaderTimingUsesLoadedWebhookIntegrationAndNativeLog(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	cfg, err := config.Load("route:\n  receiver: team\n  group_by: [alertname]\n  group_wait: 1h\n  repeat_interval: 1h\nreceivers:\n- name: team\n  webhook_configs:\n  - url: http://127.0.0.1:65534/\n")
	require.NoError(t, err)
	now := time.Now()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown", "instance": "node-1"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	require.NoError(t, r.alerts.Put(t.Context(), a))
	require.NoError(t, r.reload(cfg))
	beforeSend := httptest.NewRecorder()
	r.apih.Register(route.New(), "").ServeHTTP(beforeSend, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
	require.Equal(t, 200, beforeSend.Code, beforeSend.Body.String())
	require.Contains(t, beforeSend.Body.String(), `"state":"no_repeat_baseline"`)
	key := dispatch.GroupKeyForAlert(a, dispatch.NewRoute(cfg.Route, nil).Match(a.Labels)[0])
	log := r.notificationLog.(*nflog.Log)
	require.NoError(t, log.Log(&nflogpb.Receiver{GroupName: "team", Integration: "webhook", Idx: 0}, key, []uint64{notify.HashAlert(a)}, nil, nil, nil, 2*time.Hour))
	direct := log.LookupTiming(key, &nflogpb.Receiver{GroupName: "team", Integration: "webhook", Idx: 0}, []uint64{notify.HashAlert(a)}, 200000)
	require.True(t, direct.Found)
	require.True(t, direct.Firing[notify.HashAlert(a)])
	w := httptest.NewRecorder()
	r.apih.Register(route.New(), "").ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
	require.Equal(t, 200, w.Code, w.Body.String())
	var page struct {
		Timing map[string]struct {
			LookupState string `json:"repeat_lookup_state"`
			Schedules   []struct {
				Integration string `json:"integration"`
				State       string `json:"state"`
				Repeat      string `json:"repeat_interval_duration"`
				Next        string `json:"next_repeat_eligible_at"`
			} `json:"repeat_schedules"`
		} `json:"timing_by_fingerprint"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	timing := page.Timing[a.Fingerprint().String()]
	require.Equal(t, "ready", timing.LookupState)
	require.Len(t, timing.Schedules, 1)
	require.Equal(t, "webhook/0", timing.Schedules[0].Integration)
	require.Equal(t, "estimated", timing.Schedules[0].State)
	require.Equal(t, "1h0m0s", timing.Schedules[0].Repeat)
	require.NotEmpty(t, timing.Schedules[0].Next)
	changed, err := config.Load("route:\n  receiver: team\n  group_by: [alertname]\n  group_wait: 1h\n  repeat_interval: 1h\nreceivers:\n- name: team\n  webhook_configs:\n  - url: http://127.0.0.1:65533/\n")
	require.NoError(t, err)
	require.NoError(t, r.reload(changed))
	w = httptest.NewRecorder()
	r.apih.Register(route.New(), "").ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
	require.Equal(t, 200, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Equal(t, "estimated", page.Timing[a.Fingerprint().String()].Schedules[0].State, "native log key is reused after destination change")
}

func TestReloaderTimingUnavailableFromPreStopThroughPrePublish(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	cfg := mustConfig(t)
	now := time.Now()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	require.NoError(t, r.alerts.Put(t.Context(), a))
	require.NoError(t, r.reload(cfg))
	state := func() string {
		w := httptest.NewRecorder()
		r.apih.Register(route.New(), "").ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
		require.Equal(t, 200, w.Code, w.Body.String())
		var page struct {
			Timing map[string]struct {
				LookupState string `json:"repeat_lookup_state"`
			} `json:"timing_by_fingerprint"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
		return page.Timing[a.Fingerprint().String()].LookupState
	}
	require.Equal(t, "ready", state())
	paused, releasePause := make(chan struct{}), make(chan struct{})
	prePublish, releasePublish := make(chan struct{}), make(chan struct{})
	r.afterTimingPause = func() { close(paused); <-releasePause }
	r.beforeTimingPublish = func() { close(prePublish); <-releasePublish }
	done := make(chan error, 1)
	go func() { done <- r.reload(cfg) }()
	<-paused
	require.Equal(t, "unavailable", state())
	close(releasePause)
	<-prePublish
	require.Equal(t, "unavailable", state())
	close(releasePublish)
	require.NoError(t, <-done)
	require.Equal(t, "ready", state())
}

func TestReloaderTimingFollowsNativeIntegrationIndexesAfterReorder(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	configFor := func(first, second string) *config.Config {
		t.Helper()
		cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\n  group_by: [alertname]\n  group_wait: 1h\n  repeat_interval: 1h\nreceivers:\n- name: team\n  webhook_configs:\n  - url: %s\n  - url: %s\n", first, second))
		require.NoError(t, err)
		return cfg
	}
	first := configFor("http://127.0.0.1:65531/", "http://127.0.0.1:65532/")
	now := time.Now()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	require.NoError(t, r.alerts.Put(t.Context(), a))
	require.NoError(t, r.reload(first))
	key := dispatch.GroupKeyForAlert(a, dispatch.NewRoute(first.Route, nil).Match(a.Labels)[0])
	log := r.notificationLog.(*nflog.Log)
	require.NoError(t, log.Log(&nflogpb.Receiver{GroupName: "team", Integration: "webhook", Idx: 0}, key, []uint64{notify.HashAlert(a)}, nil, nil, nil, 2*time.Hour))
	require.NoError(t, log.Log(&nflogpb.Receiver{GroupName: "team", Integration: "webhook", Idx: 1}, key, nil, nil, nil, nil, 2*time.Hour))
	states := func() map[string]string {
		w := httptest.NewRecorder()
		r.apih.Register(route.New(), "").ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
		require.Equal(t, 200, w.Code, w.Body.String())
		var page struct {
			Timing map[string]struct {
				Schedules []struct {
					Integration string `json:"integration"`
					State       string `json:"state"`
				} `json:"repeat_schedules"`
			} `json:"timing_by_fingerprint"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
		out := map[string]string{}
		for _, step := range page.Timing[a.Fingerprint().String()].Schedules {
			out[step.Integration] = step.State
		}
		return out
	}
	want := map[string]string{"webhook/0": "estimated", "webhook/1": "no_repeat_baseline"}
	require.Equal(t, want, states())
	require.NoError(t, r.reload(configFor("http://127.0.0.1:65532/", "http://127.0.0.1:65531/")))
	require.Equal(t, want, states(), "native log keys follow integration indices after destination reorder")
}

func TestOscarActionScopesRequireCanonicalTransport(t *testing.T) {
	t.Parallel()
	id, action := "11111111-1111-4111-8111-111111111111", "ticket"
	scope := []alert.TargetScopeEntry{{ReceiverID: "team", NotifierID: &id, Action: &action}}
	_, ok := actionScope("team", false, scope)
	require.False(t, ok)
	got, ok := actionScope("team", true, scope)
	require.True(t, ok)
	require.Equal(t, scope, got)
	_, ok = actionScope("other", true, scope)
	require.False(t, ok)
}

func TestOscarActionFloorRebuildsGroupsAndInhibitorOnReload(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now().UTC()
	source := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "Disk", "severity": "major", "cluster": "x"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	require.NoError(t, r.alerts.Put(t.Context(), source))
	current, err := r.alerts.Get(source.Fingerprint())
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: base\n  group_wait: 1h\n  routes:\n  - receiver: escalated\n    matchers: ['severity=critical']\nreceivers:\n- name: base\n- name: escalated\ninhibit_rules:\n- source_matchers: ['severity=critical']\n  target_matchers: ['severity=minor']\n  equal: [cluster]\n")
	require.NoError(t, err)
	r.actions = newNativeActions(func(_, _ string, read func(*alert.Alert)) { read(current) }, nil, r.logger)
	// Exercise projected readers directly in this fixture while the shipped version is dormant.
	r.actions.version = 1
	require.NoError(t, r.actions.Bind(struct{ v2.ActionJournal }{}))
	require.NoError(t, r.reload(cfg))
	var p v2.EpisodeProjection
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"episode_ref":{"authority_id":"11111111-1111-4111-8111-111111111111","episode_id":"22222222-2222-4222-8222-222222222222","generation":1,"variant_revision":1},"native_variant":{"fingerprint":%q,"starts_at":%q},"lifecycle_seq":1,"active_since":%q,"state":"firing","source_severity":"major","floor":"critical","severity_revision":1}`, current.Fingerprint().String(), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))), &p))
	require.NoError(t, r.actions.PublishSource(t.Context(), p, current))
	for _, reload := range []bool{false, true} {
		if reload {
			require.NoError(t, r.reload(cfg))
		}
		groups, _, err := r.groups(t.Context(), func(*dispatch.Route) bool { return true }, func(*alert.Alert, time.Time) (alert.AlertStatus, bool) { return alert.AlertStatus{}, true })
		require.NoError(t, err)
		require.Len(t, groups, 1)
		require.Equal(t, "escalated", groups[0].Receiver)
		require.Same(t, current, groups[0].Alerts[0].ProviderSource())
		require.Equal(t, model.LabelValue("major"), current.Labels["severity"])
		require.True(t, r.inhibitor.Load().Mutes(t.Context(), labelset.FromModel(model.LabelSet{"cluster": "x", "severity": "minor"})))
	}
}

type fixturePermit struct{ source *alert.Alert }

func (e fixturePermit) ForMember(m *alert.Alert) bool { return m.ProviderSource() == e.source }
func (fixturePermit) Valid() bool                     { return true }
func (fixturePermit) LogicalActionID() string         { return "" }
func (fixturePermit) EntryFence() (time.Time, func() bool) {
	return time.Now().Add(time.Hour), func() bool { return true }
}
func (fixturePermit) LocalValid() bool { return true }

type terminalFixtureJournal struct {
	v2.ActionJournal
	projections                        map[*alert.Alert]v2.EpisodeProjection
	covered                            string
	coverageChecks                     int
	confirmed                          map[string]bool
	inspectSource                      func(*alert.Alert) error
	enterDirect                        func(*alert.Alert)
	failInspectHost                    string
	failReserveAfterFirst              bool
	firstPermit                        time.Time
	resumedExpired                     bool
	first                              bool
	state                              string
	reserved, claimed, settled, events []string
}

func (*terminalFixtureJournal) RecipientKey() []byte { return []byte(strings.Repeat("r", 32)) }
func (j *terminalFixtureJournal) InspectContact(_ context.Context, m *alert.Alert, p v2.EpisodeProjection, _ v2.DispatchTarget) (string, error) {
	if j.failInspectHost != "" && string(m.Labels["host"]) == j.failInspectHost {
		j.failInspectHost = ""
		return "", errors.New("temporary inspection failure")
	}
	if p.State == "resolved" && j.confirmed[p.EpisodeRef.EpisodeID] {
		return "completed", nil
	}
	if p.EpisodeRef.EpisodeID == j.covered {
		j.coverageChecks++
		return "covered", nil
	}
	return "due", nil
}

func (j *terminalFixtureJournal) InspectOrdinary(_ context.Context, s *alert.Alert) (*v2.EpisodeProjection, *v2.OrdinaryPass, error) {
	if j.inspectSource != nil {
		if err := j.inspectSource(s); err != nil {
			return nil, nil, err
		}
	}
	if j.first {
		return nil, &v2.OrdinaryPass{}, nil
	}
	p, ok := j.projections[s]
	if !ok {
		return nil, &v2.OrdinaryPass{
			Enter: func() bool {
				if j.enterDirect != nil {
					j.enterDirect(s)
				}
				return true
			},
			Valid:  func() bool { return true },
			Finish: func(bool) {},
		}, nil
	}
	return &p, nil, nil
}

func (j *terminalFixtureJournal) Project(_ context.Context, s *alert.Alert) (v2.EpisodeProjection, error) {
	j.first = false
	j.events = append(j.events, "enroll")
	return j.projections[s], nil
}

func (j *terminalFixtureJournal) reservation(id string, ref v2.EpisodeRef, t v2.DispatchTarget) v2.ActionResultV1 {
	j.reserved = append(j.reserved, ref.EpisodeID)
	j.events = append(j.events, "reserve")
	return v2.ActionResultV1{OperationID: id, EpisodeRef: ref, Targets: []v2.TargetResult{{Target: t, TargetKey: ref.EpisodeID, State: j.state}}}
}

func (j *terminalFixtureJournal) ReserveTerminal(_ context.Context, m *alert.Alert, p v2.EpisodeProjection, t v2.DispatchTarget) (v2.ActionResultV1, error) {
	if j.failReserveAfterFirst && len(j.reserved) == 0 {
		j.firstPermit = time.Now().Add(30 * time.Second)
	}
	if !j.firstPermit.IsZero() && len(j.reserved) > 0 && p.EpisodeRef.EpisodeID == j.reserved[0] {
		j.resumedExpired = time.Now().After(j.firstPermit)
	}
	if j.failReserveAfterFirst && len(j.reserved) == 1 {
		j.failReserveAfterFirst = false
		return v2.ActionResultV1{}, errors.New("sibling CAS lost")
	}
	return j.reservation(p.EpisodeRef.EpisodeID, p.EpisodeRef, t), nil
}

func (j *terminalFixtureJournal) ReserveOrdinary(_ context.Context, id string, _ *alert.Alert, p v2.EpisodeProjection, t v2.DispatchTarget) (v2.ActionResultV1, error) {
	ref := p.EpisodeRef
	if ref.EpisodeID == j.covered {
		j.coverageChecks++
		return v2.ActionResultV1{}, errors.New("NATIVE_SUPPRESSED")
	}
	return j.reservation(id, ref, t), nil
}

func (j *terminalFixtureJournal) Claim(_ context.Context, _, key string) (v2.Entry, error) {
	j.claimed = append(j.claimed, key)
	j.events = append(j.events, "claim")
	for s, p := range j.projections {
		if p.EpisodeRef.EpisodeID == key {
			return fixturePermit{s}, nil
		}
	}
	return nil, actionHeld
}

func (j *terminalFixtureJournal) Delivery(_ context.Context, s *alert.Alert, _, id string, e v2.Entry) (alert.NativeDeliveryV1, error) {
	if !e.ForMember(s) {
		return alert.NativeDeliveryV1{}, actionHeld
	}
	p := j.projections[s]
	j.events = append(j.events, "stamp")
	return alert.NativeDeliveryV1{Version: 1, EpisodeRef: p.EpisodeRef, NativeVariant: p.NativeVariant, LifecycleSeq: p.LifecycleSeq, State: p.State, ActiveSince: p.ActiveSince, SourceSeverity: p.SourceSeverity, EffectiveSeverity: p.EffectiveSeverity(), DeliveryID: id, TargetScope: []alert.TargetScopeEntry{}}, nil
}

func (j *terminalFixtureJournal) Settle(_ context.Context, e v2.Entry, outcome, _ string) (v2.ActionResultV1, error) {
	j.settled = append(j.settled, outcome)
	if outcome == "confirmed" {
		for source, p := range j.projections {
			if e.ForMember(source) {
				if j.confirmed == nil {
					j.confirmed = map[string]bool{}
				}
				j.confirmed[p.EpisodeRef.EpisodeID] = true
			}
		}
	}
	return v2.ActionResultV1{}, nil
}

func TestOscarActionTerminalNativePipeline(t *testing.T) {
	for _, tc := range []struct {
		name, order, state                             string
		canonical, sendResolved, stale, managed, first bool
		limit                                          int
		want                                           string
		wantErr, emptyLog, dynamic                     bool
	}{
		{name: "F first", order: "FR", state: "pending", sendResolved: true, limit: 1, want: "F"},
		{name: "R first", order: "RF", state: "pending", sendResolved: true, limit: 1, want: "R"},
		{name: "send-resolved filter before limit", order: "RF", state: "pending", limit: 1, want: "F"},
		{name: "stale prefix cannot admit F", order: "RF", state: "pending", limit: 1, sendResolved: true, stale: true, wantErr: true},
		{name: "group-dependent address beside covered A", order: "AB", state: "pending", sendResolved: true, want: "B", dynamic: true},
		{name: "direct acceptance beside covered A", order: "AB", state: "pending", sendResolved: true, want: "B"},
		{name: "first direct acceptance beside covered A", order: "AB", state: "pending", sendResolved: true, want: "B", emptyLog: true},
		{name: "direct stale firing copy", order: "R", state: "pending", sendResolved: true, stale: true, wantErr: true},
		{name: "stale copy with send-resolved false", order: "R", state: "pending", stale: true, wantErr: true},
		{name: "signed stale firing copy", order: "R", state: "pending", canonical: true, sendResolved: true, stale: true, wantErr: true},
		{name: "first signed ordinary closure", order: "R", state: "pending", canonical: true, sendResolved: true, first: true, want: "R"},
		{name: "signed promoted clear firing on wire", order: "R", state: "pending", canonical: true, sendResolved: true, managed: true, want: "R"},
		{name: "confirmed closure", order: "R", state: "confirmed", sendResolved: true},
		{name: "unknown closure", order: "R", state: "unknown", sendResolved: true, wantErr: true},
		{name: "disabled send-resolved", order: "R", state: "pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type capture struct {
				msg     webhook.Message
				raw     []byte
				headers http.Header
			}
			calls := make(chan capture, 4)
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				raw, _ := io.ReadAll(req.Body)
				var msg webhook.Message
				if err := json.Unmarshal(raw, &msg); err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				if tc.dynamic {
					require.Equal(t, "/B", req.URL.Path)
				}
				calls <- capture{msg, raw, req.Header.Clone()}
			}))
			t.Cleanup(sink.Close)
			r := newTestReloader(t)
			t.Cleanup(func() { _ = r.stop() })
			key := []byte(strings.Repeat("k", 32))
			file := filepath.Join(t.TempDir(), "callback")
			require.NoError(t, os.WriteFile(file, key, 0o600))
			url, options := sink.URL, ""
			if tc.dynamic {
				url += "/{{ (index .Alerts 0).Labels.host }}"
			}
			if tc.canonical {
				url = "http://alertmanager-middleware:9400" + alert.NativeCallbackPath
				options = fmt.Sprintf("    http_config:\n      follow_redirects: false\n      authorization:\n        type: Bearer\n        credentials_file: %s\n", file)
			}
			cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\n  group_by: [alertname]\n  group_wait: 1h\nreceivers:\n- name: team\n  webhook_configs:\n  - url: %s\n    max_alerts: %d\n    send_resolved: %t\n%s", url, tc.limit, tc.sendResolved, options))
			require.NoError(t, err)
			j := &terminalFixtureJournal{projections: map[*alert.Alert]v2.EpisodeProjection{}, first: tc.first, state: tc.state}
			a := newNativeActions(nil, key, r.logger)
			a.scheme = "http"
			a.version = 1
			r.actions = a
			require.NoError(t, a.Bind(j))
			require.NoError(t, r.reload(cfg))
			g := a.snapshot()
			require.NotNil(t, g)
			tmpl, err := template.FromGlobs(nil)
			require.NoError(t, err)
			tmpl.ExternalURL = r.externalURL
			integrations, err := receiver.BuildReceiverIntegrations(cfg.Receivers[0], tmpl, r.logger, commoncfg.WithDialContextFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, sink.Listener.Addr().String())
			}))
			require.NoError(t, err)
			pipeline := r.pipelineBuilder.New(map[string][]notify.Integration{"team": integrations}, r.waitFunc, g.inhibitor, r.silencer, g.timeMuter.(*timeinterval.Intervener), r.notificationLog, nil)
			now := time.Now().UTC()
			var members []*alert.Alert
			ids := map[string]string{}
			for n, letter := range tc.order {
				host := string(letter)
				end := now.Add(time.Hour)
				state := "firing"
				sev := "major"
				if host == "R" {
					state = "resolved"
					end = now.Add(-time.Second)
					if tc.managed {
						sev = "cleared"
						end = now.Add(time.Hour)
					}
				}
				source := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "Disk", "severity": model.LabelValue(sev), "host": model.LabelValue(host)}, StartsAt: now.Add(-time.Hour), EndsAt: end}, now, false)
				if tc.managed {
					source.ManagedReceiver = true
					source.ManagedOperationKind = "clear"
					source.ManagedMember = alert.ManagedMembership{Episode: strings.Repeat("a", 64), Generation: 2, Event: "11111111-1111-4111-8111-111111111111", Digest: strings.Repeat("b", 64)}
					source.ManagedEligible = func(context.Context, *alert.Alert, string, string) (bool, error) { return true, nil }
				}
				id := fmt.Sprintf("22222222-2222-4222-8222-%012d", n+1)
				ids[host] = id
				var p v2.EpisodeProjection
				start := source.StartsAt.Format(time.RFC3339Nano)
				require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"episode_ref":{"authority_id":"11111111-1111-4111-8111-111111111111","episode_id":%q,"generation":1,"variant_revision":1},"native_variant":{"fingerprint":%q,"starts_at":%q},"active_since":%q,"state":%q,"source_severity":%q,"lifecycle_seq":2}`, id, source.Fingerprint().String(), start, start, state, sev)), &p))
				if host != "B" {
					j.projections[source] = p
				}
				if host == "A" {
					j.covered = id
				}
				flush := now
				if tc.stale {
					flush = end.Add(-time.Nanosecond)
				}
				members = append(members, source.NotificationCopy(flush))
			}
			ctx := g.dispatcher.SelectedContext(t.Context(), g.routes.Match(members[0].Labels)[0], members[0])
			gkey, _ := notify.GroupKey(ctx)
			recv := &nflogpb.Receiver{GroupName: "team", Integration: "webhook"}
			if !tc.emptyLog {
				baseline := uint64(42)
				if j.covered != "" {
					baseline = notify.HashAlert(members[0])
				}
				require.NoError(t, r.notificationLog.Log(recv, gkey, []uint64{baseline}, nil, nil, nil, time.Hour))
			}
			ctx = notify.WithOrdinaryReader(ctx, func(c context.Context, receiver, name string, index int, ms []*alert.Alert, due func([]*alert.Alert) bool) (notify.OrdinaryBatch, error) {
				return a.prepare(c, g, receiver, name, index, ms, due)
			})
			_, _, err = pipeline.Exec(ctx, r.logger, members...)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tc.stale || (!tc.sendResolved && tc.order == "R") {
				require.Empty(t, j.reserved)
			}
			if tc.want == "" {
				require.Empty(t, calls)
				require.Empty(t, j.claimed)
				return
			}
			require.Len(t, calls, 1)
			c := <-calls
			require.Len(t, c.msg.Alerts, 1)
			require.Equal(t, tc.want, c.msg.Alerts[0].Labels["host"])
			if j.covered != "" {
				// A's durable repeat deadline remains in the future through both flushes.
				entries, err := r.notificationLog.Query(nflog.QGroupKey(gkey), nflog.QReceiver(recv))
				require.NoError(t, err)
				require.Len(t, entries, 1)
				require.Contains(t, entries[0].FiringAlerts, notify.HashAlert(members[1]))
				if tc.emptyLog {
					require.NotContains(t, entries[0].FiringAlerts, notify.HashAlert(members[0]))
				} else {
					require.Contains(t, entries[0].FiringAlerts, notify.HashAlert(members[0]))
				}
				stamp := entries[0].Timestamp.AsTime()
				_, _, err = pipeline.Exec(ctx, r.logger, members...)
				require.NoError(t, err)
				require.Empty(t, calls)
				require.Empty(t, j.reserved)
				require.Empty(t, j.claimed)
				require.Empty(t, j.settled)
				entries, err = r.notificationLog.Query(nflog.QGroupKey(gkey), nflog.QReceiver(recv))
				require.NoError(t, err)
				require.Equal(t, stamp, entries[0].Timestamp.AsTime())
				require.Equal(t, 2, j.coverageChecks)
				return
			}
			require.Equal(t, []string{ids[tc.want]}, j.reserved)
			require.Equal(t, j.reserved, j.claimed)
			require.Equal(t, []string{"confirmed"}, j.settled)
			if len(tc.order) == 2 {
				wantTruncated := uint64(1)
				if !tc.sendResolved {
					wantTruncated = 0
				}
				require.Equal(t, wantTruncated, c.msg.TruncatedAlerts)
				entries, err := r.notificationLog.Query(nflog.QGroupKey(gkey), nflog.QReceiver(recv))
				require.NoError(t, err)
				require.Len(t, entries, 1)
				for _, m := range members {
					if m.Resolved() {
						require.Contains(t, entries[0].ResolvedAlerts, notify.HashAlert(m))
					} else {
						require.Contains(t, entries[0].FiringAlerts, notify.HashAlert(m))
					}
				}
			}
			if tc.canonical {
				require.Len(t, c.msg.NativeDeliveries, 1)
				require.Equal(t, "resolved", c.msg.NativeDeliveries[0].Delivery.State)
				headers, err := alert.NativeDeliveryHeaders(c.raw, "team", alert.NativeCallbackPath, key)
				require.NoError(t, err)
				for k, v := range headers {
					require.Equal(t, v, c.headers.Get(k))
				}
				if tc.first {
					require.Equal(t, []string{"enroll", "reserve", "claim", "stamp"}, j.events)
				}
				if tc.managed {
					require.Equal(t, "firing", c.msg.Alerts[0].Status)
					require.Len(t, c.msg.Managed.Members, 1)
				}
			}
		})
	}
}

func TestOscarActionReloadChecksProposedCanonicalConfig(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	dir := t.TempDir()
	key := []byte(strings.Repeat("k", 32))
	file := filepath.Join(dir, "callback")
	bad := filepath.Join(dir, "wrong")
	require.NoError(t, os.WriteFile(file, key, 0o600))
	require.NoError(t, os.WriteFile(bad, []byte(strings.Repeat("x", 32)), 0o600))
	a := newNativeActions(nil, key, r.logger)
	a.version = 1
	a.scheme = "http"
	r.actions = a
	require.NoError(t, a.Bind(&terminalFixtureJournal{}))
	cfg := func(send bool, credential string) *config.Config {
		c, err := config.Load(fmt.Sprintf("route:\n  receiver: team\nreceivers:\n- name: team\n  webhook_configs:\n  - url: http://alertmanager-middleware:9400%s\n    send_resolved: %t\n    http_config:\n      follow_redirects: false\n      authorization:\n        type: Bearer\n        credentials_file: %s\n", alert.NativeCallbackPath, send, credential))
		require.NoError(t, err)
		return c
	}
	require.NoError(t, r.reload(cfg(false, file)))
	require.Nil(t, a.snapshot())
	require.Nil(t, r.dispatcher.Load().Project)
	require.NoError(t, r.reload(cfg(true, file)))
	old := a.snapshot()
	dispatcher := r.dispatcher.Load()
	require.NotNil(t, old)
	for _, invalid := range []*config.Config{cfg(false, file), cfg(true, bad)} {
		require.Error(t, r.reload(invalid))
		require.Same(t, old, a.snapshot())
		require.Same(t, dispatcher, r.dispatcher.Load())
	}
}

func TestOscarActionIncidentContentTail(t *testing.T) {
	t.Parallel()
	type flush struct {
		members   int
		repeatDue bool
		wire      string
		truncated uint64
		logged    string
	}
	mixed := []flush{
		{2, false, "AB", 0, "AB"},
		{3, true, "A", 2, "AB"},
		{3, true, "C", 2, "ABC"},
	}
	for _, tc := range []struct {
		name, hosts, tracked string
		annotationBytes      int
		maxAlerts            int
		flushes              []flush
	}{
		{"direct tail", "AB", "", 150 * 1024, 0, []flush{
			{2, false, "A", 1, "A"},
			{2, true, "B", 1, "AB"},
			{2, false, "", 0, "AB"},
		}},
		// Each distinct annotation appears in its alert and the configured metadata.
		// Any two 100 KiB members fit, while three exceed the 512 KiB wire limit.
		{"tracked repeat with a direct tail", "ABC", "A", 100 * 1024, 0, mixed},
		{"tracked repeat with a tracked tail", "ABC", "AC", 100 * 1024, 0, mixed},
		{"configured and encoded limits", "ABCDEF", "ACF", 100 * 1024, 5, []flush{
			{2, false, "AB", 0, "AB"},
			{6, true, "A", 5, "AB"},
			{6, true, "C", 5, "ABC"},
			{6, true, "DE", 4, "ABCDE"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan incidentio.Message, 5)
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var msg incidentio.Message
				if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512*1024)).Decode(&msg); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				seen <- msg
			}))
			defer sink.Close()
			r := newTestReloader(t)
			t.Cleanup(func() { _ = r.stop() })
			cfg, err := config.Load(fmt.Sprintf(`route:
  receiver: team
  group_by: [alertname]
  group_wait: 1h
  group_interval: 90s
  repeat_interval: 1m
receivers:
- name: team
  incidentio_configs:
  - url: %s
    alert_source_token: secret
    max_alerts: %d
    metadata:
      hosts: '{{ range .Alerts }}{{ .Labels.host }}{{ end }}'
      messages: '{{ range .Alerts }}{{ .Annotations.message }}{{ end }}'
`, sink.URL, tc.maxAlerts))
			require.NoError(t, err)
			a := newNativeActions(nil, nil, r.logger)
			a.version = 1
			r.actions = a
			j := &terminalFixtureJournal{state: "pending", projections: map[*alert.Alert]v2.EpisodeProjection{}}
			var direct []string
			j.enterDirect = func(s *alert.Alert) { direct = append(direct, string(s.Labels["host"])) }
			require.NoError(t, a.Bind(j))
			require.NoError(t, r.reload(cfg))
			g := a.snapshot()
			require.NotNil(t, g)
			now := time.Now()
			var members []*alert.Alert
			tracked := map[string]string{}
			hashes := map[string]uint64{}
			messages := map[string]string{}
			for n, h := range tc.hosts {
				host := string(h)
				messages[host] = host + strings.Repeat("x", tc.annotationBytes)
				s := alert.New(model.Alert{
					Labels:      model.LabelSet{"alertname": "Disk", "host": model.LabelValue(host), "severity": "major"},
					Annotations: model.LabelSet{"message": model.LabelValue(messages[host])},
					StartsAt:    now.Add(-time.Hour),
					EndsAt:      now.Add(time.Hour),
				}, now, false)
				if strings.Contains(tc.tracked, host) {
					id := fmt.Sprintf("22222222-2222-4222-8222-%012d", n+1)
					j.projections[s] = transportProjection(t, s, id, "firing")
					tracked[host] = id
				}
				members = append(members, s.NotificationCopy(now))
				hashes[host] = notify.HashAlert(s)
			}
			ctx := g.dispatcher.SelectedContext(t.Context(), g.routes, members[0])
			ctx = notify.WithOrdinaryReader(ctx, func(c context.Context, recv, kind string, idx int, ms []*alert.Alert, due func([]*alert.Alert) bool) (notify.OrdinaryBatch, error) {
				return a.prepare(c, g, recv, kind, idx, ms, due)
			})
			key, _ := notify.GroupKey(ctx)
			recv := &nflogpb.Receiver{GroupName: "team", Integration: "incidentio"}
			var lastLog time.Time
			for _, step := range tc.flushes {
				at := ctx
				if step.repeatDue {
					// Every elapsed flush is after the last write's repeat and before its expiry.
					at = notify.WithNow(ctx, lastLog.Add(90*time.Second))
				}
				reserved, claimed, settled, entered := len(j.reserved), len(j.claimed), len(j.settled), len(direct)
				_, _, err := g.pipeline.Exec(at, r.logger, members[:step.members]...)
				require.NoError(t, err)
				if step.wire == "" {
					require.Empty(t, seen)
				} else {
					require.Len(t, seen, 1)
					msg := <-seen
					var hosts []string
					var metadata strings.Builder
					for _, m := range msg.Alerts {
						host := m.Labels["host"]
						hosts = append(hosts, host)
						require.True(t, m.Annotations["message"] == messages[host], "wire annotation for %s", host)
						metadata.WriteString(messages[host])
					}
					require.Equal(t, step.wire, strings.Join(hosts, ""))
					require.Equal(t, step.wire, msg.Metadata["hosts"])
					require.True(t, metadata.String() == msg.Metadata["messages"], "metadata must match the wire members")
					require.Equal(t, step.truncated, msg.TruncatedAlerts)
				}
				var wantTracked, wantDirect []string
				for _, h := range step.wire {
					if id, ok := tracked[string(h)]; ok {
						wantTracked = append(wantTracked, id)
					} else {
						wantDirect = append(wantDirect, string(h))
					}
				}
				require.ElementsMatch(t, wantTracked, j.reserved[reserved:])
				require.ElementsMatch(t, wantTracked, j.claimed[claimed:])
				require.Len(t, j.settled[settled:], len(wantTracked))
				for _, outcome := range j.settled[settled:] {
					require.Equal(t, "confirmed", outcome)
				}
				require.ElementsMatch(t, wantDirect, direct[entered:])
				entries, err := r.notificationLog.Query(nflog.QGroupKey(key), nflog.QReceiver(recv))
				require.NoError(t, err)
				require.Len(t, entries, 1)
				var wantHashes []uint64
				for _, h := range step.logged {
					wantHashes = append(wantHashes, hashes[string(h)])
				}
				require.ElementsMatch(t, wantHashes, entries[0].FiringAlerts)
				if step.wire == "" {
					require.Equal(t, lastLog, entries[0].Timestamp.AsTime())
				}
				lastLog = entries[0].Timestamp.AsTime()
			}
		})
	}
}

func TestOscarActionRegisteredRecipients(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(`route:
  receiver: team
global:
  smtp_smarthost: localhost:25
  smtp_from: sender@example.org
receivers:
- name: team
  webhook_configs: [{url: "http://example.org/{{ .CommonLabels.host }}"}]
  discord_configs: [{webhook_url: "https://example.org"}]
  msteams_configs: [{webhook_url: "https://example.org"}]
  msteamsv2_configs: [{webhook_url: "https://example.org"}]
  mattermost_configs: [{webhook_url: "https://example.org"}]
  email_configs: [{to: team@example.org}]
  webex_configs: [{room_id: room, http_config: {authorization: {credentials: value}}}]
  slack_configs: [{api_url: "https://example.org", channel: "#team"}]
  rocketchat_configs: [{api_url: "https://example.org", token: token, token_id: account}]
  jira_configs: [{api_url: "https://example.org", project: OPS, issue_type: Incident}]
  incidentio_configs: [{url: "https://example.org", alert_source_token: secret}]
  pagerduty_configs: [{routing_key: key}]
  victorops_configs: [{routing_key: route, api_key: key}]
  opsgenie_configs: [{api_key: key}]
  pushover_configs: [{token: token, user_key: user}]
  telegram_configs: [{chat_id: 123, bot_token: token}]
  wechat_configs: [{corp_id: corp, api_secret: secret, agent_id: agent}]
  sns_configs: [{topic_arn: "arn:aws:sns:us-east-1:123456789012:example", sigv4: {region: us-east-1, access_key: test, secret_key: test}}]
`)
	require.NoError(t, err)
	tmpl, err := template.FromGlobs(nil)
	require.NoError(t, err)
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	tmpl.ExternalURL = r.externalURL
	integrations, err := receiver.BuildReceiverIntegrations(cfg.Receivers[0], tmpl, r.logger, commoncfg.WithDialContextFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("planning attempted provider I/O")
	}))
	require.NoError(t, err)
	targets, supported, err := actionDestinations(cfg, map[string][]notify.Integration{"team": integrations})
	require.NoError(t, err)
	require.True(t, supported)
	require.Len(t, targets["team"], 18)
	now := time.Now()
	m := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "Alarm", "host": "A"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	ctx := notify.WithNotificationReason(notify.WithReceiverName(notify.WithGroupLabels(notify.WithGroupKey(t.Context(), "group"), model.LabelSet{}), "team"), notify.ReasonUnknown)
	for _, target := range targets["team"] {
		t.Run(target.name, func(t *testing.T) {
			require.NotNil(t, target.prepared)
			digest, err := target.prepared.PreparedDigest(ctx, []byte(strings.Repeat("k", 32)), target.digest, []*alert.Alert{m})
			require.NoError(t, err)
			require.Len(t, digest, 64)
		})
	}
}

type transportFixturePermit struct {
	fixturePermit
	valid func() bool
}

func (p transportFixturePermit) Valid() bool { return p.valid() }

type transportFixtureJournal struct {
	terminalFixtureJournal
	permit transportFixturePermit
}

func (j *transportFixtureJournal) Claim(_ context.Context, _, key string) (v2.Entry, error) {
	j.claimed = append(j.claimed, key)
	return j.permit, nil
}

func TestOscarActionSelectedOpsgenieLaterMutationFenced(t *testing.T) {
	t.Parallel()
	received := make(chan string, 3)
	valid := make(chan struct{})
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Message string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		received <- body.Message
		select {
		case <-valid:
		default:
			close(valid)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer sink.Close()
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\n  group_by: [alertname]\nreceivers:\n- name: team\n  opsgenie_configs:\n  - api_url: %s\n    api_key: key\n    update_alerts: true\n    message: '{{ range .Alerts }}{{ .Labels.host }}{{ end }}'\n", sink.URL))
	require.NoError(t, err)
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now()
	member := func(host string) *alert.Alert {
		return alert.New(model.Alert{Labels: model.LabelSet{"alertname": "Alarm", "severity": "major", "host": model.LabelValue(host)}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	}
	a, b := member("A"), member("B")
	j := &transportFixtureJournal{permit: transportFixturePermit{fixturePermit{a}, func() bool {
		select {
		case <-valid:
			return false
		default:
			return true
		}
	}}}
	actions := newNativeActions(nil, []byte(strings.Repeat("k", 32)), r.logger)
	actions.version = 1
	r.actions = actions
	require.NoError(t, actions.Bind(j))
	require.NoError(t, r.reload(cfg))
	g := actions.snapshot()
	ctx := g.dispatcher.SelectedContext(t.Context(), g.routes, a)
	key, _ := notify.GroupKey(ctx)
	recv := &nflogpb.Receiver{GroupName: "team", Integration: "opsgenie"}
	hashes := []uint64{notify.HashAlert(a), notify.HashAlert(b)}
	require.NoError(t, r.notificationLog.Log(recv, key, hashes, nil, nil, nil, time.Hour))
	log := r.notificationLog.(*nflog.Log)
	before := log.LookupTiming(key, recv, hashes, 2)
	var p v2.EpisodeProjection
	start := a.StartsAt.UTC().Format(time.RFC3339Nano)
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"episode_ref":{"authority_id":"11111111-1111-4111-8111-111111111111","episode_id":"22222222-2222-4222-8222-222222222222","generation":1,"variant_revision":1},"native_variant":{"fingerprint":%q,"starts_at":%q},"active_since":%q,"state":"firing","source_severity":"major","lifecycle_seq":1}`, a.Fingerprint().String(), start, start)), &p))
	contacts, err := g.contacts(ctx, a, p, nil)
	require.NoError(t, err)
	require.Len(t, contacts, 1)
	c := contacts[0]
	sel := notify.SelectedAction{Source: a, Receiver: "team", Integration: "opsgenie", Invoke: func(ctx context.Context, i *notify.Integration, m *alert.Alert) notify.NotifyVerdict {
		v, _, _ := actions.invoke(ctx, g, i, []*alert.Alert{m}, []ordinaryContact{{operation: "operation", target: v2.TargetResult{TargetKey: "A", Target: c.DispatchTarget}, contact: c, p: p}}, 0)
		return v
	}}
	_, _, err = g.pipeline.Exec(notify.WithSelectedAction(ctx, sel), r.logger, a.NotificationCopy(now))
	require.Error(t, err)
	require.Len(t, received, 1)
	require.Equal(t, "A", <-received)
	require.Equal(t, []string{"A"}, j.claimed)
	require.Equal(t, []string{"unknown"}, j.settled)
	require.Equal(t, before, log.LookupTiming(key, recv, hashes, 2))
}

func TestOscarActionURLFileChangedDuringFinalClaimCheck(t *testing.T) {
	t.Parallel()
	calls := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls <- struct{}{} }))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "url")
	require.NoError(t, os.WriteFile(file, []byte(server.URL+"/before"), 0o600))
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\nreceivers:\n- name: team\n  webhook_configs:\n  - url_file: %s\n", file))
	require.NoError(t, err)
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now()
	a := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major", "host": "A"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	j := &transportFixtureJournal{permit: transportFixturePermit{fixturePermit{a}, func() bool { return os.WriteFile(file, []byte(server.URL+"/after"), 0o600) == nil }}}
	actions := newNativeActions(nil, nil, r.logger)
	actions.version = 1
	r.actions = actions
	require.NoError(t, actions.Bind(j))
	require.NoError(t, r.reload(cfg))
	g := actions.snapshot()
	ctx := g.dispatcher.SelectedContext(t.Context(), g.routes, a)
	var p v2.EpisodeProjection
	start := a.StartsAt.UTC().Format(time.RFC3339Nano)
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"episode_ref":{"authority_id":"11111111-1111-4111-8111-111111111111","episode_id":"22222222-2222-4222-8222-222222222222","generation":1,"variant_revision":1},"native_variant":{"fingerprint":%q,"starts_at":%q},"active_since":%q,"state":"firing","source_severity":"major","lifecycle_seq":1}`, a.Fingerprint().String(), start, start)), &p))
	contacts, err := g.contacts(ctx, a, p, nil)
	require.NoError(t, err)
	require.Len(t, contacts, 1)
	c := contacts[0]
	v, _, _ := actions.invoke(ctx, g, c.integration.prepared, []*alert.Alert{a.NotificationCopy(now)}, []ordinaryContact{{operation: "operation", target: v2.TargetResult{TargetKey: "A", Target: c.DispatchTarget}, contact: c, p: p}}, 0)
	require.Error(t, v.Err())
	require.Empty(t, calls)
	require.Equal(t, []string{"no_effect"}, j.settled)
}

func TestOscarActionTelegramDiagnosticPreservesPublishedFloor(t *testing.T) {
	t.Parallel()
	calls := make(chan struct{}, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls <- struct{}{} }))
	defer sink.Close()
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\nreceivers:\n- name: team\n  telegram_configs:\n  - api_url: %s\n    bot_token: token\n    chat_id: 123\n    parse_mode: HTML\n    message: '{{ (index .Alerts 0).Annotations.body }}'\n", sink.URL))
	require.NoError(t, err)
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now()
	s := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, Annotations: model.LabelSet{"body": model.LabelValue(strings.Repeat("x", 5000))}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	var p v2.EpisodeProjection
	start := s.StartsAt.UTC().Format(time.RFC3339Nano)
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"episode_ref":{"authority_id":"11111111-1111-4111-8111-111111111111","episode_id":"22222222-2222-4222-8222-222222222222","generation":1,"variant_revision":1},"native_variant":{"fingerprint":%q,"starts_at":%q},"active_since":%q,"state":"firing","source_severity":"major","floor":"critical","severity_revision":1,"lifecycle_seq":1}`, s.Fingerprint().String(), start, start)), &p))
	actions := newNativeActions(func(_, _ string, use func(*alert.Alert)) { use(s) }, nil, r.logger)
	actions.version = 1
	r.actions = actions
	j := &terminalFixtureJournal{projections: map[*alert.Alert]v2.EpisodeProjection{s: p}}
	require.NoError(t, actions.Bind(j))
	require.NoError(t, r.reload(cfg))
	require.NoError(t, actions.PublishSource(t.Context(), p, s))
	view := actions.ReadView(s)
	require.Equal(t, model.LabelValue("critical"), view.Labels["severity"])
	g := actions.snapshot()
	ctx := g.dispatcher.SelectedContext(t.Context(), g.routes, view)
	targets, err := g.contacts(ctx, s, p, nil)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	c := targets[0]
	v, delivered, _ := actions.invoke(ctx, g, c.integration.prepared, []*alert.Alert{view.NotificationCopy(now)}, []ordinaryContact{{operation: "operation", target: v2.TargetResult{TargetKey: p.EpisodeRef.EpisodeID, Target: c.DispatchTarget}, contact: c, p: p}}, 0)
	require.Error(t, v.Err())
	require.Equal(t, notify.EncodingErrorReason, v.Reason())
	require.Empty(t, delivered)
	require.Empty(t, calls)
	require.Equal(t, []string{"no_effect"}, j.settled)
	require.Equal(t, model.LabelValue("critical"), actions.ReadView(s).Labels["severity"])
}

func transportProjection(t *testing.T, s *alert.Alert, id, state string) v2.EpisodeProjection {
	t.Helper()
	var p v2.EpisodeProjection
	start := s.StartsAt.UTC().Format(time.RFC3339Nano)
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"episode_ref":{"authority_id":"11111111-1111-4111-8111-111111111111","episode_id":%q,"generation":1,"variant_revision":1},"native_variant":{"fingerprint":%q,"starts_at":%q},"active_since":%q,"state":%q,"source_severity":"major","lifecycle_seq":2}`, id, s.Fingerprint().String(), start, start, state)), &p))
	return p
}

func TestOscarActionPersistedTargetRevalidatesIndependently(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "url")
	require.NoError(t, os.WriteFile(file, []byte("http://example.invalid/dynamic"), 0o600))
	var calls atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer sink.Close()
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\nreceivers:\n- name: team\n  webhook_configs:\n  - url_file: %s\n  - url: %s\n", file, sink.URL))
	require.NoError(t, err)
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	a := newNativeActions(nil, nil, r.logger)
	a.version = 1
	r.actions = a
	now := time.Now()
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	p := transportProjection(t, source, "22222222-2222-4222-8222-222222222222", "firing")
	j := &terminalFixtureJournal{projections: map[*alert.Alert]v2.EpisodeProjection{source: p}}
	require.NoError(t, a.Bind(j))
	require.NoError(t, r.reload(cfg))
	req := v2.ActionRequestV1{}
	targets, _, err := a.Plan(t.Context(), source, p, req)
	require.NoError(t, err)
	require.Len(t, targets, 2)
	require.NoError(t, os.Remove(file))
	_, _, err = a.Plan(t.Context(), source, p, req)
	require.Error(t, err)
	valid, _, err := a.Plan(v2.WithPersistedTarget(t.Context(), targets[1]), source, p, req)
	require.NoError(t, err)
	require.Equal(t, targets[1:], valid)
	held, _, err := a.Plan(v2.WithPersistedTarget(t.Context(), targets[0]), source, p, req)
	require.NoError(t, err)
	require.Empty(t, held)
	g := a.snapshot()
	contacts, err := g.contacts(v2.WithPersistedTarget(t.Context(), targets[1]), source, p, nil)
	require.NoError(t, err)
	require.Len(t, contacts, 1)
	c := contacts[0]
	ctx := g.dispatcher.SelectedContext(t.Context(), c.route, source)
	sel := notify.SelectedAction{Source: source, Receiver: "team", Integration: "webhook", Index: 1, Invoke: func(ctx context.Context, i *notify.Integration, m *alert.Alert) notify.NotifyVerdict {
		v, _, _ := a.invoke(ctx, g, i, []*alert.Alert{m}, []ordinaryContact{{operation: "op", target: v2.TargetResult{TargetKey: p.EpisodeRef.EpisodeID, Target: c.DispatchTarget}, contact: c, p: p}}, 0)
		return v
	}}
	_, _, err = g.pipeline.Exec(notify.WithSelectedAction(ctx, sel), r.logger, source.NotificationCopy(now))
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())
	require.Equal(t, []string{"confirmed"}, j.settled)
}

func TestOscarActionIncidentResolvedTailThroughDispatcher(t *testing.T) {
	for _, scenario := range []string{"direct size tail", "tracked size tail", "inspection recovers", "sibling CAS recovers"} {
		tracked := scenario != "direct size tail"
		t.Run(scenario, func(t *testing.T) {
			seen := make(chan string, 6)
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var data struct {
					Alerts []struct{ Labels map[string]string }
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&data))
				if scenario != "sibling CAS recovers" {
					require.Len(t, data.Alerts, 1)
				}
				for _, a := range data.Alerts {
					seen <- a.Labels["host"]
				}
			}))
			defer sink.Close()
			groupInterval, waitForFlush := 500*time.Millisecond, 8*time.Second
			if scenario == "sibling CAS recovers" {
				groupInterval, waitForFlush = 31*time.Second, 40*time.Second
			}
			cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\n  group_by: [alertname]\n  group_wait: 2s\n  group_interval: %s\n  repeat_interval: 1h\nreceivers:\n- name: team\n  incidentio_configs:\n  - url: %s\n    send_resolved: true\n    alert_source_token: test\n", groupInterval, sink.URL))
			require.NoError(t, err)
			r := newTestReloader(t)
			t.Cleanup(func() { _ = r.stop() })
			a := newNativeActions(nil, nil, r.logger)
			a.version = 1
			r.actions = a
			j := &terminalFixtureJournal{state: "pending", projections: map[*alert.Alert]v2.EpisodeProjection{}}
			require.NoError(t, a.Bind(j))
			now := time.Now()
			var members []*alert.Alert
			var hashes []uint64
			size := 300 * 1024
			switch scenario {
			case "inspection recovers":
				j.failInspectHost, size = "A", 8
			case "sibling CAS recovers":
				j.failReserveAfterFirst, size = true, 8
			}
			for x, host := range []string{"A", "B"} {
				s := alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(host), "severity": "major", "alertname": "Alarm"}, Annotations: model.LabelSet{"body": model.LabelValue(host + strings.Repeat("x", size))}, StartsAt: now.Add(-time.Second), EndsAt: now.Add(-100 * time.Millisecond)}, now, false)
				require.NoError(t, r.alerts.Put(t.Context(), s))
				s, err = r.alerts.Get(s.Fingerprint())
				require.NoError(t, err)
				members = append(members, s)
				hashes = append(hashes, notify.HashAlert(s))
				if tracked {
					j.projections[s] = transportProjection(t, s, fmt.Sprintf("22222222-2222-4222-8222-%012d", x+1), "resolved")
				}
			}
			recv := &nflogpb.Receiver{GroupName: "team", Integration: "incidentio"}
			key := dispatch.GroupKeyForAlert(members[0], dispatch.NewRoute(cfg.Route, nil))
			require.NoError(t, r.notificationLog.Log(recv, key, hashes, nil, nil, nil, time.Hour))
			require.NoError(t, r.reload(cfg))
			var hosts []string
			for len(hosts) < 2 {
				select {
				case h := <-seen:
					hosts = append(hosts, h)
				case <-time.After(waitForFlush):
					t.Fatal("resolved tail lost", hosts)
				}
			}
			require.ElementsMatch(t, []string{"A", "B"}, hosts)
			if scenario == "inspection recovers" {
				require.Equal(t, []string{"B", "A"}, hosts)
			}
			require.Eventually(t, func() bool {
				groups, _, err := r.groups(t.Context(), func(*dispatch.Route) bool { return true }, func(*alert.Alert, time.Time) (alert.AlertStatus, bool) { return alert.AlertStatus{}, true })
				entries, e := r.notificationLog.Query(nflog.QGroupKey(key), nflog.QReceiver(recv))
				return err == nil && len(groups) == 0 && e == nil && len(entries) == 1 && len(entries[0].ResolvedAlerts) == 2
			}, 5*time.Second, 20*time.Millisecond)
			require.NoError(t, r.stop())
			if scenario == "sibling CAS recovers" {
				require.True(t, j.resumedExpired)
			}
			if tracked {
				require.Len(t, j.claimed, 2)
				require.Equal(t, []string{"confirmed", "confirmed"}, j.settled)
			}
			require.Empty(t, seen)
		})
	}
}

func TestOscarActionJiraResolvedNoSendAllowsRefire(t *testing.T) {
	t.Parallel()
	var writes atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "search") {
			_, _ = io.WriteString(w, `{"issues":[]}`)
			return
		}
		writes.Add(1)
		_, _ = io.WriteString(w, `{"key":"OPS-1"}`)
	}))
	defer sink.Close()
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\n  group_interval: 1h\n  repeat_interval: 2h\nreceivers:\n- name: team\n  jira_configs:\n  - api_url: %s\n    send_resolved: true\n    project: OPS\n    issue_type: Incident\n", sink.URL))
	require.NoError(t, err)
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	a := newNativeActions(nil, nil, r.logger)
	a.version = 1
	r.actions = a
	j := &terminalFixtureJournal{}
	require.NoError(t, a.Bind(j))
	require.NoError(t, r.reload(cfg))
	g := a.snapshot()
	now := time.Now()
	for x, end := range []time.Time{now.Add(time.Hour), now.Add(-time.Second), now.Add(time.Hour)} {
		s := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now.Add(-time.Minute), EndsAt: end}, now, false)
		ctx := g.dispatcher.SelectedContext(t.Context(), g.routes, s)
		ctx = notify.WithOrdinaryReader(ctx, func(c context.Context, r, k string, idx int, ms []*alert.Alert, due func([]*alert.Alert) bool) (notify.OrdinaryBatch, error) {
			return a.prepare(c, g, r, k, idx, ms, due)
		})
		_, _, err = g.pipeline.Exec(ctx, r.logger, s.NotificationCopy(now))
		require.NoError(t, err)
		require.EqualValues(t, []int{1, 1, 2}[x], writes.Load())
	}
}

func TestOscarActionDirectExpiryBetweenMutations(t *testing.T) {
	t.Parallel()
	var writes atomic.Int32
	var expires time.Time
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		<-time.After(time.Until(expires) + time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer sink.Close()
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\nreceivers:\n- name: team\n  opsgenie_configs:\n  - api_url: %s\n    api_key: key\n    update_alerts: true\n", sink.URL))
	require.NoError(t, err)
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	a := newNativeActions(nil, nil, r.logger)
	a.version = 1
	r.actions = a
	require.NoError(t, a.Bind(&terminalFixtureJournal{}))
	require.NoError(t, r.reload(cfg))
	g := a.snapshot()
	now := time.Now()
	expires = now.Add(500 * time.Millisecond)
	s := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now.Add(-time.Minute), EndsAt: expires}, now, false)
	ctx := g.dispatcher.SelectedContext(t.Context(), g.routes, s)
	m := s.NotificationCopy(now)
	possible, err := g.matchContacts(ctx, s, m, []*alert.Alert{m}, nil)
	require.NoError(t, err)
	require.Len(t, possible, 1)
	c := possible[0]
	var conclusive bool
	finished := 0
	pass := &v2.OrdinaryPass{Enter: func() bool { return true }, Valid: func() bool { return true }, Finish: func(ok bool) { finished++; conclusive = ok }}
	verdict, accepted, _ := a.invoke(ctx, g, c.integration.prepared, []*alert.Alert{m}, []ordinaryContact{{pass: pass, contact: c}}, 0)
	require.Error(t, verdict.Err())
	require.Empty(t, accepted)
	require.EqualValues(t, 1, writes.Load())
	require.Equal(t, 1, finished)
	require.False(t, conclusive)
}

func TestPersistentResolutionHoldPreservesProgressAndFiringRepeat(t *testing.T) {
	var repeats atomic.Int32
	messages := make(chan []string, 32)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data struct {
			Alerts []struct{ Labels map[string]string }
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&data))
		var hosts []string
		for _, m := range data.Alerts {
			host := m.Labels["host"]
			if host == "C" {
				repeats.Add(1)
			}
			hosts = append(hosts, host)
		}
		messages <- hosts
	}))
	defer sink.Close()
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\n  group_by: [alertname]\n  group_wait: 1s\n  group_interval: 200ms\n  repeat_interval: 2s\nreceivers:\n- name: team\n  incidentio_configs:\n  - url: %s\n    send_resolved: true\n    alert_source_token: test\n", sink.URL))
	require.NoError(t, err)
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	a := newNativeActions(nil, nil, r.logger)
	a.version = 1
	r.actions = a
	j := &terminalFixtureJournal{state: "pending", projections: map[*alert.Alert]v2.EpisodeProjection{}}
	require.NoError(t, a.Bind(j))
	recv := &nflogpb.Receiver{GroupName: "team", Integration: "incidentio"}
	now := time.Now()
	var hashes []uint64
	var key string
	for i, host := range []string{"A", "B", "C", "D", "E"} {
		end := now.Add(-time.Millisecond)
		if host == "C" {
			end = now.Add(time.Hour)
		}
		s := alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(host), "severity": "major", "alertname": "Alarm"}, StartsAt: now.Add(-time.Minute), EndsAt: end}, now, false)
		require.NoError(t, r.alerts.Put(t.Context(), s))
		s, err = r.alerts.Get(s.Fingerprint())
		require.NoError(t, err)
		key = dispatch.GroupKeyForAlert(s, dispatch.NewRoute(cfg.Route, nil))
		hashes = append(hashes, notify.HashAlert(s))
		if host == "A" || host == "D" || host == "E" {
			j.projections[s] = transportProjection(t, s, fmt.Sprintf("22222222-2222-4222-8222-%012d", i+1), "resolved")
		}
	}
	require.NoError(t, r.notificationLog.Log(recv, key, hashes, nil, nil, nil, time.Hour))
	var stamps []time.Time
	j.inspectSource = func(s *alert.Alert) error {
		if s.Labels["host"] != "A" {
			return nil
		}
		rows, err := r.notificationLog.Query(nflog.QGroupKey(key), nflog.QReceiver(recv))
		require.NoError(t, err)
		require.Len(t, rows, 1)
		stamps = append(stamps, rows[0].Timestamp.AsTime())
		if repeats.Load() < 2 {
			return errors.New("A still unavailable")
		}
		return nil
	}
	require.NoError(t, r.reload(cfg))
	read := func() []string {
		select {
		case hosts := <-messages:
			return hosts
		case <-time.After(8 * time.Second):
			t.Fatal("expected next dispatcher delivery")
			return nil
		}
	}
	require.ElementsMatch(t, []string{"B", "C", "D", "E"}, read())
	require.Equal(t, []string{"C"}, read())
	require.Equal(t, []string{"A"}, read())
	require.Eventually(t, func() bool {
		groups, _, err := r.groups(t.Context(), func(*dispatch.Route) bool { return true }, func(*alert.Alert, time.Time) (alert.AlertStatus, bool) { return alert.AlertStatus{}, true })
		return err == nil && len(groups) == 1 && len(groups[0].Alerts) == 1
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, r.stop())
	require.Empty(t, messages)
	require.GreaterOrEqual(t, len(stamps), 5)
	for _, unchanged := range stamps[2 : len(stamps)-1] {
		require.Equal(t, stamps[1], unchanged)
	}
	require.True(t, stamps[len(stamps)-1].After(stamps[1]))
	require.Equal(t, []string{"confirmed", "confirmed", "confirmed"}, j.settled)
}

type lastTransitionPermit struct {
	fixturePermit
	gate *nativeActions
}

func (e *lastTransitionPermit) EntryFence() (time.Time, func() bool) {
	// A graph writer already owns the publication lock. The original permit
	// expires while the provider is waiting to perform its last local transition.
	e.gate.mu.Lock()
	end := time.Now().Add(15 * time.Millisecond)
	go func() { <-time.After(time.Until(end)); e.gate.mu.Unlock() }()
	return end, func() bool { return true }
}

type lastTransitionJournal struct {
	terminalFixtureJournal
	permit   *lastTransitionPermit
	original v2.Entry
}

func (j *lastTransitionJournal) Claim(context.Context, string, string) (v2.Entry, error) {
	return j.permit, nil
}
func (j *lastTransitionJournal) Settle(_ context.Context, e v2.Entry, outcome, _ string) (v2.ActionResultV1, error) {
	j.original = e
	j.settled = append(j.settled, outcome)
	return v2.ActionResultV1{}, nil
}

func TestOscarActionOriginalClaimExpiresWaitingForFinalPublication(t *testing.T) {
	var writes atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { writes.Add(1) }))
	defer sink.Close()
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	file := filepath.Join(t.TempDir(), "url")
	require.NoError(t, os.WriteFile(file, []byte(sink.URL), 0600))
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\nreceivers:\n- name: team\n  webhook_configs:\n  - url_file: %s\n", file))
	require.NoError(t, err)
	a := newNativeActions(nil, nil, r.logger)
	r.actions = a
	now := time.Now()
	s := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	p := restoredFixture(t, s)
	p.Floor = ""
	j := &lastTransitionJournal{permit: &lastTransitionPermit{fixturePermit{s}, a}}
	require.NoError(t, a.Bind(j))
	require.NoError(t, r.reload(cfg))
	g := a.snapshot()
	ctx := g.dispatcher.SelectedContext(t.Context(), g.routes, s)
	cs, err := g.contacts(ctx, s, p, nil)
	require.NoError(t, err)
	require.Len(t, cs, 1)
	c := cs[0]
	v, _, _ := a.invoke(ctx, g, c.integration.prepared, []*alert.Alert{s.NotificationCopy(now)}, []ordinaryContact{{p: p, contact: c, operation: "selected", target: v2.TargetResult{Target: c.DispatchTarget, TargetKey: "original"}}}, 0)
	require.Error(t, v.Err())
	require.Zero(t, writes.Load())
	require.Same(t, j.permit, j.original)
	require.Equal(t, []string{"no_effect"}, j.settled)
}
