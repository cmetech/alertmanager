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
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/route"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/api"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/featurecontrol"
	"github.com/prometheus/alertmanager/nflog"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/alertmanager/provider/mem"
	"github.com/prometheus/alertmanager/silence"
	"github.com/prometheus/alertmanager/tracing"
)

// newTestReloader builds a reloader backed by real (but local, cluster-
// disabled) collaborators, mirroring how setup wires it. It is the
// minimum needed to exercise reload/stop in isolation from HTTP.
func newTestReloader(t *testing.T) *reloader {
	t.Helper()

	logger := promslog.NewNopLogger()
	reg := prometheus.NewRegistry()
	ff, err := featurecontrol.NewFlags(logger, "")
	require.NoError(t, err)

	m := newMetrics(reg)
	rec := eventrecorder.NopRecorder()
	dir := t.TempDir()

	alerts, err := mem.NewAlerts(context.Background(), 30*time.Minute, 0, nil, logger, rec, reg, ff)
	require.NoError(t, err)
	t.Cleanup(alerts.Close)

	silences, err := silence.New(silence.Options{
		SnapshotFile: filepath.Join(dir, "silences"),
		Logger:       logger,
		Metrics:      reg,
	})
	require.NoError(t, err)
	silencer := silence.NewSilencer(silences, logger, rec)

	nflogger, err := nflog.New(nflog.Options{
		SnapshotFile: filepath.Join(dir, "nflog"),
		Logger:       logger,
		Metrics:      reg,
	})
	require.NoError(t, err)

	// The reloader owns the dispatcher/inhibitor; the API's GroupFunc
	// reads them through r, which is assigned just below (mirroring setup).
	var r *reloader

	apih, err := api.New(api.Options{
		Alerts:          alerts,
		Silences:        silences,
		Logger:          logger,
		Registry:        reg,
		RequestDuration: m.requestDuration,
		GroupFunc: func(ctx context.Context, rf func(*dispatch.Route) bool, af dispatch.AlertFilter) (dispatch.AlertGroups, map[model.Fingerprint][]string, error) {
			return r.groups(ctx, rf, af)
		},
	})
	require.NoError(t, err)

	extURL, err := url.Parse("http://localhost:9093")
	require.NoError(t, err)

	r = &reloader{
		logger:                      logger,
		alerts:                      alerts,
		silencer:                    silencer,
		notificationLog:             nflogger,
		eventRecorder:               rec,
		apih:                        apih,
		tracingMgr:                  tracing.NewManager(logger),
		pipelineBuilder:             notify.NewPipelineBuilder(reg, ff, rec),
		dispatcherMetrics:           dispatch.NewDispatcherMetrics(false, reg, ff),
		metrics:                     m,
		peer:                        nil,
		waitFunc:                    func() time.Duration { return 0 },
		timeoutFunc:                 func(d time.Duration) time.Duration { return d },
		externalURL:                 extURL,
		startTime:                   time.Now(),
		dispatchStartDelay:          0,
		dispatchMaintenanceInterval: 30 * time.Second,
		retention:                   120 * time.Hour,
	}
	return r
}

func mustConfig(t *testing.T) *config.Config {
	t.Helper()
	conf, err := config.Load(minimalConfig)
	require.NoError(t, err)
	return conf
}

func TestReloader_SwapsComponents(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })

	// Initial apply installs a running inhibitor and dispatcher.
	require.NoError(t, r.reload(mustConfig(t)))
	dispatcher1 := r.dispatcher.Load()
	inh1 := r.inhibitor.Load()
	require.NotNil(t, dispatcher1)
	require.NotNil(t, inh1)

	// A second apply must stop the old pair and publish fresh instances.
	require.NoError(t, r.reload(mustConfig(t)))
	require.NotNil(t, r.dispatcher.Load())
	require.NotNil(t, r.inhibitor.Load())
	require.NotSame(t, dispatcher1, r.dispatcher.Load(), "dispatcher should be replaced on reload")
	require.NotSame(t, inh1, r.inhibitor.Load(), "inhibitor should be replaced on reload")
}

func TestReloader_ErrorLeavesPreviousStateIntact(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })

	require.NoError(t, r.reload(mustConfig(t)))
	dispatcher1 := r.dispatcher.Load()
	inh1 := r.inhibitor.Load()

	// A template that fails to parse makes reload error out before it
	// swaps anything, so the previously active components stay in place.
	bad := filepath.Join(t.TempDir(), "bad.tmpl")
	require.NoError(t, os.WriteFile(bad, []byte("{{ .Foo "), 0o600))
	conf := mustConfig(t)
	conf.Templates = []string{bad}

	require.Error(t, r.reload(conf))
	require.Same(t, dispatcher1, r.dispatcher.Load(), "dispatcher must be unchanged after a failed reload")
	require.Same(t, inh1, r.inhibitor.Load(), "inhibitor must be unchanged after a failed reload")
}

// TestReloader_GroupMutedByFollowsConfig checks that queries use the time
// intervals of their dispatcher's configuration even when a reload occurs
// during the query.
func TestReloader_GroupMutedByFollowsConfig(t *testing.T) {
	t.Parallel()
	synctest.Test(t, testReloaderGroupMutedByFollowsConfig)
}

func testReloaderGroupMutedByFollowsConfig(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })

	const confTmpl = `
route:
  receiver: team-X
  group_by: ['alertname']
  group_wait: 1h
  routes:
  - receiver: team-X
    mute_time_intervals: ['%s']
receivers:
- name: team-X
time_intervals:
- name: %s
  time_intervals:
  - weekdays: ['monday:sunday']
`
	load := func(name string) *config.Config {
		conf, err := config.Load(fmt.Sprintf(confTmpl, name, name))
		require.NoError(t, err)
		return conf
	}
	alertFilter := func(*alert.Alert, time.Time) (alert.AlertStatus, bool) { return alert.AlertStatus{}, true }
	mutedBy := func(t *testing.T) []string {
		t.Helper()
		groups, _, err := r.groups(t.Context(), func(*dispatch.Route) bool { return true }, alertFilter)
		require.NoError(t, err)
		require.Len(t, groups, 1)
		return groups[0].MutedBy()
	}

	require.NoError(t, r.reload(load("always_old")))
	now := time.Now()
	require.NoError(t, r.alerts.Put(context.Background(), alert.New(model.Alert{
		Labels:   model.LabelSet{"alertname": "Foo"},
		StartsAt: now.Add(-time.Minute),
		EndsAt:   now.Add(time.Hour),
	}, now, false)))
	synctest.Wait()
	require.Equal(t, []string{"always_old"}, mutedBy(t))

	// Pause a query after it has selected the old dispatcher's route but
	// before it resolves the route's interval names.
	ctx := t.Context()
	resumeQuery := make(chan struct{})
	var (
		queryPaused bool
		groups      dispatch.AlertGroups
		queryErr    error
	)
	go func() {
		groups, _, queryErr = r.groups(ctx, func(rt *dispatch.Route) bool {
			if len(rt.RouteOpts.MuteTimeIntervals) > 0 {
				queryPaused = true
				select {
				case <-resumeQuery:
				case <-ctx.Done():
				}
			}
			return true
		}, alertFilter)
	}()
	synctest.Wait()
	require.True(t, queryPaused)

	// Rename the interval while the query is paused. A new query uses the
	// new definitions, even though the in-flight query still needs the old ones.
	require.NoError(t, r.reload(load("always_new")))
	synctest.Wait()
	require.Equal(t, []string{"always_new"}, mutedBy(t))

	close(resumeQuery)
	synctest.Wait()
	require.NoError(t, queryErr)
	require.Len(t, groups, 1)
	require.Equal(t, []string{"always_old"}, groups[0].MutedBy())
}

func TestReloader_StopIsNilSafe(t *testing.T) {
	r := newTestReloader(t)
	// stop before any reload (both pointers nil) must not panic.
	require.NoError(t, r.stop())
}

type pageGateProvider struct {
	provider.Alerts
	enabled atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (p *pageGateProvider) GetPending() provider.AlertIterator {
	it := p.Alerts.GetPending()
	if !p.enabled.CompareAndSwap(true, false) {
		return it
	}
	out := make(chan *provider.Alert)
	done := make(chan struct{})
	go func() {
		defer close(out)
		defer it.Close()
		close(p.entered)
		select {
		case <-p.release:
		case <-done:
			return
		}
		for a := range it.Next() {
			select {
			case out <- a:
			case <-done:
				return
			}
		}
	}()
	return provider.NewAlertIterator(out, done, nil)
}

func TestReloader_PageKeepsGenerationAndCapturedSet(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	logger := promslog.NewNopLogger()
	reg := prometheus.NewRegistry()
	silences, err := silence.New(silence.Options{Metrics: reg, Logger: logger})
	require.NoError(t, err)
	r.silencer = silence.NewSilencer(silences, logger, eventrecorder.NopRecorder())
	gate := &pageGateProvider{Alerts: r.alerts, entered: make(chan struct{}), release: make(chan struct{})}
	apih, err := api.New(api.Options{Alerts: gate, Silences: silences, Logger: logger, Registry: reg, RequestDuration: newMetrics(reg).requestDuration, GroupFunc: r.groups})
	require.NoError(t, err)
	r.apih = apih
	handler := apih.Register(route.New(), "")
	call := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(w, req)
		return w
	}
	now := time.Now()
	for _, labels := range []model.LabelSet{{"alertname": "Test", "severity": "critical"}, {"alertname": "Test", "severity": "warning"}, {"alertname": "Silenced", "instance": "quiet"}} {
		require.NoError(t, r.alerts.Put(t.Context(), alert.New(model.Alert{Labels: labels, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)))
	}
	// This provider uses a long GC interval: the expired alert is present in
	// storage but both endpoints must exclude it before collection.
	expired := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "Expired"}, StartsAt: now.Add(-2 * time.Hour), EndsAt: now.Add(-time.Hour)}, now, false)
	require.NoError(t, r.alerts.Put(t.Context(), expired))
	stored, err := r.alerts.Get(expired.Fingerprint())
	require.NoError(t, err)
	require.NotNil(t, stored)
	load := func(receiver string, inhibit bool) *config.Config {
		yaml := fmt.Sprintf("route:\n  receiver: %s\n  group_wait: 1h\nreceivers:\n- name: %s\n", receiver, receiver)
		if inhibit {
			yaml += "inhibit_rules:\n- source_matchers: ['severity=\"critical\"']\n  target_matchers: ['severity=\"warning\"']\n  equal: [alertname]\n"
		}
		cfg, e := config.Load(yaml)
		require.NoError(t, e)
		return cfg
	}
	require.NoError(t, r.reload(load("old", true)))
	body := fmt.Sprintf(`{"matchers":[{"name":"instance","value":"quiet","isRegex":false}],"startsAt":%q,"endsAt":%q,"createdBy":"test","comment":"test"}`, now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano))
	w := call("POST", "/api/v2/silences", body)
	require.Equal(t, 200, w.Code, w.Body.String())
	legacy := call("GET", "/api/v2/alerts", "")
	require.Equal(t, 200, legacy.Code, legacy.Body.String())
	require.Contains(t, legacy.Body.String(), `"inhibitedBy":["`)
	require.Contains(t, legacy.Body.String(), `"silencedBy":["`)
	for _, query := range []string{"active=false", "silenced=false", "inhibited=false", "filter=" + url.QueryEscape(`severity=~"warning|critical"`), "filter=" + url.QueryEscape(`instance=""`), "filter=" + url.QueryEscape(`instance!=""`), "receiver=old", "receiver_matchers=" + url.QueryEscape(`owner="missing"`)} {
		unpaged := call("GET", "/api/v2/alerts?"+query, "")
		paged := call("GET", "/api/v2/oscar/alerts/page?column=fingerprint&order=asc&perPage=100&"+query, "")
		require.Equal(t, 200, unpaged.Code, query)
		require.Equal(t, 200, paged.Code, query)
		var expected []json.RawMessage
		var actual struct {
			Records []json.RawMessage `json:"records"`
			Total   int               `json:"total_records"`
		}
		require.NoError(t, json.Unmarshal(unpaged.Body.Bytes(), &expected))
		require.NoError(t, json.Unmarshal(paged.Body.Bytes(), &actual))
		require.Equal(t, expected, actual.Records, query)
		require.Equal(t, len(expected), actual.Total, query)
	}
	gate.enabled.Store(true)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- call("GET", "/api/v2/oscar/alerts/page?column=fingerprint&order=asc&perPage=100", "")
	}()
	<-gate.entered
	require.NoError(t, r.alerts.Put(t.Context(), alert.New(model.Alert{Labels: model.LabelSet{"alertname": "Later"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)))
	require.NoError(t, r.reload(load("new", false)))
	close(gate.release)
	page := <-result
	require.Equal(t, 200, page.Code, page.Body.String())
	var got struct {
		Records []json.RawMessage `json:"records"`
		Total   int               `json:"total_records"`
	}
	require.NoError(t, json.Unmarshal(page.Body.Bytes(), &got))
	var before []json.RawMessage
	require.NoError(t, json.Unmarshal(legacy.Body.Bytes(), &before))
	require.Equal(t, 3, got.Total)
	require.Equal(t, before, got.Records)
	next := call("GET", "/api/v2/oscar/alerts/page?column=fingerprint&order=asc&perPage=100", "")
	require.Equal(t, 200, next.Code, next.Body.String())
	require.NoError(t, json.Unmarshal(next.Body.Bytes(), &got))
	require.Equal(t, 4, got.Total)
	require.Contains(t, next.Body.String(), `"name":"new"`)
	require.NotContains(t, next.Body.String(), `"inhibitedBy":["`)
	after := call("GET", "/api/v2/alerts", "")
	require.NoError(t, json.Unmarshal(after.Body.Bytes(), &before))
	require.Equal(t, before, got.Records)
}
