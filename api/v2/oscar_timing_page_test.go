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

package v2

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/labelset"
	"github.com/prometheus/alertmanager/nflog"
	"github.com/prometheus/alertmanager/nflog/nflogpb"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/provider/mem"
)

func TestOscarPageTimingUsesSelectedNativeAlertAndNotificationLog(t *testing.T) {
	alerts, err := mem.NewAlerts(t.Context(), time.Minute, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(alerts.Close)
	api, err := NewAPI(alerts, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: team\n  group_by: [alertname]\n  repeat_interval: 1h\nreceivers:\n- name: team\n")
	require.NoError(t, err)
	api.Update(cfg, func(context.Context, labelset.LabelSet) {})
	now := time.Now().UTC().Truncate(time.Second)
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown", "instance": "node-1"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(30 * time.Minute)}, now, true)
	a.EndTimeSource = alert.EndTimeSourceAlertmanagerTimeout
	a.ResolveTimeout = 30 * time.Minute
	require.NoError(t, alerts.Put(t.Context(), a))
	baseline := now.Add(-10 * time.Minute)
	hash := notify.HashAlert(a)
	lookups := 0
	api.PublishTiming(cfg, map[string][]TimingIntegration{"team": {{Name: "webhook", Index: 0}}}, nil,
		func(group string, recv *nflogpb.Receiver, hashes []uint64, budget int) nflog.TimingLookup {
			lookups++
			require.Equal(t, "team", recv.GroupName)
			require.Equal(t, "webhook", recv.Integration)
			require.Equal(t, []uint64{hash}, hashes)
			require.GreaterOrEqual(t, budget, 1)
			return nflog.TimingLookup{Found: true, Timestamp: baseline, ExpiresAt: baseline.Add(2 * time.Hour), Firing: map[uint64]bool{hash: true}, Inspected: 1}
		})

	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		api.Handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		require.Equal(t, 200, w.Code, w.Body.String())
		return w
	}
	page := request("/api/v2/oscar/alerts/page?perPage=1")
	legacy := request("/api/v2/alerts")
	var got struct {
		Records []json.RawMessage `json:"records"`
		Timing  map[string]struct {
			EndSource   string `json:"end_time_source"`
			Timeout     string `json:"resolve_timeout_duration"`
			LookupState string `json:"repeat_lookup_state"`
			Schedules   []struct {
				RouteID     string     `json:"route_id"`
				Receiver    string     `json:"receiver"`
				Integration string     `json:"integration"`
				Repeat      string     `json:"repeat_interval_duration"`
				Next        *time.Time `json:"next_repeat_eligible_at"`
				State       string     `json:"state"`
			} `json:"repeat_schedules"`
		} `json:"timing_by_fingerprint"`
	}
	require.NoError(t, json.Unmarshal(page.Body.Bytes(), &got))
	var native []json.RawMessage
	require.NoError(t, json.Unmarshal(legacy.Body.Bytes(), &native))
	require.Equal(t, native, got.Records)
	timing, ok := got.Timing[a.Fingerprint().String()]
	require.True(t, ok)
	require.Equal(t, "alertmanager_timeout", timing.EndSource)
	require.Equal(t, "30m0s", timing.Timeout)
	require.Equal(t, "ready", timing.LookupState)
	require.Len(t, timing.Schedules, 1)
	require.NotEmpty(t, timing.Schedules[0].RouteID)
	require.Equal(t, "team", timing.Schedules[0].Receiver)
	require.Equal(t, "webhook/0", timing.Schedules[0].Integration)
	require.Equal(t, "1h0m0s", timing.Schedules[0].Repeat)
	require.Equal(t, "estimated", timing.Schedules[0].State)
	require.NotNil(t, timing.Schedules[0].Next)
	require.True(t, timing.Schedules[0].Next.Equal(baseline.Add(time.Hour)))
	require.Equal(t, 1, lookups)
	require.Equal(t, float64(1), testutil.ToFloat64(api.timingLookups))
	require.Equal(t, float64(1), testutil.ToFloat64(api.timingInspected))
	require.Equal(t, float64(0), testutil.ToFloat64(api.timingCappedPaths))
}

func TestOscarPageTimingConcurrentNativeLogReplacement(t *testing.T) {
	reg := prometheus.NewRegistry()
	alerts, err := mem.NewAlerts(t.Context(), time.Minute, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), reg, nil)
	require.NoError(t, err)
	t.Cleanup(alerts.Close)
	api, err := NewAPI(alerts, nil, nil, nil, promslog.NewNopLogger(), reg)
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: team\n  group_by: [alertname]\n  repeat_interval: 1h\nreceivers:\n- name: team\n")
	require.NoError(t, err)
	api.Update(cfg, func(context.Context, labelset.LabelSet) {})
	now := time.Now()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	require.NoError(t, alerts.Put(t.Context(), a))
	log, err := nflog.New(nflog.Options{Retention: 4 * time.Hour, Metrics: prometheus.NewRegistry()})
	require.NoError(t, err)
	route := dispatch.NewRoute(cfg.Route, nil).Match(a.Labels)[0]
	key := dispatch.GroupKeyForAlert(a, route)
	recv := &nflogpb.Receiver{GroupName: "team", Integration: "webhook", Idx: 0}
	api.PublishTiming(cfg, map[string][]TimingIntegration{"team": {{Name: "webhook", Index: 0}}}, nil, log.LookupTiming)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 100; i++ {
			firing := []uint64{notify.HashAlert(a)}
			if i%2 == 0 {
				firing = nil
			}
			if err := log.Log(recv, key, firing, nil, nil, nil, 2*time.Hour); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		api.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
		require.Equal(t, 200, w.Code, w.Body.String())
		var page struct {
			Timing map[string]struct {
				Schedules []struct {
					State string `json:"state"`
				} `json:"repeat_schedules"`
			} `json:"timing_by_fingerprint"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
		require.Len(t, page.Timing[a.Fingerprint().String()].Schedules, 1)
		state := page.Timing[a.Fingerprint().String()].Schedules[0].State
		require.Contains(t, []string{"estimated", "no_repeat_baseline"}, state)
	}
	require.NoError(t, <-done)
}
