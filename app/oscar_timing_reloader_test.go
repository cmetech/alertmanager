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
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/common/route"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/nflog"
	"github.com/prometheus/alertmanager/nflog/nflogpb"
	"github.com/prometheus/alertmanager/notify"
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
