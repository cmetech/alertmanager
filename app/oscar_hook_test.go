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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/oscarstate"
	"github.com/prometheus/alertmanager/oscarstate/memadapter"
	"github.com/prometheus/alertmanager/provider/mem"
)

func TestOSCARAppHookNativePipeline(t *testing.T) {
	receipts := make(chan string, 20)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receipts <- string(body)
		w.WriteHeader(200)
	}))
	defer receiver.Close()
	opts := testOptions(t)
	opts.AlertGCInterval = 100 * time.Millisecond
	opts.GetConcurrency = 1
	opts.HTTPTimeout = 100 * time.Millisecond
	writeConfig := func(name string) {
		require.NoError(t, os.WriteFile(opts.ConfigFile, []byte(fmt.Sprintf(`global:
  resolve_timeout: 1s
route:
  receiver: %s
  group_by: [alertname]
  group_wait: 10ms
  group_interval: 20ms
  repeat_interval: 1h
inhibit_rules:
  - source_matchers: ['severity="critical"']
    target_matchers: ['severity="warning"']
    equal: [alertname]
receivers:
  - name: %s
    webhook_configs:
      - url: %s
`, name, name, receiver.URL)), 0o600))
	}
	writeConfig("proof-a")
	f := oscarstate.NewFeed(100, "")
	observer := memadapter.New(f)
	var provider *mem.Alerts
	opts.StateObserver = observer
	opts.ProbeHandler = func(p *mem.Alerts) http.Handler {
		provider = p
		return oscarstate.NewProbeHandler(func() oscarstate.Snapshot { return observer.Snapshot(p) }, f)
	}
	a, err := New(opts)
	require.NoError(t, err)
	require.NoError(t, a.Start())
	t.Cleanup(func() { require.NoError(t, a.Stop(context.Background())) })
	waitHealthy(t, a.Addr())
	base := "http://" + a.Addr()
	request := func(method, path, body string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, data
	}
	post := func(body string) {
		t.Helper()
		code, data := request("POST", "/api/v2/alerts", body)
		require.Equal(t, 200, code, string(data))
	}
	post(`[{"labels":{"alertname":"Delivery","instance":"one"}},{"labels":{"alertname":"Inhibited","severity":"critical"}},{"labels":{"alertname":"Inhibited","severity":"warning"}}]`)
	code, data := request("GET", "/_oscar/probe/snapshot", "")
	require.Equal(t, 200, code)
	var snapshot oscarstate.Snapshot
	require.NoError(t, json.Unmarshal(data, &snapshot))
	require.Len(t, snapshot.Alerts, 3)
	require.Equal(t, uint64(3), snapshot.Cursor.Sequence)
	code, data = request("GET", "/api/v2/alerts", "")
	require.Equal(t, 200, code)
	require.Contains(t, string(data), "proof-a")
	require.Eventually(t, func() bool {
		_, data := request("GET", "/api/v2/alerts", "")
		return strings.Contains(string(data), `"inhibitedBy":["`)
	}, 3*time.Second, 10*time.Millisecond)
	select {
	case receipt := <-receipts:
		require.Contains(t, receipt, "proof-a")
	case <-time.After(3 * time.Second):
		t.Fatal("native dispatcher produced no notification")
	}
	now := time.Now()
	silenceBody := fmt.Sprintf(`{"matchers":[{"name":"instance","value":"one","isRegex":false}],"startsAt":%q,"endsAt":%q,"createdBy":"proof","comment":"proof"}`, now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano))
	code, data = request("POST", "/api/v2/silences", silenceBody)
	require.Equal(t, 200, code, string(data))
	_, data = request("GET", "/api/v2/alerts", "")
	require.Contains(t, string(data), `"silencedBy":["`)
	writeConfig("proof-b")
	code, data = request("POST", "/-/reload", "")
	require.Equal(t, 200, code, string(data))
	_, data = request("GET", "/api/v2/alerts", "")
	require.Contains(t, string(data), "proof-b")
	require.NoError(t, a.Reload())
	require.True(t, provider.TryHeartbeat(time.Second))
	batch, err := f.Read(snapshot.Cursor, 100)
	require.NoError(t, err)
	require.False(t, batch.HeartbeatAt.IsZero())
	require.Eventually(t, func() bool { s := observer.Snapshot(provider); return len(s.Alerts) == 0 }, 4*time.Second, 20*time.Millisecond)
	batch, err = f.Read(snapshot.Cursor, 100)
	require.NoError(t, err)
	require.Len(t, batch.Changes, 3)
	for _, change := range batch.Changes {
		require.Equal(t, oscarstate.Delete, change.Kind)
	}
}

func TestOSCARAppHookGETConcurrency(t *testing.T) {
	opts := testOptions(t)
	opts.GetConcurrency = 1
	opts.HTTPTimeout = time.Second
	var provider *mem.Alerts
	opts.ProbeHandler = func(p *mem.Alerts) http.Handler { provider = p; return http.NotFoundHandler() }
	a, err := New(opts)
	require.NoError(t, err)
	require.NoError(t, a.Start())
	defer a.Stop(context.Background())
	locked, release, unlocked := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		provider.SnapshotWithSequence(func() uint64 { close(locked); <-release; return 0 })
		close(unlocked)
	}()
	<-locked
	first := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + a.Addr() + "/api/v2/alerts")
		if err != nil {
			first <- 0
			return
		}
		defer resp.Body.Close()
		first <- resp.StatusCode
	}()
	require.Eventually(t, func() bool {
		metrics, err := opts.Registerer.(interface {
			Gather() ([]*dto.MetricFamily, error)
		}).Gather()
		require.NoError(t, err)
		for _, m := range metrics {
			if m.GetName() == "alertmanager_http_requests_in_flight" {
				return m.Metric[0].Gauge.GetValue() == 1
			}
		}
		return false
	}, time.Second, time.Millisecond)
	resp, err := http.Get("http://" + a.Addr() + "/api/v2/alerts")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	close(release)
	<-unlocked
	require.Equal(t, 200, <-first)
}

type oscarPausedWriter struct {
	http.ResponseWriter
	entered, release chan struct{}
	once             sync.Once
}

func (w *oscarPausedWriter) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return w.ResponseWriter.Write(b)
}

func TestOSCARAppHookFixedSnapshotTransfer(t *testing.T) {
	opts := testOptions(t)
	opts.AlertGCInterval = 10 * time.Millisecond
	f := oscarstate.NewFeed(20, "")
	observer := memadapter.New(f)
	opts.StateObserver = observer
	entered, release := make(chan struct{}), make(chan struct{})
	var provider *mem.Alerts
	opts.ProbeHandler = func(p *mem.Alerts) http.Handler {
		provider = p
		h := oscarstate.NewProbeHandler(func() oscarstate.Snapshot { return observer.Snapshot(p) }, f)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("pause") == "1" {
				h.ServeHTTP(&oscarPausedWriter{ResponseWriter: w, entered: entered, release: release}, r)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	a, err := New(opts)
	require.NoError(t, err)
	require.NoError(t, a.Start())
	defer a.Stop(context.Background())
	base := "http://" + a.Addr()
	post := func(body string) {
		resp, err := http.Post(base+"/api/v2/alerts", "application/json", strings.NewReader(body))
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, 200, resp.StatusCode)
	}
	post(fmt.Sprintf(`[{"labels":{"alertname":"Old"},"startsAt":%q}]`, time.Now().Add(-time.Minute).Format(time.RFC3339Nano)))
	result := make(chan oscarstate.Snapshot, 1)
	errors := make(chan error, 1)
	go func() {
		resp, err := http.Get(base + "/_oscar/probe/snapshot?pause=1")
		if err != nil {
			errors <- err
			return
		}
		defer resp.Body.Close()
		var s oscarstate.Snapshot
		err = json.NewDecoder(resp.Body).Decode(&s)
		if err != nil {
			errors <- err
			return
		}
		result <- s
	}()
	<-entered
	now := time.Now()
	post(fmt.Sprintf(`[{"labels":{"alertname":"Old"},"startsAt":%q,"endsAt":%q},{"labels":{"alertname":"New"}}]`, now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(-time.Second).Format(time.RFC3339Nano)))
	require.Eventually(t, func() bool {
		s := observer.Snapshot(provider)
		return len(s.Alerts) == 1 && s.Alerts[0].Labels["alertname"] == "New"
	}, time.Second, time.Millisecond)
	close(release)
	select {
	case err := <-errors:
		require.NoError(t, err)
	case s := <-result:
		require.Len(t, s.Alerts, 1)
		require.Equal(t, model.LabelValue("Old"), s.Alerts[0].Labels["alertname"])
		b, err := f.Read(s.Cursor, 20)
		require.NoError(t, err)
		require.Len(t, b.Changes, 3)
		require.Equal(t, oscarstate.Delete, b.Changes[2].Kind)
	case <-time.After(time.Second):
		t.Fatal("snapshot did not finish")
	}
}
