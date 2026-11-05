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

package memadapter

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/oscarstate"
	"github.com/prometheus/alertmanager/provider/mem"
)

func TestOSCARFeedAdapter(t *testing.T) {
	t.Parallel()
	f := oscarstate.NewFeed(4, "")
	adapter := New(f)
	p, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	defer p.Close()
	p.SetStateObserver(adapter)
	c := f.Cursor()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "A"}, EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	require.NoError(t, p.Put(t.Context(), a))
	s := adapter.Snapshot(p)
	require.Len(t, s.Alerts, 1)
	require.Equal(t, f.Cursor(), s.Cursor)
	b, err := f.Read(c, 4)
	require.NoError(t, err)
	require.Equal(t, oscarstate.Upsert, b.Changes[0].Kind)
	require.True(t, p.TryHeartbeat(time.Second))
	b, err = f.Read(s.Cursor, 4)
	require.NoError(t, err)
	require.False(t, b.HeartbeatAt.IsZero())
	require.Empty(t, b.Changes)
	adapter.Deleted(a)
	b, err = f.Read(s.Cursor, 4)
	require.NoError(t, err)
	require.Equal(t, oscarstate.Delete, b.Changes[0].Kind)
}

func TestOSCARFeedLockMeasurements(t *testing.T) {
	// Sequential single-event calls measure instrumentation, not capacity qualification.
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("observer=%t", enabled), func(t *testing.T) {
			reg := prometheus.NewRegistry()
			p, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), reg, nil)
			require.NoError(t, err)
			defer p.Close()
			f := oscarstate.NewFeed(4096, "")
			if enabled {
				p.SetStateObserver(New(f))
			}
			now := time.Now()
			a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LockTrial", "instance": "one"}, Annotations: model.LabelSet{"summary": model.LabelValue(strings.Repeat("x", 512))}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
			for range 10000 {
				require.NoError(t, p.Put(t.Context(), a))
			}
			metrics, err := reg.Gather()
			require.NoError(t, err)
			for _, m := range metrics {
				if m.GetName() == "alertmanager_provider_put_mutex_hold_seconds" || m.GetName() == "alertmanager_provider_put_mutex_wait_seconds" {
					h := m.Metric[0].Histogram
					require.Equal(t, uint64(10000), h.GetSampleCount())
					t.Logf("%s count=%d sum_seconds=%.9f mean_ns=%.1f", m.GetName(), h.GetSampleCount(), h.GetSampleSum(), h.GetSampleSum()/float64(h.GetSampleCount())*1e9)
				}
			}
		})
	}
}
