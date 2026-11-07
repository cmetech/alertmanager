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

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/oscarstate"
)

func TestOSCARProbeMain(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:0", ":9093", "localhost:9093", "192.0.2.1:9093", "[::]:9093"} {
		_, err := startProbe(t.Context(), probeOptions{listen: listen})
		require.ErrorContains(t, err, "loopback")
	}
	opts := defaultProbeOptions()
	opts.listen = "127.0.0.1:0"
	opts.gcInterval = 100 * time.Millisecond
	p, err := startProbe(t.Context(), opts)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close(context.Background())) })
	base := "http://" + p.app.Addr()
	resp, err := http.Post(base+"/api/v2/alerts", "application/json", strings.NewReader(`[{"labels":{"alertname":"Proof"}}]`))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()
	resp, err = http.Get(base + "/_oscar/probe/snapshot")
	require.NoError(t, err)
	var s oscarstate.Snapshot
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&s))
	resp.Body.Close()
	require.Len(t, s.Alerts, 1)
	require.Eventually(t, func() bool { b, err := p.feed.Read(p.feed.Cursor(), 1); return err == nil && !b.HeartbeatAt.IsZero() }, 2*time.Second, 10*time.Millisecond)
	select {
	case body := <-p.receipts:
		require.Contains(t, body, "Proof")
	case <-time.After(3 * time.Second):
		t.Fatal("no notification")
	}
	resp, err = http.Get(base + "/_oscar/probe/metrics")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	require.Contains(t, string(body), "oscar_probe_heartbeat_cadence_seconds_count")
	for line := range strings.SplitSeq(string(body), "\n") {
		if strings.HasPrefix(line, "oscar_probe_heartbeat_cadence_seconds_sum ") || strings.HasPrefix(line, "oscar_probe_heartbeat_cadence_seconds_count ") {
			t.Log(line)
		}
	}
	require.NoError(t, p.Close(context.Background()))
	next, err := startProbe(t.Context(), opts)
	require.NoError(t, err)
	defer next.Close(context.Background())
	require.NotEqual(t, s.Cursor.Epoch, next.feed.Cursor().Epoch)
	require.Equal(t, 30*time.Minute, defaultProbeOptions().gcInterval)
}
