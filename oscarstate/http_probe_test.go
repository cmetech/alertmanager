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

package oscarstate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/common/model"

	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
)

func TestOSCARProbeHTTP(t *testing.T) {
	t.Parallel()
	f := NewFeed(2, "epoch")
	calls := 0
	h := NewProbeHandler(func() Snapshot { calls++; return Snapshot{Cursor: f.Cursor(), Alerts: []SnapshotAlert{}} }, f)
	request := func(path, addr string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	require.Equal(t, http.StatusForbidden, request("/_oscar/probe/snapshot", "192.0.2.1:80").Code)
	w := request("/_oscar/probe/snapshot", "127.0.0.1:1")
	require.Equal(t, 200, w.Code)
	require.Equal(t, 1, calls)
	var s Snapshot
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &s))
	require.Equal(t, f.Cursor(), s.Cursor)
	f.Publish(Change{Kind: Delete})
	w = request("/_oscar/probe/changes?epoch=epoch&after=0&limit=1", "[::1]:1")
	require.Equal(t, 200, w.Code)
	var b Batch
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))
	require.Len(t, b.Changes, 1)
	require.Equal(t, uint64(1), b.Continue.Sequence)
	require.Equal(t, 400, request("/_oscar/probe/changes?epoch=epoch&after=x&limit=1", "127.0.0.1:1").Code)
	require.Equal(t, 400, request("/_oscar/probe/changes?epoch=epoch&after=0&limit=1001", "127.0.0.1:1").Code)
	require.Equal(t, 409, request("/_oscar/probe/changes?epoch=old&after=0&limit=1", "127.0.0.1:1").Code)
}

type probeCountingWriter struct {
	*httptest.ResponseRecorder
	writes int
}

func (w *probeCountingWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.ResponseRecorder.Write(p)
}

func TestOSCARProbeHTTPStreamsFixedCopy(t *testing.T) {
	t.Parallel()
	f := NewFeed(1, "test")
	calls := 0
	h := NewProbeHandler(func() Snapshot {
		calls++
		a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "A"}}, time.Now(), false)
		b := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "B"}}, time.Now(), false)
		return Snapshot{Cursor: f.Cursor(), Alerts: []SnapshotAlert{{Fingerprint: a.Fingerprint(), Alert: a}, {Fingerprint: b.Fingerprint(), Alert: b}}}
	}, f)
	r := httptest.NewRequest("GET", "/_oscar/probe/snapshot", nil)
	r.RemoteAddr = "127.0.0.1:1"
	w := &probeCountingWriter{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, r)
	require.Equal(t, 1, calls)
	require.Greater(t, w.writes, 2)
	var s Snapshot
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &s))
	require.Len(t, s.Alerts, 2)
}
