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
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/prometheus/alertmanager/alert"
)

// Snapshot is a single materialized copy captured under the provider mutex.
// JSON encoding and network transfer take place after that mutex is released.
type Snapshot struct {
	Alerts []*alert.Alert `json:"alerts"`
	Cursor Cursor         `json:"cursor"`
}

// NewProbeHandler serves the proof protocol only to loopback peers. Changes are
// capped at 1000 per request; a snapshot is streamed from exactly one fixed copy.
func NewProbeHandler(snapshot func() Snapshot, feed *Feed) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			http.Error(w, "loopback only", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		var payload any
		switch r.URL.Path {
		case "/_oscar/probe/snapshot":
			fixed := snapshot()
			w.Header().Set("Content-Type", "application/json")
			streamSnapshot(w, fixed)
			return
		case "/_oscar/probe/changes":
			after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
			limit, limitErr := strconv.Atoi(r.URL.Query().Get("limit"))
			if err != nil || limitErr != nil || limit < 1 || limit > 1000 {
				http.Error(w, "invalid cursor or limit (1..1000)", http.StatusBadRequest)
				return
			}
			batch, err := feed.Read(Cursor{Epoch: r.URL.Query().Get("epoch"), Sequence: after}, limit)
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			payload = batch
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Encoder writes directly to the response; no second inventory is captured.
		_ = json.NewEncoder(w).Encode(payload)
	})
}

// streamSnapshot bounds encoder memory to one alert while transferring a fixed copy.
func streamSnapshot(w io.Writer, s Snapshot) {
	if _, err := io.WriteString(w, `{"cursor":`); err != nil {
		return
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(s.Cursor); err != nil {
		return
	}
	if _, err := io.WriteString(w, `,"alerts":[`); err != nil {
		return
	}
	for i, a := range s.Alerts {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return
			}
		}
		if err := encoder.Encode(a); err != nil {
			return
		}
	}
	_, _ = io.WriteString(w, "]}\n")
}
