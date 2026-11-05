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

// Package memadapter connects the proof feed to the native memory provider.
package memadapter

import (
	"time"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/oscarstate"
	"github.com/prometheus/alertmanager/provider/mem"
)

// Observer publishes bounded copies and never acquires the provider mutex.
type Observer struct{ feed *oscarstate.Feed }

var _ mem.StateObserver = (*Observer)(nil)

// New creates an observer for a process-local feed.
func New(feed *oscarstate.Feed) *Observer { return &Observer{feed: feed} }

// Upserted publishes a successfully stored alert.
func (o *Observer) Upserted(a *alert.Alert) {
	o.feed.Publish(oscarstate.Change{Kind: oscarstate.Upsert, Fingerprint: a.Fingerprint(), Alert: a})
}

// Deleted publishes a provider garbage collection deletion.
func (o *Observer) Deleted(a *alert.Alert) {
	o.feed.Publish(oscarstate.Change{Kind: oscarstate.Delete, Fingerprint: a.Fingerprint()})
}

// Heartbeat records contact confirmed by acquiring the provider mutex.
func (o *Observer) Heartbeat(now time.Time) { o.feed.Heartbeat(now) }

// Snapshot captures a copy and its feed position within one provider lock.
func (o *Observer) Snapshot(p *mem.Alerts) oscarstate.Snapshot {
	alerts, seq := p.SnapshotWithSequence(func() uint64 { return o.feed.Cursor().Sequence })
	cursor := o.feed.Cursor()
	cursor.Sequence = seq
	rows := make([]oscarstate.SnapshotAlert, len(alerts))
	for i, a := range alerts {
		rows[i] = oscarstate.SnapshotAlert{Fingerprint: a.Fingerprint(), Alert: a}
	}
	return oscarstate.Snapshot{Alerts: rows, Cursor: cursor}
}
