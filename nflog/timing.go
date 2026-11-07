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

package nflog

import (
	"time"

	pb "github.com/prometheus/alertmanager/nflog/nflogpb"
)

// TimingLookup is a bounded read of one immutable notification-log entry.
// Firing contains only requested hashes present in the entry.
type TimingLookup struct {
	Found     bool
	Capped    bool
	Timestamp time.Time
	ExpiresAt time.Time
	Firing    map[uint64]bool
	Inspected int
}

// LookupTiming reads one native group/receiver log entry for selected hashes.
// It rejects an entry that exceeds maxScan before scanning any firing hashes.
func (l *Log) LookupTiming(groupKey string, recv *pb.Receiver, hashes []uint64, maxScan int) TimingLookup {
	l.mtx.RLock()
	entry := l.st[stateKey(groupKey, recv)]
	l.mtx.RUnlock()
	if entry == nil || entry.Entry == nil {
		return TimingLookup{}
	}

	result := TimingLookup{
		Found:     true,
		Timestamp: entry.Entry.Timestamp.AsTime(),
		ExpiresAt: entry.ExpiresAt.AsTime(),
	}
	if maxScan < 0 || len(entry.Entry.FiringAlerts) > maxScan {
		result.Capped = true
		return result
	}
	selected := make(map[uint64]struct{}, len(hashes))
	for _, hash := range hashes {
		selected[hash] = struct{}{}
	}
	result.Firing = make(map[uint64]bool, len(selected))
	for _, hash := range entry.Entry.FiringAlerts {
		if _, ok := selected[hash]; ok {
			result.Firing[hash] = true
		}
	}
	result.Inspected = len(entry.Entry.FiringAlerts)
	return result
}
