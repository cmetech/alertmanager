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
	"sync"
	"testing"
	"time"

	pb "github.com/prometheus/alertmanager/nflog/nflogpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestLookupTimingBatchesSelectedHashesAndBoundsEntryScan(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	recv := &pb.Receiver{GroupName: "team", Integration: "webhook", Idx: 0}
	entry := func(firing []uint64) *pb.MeshEntry {
		return &pb.MeshEntry{
			Entry:     &pb.Entry{Receiver: recv, GroupKey: []byte("group"), Timestamp: timestamppb.New(now), FiringAlerts: firing},
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		}
	}
	l := &Log{st: state{stateKey("group", recv): entry([]uint64{11, 22, 33})}}

	got := l.LookupTiming("group", recv, []uint64{11, 44}, 3)
	require.True(t, got.Found)
	require.False(t, got.Capped)
	require.Equal(t, 3, got.Inspected)
	require.Equal(t, now, got.Timestamp)
	require.Equal(t, now.Add(time.Hour), got.ExpiresAt)
	require.Equal(t, map[uint64]bool{11: true}, got.Firing)

	capped := l.LookupTiming("group", recv, []uint64{11}, 2)
	require.True(t, capped.Capped)
	require.Zero(t, capped.Inspected)
	require.Empty(t, capped.Firing)

	missing := l.LookupTiming("missing", recv, []uint64{11}, 3)
	require.False(t, missing.Found)
	require.False(t, missing.Capped)

	l.mtx.Lock()
	l.st[stateKey("group", recv)] = entry([]uint64{44})
	l.mtx.Unlock()
	updated := l.LookupTiming("group", recv, []uint64{11, 44}, 3)
	require.Equal(t, map[uint64]bool{44: true}, updated.Firing)
}

func TestLookupTimingConcurrentImmutableEntryReplacement(t *testing.T) {
	recv := &pb.Receiver{GroupName: "team", Integration: "webhook"}
	now := time.Now().UTC()
	entry := func(hash uint64) *pb.MeshEntry {
		return &pb.MeshEntry{Entry: &pb.Entry{Timestamp: timestamppb.New(now), FiringAlerts: []uint64{hash}}, ExpiresAt: timestamppb.New(now.Add(time.Hour))}
	}
	l := &Log{st: state{stateKey("group", recv): entry(1)}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			l.mtx.Lock()
			l.st[stateKey("group", recv)] = entry(uint64(i%2 + 1))
			l.mtx.Unlock()
		}
	}()
	for i := 0; i < 1000; i++ {
		got := l.LookupTiming("group", recv, []uint64{1, 2}, 1)
		require.True(t, got.Found)
		require.Equal(t, 1, got.Inspected)
		require.Len(t, got.Firing, 1)
	}
	wg.Wait()
}

func TestLookupTimingSingleLargeGroup(t *testing.T) {
	recv := &pb.Receiver{GroupName: "team", Integration: "webhook"}
	firing := make([]uint64, 100000)
	for i := range firing {
		firing[i] = uint64(i + 1)
	}
	now := time.Now().UTC()
	l := &Log{st: state{stateKey("group", recv): {
		Entry:     &pb.Entry{Timestamp: timestamppb.New(now), FiringAlerts: firing},
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}}}
	got := l.LookupTiming("group", recv, []uint64{1, 50000, 100000, 100001}, 200000)
	require.Equal(t, 100000, got.Inspected)
	require.Len(t, got.Firing, 3)
	require.True(t, got.Firing[1] && got.Firing[50000] && got.Firing[100000])
	require.False(t, got.Firing[100001])
}
