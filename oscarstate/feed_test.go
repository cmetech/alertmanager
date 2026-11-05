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
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
)

func TestOSCARFeedCursorAndCopies(t *testing.T) {
	t.Parallel()
	f := NewFeed(4, "test")
	start := f.Cursor()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "A"}, Annotations: model.LabelSet{"summary": "original"}}, time.Now(), false)
	f.Publish(Change{Kind: Upsert, Fingerprint: a.Fingerprint(), Alert: a})
	a.Annotations["summary"] = "mutated"
	b, err := f.Read(start, 1)
	require.NoError(t, err)
	require.Len(t, b.Changes, 1)
	require.Equal(t, uint64(1), b.Changes[0].Sequence)
	require.False(t, b.Changes[0].PublishedAt.IsZero())
	require.Equal(t, time.UTC, b.Changes[0].PublishedAt.Location())
	require.Equal(t, model.LabelValue("original"), b.Changes[0].Alert.Annotations["summary"])
	b.Changes[0].Alert.Annotations["summary"] = "consumer"
	again, err := f.Read(start, 1)
	require.NoError(t, err)
	require.Equal(t, model.LabelValue("original"), again.Changes[0].Alert.Annotations["summary"])
	require.Equal(t, b.Continue, b.Head)
	now := time.Now().UTC()
	f.Heartbeat(now)
	quiet, err := f.Read(b.Continue, 1)
	require.NoError(t, err)
	require.Empty(t, quiet.Changes)
	require.Equal(t, b.Continue, quiet.Continue)
	require.Equal(t, now, quiet.HeartbeatAt)
	require.Equal(t, b.HeadAt, quiet.HeadAt)
	_, err = f.Read(Cursor{Epoch: "old"}, 1)
	require.ErrorIs(t, err, ErrEpoch)
	_, err = f.Read(Cursor{Epoch: "test", Sequence: 2}, 1)
	require.ErrorIs(t, err, ErrFuture)
	_, err = f.Read(start, 0)
	require.Error(t, err)
	firstEpoch, secondEpoch := NewFeed(1, "").Cursor().Epoch, NewFeed(1, "").Cursor().Epoch
	require.NotEqual(t, firstEpoch, secondEpoch)
}

func TestOSCARFeedLimitedDrainAndOverflow(t *testing.T) {
	t.Parallel()
	f := NewFeed(16, "test")
	c := f.Cursor()
	for range 12 {
		f.Publish(Change{Kind: Delete})
	}
	var seen []uint64
	for range 7 {
		b, err := f.Read(c, 2)
		require.NoError(t, err)
		for _, change := range b.Changes {
			seen = append(seen, change.Sequence)
			require.GreaterOrEqual(t, time.Since(change.PublishedAt), time.Duration(0))
		}
		c = b.Continue
		if c.Sequence < 14 {
			f.Publish(Change{Kind: Delete})
		}
	}
	require.Len(t, seen, 14)
	for i, s := range seen {
		require.Equal(t, uint64(i+1), s)
	}
	for range 20 {
		f.Publish(Change{Kind: Delete})
	}
	_, err := f.Read(c, 2)
	require.ErrorIs(t, err, ErrGap)
	// Recovery from a fresh snapshot starts at that snapshot's cursor.
	c = f.Cursor()
	f.Publish(Change{Kind: Delete})
	b, err := f.Read(c, 2)
	require.NoError(t, err)
	require.Len(t, b.Changes, 1)
}

func TestOSCARFeedConcurrentLimitedDrain(t *testing.T) {
	t.Parallel()
	f := NewFeed(64, "epoch")
	cursor := f.Cursor()
	published := make(chan struct{})
	next := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			for range 3 {
				f.Publish(Change{Kind: Delete})
			}
			published <- struct{}{}
			<-next
		}
	}()
	var got []uint64
	for range 20 {
		<-published
		b, err := f.Read(cursor, 2)
		require.NoError(t, err)
		for _, c := range b.Changes {
			got = append(got, c.Sequence)
		}
		cursor = b.Continue
		next <- struct{}{}
	}
	<-done
	for cursor.Sequence < f.Cursor().Sequence {
		b, err := f.Read(cursor, 2)
		require.NoError(t, err)
		for _, c := range b.Changes {
			got = append(got, c.Sequence)
		}
		cursor = b.Continue
	}
	require.Len(t, got, 60)
	for i, seq := range got {
		require.Equal(t, uint64(i+1), seq)
	}
}

func TestOSCARFeedRetainedAfterOverflow(t *testing.T) {
	t.Parallel()
	f := NewFeed(12, "epoch")
	start := f.Cursor()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 30 {
			f.Publish(Change{Kind: Delete})
		}
	}()
	<-done
	_, err := f.Read(start, 2)
	require.ErrorIs(t, err, ErrGap)
	// An explicit retained-boundary cursor is only for this ring test. A real
	// consumer repairs gaps with a new source snapshot, not by skipping changes.
	cursor := Cursor{Epoch: "epoch", Sequence: 18}
	for expected := uint64(19); expected <= 30; expected += 2 {
		b, err := f.Read(cursor, 2)
		require.NoError(t, err)
		require.Equal(t, expected, b.Changes[0].Sequence)
		require.Equal(t, expected+1, b.Changes[1].Sequence)
		cursor = b.Continue
	}
	require.Equal(t, f.Cursor(), cursor)
}
