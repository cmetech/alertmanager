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
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
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

// The writer runs freely alongside Read: there is no per-batch rendezvous.
// A deliberate reader pause guarantees overflow; every recovery starts a new
// snapshot segment, and only Continue advances within a segment.
func TestOSCARFeedConcurrentLimitedDrain(t *testing.T) {
	t.Parallel()
	for iteration := range 20 {
		t.Run(fmt.Sprintf("iteration-%d", iteration), func(t *testing.T) {
			const capacity = 64
			f := NewFeed(capacity, "epoch")
			cursor := f.Cursor()
			publish := func(sequence uint64) { f.Publish(Change{Kind: Delete, Fingerprint: model.Fingerprint(sequence)}) }
			for sequence := uint64(1); sequence <= capacity; sequence++ {
				publish(sequence)
			}
			// Exactly capacity remains readable; capacity+1 beyond Continue must gap.
			boundary, err := f.Read(cursor, 3)
			require.NoError(t, err)
			require.Equal(t, uint64(1), boundary.Changes[0].Sequence)
			cursor = boundary.Continue
			for sequence := uint64(65); sequence <= 68; sequence++ {
				publish(sequence)
			}
			gap, err := f.Read(cursor, 3)
			require.ErrorIs(t, err, ErrGap)
			require.Equal(t, uint64(capacity+1), gap.Head.Sequence-cursor.Sequence)
			cursor = f.Cursor()
			var latest atomic.Uint64
			latest.Store(68)
			stop, done := make(chan struct{}), make(chan struct{})
			var stopOnce sync.Once
			finish := func() { stopOnce.Do(func() { close(stop) }); <-done }
			go func() {
				defer close(done)
				for sequence := uint64(69); ; sequence++ {
					select {
					case <-stop:
						return
					default:
					}
					publish(sequence)
					latest.Store(sequence)
					runtime.Gosched()
				}
			}()
			defer finish()
			// The publisher is not gated by the reader; it continues after this pause.
			require.Eventually(t, func() bool { return latest.Load() > cursor.Sequence+capacity }, 2*time.Second, time.Millisecond)
			seen := map[uint64]bool{}
			batches, gaps := 0, 0
			consume := func() {
				batch, err := f.Read(cursor, 3)
				if err != nil {
					require.ErrorIs(t, err, ErrGap)
					require.Greater(t, batch.Head.Sequence-cursor.Sequence, uint64(capacity))
					gaps++
					cursor = f.Cursor()
					return
				}
				require.Len(t, batch.Changes, int(min(uint64(3), batch.Head.Sequence-cursor.Sequence)))
				for i, change := range batch.Changes {
					require.Equal(t, cursor.Sequence+uint64(i)+1, change.Sequence)
					require.Equal(t, model.Fingerprint(change.Sequence), change.Fingerprint)
					require.False(t, seen[change.Sequence])
					seen[change.Sequence] = true
				}
				if len(batch.Changes) > 0 {
					require.Equal(t, batch.Changes[len(batch.Changes)-1].Sequence, batch.Continue.Sequence)
					batches++
				} else {
					require.Equal(t, cursor, batch.Continue)
				}
				cursor = batch.Continue
			}
			consume()
			require.Equal(t, 1, gaps)
			deadline := time.Now().Add(3 * time.Second)
			for batches < 12 && time.Now().Before(deadline) {
				consume()
				runtime.Gosched()
			}
			require.GreaterOrEqual(t, batches, 12)
			finish()
			for cursor.Sequence < f.Cursor().Sequence {
				consume()
			}
			require.Equal(t, f.Cursor(), cursor)
			t.Logf("committed_batches=%d detected_gaps=%d unique_changes=%d", batches, gaps, len(seen))
		})
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

func TestOSCARFeedReadCopyDoesNotBlockPublish(t *testing.T) {
	t.Parallel()
	f := NewFeed(2, "epoch")
	start := f.Cursor()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "A"}, Annotations: model.LabelSet{"summary": "original"}}, time.Now(), false)
	f.Publish(Change{Kind: Upsert, Fingerprint: a.Fingerprint(), Alert: a})
	copying, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	readDone := make(chan Batch, 1)
	readErrors := make(chan error, 1)
	go func() {
		b, err := f.read(start, 1, func(a *alert.Alert) *alert.Alert { close(copying); <-release; return CopyAlert(a) })
		if err != nil {
			readErrors <- err
			return
		}
		readDone <- b
	}()
	select {
	case <-copying:
	case err := <-readErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("reader never reached payload copy")
	}
	// These wrap the ring while the reader still owns its captured pointers.
	published := make(chan struct{})
	go func() {
		for range 3 {
			f.Publish(Change{Kind: Delete})
		}
		close(published)
	}()
	select {
	case <-published:
	case <-time.After(time.Second):
		t.Fatal("payload copying blocked producer progress")
	}
	once.Do(func() { close(release) })
	select {
	case b := <-readDone:
		require.Equal(t, uint64(1), b.Continue.Sequence)
		require.Equal(t, model.LabelValue("original"), b.Changes[0].Alert.Annotations["summary"])
		b.Changes[0].Alert.Annotations["summary"] = "consumer"
		require.Equal(t, model.LabelValue("original"), a.Annotations["summary"])
	case err := <-readErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("reader did not finish")
	}
}
