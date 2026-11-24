// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
)

// capacityFixture is an owner whose durable store holds one firing episode
// for a source that was evicted from its resident slot while firing.
type capacityFixture struct {
	o        *nativeActionOwner
	source   *alert.Alert
	key      string
	mu       sync.Mutex
	current  *alert.Alert // The provider's member, nil once garbage-collected.
	resolved int
}

func newCapacityFixture(t *testing.T) *capacityFixture {
	t.Helper()
	now := time.Now()
	f := &capacityFixture{source: alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}, now, false)}
	fp := f.source.Fingerprint().String()
	p := EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: episodeUpdate{EpisodeRef: EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "22222222-1111-4111-8111-111111111111", Generation: 1, VariantRevision: 1}, LifecycleSeq: 1, NativeVariant: variantOf(f.source), State: "firing", SourceSeverity: "major", ActiveSince: f.source.StartsAt.UTC().Format(time.RFC3339Nano)}}
	f.o = newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		switch cmd {
		case "recover":
			require.Equal(t, "source", args["projection"])
			require.Equal(t, fp, args["fingerprint"])
			*out.(*[]EpisodeProjection) = []EpisodeProjection{p}
		case "project-episode":
			u := args["update"].(episodeUpdate)
			require.Equal(t, p.EpisodeRef, u.EpisodeRef)
			require.Equal(t, "resolved", u.State)
			f.mu.Lock()
			f.resolved++
			f.mu.Unlock()
			x := p
			x.episodeUpdate = u
			*out.(*EpisodeProjection) = x
		default:
			t.Fatalf("unexpected %s", cmd)
		}
		return nil
	}), testActionDispatch{})
	f.o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
	f.o.recovered = true
	f.o.readSource = func(_, _ string, use func(*alert.Alert)) {
		f.mu.Lock()
		current := f.current
		f.mu.Unlock()
		if current != nil {
			use(current)
		}
	}
	f.key = sourceKey("", fp)
	bucket, bit := membershipBit(f.key)
	f.o.membership[bucket] |= bit
	f.o.parked[f.key] = parkedEpisode{source: f.source}
	return f
}

// resolve is the provider edge for each lifecycle path that gaps at the bound today.
func (f *capacityFixture) resolve(edge string) {
	switch edge {
	case "gc close":
		f.o.observe("", f.source, true)
	case "resolved upsert":
		r := *f.source
		r.EndsAt = time.Now().Add(-time.Minute)
		f.mu.Lock()
		f.current = &r
		f.mu.Unlock()
		f.o.observe("", &r, false)
	}
}

func (f *capacityFixture) turn(t *testing.T) context.Context {
	return f.o.withEpoch(context.WithValue(t.Context(), actionEpochKey{}, uint64(1)))
}

func (f *capacityFixture) gap() bool {
	bucket, bit := membershipBit(f.key)
	return f.o.gaps[bucket]&bit != 0
}

// drain runs the sweep's hand-off drain until the queue is empty or n passes.
func (f *capacityFixture) drain(t *testing.T, n int) {
	for range n {
		f.o.mu.Lock()
		empty := f.o.work.Len() == 0
		f.o.mu.Unlock()
		if empty {
			return
		}
		f.o.drainHandoff(f.turn(t))
	}
}

func (f *capacityFixture) resolvedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resolved
}

func queueFiller(o *nativeActionOwner, n int) {
	for i := range n {
		k := fmt.Sprint("filler-", i)
		o.handoffs[k] = &observationHandoff{work: o.work.PushBack(k)}
	}
}

func idleResident(o *nativeActionOwner, key string) {
	s := &episodeSlot{source: &alert.Alert{}, projection: EpisodeProjection{ID: key}}
	s.clock = o.clock.PushBack(key)
	o.byKey[key] = s
}

func enrollKey(o *nativeActionOwner, key string) func() (*episodeSlot, error) {
	return func() (*episodeSlot, error) {
		o.mu.Lock()
		defer o.mu.Unlock()
		return o.slotLocked(key, true), nil
	}
}

// AC-1: an edge past the hand-off bound is queued, never gapped, and reaches the journal.
func TestOscarActionHandoffAtBoundQueuesAndDrains(t *testing.T) {
	t.Parallel()
	for _, edge := range []string{"gc close", "resolved upsert"} {
		t.Run(edge, func(t *testing.T) {
			t.Parallel()
			f := newCapacityFixture(t)
			f.o.maxHandoffs = 2
			queueFiller(f.o, 2)

			f.resolve(edge)
			require.False(t, f.gap(), "a full hand-off queue must not discard the edge into gaps")
			require.NotNil(t, f.o.handoffs[f.key], "the edge must be queued past the bound")
			require.Len(t, f.o.handoffs, 3)

			f.drain(t, 3)
			require.Equal(t, 1, f.resolvedCount(), "the queued edge must be projected as resolved")
			require.Nil(t, f.o.handoffs[f.key])
		})
	}
}

// AC-1: while hand-offs are at their bound, only their drain may evict.
func TestOscarActionSlotBackPressureWhileHandoffsAtBound(t *testing.T) {
	t.Parallel()
	t.Run("eviction", func(t *testing.T) {
		t.Parallel()
		o := newNativeActionOwner(defaultActionAuthority, nil, testActionDispatch{})
		o.maxEpisodes, o.maxHandoffs = 2, 1
		idleResident(o, "resident-1")
		idleResident(o, "resident-2")
		o.handoffs["queued"] = &observationHandoff{work: o.work.PushBack("queued")}

		start := time.Now()
		s, err := o.obtainSlot(t.Context(), "new", enrollKey(o, "new"))
		require.ErrorIs(t, err, unavailable, "a new enrollment retries while the drain catches up")
		require.Nil(t, s)
		require.Less(t, time.Since(start), 100*time.Millisecond, "a refused enrollment does not wait")
		require.Len(t, o.byKey, 2)
		require.Empty(t, o.parked, "no resident may be evicted for a new enrollment")

		s, err = o.obtainSlot(t.Context(), "queued", enrollKey(o, "queued"))
		require.NoError(t, err)
		require.NotNil(t, s, "the drain may evict to absorb its hand-off")
		require.Empty(t, o.handoffs)
		require.Len(t, o.parked, 1)

		s, err = o.obtainSlot(t.Context(), "new", enrollKey(o, "new"))
		require.NoError(t, err)
		require.NotNil(t, s, "below the bound a new enrollment evicts as before")
		require.Len(t, o.parked, 2)
	})
	t.Run("refused enrollments cannot starve the drain", func(t *testing.T) {
		t.Parallel()
		f := newCapacityFixture(t)
		f.o.maxEpisodes, f.o.maxHandoffs = 1, 1
		idleResident(f.o, "resident")
		f.resolve("gc close")
		require.NotNil(t, f.o.handoffs[f.key])

		stop := make(chan struct{})
		var wg sync.WaitGroup
		for i := range 32 {
			key := fmt.Sprint("new-", i)
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					_, _ = f.o.obtainSlot(t.Context(), key, func() (*episodeSlot, error) {
						f.o.mu.Lock()
						defer f.o.mu.Unlock()
						if len(f.o.byKey) >= f.o.maxEpisodes {
							return nil, nil
						}
						return nil, unavailable // Never take the drain's slot.
					})
				}
			})
		}
		time.Sleep(10 * time.Millisecond)
		f.drain(t, 1)
		close(stop)
		wg.Wait()
		require.Equal(t, 1, f.resolvedCount(), "one drain pass enrolls and projects the queued close")
	})
}

// AC-2: both bounds are configurable with defaults sized for 10 alerts/s x 30 min.
func TestOscarActionBoundsConfigurable(t *testing.T) {
	t.Parallel()
	o := newNativeActionOwner(defaultActionAuthority, nil, testActionDispatch{})
	require.Equal(t, 65536, o.maxEpisodes)
	require.Equal(t, 65536, o.maxHandoffs)
	for _, tc := range []struct {
		config             ActionOwnerConfig
		episodes, handoffs int
		err                bool
	}{
		{ActionOwnerConfig{}, 65536, 65536, false},
		{ActionOwnerConfig{MaxEpisodes: 2, MaxHandoffs: 3}, 2, 3, false},
		{ActionOwnerConfig{MaxEpisodes: -1}, 0, 0, true},
		{ActionOwnerConfig{MaxHandoffs: -1}, 0, 0, true},
	} {
		episodes, handoffs, err := tc.config.bounds()
		if tc.err {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, tc.episodes, episodes)
		require.Equal(t, tc.handoffs, handoffs)
	}
	o.maxEpisodes = 2
	require.NotNil(t, o.slot("a", true))
	require.NotNil(t, o.slot("b", true))
	require.Nil(t, o.slot("c", true), "the configured resident bound is enforced")
}

// AC-2: an invalid bound fails installation before any credential is read.
func TestOscarActionInstallRejectsNegativeBounds(t *testing.T) {
	api, err := NewAPI(nil, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	require.ErrorContains(t, api.InstallActionOwner(ActionOwnerConfig{Enabled: true, MaxHandoffs: -1}), "bounds")
	require.Nil(t, api.actionOwner)
}

// AC-3: a slot wait that times out leaves the work for a retry, never a drop.
func TestOscarActionSlotWaitTimeoutRetriesNotDrops(t *testing.T) {
	t.Parallel()
	t.Run("hand-off drain", func(t *testing.T) {
		t.Parallel()
		f := newCapacityFixture(t)
		f.o.maxEpisodes = 1
		f.o.byKey["busy"] = &episodeSlot{pending: []actionEvent{{}}} // Not evictable.
		f.resolve("gc close")
		require.NotNil(t, f.o.handoffs[f.key])

		f.drain(t, 1) // obtainSlot times out.
		require.NotNil(t, f.o.handoffs[f.key], "a timed-out drain keeps the close queued")
		require.Zero(t, f.resolvedCount())
		require.False(t, f.gap())

		f.o.mu.Lock()
		delete(f.o.byKey, "busy")
		f.o.mu.Unlock()
		f.drain(t, 1)
		require.Equal(t, 1, f.resolvedCount(), "the retried drain projects the close")
		require.Nil(t, f.o.handoffs[f.key])
	})
	t.Run("delivery projection", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
		writes := 0
		o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
			require.Equal(t, "project-episode", cmd)
			u := args["update"].(episodeUpdate)
			*out.(*EpisodeProjection) = EpisodeProjection{episodeUpdate: u, ID: u.EpisodeRef.EpisodeID}
			writes++
			return nil
		}), testActionDispatch{})
		o.recovered = true
		o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
		o.readSource = func(_, fp string, read func(*alert.Alert)) {
			if source.Fingerprint().String() == fp {
				read(source)
			}
		}
		o.maxEpisodes = 1
		o.byKey["busy"] = &episodeSlot{pending: []actionEvent{{}}}
		o.observe("", source, false)

		_, err := o.Project(t.Context(), source)
		require.ErrorIs(t, err, unavailable, "the retryable hold code, not a drop")
		require.Zero(t, writes)

		o.mu.Lock()
		delete(o.byKey, "busy")
		o.mu.Unlock()
		p, err := o.Project(t.Context(), source)
		require.NoError(t, err, "the retried projection enrolls the same source")
		require.Equal(t, "firing", p.State)
		require.Equal(t, 1, writes)
	})
}
