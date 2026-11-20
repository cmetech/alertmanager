package mem

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

func managedFixture(i int, kind string) *alert.Alert {
	now := time.Now()
	return alert.New(model.Alert{Labels: model.LabelSet{"alertname": "managed", "alert_type": model.LabelValue(kind), "variant": model.LabelValue(strconv.Itoa(i))}, Annotations: model.LabelSet{"summary": "retained"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
}

func TestManagedBatchFailurePreservesPointersSnapshotsAndSequence(t *testing.T) {
	t.Parallel()
	p := clearProvider(t, &clearCallback{})
	p.EnableManaged()
	observer := &oscarObserver{owner: p}
	p.SetStateObserver(observer)
	ok := func() error { return nil }
	first := managedFixture(1, "problem")
	second := managedFixture(2, "problem")
	require.NoError(t, p.ApplyManaged(t.Context(), "episode", first, provider.ManagedStamp{Generation: 1}, ok))
	retained, err := p.Get(first.Fingerprint())
	require.NoError(t, err)
	before, seq := p.SnapshotWithSequence(func() uint64 { return observer.sequence })
	err = p.ApplyManaged(t.Context(), "episode", second, provider.ManagedStamp{Generation: 2}, func() error { return context.DeadlineExceeded })
	require.ErrorIs(t, err, context.DeadlineExceeded)
	got, _ := p.Get(first.Fingerprint())
	require.Same(t, retained, got)
	require.False(t, got.Resolved())
	require.Equal(t, before[0].EndsAt, got.EndsAt)
	after, next := p.SnapshotWithSequence(func() uint64 { return observer.sequence })
	require.Equal(t, before, after)
	require.Equal(t, seq, next)
	require.NoError(t, p.Put(t.Context(), first))
	require.Equal(t, seq, observer.sequence)
	p.callback = oscarRejectStore{}
	require.Error(t, p.ApplyManaged(t.Context(), "episode", second, provider.ManagedStamp{Generation: 2}, ok))
	require.Equal(t, seq, observer.sequence)
	p.callback = noopCallback{}
	require.NoError(t, p.ApplyManaged(t.Context(), "episode", second, provider.ManagedStamp{Generation: 2}, ok))
	got, _ = p.Get(first.Fingerprint())
	require.NotSame(t, first, got)
	require.True(t, got.Resolved())
	require.False(t, before[0].Resolved())
	require.Error(t, p.PutResolvedConversion(t.Context(), second))
}

func TestManagedCommitOver200BlockedListenerPreservesSeedOrderAndShutdown(t *testing.T) {
	t.Parallel()
	p := clearProvider(t, &clearCallback{})
	p.EnableManaged()
	// Seed actual store and verified variant index as a pre-existing installation
	// with 240 owned problems. No dispatcher membership or silencing input is consulted.
	refs := make(map[model.Fingerprint]bool)
	p.variants["episode"] = refs
	for i := range 240 {
		v := managedFixture(i, "problem")
		fp := v.Fingerprint()
		refs[fp] = true
		p.owners[fp] = "episode"
		require.NoError(t, p.alerts.Set(v))
	}
	o := &oscarObserver{owner: p}
	p.SetStateObserver(o)
	_, slow := p.SlurpAndSubscribe("stalled")
	clear := managedFixture(241, "resolution")
	ok := func() error { return nil }
	require.NoError(t, p.ApplyManaged(t.Context(), "episode", clear, provider.ManagedStamp{Generation: 2}, ok))
	require.True(t, p.TryHeartbeat(time.Second))
	snapshot, seq := p.SnapshotWithSequence(func() uint64 { return o.sequence })
	require.Len(t, snapshot, 241)
	require.Equal(t, uint64(241), seq)
	active := 0
	for _, v := range snapshot {
		if !v.Resolved() {
			active++
			require.Equal(t, clear.Fingerprint(), v.Fingerprint())
		}
	}
	require.Equal(t, 1, active)
	seed, later := p.SlurpAndSubscribe("later")
	require.Len(t, seed, 241)
	defer later.Close()
	ordinary := managedFixture(250, "ordinary")
	written := make(chan error, 1)
	go func() { written <- p.Put(t.Context(), ordinary) }()
	select {
	case <-written:
		t.Fatal("ordinary overtook blocked managed commit")
	case <-time.After(10 * time.Millisecond):
	}
	select {
	case <-later.Next():
		t.Fatal("old managed commit duplicated seeded snapshot")
	default:
	}
	slow.Close()
	p.gcListeners()
	require.NoError(t, <-written)
	require.Same(t, ordinary, (<-later.Next()).Data)
	p.gcAlerts()
	snapshot, seq = p.SnapshotWithSequence(func() uint64 { return o.sequence })
	require.Len(t, snapshot, 2)
	require.Equal(t, uint64(482), seq)
	require.False(t, o.deletedOutsideLock.Load())
	_, halt := p.SlurpAndSubscribe("shutdown")
	defer halt.Close()
	for i := range 200 {
		require.NoError(t, p.Put(t.Context(), managedFixture(300+i, "ordinary")))
		<-later.Next()
	}
	done := make(chan error, 1)
	go func() { done <- p.Put(t.Context(), managedFixture(999, "ordinary")) }()
	p.Close()
	select {
	case err := <-done:
		require.True(t, err == nil || errors.Is(err, context.Canceled))
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked on subscriber")
	}
}

func TestManagedFutureStartRemainsRetryableAndCannotStrandManualRetirement(t *testing.T) {
	p := clearProvider(t, &clearCallback{})
	p.EnableManaged()
	a := managedFixture(3, "problem")
	a.StartsAt = time.Now().Add(120 * time.Millisecond)
	valid := func() error { return nil }
	require.Error(t, p.ApplyManaged(t.Context(), "future", a, provider.ManagedStamp{Generation: 1}, valid))
	_, present := p.ManagedApplied("future")
	require.False(t, present)
	// Simulate earlier accepted bytes restored on a clock that stepped back.
	require.NoError(t, p.alerts.Set(a))
	p.owners[a.Fingerprint()] = "restored"
	p.variants["restored"] = map[model.Fingerprint]bool{a.Fingerprint(): true}
	require.Error(t, p.ApplyManaged(t.Context(), "restored", nil, provider.ManagedStamp{Generation: 2}, valid))
	time.Sleep(time.Until(a.StartsAt.Add(time.Millisecond)))
	require.NoError(t, p.ApplyManaged(t.Context(), "restored", nil, provider.ManagedStamp{Generation: 2}, valid))
	got, err := p.Get(a.Fingerprint())
	require.NoError(t, err)
	require.True(t, got.Resolved())
	fresh := managedFixture(4, "problem")
	fresh.StartsAt = a.StartsAt
	require.NoError(t, p.ApplyManaged(t.Context(), "future", fresh, provider.ManagedStamp{Generation: 1}, valid))
	require.Equal(t, a.StartsAt, fresh.StartsAt)
}
