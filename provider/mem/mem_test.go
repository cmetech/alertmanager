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

package mem

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/oscarstate"
	"github.com/prometheus/alertmanager/store"
)

// testAlerts holds three alerts that start "now" and end 100ms later. It is
// built inside each test rather than at package init so that tests running in
// a synctest bubble see timestamps from the bubble's clock.
type testAlerts struct {
	t0, t1                 time.Time
	alert1, alert2, alert3 *alert.Alert
}

func newTestAlerts() testAlerts {
	t0 := time.Now()
	t1 := t0.Add(100 * time.Millisecond)
	newAlert := func(labels, annotations model.LabelSet) *alert.Alert {
		return alert.New(model.Alert{
			Labels:       labels,
			Annotations:  annotations,
			StartsAt:     t0,
			EndsAt:       t1,
			GeneratorURL: "http://example.com/prometheus",
		}, t0, false)
	}
	return testAlerts{
		t0:     t0,
		t1:     t1,
		alert1: newAlert(model.LabelSet{"bar": "foo"}, model.LabelSet{"foo": "bar"}),
		alert2: newAlert(model.LabelSet{"bar": "foo2"}, model.LabelSet{"foo": "bar2"}),
		alert3: newAlert(model.LabelSet{"bar": "foo3"}, model.LabelSet{"foo": "bar3"}),
	}
}

// TestAlertsSubscribePutStarvation tests starvation of `iterator.Close` and
// `alerts.Put`. Both `Subscribe` and `Put` use the Alerts.mtx lock. `Subscribe`
// needs it to subscribe and more importantly unsubscribe `Alerts.listeners`. `Put`
// uses the lock to add additional alerts and iterate the `Alerts.listeners` map.
// If the channel of a listener is at its limit, `alerts.Lock` is blocked, whereby
// a listener can not unsubscribe as the lock is hold by `alerts.Lock`.
func TestAlertsSubscribePutStarvation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newTestAlerts()
		alerts, err := NewAlerts(t.Context(), 30*time.Minute, 0, noopCallback{}, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
		require.NoError(t, err)

		iterator := alerts.Subscribe("test")

		alertsToInsert := []*alert.Alert{}
		// Exhaust alert channel
		for i := range alertChannelLength + 1 {
			alertsToInsert = append(alertsToInsert, alert.New(model.Alert{
				// Make sure the fingerprints differ
				Labels:       model.LabelSet{"iteration": model.LabelValue(strconv.Itoa(i))},
				Annotations:  model.LabelSet{"foo": "bar"},
				StartsAt:     f.t0,
				EndsAt:       f.t1,
				GeneratorURL: "http://example.com/prometheus",
			}, f.t0, false))
		}

		putDone := make(chan error, 1)
		go func() {
			putDone <- alerts.Put(context.Background(), alertsToInsert...)
		}()

		// Wait until Put is blocked on the full subscriber channel, then close
		// the iterator: neither side may starve the other.
		synctest.Wait()
		iterator.Close()

		select {
		case err := <-putDone:
			require.NoError(t, err)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("expected `alerts.Put` and `iterator.Close` not to starve each other")
		}
	})
}

func TestDeadLock(t *testing.T) {
	t0 := time.Now()
	t1 := t0.Add(5 * time.Second)

	// Run gc every 5 milliseconds to increase the possibility of a deadlock with Subscribe()
	alerts, err := NewAlerts(context.Background(), 5*time.Millisecond, 0, noopCallback{}, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	alertsToInsert := []*alert.Alert{}
	for i := range 200 + 1 {
		alertsToInsert = append(alertsToInsert, alert.New(model.Alert{
			// Make sure the fingerprints differ
			Labels:       model.LabelSet{"iteration": model.LabelValue(strconv.Itoa(i))},
			Annotations:  model.LabelSet{"foo": "bar"},
			StartsAt:     t0,
			EndsAt:       t1,
			GeneratorURL: "http://example.com/prometheus",
		}, t0, false))
	}

	if err := alerts.Put(context.Background(), alertsToInsert...); err != nil {
		t.Fatal("Unable to add alerts")
	}
	done := make(chan bool)

	// call subscribe repeatedly in a goroutine to increase
	// the possibility of a deadlock occurring
	go func() {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		stopAfter := time.After(1 * time.Second)
		for {
			select {
			case <-tick.C:
				alerts.Subscribe("test")
			case <-stopAfter:
				done <- true
				break
			}
		}
	}()

	select {
	case <-done:
		// no deadlock
		alerts.Close()
	case <-time.After(10 * time.Second):
		t.Error("Deadlock detected")
	}
}

func TestAlertsPut(t *testing.T) {
	f := newTestAlerts()
	alerts, err := NewAlerts(context.Background(), 30*time.Minute, 0, noopCallback{}, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}

	insert := []*alert.Alert{f.alert1, f.alert2, f.alert3}

	if err := alerts.Put(context.Background(), insert...); err != nil {
		t.Fatalf("Insert failed: %s", err)
	}

	for i, a := range insert {
		res, err := alerts.Get(a.Fingerprint())
		if err != nil {
			t.Fatalf("retrieval error: %s", err)
		}
		require.NoError(t, alertDiff(a, res), "unexpected alert: %d", i)
	}
}

func TestAlertsSubscribe(t *testing.T) {
	ctx := t.Context()
	f := newTestAlerts()
	alerts, err := NewAlerts(ctx, 30*time.Minute, 0, noopCallback{}, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add alert1 to validate if pending alerts will be sent.
	if err := alerts.Put(ctx, f.alert1); err != nil {
		t.Fatalf("Insert failed: %s", err)
	}

	expectedAlerts := map[model.Fingerprint]*alert.Alert{
		f.alert1.Fingerprint(): f.alert1,
		f.alert2.Fingerprint(): f.alert2,
		f.alert3.Fingerprint(): f.alert3,
	}

	// Start many consumers and make sure that each receives all the subsequent alerts.
	var (
		nb     = 100
		fatalc = make(chan string, nb)
		wg     sync.WaitGroup
	)
	wg.Add(nb)
	for i := range nb {
		go func(i int) {
			defer wg.Done()

			it := alerts.Subscribe("test")
			defer it.Close()

			received := make(map[model.Fingerprint]struct{})
			for {
				select {
				case got, ok := <-it.Next():
					if !ok {
						fatalc <- fmt.Sprintf("Iterator %d closed", i)
						return
					}
					if it.Err() != nil {
						fatalc <- fmt.Sprintf("Iterator %d: %v", i, it.Err())
						return
					}
					expected := expectedAlerts[got.Data.Fingerprint()]
					if err := alertDiff(got.Data, expected); err != nil {
						fatalc <- fmt.Sprintf("Unexpected alert (iterator %d)\n%s", i, err.Error())
						return
					}
					received[got.Data.Fingerprint()] = struct{}{}
					if len(received) == len(expectedAlerts) {
						return
					}
				case <-time.After(5 * time.Second):
					fatalc <- fmt.Sprintf("Unexpected number of alerts for iterator %d, got: %d, expected: %d", i, len(received), len(expectedAlerts))
					return
				}
			}
		}(i)
	}

	// Add more alerts that should be received by the subscribers.
	if err := alerts.Put(ctx, f.alert2); err != nil {
		t.Fatalf("Insert failed: %s", err)
	}
	if err := alerts.Put(ctx, f.alert3); err != nil {
		t.Fatalf("Insert failed: %s", err)
	}

	wg.Wait()
	close(fatalc)
	fatal, ok := <-fatalc
	if ok {
		t.Fatal(fatal)
	}
}

func TestAlertsGetPending(t *testing.T) {
	f := newTestAlerts()
	alerts, err := NewAlerts(context.Background(), 30*time.Minute, 0, noopCallback{}, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := alerts.Put(ctx, f.alert1, f.alert2); err != nil {
		t.Fatalf("Insert failed: %s", err)
	}

	expectedAlerts := map[model.Fingerprint]*alert.Alert{
		f.alert1.Fingerprint(): f.alert1,
		f.alert2.Fingerprint(): f.alert2,
	}
	iterator := alerts.GetPending()
	for actual := range iterator.Next() {
		expected := expectedAlerts[actual.Data.Fingerprint()]
		require.NoError(t, alertDiff(actual.Data, expected))
	}

	if err := alerts.Put(ctx, f.alert3); err != nil {
		t.Fatalf("Insert failed: %s", err)
	}

	expectedAlerts = map[model.Fingerprint]*alert.Alert{
		f.alert1.Fingerprint(): f.alert1,
		f.alert2.Fingerprint(): f.alert2,
		f.alert3.Fingerprint(): f.alert3,
	}
	iterator = alerts.GetPending()
	for actual := range iterator.Next() {
		expected := expectedAlerts[actual.Data.Fingerprint()]
		require.NoError(t, alertDiff(actual.Data, expected))
	}
}

func TestAlertsGC(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newTestAlerts()
		alerts, err := NewAlerts(t.Context(), 200*time.Millisecond, 0, noopCallback{}, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
		require.NoError(t, err)

		insert := []*alert.Alert{f.alert1, f.alert2, f.alert3}
		require.NoError(t, alerts.Put(context.Background(), insert...))

		// The alerts end after 100ms and the GC runs every 200ms, so one GC
		// round has removed them by now (time is virtual in the bubble).
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()

		for i, a := range insert {
			_, err := alerts.Get(a.Fingerprint())
			require.ErrorIs(t, err, store.ErrNotFound, "alert %d didn't get GC'd", i)
		}
	})
}

func TestAlertsStoreCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cb := &limitCountCallback{limit: 3}
		f := newTestAlerts()

		alerts, err := NewAlerts(t.Context(), 200*time.Millisecond, 0, cb, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
		require.NoError(t, err)

		ctx := context.Background()
		require.NoError(t, alerts.Put(ctx, f.alert1, f.alert2, f.alert3))
		require.Equal(t, int32(3), cb.alerts.Load(), "unexpected number of alerts in the store")

		alert1Mod := *f.alert1
		alert1Mod.Annotations = model.LabelSet{"foo": "bar", "new": "test"} // Update annotations for alert1

		alert4 := alert.New(model.Alert{
			Labels:       model.LabelSet{"bar4": "foo4"},
			Annotations:  model.LabelSet{"foo4": "bar4"},
			StartsAt:     f.t0,
			EndsAt:       f.t1,
			GeneratorURL: "http://example.com/prometheus",
		}, f.t0, false)

		// The new alert is rejected by the callback, which is not reported as
		// an error but only visible through the callback's count.
		require.NoError(t, alerts.Put(ctx, &alert1Mod, alert4))
		require.Equal(t, int32(3), cb.alerts.Load(), "unexpected number of alerts in the store")

		// But we still managed to update alert1, since callback doesn't report error when updating existing alert.
		a, err := alerts.Get(f.alert1.Fingerprint())
		require.NoError(t, err)
		require.NoError(t, alertDiff(a, &alert1Mod))

		// Now wait until existing alerts are GC-ed, and make sure that callback was called.
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()
		require.Equal(t, int32(0), cb.alerts.Load(), "unexpected number of alerts in the store")

		// With the limit freed up, the retry stores alert4: the callback
		// counts it and it can be retrieved from the store.
		require.NoError(t, alerts.Put(ctx, alert4))
		require.Equal(t, int32(1), cb.alerts.Load(), "unexpected number of alerts in the store")
		a, err = alerts.Get(alert4.Fingerprint())
		require.NoError(t, err)
		require.NoError(t, alertDiff(a, alert4))
	})
}

func alertDiff(left, right *alert.Alert) error {
	if left == nil || right == nil {
		return errors.New("should not be nil")
	}
	comparisons := []struct {
		name     string
		isEqual  bool
		expected any
		got      any
	}{
		{"Labels", reflect.DeepEqual(right.Labels, left.Labels), right.Labels, left.Labels},
		{"Annotations", reflect.DeepEqual(right.Annotations, left.Annotations), right.Annotations, left.Annotations},
		{"StartsAt", right.StartsAt.Equal(left.StartsAt), right.StartsAt, left.StartsAt},
		{"EndsAt", right.EndsAt.Equal(left.EndsAt), right.EndsAt, left.EndsAt},
		{"UpdatedAt", right.UpdatedAt.Equal(left.UpdatedAt), right.UpdatedAt, left.UpdatedAt},
		{"GeneratorURL", right.GeneratorURL == left.GeneratorURL, right.GeneratorURL, left.GeneratorURL},
		{"Timeout", right.Timeout == left.Timeout, right.Timeout, left.Timeout},
	}
	var errs []error
	for _, comp := range comparisons {
		if !comp.isEqual {
			errs = append(errs, fmt.Errorf("field `%s` mismatch.\n Expected: %v\n Got: %v", comp.name, comp.expected, comp.got))
		}
	}
	return errors.Join(errs...)
}

type limitCountCallback struct {
	alerts  atomic.Int32
	gcCount atomic.Int32
	limit   int
}

var errTooManyAlerts = fmt.Errorf("too many alerts")

func (l *limitCountCallback) PreStore(_ *alert.Alert, existing bool) error {
	if existing {
		return nil
	}

	if int(l.alerts.Load())+1 > l.limit {
		return errTooManyAlerts
	}

	return nil
}

func (l *limitCountCallback) PostStore(_ *alert.Alert, existing bool) {
	if !existing {
		l.alerts.Add(1)
		l.gcCount.Add(1)
	}
}

func (l *limitCountCallback) PostDelete(_ *alert.Alert) {
	l.alerts.Add(-1)
}

func (l *limitCountCallback) PostGC(fingerprints model.Fingerprints) {
	l.gcCount.Add(-int32(fingerprints.Len()))
}

func TestAlertsConcurrently(t *testing.T) {
	callback := &limitCountCallback{limit: 100}
	a, err := NewAlerts(context.Background(), time.Millisecond, 0, callback, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
	require.NoError(t, err)

	stopc := make(chan struct{})
	failc := make(chan struct{})
	go func() {
		time.Sleep(2 * time.Second)
		close(stopc)
	}()
	expire := 10 * time.Millisecond
	wg := sync.WaitGroup{}
	for range 100 {
		wg.Go(func() {
			j := 0
			for {
				select {
				case <-failc:
					return
				case <-stopc:
					return
				default:
				}
				now := time.Now()
				err := a.Put(context.Background(), alert.New(model.Alert{
					Labels:   model.LabelSet{"bar": model.LabelValue(strconv.Itoa(j))},
					StartsAt: now,
					EndsAt:   now.Add(expire),
				}, now, false))
				if err != nil && !errors.Is(err, errTooManyAlerts) {
					close(failc)
					return
				}
				j++
			}
		})
	}
	wg.Wait()
	select {
	case <-failc:
		t.Fatalf("unexpected error happened")
	default:
	}

	time.Sleep(expire)
	require.Eventually(t, func() bool {
		// When the alert will eventually expire and is considered resolved - it won't be in the store.
		return len(a.alerts.List()) == 0
	}, 2*expire, expire)
	require.Equal(t, int32(0), callback.alerts.Load())
	require.Equal(t, int32(0), callback.gcCount.Load())
}

func TestSubscriberChannelMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	alerts, err := NewAlerts(context.Background(), 30*time.Minute, 0, noopCallback{}, promslog.NewNopLogger(), eventrecorder.NopRecorder(), reg, nil)
	require.NoError(t, err)

	subscriberName := "test_subscriber"

	// Subscribe to alerts
	iterator := alerts.Subscribe(subscriberName)
	defer iterator.Close()

	// Consume alerts in the background
	go func() {
		for range iterator.Next() {
			// Just drain the channel
		}
	}()

	// Helper function to get counter value
	getCounterValue := func(name, labelName, labelValue string) float64 {
		metrics, err := reg.Gather()
		require.NoError(t, err)
		for _, mf := range metrics {
			if mf.GetName() == name {
				for _, m := range mf.GetMetric() {
					for _, label := range m.GetLabel() {
						if label.GetName() == labelName && label.GetValue() == labelValue {
							return m.GetCounter().GetValue()
						}
					}
				}
			}
		}
		return 0
	}

	// Initially, the counter should be 0
	writeCount := getCounterValue("alertmanager_alerts_subscriber_channel_writes_total", "subscriber", subscriberName)
	require.Equal(t, 0.0, writeCount, "subscriberChannelWrites should start at 0")

	// Put some alerts
	now := time.Now()
	alertsToSend := []*alert.Alert{
		alert.New(model.Alert{
			Labels:       model.LabelSet{"test": "1"},
			Annotations:  model.LabelSet{"foo": "bar"},
			StartsAt:     now,
			EndsAt:       now.Add(1 * time.Hour),
			GeneratorURL: "http://example.com/prometheus",
		}, now, false),
		alert.New(model.Alert{
			Labels:       model.LabelSet{"test": "2"},
			Annotations:  model.LabelSet{"foo": "bar"},
			StartsAt:     now,
			EndsAt:       now.Add(1 * time.Hour),
			GeneratorURL: "http://example.com/prometheus",
		}, now, false),
		alert.New(model.Alert{
			Labels:       model.LabelSet{"test": "3"},
			Annotations:  model.LabelSet{"foo": "bar"},
			StartsAt:     now,
			EndsAt:       now.Add(1 * time.Hour),
			GeneratorURL: "http://example.com/prometheus",
		}, now, false),
	}

	err = alerts.Put(context.Background(), alertsToSend...)
	require.NoError(t, err)

	// Verify the counter incremented for each successful write
	require.Eventually(t, func() bool {
		writeCount := getCounterValue("alertmanager_alerts_subscriber_channel_writes_total", "subscriber", subscriberName)
		return writeCount == float64(len(alertsToSend))
	}, 1*time.Second, 10*time.Millisecond, "subscriberChannelWrites should equal the number of alerts sent")
}

// oscarObserver is local so core oscarstate never depends on provider/mem.
type oscarObserver struct {
	owner              *Alerts
	deletedOutsideLock atomic.Bool
	events             []string
	sequence           uint64
	heartbeat          time.Time
	feed               *oscarstate.Feed
}

func (o *oscarObserver) Upserted(a *alert.Alert) {
	o.events = append(o.events, "upsert")
	o.sequence++
	if o.feed != nil {
		o.feed.Publish(oscarstate.Change{Kind: oscarstate.Upsert, Fingerprint: a.Fingerprint(), Alert: a})
	}
}

func (o *oscarObserver) Deleted(a *alert.Alert) {
	if o.owner != nil && o.owner.mtx.TryLock() {
		o.deletedOutsideLock.Store(true)
		o.owner.mtx.Unlock()
	}
	o.events = append(o.events, "delete")
	o.sequence++
	if o.feed != nil {
		o.feed.Publish(oscarstate.Change{Kind: oscarstate.Delete, Fingerprint: a.Fingerprint()})
	}
}

func (o *oscarObserver) Heartbeat(now time.Time) {
	o.heartbeat = now
	if o.feed != nil {
		o.feed.Heartbeat(now)
	}
}

func TestOSCARFeedStoresAndSnapshot(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	p, err := NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), reg, nil)
	require.NoError(t, err)
	defer p.Close()
	o := &oscarObserver{}
	p.SetStateObserver(o)
	now := time.Now()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "A"}, Annotations: model.LabelSet{"summary": "a"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	require.NoError(t, p.Put(t.Context(), a))
	require.NoError(t, p.Put(t.Context(), a))
	obsolete := alert.New(model.Alert{Labels: a.Labels, StartsAt: now.Add(-2 * time.Hour), EndsAt: now.Add(-time.Hour)}, now, false)
	require.NoError(t, p.Put(t.Context(), obsolete))
	require.Equal(t, []string{"upsert", "upsert"}, o.events)
	snap, seq := p.SnapshotWithSequence(func() uint64 { return o.sequence })
	require.Equal(t, uint64(2), seq)
	require.Len(t, snap, 1)
	snap[0].Annotations["summary"] = "consumer"
	stored, err := p.Get(a.Fingerprint())
	require.NoError(t, err)
	require.Equal(t, model.LabelValue("a"), stored.Annotations["summary"])
	require.True(t, p.TryHeartbeat(time.Second))
	require.False(t, o.heartbeat.IsZero())
	p.mtx.Lock()
	previous := o.heartbeat
	require.False(t, p.TryHeartbeat(time.Millisecond))
	require.False(t, p.TryHeartbeat(time.Millisecond))
	require.Equal(t, previous, o.heartbeat)
	p.mtx.Unlock()
	require.Eventually(t, func() bool { return p.TryHeartbeat(time.Second) }, time.Second, time.Millisecond)
}

func TestOSCARFeedNilObserverMetrics(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	p, err := NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), reg, nil)
	require.NoError(t, err)
	defer p.Close()
	require.NoError(t, p.Put(t.Context(), newTestAlerts().alert1))
	p.gcAlerts()
	p.SnapshotWithSequence(func() uint64 { return 0 })
	metrics, err := reg.Gather()
	require.NoError(t, err)
	counts := map[string]uint64{}
	for _, m := range metrics {
		if len(m.Metric) > 0 && m.Metric[0].Histogram != nil {
			counts[m.GetName()] = m.Metric[0].Histogram.GetSampleCount()
		}
	}
	for _, name := range []string{"alertmanager_provider_put_mutex_wait_seconds", "alertmanager_provider_put_mutex_hold_seconds", "alertmanager_provider_gc_mutex_hold_seconds", "alertmanager_provider_snapshot_mutex_hold_seconds"} {
		require.Equal(t, uint64(1), counts[name], name)
	}
}

// oscarBlockedDelete pauses only the existing post-delete callback, after GC unlocks.
type oscarBlockedDelete struct {
	noopCallback
	entered, resume chan struct{}
}

func (c *oscarBlockedDelete) PostDelete(_ *alert.Alert) { close(c.entered); <-c.resume }
func TestOSCARSnapshotGCReinsertOrdering(t *testing.T) {
	t.Parallel()
	callback := &oscarBlockedDelete{entered: make(chan struct{}), resume: make(chan struct{})}
	p, err := NewAlerts(t.Context(), time.Hour, 0, callback, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	defer p.Close()
	f := oscarstate.NewFeed(10, "test")
	initial := f.Cursor()
	o := &oscarObserver{feed: f, owner: p}
	p.SetStateObserver(o)
	now := time.Now()
	old := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "A"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(-time.Minute)}, now, false)
	require.NoError(t, p.Put(t.Context(), old))
	done := make(chan struct{})
	go func() { p.gc(); close(done) }()
	<-callback.entered
	var resumeOnce sync.Once
	defer resumeOnce.Do(func() { close(callback.resume); <-done })
	fresh := alert.New(model.Alert{Labels: old.Labels, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	require.NoError(t, p.Put(t.Context(), fresh))
	snapshot, seq := p.SnapshotWithSequence(func() uint64 { return f.Cursor().Sequence })
	require.Equal(t, uint64(3), seq)
	require.Equal(t, f.Cursor().Sequence, seq)
	empty, err := f.Read(oscarstate.Cursor{Epoch: initial.Epoch, Sequence: seq}, 10)
	require.NoError(t, err)
	require.Empty(t, empty.Changes)
	require.Len(t, snapshot, 1)
	require.Equal(t, fresh.StartsAt, snapshot[0].StartsAt)
	require.Equal(t, []string{"upsert", "delete", "upsert"}, o.events)
	resumeOnce.Do(func() { close(callback.resume); <-done })
	require.False(t, o.deletedOutsideLock.Load(), "delete publication must hold the provider mutex")
	batch, err := f.Read(initial, 10)
	require.NoError(t, err)
	require.Len(t, batch.Changes, 3)
	for i, kind := range []oscarstate.Kind{oscarstate.Upsert, oscarstate.Delete, oscarstate.Upsert} {
		require.Equal(t, kind, batch.Changes[i].Kind)
		require.Equal(t, uint64(i+1), batch.Changes[i].Sequence)
		require.Equal(t, fresh.Fingerprint(), batch.Changes[i].Fingerprint)
	}
	lateDelete := batch.Changes[1]
	require.Equal(t, oscarstate.Delete, lateDelete.Kind)
	inventory := map[model.Fingerprint]*alert.Alert{}
	var committed uint64
	// Retry the batch, then replay a late old delete: committed sequences win.
	apply := func(changes []oscarstate.Change) {
		for _, change := range changes {
			if change.Sequence <= committed {
				continue
			}
			if change.Kind == oscarstate.Delete {
				delete(inventory, change.Fingerprint)
			} else {
				inventory[change.Fingerprint] = change.Alert
			}
			committed = change.Sequence
		}
	}
	apply(batch.Changes[:1])
	require.Len(t, inventory, 1)
	apply([]oscarstate.Change{lateDelete})
	require.Empty(t, inventory)
	apply(batch.Changes[2:])
	require.Equal(t, fresh.StartsAt, inventory[fresh.Fingerprint()].StartsAt)
	lag := time.Since(batch.Changes[len(batch.Changes)-1].PublishedAt)
	require.GreaterOrEqual(t, lag, time.Duration(0))
	apply(batch.Changes)
	apply([]oscarstate.Change{lateDelete})
	require.Len(t, inventory, 1)
	require.Equal(t, fresh.StartsAt, inventory[fresh.Fingerprint()].StartsAt)
	require.Equal(t, []string{"upsert", "delete", "upsert"}, o.events)
}

type oscarRejectStore struct{ noopCallback }

func (oscarRejectStore) PreStore(*alert.Alert, bool) error { return errors.New("rejected") }
func TestOSCARFeedFailedStore(t *testing.T) {
	t.Parallel()
	p, err := NewAlerts(t.Context(), time.Hour, 0, oscarRejectStore{}, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	defer p.Close()
	o := &oscarObserver{}
	p.SetStateObserver(o)
	require.NoError(t, p.Put(t.Context(), newTestAlerts().alert1))
	require.Empty(t, o.events)
}

func TestOSCARFeedHeartbeatProviderProgress(t *testing.T) {
	t.Parallel()
	p, err := NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	defer p.Close()
	f := oscarstate.NewFeed(10, "")
	p.SetStateObserver(&oscarObserver{feed: f})
	require.True(t, p.TryHeartbeat(time.Second))
	before, err := f.Read(f.Cursor(), 1)
	require.NoError(t, err)
	require.False(t, before.HeartbeatAt.IsZero())
	p.mtx.Lock()
	require.False(t, p.TryHeartbeat(time.Millisecond))
	held, err := f.Read(f.Cursor(), 1)
	require.NoError(t, err)
	require.Equal(t, before.HeartbeatAt, held.HeartbeatAt)
	p.mtx.Unlock()
	require.NoError(t, p.Put(t.Context(), newTestAlerts().alert1))
	require.True(t, p.TryHeartbeat(time.Second))
	after, err := f.Read(f.Cursor(), 1)
	require.NoError(t, err)
	require.True(t, after.HeartbeatAt.After(before.HeartbeatAt))
	require.Empty(t, after.Changes)
}

func TestOSCARFeedDuplicateAndLateRefresh(t *testing.T) {
	t.Parallel()
	p, err := NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
	require.NoError(t, err)
	defer p.Close()
	o := &oscarObserver{}
	p.SetStateObserver(o)
	now := time.Now()
	current := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "A"}, Annotations: model.LabelSet{"summary": "current"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	late := alert.New(model.Alert{Labels: current.Labels, Annotations: model.LabelSet{"summary": "late"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Minute)}, now.Add(-time.Second), false)
	require.NoError(t, p.Put(t.Context(), current, current, late))
	snapshot, seq := p.SnapshotWithSequence(func() uint64 { return o.sequence })
	require.Equal(t, uint64(3), seq)
	require.Len(t, snapshot, 1)
	require.Equal(t, model.LabelValue("current"), snapshot[0].Annotations["summary"])
	p.gcAlerts()
}

func TestOSCARFeedStoreLimitPublishesOnlySuccess(t *testing.T) {
	t.Parallel()
	p, err := NewAlerts(t.Context(), time.Hour, 1, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	defer p.Close()
	o := &oscarObserver{}
	p.SetStateObserver(o)
	now := time.Now()
	for _, instance := range []string{"one", "two"} {
		a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "A", "instance": model.LabelValue(instance)}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
		require.NoError(t, p.Put(t.Context(), a))
	}
	require.Equal(t, []string{"upsert"}, o.events)
}
