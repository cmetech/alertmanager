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
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/model"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/featurecontrol"
	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/alertmanager/store"
	"github.com/prometheus/alertmanager/tracing"
)

const alertChannelLength = 200

var tracer = tracing.NewTracer("github.com/prometheus/alertmanager/provider/mem")

// Alerts gives access to a set of alerts. All methods are goroutine-safe.
type Alerts struct {
	cancel context.CancelFunc

	mtx sync.Mutex

	alerts *store.Alerts

	listeners map[int]listeningAlerts
	next      int

	callback                               AlertStoreCallback
	observer                               StateObserver
	heartbeatProbe                         atomic.Bool
	putWait, putHold, gcHold, snapshotHold prometheus.Histogram
	heartbeatContention                    prometheus.Counter

	logger     *slog.Logger
	propagator propagation.TextMapPropagator
	recorder   eventrecorder.Recorder
	flagger    featurecontrol.Flagger

	alertsLimit             prometheus.Gauge
	alertsLimitedTotal      *prometheus.CounterVec
	subscriberChannelWrites *prometheus.CounterVec
}

// StateObserver observes successful provider mutations under the provider mutex.
// Implementations must do bounded, nonblocking work and perform no I/O.
type StateObserver interface {
	Upserted(*alert.Alert)
	Deleted(*alert.Alert)
}

// SetStateObserver installs the observer before ingestion begins.
func (a *Alerts) SetStateObserver(observer StateObserver) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.observer = observer
}

// SnapshotWithSequence captures one owned copy and its sequence atomically.
// The sequence function must never acquire the provider mutex (lock order: provider, feed).
func (a *Alerts) SnapshotWithSequence(sequence func() uint64) ([]*alert.Alert, uint64) {
	a.mtx.Lock()
	start := time.Now()
	defer func() { observeDuration(a.snapshotHold, start); a.mtx.Unlock() }()
	stored := a.alerts.List()
	result := make([]*alert.Alert, len(stored))
	for i, alrt := range stored {
		copy := *alrt
		copy.Labels = alrt.Labels.Clone()
		copy.Annotations = alrt.Annotations.Clone()
		result[i] = &copy
	}
	return result, sequence()
}

// TryHeartbeat confirms provider progress within timeout. Only one probe may
// poll at a time; a contended provider cannot advance source contact.
// The optional Heartbeat capability preserves the basic observer contract.
func (a *Alerts) TryHeartbeat(timeout time.Duration) bool {
	contended := func() {
		if a.heartbeatContention != nil {
			a.heartbeatContention.Inc()
		}
	}
	if !a.heartbeatProbe.CompareAndSwap(false, true) {
		contended()
		return false
	}
	defer a.heartbeatProbe.Store(false)
	deadline := time.Now().Add(timeout)
	for {
		if a.mtx.TryLock() {
			defer a.mtx.Unlock()
			if observer, ok := a.observer.(interface{ Heartbeat(time.Time) }); ok {
				observer.Heartbeat(time.Now().UTC())
			}
			return true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			contended()
			return false
		}
		time.Sleep(min(time.Millisecond, remaining))
	}
}

func observeDuration(metric prometheus.Histogram, start time.Time) {
	if metric != nil {
		metric.Observe(time.Since(start).Seconds())
	}
}

type AlertStoreCallback interface {
	// PreStore is called before alert is stored into the store. If this method returns error,
	// alert is not stored.
	// Existing flag indicates whether alert has existed before (and is only updated) or not.
	// If alert has existed before, then alert passed to PreStore is result of merging existing alert with new alert.
	PreStore(alrt *alert.Alert, existing bool) error

	// PostStore is called after alert has been put into store.
	PostStore(alrt *alert.Alert, existing bool)

	// PostDelete is called after alert have been removed from the store due to alert garbage collection.
	PostDelete(alrt *alert.Alert)

	// PostGC is called after alerts have been removed from the store due to alert garbage collection.
	PostGC(fingerprints model.Fingerprints)
}

type listeningAlerts struct {
	name   string
	alerts chan *provider.Alert
	done   chan struct{}
}

func (a *Alerts) registerMetrics(r prometheus.Registerer) {
	histogram := func(name, help string) prometheus.Histogram {
		return promauto.With(r).NewHistogram(prometheus.HistogramOpts{Name: "alertmanager_provider_" + name + "_seconds", Help: help, Buckets: prometheus.ExponentialBuckets(0.000001, 4, 12)})
	}
	a.putWait = histogram("put_mutex_wait", "Time waiting for the provider Put mutex.")
	a.putHold = histogram("put_mutex_hold", "Time holding the provider Put mutex per call.")
	a.gcHold = histogram("gc_mutex_hold", "Time holding the provider GC mutex.")
	a.snapshotHold = histogram("snapshot_mutex_hold", "Time holding the provider snapshot mutex.")
	a.heartbeatContention = promauto.With(r).NewCounter(prometheus.CounterOpts{Name: "alertmanager_provider_heartbeat_contention_total", Help: "Provider heartbeat probes rejected by contention."})
	a.alertsLimit = promauto.With(r).NewGauge(prometheus.GaugeOpts{
		Name: "alertmanager_alerts_per_alert_limit",
		Help: "Current limit on number of alerts per alert name",
	})

	labels := []string{}
	if a.flagger.EnableAlertNamesInMetrics() {
		labels = append(labels, "alertname")
	}
	a.alertsLimitedTotal = promauto.With(r).NewCounterVec(
		prometheus.CounterOpts{
			Name: "alertmanager_alerts_limited_total",
			Help: "Total number of alerts that were dropped due to per alert name limit",
		},
		labels,
	)

	a.subscriberChannelWrites = promauto.With(r).NewCounterVec(
		prometheus.CounterOpts{
			Name: "alertmanager_alerts_subscriber_channel_writes_total",
			Help: "Number of times alerts were written to subscriber channels",
		},
		[]string{"subscriber"},
	)
}

// NewAlerts returns a new alert provider.
func NewAlerts(
	ctx context.Context,
	intervalGC time.Duration,
	perAlertNameLimit int,
	alertCallback AlertStoreCallback,
	l *slog.Logger,
	recorder eventrecorder.Recorder,
	r prometheus.Registerer,
	flagger featurecontrol.Flagger,
) (*Alerts, error) {
	if alertCallback == nil {
		alertCallback = noopCallback{}
	}

	if perAlertNameLimit > 0 {
		l.Info("per alert name limit enabled", "limit", perAlertNameLimit)
	}

	if flagger == nil {
		flagger = featurecontrol.NoopFlags{}
	}

	ctx, cancel := context.WithCancel(ctx)
	a := &Alerts{
		alerts:     store.NewAlerts().WithPerAlertLimit(perAlertNameLimit),
		cancel:     cancel,
		listeners:  map[int]listeningAlerts{},
		next:       0,
		logger:     l.With("component", "provider"),
		propagator: otel.GetTextMapPropagator(),
		recorder:   recorder,
		callback:   alertCallback,
		flagger:    flagger,
	}

	if r != nil {
		a.registerMetrics(r)
		a.alertsLimit.Set(float64(perAlertNameLimit))
	}

	go a.gcLoop(ctx, intervalGC)

	return a, nil
}

func (a *Alerts) gcLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.gc()
		}
	}
}

func (a *Alerts) gc() {
	a.gcListeners()

	// As we don't persist alerts, we no longer consider them after
	// they are resolved. Alerts waiting for resolved notifications are
	// held in memory in aggregation groups redundantly.
	deleted := a.gcAlerts()

	// If there are no deleted alerts, there is nothing to do.
	if len(deleted) == 0 {
		return
	}

	ff := make(model.Fingerprints, len(deleted))
	for i, alrt := range deleted {
		ff[i] = alrt.Fingerprint()
		a.callback.PostDelete(alrt)
	}
	a.callback.PostGC(ff)
}

func (a *Alerts) gcAlerts() []*alert.Alert {
	a.mtx.Lock()
	start := time.Now()
	defer func() { observeDuration(a.gcHold, start); a.mtx.Unlock() }()
	deleted := a.alerts.GC()
	if a.observer != nil {
		for _, alrt := range deleted {
			a.observer.Deleted(alrt)
		}
	}
	return deleted
}

func (a *Alerts) gcListeners() {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	for i, l := range a.listeners {
		select {
		case <-l.done:
			delete(a.listeners, i)
			close(l.alerts)
		default:
			// listener is not closed yet, hence proceed.
		}
	}
}

// Close the alert provider.
func (a *Alerts) Close() {
	if a.cancel != nil {
		a.cancel()
	}
}

// Subscribe returns an iterator over active alerts that have not been
// resolved and successfully notified about.
// They are not guaranteed to be in chronological order.
func (a *Alerts) Subscribe(name string) provider.AlertIterator {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	var (
		done   = make(chan struct{})
		alerts = a.alerts.List()
		ch     = make(chan *provider.Alert, max(len(alerts), alertChannelLength))
	)

	for _, a := range alerts {
		ch <- &provider.Alert{
			Header: map[string]string{},
			Data:   a,
		}
	}

	a.listeners[a.next] = listeningAlerts{name: name, alerts: ch, done: done}
	a.next++

	return provider.NewAlertIterator(ch, done, nil)
}

func (a *Alerts) SlurpAndSubscribe(name string) ([]*alert.Alert, provider.AlertIterator) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	var (
		done   = make(chan struct{})
		alerts = a.alerts.List()
		ch     = make(chan *provider.Alert, alertChannelLength)
	)

	a.listeners[a.next] = listeningAlerts{name: name, alerts: ch, done: done}
	a.next++

	return alerts, provider.NewAlertIterator(ch, done, nil)
}

// GetPending returns an iterator over all the alerts that have
// pending notifications.
func (a *Alerts) GetPending() provider.AlertIterator {
	var (
		ch   = make(chan *provider.Alert, alertChannelLength)
		done = make(chan struct{})
	)
	a.mtx.Lock()
	defer a.mtx.Unlock()
	alerts := a.alerts.List()

	go func() {
		defer close(ch)
		for _, a := range alerts {
			select {
			case ch <- &provider.Alert{
				Header: map[string]string{},
				Data:   a,
			}:
			case <-done:
				return
			}
		}
	}()

	return provider.NewAlertIterator(ch, done, nil)
}

// Get returns the alert for a given fingerprint.
func (a *Alerts) Get(fp model.Fingerprint) (*alert.Alert, error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.alerts.Get(fp)
}

// Put adds the given alert to the set.
func (a *Alerts) Put(ctx context.Context, alerts ...*alert.Alert) error {
	wait := time.Now()
	a.mtx.Lock()
	start := time.Now()
	observeDuration(a.putWait, wait)
	defer func() { observeDuration(a.putHold, start); a.mtx.Unlock() }()

	ctx, span := tracer.Start(ctx, "provider.mem.Put",
		trace.WithAttributes(
			attribute.Int("alerting.alerts.count", len(alerts)),
		),
		trace.WithSpanKind(trace.SpanKindProducer),
	)
	defer span.End()

	for _, alrt := range alerts {
		fp := alrt.Fingerprint()

		existing := false

		// Check that there's an alert existing within the store before
		// trying to merge.
		if old, err := a.alerts.Get(fp); err == nil {
			// Ignore explicit clears from disjoint earlier intervals before any side effects.
			if !alrt.Timeout && alrt.Resolved() && alrt.EndsAt.Before(old.StartsAt) {
				continue
			}
			existing = true

			// Merge alerts if there is an overlap in activity range.
			if (alrt.EndsAt.After(old.StartsAt) && alrt.EndsAt.Before(old.EndsAt)) ||
				(alrt.StartsAt.After(old.StartsAt) && alrt.StartsAt.Before(old.EndsAt)) {
				alrt = old.Merge(alrt)
			}
		}

		if err := a.callback.PreStore(alrt, existing); err != nil {
			a.logger.Error("pre-store callback returned error on set alert", "err", err)
			continue
		}

		if err := a.alerts.Set(alrt); err != nil {
			a.logger.Warn("error on set alert", "alertname", alrt.Name(), "err", err)
			if errors.Is(err, store.ErrLimited) {
				labels := []string{}
				if a.flagger.EnableAlertNamesInMetrics() {
					labels = append(labels, alrt.Name())
				}
				a.alertsLimitedTotal.WithLabelValues(labels...).Inc()
			}
			continue
		}

		a.callback.PostStore(alrt, existing)
		if a.observer != nil {
			a.observer.Upserted(alrt)
		}

		if !existing {
			a.recorder.RecordEvent(ctx, func() eventrecorder.EventData {
				return eventrecorder.NewAlertCreatedEvent(alrt)
			})
		}

		metadata := map[string]string{}
		a.propagator.Inject(ctx, propagation.MapCarrier(metadata))
		msg := &provider.Alert{
			Data:   alrt,
			Header: metadata,
		}

		for _, l := range a.listeners {
			select {
			case l.alerts <- msg:
				a.subscriberChannelWrites.WithLabelValues(l.name).Inc()
			case <-l.done:
			}
		}
	}

	return nil
}

type noopCallback struct{}

func (n noopCallback) PreStore(_ *alert.Alert, _ bool) error { return nil }
func (n noopCallback) PostStore(_ *alert.Alert, _ bool)      {}
func (n noopCallback) PostDelete(_ *alert.Alert)             {}
func (n noopCallback) PostGC(_ model.Fingerprints)           {}
