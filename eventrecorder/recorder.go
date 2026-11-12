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

// Package eventrecorder provides a structured event recorder for
// significant Alertmanager events.  Events are serialized as JSON and
// fanned out to one or more configured destinations.
//
// RecordEvent never blocks the caller: events are serialized and
// placed on a bounded in-memory queue.  A background goroutine
// drains the queue and sends to destinations.  If the queue is full,
// events are dropped and a metric is incremented.
package eventrecorder

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/prometheus/alertmanager/cluster"
)

const (
	// Maximum number of events buffered before new events are dropped.
	// Observation snapshots have separate field/byte bounds; queue slots alone
	// are not a four-megabyte memory guarantee.
	eventQueueSize = 8192
)

type recordingEnabledContextKey struct{}

// WithEventRecording returns a context that enables event recording.
// By default, event recording is disabled; callers must opt in by
// decorating their context with this function.
func WithEventRecording(ctx context.Context) context.Context {
	return context.WithValue(ctx, recordingEnabledContextKey{}, true)
}

// EventRecordingEnabled reports whether event recording has been
// enabled in the given context via WithEventRecording.
func EventRecordingEnabled(ctx context.Context) bool {
	v, _ := ctx.Value(recordingEnabledContextKey{}).(bool)
	return v
}

// Recorder is a concrete, non-nil-able handle to an event recorder.
// Because it is a struct (not an interface), passing nil where a
// Recorder is expected is a compile-time error.
//
// The zero value (Recorder{}) is safe to use and silently discards all
// events, but prefer NopRecorder() for clarity.
type Recorder struct {
	core *sharedRecorder
}

// writeRequest is a single event queued for background serialization
// and writing.
type writeRequest struct {
	event Event
}

// sharedRecorder holds the mutable state shared by all copies of a
// Recorder value.  Mutable state (outputs, currentCfg) is owned
// exclusively by the writeLoop goroutine and updated via the
// cfgUpdate channel, eliminating the need for a mutex.
type sharedRecorder struct {
	instance                                  string
	logger                                    *slog.Logger
	metrics                                   *metrics
	peer                                      atomic.Pointer[cluster.Peer]
	runtimeEpoch                              string
	interest                                  atomic.Uint32
	admissions                                admissionCache
	observation                               observationCounters
	observationEnabled, observationConfigured bool
	observationStarted                        int64
	observationOutput                         atomic.Pointer[WebhookOutput]

	// Async write queue.  nil for NopRecorder, non-nil for active.
	events    chan writeRequest
	cfgUpdate chan cfgUpdateMsg
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// cfgUpdateMsg is sent to writeLoop to hot-reload the configuration.
// The sender blocks until the writeLoop acknowledges by closing done.
type cfgUpdateMsg struct {
	cfg  Config
	done chan struct{}
}

// Destination is a single event destination.  Each implementation
// owns its own serialization: it receives the structured event and is
// responsible for encoding it with Event.MarshalJSON or
// Event.MarshalProtobuf and delivering it.
//
// Owning serialization per destination — rather than handing every
// destination a pre-encoded JSON blob — avoids the footgun of, say, a
// protobuf-configured Kafka output silently shipping a JSON payload.
type Destination interface {
	// Name returns the type and configured name for this destination,
	// suitable for use as a Prometheus label value (e.g. "file:archive"
	// or "webhook:primary").
	Name() string
	// SendEvent encodes and delivers the event.  It returns the number
	// of payload bytes written (for the bytes-written metric) and any
	// delivery error.  A serialization failure should be returned
	// wrapped in *serializeError so the recorder can attribute it to
	// the serialize-errors metric.
	SendEvent(event Event) (size int, err error)
	io.Closer
}

// serializeError marks a failure to encode an event (as opposed to a
// delivery failure) so marshalAndSend can attribute it to the
// serialize-errors metric.  Destinations wrap encoding failures in it.
type serializeError struct{ err error }

func (e *serializeError) Error() string { return e.err.Error() }
func (e *serializeError) Unwrap() error { return e.err }

// NopRecorder returns a Recorder that silently discards all events.
// Use this in tests or when the event recorder is not configured.
func NopRecorder() Recorder {
	return Recorder{core: &sharedRecorder{}}
}

// NewRecorderFromConfig builds a Recorder from the given configuration.
// A background goroutine is started to drain the event queue; call
// Close to stop it.
func NewRecorderFromConfig(cfg Config, instance string, logger *slog.Logger, r prometheus.Registerer) Recorder {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	core := &sharedRecorder{
		instance:     boundedString(instance, 256),
		runtimeEpoch: newRuntimeEpoch(),
		logger:       logger,
		metrics:      newMetrics(r),
		events:       make(chan writeRequest, eventQueueSize),
		cfgUpdate:    make(chan cfgUpdateMsg),
		done:         make(chan struct{}),
	}
	initialOutputs := buildOutputs(cfg, instance, core.metrics, logger, core.recordObservationReceipt)
	core.setOutputs(initialOutputs)

	if r != nil {
		r.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "alertmanager_event_recorder_queue_length",
			Help: "Current number of events waiting in the event recorder write queue.",
		}, func() float64 {
			return float64(len(core.events))
		}))
	}

	core.wg.Add(1)
	go core.writeLoop(initialOutputs, cfg)

	return Recorder{core: core}
}

// buildOutputs creates Destination implementations from the given config.
func buildOutputs(cfg Config, instance string, m *metrics, logger *slog.Logger, observationReceipt ...func(int64)) []Destination {
	if err := cfg.validate(); err != nil {
		logger.Error("Invalid event recorder output configuration")
		return nil
	}
	var outputs []Destination
	for _, fc := range cfg.FileOutputs {
		fo, err := NewFileOutput(fc, logger)
		if err != nil {
			logger.Error("Failed to create file event recorder output", "output", safeOutputIdentifier("file", fc.Name), "path", fc.Path, "err", err)
			continue
		}
		outputs = append(outputs, fo)
	}
	for _, wc := range cfg.WebhookOutputs {
		if wc.observationKey != "" && len(observationReceipt) > 0 {
			wc.observationReceipt = observationReceipt[0]
		}
		wo, err := NewWebhookOutput(wc, m.outputDrops, logger)
		if err != nil {
			logger.Error("Failed to create webhook event recorder output", "output", safeOutputIdentifier("webhook", wc.Name))
			continue
		}
		outputs = append(outputs, wo)
	}
	for _, kc := range cfg.KafkaOutputs {
		ko, err := NewKafkaOutput(kc, instance, m.outputDrops, m.kafkaProduceErrors, logger)
		if err != nil {
			logger.Error("Failed to create kafka event recorder output", "output", safeOutputIdentifier("kafka", kc.Name))
			continue
		}
		outputs = append(outputs, ko)
	}
	for _, sc := range cfg.StdoutOutputs {
		so, err := NewStdoutOutput(sc)
		if err != nil {
			logger.Error("Failed to create stdout event recorder output", "output", safeOutputIdentifier("stdout", sc.Name))
			continue
		}
		outputs = append(outputs, so)
	}
	return outputs
}

// writeLoop drains the event queue, serializes events, and writes to
// outputs.  It owns the outputs and currentCfg exclusively — all
// mutations arrive via the cfgUpdate channel, so no mutex is needed.
//
// The protojson.Marshal runs here (not in the caller goroutine) so that
// the serialization cost is off the alert-processing hot path.
//
// It runs until the done channel is closed, then drains remaining
// events and closes all outputs before returning.
func (c *sharedRecorder) writeLoop(outputs []Destination, currentCfg Config) {
	defer c.wg.Done()
	defer c.setOutputs(nil)
	defer func() {
		for _, out := range outputs {
			if err := out.Close(); err != nil && c.logger != nil {
				c.logger.Error("Failed to close event recorder output", "output", out.Name())
			}
		}
	}()

	for {
		select {
		case req := <-c.events:
			c.marshalAndSend(req, outputs)
		case update := <-c.cfgUpdate:
			if !configEqual(update.cfg, currentCfg) {
				buildCfg := update.cfg
				var retained *WebhookOutput
				if current := c.observationOutput.Load(); current != nil {
					for _, before := range currentCfg.WebhookOutputs {
						if before.observationKey == "" {
							continue
						}
						for i, after := range buildCfg.WebhookOutputs {
							if before.equal(after) {
								retained = current
								buildCfg.WebhookOutputs = append(append([]WebhookOutputConfig{}, buildCfg.WebhookOutputs[:i]...), buildCfg.WebhookOutputs[i+1:]...)
								break
							}
						}
					}
				}
				newOutputs := buildOutputs(buildCfg, c.instance, c.metrics, c.logger, c.recordObservationReceipt)
				if retained != nil {
					newOutputs = append(newOutputs, retained)
				}
				if len(newOutputs) != update.cfg.totalOutputs() {
					// Some outputs failed to initialize.  Keep the existing
					// (known-good) set rather than risking partial coverage.
					c.logger.Error("Failed to reload event recorder outputs; keeping existing outputs")
					for _, out := range newOutputs {
						if out == retained {
							continue
						}
						if err := out.Close(); err != nil {
							c.logger.Error("Failed to close partially-built event recorder output", "output", out.Name())
						}
					}
					close(update.done)
					continue
				}
				oldOutputs := outputs
				outputs = newOutputs
				currentCfg = update.cfg
				c.setOutputs(outputs)
				for _, out := range oldOutputs {
					if out == retained {
						continue
					}
					if err := out.Close(); err != nil {
						c.logger.Error("Failed to close old event recorder output", "output", out.Name())
					}
				}
				c.logger.Info("Event recorder configuration reloaded", "outputs", len(outputs))
			}
			close(update.done)
		case <-c.done:
			// Drain remaining events and any pending config updates.
			for {
				select {
				case req := <-c.events:
					c.marshalAndSend(req, outputs)
				case update := <-c.cfgUpdate:
					close(update.done)
				default:
					return
				}
			}
		}
	}
}

// marshalAndSend fans the queued event out to all outputs.  Each
// destination owns its own serialization, so the recorder hands every
// output the structured event and records per-output result and
// bytes-written metrics from the returned size/error.
func (c *sharedRecorder) marshalAndSend(req writeRequest, outputs []Destination) {
	if req.event.message.GetData().GetInhibitionMutedAlert().GetObservation() != nil && time.Since(req.event.message.Timestamp.AsTime()) > ObservationResidence {
		c.dropObservation()
		c.metrics.eventsDropped.WithLabelValues("inhibition_muted_alert").Inc()
		return
	}
	for _, out := range outputs {
		if filter, ok := out.(interface{ Interested(string) bool }); ok && !filter.Interested(req.event.typeName()) {
			continue
		}
		name := out.Name()
		size, err := out.SendEvent(req.event)
		if err != nil {
			if _, ok := errors.AsType[*serializeError](err); ok {
				c.metrics.eventSerializeErrors.WithLabelValues(req.event.typeName()).Inc()
			}
			c.metrics.eventsRecorded.WithLabelValues(req.event.typeName(), name, "error").Inc()
			c.logger.Error("Failed to write event", "event_type", req.event.typeName(), "output", name)
			continue
		}
		c.metrics.eventsRecorded.WithLabelValues(req.event.typeName(), name, "success").Inc()
		c.metrics.eventRecorderBytesWritten.WithLabelValues(req.event.typeName(), name).Add(float64(size))
	}
}

// RecordEvent wraps the event data with metadata and places it on a bounded
// queue for background serialization and delivery.  If the queue is full the
// event is dropped (never blocks the caller).  Recording only occurs when the
// context has been decorated with WithEventRecording.
//
// The event data is supplied as a builder function rather than a value so
// that callers on hot read paths do not pay to snapshot alerts and fingerprints
// for an event that would only be discarded when recording is disabled.  The
// builder is invoked only
// after the recording gates pass, and exactly once.
//
// The expensive protojson.Marshal call is deferred to the write-loop
// goroutine so that the caller's hot path only pays for snapshot construction
// and a channel send.
// RecordEvent is the legacy all-events API. Production callers use RecordTypedEvent
// so inhibition-only outputs cannot enable unrelated builders.
func (r Recorder) RecordEvent(ctx context.Context, build func() EventData) {
	r.RecordTypedEvent(ctx, "*", build)
}

const (
	interestAll        uint32 = 1
	interestInhibition uint32 = 1 << 10
)

func eventInterest(eventType string) uint32 {
	switch eventType {
	case "alertmanager_startup_event":
		return 1 << 1
	case "alertmanager_shutdown_event":
		return 1 << 2
	case "alert_created":
		return 1 << 3
	case "alert_resolved":
		return 1 << 4
	case "alert_grouped":
		return 1 << 5
	case "notification":
		return 1 << 6
	case "silence_created":
		return 1 << 7
	case "silence_updated":
		return 1 << 8
	case "silence_muted_alert":
		return 1 << 9
	case "inhibition_muted_alert":
		return interestInhibition
	}
	return 0
}

func (c *sharedRecorder) setOutputs(outputs []Destination) {
	var interest uint32
	var observation *WebhookOutput
	for _, out := range outputs {
		if wo, ok := out.(*WebhookOutput); ok && len(wo.eventTypes) > 0 {
			for _, kind := range wo.eventTypes {
				interest |= eventInterest(kind)
			}
			if wo.observationKey != "" {
				observation = wo
			}
		} else {
			interest |= interestAll | interestInhibition
		}
	}
	c.observationOutput.Store(observation)
	c.interest.Store(interest)
}

// Interested is the pre-builder event-type gate. It performs no snapshots or I/O.
func (r Recorder) Interested(ctx context.Context, eventType string) bool {
	if r.core == nil || r.core.events == nil || !EventRecordingEnabled(ctx) {
		return false
	}
	interest := r.core.interest.Load()
	return interest&interestAll != 0 || interest&eventInterest(eventType) != 0
}

// RecordTypedEvent checks configured interest before constructing immutable snapshots.
func (r Recorder) RecordTypedEvent(ctx context.Context, eventType string, build func() EventData) bool {
	if !r.Interested(ctx, eventType) {
		return false
	}
	return r.enqueue(build(), time.Now())
}

func (r Recorder) enqueue(data EventData, now time.Time) bool {
	clusterPosition := uint64(0)
	if peer := r.core.peer.Load(); peer != nil {
		clusterPosition = uint64(peer.Position())
	}
	event := data.withMetadata(timestamppb.New(now), r.core.instance, clusterPosition)
	select {
	case <-r.core.done:
		return false
	default:
	}
	select {
	case r.core.events <- writeRequest{event: event}:
		return true
	default:
		r.core.metrics.eventsDropped.WithLabelValues(event.typeName()).Inc()
		return false
	}
}

// SetObservationOptions records fixed service enablement independently of sink success.
// Call once during construction before sharing the recorder.
func (r Recorder) SetObservationOptions(enabled, configured bool) {
	if r.core != nil {
		r.core.observationStarted = time.Now().UnixNano()
		r.core.observationEnabled = enabled
		r.core.observationConfigured = configured
	}
}

// SetClusterPeer sets the cluster peer for HA position tracking.
func (r Recorder) SetClusterPeer(peer *cluster.Peer) {
	if r.core == nil {
		return
	}
	r.core.peer.Store(peer)
}

// ApplyConfig hot-reloads the event recorder configuration.  The update is
// sent to the writeLoop goroutine, which owns the outputs; this method
// blocks until the writeLoop has acknowledged the update.
func (r Recorder) ApplyConfig(cfg Config) {
	if r.core == nil || r.core.cfgUpdate == nil {
		return
	}
	ack := make(chan struct{})
	select {
	case r.core.cfgUpdate <- cfgUpdateMsg{cfg: cfg, done: ack}:
		<-ack
	case <-r.core.done:
		// Shutting down; ignore config update.
	}
}

// Close signals the background goroutine to drain remaining events
// and stop.  The writeLoop closes all outputs before returning.
func (r Recorder) Close() error {
	if r.core == nil || r.core.done == nil {
		return nil
	}
	r.core.closeOnce.Do(func() {
		close(r.core.done)
	})
	r.core.wg.Wait()
	return nil
}
