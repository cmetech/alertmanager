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

package eventrecorder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"

	amcommoncfg "github.com/prometheus/alertmanager/config/common"
)

// WebhookOutputConfig configures an HTTP webhook event recorder output.
type WebhookOutputConfig struct {
	EventTypes         []string `yaml:"event_types,omitempty" json:"event_types,omitempty"`
	observationKey     string
	observationReceipt func(int64)
	// Name identifies this output in metrics and logs.
	Name string `yaml:"name" json:"name"`
	// URL is the endpoint to POST each event to.
	URL *amcommoncfg.SecretURL `yaml:"url" json:"url"`
	// HTTPConfig configures the HTTP client used for webhook delivery.
	HTTPConfig *commoncfg.HTTPClientConfig `yaml:"http_config,omitempty" json:"http_config,omitempty"`
	// Timeout for webhook HTTP requests (default 10s).
	Timeout model.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// Workers is the number of concurrent delivery goroutines (default 4).
	Workers int `yaml:"workers,omitempty" json:"workers,omitempty"`
	// MaxRetries is the maximum number of delivery attempts per event
	// (default 3).
	MaxRetries int `yaml:"max_retries,omitempty" json:"max_retries,omitempty"`
	// RetryBackoff is the base backoff between retry attempts (default
	// 500ms).  Successive attempts use exponential backoff (base *
	// 2^attempt).
	RetryBackoff model.Duration `yaml:"retry_backoff,omitempty" json:"retry_backoff,omitempty"`
	// Batch enables sending events as JSON arrays instead of individual objects.
	Batch bool `yaml:"batch,omitempty" json:"batch,omitempty"`
	// BatchMaxEvents is the maximum number of events in one request (default 100).
	BatchMaxEvents int `yaml:"batch_max_events,omitempty" json:"batch_max_events,omitempty"`
	// BatchMaxBytes is the soft maximum encoded request size (default 1 MiB).
	BatchMaxBytes int `yaml:"batch_max_bytes,omitempty" json:"batch_max_bytes,omitempty"`
	// BatchFlushInterval is the maximum time an incomplete batch waits (default 100ms).
	BatchFlushInterval model.Duration `yaml:"batch_flush_interval,omitempty" json:"batch_flush_interval,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface, validating
// the webhook output configuration.
//
// Note: SecretURL.UnmarshalYAML delegates to ParseURL, which already
// enforces a non-empty host and an http(s) scheme.  The only way an
// otherwise-valid config reaches this function with a degenerate URL is
// via the "<secret>" placeholder shortcut in SecretURL.UnmarshalYAML,
// which sets URL to an empty url.URL{}.  We catch that case here.
func (c *WebhookOutputConfig) UnmarshalYAML(unmarshal func(any) error) error {
	type plain WebhookOutputConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return errors.New("invalid event_recorder webhook output configuration")
	}
	return c.validate()
}

func (c WebhookOutputConfig) validate() error {
	if _, err := outputIdentifier("webhook", c.Name); err != nil {
		return err
	}
	if c.URL == nil || c.URL.URL == nil {
		return errors.New("event_recorder webhook output requires a url")
	}
	if c.URL.Scheme == "" || c.URL.Host == "" {
		return errors.New("event_recorder webhook output requires an absolute http(s) url")
	}
	if c.BatchMaxEvents < 0 || c.BatchMaxBytes < 0 || c.BatchFlushInterval < 0 {
		return errors.New("event_recorder webhook batch settings cannot be negative")
	}
	if !c.Batch && (c.BatchMaxEvents != 0 || c.BatchMaxBytes != 0 || c.BatchFlushInterval != 0) {
		return errors.New("event_recorder webhook batch settings require batch: true")
	}
	return nil
}

// equal reports whether two webhook output configs are semantically
// equal.
func (c WebhookOutputConfig) equal(o WebhookOutputConfig) bool {
	if !slices.Equal(c.EventTypes, o.EventTypes) || c.observationKey != o.observationKey || c.Name != o.Name {
		return false
	}
	aURL, bURL := "", ""
	if c.URL != nil {
		aURL = c.URL.String()
	}
	if o.URL != nil {
		bURL = o.URL.String()
	}
	if aURL != bURL {
		return false
	}
	if c.Timeout != o.Timeout {
		return false
	}
	if c.Workers != o.Workers {
		return false
	}
	if c.MaxRetries != o.MaxRetries {
		return false
	}
	if c.RetryBackoff != o.RetryBackoff {
		return false
	}
	if c.Batch != o.Batch {
		return false
	}
	if c.Batch && !httpBatchConfigsEqual(
		newHTTPBatchConfig(c.BatchMaxEvents, c.BatchMaxBytes, c.BatchFlushInterval),
		newHTTPBatchConfig(o.BatchMaxEvents, o.BatchMaxBytes, o.BatchFlushInterval),
	) {
		return false
	}
	return reflect.DeepEqual(c.HTTPConfig, o.HTTPConfig)
}

const (
	defaultWebhookTimeout      = 10 * time.Second
	defaultWebhookWorkers      = 4
	defaultWebhookMaxRetries   = 3
	defaultWebhookRetryBackoff = 500 * time.Millisecond
	defaultWebhookMaxBackoff   = 30 * time.Second
	defaultHTTPBatchMaxEvents  = 100
	defaultHTTPBatchMaxBytes   = 1 << 20
	defaultHTTPBatchInterval   = 100 * time.Millisecond
	webhookQueueSize           = 1024
)

// WebhookOutput POSTs each event as a JSON body to a configured URL.
// Events are processed by a bounded worker pool so that a slow or
// temporarily unavailable webhook does not block the event recorder queue.
// Events are dropped (with a log message) when the internal queue is
// full.
type outputHealth struct {
	// Only recorder/HTTP workers and status readers use this mutex, never alert threads.
	mu                          sync.Mutex
	dropped, failures           atomic.Uint64
	success, problem, recovered atomic.Int64
}

func (h *outputHealth) drop() { h.dropCount(1) }
func (h *outputHealth) dropCount(count int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropped.Add(uint64(count))
	h.problem.CompareAndSwap(0, time.Now().UnixNano())
}

func (h *outputHealth) failed() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failures.Add(1)
	h.problem.CompareAndSwap(0, time.Now().UnixNano())
}

type WebhookOutput struct {
	eventTypes         []string
	observationKey     string
	observationReceipt func(int64)
	health             outputHealth
	client             *http.Client
	url                string
	name               string
	kind               string
	batch              *httpBatchConfig
	maxRetries         int
	retryBackoff       time.Duration
	maxBackoff         time.Duration
	logger             *slog.Logger
	drops              prometheus.Counter
	work               chan []byte
	batches            chan []byte
	done               chan struct{}
	cancel             chan struct{} // closed after drain to abort remaining retries
	wg                 sync.WaitGroup
}

type httpBatchConfig struct {
	maxEvents     int
	maxBytes      int
	flushInterval time.Duration
}

// NewWebhookOutput creates a new webhook-based event recorder output.
func NewWebhookOutput(cfg WebhookOutputConfig, dropsCounter *prometheus.CounterVec, logger *slog.Logger) (*WebhookOutput, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	var batch *httpBatchConfig
	if cfg.Batch {
		batch = newHTTPBatchConfig(cfg.BatchMaxEvents, cfg.BatchMaxBytes, cfg.BatchFlushInterval)
	}
	return newWebhookOutput(cfg, "webhook", batch, dropsCounter, logger)
}

func newHTTPBatchConfig(maxEvents, maxBytes int, flushInterval model.Duration) *httpBatchConfig {
	batch := &httpBatchConfig{
		maxEvents:     defaultHTTPBatchMaxEvents,
		maxBytes:      defaultHTTPBatchMaxBytes,
		flushInterval: defaultHTTPBatchInterval,
	}
	if maxEvents > 0 {
		batch.maxEvents = maxEvents
	}
	if maxBytes > 0 {
		batch.maxBytes = maxBytes
	}
	if flushInterval > 0 {
		batch.flushInterval = time.Duration(flushInterval)
	}
	return batch
}

func httpBatchConfigsEqual(a, b *httpBatchConfig) bool {
	return *a == *b
}

func newWebhookOutput(cfg WebhookOutputConfig, kind string, batch *httpBatchConfig, dropsCounter *prometheus.CounterVec, logger *slog.Logger) (*WebhookOutput, error) {
	httpCfg := commoncfg.DefaultHTTPClientConfig
	if cfg.HTTPConfig != nil {
		httpCfg = *cfg.HTTPConfig
	}

	client, err := commoncfg.NewClientFromConfig(httpCfg, "eventrecorder")
	if err != nil {
		return nil, fmt.Errorf("creating HTTP client for event recorder %s: %w", kind, err)
	}

	timeout := defaultWebhookTimeout
	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout)
	}
	client.Timeout = timeout
	if cfg.observationKey != "" {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	workers := defaultWebhookWorkers
	if cfg.Workers > 0 {
		workers = cfg.Workers
	}

	maxRetries := defaultWebhookMaxRetries
	if cfg.MaxRetries > 0 {
		maxRetries = cfg.MaxRetries
	}

	retryBackoff := defaultWebhookRetryBackoff
	if cfg.RetryBackoff > 0 {
		retryBackoff = time.Duration(cfg.RetryBackoff)
	}

	urlStr := cfg.URL.String()
	name, err := outputIdentifier(kind, cfg.Name)
	if err != nil {
		return nil, err
	}
	wo := &WebhookOutput{
		client:             client,
		eventTypes:         slices.Clone(cfg.EventTypes),
		observationKey:     cfg.observationKey,
		observationReceipt: cfg.observationReceipt,
		url:                urlStr,
		name:               name,
		kind:               kind,
		batch:              batch,
		maxRetries:         maxRetries,
		retryBackoff:       retryBackoff,
		maxBackoff:         defaultWebhookMaxBackoff,
		logger:             logger,
		drops:              dropsCounter.WithLabelValues(name),
		work:               make(chan []byte, webhookQueueSize),
		done:               make(chan struct{}),
		cancel:             make(chan struct{}),
	}

	if batch != nil {
		wo.wg.Add(1)
		wo.batches = make(chan []byte, workers)
		go wo.batchLoop()
		for range workers {
			wo.wg.Add(1)
			go wo.batchDeliveryWorker()
		}
	} else {
		for range workers {
			wo.wg.Add(1)
			go wo.worker()
		}
	}

	return wo, nil
}

// Name returns a stable identifier for this output.
func (wo *WebhookOutput) Name() string {
	return wo.name
}

// SendEvent serializes the event as JSON and queues it for delivery by
// a worker.  It returns the serialized size (for the bytes-written
// metric).  If the internal queue is full the event is dropped and
// counted via the output-drops metric.
// Interested filters before serialization as well as the recorder builder gate.
func (wo *WebhookOutput) Interested(eventType string) bool {
	return len(wo.eventTypes) == 0 || slices.Contains(wo.eventTypes, eventType)
}

func (wo *WebhookOutput) SendEvent(event Event) (int, error) {
	if !wo.Interested(event.typeName()) {
		return 0, nil
	}
	if wo.observationKey != "" && event.message.GetData().GetInhibitionMutedAlert().GetObservation() == nil {
		return 0, nil
	}
	data, err := event.MarshalJSON()
	if err != nil {
		if wo.observationKey != "" {
			wo.health.drop()
			wo.drops.Inc()
		}
		return 0, &serializeError{err: err}
	}
	if wo.observationKey != "" && len(data) > observationMaxEventBytes {
		wo.drops.Inc()
		wo.health.drop()
		return 0, errors.New("observation exceeds encoded byte budget")
	}
	select {
	case wo.work <- data:
	default:
		wo.drops.Inc()
		wo.health.drop()
		wo.logger.Warn("Event recorder HTTP output queue full, dropping event", "output", wo.name)
	}
	return len(data), nil
}

func (wo *WebhookOutput) worker() {
	defer wo.wg.Done()
	for {
		select {
		case data := <-wo.work:
			wo.postWithRetry(data)
		case <-wo.done:
			// Drain remaining items.
			for {
				select {
				case data := <-wo.work:
					wo.postWithRetry(data)
				default:
					return
				}
			}
		}
	}
}

func (wo *WebhookOutput) batchLoop() {
	defer wo.wg.Done()
	defer close(wo.batches)

	batch := make([][]byte, 0, min(wo.batch.maxEvents, webhookQueueSize))
	batchSize := 2 // Opening and closing brackets.
	var timer *time.Timer
	var timerC <-chan time.Time

	stopTimer := func() {
		if timer != nil {
			timer.Stop()
			timer = nil
			timerC = nil
		}
	}
	flush := func() {
		stopTimer()
		if len(batch) == 0 {
			return
		}
		wo.batches <- jsonArray(batch, batchSize)
		batch = batch[:0]
		batchSize = 2
	}
	add := func(data []byte) {
		additionalSize := len(data)
		if len(batch) > 0 {
			additionalSize++ // Comma separator.
		}
		if len(batch) > 0 && (len(batch) >= wo.batch.maxEvents || batchSize+additionalSize > wo.batch.maxBytes) {
			flush()
			additionalSize = len(data)
		}
		batch = append(batch, data)
		batchSize += additionalSize
		if len(batch) == 1 {
			timer = time.NewTimer(wo.batch.flushInterval)
			timerC = timer.C
		}
		if len(batch) >= wo.batch.maxEvents || batchSize >= wo.batch.maxBytes {
			flush()
		}
	}

	for {
		select {
		case data := <-wo.work:
			add(data)
		case <-timerC:
			flush()
		case <-wo.done:
			for {
				select {
				case data := <-wo.work:
					add(data)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (wo *WebhookOutput) batchDeliveryWorker() {
	defer wo.wg.Done()
	for data := range wo.batches {
		wo.postWithRetry(data)
	}
}

func jsonArray(events [][]byte, size int) []byte {
	data := make([]byte, 0, size)
	data = append(data, '[')
	for i, event := range events {
		if i > 0 {
			data = append(data, ',')
		}
		data = append(data, event...)
	}
	return append(data, ']')
}

func (wo *WebhookOutput) postWithRetry(data []byte) {
	count := 1
	deadline := time.Time{}
	if wo.observationKey != "" {
		// Queue residence is independent of retries, including time in the shared queue.
		var batch []struct {
			Timestamp time.Time `json:"@timestamp"`
		}
		if err := json.Unmarshal(data, &batch); err != nil || len(batch) == 0 {
			wo.dropEvents(count)
			return
		}
		count = len(batch)
		deadline = batch[0].Timestamp.Add(ObservationResidence)
		for _, entry := range batch {
			if d := entry.Timestamp.Add(ObservationResidence); d.Before(deadline) {
				deadline = d
			}
		}
	}
	for attempt := range wo.maxRetries {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			wo.dropEvents(count)
			return
		}
		if err := wo.postBefore(data, deadline); err == nil {
			wo.health.mu.Lock()
			now := time.Now().UnixNano()
			wo.health.success.Store(now)
			if wo.health.problem.Swap(0) != 0 {
				wo.health.recovered.Store(now)
			}
			if wo.observationReceipt != nil {
				wo.observationReceipt(now)
			}
			wo.health.mu.Unlock()
			return
		}
		wo.logger.Warn("Event recorder HTTP output POST failed", "output", wo.name, "attempt", attempt+1)
		wo.health.failed()
		if attempt < wo.maxRetries-1 {
			backoff := min(wo.retryBackoff<<attempt, wo.maxBackoff)
			if !deadline.IsZero() {
				backoff = min(backoff, time.Until(deadline))
			}
			select {
			case <-time.After(backoff):
			case <-wo.cancel:
				wo.dropEvents(count)
				return
			}
		}
	}
	wo.dropEvents(count)
}

func (wo *WebhookOutput) dropEvents(n int) {
	wo.health.dropCount(n)
	wo.drops.Add(float64(n))
}

func (wo *WebhookOutput) post(data []byte) error {
	return wo.postBefore(data, time.Time{})
}

func (wo *WebhookOutput) postBefore(data []byte, deadline time.Time) error {
	ctx := context.Background()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wo.url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if wo.observationKey != "" {
		req.Header.Set(ObservationKeyHeader, wo.observationKey)
	}
	resp, err := wo.client.Do(req)
	if err != nil {
		return fmt.Errorf("event recorder %s POST failed: %w", wo.kind, err)
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("event recorder %s returned HTTP %d", wo.kind, resp.StatusCode)
	}
	return nil
}

// Close signals all workers to stop, drains remaining events, and
// waits.  If the drain takes longer than 30 seconds, remaining
// retries are canceled.
func (wo *WebhookOutput) Close() error {
	defer wo.client.CloseIdleConnections()
	close(wo.done)
	ch := make(chan struct{})
	go func() {
		wo.wg.Wait()
		close(ch)
	}()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		close(wo.cancel)
		wo.wg.Wait()
	}
	return nil
}

// SameWebhookConfig compares effective output configuration, including private fixed credentials.
func SameWebhookConfig(a, b WebhookOutputConfig) bool { return a.equal(b) }
