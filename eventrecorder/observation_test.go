package eventrecorder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/pkg/labels"
)

func observationFixture() (*alert.Alert, *alert.Alert, ObservationRule) {
	now := time.Now().UTC()
	return alert.New(model.Alert{Labels: model.LabelSet{"role": "source"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}, now, false), alert.New(model.Alert{Labels: model.LabelSet{"role": "target"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false), NewObservationRule("test-rev-1", nil, nil, nil)
}

func queueRecorder(size int) Recorder {
	r := Recorder{core: &sharedRecorder{events: make(chan writeRequest, size), metrics: newMetrics(nil), done: make(chan struct{}), runtimeEpoch: newRuntimeEpoch(), logger: slog.New(slog.DiscardHandler)}}
	r.core.interest.Store(interestInhibition)
	return r
}

func observe(r Recorder, source, target *alert.Alert, rule ObservationRule) bool {
	return r.RecordInhibition(recordCtx(), rule, source, target, source.Fingerprint(), target.Fingerprint())
}

func TestObservationAdmission(t *testing.T) {
	t.Parallel()
	s, target, rule := observationFixture()
	r := queueRecorder(1)
	require.True(t, observe(r, s, target, rule))
	require.False(t, observe(r, s, target, rule))
	require.Len(t, r.core.events, 1)
	req := <-r.core.events
	o := req.event.message.GetData().GetInhibitionMutedAlert().Observation
	require.Equal(t, s.StartsAt, o.Source.StartsAt.AsTime())
	require.Equal(t, target.EndsAt, o.Target.EndsAt.AsTime())
	require.Equal(t, s.Fingerprint().String(), o.Source.Fingerprint)
	// Later downstream loss does not undo successful local admission.
	r.core.marshalAndSend(req, nil)
	require.False(t, observe(r, s, target, rule))
	for key := range r.core.admissions.recent {
		r.core.admissions.recent[key] = time.Now().Add(-ObservationRefresh)
	}
	require.True(t, observe(r, s, target, rule))
	<-r.core.events
	changed := NewObservationRule("test-rev-2", nil, nil, nil)
	require.True(t, observe(r, s, target, changed))
	<-r.core.events
	switched := alert.New(model.Alert{Labels: model.LabelSet{"role": "other-source"}, StartsAt: s.StartsAt, EndsAt: s.EndsAt}, time.Now(), false)
	require.True(t, observe(r, switched, target, rule))
	<-r.core.events
	// New runtime has no admission journal and remains eligible.
	restart := queueRecorder(1)
	require.NotEqual(t, r.core.runtimeEpoch, restart.core.runtimeEpoch)
	require.True(t, observe(restart, s, target, rule))
}

func TestObservationFailedEnqueueRetryAndContention(t *testing.T) {
	t.Parallel()
	s, target, rule := observationFixture()
	r := queueRecorder(1)
	r.core.events <- writeRequest{}
	require.False(t, observe(r, s, target, rule))
	require.Empty(t, r.core.admissions.recent)
	<-r.core.events
	require.True(t, observe(r, s, target, rule))
	<-r.core.events
	r.core.admissions.mu.Lock()
	done := make(chan bool, 1)
	go func() { done <- observe(r, s, target, rule) }()
	select {
	case accepted := <-done:
		require.True(t, accepted)
	case <-time.After(time.Second):
		t.Fatal("capture waited for cache lock")
	}
	r.core.admissions.mu.Unlock()
	<-r.core.events
	require.Equal(t, uint64(1), r.core.observation.bypassed.Load())
}

func TestObservationCacheSaturation(t *testing.T) {
	t.Parallel()
	s, target, rule := observationFixture()
	r := queueRecorder(2)
	r.core.admissions.recent = make(map[admissionKey]time.Time)
	for i := range observationCacheSize {
		r.core.admissions.recent[admissionKey{source: model.Fingerprint(i), rule: "other"}] = time.Now()
	}
	require.True(t, observe(r, s, target, rule))
	require.True(t, observe(r, s, target, rule))
	require.Len(t, r.core.admissions.recent, observationCacheSize)
}

func TestObservationBoundsAndImmutability(t *testing.T) {
	t.Parallel()
	s, target, rule := observationFixture()
	target.Labels = model.LabelSet{"oversized": model.LabelValue(strings.Repeat("x", 1<<20))}
	target.Annotations = model.LabelSet{}
	for i := range 10000 {
		target.Annotations[model.LabelName(fmt.Sprint(i))] = "annotation"
	}
	r := queueRecorder(1)
	require.True(t, observe(r, s, target, rule))
	event := (<-r.core.events).event
	o := event.message.GetData().GetInhibitionMutedAlert().Observation
	require.True(t, o.Target.LabelsTruncated)
	require.True(t, o.Target.AnnotationsTruncated)
	require.Len(t, o.Target.Annotations, 32)
	require.Equal(t, target.Fingerprint().String(), o.Target.Fingerprint)
	s.Labels["role"] = "mutated"
	require.Equal(t, "source", o.Source.Labels["role"])
	data, err := event.MarshalJSON()
	require.NoError(t, err)
	require.Less(t, len(data), observationMaxEventBytes)
	unknown := alert.New(model.Alert{}, time.Now(), false)
	require.False(t, observedOccurrence(unknown, unknown.Fingerprint()).IdentityAvailable)
	m, err := labels.NewMatcher(labels.MatchEqual, "role", strings.Repeat("x", 2000))
	require.NoError(t, err)
	bounded := NewObservationRule(strings.Repeat("n", 300), labels.Matchers{m}, nil, nil)
	require.True(t, bounded.truncated)
	require.Len(t, bounded.name, 256)
	require.Len(t, bounded.identity, 64)
	other := NewObservationRule(strings.Repeat("n", 301), labels.Matchers{m}, nil, nil)
	require.NotEqual(t, bounded.identity, other.identity)
}

func TestObservationInterestPrecedesEveryBuilder(t *testing.T) {
	t.Parallel()
	r := queueRecorder(1)
	for _, kind := range []string{"alertmanager_startup_event", "alertmanager_shutdown_event", "alert_created", "alert_grouped", "alert_resolved", "notification", "silence_created", "silence_updated", "silence_muted_alert"} {
		require.False(t, r.RecordTypedEvent(recordCtx(), kind, func() EventData { t.Fatalf("unrelated %s builder executed", kind); return EventData{} }))
	}
	r.core.setOutputs([]Destination{newMockDestination("existing")})
	require.True(t, r.RecordTypedEvent(recordCtx(), "alert_created", startupEvent))
}

func observationConfig(t *testing.T, url string) Config {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(keyPath, []byte(strings.Repeat("k", 32)), 0o600))
	cfg, err := FixedObservationConfig(Config{}, ObservationOptions{Enabled: true, URL: url, KeyFile: keyPath})
	require.NoError(t, err)
	return cfg
}

func TestObservationTransportAndHealth(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	received := make(chan []byte, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, strings.Repeat("k", 32), r.Header.Get(ObservationKeyHeader))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		received <- body
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	cfg := observationConfig(t, server.URL)
	rec := NewRecorderFromConfig(cfg, "producer", nil, nil)
	rec.SetObservationOptions(true, true)
	defer rec.Close()
	require.Equal(t, "unknown", rec.ObservationStatus()["state"])
	s, target, rule := observationFixture()
	require.True(t, observe(rec, s, target, rule))
	require.Eventually(t, func() bool { return calls.Load() == 2 && rec.ObservationStatus()["state"] == "recovering" }, 3*time.Second, 10*time.Millisecond)
	first, second := <-received, <-received
	require.JSONEq(t, string(first), string(second))
	var batch []map[string]any
	require.NoError(t, json.Unmarshal(first, &batch))
	require.Len(t, batch, 1)
	require.Equal(t, uint64(1), rec.ObservationStatus()["output_failures"])
	require.NotNil(t, rec.ObservationStatus()["recovered_at"])
	old := rec.core.observationOutput.Load()
	rec.ApplyConfig(cfg)
	require.Same(t, old, rec.core.observationOutput.Load())
	require.False(t, observe(rec, s, target, rule))
	cfg.FileOutputs = []FileOutputConfig{{Name: "existing-archive", Path: filepath.Join(t.TempDir(), "events.jsonl")}}
	rec.ApplyConfig(cfg)
	require.Same(t, old, rec.core.observationOutput.Load(), "unrelated output reload preserves sink/counters/admission")
	require.True(t, rec.Interested(recordCtx(), "alert_created"))
	require.False(t, observe(rec, s, target, rule))
}

func TestObservationQueueExpiryAndFailures(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
	defer server.Close()
	cfg := observationConfig(t, server.URL).WebhookOutputs[0]
	cfg.RetryBackoff = model.Duration(time.Millisecond)
	wo, err := NewWebhookOutput(cfg, newMetrics(nil).outputDrops, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	defer wo.Close()
	stale := fmt.Sprintf(`[{"@timestamp":%q}]`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
	wo.postWithRetry([]byte(stale))
	require.Zero(t, calls.Load())
	require.Equal(t, uint64(1), wo.health.dropped.Load())
	fresh := fmt.Sprintf(`[{"@timestamp":%q}]`, time.Now().UTC().Format(time.RFC3339Nano))
	wo.postWithRetry([]byte(fresh))
	require.Equal(t, int64(3), calls.Load())
	require.Equal(t, uint64(3), wo.health.failures.Load())
	require.Equal(t, uint64(2), wo.health.dropped.Load())
}

func TestObservationDisabledAndUnavailable(t *testing.T) {
	t.Parallel()
	require.Equal(t, "not_enabled", NopRecorder().ObservationStatus()["state"])
	cfg, err := FixedObservationConfig(Config{}, ObservationOptions{Enabled: true, URL: "http://localhost", KeyFile: "/missing/key"})
	require.Error(t, err)
	rec := NewRecorderFromConfig(cfg, "test", nil, nil)
	rec.SetObservationOptions(true, false)
	defer rec.Close()
	require.Equal(t, "degraded", rec.ObservationStatus()["state"])
	require.Equal(t, false, rec.ObservationStatus()["sink_initialized"])
	require.False(t, rec.Interested(context.Background(), "inhibition_muted_alert"))
}

func BenchmarkObservationRepeatedGroups(b *testing.B) {
	for _, size := range []int{1000, 10000, 50000} {
		for _, enabled := range []bool{false, true} {
			b.Run(fmt.Sprintf("size=%d/enabled=%t", size, enabled), func(b *testing.B) {
				r := queueRecorder(size)
				if !enabled {
					r.core.interest.Store(0)
				}
				source, base, rule := observationFixture()
				targets := make([]*alert.Alert, size)
				for i := range size {
					targets[i] = alert.New(model.Alert{Labels: model.LabelSet{"id": model.LabelValue(fmt.Sprint(i))}, StartsAt: base.StartsAt, EndsAt: base.EndsAt}, time.Now(), false)
					observe(r, source, targets[i], rule)
				}
				for len(r.core.events) > 0 {
					<-r.core.events
				}
				ctx := recordCtx()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					t := targets[i%size]
					r.RecordInhibition(ctx, rule, source, t, source.Fingerprint(), t.Fingerprint())
				}
				b.StopTimer()
				b.ReportMetric(float64(r.core.observation.dropped.Load()), "capture_drops")
			})
		}
	}
}

func BenchmarkObservationColdAndRefresh(b *testing.B) {
	for _, mode := range []string{"cold", "refresh"} {
		b.Run(mode, func(b *testing.B) {
			r := queueRecorder(1)
			source, target, rule := observationFixture()
			ctx := recordCtx()
			if mode == "refresh" {
				observe(r, source, target, rule)
				<-r.core.events
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if mode == "cold" {
					target.StartsAt = target.StartsAt.Add(time.Nanosecond)
				} else {
					for k := range r.core.admissions.recent {
						r.core.admissions.recent[k] = time.Time{}
					}
				}
				r.RecordInhibition(ctx, rule, source, target, source.Fingerprint(), target.Fingerprint())
				<-r.core.events
			}
		})
	}
}

func TestObservationLoadQualification(t *testing.T) {
	// In-process qualification only: no product processes or external receiver.
	for _, size := range []int{1000, 10000, 50000} {
		for _, mode := range []string{"disabled", "repeat", "cold", "refresh"} {
			t.Run(fmt.Sprintf("%d/%s", size, mode), func(t *testing.T) {
				source, base, rule := observationFixture()
				r := queueRecorder(eventQueueSize)
				ctx := recordCtx()
				targets := make([]*alert.Alert, size)
				for i := range size {
					targets[i] = alert.New(model.Alert{Labels: model.LabelSet{"instance": model.LabelValue(fmt.Sprint(i)), "alertname": "RepresentativeChild", "severity": "warning"}, Annotations: model.LabelSet{"summary": model.LabelValue(strings.Repeat("s", 256))}, StartsAt: base.StartsAt, EndsAt: base.EndsAt}, time.Now(), false)
				}
				if mode == "disabled" {
					r.core.interest.Store(0)
				}
				if mode == "repeat" || mode == "refresh" {
					for _, target := range targets {
						observe(r, source, target, rule)
						<-r.core.events
					}
					if mode == "refresh" {
						for k := range r.core.admissions.recent {
							r.core.admissions.recent[k] = time.Now().Add(-ObservationRefresh)
						}
					}
				}
				times := make([]int64, 0, size)
				start := time.Now()
				maxQueue := 0
				for _, target := range targets {
					begin := time.Now()
					r.RecordInhibition(ctx, rule, source, target, source.Fingerprint(), target.Fingerprint())
					times = append(times, time.Since(begin).Nanoseconds())
					maxQueue = max(maxQueue, len(r.core.events))
				}
				elapsed := time.Since(start)
				slices.Sort(times)
				drops := r.core.observation.dropped.Load()
				admitted := r.core.observation.admitted.Load()
				t.Logf("n=%d mode=%s throughput=%.0f/s p95=%dns p99=%dns max_queue=%d first_pass_admitted=%d dropped=%d", size, mode, float64(size)/elapsed.Seconds(), times[size*95/100], times[size*99/100], maxQueue, admitted, drops)
				// Controlled sufficient capacity: drain each accepted event and retry every target.
				for len(r.core.events) > 0 {
					<-r.core.events
				}
				if mode == "cold" || mode == "refresh" {
					before := r.core.observation.admitted.Load()
					for _, target := range targets {
						if observe(r, source, target, rule) {
							<-r.core.events
						}
					}
					require.Equal(t, uint64(size), uint64(maxQueue)+r.core.observation.admitted.Load()-before, "failed first enqueues retry; admitted repeats are suppressed")
				}
			})
		}
	}
}

func TestObservationCredentialNeverFollowsRedirect(t *testing.T) {
	t.Parallel()
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(r.Header.Get(ObservationKeyHeader) != "")
		w.WriteHeader(204)
	}))
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	cfg := observationConfig(t, redirect.URL).WebhookOutputs[0]
	wo, err := NewWebhookOutput(cfg, newMetrics(nil).outputDrops, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	defer wo.Close()
	require.Error(t, wo.post([]byte("[]")))
	require.False(t, leaked.Load())
}

func TestObservationUnknownOccurrenceNeverDeduplicates(t *testing.T) {
	t.Parallel()
	source, target, rule := observationFixture()
	source.StartsAt = time.Time{}
	rec := queueRecorder(2)
	require.True(t, observe(rec, source, target, rule))
	require.True(t, observe(rec, source, target, rule))
	require.Empty(t, rec.core.admissions.recent)
}

func TestObservationOversizedEncodedEventAndOutputQueueFull(t *testing.T) {
	t.Parallel()
	source, target, rule := observationFixture()
	rec := queueRecorder(1)
	require.True(t, observe(rec, source, target, rule))
	event := (<-rec.core.events).event
	// Pause the output by constructing its bounded queue without worker goroutines.
	wo := &WebhookOutput{name: "webhook:test", work: make(chan []byte, 1), observationKey: "key", eventTypes: []string{"inhibition_muted_alert"}, drops: newMetrics(nil).outputDrops.WithLabelValues("webhook:test"), logger: slog.New(slog.DiscardHandler)}
	_, err := wo.SendEvent(event)
	require.NoError(t, err)
	_, err = wo.SendEvent(event)
	require.NoError(t, err)
	require.Equal(t, uint64(1), wo.health.dropped.Load())
	event.message.Data.GetInhibitionMutedAlert().Observation.RuleName = strings.Repeat("x", observationMaxEventBytes)
	_, err = wo.SendEvent(event)
	require.ErrorContains(t, err, "byte budget")
	require.Equal(t, uint64(2), wo.health.dropped.Load())
}

type observationHealthTransport func(*http.Request) (*http.Response, error)

func (f observationHealthTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestObservationCaptureRecoveryStableAndDegradationPrecedence(t *testing.T) {
	for _, scenario := range []string{"sustained_success", "unpolled_success", "quiet_recovery", "new_output_failure", "new_capture_loss"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := observationConfig(t, "http://test.invalid")
				cfg.WebhookOutputs[0].MaxRetries = 1
				rec := NewRecorderFromConfig(cfg, "test", nil, nil)
				rec.SetObservationOptions(true, true)
				defer rec.Close()
				wo := rec.core.observationOutput.Load()
				statusCode := http.StatusNoContent
				wo.client.Transport = observationHealthTransport(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: statusCode, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
				})
				receipt := func() {
					data := fmt.Sprintf(`[{"@timestamp":%q}]`, time.Now().UTC().Format(time.RFC3339Nano))
					wo.postWithRetry([]byte(data))
				}
				rec.core.dropObservation()
				require.Equal(t, "degraded", rec.ObservationStatus()["state"])
				time.Sleep(time.Second)
				recoveredAt := time.Now()
				receipt()
				if scenario != "unpolled_success" {
					require.Equal(t, "recovering", rec.ObservationStatus()["state"])
					require.Equal(t, healthTime(recoveredAt.UnixNano()), rec.ObservationStatus()["recovered_at"])
				}
				switch scenario {
				case "sustained_success", "unpolled_success":
					for range 4 {
						time.Sleep(10 * time.Second)
						receipt()
					}
					status := rec.ObservationStatus()
					require.Equal(t, "healthy", status["state"], "new receipts must not restart capture recovery")
					require.Equal(t, healthTime(recoveredAt.UnixNano()), status["recovered_at"])
				case "quiet_recovery":
					time.Sleep(31 * time.Second)
					status := rec.ObservationStatus()
					require.Equal(t, "healthy", status["state"])
					require.Equal(t, healthTime(recoveredAt.UnixNano()), status["recovered_at"], "recovery timestamp persists after recovery window")
					time.Sleep(31 * time.Second)
					status = rec.ObservationStatus()
					require.Equal(t, "unknown", status["state"])
					require.Equal(t, healthTime(recoveredAt.UnixNano()), status["recovered_at"])
				case "new_capture_loss":
					time.Sleep(time.Second)
					rec.core.dropObservation()
					status := rec.ObservationStatus()
					require.Equal(t, "degraded", status["state"])
					require.Equal(t, healthTime(recoveredAt.UnixNano()), status["recovered_at"])
					time.Sleep(time.Second)
					secondRecovery := time.Now()
					receipt()
					status = rec.ObservationStatus()
					require.Equal(t, "recovering", status["state"])
					require.Equal(t, healthTime(secondRecovery.UnixNano()), status["recovered_at"])
				case "new_output_failure":
					time.Sleep(time.Second)
					statusCode = http.StatusServiceUnavailable
					receipt()
					status := rec.ObservationStatus()
					require.Equal(t, "degraded", status["state"], "active output failure takes precedence over previous capture recovery")
					require.Equal(t, healthTime(recoveredAt.UnixNano()), status["recovered_at"])
					require.Equal(t, healthTime(time.Now().UnixNano()), status["problem_since"])
					require.Equal(t, healthTime(recoveredAt.UnixNano()), status["last_successful_receipt"])
					time.Sleep(time.Second)
					statusCode = http.StatusNoContent
					outputRecovery := time.Now()
					receipt()
					status = rec.ObservationStatus()
					require.Equal(t, "recovering", status["state"])
					require.Equal(t, healthTime(outputRecovery.UnixNano()), status["recovered_at"])
				}
			})
		})
	}
}

func TestObservationCaptureDropDoesNotWaitForOutputHealth(t *testing.T) {
	t.Parallel()
	rec := queueRecorder(1)
	rec.core.events <- writeRequest{}
	output := &WebhookOutput{}
	rec.core.observationOutput.Store(output)
	output.health.mu.Lock()
	defer output.health.mu.Unlock()
	source, target, rule := observationFixture()
	done := make(chan bool, 1)
	go func() { done <- observe(rec, source, target, rule) }()
	select {
	case admitted := <-done:
		require.False(t, admitted)
	case <-time.After(time.Second):
		t.Fatal("alert thread waited for output health mutex")
	}
}

// Existing interested outputs share the bounded first-plus-refresh observation cadence.
func TestObservationExistingOutputCadenceCompatibility(t *testing.T) {
	t.Parallel()
	source, target, rule := observationFixture()
	target.Labels = model.LabelSet{}
	for i := range 40 {
		target.Labels[model.LabelName(fmt.Sprintf("label_%02d", i))] = "value"
	}
	r := queueRecorder(4)
	existing := newMockDestination("existing-output")
	r.core.setOutputs([]Destination{existing})
	require.True(t, observe(r, source, target, rule))
	require.False(t, observe(r, source, target, rule))
	first := <-r.core.events
	event := first.event.message.GetData().GetInhibitionMutedAlert()
	require.Len(t, event.MutedAlert.Labels, 32)
	require.True(t, event.Observation.Target.LabelsTruncated)
	r.core.marshalAndSend(first, []Destination{existing})
	for key := range r.core.admissions.recent {
		r.core.admissions.recent[key] = time.Now().Add(-ObservationRefresh)
	}
	require.True(t, observe(r, source, target, rule))
	require.Equal(t, 10*time.Minute, ObservationRefresh)
	r.core.marshalAndSend(<-r.core.events, []Destination{existing})
	require.Equal(t, 2, existing.eventCount())
}
