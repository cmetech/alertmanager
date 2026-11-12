package eventrecorder

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/prometheus/common/model"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/prometheus/alertmanager/alert"
	common "github.com/prometheus/alertmanager/config/common"
	events "github.com/prometheus/alertmanager/eventrecorder/events/v2"
	"github.com/prometheus/alertmanager/pkg/labels"
)

const (
	ObservationOutputName    = "oscar-native-inhibition"
	ObservationKeyHeader     = "X-Oscar-Inhibition-Observation-Key"
	ObservationRefresh       = 10 * time.Minute
	ObservationResidence     = 30 * time.Second
	observationCacheSize     = 65536
	observationMaxEventBytes = 64 << 10
	observationMaxBatchBytes = 256 << 10
)

// ObservationOptions are fixed process settings, never authored rule configuration.
type ObservationOptions struct {
	Enabled      bool
	URL, KeyFile string
}

// FixedObservationConfig installs the reserved, inhibition-only destination.
// Errors leave ordinary outputs available; runtime conflicts are rejected by the coordinator.
func FixedObservationConfig(cfg Config, opts ObservationOptions) (Config, error) {
	if !opts.Enabled {
		return cfg, nil
	}
	for _, w := range cfg.WebhookOutputs {
		if w.Name == ObservationOutputName {
			return cfg, errors.New("reserved inhibition observation output name")
		}
	}
	u, err := url.Parse(opts.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || len(opts.URL) > 2048 {
		return cfg, errors.New("invalid fixed inhibition observation URL")
	}
	f, err := os.Open(opts.KeyFile)
	if err != nil {
		return cfg, errors.New("inhibition observation key unavailable")
	}
	defer f.Close()
	keyBytes, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(keyBytes) > 4096 {
		return cfg, errors.New("invalid inhibition observation key")
	}
	key := strings.TrimSpace(string(keyBytes))
	if len(key) < 32 || strings.ContainsAny(key, "\r\n") {
		return cfg, errors.New("invalid inhibition observation key")
	}
	cfg.WebhookOutputs = append(slices.Clone(cfg.WebhookOutputs), WebhookOutputConfig{Name: ObservationOutputName, URL: &common.SecretURL{URL: u}, Timeout: model.Duration(2 * time.Second), Workers: 2, MaxRetries: 3, RetryBackoff: model.Duration(500 * time.Millisecond), Batch: true, BatchMaxEvents: 100, BatchMaxBytes: observationMaxBatchBytes, BatchFlushInterval: model.Duration(100 * time.Millisecond), EventTypes: []string{"inhibition_muted_alert"}, observationKey: key})
	return cfg, nil
}

// IsManagedObservationOutput identifies the private service-configured sink.
func IsManagedObservationOutput(cfg WebhookOutputConfig) bool {
	return cfg.Name == ObservationOutputName && cfg.observationKey != ""
}

// ObservationRule is a bounded immutable display snapshot plus full-definition identity.
type ObservationRule struct {
	identity, name, origin string
	snapshot               *events.InhibitRule
	truncated              bool
}

// NewObservationRule hashes the complete effective rule once, before bounded copying.
func NewObservationRule(name string, source, target labels.Matchers, equal map[model.LabelName]struct{}, managed ...bool) ObservationRule {
	origin := "external"
	if len(managed) > 0 && managed[0] {
		origin = "managed"
	}
	src, tgt := make([]string, 0, len(source)), make([]string, 0, len(target))
	eq := make([]string, 0, len(equal))
	for _, m := range source {
		src = append(src, m.String())
	}
	for _, m := range target {
		tgt = append(tgt, m.String())
	}
	for k := range equal {
		eq = append(eq, string(k))
	}
	slices.Sort(src)
	slices.Sort(tgt)
	slices.Sort(eq)
	raw, _ := json.Marshal(struct {
		Name                  string
		Source, Target, Equal []string
		Origin                string
	}{name, src, tgt, eq, origin})
	digest := sha256.Sum256(raw)
	r := ObservationRule{identity: hex.EncodeToString(digest[:]), name: boundedString(name, 256), origin: origin}
	r.truncated = len(name) > 256
	budget := 4096
	snapshot := &events.InhibitRule{Name: r.name}
	copyMatchers := func(ms labels.Matchers) []*events.Matcher {
		result := make([]*events.Matcher, 0, min(len(ms), 20))
		for i, m := range ms {
			if i >= 20 || len(m.Name) > 256 || len(m.Value) > 1024 || len(m.Name)+len(m.Value) > budget {
				r.truncated = true
				break
			}
			budget -= len(m.Name) + len(m.Value)
			result = append(result, &events.Matcher{Type: matcherTypeToEvents(m.Type), Name: strings.Clone(m.Name), Pattern: strings.Clone(m.Value)})
		}
		return result
	}
	snapshot.SourceMatchers = copyMatchers(source)
	snapshot.TargetMatchers = copyMatchers(target)
	for i, k := range eq {
		if i >= 20 || len(k) > 256 || len(k) > budget {
			r.truncated = true
			break
		}
		budget -= len(k)
		snapshot.EqualLabels = append(snapshot.EqualLabels, strings.Clone(k))
	}
	r.snapshot = snapshot
	return r
}

func boundedString(s string, max int) string {
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return strings.Clone(s)
}

func boundedLabels(ls model.LabelSet) (map[string]string, bool) {
	result := make(map[string]string, min(len(ls), 32))
	budget := 4096
	visited := 0
	truncated := false
	for k, v := range ls {
		if visited >= 32 {
			truncated = true
			break
		}
		visited++
		if len(k) > 256 || len(v) > 1024 || len(k)+len(v) > budget {
			truncated = true
			continue
		}
		budget -= len(k) + len(v)
		result[strings.Clone(string(k))] = strings.Clone(string(v))
	}
	return result, truncated
}

func observedOccurrence(a *alert.Alert, fp model.Fingerprint) *events.ObservedOccurrence {
	ls, lt := boundedLabels(a.Labels)
	as, at := boundedLabels(a.Annotations)
	return &events.ObservedOccurrence{Fingerprint: fp.String(), StartsAt: timestamppb.New(a.StartsAt), EndsAt: timestamppb.New(a.OccurrenceEndsAt()), Labels: ls, Annotations: as, LabelsTruncated: lt, AnnotationsTruncated: at, IdentityAvailable: !a.StartsAt.IsZero()}
}

type admissionKey struct {
	source, target           model.Fingerprint
	sourceStart, targetStart time.Time
	rule                     string
}
type admissionCache struct {
	mu     sync.Mutex
	recent map[admissionKey]time.Time
}
type observationCounters struct {
	admitted, dropped, suppressed, bypassed atomic.Uint64
	lastDrop, problem                       atomic.Int64
	recovery                                atomic.Pointer[captureRecovery]
}

// captureRecovery identifies one completed capture-loss episode. The original
// receipt is retained across later successes and status polls.
type captureRecovery struct{ drop, at int64 }

// recordObservationReceipt runs on the HTTP worker, serialized with output health.
// Alert threads only update atomic drop signals and never wait for this transition.
func (c *sharedRecorder) recordObservationReceipt(receipt int64) {
	lastDrop := c.observation.lastDrop.Load()
	previous := c.observation.recovery.Load()
	if lastDrop == 0 || receipt <= lastDrop || previous != nil && previous.drop >= lastDrop {
		return
	}
	c.observation.recovery.CompareAndSwap(previous, &captureRecovery{drop: lastDrop, at: receipt})
}

func (c *sharedRecorder) dropObservation() {
	now := time.Now().UnixNano()
	previous := c.observation.lastDrop.Swap(now)
	c.observation.dropped.Add(1)
	var receipt int64
	if out := c.observationOutput.Load(); out != nil {
		receipt = out.health.success.Load()
	}
	if previous <= receipt {
		c.observation.problem.Store(now)
	} else {
		c.observation.problem.CompareAndSwap(0, now)
	}
}

// RecordInhibition observes an already-made decision. No alert pointer escapes the call.
func (r Recorder) RecordInhibition(ctx context.Context, rule ObservationRule, source, target *alert.Alert, sourceFP, targetFP model.Fingerprint) bool {
	if !r.Interested(ctx, "inhibition_muted_alert") || source == nil || target == nil {
		return false
	}
	now := time.Now()
	key := admissionKey{sourceFP, targetFP, source.StartsAt.UTC().Round(0), target.StartsAt.UTC().Round(0), rule.identity}
	cache := &r.core.admissions
	locked := !source.StartsAt.IsZero() && !target.StartsAt.IsZero() && cache.mu.TryLock()
	if locked {
		defer cache.mu.Unlock()
		if last, ok := cache.recent[key]; ok && now.Sub(last) < ObservationRefresh {
			r.core.observation.suppressed.Add(1)
			return false
		}
	} else {
		r.core.observation.bypassed.Add(1)
	}
	// Reserve queue capacity cheaply before bounded snapshots; failed enqueue is never admitted.
	if len(r.core.events) == cap(r.core.events) {
		r.core.dropObservation()
		r.core.metrics.eventsDropped.WithLabelValues("inhibition_muted_alert").Inc()
		return false
	}
	for _, ts := range [...]time.Time{source.StartsAt, source.OccurrenceEndsAt(), target.StartsAt, target.OccurrenceEndsAt()} {
		if year := ts.Year(); year < 1 || year > 9999 {
			r.core.dropObservation()
			return false
		}
	}
	sourceSnapshot, targetSnapshot := observedOccurrence(source, sourceFP), observedOccurrence(target, targetFP)
	data := newEventData("inhibition_muted_alert", &events.EventData{EventType: &events.EventData_InhibitionMutedAlert{InhibitionMutedAlert: &events.InhibitionMutedAlertEvent{
		InhibitRules:           []*events.InhibitRule{rule.snapshot},
		MutedAlert:             &events.MutedAlert{Fingerprint: uint64(targetFP), Labels: targetSnapshot.Labels},
		InhibitingFingerprints: []uint64{uint64(sourceFP)},
		Observation:            &events.InhibitionObservation{SchemaVersion: 1, RuleOrigin: rule.origin, RuntimeEpoch: r.core.runtimeEpoch, RuleIdentity: rule.identity, RuleName: rule.name, RuleSnapshot: rule.snapshot, RuleSnapshotTruncated: rule.truncated, Source: sourceSnapshot, Target: targetSnapshot},
	}}})
	if !r.enqueue(data, now) {
		r.core.dropObservation()
		return false
	}
	r.core.observation.admitted.Add(1)
	if locked {
		if cache.recent == nil {
			cache.recent = make(map[admissionKey]time.Time)
		}
		if _, exists := cache.recent[key]; exists || len(cache.recent) < observationCacheSize {
			cache.recent[key] = now
		} else { // Constant bounded maintenance; saturation bypasses suppression.
			for old, last := range cache.recent {
				if now.Sub(last) >= ObservationRefresh {
					delete(cache.recent, old)
				}
				break
			}
			r.core.observation.bypassed.Add(1)
		}
	}
	return true
}

func newRuntimeEpoch() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ObservationStatus reports actual initialization/interest and transport signals.
func (r Recorder) ObservationStatus() map[string]any {
	result := map[string]any{"supported": true, "flag_enabled": false, "sink_configured": false, "sink_initialized": false, "interest_active": false, "state": "not_enabled"}
	if r.core == nil {
		return result
	}
	c := r.core
	result["flag_enabled"] = c.observationEnabled
	result["sink_configured"] = c.observationConfigured
	if !c.observationEnabled {
		return result
	}
	result["state"] = "degraded"
	result["problem_since"] = healthTime(c.observationStarted)
	result["admitted"] = c.observation.admitted.Load()
	result["capture_drops"] = c.observation.dropped.Load()
	result["suppressed_repeats"] = c.observation.suppressed.Load()
	result["cache_bypasses"] = c.observation.bypassed.Load()
	result["queue_length"] = len(c.events)
	result["runtime_epoch"] = c.runtimeEpoch
	wo := c.observationOutput.Load()
	if wo == nil {
		return result
	}
	result["sink_initialized"] = true
	result["interest_active"] = c.interest.Load()&interestInhibition != 0
	// Snapshot each signal once. The output mutex serializes transport transitions
	// and capture recovery; native drop publication remains lock-free.
	wo.health.mu.Lock()
	outputDrops, outputFailures := wo.health.dropped.Load(), wo.health.failures.Load()
	receipt, outputProblem, outputRecovered := wo.health.success.Load(), wo.health.problem.Load(), wo.health.recovered.Load()
	captureRecovered := c.observation.recovery.Load()
	lastCaptureDrop, captureProblem := c.observation.lastDrop.Load(), c.observation.problem.Load()
	wo.health.mu.Unlock()
	now := time.Now()
	recovered := outputRecovered
	if captureRecovered != nil {
		recovered = max(recovered, captureRecovered.at)
	}
	problem := outputProblem
	if lastCaptureDrop > 0 && (captureRecovered == nil || captureRecovered.drop < lastCaptureDrop) {
		if captureProblem == 0 {
			captureProblem = lastCaptureDrop
		}
		if problem == 0 || captureProblem < problem {
			problem = captureProblem
		}
	}
	result["output_drops"] = outputDrops
	result["output_failures"] = outputFailures
	result["last_successful_receipt"] = healthTime(receipt)
	result["problem_since"] = healthTime(problem)
	result["recovered_at"] = healthTime(recovered)
	switch {
	case problem != 0:
		result["state"] = "degraded"
	case receipt == 0 || now.Sub(time.Unix(0, receipt)) > 2*ObservationResidence:
		result["state"] = "unknown"
	case recovered > 0 && now.Sub(time.Unix(0, recovered)) < ObservationResidence:
		result["state"] = "recovering"
	default:
		result["state"] = "healthy"
	}
	return result
}

func healthTime(n int64) any {
	if n == 0 {
		return nil
	}
	return time.Unix(0, n).UTC().Format(time.RFC3339Nano)
}
