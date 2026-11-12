package inhibit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	common "github.com/prometheus/alertmanager/config/common"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/marker"
	"github.com/prometheus/alertmanager/pkg/labels"
)

func TestObservationNativeDecisionParityAndSelectedOccurrence(t *testing.T) {
	t.Parallel()
	bodies := make(chan []byte, 10)
	var failing atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		if failing.Load() {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	key := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0o600))
	cfg, err := eventrecorder.FixedObservationConfig(eventrecorder.Config{}, eventrecorder.ObservationOptions{Enabled: true, URL: server.URL, KeyFile: key})
	require.NoError(t, err)
	rec := eventrecorder.NewRecorderFromConfig(cfg, "instance", nil, nil)
	defer rec.Close()
	rec.SetObservationOptions(true, true)
	sourceMatch, err := labels.NewMatcher(labels.MatchEqual, "role", "source")
	require.NoError(t, err)
	targetMatch, err := labels.NewMatcher(labels.MatchEqual, "role", "target")
	require.NoError(t, err)
	rules := []common.InhibitRule{{Name: "oscar-inh-111-r1", SourceMatchers: common.Matchers{sourceMatch}, TargetMatchers: common.Matchers{targetMatch}}}
	makeInhibitor := func() *Inhibitor { return NewInhibitor(nil, rules, nopLogger, rec) }
	ih := makeInhibitor()
	now := time.Now().UTC()
	source := alert.New(model.Alert{Labels: model.LabelSet{"role": "source"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}, now, false)
	target := alert.New(model.Alert{Labels: model.LabelSet{"role": "target"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(-time.Second)}, now, false)
	ih.processAlert(context.Background(), source)
	ctx := eventrecorder.WithEventRecording(context.Background())
	require.True(t, ih.Mutes(ctx, target.LabelSet()), "API label-only path retains inhibition but records nothing")
	select {
	case <-bodies:
		t.Fatal("API read recorded an observation")
	case <-time.After(120 * time.Millisecond):
	}
	m := marker.NewAlertMarker()
	ctx = marker.WithContext(ctx, m)
	require.True(t, ih.MutesAlert(ctx, target), "resolved target is still inhibited")
	read := func() map[string]any {
		select {
		case body := <-bodies:
			var batch []map[string]any
			require.NoError(t, json.Unmarshal(body, &batch))
			return batch[0]["data"].(map[string]any)["inhibitionMutedAlert"].(map[string]any)["observation"].(map[string]any)
		case <-time.After(time.Second):
			t.Fatal("no first observation")
			return nil
		}
	}
	observed := read()
	require.Equal(t, "external", observed["ruleOrigin"], "reserved-looking base names stay external")
	s := observed["source"].(map[string]any)
	require.Equal(t, m.Status(target.Fingerprint()).InhibitedBy[0], s["fingerprint"])
	parsedStart, err := time.Parse(time.RFC3339Nano, s["startsAt"].(string))
	require.NoError(t, err)
	require.Equal(t, source.StartsAt, parsedStart)
	require.True(t, ih.MutesAlert(ctx, target))
	rebuilt := makeInhibitor()
	rebuilt.processAlert(ctx, source)
	require.True(t, rebuilt.MutesAlert(ctx, target))
	select {
	case <-bodies:
		t.Fatal("rebuild lost admission cache")
	case <-time.After(120 * time.Millisecond):
	}
	// Updating the same source fingerprint with another occurrence must retain that exact selected occurrence.
	recurrence := alert.New(model.Alert{Labels: source.Labels, StartsAt: now.Add(-time.Second), EndsAt: now.Add(time.Hour)}, now, false)
	rebuilt.processAlert(ctx, recurrence)
	require.True(t, rebuilt.MutesAlert(ctx, target))
	next := read()
	parsedStart, err = time.Parse(time.RFC3339Nano, next["source"].(map[string]any)["startsAt"].(string))
	require.NoError(t, err)
	require.Equal(t, recurrence.StartsAt, parsedStart)
	rules[0].ManagedOrigin = true
	managed := makeInhibitor()
	managed.processAlert(ctx, recurrence)
	require.True(t, managed.MutesAlert(ctx, target))
	managedObservation := read()
	require.Equal(t, "managed", managedObservation["ruleOrigin"])
	require.NotEqual(t, next["ruleIdentity"], managedObservation["ruleIdentity"])
	failing.Store(true)
	newTarget := alert.New(model.Alert{Labels: target.Labels, StartsAt: target.StartsAt.Add(time.Nanosecond), EndsAt: target.EndsAt}, now, false)
	begin := time.Now()
	require.True(t, managed.MutesAlert(ctx, newTarget))
	require.Less(t, time.Since(begin), time.Second, "native decision must not wait for HTTP retry budget")
	require.Eventually(t, func() bool { return rec.ObservationStatus()["output_failures"].(uint64) > 0 }, 3*time.Second, 10*time.Millisecond)
	require.True(t, managed.MutesAlert(ctx, newTarget))
	// Recording loss and receiver failure cannot change decisions or inhibit the source itself.
	require.False(t, rebuilt.MutesAlert(ctx, source))
	disabled := NewInhibitor(nil, rules, nopLogger, eventrecorder.NopRecorder())
	disabled.processAlert(ctx, recurrence)
	require.True(t, disabled.MutesAlert(ctx, target))
}
