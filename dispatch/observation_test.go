package dispatch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	common "github.com/prometheus/alertmanager/config/common"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/featurecontrol"
	"github.com/prometheus/alertmanager/inhibit"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/pkg/labels"
	"github.com/prometheus/alertmanager/provider/mem"
)

func TestObservationDispatchPreservesRawOccurrenceEnds(t *testing.T) {
	t.Parallel()
	bodies := make(chan []byte, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			bodies <- body
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	key := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0o600))
	cfg, err := eventrecorder.FixedObservationConfig(eventrecorder.Config{}, eventrecorder.ObservationOptions{Enabled: true, URL: server.URL, KeyFile: key})
	require.NoError(t, err)
	rec := eventrecorder.NewRecorderFromConfig(cfg, "test", nil, nil)
	defer rec.Close()
	logger := promslog.NewNopLogger()
	provider, err := mem.NewAlerts(context.Background(), time.Hour, 0, nil, logger, eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	defer provider.Close()
	now := time.Now().UTC()
	makeAlert := func(role, state string, end time.Time) *alert.Alert {
		return alert.New(model.Alert{Labels: model.LabelSet{"role": model.LabelValue(role), "state": model.LabelValue(state)}, StartsAt: now.Add(-time.Hour), EndsAt: end}, now, false)
	}
	source := makeAlert("source", "firing", now.Add(2*time.Hour))
	firing := makeAlert("target", "firing", now.Add(time.Hour))
	resolved := makeAlert("target", "resolved", now.Add(-time.Minute))
	require.NoError(t, provider.Put(context.Background(), source))
	sourceMatch, err := labels.NewMatcher(labels.MatchEqual, "role", "source")
	require.NoError(t, err)
	targetMatch, err := labels.NewMatcher(labels.MatchEqual, "role", "target")
	require.NoError(t, err)
	inhibitor := inhibit.NewInhibitor(provider, []common.InhibitRule{{Name: "raw-occurrence", SourceMatchers: common.Matchers{sourceMatch}, TargetMatchers: common.Matchers{targetMatch}}}, logger, rec)
	done := make(chan struct{})
	go func() { inhibitor.Run(); close(done) }()
	inhibitor.WaitForLoading()
	defer func() { inhibitor.Stop(); <-done }()
	ctx := eventrecorder.WithEventRecording(context.Background())
	group := newAggrGroup(ctx, nil, &Route{RouteOpts: RouteOpts{Receiver: "test", GroupInterval: time.Minute}}, nil, rec, logger, nil)
	defer group.next.Stop()
	defer group.cancel()
	for _, a := range []*alert.Alert{source, firing, resolved} {
		group.insert(ctx, a)
	}
	stage := notify.NewMuteStage(inhibitor, notify.NewMetrics(prometheus.NewRegistry(), featurecontrol.NoopFlags{}))
	group.flush(func(alerts ...*alert.Alert) bool {
		require.Len(t, alerts, 3)
		for _, a := range alerts {
			if a.Fingerprint() == resolved.Fingerprint() {
				require.Equal(t, resolved.EndsAt, a.EndsAt)
			} else {
				require.True(t, a.EndsAt.IsZero(), "firing notification EndsAt remains cleared")
			}
		}
		_, delivered, err := stage.Exec(ctx, logger, alerts...)
		require.NoError(t, err)
		require.Len(t, delivered, 1)
		require.Equal(t, source.Fingerprint(), delivered[0].Fingerprint(), "parent remains normally deliverable")
		return true
	})
	require.Equal(t, now.Add(time.Hour), firing.EndsAt, "dispatch must not mutate stored occurrence")
	observed := map[string]struct {
		Fingerprint      string
		StartsAt, EndsAt time.Time
	}{}
	for len(observed) < 2 {
		select {
		case body := <-bodies:
			var batch []struct {
				Data struct {
					InhibitionMutedAlert struct {
						Observation struct {
							Source, Target struct {
								Fingerprint      string
								StartsAt, EndsAt time.Time
							}
						}
					}
				}
			}
			require.NoError(t, json.Unmarshal(body, &batch))
			for _, event := range batch {
				o := event.Data.InhibitionMutedAlert.Observation
				require.Equal(t, source.EndsAt, o.Source.EndsAt)
				observed[o.Target.Fingerprint] = o.Target
			}
		case <-time.After(3 * time.Second):
			t.Fatal("missing first dispatch inhibition observations")
		}
	}
	require.Equal(t, firing.StartsAt, observed[firing.Fingerprint().String()].StartsAt)
	require.Equal(t, firing.EndsAt, observed[firing.Fingerprint().String()].EndsAt, "firing target evidence retains raw stored EndsAt")
	require.Equal(t, resolved.EndsAt, observed[resolved.Fingerprint().String()].EndsAt, "resolved target evidence retains native EndsAt")
}
