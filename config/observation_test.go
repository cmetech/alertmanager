package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/eventrecorder"
)

func TestObservationFixedSinkSurvivesAllCoordinatorMerges(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0o600))
	fixed, err := eventrecorder.FixedObservationConfig(eventrecorder.Config{}, eventrecorder.ObservationOptions{Enabled: true, URL: "http://127.0.0.1:1/api/v1/alerts/internal/inhibition/observations", KeyFile: key})
	require.NoError(t, err)
	basePath := filepath.Join(dir, "base.yml")
	require.NoError(t, os.WriteFile(basePath, []byte("route:\n  receiver: default\nreceivers:\n- name: default\n"), 0o600))
	recorder := eventrecorder.NewRecorderFromConfig(fixed, "test", nil, nil)
	recorder.SetObservationOptions(true, true)
	defer recorder.Close()
	c := NewCoordinator(basePath, prometheus.NewRegistry(), slog.New(slog.DiscardHandler))
	c.ConfigureObservations(recorder, fixed, false)
	require.NoError(t, c.EnableManagedInhibition(filepath.Join(dir, "managed.json"), "test"))
	activations := 0
	c.Subscribe(func(conf *Config) error {
		activations++
		require.Len(t, conf.EventRecorder.WebhookOutputs, 1)
		require.True(t, eventrecorder.SameWebhookConfig(fixed.WebhookOutputs[0], conf.EventRecorder.WebhookOutputs[0]))
		recorder.ApplyConfig(conf.EventRecorder)
		return nil
	})
	require.NoError(t, c.Reload())
	require.NoError(t, c.Reload())
	require.Equal(t, 2, activations)
	require.Equal(t, true, c.ObservationStatus()["sink_initialized"])
	desired := ManagedInhibitionSet{Rules: []ManagedInhibitionRule{{Name: "oscar-inh-1-r1", SourceMatchers: []ManagedInhibitionMatcher{{Label: "severity", Operator: "=", Value: "critical"}}, TargetMatchers: []ManagedInhibitionMatcher{{Label: "severity", Operator: "=", Value: "warning"}}, Equal: []string{"site"}}}}
	_, err = c.ApplyManagedInhibition(c.ManagedInhibitionStatus().ETag, desired)
	require.NoError(t, err)
	require.Equal(t, 3, activations)
	require.True(t, c.config.InhibitRules[0].ManagedOrigin)

	// Reserved name conflicts reject the update without replacing the active config.
	conflict := "route:\n  receiver: default\nreceivers:\n- name: default\nevent_recorder:\n  webhook_outputs:\n  - name: oscar-native-inhibition\n    url: http://elsewhere.invalid\n"
	require.NoError(t, os.WriteFile(basePath, []byte(conflict), 0o600))
	require.ErrorContains(t, c.Reload(), "reserved inhibition observation output conflict")
	require.Equal(t, 3, activations)
}
