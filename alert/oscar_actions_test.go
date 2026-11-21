package alert

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

func TestOscarActionWire(t *testing.T) {
	t.Parallel()
	fixture, err := os.ReadFile("../api/v2/testdata/oscar_actions_v1.json")
	require.NoError(t, err)
	var vector struct {
		Body     string
		Receiver string `json:"receiver_id"`
		TestKey  string `json:"test_key"`
		Headers  map[string]string
	}
	require.NoError(t, json.Unmarshal(fixture, &vector))
	var batch struct {
		Members []NativeDeliveryMember `json:"oscarNativeDeliveries"`
	}
	require.NoError(t, json.Unmarshal([]byte(vector.Body), &batch))
	require.Len(t, batch.Members, 2)
	for i, member := range batch.Members {
		require.Equal(t, i, member.Index)
		require.NoError(t, member.Delivery.Validate(vector.Receiver))
	}
	first, second := batch.Members[0].Delivery, batch.Members[1].Delivery
	require.Equal(t, first.NativeVariant.Fingerprint, second.NativeVariant.Fingerprint)
	require.NotEqual(t, first.NativeVariant.StartsAt, second.NativeVariant.StartsAt)
	headers, err := NativeDeliveryHeaders([]byte(vector.Body), vector.Receiver, NativeCallbackPath, []byte(vector.TestKey))
	require.NoError(t, err)
	require.Equal(t, vector.Headers, headers)
	second.TargetScope = append(second.TargetScope, second.TargetScope[0])
	require.Error(t, second.Validate(vector.Receiver))
}

func TestOscarActionDispatchView(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 11, 21, 12, 0, 0, 123456789, time.UTC)
	source := New(model.Alert{Labels: model.LabelSet{"alertname": "disk", "severity": "major"}, StartsAt: start}, start, false)
	fingerprint := source.Fingerprint()
	ref := EpisodeRef{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1, 2}
	view, err := BuildDispatchView(source, ref, "critical", 3)
	require.NoError(t, err)
	require.Equal(t, ref, view.EpisodeRef)
	require.Equal(t, fingerprint.String(), view.NativeVariant.Fingerprint)
	require.Equal(t, start.Format(time.RFC3339Nano), view.NativeVariant.StartsAt)
	require.Equal(t, model.LabelValue("critical"), view.EffectiveLabels["severity"])
	view.EffectiveLabels["alertname"] = "changed"
	require.Equal(t, model.LabelSet{"alertname": "disk", "severity": "major"}, source.Labels)
	require.Equal(t, fingerprint, source.Fingerprint())
	require.Equal(t, fingerprint, source.Labels.Fingerprint())
	for _, invalid := range []string{"cleared", "resolved", "invented", "minor"} {
		_, err = BuildDispatchView(source, ref, invalid, 3)
		require.Error(t, err)
	}
}

func TestOscarActionManagedClearWire(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../api/v2/testdata/oscar_actions_managed_clear_v1.json")
	require.NoError(t, err)
	var fixture struct {
		Body       string
		TestKey    string `json:"test_key"`
		ReceiverID string `json:"receiver_id"`
		Headers    map[string]string
	}
	require.NoError(t, json.Unmarshal(raw, &fixture))
	var msg struct {
		Alerts  []struct{ Status string }
		Members []NativeDeliveryMember `json:"oscarNativeDeliveries"`
	}
	require.NoError(t, json.Unmarshal([]byte(fixture.Body), &msg))
	require.Equal(t, "firing", msg.Alerts[0].Status)
	require.Equal(t, "resolved", msg.Members[0].Delivery.State)
	headers, err := NativeDeliveryHeaders([]byte(fixture.Body), fixture.ReceiverID, NativeCallbackPath, []byte(fixture.TestKey))
	require.NoError(t, err)
	require.Equal(t, fixture.Headers, headers)
}
