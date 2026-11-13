package v2

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	model "github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v2"

	"github.com/prometheus/alertmanager/alert"
)

func TestOscarOccurrencePrecisionSerialization(t *testing.T) {
	t.Parallel()
	var records []json.RawMessage
	for i, name := range []string{"Root", "Target", "Target"} {
		raw := "2026-11-12T11:00:00.123456789Z"
		if i == 2 {
			raw = "2026-11-12T11:00:00.123456788Z"
		}
		starts, err := time.Parse(time.RFC3339Nano, raw)
		require.NoError(t, err)
		source := alert.New(model.Alert{Labels: model.LabelSet{"alertname": model.LabelValue(name)},
			StartsAt: starts, EndsAt: starts.Add(time.Hour)}, starts.Add(time.Second), false)
		encoded, err := json.Marshal(AlertToOpenAPIAlert(source, alert.AlertStatus{State: alert.AlertStateActive}, []string{"default"}, nil))
		require.NoError(t, err)
		var record map[string]any
		require.NoError(t, json.Unmarshal(encoded, &record))
		require.Equal(t, raw, record["startsAtRaw"])
		require.Equal(t, "2026-11-12T11:00:00.123Z", record["startsAt"])
		records = append(records, encoded)
	}
	encoded, err := json.Marshal(records)
	require.NoError(t, err)
	fixture, err := os.ReadFile("testdata/native_occurrence_precision.json")
	require.NoError(t, err)
	require.JSONEq(t, string(fixture), string(encoded))
}

func TestOscarInhibitionStructuredErrorSchemas(t *testing.T) {
	t.Parallel()
	source, err := os.ReadFile("openapi.yaml")
	require.NoError(t, err)
	var spec map[string]any
	require.NoError(t, yaml.Unmarshal(source, &spec))
	paths := spec["paths"].(map[any]any)

	for path, codes := range map[string][]string{"/oscar/inhibition/status": {"403", "503"}, "/oscar/inhibition/validate": {"403", "413"}} {
		method := "get"
		if path == "/oscar/inhibition/validate" {
			method = "post"
		}
		for _, code := range codes {
			operation := paths[path].(map[any]any)[method].(map[any]any)
			response := operation["responses"].(map[any]any)[code].(map[any]any)
			require.Equal(t, "#/definitions/oscarInhibitionError", response["schema"].(map[any]any)["$ref"])
		}
	}
}
