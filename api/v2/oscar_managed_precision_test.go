package v2

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/api/v2/models"
)

func TestManagedNativePairPrecision(t *testing.T) {
	for _, fraction := range []string{"123456789", "123456", "123"} {
		stamp := "2026-11-18T14:30:01." + fraction + "Z"
		var posts models.PostableAlerts
		if err := json.Unmarshal([]byte(`[{"labels":{"alertname":"fixture"},"startsAt":"`+stamp+`"}]`), &posts); err != nil {
			t.Fatal(err)
		}
		input := OpenAPIAlertsToAlerts(context.Background(), posts)[0]
		want, _ := time.Parse(time.RFC3339Nano, stamp)
		if !input.StartsAt.Equal(want) {
			t.Fatalf("native input %s: %s", stamp, input.StartsAt)
		}
		view := AlertToOpenAPIAlert(alert.New(input, want, false), alert.AlertStatus{}, nil, nil)
		raw, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		var read struct{ StartsAt string }
		if err = json.Unmarshal(raw, &read); err != nil {
			t.Fatal(err)
		}
		if read.StartsAt != "2026-11-18T14:30:01.123Z" {
			t.Fatalf("native API read %s: %s", stamp, read.StartsAt)
		}
	}
}

func TestManagedSameMillisNativePairs(t *testing.T) {
	path := os.Getenv("TL1_PAIR_NATIVE_INPUT")
	if path == "" {
		path = "testdata/managed_same_millisecond.json"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var posts models.PostableAlerts
	if err = json.Unmarshal(raw, &posts); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	pairs := [][2]string{}
	for _, input := range OpenAPIAlertsToAlerts(context.Background(), posts) {
		a := alert.New(input, input.StartsAt, false)
		view := AlertToOpenAPIAlert(a, alert.AlertStatus{}, nil, nil)
		fp := *view.Fingerprint
		if seen[fp] {
			t.Fatal("episodes/clear share fingerprint")
		}
		seen[fp] = true
		pairs = append(pairs, [2]string{fp, view.StartsAt.String()})
		if view.StartsAt.String() != "2026-11-18T14:30:01.123Z" {
			t.Fatal("native start mismatch")
		}
	}
	if len(pairs) != 3 {
		t.Fatal("three native pairs required")
	}
	if output := os.Getenv("TL1_PAIR_HISTORY_INPUT"); output != "" {
		raw, err = json.Marshal(pairs)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(output, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
