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

package v2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/require"

	models "github.com/prometheus/alertmanager/api/v2/models"
)

func TestOscarTimingUnavailableDatesAreOptional(t *testing.T) {
	alertTime := time.Now()
	state := "no_repeat_baseline"
	routeID, receiver, integration, interval := "r", "team", "webhook/0", "1h0m0s"
	step := &models.OscarRepeatSchedule{RouteID: &routeID, Receiver: &receiver, Integration: &integration, RepeatIntervalDuration: &interval, State: &state}
	stamp := strfmt.DateTime(alertTime)
	source, lookup := "sender_ends_at", "ready"
	meta := models.OscarAlertTiming{EndTimeSource: &source, RepeatLookupState: &lookup, RepeatSchedules: []*models.OscarRepeatSchedule{step}, TimingAsOf: &stamp}
	require.NoError(t, meta.Validate(strfmt.Default))
	b, err := json.Marshal(meta)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(b, &decoded))
	require.NotContains(t, decoded, "resolve_timeout_duration")
	schedules := decoded["repeat_schedules"].([]any)
	stepJSON := schedules[0].(map[string]any)
	require.NotContains(t, stepJSON, "next_repeat_eligible_at")
}

func TestOscarTimingModelsRejectUnknownStates(t *testing.T) {
	stamp := strfmt.DateTime(time.Now())
	source, lookup, bad := "typo", "ready", "typo"
	routeID, receiver, integration, interval := "r", "team", "webhook/0", "1h0m0s"
	step := &models.OscarRepeatSchedule{RouteID: &routeID, Receiver: &receiver, Integration: &integration, RepeatIntervalDuration: &interval, State: &bad}
	meta := models.OscarAlertTiming{EndTimeSource: &source, RepeatLookupState: &lookup, TimingAsOf: &stamp, RepeatSchedules: []*models.OscarRepeatSchedule{step}}
	require.Error(t, meta.Validate(strfmt.Default))
}
