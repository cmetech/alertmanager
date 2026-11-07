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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/api/metrics"
	open_api_models "github.com/prometheus/alertmanager/api/v2/models"
	alert_ops "github.com/prometheus/alertmanager/api/v2/restapi/operations/alert"
	"github.com/prometheus/alertmanager/config"
)

func TestPostAlertsCapturesEffectiveDeadlineOriginAndAppliedTimeout(t *testing.T) {
	stored := &putRecorder{}
	post := func(timeout time.Duration, name string, endsAt time.Time) (time.Time, time.Time) {
		t.Helper()
		api := API{
			alerts:             stored,
			logger:             promslog.NewNopLogger(),
			m:                  metrics.NewAlerts(prometheus.NewRegistry()),
			alertmanagerConfig: &config.Config{Global: &config.GlobalConfig{ResolveTimeout: model.Duration(timeout)}},
		}
		r, err := http.NewRequest("POST", "/api/v2/alerts", nil)
		require.NoError(t, err)
		pa := &open_api_models.PostableAlert{Alert: open_api_models.Alert{Labels: open_api_models.LabelSet{"alertname": name}}}
		if !endsAt.IsZero() {
			pa.EndsAt = strfmt.DateTime(endsAt)
		}
		before := time.Now()
		w := httptest.NewRecorder()
		api.postAlertsHandler(alert_ops.PostAlertsParams{HTTPRequest: r, Alerts: open_api_models.PostableAlerts{pa}}).WriteResponse(w, runtime.TextProducer())
		after := time.Now()
		require.Equal(t, 200, w.Code, w.Body.String())
		return before, after
	}

	before, after := post(1500*time.Millisecond, "implicit-1", time.Time{})
	require.Len(t, stored.stored, 1)
	first := stored.stored[0]
	require.Equal(t, alert.EndTimeSourceAlertmanagerTimeout, first.EndTimeSource)
	require.Equal(t, 1500*time.Millisecond, first.ResolveTimeout)
	require.False(t, first.EndsAt.Before(before.Add(1500*time.Millisecond)))
	require.False(t, first.EndsAt.After(after.Add(1500*time.Millisecond)))

	explicitEnd := time.Now().Add(time.Hour)
	post(2*time.Second, "explicit", explicitEnd)
	require.Len(t, stored.stored, 2)
	require.Equal(t, alert.EndTimeSourceSender, stored.stored[1].EndTimeSource)
	require.Zero(t, stored.stored[1].ResolveTimeout)
	require.True(t, stored.stored[1].EndsAt.Equal(explicitEnd))

	before, after = post(2*time.Second, "implicit-after-reload", time.Time{})
	require.Len(t, stored.stored, 3)
	last := stored.stored[2]
	require.Equal(t, alert.EndTimeSourceAlertmanagerTimeout, last.EndTimeSource)
	require.Equal(t, 2*time.Second, last.ResolveTimeout)
	require.False(t, last.EndsAt.Before(before.Add(2*time.Second)))
	require.False(t, last.EndsAt.After(after.Add(2*time.Second)))
}
