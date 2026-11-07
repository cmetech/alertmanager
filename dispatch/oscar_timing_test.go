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

package dispatch

import (
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/eventrecorder"
)

func TestGroupKeyForAlertMatchesNativeAggregationGroup(t *testing.T) {
	cfg, err := config.Load("route:\n  receiver: default\n  group_by: [alertname, severity]\nreceivers:\n- name: default\n")
	require.NoError(t, err)
	route := NewRoute(cfg.Route, nil)
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown", "severity": "major", "instance": "node-1"}}, time.Now(), false)
	groupLabels := getGroupLabels(a, route)
	ag := newAggrGroup(t.Context(), groupLabels, route, nil, eventrecorder.NopRecorder(), promslog.NewNopLogger(), nil)
	t.Cleanup(func() { ag.next.Stop(); ag.cancel() })
	require.Equal(t, ag.GroupKey(), GroupKeyForAlert(a, route))
}
