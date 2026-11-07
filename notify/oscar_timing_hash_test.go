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

package notify

import (
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
)

func TestExportedNotificationHashMatchesNativeDedupHash(t *testing.T) {
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown", "instance": "node-1"}}, time.Now(), false)
	require.Equal(t, hashAlert(a), HashAlert(a))
	require.NotEqual(t, uint64(a.Fingerprint()), HashAlert(a))
}
