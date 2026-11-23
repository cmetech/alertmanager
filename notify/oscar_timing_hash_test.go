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

func TestOscarActionProjectedNflogIdentity(t *testing.T) {
	t.Parallel()
	now := time.Now()
	a := alert.New(model.Alert{StartsAt: now, Labels: model.LabelSet{"severity": "major"}}, now, false)
	b := alert.New(model.Alert{StartsAt: now, Labels: model.LabelSet{"severity": "critical"}}, now, false)
	ref := alert.EpisodeRef{AuthorityID: "11111111-1111-4111-8111-111111111111", EpisodeID: "22222222-2222-4222-8222-222222222222", Generation: 1, VariantRevision: 1}
	view, err := alert.BuildDispatchView(a, ref, "critical", 1)
	require.NoError(t, err)
	m := view.NotificationMember()
	require.Equal(t, b.Fingerprint(), m.Fingerprint())
	require.NotEqual(t, HashAlert(b), HashAlert(m))
	require.Equal(t, HashAlert(a), HashAlert(a.NotificationCopy(now)))
}
