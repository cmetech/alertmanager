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

package alert

import (
	"testing"
	"time"

	"github.com/prometheus/common/model"
)

func TestEndTimeProvenanceFollowsEffectiveDeadline(t *testing.T) {
	now := time.Now()
	makeAlert := func(updated time.Time, end time.Time, timeout bool, source EndTimeSource, applied time.Duration) *Alert {
		a := New(model.Alert{Labels: model.LabelSet{"alertname": "same"}, StartsAt: now.Add(-time.Hour), EndsAt: end}, updated, timeout)
		a.EndTimeSource = source
		a.ResolveTimeout = applied
		return a
	}
	assertEnd := func(t *testing.T, a *Alert, end time.Time, source EndTimeSource, applied time.Duration) {
		t.Helper()
		if !a.EndsAt.Equal(end) || a.EndTimeSource != source || a.ResolveTimeout != applied {
			t.Fatalf("end=%s source=%s duration=%s, want end=%s source=%s duration=%s", a.EndsAt, a.EndTimeSource, a.ResolveTimeout, end, source, applied)
		}
	}

	explicitEnd := now.Add(3 * time.Hour)
	firstTimeoutEnd := now.Add(2 * time.Hour)
	secondTimeoutEnd := now.Add(4 * time.Hour)
	explicit := makeAlert(now, explicitEnd, false, EndTimeSourceSender, 0)
	firstTimeout := makeAlert(now.Add(time.Second), firstTimeoutEnd, true, EndTimeSourceAlertmanagerTimeout, time.Hour)
	merged := explicit.Merge(firstTimeout)
	assertEnd(t, merged, explicitEnd, EndTimeSourceSender, 0)
	if !merged.Timeout {
		t.Fatal("native Timeout flag must remain from the newer alert")
	}
	secondTimeout := makeAlert(now.Add(2*time.Second), secondTimeoutEnd, true, EndTimeSourceAlertmanagerTimeout, 1500*time.Millisecond)
	assertEnd(t, merged.Merge(secondTimeout), secondTimeoutEnd, EndTimeSourceAlertmanagerTimeout, 1500*time.Millisecond)

	equal := makeAlert(now.Add(3*time.Second), secondTimeoutEnd, false, EndTimeSourceSender, 0)
	assertEnd(t, secondTimeout.Merge(equal), secondTimeoutEnd, EndTimeSourceSender, 0)
	assertEnd(t, equal.Merge(secondTimeout), secondTimeoutEnd, EndTimeSourceSender, 0)

	olderUpdate := makeAlert(now.Add(-time.Second), now.Add(5*time.Hour), false, EndTimeSourceSender, 0)
	assertEnd(t, secondTimeout.Merge(olderUpdate), olderUpdate.EndsAt, EndTimeSourceSender, 0)

	resolvedOld := makeAlert(now.Add(-2*time.Minute), now.Add(-time.Minute), false, EndTimeSourceSender, 0)
	resolvedNew := makeAlert(now.Add(-time.Minute), now.Add(-2*time.Minute), true, EndTimeSourceAlertmanagerTimeout, time.Hour)
	assertEnd(t, resolvedOld.Merge(resolvedNew), resolvedOld.EndsAt, EndTimeSourceSender, 0)
}

func TestNewAlertEndTimeProvenanceIsUnknown(t *testing.T) {
	a := New(model.Alert{Labels: model.LabelSet{"alertname": "outside-post"}}, time.Now(), false)
	if a.EndTimeSource != EndTimeSourceUnknown || a.ResolveTimeout != 0 {
		t.Fatalf("unexpected default provenance: %q, %s", a.EndTimeSource, a.ResolveTimeout)
	}
}
