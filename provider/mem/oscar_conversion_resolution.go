// Copyright 2018 Prometheus Team
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

package mem

import (
	"context"
	"errors"
	"time"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/provider"
)

const conversionAnnotation = "__oscar_fingerprint_conversion"

// PutResolvedConversion resolves current source-owned entries without creating authority.
// All preconditions and mutation share Put/GC's provider mutex; no I/O occurs here.
func (a *Alerts) PutResolvedConversion(ctx context.Context, alerts ...*alert.Alert) error {
	stream := a.handoff.Load()
	var messages []*provider.Alert
	var targets []listeningAlerts
	if stream != nil {
		if err := stream.acquire(ctx, a.shutdown); err != nil {
			return err
		}
		defer func() { a.drain(stream, targets, messages) }()
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	owned := make([]*alert.Alert, 0, len(alerts))
	nativeNow := time.Now()
	for _, incoming := range alerts {
		old, err := a.alerts.Get(incoming.Fingerprint())
		supplied := *incoming
		supplied.Annotations = incoming.Annotations.Clone()
		receipt := string(supplied.Annotations["__oscar_fingerprint_conversion_resolution"])
		delete(supplied.Annotations, "__oscar_fingerprint_conversion_resolution")
		incoming = &supplied
		// This actor authenticates resolve-only intent. Bound host clock skew,
		// then end at native now; a caller timestamp can never extend firing.
		if incoming.EndsAt.After(nativeNow) && !incoming.EndsAt.After(nativeNow.Add(5*time.Second)) {
			incoming.EndsAt = nativeNow
		}
		reason := ""
		switch {
		case a.owners[incoming.Fingerprint()] != "":
			reason = "managed owner"
		case err != nil:
			reason = "missing"
		case incoming.Timeout || incoming.EndsAt.IsZero() || incoming.EndsAt.After(nativeNow) || incoming.EndsAt.Before(old.StartsAt) || incoming.EndsAt.After(old.EndsAt):
			reason = "lifecycle"
		case receipt != alert.ConversionResolutionReceipt(old):
			reason = "receipt"
		case !incoming.Labels.Equal(old.Labels):
			reason = "labels"
		case !incoming.Annotations.Equal(old.Annotations):
			reason = "annotations"
		case old.Annotations[conversionAnnotation] == "":
			reason = "capsule"
		case incoming.GeneratorURL != old.GeneratorURL:
			reason = "generator"
		case !(incoming.StartsAt.Equal(old.StartsAt) || incoming.StartsAt.Equal(old.StartsAt.Truncate(time.Millisecond))):
			reason = "episode"
		}
		if reason != "" {
			return errors.New("conversion resolution current-entry precondition failed: " + reason)
		}

		// GET serializes milliseconds. Exact current capsule + complete contents and
		// the codec's exact timestamp projection identify the same current statement.
		// Retain native's precise original episode timestamp and annotations.
		resolved := *old
		resolved.Labels = old.Labels.Clone()
		resolved.Annotations = old.Annotations.Clone()
		resolved.EndsAt = incoming.EndsAt
		resolved.UpdatedAt = incoming.UpdatedAt
		resolved.Timeout = false
		resolved.EndTimeSource = incoming.EndTimeSource
		owned = append(owned, &resolved)
	}
	if stream == nil {
		return a.putLocked(ctx, nil, owned...)
	}
	targets = a.subscribers()
	return a.putLocked(ctx, &messages, owned...)
}
