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
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/featurecontrol"
	"github.com/prometheus/alertmanager/nflog/nflogpb"
)

// SetNotifiesStage sets the notification information about passed alerts. The
// passed alerts should have already been sent to the receivers.
type SetNotifiesStage struct {
	nflog NotificationLog
	recv  *nflogpb.Receiver
	ff    featurecontrol.Flagger
}

// NewSetNotifiesStage returns a new instance of a SetNotifiesStage.
func NewSetNotifiesStage(l NotificationLog, recv *nflogpb.Receiver, ff featurecontrol.Flagger) *SetNotifiesStage {
	return &SetNotifiesStage{
		nflog: l,
		recv:  recv,
		ff:    ff,
	}
}

// mutedAlerts returns the hashes of the alerts a mute stage removed from the
// pipeline. The hashes are sorted so that an unchanged muted set
// always serializes to the same bytes.
func (n SetNotifiesStage) mutedAlerts(ctx context.Context) []uint64 {
	if !n.ff.EnableMutedAlertsInNflog() {
		return nil
	}

	muted, ok := MutedAlerts(ctx)
	if !ok || len(muted) == 0 {
		return nil
	}

	return slices.Sorted(maps.Keys(muted))
}

// Exec implements the Stage interface.
func (n SetNotifiesStage) Exec(ctx context.Context, l *slog.Logger, alerts ...*alert.Alert) (context.Context, []*alert.Alert, error) {
	if _, selected := selectedAction(ctx); selected {
		return ctx, alerts, nil
	}
	gkey, ok := GroupKey(ctx)
	if !ok {
		return ctx, nil, errors.New("group key missing")
	}

	ctx, span := tracer.Start(ctx, "notify.SetNotifiesStage.Exec",
		trace.WithAttributes(attribute.String("alerting.group.key", gkey)),
		trace.WithAttributes(attribute.Int("alerting.alerts.count", len(alerts))),
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	firing, ok := FiringAlerts(ctx)
	if !ok {
		return ctx, nil, errors.New("firing alerts missing")
	}

	resolved, ok := ResolvedAlerts(ctx)
	if !ok {
		return ctx, nil, errors.New("resolved alerts missing")
	}

	var held error
	if batch, ordinary := ctx.Value(ordinaryBatchKey{}).(OrdinaryBatch); ordinary {
		if batch.LogMembers == nil {
			return ctx, alerts, nil
		}
		var accepted []*alert.Alert
		accepted, held = batch.LogMembers()
		if len(accepted) == 0 {
			return ctx, alerts, held
		}
		if !slices.Equal(accepted, batch.group) {
			f, r, fs, rs := partitionAlertsByState(accepted, batch.hash)
			firing = retainLoggedMembers(f, fs, batch.groupFiring, batch.previous.GetFiringAlerts())
			resolved = retainLoggedMembers(r, rs, batch.groupResolved, batch.previous.GetResolvedAlerts())
		}
	}

	repeat, ok := RepeatInterval(ctx)
	if !ok {
		return ctx, nil, errors.New("repeat interval missing")
	}
	expiry := 2 * repeat

	muted := n.mutedAlerts(ctx)

	span.SetAttributes(
		attribute.Int("alerting.alerts.firing.count", len(firing)),
		attribute.Int("alerting.alerts.resolved.count", len(resolved)),
		attribute.Int("alerting.alerts.muted.count", len(muted)),
	)

	// Extract receiver data from context if present (it's ok for it to be nil).
	store, _ := NflogStore(ctx)
	if err := n.nflog.Log(n.recv, gkey, firing, resolved, muted, store, expiry); err != nil {
		return ctx, nil, err
	}
	return ctx, alerts, held
}

// retainLoggedMembers keeps previously acknowledged siblings still present in this state.
func retainLoggedMembers(accepted []uint64, seen, current map[uint64]struct{}, previous []uint64) []uint64 {
	for _, hash := range previous {
		if _, present := current[hash]; present {
			if _, recorded := seen[hash]; !recorded {
				accepted = append(accepted, hash)
				seen[hash] = struct{}{}
			}
		}
	}
	return accepted
}
