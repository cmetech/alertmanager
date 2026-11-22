// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/nflog"
	"github.com/prometheus/alertmanager/nflog/nflogpb"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/notify/webhook"
	"github.com/prometheus/alertmanager/template"
)

type actionRPCFunc func(context.Context, string, map[string]any, any) error

func (f actionRPCFunc) call(c context.Context, k string, p map[string]any, v any) error {
	return f(c, k, p, v)
}

type testActionDispatch struct{ ActionDispatch }

func (testActionDispatch) Version() int { return 1 }
func (testActionDispatch) Plan(context.Context, *alert.Alert, EpisodeProjection, ActionRequestV1) ([]DispatchTarget, string, error) {
	return []DispatchTarget{}, "", nil
}
func (testActionDispatch) Publish(context.Context, EpisodeProjection) error { return nil }
func (testActionDispatch) Wake(context.Context, string) error               { return nil }

func TestOscarActionPersistenceLossAndInvalidation(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"reserve", "commit", "resolve-during-commit", "expired-permit", "expired-sibling-permit", "operation-conflict"} {
		t.Run(failure, func(t *testing.T) {
			var req ActionRequestV1
			require.NoError(t, json.Unmarshal([]byte(actionBody), &req))
			source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Minute), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
			var o *nativeActionOwner
			var record *actionIntent
			var renewed bool
			var writes int
			rpc := actionRPCFunc(func(ctx context.Context, cmd string, p map[string]any, out any) error {
				var value any
				switch cmd {
				case "lookup":
					value = record
				case "reserve":
					writes++
					record = &actionIntent{Digest: p["digest"].(string), Result: ActionResultV1{OperationID: req.OperationID, EpisodeRef: req.EpisodeRef, State: "held"}, Request: mustRaw(t, req)}
					if failure == "operation-conflict" {
						record.Digest = strings.Repeat("0", 64)
					}
					if failure == "reserve" || failure == "operation-conflict" {
						return errors.New("lost reserve reply")
					}
					value = record.Result
				case "commit":
					writes++
					update := p["update"].(actionCommit)
					record.Intent = &update
					record.Result.State = "accepted"
					expiry := time.Now().Add(30 * time.Second)
					if p["renew_permit"] == true {
						renewed = true
					}
					record.Result.PermitExpiresAt = &expiry
					if failure == "resolve-during-commit" {
						other := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "other"}, StartsAt: source.StartsAt, EndsAt: source.EndsAt}, source.UpdatedAt, false)
						o.observe("", other, false)
						_, err := o.Project(ctx, other)
						require.NoError(t, err)
						closed := *source
						closed.EndsAt = time.Now()
						o.observe("", &closed, false)
					}
					if failure == "commit" {
						return errors.New("lost commit reply")
					}
					value = record.Result
				case "project-episode":
					u := p["update"].(episodeUpdate)
					value = EpisodeProjection{episodeUpdate: u}
				case "reconcile-invalidated":
					value = record.Result
				default:
					t.Fatalf("unexpected %s", cmd)
				}
				b, err := json.Marshal(value)
				require.NoError(t, err)
				return json.Unmarshal(b, out)
			})
			o = newNativeActionOwner(req.EpisodeRef.AuthorityID, rpc, testActionDispatch{})
			var dynamicFile string
			if failure == "expired-sibling-permit" {
				req.Kind = "resend"
				dynamicFile = filepath.Join(t.TempDir(), "url")
				require.NoError(t, os.WriteFile(dynamicFile, []byte("https://fixture.invalid"), 0o600))
				o.dispatch = retainedTargetPlan{testActionDispatch{}, dynamicFile, []DispatchTarget{
					{ReceiverID: "team", IntegrationDigest: strings.Repeat("b", 64)}, {ReceiverID: "team", IntegrationDigest: strings.Repeat("c", 64)},
				}}
			}
			o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
			o.recovered = true
			o.observe("", source, false)
			proj, err := o.Project(t.Context(), source)
			require.NoError(t, err)
			req.EpisodeRef = proj.EpisodeRef
			_, err = o.Execute(t.Context(), req)
			if failure == "operation-conflict" {
				require.ErrorIs(t, err, conflict)
				return
			}
			if failure == "resolve-during-commit" {
				require.ErrorIs(t, err, mismatch)
				return
			}
			require.NoError(t, err)
			if failure == "expired-permit" {
				expired := time.Now().Add(-time.Second)
				record.Result.PermitExpiresAt = &expired
				_, err = o.Execute(t.Context(), req)
				require.NoError(t, err)
				require.True(t, renewed)
			}
			if failure == "expired-sibling-permit" {
				expired := time.Now().Add(-time.Second)
				record.Result.PermitExpiresAt = &expired
				require.Len(t, record.Intent.Targets, 2)
				frozen := append([]DispatchTarget(nil), record.Intent.Targets...)
				for _, dst := range frozen {
					record.Result.Targets = append(record.Result.Targets, TargetResult{Target: dst, State: "pending"})
				}
				require.NoError(t, os.Remove(dynamicFile))
				err = o.recoverWork(t.Context(), req.OperationID, map[string]bool{})
				require.Equal(t, frozen, record.Intent.Targets)
				require.NoError(t, err)
				require.True(t, renewed)
			}
			if failure == "reserve" || failure == "commit" {
				require.Equal(t, 2, writes)
			}
		})
	}
}

func mustRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestOscarActionRecoveryRequiresExactSource(t *testing.T) {
	t.Parallel()
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	owner := newNativeActionOwner(defaultActionAuthority, nil, testActionDispatch{})
	proj := EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "11111111-1111-4111-8111-111111111113", Generation: 1, VariantRevision: 1}, NativeVariant: variantOf(source), State: "firing", SourceSeverity: "major", ActiveSince: source.StartsAt.UTC().Format(time.RFC3339Nano), LifecycleSeq: 1}, Floor: "critical", SeverityRevision: 1}
	owner.lease = actionLease{Epoch: 2, ExpiresAt: time.Now().Add(time.Minute)}
	owner.recovered = true
	require.NoError(t, owner.restoreEpisode(proj))
	other := *source
	other.StartsAt = source.StartsAt.Add(time.Nanosecond)
	owner.observe("", &other, false)
	_, err := owner.Project(t.Context(), &other)
	require.ErrorIs(t, err, unverified)
}

func TestOscarActionRecoveryFollowsReservationAndTargetSuccessors(t *testing.T) {
	t.Parallel()
	ids := []string{"11111111-1111-4111-8111-111111111111", "11111111-1111-4111-8111-111111111112", "11111111-1111-4111-8111-111111111113"}
	ref := EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "11111111-1111-4111-8111-111111111114", Generation: 1, VariantRevision: 1}
	for _, zero := range []bool{true, false} {
		looked := map[string]int{}
		rpc := actionRPCFunc(func(ctx context.Context, cmd string, p map[string]any, out any) error {
			id := p["operation_id"].(string)
			if cmd == "reconcile-invalidated" {
				require.Equal(t, uint64(2), p["epoch"])
				return nil
			}
			require.Equal(t, "lookup", cmd)
			require.Equal(t, "intent", p["projection"])
			looked[id]++
			i := actionIntent{Digest: strings.Repeat("b", 64), Result: ActionResultV1{OperationID: id, EpisodeRef: ref}}
			if id == ids[0] {
				if zero {
					i.ReservationSuccessorID = &ids[1]
				} else {
					i.Result.Targets = []TargetResult{{SuccessorID: &ids[1]}, {SuccessorID: &ids[2]}}
				}
			}
			return json.Unmarshal(mustRaw(t, i), out)
		})
		o := newNativeActionOwner(defaultActionAuthority, rpc, testActionDispatch{})
		o.lease = actionLease{Epoch: 2, ExpiresAt: time.Now().Add(time.Minute)}
		o.recovered = true
		require.NoError(t, o.recoverWork(t.Context(), ids[0], map[string]bool{}))
		require.Equal(t, 1, looked[ids[0]])
		require.Equal(t, 1, looked[ids[1]])
		if !zero {
			require.Equal(t, 1, looked[ids[2]])
		}
	}
}

func TestOscarActionExpiredWriterMayOnlySettleOriginalEntry(t *testing.T) {
	t.Parallel()
	id := "11111111-1111-4111-8111-111111111111"
	token := strings.Repeat("d", 64)
	key := strings.Repeat("f", 64)
	settled := false
	rpc := actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, _ any) error {
		require.Equal(t, "settle-target", cmd)
		require.Equal(t, token, p["entry_token"])
		require.NotContains(t, p, "owner_id")
		require.NotContains(t, p, "epoch")
		settled = true
		return nil
	})
	o := newNativeActionOwner(defaultActionAuthority, rpc, testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	stale := o.withEpoch(t.Context())
	o.lease.Epoch = 2
	require.ErrorIs(t, o.write(stale, "commit", map[string]any{}, nil), unavailable)
	o.lease.ExpiresAt = time.Now().Add(-time.Second)
	require.ErrorIs(t, o.write(o.withEpoch(t.Context()), "claim-target", map[string]any{}, nil), unavailable)
	_, err := o.Settle(t.Context(), claimedEntry{OperationID: id, TargetKey: key, token: token}, "confirmed", "original attempt receipt")
	require.NoError(t, err)
	require.True(t, settled)
}

func TestOscarActionReadinessNeedsVersionAndRejectsConflictingLease(t *testing.T) {
	t.Parallel()
	var o *nativeActionOwner
	protocol := "old-store"
	selectors := 0
	foreign := false
	rpc := actionRPCFunc(func(_ context.Context, cmd string, _ map[string]any, out any) error {
		if foreign {
			return unavailable
		}
		return json.Unmarshal(mustRaw(t, actionLease{Protocol: protocol, RecoverySelectors: selectors, TerminalObservations: 2, RecipientBinding: 2, RecipientKey: strings.Repeat("ab", 32), OwnerID: o.owner, AuthorityID: o.authority, Epoch: 1, ExpiresAt: time.Now().Add(30 * time.Second), RenewSeconds: 10}), out)
	})
	o = newNativeActionOwner(defaultActionAuthority, rpc, nil)
	require.ErrorIs(t, o.leaseTick(t.Context()), unavailable)
	require.False(t, o.ready())
	foreign = true
	require.ErrorIs(t, o.leaseTick(t.Context()), unavailable)
	foreign = false
	protocol = "native-action-store-v1"
	require.ErrorIs(t, o.leaseTick(t.Context()), unavailable)
	selectors = 1
	require.NoError(t, o.leaseTick(t.Context()))
	o.recovered = true
	require.False(t, o.ready())
	o.dispatch = testActionDispatch{}
	require.True(t, o.ready())
}

func TestOscarActionEligibilityResolvedAndReplacedIsReadOnly(t *testing.T) {
	t.Parallel()
	var req ActionRequestV1
	require.NoError(t, json.Unmarshal([]byte(actionBody), &req))
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, actionRPCFunc(func(context.Context, string, map[string]any, any) error {
		t.Fatal("eligibility wrote or read the durable action journal")
		return nil
	}), testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	end := time.Now().Add(-time.Second)
	a := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: end.Add(-time.Minute), EndsAt: end}, end, false)
	current := req.EpisodeRef
	current.VariantRevision++
	o.byID[current.EpisodeID] = &episodeSlot{source: a, projection: EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: current, State: "resolved", NativeVariant: variantOf(a)}}}
	items, err := o.Eligibility(t.Context(), []EpisodeRef{req.EpisodeRef, current})
	require.NoError(t, err)
	require.Len(t, items, 2)
	for n, reason := range []string{mismatch.reason, resolved.reason} {
		for kind := range actionGrants {
			decision := items[n].Actions[kind]
			require.False(t, decision.Allowed)
			require.Equal(t, reason, *decision.Reason)
		}
	}
}

func TestOscarActionPolicyRecoveryRequiresFreshFencedSubmission(t *testing.T) {
	t.Parallel()
	var req ActionRequestV1
	require.NoError(t, json.Unmarshal([]byte(actionBody), &req))
	req.Kind = "resend"
	req.Actor = ActionActor{Kind: "policy", ID: "resend-policy"}
	req.PolicyBinding = &PolicyBinding{BindingID: req.OperationID, RevisionID: req.EpisodeRef.EpisodeID}
	req.TargetScope = []ScopeEntry{{ReceiverID: "ops"}}
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	next := req.EpisodeRef
	next.VariantRevision++
	digest, err := actionDigest(req)
	require.NoError(t, err)
	record := actionIntent{Digest: digest, Request: mustRaw(t, req), LogicalActionID: req.OperationID, Result: ActionResultV1{OperationID: req.OperationID, EpisodeRef: req.EpisodeRef, State: "held", Targets: []TargetResult{}}}
	transfers := 0
	childID := "77777777-1111-4111-8111-111111111111"
	rpc := actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		switch cmd {
		case "lookup":
			if p["projection"] == "transfer" {
				if p["expected_revision"] != uint64(0) {
					return reconcile
				}
				return json.Unmarshal(mustRaw(t, ActionResultV1{OperationID: childID, EpisodeRef: next, State: "held"}), out)
			}
			if p["operation_id"] == childID {
				child := actionIntent{SupersedesOperationID: &req.OperationID, Digest: strings.Repeat("a", 64), LogicalActionID: req.OperationID, Result: ActionResultV1{OperationID: childID, EpisodeRef: next, State: "held"}}
				return json.Unmarshal(mustRaw(t, child), out)
			}
			return json.Unmarshal(mustRaw(t, record), out)
		case "supersede-not-started":
			transfers++
			record.ReservationSuccessorID = &childID
			require.Equal(t, next, p["current_ref"])
			return json.Unmarshal(mustRaw(t, ActionResultV1{OperationID: childID, EpisodeRef: next, State: "held"}), out)
		default:
			t.Fatalf("unexpected policy mutation %s", cmd)
			return nil
		}
	})
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, rpc, testActionDispatch{})
	o.lease = actionLease{Epoch: 2, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	o.byID[next.EpisodeID] = &episodeSlot{source: source, projection: EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: next, NativeVariant: variantOf(source), State: "firing", SourceSeverity: "major", LifecycleSeq: 2}}}
	require.NoError(t, o.recoverWork(t.Context(), req.OperationID, map[string]bool{}))
	require.Zero(t, transfers)
	_, err = o.Execute(t.Context(), req)
	require.Error(t, err)
	original := context.WithValue(t.Context(), policyAssertionKey{}, policyAssertion{})
	got, err := o.Execute(original, req)
	require.NoError(t, err)
	require.Equal(t, "held", got.State)
	require.Zero(t, transfers)
	directive := policyRecovery{Mode: "transfer", CurrentRef: next, TargetKeys: []string{}}
	fresh := context.WithValue(t.Context(), policyAssertionKey{}, policyAssertion{Recovery: &directive, ExpiresAt: time.Now().Add(10 * time.Second)})
	got, err = o.Execute(fresh, req)
	require.NoError(t, err)
	require.Equal(t, childID, got.OperationID)
	require.Equal(t, 1, transfers)
	replay, err := o.Execute(fresh, req)
	require.NoError(t, err)
	require.Equal(t, childID, replay.OperationID)
	require.Equal(t, 1, transfers)
}

type heldPolicyDispatch struct{ testActionDispatch }

func (heldPolicyDispatch) Plan(context.Context, *alert.Alert, EpisodeProjection, ActionRequestV1) ([]DispatchTarget, string, error) {
	return nil, "NATIVE_SUPPRESSED", nil
}

func TestOscarActionSuppressedPolicyReservationRemainsTransferable(t *testing.T) {
	t.Parallel()
	var req ActionRequestV1
	require.NoError(t, json.Unmarshal([]byte(actionBody), &req))
	req.Kind = "resend"
	req.Actor = ActionActor{Kind: "policy", ID: "resend-policy"}
	req.PolicyBinding = &PolicyBinding{BindingID: req.OperationID, RevisionID: req.EpisodeRef.EpisodeID}
	req.TargetScope = []ScopeEntry{{ReceiverID: "ops"}}
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	var record *actionIntent
	rpc := actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		switch cmd {
		case "lookup":
			return json.Unmarshal(mustRaw(t, record), out)
		case "reserve":
			reason := "AWAITING_NATIVE_COMMIT"
			record = &actionIntent{Digest: p["digest"].(string), Request: mustRaw(t, req), LogicalActionID: req.OperationID, Result: ActionResultV1{OperationID: req.OperationID, EpisodeRef: req.EpisodeRef, State: "held", Reason: &reason}}
			return json.Unmarshal(mustRaw(t, record.Result), out)
		default:
			t.Fatalf("suppressed policy produced %s", cmd)
			return nil
		}
	})
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, rpc, heldPolicyDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	o.byID[req.EpisodeRef.EpisodeID] = &episodeSlot{source: source, projection: EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: req.EpisodeRef, NativeVariant: variantOf(source), State: "firing", SourceSeverity: "major", LifecycleSeq: 1}}}
	ctx := context.WithValue(t.Context(), policyAssertionKey{}, policyAssertion{})
	got, err := o.Execute(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "NATIVE_SUPPRESSED", *got.Reason)
	require.Nil(t, record.Intent)
	replay, err := o.Execute(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "AWAITING_NATIVE_COMMIT", *replay.Reason)
}

func TestActionManagedTransitionsRequireDurableOwnerEvidence(t *testing.T) {
	for _, kind := range []string{"update", "clear"} {
		t.Run(kind, func(t *testing.T) {
			key := strings.Repeat("b", 64)
			old := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
			old.ManagedReceiver, old.ManagedOperationKind = true, "raise"
			old.ManagedMember = alert.ManagedMembership{Episode: key, Generation: 1, Event: "11111111-1111-4111-8111-111111111111", Digest: strings.Repeat("d", 64)}
			candidate := *old
			candidate.ManagedOperationKind = kind
			candidate.ManagedMember.Generation = 2
			candidate.ManagedMember.Event = "22222222-1111-4111-8111-111111111111"
			mkSlot := func(a *alert.Alert) *ownerSlot {
				return &ownerSlot{Generation: a.ManagedMember.Generation, Projection: snapshot(a), Operation: mustRaw(t, map[string]string{"kind": a.ManagedOperationKind, "event_id": a.ManagedMember.Event, "source_digest": a.ManagedMember.Digest})}
			}
			row := ownerState{Key: key, State: "open", Phase: "settled", Current: mkSlot(old), Generation: 1}
			var writes []episodeUpdate
			o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
				require.Equal(t, "project-episode", cmd)
				u := p["update"].(episodeUpdate)
				writes = append(writes, u)
				*out.(*EpisodeProjection) = EpisodeProjection{ID: "33333333-1111-4111-8111-111111111111", episodeUpdate: u, Floor: "critical", SeverityRevision: 1}
				return nil
			}), testActionDispatch{})
			o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
			o.recovered = true
			o.verifyManaged = func(_ context.Context, a *alert.Alert, state string) error { return actionMemberProof(row, a, state) }
			o.observe(key, old, false)
			first, err := o.Project(t.Context(), old)
			require.NoError(t, err)
			row.Phase, row.Generation, row.Pending = "reserved", 2, mkSlot(&candidate)
			o.observe(key, &candidate, false)
			s := o.slot(sourceKey(key, ""), false)
			require.Error(t, o.flush(o.withEpoch(t.Context()), s))
			require.Len(t, writes, 1)
			// Restart can restore the predecessor and cancel a prior epoch's pending stamp.
			row.Phase, row.Generation, row.Pending = "cancelled", 3, nil
			o.observe(key, old, false)
			p, err := o.Project(t.Context(), old)
			require.NoError(t, err)
			require.Equal(t, first.EpisodeRef, p.EpisodeRef)
			require.Equal(t, "critical", p.Floor)
			// A fresh native coordinator reattaches only the previously journaled predecessor.
			restarted := newNativeActionOwner(o.authority, o.rpc, o.dispatch)
			restarted.lease = actionLease{Epoch: 2, ExpiresAt: time.Now().Add(time.Minute)}
			restarted.recovered = true
			restarted.verifyManaged = o.verifyManaged
			require.NoError(t, restarted.restoreEpisode(p))
			restarted.observe(key, old, false)
			recovered, err := restarted.Project(t.Context(), old)
			require.NoError(t, err)
			require.Equal(t, first.EpisodeRef, recovered.EpisodeRef)
			require.Equal(t, "critical", recovered.Floor)
			o = restarted
			s = o.slot(sourceKey(key, ""), false)
			candidate.ManagedMember.Generation = 4
			row.Current, row.Phase, row.Generation = mkSlot(&candidate), "applied", 4
			if kind == "clear" {
				closed := time.Now().UnixMilli()
				row.Closed = &closed
				row.State = "exact_closed"
			}
			o.observe(key, &candidate, false)
			p, err = o.Project(t.Context(), &candidate)
			require.NoError(t, err)
			require.Equal(t, uint64(2), p.EpisodeRef.VariantRevision)
			if kind == "clear" {
				require.Equal(t, "resolved", p.State)
			} else {
				require.Equal(t, "firing", p.State)
				// Administrative closure retires the proven projection, even with a different unpromoted pending stamp.
				other := candidate
				other.ManagedMember.Generation = 5
				row.Pending, row.Generation, row.Phase = mkSlot(&other), 5, "reserved"
				o.observe(key, &other, false)
				closed := time.Now().UnixMilli()
				row.Closed = &closed
				row.State, row.Phase, row.Generation = "exact_closed", "closing", 6
				o.observe(key, nil, true)
				require.NoError(t, o.flush(o.withEpoch(t.Context()), s))
				require.Equal(t, p.EpisodeRef, s.projection.EpisodeRef)
				require.Equal(t, "resolved", s.projection.State)
			}
		})
	}
}

func TestPolicyInvalidationReleasesOnlyOriginalSameVariantOperation(t *testing.T) {
	var req ActionRequestV1
	require.True(t, decodeAction([]byte(actionBody), &req))
	req.Actor = ActionActor{Kind: "policy", ID: "policy"}
	req.Kind = "resend"
	req.TargetScope = []ScopeEntry{{ReceiverID: "ops"}}
	req.PolicyBinding = &PolicyBinding{BindingID: req.OperationID, RevisionID: req.EpisodeRef.EpisodeID}
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	escalationID := "22222222-1111-4111-8111-111111111111"
	ops := map[string]*actionIntent{req.OperationID: {Request: mustRaw(t, req), Digest: strings.Repeat("a", 64), Result: ActionResultV1{OperationID: req.OperationID, EpisodeRef: req.EpisodeRef, SeverityRevision: 0, Targets: []TargetResult{{State: "pending"}, {State: "unknown"}, {State: "confirmed"}}}}, escalationID: {Result: ActionResultV1{OperationID: escalationID, EpisodeRef: req.EpisodeRef, SeverityRevision: 1}}}
	var reconciled []string
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		id := p["operation_id"].(string)
		switch cmd {
		case "lookup":
			return json.Unmarshal(mustRaw(t, ops[id]), out)
		case "reconcile-invalidated":
			reconciled = append(reconciled, id)
			return nil
		default:
			t.Fatalf("unauthorized %s", cmd)
			return nil
		}
	}), testActionDispatch{})
	o.recovered = true
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.byID[req.EpisodeRef.EpisodeID] = &episodeSlot{source: source, projection: EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: req.EpisodeRef, State: "firing", NativeVariant: variantOf(source)}, SeverityRevision: ops[escalationID].Result.SeverityRevision}}
	require.NoError(t, o.recoverWork(t.Context(), req.OperationID, map[string]bool{}))
	require.Equal(t, []string{req.OperationID}, reconciled)
}

type singleActionDispatch struct {
	testActionDispatch
	target DispatchTarget
}

func (d singleActionDispatch) Plan(context.Context, *alert.Alert, EpisodeProjection, ActionRequestV1) ([]DispatchTarget, string, error) {
	return []DispatchTarget{d.target}, "", nil
}

func TestFloorCommitFencesOutstandingEntryBeforeLostReply(t *testing.T) {
	var req ActionRequestV1
	require.True(t, decodeAction([]byte(actionBody), &req))
	sev := "critical"
	req.Kind, req.TargetSeverity = "escalate", &sev
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	key := strings.Repeat("a", 64)
	oldID := "22222222-1111-4111-8111-111111111111"
	expiry := time.Now().Add(time.Minute)
	target := DispatchTarget{ReceiverID: "ops"}
	var entry Entry
	lost := false
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		switch cmd {
		case "lookup":
			if p["operation_id"] == oldID {
				record := actionIntent{Request: mustRaw(t, ordinaryRequest{Kind: "ordinary", LifecycleSeq: 1, OperationID: oldID, EpisodeRef: req.EpisodeRef, Target: target}), Digest: strings.Repeat("b", 64), Result: ActionResultV1{EpisodeRef: req.EpisodeRef, OperationID: oldID, PermitExpiresAt: &expiry, Targets: []TargetResult{{State: "pending", TargetKey: key, Target: target}}}}
				return json.Unmarshal(mustRaw(t, record), out)
			}
			if lost {
				return unavailable
			}
			return nil
		case "claim-target":
			return json.Unmarshal(mustRaw(t, map[string]any{"entry_token": key, "lease_expires_at": expiry, "permit_expires_at": expiry}), out)
		case "reserve":
			reason := "AWAITING_NATIVE_COMMIT"
			*out.(*ActionResultV1) = ActionResultV1{Reason: &reason}
			return nil
		case "commit":
			require.False(t, entry.Valid())
			lost = true
			return unavailable
		case "recover":
			// The initial read can overtake the ambiguous write and still see the old floor.
			*out.(**EpisodeProjection) = &EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: req.EpisodeRef, State: "firing", LifecycleSeq: 1, NativeVariant: variantOf(source)}}
			return nil
		default:
			t.Fatalf("unexpected %s", cmd)
			return nil
		}
	}), singleActionDispatch{target: target})
	o.lease = actionLease{Epoch: 1, ExpiresAt: expiry}
	o.recovered = true
	o.byID[req.EpisodeRef.EpisodeID] = &episodeSlot{source: source, projection: EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: req.EpisodeRef, State: "firing", SourceSeverity: "major", NativeVariant: variantOf(source), LifecycleSeq: 1}}}
	var err error
	entry, err = o.Claim(t.Context(), oldID, key)
	require.NoError(t, err)
	require.True(t, entry.Valid())
	_, err = o.Execute(t.Context(), req)
	require.Error(t, err)
	require.False(t, entry.Valid())
	_, err = o.Claim(t.Context(), oldID, key)
	require.Error(t, err)
}

func TestEntryExpiresDuringReadiness(t *testing.T) {
	deadline := time.Now().Add(20 * time.Millisecond)
	e := claimedEntry{expires: deadline, valid: func() bool { <-time.After(time.Until(deadline)); return true }}
	require.False(t, e.Valid())
}

func TestOverflowGCAndDeferredRecoveryAtCapacity(t *testing.T) {
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	fp := source.Fingerprint().String()
	p := EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: episodeUpdate{EpisodeRef: EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "22222222-1111-4111-8111-111111111111", Generation: 1, VariantRevision: 1}, LifecycleSeq: 1, NativeVariant: variantOf(source), State: "firing", SourceSeverity: "major", ActiveSince: source.StartsAt.UTC().Format(time.RFC3339Nano)}, Floor: "critical", SeverityRevision: 1}
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		if cmd == "recover" {
			if args["projection"] == "membership" {
				*out.(*[]string) = []string{fp}
				return nil
			}
			if args["projection"] == "episodes" {
				rows := []EpisodeProjection{}
				if args["after_id"] == nil {
					rows = append(rows, p)
				}
				*out.(*[]EpisodeProjection) = rows
				return nil
			}
			require.Equal(t, "source", args["projection"])
			require.Equal(t, fp, args["fingerprint"])
			*out.(*[]EpisodeProjection) = []EpisodeProjection{p}
			return nil
		}
		require.Equal(t, "project-episode", cmd)
		u := args["update"].(episodeUpdate)
		require.Equal(t, p.EpisodeRef, u.EpisodeRef)
		x := p
		x.episodeUpdate = u
		*out.(*EpisodeProjection) = x
		return nil
	}), testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	churn := *source
	churn.Labels = model.LabelSet{"alertname": "churning"}
	key := sourceKey("", churn.Fingerprint().String())
	o.observe("", &churn, false)
	for n := 1; n < maxActionEpisodes; n++ {
		o.byKey[fmt.Sprint(n)] = &episodeSlot{}
	}
	require.NoError(t, o.recoverEpisodes(t.Context(), o.lease.Epoch))
	require.Len(t, o.byKey, maxActionEpisodes)
	s := o.slot(key, false)
	for n := 1; n <= maxTransitions*4; n++ {
		a := churn
		a.StartsAt = churn.StartsAt.Add(time.Duration(n))
		o.observe("", &a, false)
		if n == maxTransitions*4 {
			o.observe("", &a, true)
		}
	}
	require.True(t, s.overflow)
	require.Len(t, s.pending, maxTransitions)
	o.sweepSlot(o.withEpoch(t.Context()), key, s)
	require.Len(t, o.byKey, maxActionEpisodes-1)
	other := *source
	other.StartsAt = other.StartsAt.Add(time.Nanosecond)
	o.observe("", &other, false)
	_, err := o.Project(t.Context(), &other)
	require.ErrorIs(t, err, unverified)
	slot := o.slot(sourceKey("", fp), false)
	require.Equal(t, p.EpisodeRef, slot.projection.EpisodeRef)
	require.Equal(t, "critical", slot.projection.Floor)
	// GC retires the unmatched local pair. A later exact provider member recovers its floor.
	o.observe("", &other, true)
	o.sweepSlot(o.withEpoch(t.Context()), sourceKey("", fp), slot)
	require.Nil(t, o.slot(sourceKey("", fp), false))
	o.observe("", source, false)
	match, err := o.Project(t.Context(), source)
	require.NoError(t, err)
	require.Equal(t, p.EpisodeRef, match.EpisodeRef)
	require.Equal(t, "critical", match.Floor)
}

func TestPreparedOrdinaryLifecycleTakeoverAndGC(t *testing.T) {
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	var journal EpisodeProjection
	var attempts []uint64
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		switch cmd {
		case "project-episode":
			u := p["update"].(episodeUpdate)
			attempts = append(attempts, u.LifecycleSeq)
			if u.LifecycleSeq == 2 {
				return unavailable
			}
			require.Equal(t, journal.LifecycleSeq+1, u.LifecycleSeq)
			journal = EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: u}
			*out.(*EpisodeProjection) = journal
		case "recover":
			require.Equal(t, "episode", p["projection"])
			require.Equal(t, journal.EpisodeRef.EpisodeID, p["episode_id"])
			reply := journal
			*out.(**EpisodeProjection) = &reply
		default:
			t.Fatalf("unexpected command %s", cmd)
		}
		return nil
	}), testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	o.observe("", source, false)
	_, err := o.Project(t.Context(), source)
	require.NoError(t, err)
	key := sourceKey("", source.Fingerprint().String())
	s := o.slot(key, false)
	o.observe("", source, false)
	_, err = o.Project(t.Context(), source)
	require.Error(t, err)
	o.observe("", source, true)
	o.sweepSlot(o.withEpoch(t.Context()), key, s)
	require.Same(t, s, o.slot(key, false))
	require.NotNil(t, s.next)
	require.Equal(t, uint64(2), s.next.LifecycleSeq)
	// A different lease owner committed the prepared lifecycle and a subsequent
	// observation. Startup reattaches the later projection before draining GC.
	journal.LifecycleSeq = 3
	journal.Floor = "critical"
	journal.SeverityRevision = 1
	o.lease.Epoch = 3
	s.uncertain = true
	require.NoError(t, o.restoreEpisode(journal))
	before := len(attempts)
	o.sweepSlot(o.withEpoch(t.Context()), key, s)
	require.Nil(t, s.next)
	require.Nil(t, o.slot(key, false))
	require.Equal(t, []uint64{4}, attempts[before:])
	require.Equal(t, "resolved", journal.State)
}

func TestPreparedOrdinaryTakeoverRequiresExactLaterInterval(t *testing.T) {
	for _, mode := range []string{"old-resident", "exact-successor", "exact-closed", "reused-start"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			old := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now.Add(-3 * time.Hour), EndsAt: now.Add(time.Hour)}, now, false)
			var journal EpisodeProjection
			var writes []episodeUpdate
			o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
				switch cmd {
				case "project-episode":
					u := args["update"].(episodeUpdate)
					writes = append(writes, u)
					if u.LifecycleSeq == 2 && u.EpisodeRef.Generation == 1 {
						return unavailable
					}
					journal = EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: u}
					*out.(*EpisodeProjection) = journal
				case "recover":
					require.Equal(t, "episode", args["projection"])
					require.Equal(t, journal.EpisodeRef.EpisodeID, args["episode_id"])
					row := journal
					*out.(**EpisodeProjection) = &row
				default:
					t.Fatalf("unexpected %s", cmd)
				}
				return nil
			}), testActionDispatch{})
			o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
			o.recovered = true
			o.observe("", old, false)
			_, err := o.Project(t.Context(), old)
			require.NoError(t, err)
			o.observe("", old, false)
			_, err = o.Project(t.Context(), old)
			require.Error(t, err)
			older := *old
			older.StartsAt = old.StartsAt.Add(time.Minute)
			o.observe("", old, false)
			o.observe("", &older, false)
			key := sourceKey("", old.Fingerprint().String())
			s := o.slot(key, false)
			require.Len(t, s.pending, 3)
			successor := *old
			successor.StartsAt = now.Add(-time.Hour)
			if mode == "reused-start" {
				successor.StartsAt = old.StartsAt
			}
			// A different owner closed the old generation and advanced the same
			// fingerprint. It also closed the successor in the reported failure.
			journal.ID = "22222222-2222-4222-8222-222222222222"
			journal.EpisodeRef.Generation++
			journal.LifecycleSeq = 2
			journal.NativeVariant = variantOf(&successor)
			journal.ActiveSince = journal.NativeVariant.StartsAt
			journal.State = "resolved"
			current := &older
			if mode != "old-resident" {
				journal.State = "firing"
				journal.LifecycleSeq = 1
				journal.Floor = "critical"
				journal.SeverityRevision = 1
				if mode == "exact-closed" {
					journal.State = "resolved"
					journal.Floor = ""
					successor.EndsAt = now.Add(-time.Minute)
				}
				current = &successor
				o.observe("", current, false)
			}
			o.lease.Epoch = 3
			s.uncertain = true
			if journal.State == "firing" {
				require.NoError(t, o.restoreEpisode(journal))
			}
			before := len(writes)
			p, err := o.Project(t.Context(), current)
			if mode == "exact-successor" || mode == "exact-closed" {
				require.NoError(t, err)
				require.Equal(t, journal.State, p.State)
				require.Equal(t, journal.EpisodeRef, p.EpisodeRef)
				require.Equal(t, journal.Floor, p.Floor)
				_, err = o.Project(t.Context(), old)
				require.Error(t, err)
			} else {
				require.ErrorIs(t, err, reconcile)
				o.sweepSlot(o.withEpoch(t.Context()), key, s)
				require.Same(t, s, o.slot(key, false))
				o.observe("", current, true)
				o.sweepSlot(o.withEpoch(t.Context()), key, s)
				require.Nil(t, o.slot(key, false))
			}
			require.Empty(t, writes[before:], "takeover replayed a buffered firing observation")
		})
	}
}

func TestOscarActionUntrackedEntryFencesEnrollment(t *testing.T) {
	t.Parallel()
	now := time.Now()
	a := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(context.Context, string, map[string]any, any) error {
		t.Fatal("verified negative must not access the journal")
		return nil
	}), testActionDispatch{})
	o.readSource = func(_, _ string, read func(*alert.Alert)) { read(a) }
	o.recovered, o.lease = true, actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
	p, pass, err := o.InspectOrdinary(t.Context(), a)
	require.NoError(t, err)
	require.Nil(t, p)
	require.True(t, pass.Enter())
	_, err = o.Project(t.Context(), a)
	require.Error(t, err)
	pass.Finish(false)
	_, err = o.Project(t.Context(), a)
	require.Error(t, err)
	_, _, err = o.InspectOrdinary(t.Context(), a)
	require.Error(t, err)
}

func TestOscarActionMembershipCandidateMissNeverEnrolls(t *testing.T) {
	t.Parallel()
	now := time.Now()
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	reads := 0
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		require.Equal(t, "recover", cmd)
		require.Equal(t, "source", p["projection"])
		reads++
		*out.(*[]EpisodeProjection) = []EpisodeProjection{}
		return nil
	}), testActionDispatch{})
	o.readSource = func(_, _ string, read func(*alert.Alert)) { read(source) }
	o.recovered = true
	o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
	key := sourceKey("", source.Fingerprint().String())
	bucket, bit := membershipBit(key)
	o.membership[bucket] |= bit
	p, pass, err := o.InspectOrdinary(t.Context(), source)
	require.NoError(t, err)
	require.Nil(t, p)
	require.Empty(t, o.byKey)
	require.Equal(t, 1, reads)
	o.slot(key, true)
	require.False(t, pass.Enter(), "enrollment after a checked negative revokes its entry")
}

func TestOscarActionTerminalEntryRequiresOriginalObservation(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(-time.Second)}, now, false)
	p := EpisodeProjection{episodeUpdate: episodeUpdate{State: "resolved", NativeVariant: variantOf(source), LifecycleSeq: 2}}
	s := &episodeSlot{source: source}
	terminal := &terminalObservation{LifecycleSeq: 2, NativeVariant: variantOf(source), SourceEndsAt: source.EndsAt}
	require.NoError(t, s.contactCurrentLocked(p, source, terminal))
	require.Error(t, s.contactCurrentLocked(p, source, nil))
	replacement := *source
	replacement.EndsAt = now.Add(time.Hour)
	s.source = &replacement
	require.Error(t, s.contactCurrentLocked(p, source, terminal))
	require.Error(t, s.contactCurrentLocked(p, &replacement, terminal))
	s.source = source
	s.removed = true
	require.Error(t, s.contactCurrentLocked(p, source, terminal))
}

func TestOscarActionRecoverTerminalUsesExactInterval(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	a := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(-time.Second)}, now, false)
	ref := EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "22222222-2222-4222-8222-222222222222", Generation: 1, VariantRevision: 1}
	p := EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: episodeUpdate{EpisodeRef: ref, NativeVariant: variantOf(a), State: "resolved", SourceSeverity: "major", ActiveSince: variantOf(a).StartsAt, LifecycleSeq: 2}}
	lookups := 0
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		require.Equal(t, "recover", cmd)
		require.Equal(t, "terminal", args["projection"])
		lookups++
		*out.(*[]EpisodeProjection) = []EpisodeProjection{}
		if sameVariant(args["native_variant"].(alert.NativeVariant), p.NativeVariant) {
			*out.(*[]EpisodeProjection) = []EpisodeProjection{p}
		}
		return nil
	}), nil)
	require.NoError(t, o.rememberTerminal(p))
	got, err := o.terminalCandidate(t.Context(), a)
	require.NoError(t, err)
	require.Equal(t, &p, got)
	replacement := *a
	replacement.EndsAt = now.Add(time.Hour)
	_, err = o.terminalCandidate(t.Context(), &replacement)
	require.Error(t, err)
	replacement.StartsAt = now
	// A new interval with the same historical source key still requires exact lookup.
	got, err = o.terminalCandidate(t.Context(), &replacement)
	require.NoError(t, err)
	require.Nil(t, got)
	require.Equal(t, 3, lookups)
}

func TestOscarActionTerminalClaimAndSignedMember(t *testing.T) {
	t.Parallel()
	for _, fault := range []string{"none", "lost claim reply", "annotation replacement on takeover", "promoted managed clear", "evicted before late settlement", "expiry in allocated slot", "expiry after slot reclamation"} {
		t.Run(fault, func(t *testing.T) { exerciseTerminalReceipt(t, fault, "", "") })
	}
}

func TestOscarManagedTimeoutBeforeProviderGC(t *testing.T) {
	t.Parallel()
	for _, fault := range []string{"expiry in allocated slot", "expiry after slot reclamation"} {
		for _, kind := range []string{"raise", "update"} {
			for _, invalid := range []string{"exact", "expiry", "generation", "event", "digest", "variant", "native variant", "pending"} {
				t.Run(fault+"/"+kind+"/"+invalid, func(t *testing.T) { exerciseTerminalReceipt(t, fault, kind, invalid) })
			}
		}
	}
}

func exerciseTerminalReceipt(t *testing.T, fault, timeoutKind, invalid string) {
	t.Helper()
	now := time.Now().UTC()
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now.Add(-2 * time.Hour), EndsAt: now.Add(-time.Minute)}, now, false)
	if timeoutKind != "" || fault == "promoted managed clear" {
		source.ManagedReceiver, source.ManagedOperationKind = true, timeoutKind
		if fault == "promoted managed clear" {
			source.ManagedOperationKind = "clear"
			source.EndsAt = now.Add(time.Hour)
		}
		source.ManagedMember = alert.ManagedMembership{Episode: strings.Repeat("b", 64), Generation: 2, Event: "44444444-4444-4444-8444-444444444444", Digest: strings.Repeat("d", 64)}
	}
	if timeoutKind != "" {
		source.ManagedEligible = func(_ context.Context, member *alert.Alert, receiver, group string) (bool, error) {
			return member == source && receiver == "ops" && group == "managed-timeout", nil
		}
	}
	wire := source.NotificationCopy(now)
	ref := EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "22222222-2222-4222-8222-222222222222", Generation: 1, VariantRevision: 1}
	p := EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: episodeUpdate{EpisodeRef: ref, NativeVariant: variantOf(source), State: "resolved", LifecycleSeq: 2, SourceSeverity: "major", ActiveSince: variantOf(source).StartsAt}}
	if timeoutKind != "" {
		p.ManagedOwner = &sourceOwner{source.ManagedMember.Episode, source.ManagedMember.Generation}
	}
	target := DispatchTarget{ReceiverID: "ops", Scope: []ScopeEntry{}, IntegrationDigest: strings.Repeat("b", 64), RepeatIntervalUS: 1000}
	key, token := strings.Repeat("c", 64), strings.Repeat("a", 64)
	id := "33333333-3333-4333-8333-333333333333"
	expires := now.Add(time.Minute)
	result := ActionResultV1{OperationID: id, EpisodeRef: ref, State: "accepted", PermitExpiresAt: &expires, Targets: []TargetResult{{Target: target, TargetKey: key, State: "pending"}}}
	request := ordinaryRequest{Kind: "ordinary", OperationID: id, EpisodeRef: ref, Target: target, Terminal: &terminalObservation{wire.Resolved(), terminalSourceDigest(source), p.LifecycleSeq, p.NativeVariant, source.EndsAt}}
	expired := strings.HasPrefix(fault, "expiry ")
	durable := p
	if expired {
		durable.State = "firing"
		durable.LifecycleSeq = 1
	}
	if invalid == "native variant" {
		durable.NativeVariant.StartsAt = source.StartsAt.Add(-time.Second).UTC().Format(time.RFC3339Nano)
	}
	claims, closures, settlements := 0, 0, 0
	rpc := actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		switch cmd {
		case "recover":
			if args["projection"] == "source" && durable.State == "firing" || args["projection"] == "terminal" && durable.State == "resolved" {
				*out.(*[]EpisodeProjection) = []EpisodeProjection{durable}
			} else {
				*out.(*[]EpisodeProjection) = []EpisodeProjection{}
			}
		case "project-episode":
			closures++
			update := args["update"].(episodeUpdate)
			require.Equal(t, p.EpisodeRef, update.EpisodeRef)
			require.Equal(t, "resolved", update.State)
			require.EqualValues(t, 2, update.LifecycleSeq)
			durable.episodeUpdate = update
			*out.(*EpisodeProjection) = durable
		case "reserve-terminal":
			require.Equal(t, source.EndsAt.UTC(), args["source_ends_at"])
			*out.(*ActionResultV1) = result
		case "lookup":
			*out.(**actionIntent) = &actionIntent{Request: mustRaw(t, request), Digest: key, Result: result}
		case "claim-target":
			claims++
			if fault == "lost claim reply" {
				result.Targets[0].State = "unknown"
				return unavailable
			}
			return json.Unmarshal(mustRaw(t, map[string]any{"entry_token": token, "lease_expires_at": expires, "permit_expires_at": expires}), out)
		case "settle-target":
			settlements++
			if timeoutKind != "" {
				require.Equal(t, "confirmed", args["receipt"].(map[string]string)["outcome"])
			}
			require.Equal(t, id, args["operation_id"])
			require.Equal(t, key, args["target_key"])
			require.Equal(t, token, args["entry_token"])
			*out.(*ActionResultV1) = result
		default:
			t.Fatalf("unexpected %s", cmd)
		}
		return nil
	})
	o := newNativeActionOwner(defaultActionAuthority, rpc, singleActionDispatch{target: target})
	o.lease = actionLease{Epoch: 1, ExpiresAt: expires}
	o.recovered = true
	slot := &episodeSlot{source: source, projection: durable}
	o.byKey[sourceKey(source.ManagedMember.Episode, p.NativeVariant.Fingerprint)], o.byID[ref.EpisodeID] = slot, slot
	var writes atomic.Int32
	var send func(Entry, alert.NativeDeliveryV1)
	if timeoutKind != "" {
		m := source.ManagedMember
		promoted := &ownerSlot{Generation: m.Generation, Projection: snapshot(source), Operation: mustRaw(t, map[string]string{"kind": timeoutKind, "event_id": m.Event, "source_digest": m.Digest})}
		state := ownerState{Key: m.Episode, State: "open", Phase: "settled", Generation: m.Generation, Current: promoted}
		switch invalid {
		case "expiry":
			promoted.Projection.Alert.EndsAt = source.EndsAt.Add(-time.Second)
		case "generation":
			promoted.Generation++
			state.Generation++
		case "event":
			promoted.Operation = mustRaw(t, map[string]string{"kind": timeoutKind, "event_id": id, "source_digest": m.Digest})
		case "digest":
			promoted.Operation = mustRaw(t, map[string]string{"kind": timeoutKind, "event_id": m.Event, "source_digest": key})
		case "variant":
			promoted.Projection.Alert.StartsAt = source.StartsAt.Add(-time.Second)
		case "pending":
			state.Current, state.Pending, state.Phase = nil, promoted, "reserved"
		}
		o.verifyManaged = func(_ context.Context, a *alert.Alert, logical string) error {
			return actionMemberProof(state, a, logical)
		}
		send = managedTimeoutWebhook(t, wire, target, &writes)
	}
	if expired {
		k := sourceKey(source.ManagedMember.Episode, source.Fingerprint().String())
		bucket, bit := membershipBit(k)
		o.membership[bucket] |= bit
		o.readSource = func(_, _ string, visit func(*alert.Alert)) { visit(source) }
		if fault == "expiry after slot reclamation" {
			slot.clock = o.clock.PushBack(k)
			require.True(t, o.evictOne())
		}
		current, pass, err := o.InspectOrdinary(t.Context(), source)
		if timeoutKind != "" && invalid != "exact" {
			require.Error(t, err)
			require.Nil(t, pass)
			require.Zero(t, closures)
			require.Zero(t, claims)
			require.Zero(t, writes.Load())
			return
		}
		require.NoError(t, err)
		require.Nil(t, pass)
		require.NotNil(t, current)
		require.Equal(t, p.EpisodeRef, current.EpisodeRef)
		require.Equal(t, p.LifecycleSeq, current.LifecycleSeq)
		require.Equal(t, p.State, current.State)
		require.Equal(t, p.ManagedOwner, current.ManagedOwner)
		require.Equal(t, p.NativeVariant, current.NativeVariant)
		require.Equal(t, 1, closures)
	}
	if fault == "promoted managed clear" {
		m := source.ManagedMember
		current := &ownerSlot{Generation: m.Generation, Projection: snapshot(source), Operation: mustRaw(t, map[string]string{"kind": "clear", "event_id": m.Event, "source_digest": m.Digest})}
		closed := now.UnixMilli()
		state := ownerState{Key: m.Episode, State: "exact_closed", Phase: "reserved", Generation: m.Generation, Closed: &closed, Pending: current}
		o.verifyManaged = func(_ context.Context, a *alert.Alert, logical string) error {
			return actionMemberProof(state, a, logical)
		}
		_, err := o.ReserveTerminal(t.Context(), wire, p, target)
		require.Error(t, err)
		state.Current, state.Pending, state.Phase = current, nil, "applied"
	}
	r, err := o.ReserveTerminal(t.Context(), wire, p, target)
	require.NoError(t, err)
	if fault == "annotation replacement on takeover" {
		replacement := *source
		replacement.Annotations = model.LabelSet{"changed": "new"}
		o = newNativeActionOwner(defaultActionAuthority, rpc, singleActionDispatch{target: target})
		o.recovered = true
		o.lease = actionLease{Epoch: 2, ExpiresAt: expires}
		o.byID[ref.EpisodeID] = &episodeSlot{source: &replacement, projection: p}
		_, err = o.Claim(t.Context(), r.OperationID, key)
		require.Error(t, err)
		require.Zero(t, claims)
		return
	}
	entry, err := o.Claim(t.Context(), r.OperationID, key)
	if fault == "lost claim reply" {
		require.Error(t, err)
		require.Nil(t, entry)
		entry, err = o.Claim(t.Context(), r.OperationID, key)
		require.Error(t, err)
		require.Nil(t, entry)
		require.Equal(t, 1, claims)
		return
	}
	require.NoError(t, err)
	require.True(t, entry.ForMember(wire))
	deliveryID := uuid.NewSHA1(uuid.MustParse(id), []byte(key)).String()
	stamp, err := o.Delivery(t.Context(), source, target.ReceiverID, deliveryID, entry)
	require.NoError(t, err)
	require.Equal(t, "resolved", stamp.State)
	require.Nil(t, stamp.OperationID)
	require.Equal(t, p.LifecycleSeq, stamp.LifecycleSeq)
	_, err = o.Delivery(t.Context(), source, target.ReceiverID, id, nil)
	require.Error(t, err)
	if fault == "promoted managed clear" {
		require.False(t, wire.Resolved())
		return
	}
	if timeoutKind != "" {
		send(entry, stamp)
		require.EqualValues(t, 1, writes.Load())
		require.Equal(t, 1, claims)
		_, err = o.Settle(t.Context(), entry, "confirmed", "NATIVE_TRANSPORT_ACCEPTED")
		require.NoError(t, err)
		require.Equal(t, 1, settlements)
		return
	}
	if fault == "evicted before late settlement" {
		slotKey := sourceKey("", p.NativeVariant.Fingerprint)
		slot.clock = o.clock.PushBack(slotKey)
		require.True(t, o.evictOne())
		require.True(t, entry.LocalValid())
		// Use the production provider observer semantics for this detached key.
		o.readSource = func(_, _ string, use func(*alert.Alert)) { use(source) }
	}
	next := *source
	next.StartsAt, next.EndsAt = now, expires
	o.observe("", &next, false)
	require.False(t, entry.LocalValid())
	_, err = o.Settle(t.Context(), entry, "confirmed", "original acceptance")
	require.NoError(t, err)
}

// Use the real webhook signer and the managed baseline from the native notification log.
func managedTimeoutWebhook(t *testing.T, wire *alert.Alert, target DispatchTarget, writes *atomic.Int32) func(Entry, alert.NativeDeliveryV1) {
	t.Helper()
	key := []byte(strings.Repeat("k", 32))
	expected := make(chan alert.NativeDeliveryV1, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		raw, err := io.ReadAll(r.Body)
		var original alert.NativeDeliveryV1
		select {
		case original = <-expected:
		default:
			t.Error("unexpected provider write")
			w.WriteHeader(http.StatusConflict)
			return
		}
		var m webhook.Message
		headers, signatureErr := alert.NativeDeliveryHeaders(raw, target.ReceiverID, r.URL.RequestURI(), key)
		if err != nil || signatureErr != nil || headers["X-Oscar-Native-Signature"] != r.Header.Get("X-Oscar-Native-Signature") ||
			json.Unmarshal(raw, &m) != nil || m.Data == nil || len(m.Alerts) != 1 || m.Alerts[0].Status != "resolved" || !m.Alerts[0].EndsAt.Equal(wire.EndsAt) ||
			m.Managed == nil || m.Managed.Baseline <= 0 || len(m.Managed.Members) != 1 || !m.Managed.Members[0].Eligible || m.Managed.Members[0].ManagedMembership != wire.ManagedMember ||
			len(m.NativeDeliveries) != 1 || !reflect.DeepEqual(m.NativeDeliveries[0], alert.NativeDeliveryMember{Index: 0, Delivery: original}) {
			t.Error("incorrect signed managed terminal receipt")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	cred := filepath.Join(t.TempDir(), "callback-key")
	require.NoError(t, os.WriteFile(cred, key, 0600))
	cfg := &webhook.WebhookConfig{URL: "http://alertmanager-middleware:9400" + alert.NativeCallbackPath,
		HTTPConfig: &commoncfg.HTTPClientConfig{Authorization: &commoncfg.Authorization{Type: "Bearer", CredentialsFile: cred}}}
	cfg.VSendResolved = true
	tmpl, err := template.FromGlobs(nil)
	require.NoError(t, err)
	tmpl.ExternalURL = &url.URL{}
	l := slog.New(slog.DiscardHandler)
	sender, err := webhook.New(cfg, tmpl, l, commoncfg.WithDialContextFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}))
	require.NoError(t, err)
	log, err := nflog.New(nflog.Options{Retention: time.Hour, Metrics: prometheus.NewRegistry()})
	require.NoError(t, err)
	receiver := &nflogpb.Receiver{GroupName: target.ReceiverID, Integration: "webhook"}
	const group = "managed-timeout"
	require.NoError(t, log.Log(receiver, group, []uint64{notify.HashAlert(wire)}, nil, nil, nil, time.Hour))
	ctx := notify.WithReceiverName(notify.WithGroupKey(t.Context(), group), target.ReceiverID)
	ctx = notify.WithGroupLabels(notify.WithRepeatInterval(ctx, time.Hour), model.LabelSet{})
	ctx, members, err := notify.NewDedupStage(cfg, log, receiver).Exec(ctx, l, wire)
	require.NoError(t, err)
	require.Equal(t, []*alert.Alert{wire}, members)
	return func(e Entry, d alert.NativeDeliveryV1) {
		t.Helper()
		expected <- d
		permit := &notify.ProviderEntry{Begin: func() bool { return e.ForMember(wire) && e.Valid() }, Members: []alert.NativeDeliveryMember{{Index: 0, Delivery: d}}, Key: key}
		require.NoError(t, sender.Notify(notify.WithProviderEntry(ctx, permit), members...).Err())
	}
}

func TestTerminalEvidenceChangesOnAnnotationReplacement(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	s := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(-time.Second), Annotations: model.LabelSet{"description": "original"}}, now, false)
	digest := terminalSourceDigest(s)
	restored := *s
	require.Equal(t, digest, terminalSourceDigest(&restored))
	restored.Annotations = model.LabelSet{"description": "replacement"}
	require.NotEqual(t, digest, terminalSourceDigest(&restored))
	restored = *s
	restored.GeneratorURL = "https://replacement.invalid/alert"
	require.NotEqual(t, digest, terminalSourceDigest(&restored))
}

func TestOscarActionIncompleteMembershipResumesAfterIntermediateFailure(t *testing.T) {
	t.Parallel()
	var cursors []string
	var activePages int
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, _ string, args map[string]any, out any) error {
		if args["projection"] == "episodes" {
			activePages++
			*out.(*[]EpisodeProjection) = []EpisodeProjection{}
			return nil
		}
		key, _ := args["after_key"].(string)
		cursors = append(cursors, key)
		if key == "" {
			keys := make([]string, 64)
			for i := range keys {
				keys[i] = fmt.Sprintf("%016x", i+1)
			}
			*out.(*[]string) = keys
			return nil
		}
		if len(cursors) == 2 {
			return unavailable
		}
		*out.(*[]string) = []string{"0000000000000041"}
		return nil
	}), testActionDispatch{})
	o.lease = actionLease{Epoch: 2, ExpiresAt: time.Now().Add(time.Hour)}
	require.Error(t, o.recoverEpisodes(t.Context(), o.lease.Epoch))
	require.False(t, o.ready())
	require.Error(t, o.recoverEpisodes(t.Context(), o.lease.Epoch))
	require.False(t, o.ready())
	require.NoError(t, o.recoverEpisodes(t.Context(), o.lease.Epoch))
	require.Equal(t, 1, activePages)
	require.Equal(t, []string{"", "0000000000000040", "0000000000000040"}, cursors)
}

func TestOscarActionBootEpochSwapAfterRestoringFiringSlot(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}, now, false)
	p := EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: episodeUpdate{
		EpisodeRef:    EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "22222222-2222-4222-8222-222222222222", Generation: 1, VariantRevision: 1},
		NativeVariant: variantOf(source), ActiveSince: source.StartsAt.Format(time.RFC3339Nano), LifecycleSeq: 1, State: "firing", SourceSeverity: "major",
	}}
	var owner *nativeActionOwner
	var lookups, pages int
	owner = newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		require.Equal(t, "recover", cmd)
		pages++
		switch args["projection"] {
		case "episodes":
			rows := []EpisodeProjection{}
			if owner.lease.Epoch == 1 {
				rows = append(rows, p)
			}
			*out.(*[]EpisodeProjection) = rows
		case "membership":
			if owner.lease.Epoch == 1 && args["after_key"] == nil {
				keys := make([]string, 64)
				for i := range keys {
					keys[i] = fmt.Sprintf("%016x", i+1)
				}
				*out.(*[]string) = keys
			} else {
				if owner.lease.Epoch == 1 {
					// While this page is in flight, another owner closes the interval
					// and this process then reacquires the lease under a new epoch.
					p.State, p.LifecycleSeq = "resolved", 2
					owner.mu.Lock()
					owner.lease.Epoch = 3
					owner.mu.Unlock()
				} else {
					require.Nil(t, args["after_key"], "new epoch starts its own membership scan")
				}
				*out.(*[]string) = []string{source.Fingerprint().String()}
			}
		case "episode":
			require.Equal(t, p.EpisodeRef.EpisodeID, args["episode_id"])
			*out.(**EpisodeProjection) = &p
			lookups++
		case "operations":
			*out.(*[]ActionResultV1) = []ActionResultV1{}
		default:
			t.Fatalf("unexpected projection %v", args["projection"])
		}
		return nil
	}), testActionDispatch{})
	owner.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
	require.Error(t, owner.recoverAuthority(t.Context(), 1))
	slot := owner.slot(sourceKey("", source.Fingerprint().String()), false)
	require.NotNil(t, slot)
	require.Equal(t, "firing", slot.projection.State)
	require.Error(t, owner.recoverAuthority(t.Context(), 1))
	require.False(t, owner.ready())
	before := pages
	require.Error(t, owner.recoverAuthority(t.Context(), 1), "a turn already holding the old epoch cannot act for its replacement")
	require.Equal(t, before, pages)
	require.NoError(t, owner.recoverAuthority(t.Context(), 3))
	require.True(t, owner.ready())
	slot.turn.Lock()
	defer slot.turn.Unlock()
	require.NoError(t, owner.flush(owner.withEpoch(t.Context()), slot))
	require.Equal(t, 1, lookups)
	require.Equal(t, "resolved", slot.projection.State)
	require.Equal(t, p.LifecycleSeq, slot.projection.LifecycleSeq)
}

func TestOscarActionRecipientKeySurvivesOwnerReplacement(t *testing.T) {
	t.Parallel()
	key := strings.Repeat("a1", 32)
	binding := 2
	var prior []byte
	for _, credential := range []string{"original", "rotated"} {
		var o *nativeActionOwner
		rpc := actionRPCFunc(func(_ context.Context, _ string, args map[string]any, out any) error {
			require.Equal(t, 2, args["recipient_binding"])
			return json.Unmarshal(mustRaw(t, actionLease{Protocol: "native-action-store-v1", RecoverySelectors: 1, TerminalObservations: 2, RecipientBinding: binding, RecipientKey: key, OwnerID: o.owner, AuthorityID: o.authority, Epoch: 1, ExpiresAt: time.Now().Add(30 * time.Second), RenewSeconds: 10}), out)
		})
		o = newNativeActionOwner(defaultActionAuthority, rpc, nil)
		require.NoError(t, o.leaseTick(t.Context()))
		if credential == "original" {
			prior = o.RecipientKey()
			continue
		}
		require.Equal(t, prior, o.RecipientKey())
		for _, tc := range []struct {
			marker int
			key    string
		}{{0, key}, {1, key}, {2, ""}, {2, strings.Repeat("bd", 32)}} {
			binding, key = tc.marker, tc.key
			require.Error(t, o.leaseTick(t.Context()))
			require.False(t, o.lease.ExpiresAt.After(time.Now()))
		}
	}
}

type renewalResponse func(*http.Request) (*http.Response, error)

func (f renewalResponse) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWireRenewalReadiness(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		live   bool
	}{
		{200, `{"recipient_binding":"2"}`, false},
		{200, `{"recipient_key":42}`, false},
		{422, `{"detail":[{"type":"literal_error"}]}`, false},
		{204, "", false},
		{301, "", false},
		{308, "", false},
		{429, "", true},
		{503, `{"detail":"temporary outage"}`, true},
	} {
		token := filepath.Join(t.TempDir(), "credential")
		require.NoError(t, os.WriteFile(token, []byte(strings.Repeat("k", 32)), 0o600))
		client, err := newManagedClient("http", "", token)
		require.NoError(t, err)
		calls := 0
		client.http.Transport = renewalResponse(func(r *http.Request) (*http.Response, error) {
			calls++
			require.True(t, strings.HasSuffix(r.URL.Path, "/renew-authority"))
			header := make(http.Header)
			if tc.status == 301 || tc.status == 308 {
				header.Set("Location", "http://other.invalid/moved")
			}
			return &http.Response{StatusCode: tc.status, Header: header, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})
		rpc := actionClient{client}
		o := newNativeActionOwner(defaultActionAuthority, rpc, testActionDispatch{})
		o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
		o.recovered = true
		s := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
		o.readSource = func(_, _ string, use func(*alert.Alert)) { use(s) }
		_, pass, err := o.InspectOrdinary(t.Context(), s)
		require.NoError(t, err)
		require.True(t, pass.Enter())
		require.Error(t, o.leaseTick(t.Context()))
		require.Equal(t, 1, calls)
		require.Equal(t, tc.live, o.ready())
		require.Equal(t, tc.live, pass.Valid())
	}
}

type retainedTargetPlan struct {
	testActionDispatch
	file    string
	targets []DispatchTarget
}

func (d retainedTargetPlan) Plan(ctx context.Context, _ *alert.Alert, _ EpisodeProjection, _ ActionRequestV1) ([]DispatchTarget, string, error) {
	if wanted, ok := PersistedTarget(ctx); ok && wanted.IntegrationDigest == d.targets[1].IntegrationDigest {
		return d.targets[1:], "", nil
	}
	if _, err := os.ReadFile(d.file); err != nil {
		return nil, "", err
	}
	return d.targets, "", nil
}

func TestFiringReserveRejectsFloorUpdateAfterInspection(t *testing.T) {
	now := time.Now()
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	var commands []string
	rpc := actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		commands = append(commands, cmd)
		switch cmd {
		case "project-episode":
			return json.Unmarshal(mustRaw(t, EpisodeProjection{episodeUpdate: args["update"].(episodeUpdate)}), out)
		case "inspect-contact":
			return json.Unmarshal([]byte(`"due"`), out)
		default:
			t.Fatalf("stale major payload reached %s", cmd)
			return nil
		}
	})
	o := newNativeActionOwner(defaultActionAuthority, rpc, testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Minute)}
	o.recovered = true
	o.observe("", source, false)
	p, err := o.Project(t.Context(), source)
	require.NoError(t, err)
	m := source.NotificationCopy(now)
	target := DispatchTarget{ReceiverID: "team", IntegrationDigest: strings.Repeat("d", 64)}
	state, err := o.InspectContact(t.Context(), m, p, target)
	require.NoError(t, err)
	require.Equal(t, "due", state)
	slot, err := o.episode(p.EpisodeRef)
	require.NoError(t, err)
	slot.turn.Lock()
	slot.projection.Floor = "critical"
	slot.projection.SeverityRevision++
	slot.turn.Unlock()
	_, err = o.ReserveOrdinary(t.Context(), "11111111-1111-4111-8111-111111111111", m, p, target)
	require.ErrorIs(t, err, mismatch)
	require.NotContains(t, commands, "reserve-coverage")
}

func TestOperatorReplayReturnsAcceptedIntentNoEffectReceipts(t *testing.T) {
	var req ActionRequestV1
	require.True(t, decodeAction([]byte(actionBody), &req))
	req.Kind = "resend"
	digest, err := actionDigest(req)
	require.NoError(t, err)
	expiry := time.Now().UTC().Add(time.Minute)
	receipt := ActionResultV1{OperationID: req.OperationID, EpisodeRef: req.EpisodeRef, State: "held", PermitExpiresAt: &expiry}
	intent := actionCommit{EpisodeRef: req.EpisodeRef, State: "accepted"}
	for i, evidence := range []string{"FENCED_BEFORE_PROVIDER_ENTRY", "NATIVE_ALERT_CONTENT_UNDELIVERABLE"} {
		dst := DispatchTarget{ReceiverID: "team", IntegrationDigest: strings.Repeat(fmt.Sprint(i+1), 64)}
		intent.Targets = append(intent.Targets, dst)
		receipt.Targets = append(receipt.Targets, TargetResult{Target: dst, TargetKey: strings.Repeat(fmt.Sprint(i+3), 64), State: "no_effect", Evidence: &evidence})
	}
	record := actionIntent{Digest: digest, Request: mustRaw(t, req), Intent: &intent, Result: receipt}
	rpc := actionRPCFunc(func(_ context.Context, cmd string, _ map[string]any, out any) error {
		require.Equal(t, "lookup", cmd)
		return json.Unmarshal(mustRaw(t, record), out)
	})
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, rpc, testActionDispatch{})
	o.recovered = true
	o.lease = actionLease{Epoch: 1, ExpiresAt: expiry}
	got, err := o.Execute(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, receipt, got)
}

func TestOscarActionCanonicalEnrollmentAndRepeatBeyondSlotCapacity(t *testing.T) {
	t.Parallel()
	now := time.Now()
	members := make([]*alert.Alert, maxActionEpisodes+13)
	residents := make(map[string]*alert.Alert)
	rows := make(map[string]EpisodeProjection)
	var sourceReads int
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		switch cmd {
		case "recover":
			require.Equal(t, "source", args["projection"], "a delivery must never scan an inventory page")
			sourceReads++
			found := []EpisodeProjection{}
			if p, ok := rows[args["fingerprint"].(string)]; ok {
				found = append(found, p)
			}
			*out.(*[]EpisodeProjection) = found
		case "project-episode":
			u := args["update"].(episodeUpdate)
			prev, exists := rows[u.NativeVariant.Fingerprint]
			if exists {
				require.Equal(t, prev.EpisodeRef, u.EpisodeRef)
			}
			p := EpisodeProjection{episodeUpdate: u, ID: u.EpisodeRef.EpisodeID}
			rows[u.NativeVariant.Fingerprint] = p
			*out.(*EpisodeProjection) = p
		default:
			t.Fatalf("unexpected %s", cmd)
		}
		return nil
	}), testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
	o.recovered = true
	o.readSource = func(_, fp string, use func(*alert.Alert)) {
		if s := residents[fp]; s != nil {
			use(s)
		}
	}
	for i := range members {
		s := alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(fmt.Sprint(i)), "severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
		members[i] = s
		residents[s.Fingerprint().String()] = s
		o.observe("", s, false)
	}
	for round := range 2 {
		for i, s := range members {
			p, pass, err := o.InspectOrdinary(t.Context(), s)
			require.NoError(t, err)
			if round == 0 {
				require.NotNil(t, pass)
				require.Nil(t, p)
			} else {
				require.Nil(t, pass)
				require.NotNil(t, p)
			}
			d, err := o.Delivery(t.Context(), s, "canonical", fmt.Sprintf("00000000-1111-4111-8111-%012d", i), nil)
			require.NoError(t, err)
			require.Equal(t, rows[s.Fingerprint().String()].EpisodeRef, d.EpisodeRef)
			require.LessOrEqual(t, len(o.byKey), maxActionEpisodes)
		}
	}
	require.Len(t, rows, len(members))
	require.LessOrEqual(t, sourceReads, 4*len(members))
}

type directResidentFixture struct {
	testActionDispatch
	current  map[string]*alert.Alert
	contacts map[string]*DirectContact
}

func (d *directResidentFixture) DirectContact(k string) *DirectContact { return d.contacts[k] }
func (d *directResidentFixture) ChangeDirectContact(k string, old, next *DirectContact) bool {
	if d.current[k] == nil || d.contacts[k] != old {
		return false
	}
	if next == nil {
		delete(d.contacts, k)
	} else {
		d.contacts[k] = next
	}
	return true
}
func (d *directResidentFixture) ObserveSource(owner string, s *alert.Alert, closed, possible bool) (*alert.Alert, *DirectContact) {
	k := sourceKey(owner, s.Fingerprint().String())
	old := d.current[k]
	if closed {
		p := d.contacts[k]
		delete(d.current, k)
		delete(d.contacts, k)
		return old, p
	}
	d.current[k] = s
	return old, nil
}
func (*directResidentFixture) InvalidateSource(*alert.Alert)                         {}
func (*directResidentFixture) PublicationGeneration() uint64                         { return 1 }
func (*directResidentFixture) PublishedEpisode(*alert.Alert, EpisodeProjection) bool { return false }
func (*directResidentFixture) VerifiedNegative(*alert.Alert, uint64) bool            { return true }

func TestOscarActionDirectGroupBeyondSlotCapAndDetachedUnknownOverflow(t *testing.T) {
	t.Parallel()
	d := &directResidentFixture{current: map[string]*alert.Alert{}, contacts: map[string]*DirectContact{}}
	o := newNativeActionOwner(defaultActionAuthority, nil, d) // Direct passes have no RPC client.
	now := time.Now()
	o.recovered = true
	o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
	o.readSource = func(owner, fp string, use func(*alert.Alert)) {
		if s := d.current[sourceKey(owner, fp)]; s != nil {
			use(s)
		}
	}
	var sources []*alert.Alert
	var passes []*OrdinaryPass
	for i := range maxActionEpisodes + 12 {
		s := alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(fmt.Sprint(i))}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
		o.observe("", s, false)
		_, pass, err := o.InspectOrdinary(t.Context(), s)
		require.NoError(t, err)
		require.True(t, pass.Enter())
		sources = append(sources, s)
		passes = append(passes, pass)
	}
	for _, p := range passes {
		require.True(t, p.Valid())
	}
	require.Empty(t, o.byKey)
	require.Empty(t, o.untracked)
	for i, s := range sources {
		o.observe("", s, true)
		require.False(t, passes[i].Valid())
	}
	require.Len(t, o.untracked, maxActionEpisodes)
	for i, s := range sources {
		o.observe("", s, false)
		_, _, err := o.InspectOrdinary(t.Context(), s)
		require.Error(t, err)
		if i == len(sources)-1 {
			passes[i].Finish(false)
		} else {
			passes[i].Finish(true)
		}
	}
	last := sources[len(sources)-1]
	_, _, err := o.InspectOrdinary(t.Context(), last)
	require.Error(t, err, "the last detached unknown cannot be evicted by late conclusive settlements")
}

func TestOscarActionReceiptLeaseCompatibilityIsAffirmative(t *testing.T) {
	t.Parallel()
	o := newNativeActionOwner(defaultActionAuthority, nil, testActionDispatch{})
	o.recovered = true
	o.lease = actionLease{Epoch: 3, ExpiresAt: time.Now().Add(time.Hour)}
	for _, tc := range []struct {
		value string
		ready bool
	}{{"1", true}, {"", false}, {"null", false}, {"true", false}, {`"1"`, false}, {"2", false}, {"1", true}} {
		o.lease.OrdinaryCohort = json.RawMessage("2")
		o.lease.NativeDeliveryReceipts = json.RawMessage(tc.value)
		o.publishLeaseLocked()
		epoch, ready := o.RecoveryState()
		require.Equal(t, uint64(3), epoch)
		require.Equal(t, tc.ready, ready)
	}
	for _, value := range []string{"", "null", "true", `"2"`, "1", "3"} {
		o.lease.OrdinaryCohort = json.RawMessage(value)
		o.publishLeaseLocked()
		epoch, signed := o.RecoveryState()
		require.EqualValues(t, 3, epoch)
		require.False(t, signed)
		require.False(t, o.CohortSupported())
	}
	o.lease.OrdinaryCohort = json.RawMessage("2")
	o.lease.NativeDeliveryReceipts = nil
	o.publishLeaseLocked()
	require.True(t, o.CohortSupported(), "direct cohort support is independent of OSCAR delivery receipt consumption")
	require.Error(t, o.rejectLease())
	epoch, ready := o.RecoveryState()
	require.Zero(t, epoch)
	require.False(t, ready)
}

func TestOscarActionInvalidSeverityCannotExhaustEnrollment(t *testing.T) {
	t.Parallel()
	now := time.Now()
	var current *alert.Alert
	writes := 0
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		require.Equal(t, "project-episode", cmd)
		u := args["update"].(episodeUpdate)
		*out.(*EpisodeProjection) = EpisodeProjection{episodeUpdate: u, ID: u.EpisodeRef.EpisodeID}
		writes++
		return nil
	}), testActionDispatch{})
	o.recovered = true
	o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
	o.readSource = func(_, fp string, read func(*alert.Alert)) {
		if current.Fingerprint().String() == fp {
			read(current)
		}
	}
	var residents []*alert.Alert
	for i := range maxActionEpisodes + 1 {
		severity := "high"
		if i == maxActionEpisodes {
			severity = "major"
		}
		current = alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(fmt.Sprint(i)), "severity": model.LabelValue(severity)}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
		residents = append(residents, current)
		o.observe("", current, false)
		_, err := o.Project(t.Context(), current)
		if i < maxActionEpisodes {
			require.Error(t, err)
			require.Empty(t, o.byKey)
		} else {
			require.NoError(t, err)
		}
	}
	require.Len(t, residents, maxActionEpisodes+1)
	require.Equal(t, 1, writes)
}

func TestOscarActionDelayedSelectorCannotRestoreEarlierFloor(t *testing.T) {
	t.Parallel()
	now := time.Now()
	src := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	ref := EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "11111111-1111-4111-8111-111111111111", Generation: 1, VariantRevision: 1}
	old := EpisodeProjection{ID: ref.EpisodeID, episodeUpdate: episodeUpdate{EpisodeRef: ref, State: "firing", SourceSeverity: "major", NativeVariant: variantOf(src), LifecycleSeq: 1, ActiveSince: now.UTC().Format(time.RFC3339Nano)}}
	durable := old
	var delay atomic.Bool
	paused, release := make(chan struct{}), make(chan struct{})
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		require.Equal(t, "recover", cmd)
		require.Equal(t, "source", args["projection"])
		snapshot := durable
		if delay.Swap(false) {
			close(paused)
			<-release
		}
		*out.(*[]EpisodeProjection) = []EpisodeProjection{snapshot}
		return nil
	}), testActionDispatch{})
	o.recovered = true
	o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
	o.readSource = func(_, _ string, use func(*alert.Alert)) { use(src) }
	ctx := o.withEpoch(t.Context())
	bucket, bit := membershipBit(sourceKey("", src.Fingerprint().String()))
	o.membership[bucket] |= bit
	_, err := o.restoreCurrent(ctx, old, src)
	require.NoError(t, err)
	require.True(t, o.evictOne())
	delay.Store(true)
	done := make(chan error, 1)
	go func() { _, _, err := o.InspectOrdinary(ctx, src); done <- err }()
	<-paused
	durable.Floor, durable.SeverityRevision = "critical", 1
	_, err = o.restoreCurrent(ctx, durable, src)
	require.NoError(t, err)
	require.True(t, o.evictOne())
	close(release)
	require.NoError(t, <-done)
	got, err := o.ClassifyResident(ctx, 1, src)
	require.NoError(t, err)
	require.Equal(t, durable.SeverityRevision, got.SeverityRevision)
	require.Equal(t, "critical", got.EffectiveSeverity())
}

type cohortFixtureDispatch struct {
	testActionDispatch
	target     DispatchTarget
	stamp      atomic.Bool
	beforePlan func(*alert.Alert)
}

func (f *cohortFixtureDispatch) FreezeEpisode(*alert.Alert, EpisodeProjection) *atomic.Bool {
	return &f.stamp
}
func (f *cohortFixtureDispatch) Plan(_ context.Context, source *alert.Alert, _ EpisodeProjection, _ ActionRequestV1) ([]DispatchTarget, string, error) {
	if f.beforePlan != nil {
		f.beforePlan(source)
	}
	return []DispatchTarget{f.target}, "", nil
}

func TestOscarOrdinaryCohortLostRepliesUseOnlyOriginalIDsAndTokens(t *testing.T) {
	for _, settleCommitted := range []bool{false, true} {
		t.Run(fmt.Sprint(settleCommitted), func(t *testing.T) {
			target := DispatchTarget{ReceiverID: "team", IntegrationDigest: strings.Repeat("a", 64), Scope: []ScopeEntry{}, RepeatIntervalUS: 1e6}
			dispatch := &cohortFixtureDispatch{target: target}
			dispatch.stamp.Store(true)
			var submitted, lost []string
			token := strings.Repeat("b", 64)
			key, err := canonicalActionDigest([]any{target.ReceiverID, target.IntegrationDigest, []string{}})
			require.NoError(t, err)
			lookups, settles := 0, 0
			now := time.Now()
			o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
				switch cmd {
				case "admit-cohort":
					requests := p["members"].([]cohortRequest)
					for _, r := range requests {
						submitted = append(submitted, r.ID)
					}
					if len(requests) == ordinaryChunk {
						lost = append(lost, submitted...)
						return errors.New("reserve/claim response lost")
					}
					require.Len(t, requests, 1)
					*out.(*[]cohortResult) = []cohortResult{{ID: requests[0].ID, State: "entered", Token: token, Key: key, Target: target, Permit: now.Add(30 * time.Second), Lease: now.Add(30 * time.Second)}}
				case "lookup-cohort":
					lookups++
					ids := p["operation_ids"].([]string)
					rows := make([]cohortResult, len(ids))
					if len(ids) == ordinaryChunk {
						require.Equal(t, lost, ids)
						for n, id := range ids {
							rows[n] = cohortResult{ID: id, Key: key, State: "entered"}
						}
						rows[0].State = "missing"
						rows[1].State = "unknown"
					} else {
						require.Equal(t, submitted[ordinaryChunk:], ids)
						rows[0] = cohortResult{ID: ids[0], Key: key, State: "entered"}
						if settleCommitted {
							rows[0].State = "confirmed"
							rows[0].Evidence = "accepted"
						}
					}
					*out.(*[]cohortResult) = rows
				case "settle-cohort":
					settles++
					m := p["members"].([]map[string]any)
					require.Len(t, m, 1)
					require.Equal(t, submitted[ordinaryChunk], m[0]["operation_id"])
					require.Equal(t, token, m[0]["entry_token"])
					if settles == 1 {
						return errors.New("settle response lost")
					}
					*out.(*[]string) = submitted[ordinaryChunk:]
				default:
					t.Fatalf("unexpected single-member RPC %s", cmd)
				}
				return nil
			}), dispatch)
			o.recovered = true
			o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Minute), NativeDeliveryReceipts: json.RawMessage("1"), OrdinaryCohort: json.RawMessage("2")}
			o.publishLeaseLocked()
			var candidates []OrdinaryCandidate
			for n := range ordinaryChunk + 1 {
				source := alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(fmt.Sprint(n)), "severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
				id := fmt.Sprintf("00000000-0000-4000-8000-%012d", n+1)
				p := EpisodeProjection{ID: id, episodeUpdate: episodeUpdate{EpisodeRef: EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: id, Generation: 1, VariantRevision: 1}, NativeVariant: variantOf(source), ActiveSince: now.UTC().Format(time.RFC3339Nano), State: "firing", LifecycleSeq: 1, SourceSeverity: "major"}}
				if n%2 == 0 {
					source.EndsAt, p.State, p.LifecycleSeq = now, "resolved", 2
				}
				candidates = append(candidates, OrdinaryCandidate{Canonical: true, Member: source.NotificationCopy(now), Projection: p, Target: target})
			}
			out := o.AdmitCohort(t.Context(), candidates)
			require.Len(t, submitted, len(candidates))
			require.ErrorIs(t, out[0].Err, unavailable)
			for _, r := range out[1:ordinaryChunk] {
				require.ErrorIs(t, r.Err, reconcile)
				require.Nil(t, r.Entry)
			}
			require.NoError(t, out[ordinaryChunk].Err)
			require.Equal(t, "resolved", out[ordinaryChunk].Delivery.State)
			for n, c := range candidates {
				if c.Projection.State == "resolved" {
					require.Equal(t, terminalOperationID(c.Projection, key), submitted[n])
				}
			}
			o.recovered = false
			o.publishLeaseLocked()
			require.NoError(t, o.SettleCohort(t.Context(), []OrdinaryReceipt{{out[ordinaryChunk].Entry, "confirmed", "accepted"}}))
			require.Equal(t, 2, lookups)
			if settleCommitted {
				require.Equal(t, 1, settles)
			} else {
				require.Equal(t, 2, settles)
			}
		})
	}
}

func TestOrdinaryCohortBoundsExactPrivateBodyBeforeSending(t *testing.T) {
	for _, name := range []string{strings.Repeat("x", 4096), strings.Repeat("<", 4096), strings.Repeat("x", actionBodyLimit)} {
		t.Run(fmt.Sprint(len(name), name[0]), func(t *testing.T) {
			destination := DispatchTarget{ReceiverID: name, IntegrationDigest: strings.Repeat("a", 64), Scope: []ScopeEntry{}, RepeatIntervalUS: 1000}
			key, err := canonicalActionDigest([]any{name, destination.IntegrationDigest, []string{}})
			require.NoError(t, err)
			dispatch := &cohortFixtureDispatch{target: destination}
			dispatch.stamp.Store(true)
			now := time.Now()
			observed := map[string][]int{}
			var reserved []string
			o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
				body, err := json.Marshal(args)
				require.NoError(t, err)
				require.LessOrEqual(t, len(body), actionBodyLimit)
				require.Len(t, args, 4)
				items := args["members"].([]cohortRequest)
				observed[cmd] = append(observed[cmd], len(items))
				require.LessOrEqual(t, len(items), 64)
				rows := make([]cohortResult, len(items))
				for n, r := range items {
					rows[n] = cohortResult{ID: r.ID, State: "due"}
					switch cmd {
					case "inspect-cohort":
					case "admit-cohort":
						reserved = append(reserved, r.ID)
						rows[n] = cohortResult{ID: r.ID, State: "entered", Key: key, Token: strings.Repeat("c", 64), Target: r.Target, Lease: now.Add(30 * time.Second), Permit: now.Add(30 * time.Second)}
					default:
						t.Fatalf("unexpected %s", cmd)
					}
				}
				*out.(*[]cohortResult) = rows
				return nil
			}), dispatch)
			o.recovered = true
			o.lease = actionLease{Epoch: 128, ExpiresAt: now.Add(time.Minute), OrdinaryCohort: json.RawMessage("2")}
			o.publishLeaseLocked()
			var members []OrdinaryCandidate
			for n := range ordinaryChunk {
				src := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major", "host": model.LabelValue(fmt.Sprint(n))}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
				id := fmt.Sprintf("00000000-0000-4000-8000-%012d", n+1)
				p := EpisodeProjection{ID: id, episodeUpdate: episodeUpdate{EpisodeRef: EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: id, Generation: 1, VariantRevision: 1}, NativeVariant: variantOf(src), ActiveSince: now.UTC().Format(time.RFC3339Nano), State: "firing", SourceSeverity: "major", LifecycleSeq: 1}}
				if n%2 == 0 {
					src.EndsAt, p.State, p.LifecycleSeq = now, "resolved", 2
				}
				members = append(members, OrdinaryCandidate{Member: src, Target: destination, Projection: p})
			}
			states := o.InspectCohort(t.Context(), members)
			entries := o.AdmitCohort(t.Context(), members)
			if len(name) == actionBodyLimit {
				require.Empty(t, observed)
				for n, entry := range entries {
					require.ErrorIs(t, entry.Err, privateCommandTooLarge)
					require.Nil(t, entry.Entry)
					require.Empty(t, states[n])
				}
				return
			}
			require.Len(t, reserved, len(members))
			require.Greater(t, len(observed["inspect-cohort"]), 1)
			require.Equal(t, observed["inspect-cohort"], observed["admit-cohort"])
			for n, entry := range entries {
				require.Equal(t, "due", states[n])
				require.NoError(t, entry.Err)
				require.Equal(t, reserved[n], entry.Entry.(claimedEntry).OperationID)
			}
		})
	}
}

func TestOscarTerminalCohortOriginalWireAndManagedProof(t *testing.T) {
	t.Parallel()
	for _, expiresDuringPlan := range []bool{false, true} {
		t.Run(fmt.Sprintf("expires-during-sibling-plan-%t", expiresDuringPlan), func(t *testing.T) {
			exerciseTerminalWireProof(t, expiresDuringPlan)
		})
	}
}

func exerciseTerminalWireProof(t *testing.T, expiresDuringPlan bool) {
	t.Helper()
	now := time.Now().UTC()
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "cleared"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}, now, false)
	if expiresDuringPlan {
		source.EndsAt = now.Add(3 * time.Second)
		source.ManagedEligible = func(_ context.Context, member *alert.Alert, receiver, group string) (bool, error) {
			return member == source && receiver == "ops" && group == "managed-timeout", nil
		}
	}
	source.ManagedReceiver, source.ManagedOperationKind = true, "clear"
	source.ManagedMember = alert.ManagedMembership{Episode: strings.Repeat("a", 64), Event: uuid.NewString(), Generation: 2, Digest: strings.Repeat("b", 64)}
	m := source.ManagedMember
	ref := EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: uuid.NewString(), Generation: 1, VariantRevision: 1}
	p := EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: episodeUpdate{
		EpisodeRef: ref, ActiveSince: variantOf(source).StartsAt, NativeVariant: variantOf(source), State: "resolved", SourceSeverity: "cleared", LifecycleSeq: 2, ManagedOwner: &sourceOwner{m.Episode, m.Generation},
	}}
	// Compact Python JSON includes the literal separator rune and preserves the
	// literal backslash sequence. UUIDv5 uses the episode row, not the public episode.
	target := DispatchTarget{ReceiverID: "ops<&\u2028\\u2029>", IntegrationDigest: strings.Repeat("a", 64), Scope: []ScopeEntry{}, RepeatIntervalUS: 1000}
	targetKey := "46ed006f39eb8cbdc6a48fdb8b8d6aca4d9d23956450351887500a1c07ce308d"
	original := "1ac992d7-5393-5645-8126-c87e03eb6b2c"
	if expiresDuringPlan {
		target.ReceiverID = "ops"
		var err error
		targetKey, err = canonicalActionDigest([]any{target.ReceiverID, target.IntegrationDigest, []string{}})
		require.NoError(t, err)
		original = terminalOperationID(p, targetKey)
	}
	token := strings.Repeat("c", 64)
	dispatch := &cohortFixtureDispatch{target: target}
	dispatch.stamp.Store(true)
	claims, settlements := 0, 0
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		switch cmd {
		case "admit-cohort":
			requests := args["members"].([]cohortRequest)
			require.Len(t, requests, 1)
			r := requests[0]
			if r.Terminal == nil {
				// The live sibling uses its existing firing coverage.
				require.True(t, expiresDuringPlan)
				*out.(*[]cohortResult) = []cohortResult{{ID: r.ID, State: "covered"}}
				return nil
			}
			require.Equal(t, original, r.ID)
			require.Equal(t, terminalSourceDigest(source), r.Terminal.SourceDigest)
			require.Equal(t, source.EndsAt, r.Terminal.SourceEndsAt)
			require.Equal(t, expiresDuringPlan, r.Terminal.WireResolved)
			if settlements > 0 {
				*out.(*[]cohortResult) = []cohortResult{{ID: original, State: "completed"}}
				return nil
			}
			claims++
			*out.(*[]cohortResult) = []cohortResult{{ID: original, Key: targetKey, Target: target, Token: token, State: "entered", Lease: now.Add(time.Minute), Permit: now.Add(30 * time.Second)}}
		case "settle-cohort":
			settlements++
			r := args["members"].([]map[string]any)[0]
			require.Equal(t, original, r["operation_id"])
			require.Equal(t, targetKey, r["target_key"])
			require.Equal(t, token, r["entry_token"])
			if expiresDuringPlan {
				require.Equal(t, map[string]string{"outcome": "confirmed", "evidence": "NATIVE_TRANSPORT_ACCEPTED"}, r["receipt"])
			}
			*out.(*[]string) = []string{original}
		default:
			t.Fatalf("unexpected command %s", cmd)
		}
		return nil
	}), dispatch)
	o.recovered = true
	o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Minute), OrdinaryCohort: json.RawMessage("2"), NativeDeliveryReceipts: json.RawMessage("1")}
	o.publishLeaseLocked()
	promoted := &ownerSlot{Generation: m.Generation, Projection: snapshot(source), Operation: mustRaw(t, map[string]string{"kind": "clear", "event_id": m.Event, "source_digest": m.Digest})}
	closed := now.UnixMilli()
	state := ownerState{Key: m.Episode, State: "exact_closed", Phase: "reserved", Generation: m.Generation, Closed: &closed, Pending: promoted}
	o.verifyManaged = func(_ context.Context, s *alert.Alert, logical string) error {
		return actionMemberProof(state, s, logical)
	}
	wire := source.NotificationCopy(now)
	c := OrdinaryCandidate{Canonical: expiresDuringPlan, Member: wire, Projection: p, Target: target}
	run := func() OrdinaryAdmission { return o.AdmitCohort(t.Context(), []OrdinaryCandidate{c})[0] }
	require.Error(t, run().Err)
	require.Zero(t, claims)
	state.Current, state.Pending, state.Phase = promoted, nil, "applied"
	wrong := *wire
	wrong.EndsAt = now.Add(-time.Minute)
	c.Member = &wrong
	require.Error(t, run().Err)
	require.Zero(t, claims)
	c.Member = wire
	if expiresDuringPlan {
		source2 := alert.New(model.Alert{Labels: model.LabelSet{"host": "sibling", "severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
		ref2 := ref
		ref2.EpisodeID = uuid.NewString()
		p2 := EpisodeProjection{ID: uuid.NewString(), episodeUpdate: episodeUpdate{EpisodeRef: ref2, NativeVariant: variantOf(source2), ActiveSince: variantOf(source2).StartsAt, State: "firing", SourceSeverity: "major", LifecycleSeq: 1}}
		other := OrdinaryCandidate{Member: source2.NotificationCopy(now), Projection: p2, Target: target}
		var slowPlans int
		dispatch.beforePlan = func(s *alert.Alert) {
			if s == source2 {
				slowPlans++
				require.False(t, source.Resolved(), "first member still has its firing wire before the sibling plan")
				time.Sleep(time.Until(source.EndsAt.Add(time.Millisecond)))
			}
		}
		rows := o.AdmitCohort(t.Context(), []OrdinaryCandidate{c, other})
		require.Equal(t, 1, slowPlans)
		require.Error(t, rows[0].Err)
		require.Nil(t, rows[0].Entry)
		require.True(t, rows[1].Covered)
		require.Zero(t, claims)
		require.Zero(t, settlements)
		c.Member = source.NotificationCopy(time.Now())
		require.True(t, c.Member.Resolved())
	}
	admitted := run()
	require.NoError(t, admitted.Err)
	require.True(t, admitted.Entry.ForMember(c.Member))
	require.False(t, admitted.Entry.ForMember(&wrong))
	require.Equal(t, "resolved", admitted.Delivery.State)
	require.Nil(t, admitted.Delivery.OperationID)
	require.True(t, admitted.Entry.LocalValid())
	outcome, evidence := "no_effect", "FENCED_BEFORE_PROVIDER_ENTRY"
	var writes atomic.Int32
	if expiresDuringPlan {
		send := managedTimeoutWebhook(t, c.Member, target, &writes)
		send(admitted.Entry, admitted.Delivery)
		require.EqualValues(t, 1, writes.Load())
		outcome, evidence = "confirmed", "NATIVE_TRANSPORT_ACCEPTED"
	}
	o.lease.Epoch++
	o.publishLeaseLocked()
	require.False(t, admitted.Entry.LocalValid())
	dispatch.stamp.Store(false)
	require.NoError(t, o.SettleCohort(t.Context(), []OrdinaryReceipt{{admitted.Entry, outcome, evidence}}))
	if expiresDuringPlan {
		dispatch.stamp.Store(true)
		replay := run()
		require.NoError(t, replay.Err)
		require.True(t, replay.Completed)
		require.Nil(t, replay.Entry)
		require.EqualValues(t, 1, writes.Load())
	}
	require.Equal(t, 1, claims)
	require.Equal(t, 1, settlements)
}
